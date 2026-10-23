# SPDX-License-Identifier: Apache-2.0
"""复算回放（M04 §6 流程 3 / INV-03 / 验收 ②⑤）。

只做三件事，且**只读**线上日志（不改历史决策、不改日志）：

1. 从决策日志里取回 ``candidates``（输入快照）与记录时的 ``λ`` / ``ε``；
2. 用**同一条**打分 / tie-break 代码路径重新求解（``scoring`` + ``pipeline`` 的纯函数部分）；
3. 比对 ``chosen`` / ``tie_break`` / ``fallback_used``——差异 ≠ 0 即 P0（差异点落库待人工裁决）。

并发约束：同一时刻只允许 1 个复算作业（spec ReplayRequest「并发 1」），用
**事务级 advisory lock** 实现；重复提交返回 ``409 + 40901``。

T2 的边界：作业状态存**注入的 job store**（默认进程内存 + 结构化日志）。持久化作业表
（``replay_jobs``）需要先在 01-ownership 登记，属于 T4 的写域；因此 T2 的 HTTP 端点在
同一个事务里同步跑完作业并返回 ``202 + job_id``（状态已是终态），语义与异步版一致。
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, Sequence

from . import candidates, clock, config_source, decisions, facts, models, scoring
from .errors import InvalidArgument, ReplayBusy

log = logging.getLogger("djb.scheduling.replay")

LOCK_NAMESPACE = 4003
LOCK_REPLAY_JOB = 1

#: 单次复算作业的决策上限（防止一个请求把库拖死；超出请缩小窗口）
MAX_DECISIONS_PER_JOB = 10_000


# --------------------------------------------------------------------------- 重算
def _lambda_from_log(decision: models.Decision) -> int | None:
    """记录时的 λ（同一请求内所有候选相同；缺记录 → None，由调用方用当前策略补）。"""
    for item in decision.score_breakdown:
        value = item.get("lambda_micro") if isinstance(item, Mapping) else None
        if value is not None:
            return int(value)
    return None


def recompute(decision: models.Decision, *, policy: Mapping[str, Any] | None = None,
              epsilon_bps: int | None = None) -> dict[str, Any]:
    """按记录的输入快照重算（纯函数）：返回重算结果与逐项比对。

    * ``chosen`` / ``tie_break``：直接从重算的排序得出
    * ``fallback_used``：用候选里的 ``quote_created_at`` + ``quotebook_refresh_s`` 重算
      （所以它是**输入的函数**，不是机器速度的函数）
    """
    values = config_source.resolve(policy or {}) if policy else {}
    rebuilt = candidates.rebuild(decision.candidates)
    lambda_value = _lambda_from_log(decision)
    if lambda_value is None:                                  # pragma: no cover - 旧数据兜底
        lambda_value = scoring.lambda_micro("realtime",
                                           config_source.latency_lambda_milli(values)
                                           if values else 1_000)
    scores = [scoring.score(candidate, lambda_value=lambda_value) for candidate in rebuilt]
    if epsilon_bps is not None:
        epsilon = int(epsilon_bps)
    elif values:
        epsilon = config_source.tie_break_epsilon_bps(values)
    else:
        epsilon = facts.TIE_EPSILON_DEFAULT_BPS

    result: dict[str, Any] = {"decision_id": str(decision.decision_id),
                             "candidates": len(rebuilt), "scores": scores,
                             "chosen": None, "tie_break": None, "fallback_used": False,
                             "costs": {item.node_id: item.cost_micro for item in scores},
                             "recorded_costs": {str(item.get("node_id")): int(item["cost_micro"])
                                                for item in decision.score_breakdown
                                                if isinstance(item, Mapping)
                                                and item.get("cost_micro") is not None}}
    if not scores:
        result["fallback_used"] = _fallback_flag(decision, rebuilt, values)
        return result

    selection = scoring.select(scores, epsilon_bps=epsilon)
    result["chosen"] = selection.winner.node_id
    result["tie_break"] = selection.tie_break
    result["fallback_used"] = _fallback_flag(decision, rebuilt, values)
    return result


def _fallback_flag(decision: models.Decision, rebuilt: Sequence[models.Candidate],
                   values: Mapping[str, Any]) -> bool:
    stamps = [candidate.quote_created_at for candidate in rebuilt
              if candidate.quote_created_at is not None]
    if not stamps:
        return False
    refresh = config_source.quotebook_refresh_s(values) if values \
        else facts.QUOTEBOOK_REFRESH_S
    return (decision.snapshot_ts - max(stamps)).total_seconds() > int(refresh)


def compare(recorded: models.Decision, recomputed: Mapping[str, Any], *,
            policy_drift: bool = False) -> dict[str, Any]:
    """比对：``chosen`` / ``tie_break`` / ``fallback_used`` + 成本分项（INV-03）。"""
    diffs: dict[str, Any] = {}
    recorded_chosen = recorded.chosen_node_id
    recomputed_chosen = recomputed.get("chosen")

    if recorded_chosen is not None:
        if recorded_chosen != recomputed_chosen:
            diffs["chosen"] = {"recorded": recorded_chosen, "recomputed": recomputed_chosen}
        if recorded.tie_break != recomputed.get("tie_break"):
            diffs["tie_break"] = {"recorded": recorded.tie_break,
                                  "recomputed": recomputed.get("tie_break")}
        # fallback_used 是策略相关的：policy 漂移时只做提示，不计入不一致（见模块 docstring）
        if not policy_drift and bool(recorded.fallback_used) != bool(recomputed.get("fallback_used")):
            diffs["fallback_used"] = {"recorded": bool(recorded.fallback_used),
                                      "recomputed": bool(recomputed.get("fallback_used"))}
        recorded_costs = recomputed.get("recorded_costs") or {}
        recomputed_costs = recomputed.get("costs") or {}
        for node_id, cost in recorded_costs.items():
            if node_id in recomputed_costs and int(recomputed_costs[node_id]) != int(cost):
                diffs.setdefault("cost_micro", {})[node_id] = {
                    "recorded": int(cost), "recomputed": int(recomputed_costs[node_id])}

    return {"decision_id": str(recorded.decision_id), "outcome": recorded.outcome,
            "consistent": not diffs, "diffs": diffs, "policy_drift": policy_drift,
            "compared": "chosen/tie_break/fallback_used" if recorded_chosen is not None
            else "skipped(no_chosen)"}


# --------------------------------------------------------------------------- 作业
@dataclass
class ReplayJob:
    """一次复算作业（T2 存注入 store；T4 落 ``replay_jobs`` 表）。"""

    job_id: uuid.UUID
    state: str
    requested_at: datetime
    from_ts: datetime
    to_ts: datetime
    decisions_total: int = 0
    consistent: int = 0
    report: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"job_id": str(self.job_id), "state": self.state,
                "requested_at": self.requested_at.isoformat(),
                "decisions_total": self.decisions_total,
                "consistent": self.consistent, "report": self.report}


class JobStore(Protocol):                                  # pragma: no cover - 协议
    def save(self, job: ReplayJob) -> None: ...
    def get(self, job_id: uuid.UUID) -> ReplayJob | None: ...


class InMemoryJobStore:
    """默认 job store：进程内存 + 结构化日志（重启丢历史，T4 换持久化实现）。"""

    def __init__(self) -> None:
        self._jobs: dict[uuid.UUID, ReplayJob] = {}

    def save(self, job: ReplayJob) -> None:
        self._jobs[job.job_id] = job
        log.info("scheduling.replay.job", extra={"event": "replay.job",
                                                "job_id": str(job.job_id), "state": job.state})

    def get(self, job_id: uuid.UUID) -> ReplayJob | None:
        return self._jobs.get(job_id)

    def __len__(self) -> int:                              # pragma: no cover - 观测
        return len(self._jobs)


_store: JobStore = InMemoryJobStore()


def set_store(store: JobStore | None) -> None:
    """注入 job store（``None`` = 复位成默认内存实现）。

    注意：不能用 ``store or default``——实现了 ``__len__`` 的 store 在空的时候是 falsy。
    """
    global _store
    _store = store if store is not None else InMemoryJobStore()


def current_store() -> JobStore:
    return _store


def acquire(c) -> None:
    """并发 1：抢事务级 advisory lock，抢不到 → ``409 + 40901``。"""
    with c.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_xact_lock(%s, %s)",
                    (LOCK_NAMESPACE, LOCK_REPLAY_JOB))
        row = cur.fetchone()
    if not row or not row[0]:
        raise ReplayBusy("已有复算作业在跑（并发 1）；请稍后重试", reason="replay_busy")


def run(c, *, from_ts: datetime, to_ts: datetime, decision_ids: Sequence[str] | None = None,
        policy: Mapping[str, Any] | None = None,
        limit: int = MAX_DECISIONS_PER_JOB) -> dict[str, Any]:
    """跑一次复算（只读）：返回差异报告；**不改**线上决策与日志。"""
    if from_ts >= to_ts:
        raise InvalidArgument("复算窗口非法：from 必须早于 to", field="from")
    if limit <= 0 or limit > MAX_DECISIONS_PER_JOB:
        raise InvalidArgument(f"limit 必须在 1–{MAX_DECISIONS_PER_JOB}", field="limit")
    records = decisions.window(c, from_ts=from_ts, to_ts=to_ts,
                              decision_ids=decision_ids, limit=limit)
    values = dict(policy or {})
    diffs: list[dict[str, Any]] = []
    drift = 0
    for record in records:
        policy_drift = bool(values) and \
            config_source.policy_version(values) != record.policy_version
        drift += 1 if policy_drift else 0
        recomputed = recompute(record, policy=values or None)
        comparison = compare(record, recomputed, policy_drift=policy_drift)
        if not comparison["consistent"]:
            diffs.append(comparison)
    report = {"total": len(records), "consistent": len(records) - len(diffs),
              "inconsistent": len(diffs), "policy_drift": drift, "diffs": diffs,
              "from": from_ts.isoformat(), "to": to_ts.isoformat()}
    log.info("scheduling.replay.done", extra={"event": "replay.done", **{
        key: report[key] for key in ("total", "consistent", "inconsistent")}})
    return report


def start(c, *, from_ts: datetime, to_ts: datetime,
          decision_ids: Sequence[str] | None = None,
          policy: Mapping[str, Any] | None = None,
          now: datetime | None = None, store: JobStore | None = None) -> ReplayJob:
    """受理并同步跑完一个复算作业（202 + job_id；并发 1）。"""
    moment = now or clock.utcnow()
    acquire(c)
    job = ReplayJob(job_id=models.uuid7(int(moment.timestamp() * 1_000_000)), state="queued",
                    requested_at=moment, from_ts=from_ts, to_ts=to_ts)
    target = store if store is not None else _store
    target.save(job)
    try:
        report = run(c, from_ts=from_ts, to_ts=to_ts, decision_ids=decision_ids, policy=policy)
    except Exception:
        job.state = "failed"
        target.save(job)
        raise
    job.state = "succeeded"
    job.decisions_total = int(report["total"])
    job.consistent = int(report["consistent"])
    job.report = report
    target.save(job)
    return job


def get_job(job_id: str | uuid.UUID, *, store: JobStore | None = None) -> ReplayJob:
    identifier = job_id if isinstance(job_id, uuid.UUID) else uuid.UUID(str(job_id))
    job = (store if store is not None else _store).get(identifier)
    if job is None:
        from .errors import NotFound

        raise NotFound("复算作业不存在", reason="replay_job_not_found", object="replay_job")
    return job


__all__ = ["MAX_DECISIONS_PER_JOB", "recompute", "compare", "ReplayJob", "JobStore",
           "InMemoryJobStore", "set_store", "current_store", "acquire", "run", "start", "get_job"]
