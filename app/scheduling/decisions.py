# SPDX-License-Identifier: AGPL-3.0-or-later
"""决策日志（M04 §3 RoutingDecision / §5 routing_decisions / INV-03 / INV-11）。

三条硬规则：

* **四元锚点 ⇒ 同一决策**（INV-03）：``decision_id`` 由
  ``(snapshot_ts, quote_version, policy_version, request_digest)`` **确定性派生**（UUIDv5）。
  同一锚点并发 100 次只会有一行，其余请求读回同一条决策（验收 ②）。
* **只追加**（INV-11）：库层 ``m04_routing_decisions_guard`` 拒绝 UPDATE；DELETE 只允许
  归档作业（``SET LOCAL m04.archive = 'on'``）。写入失败 ⇒ 熔断新决策（503 + 50001）。
* **只存元数据与摘要**（INV-12）：``candidates`` 只放输入快照（node_id / access / model /
  报价 / ρ / κ），``score_breakdown`` 只放分项，**不含**正文、凭据、阈值。

``request_digest`` 不含 ``trace_id``：trace 是链路标识，同一业务请求换一次 trace 仍是
同一个「输入」——把它算进摘要会让复算对不上（INV-03 的可比性）。
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Sequence

from . import clock, facts, models
from .errors import DecisionLogUnavailable, NotFound

log = logging.getLogger("djb.scheduling.decisions")

COLUMNS = ("decision_id", "trace_id", "attempt_no", "snapshot_ts", "quote_version",
           "policy_version", "request_digest", "candidates", "eliminated", "score_breakdown",
           "chosen", "tie_break", "preempt_plan", "fallbacks", "reason_codes", "eta_seconds",
           "price_minor", "outcome", "fallback_used", "decided_at")
SELECT_COLUMNS = ", ".join(COLUMNS)

#: decision_id 的 UUIDv5 命名空间（M04 固定；改它等于改锚点语义，必须走契约变更）
DECISION_NAMESPACE = uuid.UUID("6f0d4a1e-8b3c-5d21-9a7e-4c1b2f3d4e5a")

#: 归档口径（M04 CR-3：12 个月）
RETENTION_MONTHS = facts.DECISION_RETENTION_MONTHS


def request_digest(route_input: Any) -> str:
    """``request_digest``：路由输入的规范化摘要（排除 trace_id / attempt_no）。

    ``route_input`` 是 ``candidates.RouteInput``（有 ``as_dict()``）或等价 dict。
    """
    payload = route_input.as_dict() if hasattr(route_input, "as_dict") else dict(route_input)
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def decision_id(snapshot_ts: datetime, quote_version: int, policy_version: str,
                digest: str) -> uuid.UUID:
    """四元锚点 → ``decision_id``（确定性；INV-03 的唯一性来源）。"""
    stamp = clock.truncate(snapshot_ts).isoformat()
    material = f"{facts.EVENT_PRODUCER}|{stamp}|{int(quote_version)}|{policy_version}|{digest}"
    return uuid.uuid5(DECISION_NAMESPACE, material)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def record(c, decision: models.Decision) -> tuple[models.Decision, bool]:
    """写入决策日志；同锚点已存在则读回既有行（``created=False``）。

    写失败一律抛 :class:`DecisionLogUnavailable`（INV-11：**禁止「不记录继续」**）。
    """
    try:
        with c.cursor() as cur:
            cur.execute(
                """INSERT INTO routing_decisions
                       (decision_id, trace_id, attempt_no, snapshot_ts, quote_version,
                        policy_version, request_digest, candidates, eliminated,
                        score_breakdown, chosen, tie_break, preempt_plan, fallbacks,
                        reason_codes, eta_seconds, price_minor, outcome, fallback_used,
                        decided_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb,
                           %s::jsonb, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s)
                   ON CONFLICT ON CONSTRAINT routing_decisions_anchor_uq DO NOTHING""",
                (decision.decision_id, decision.trace_id, decision.attempt_no,
                 decision.snapshot_ts, decision.quote_version, decision.policy_version,
                 decision.request_digest, _json(decision.candidates),
                 _json(decision.eliminated), _json(decision.score_breakdown),
                 _json(decision.chosen) if decision.chosen is not None else None,
                 decision.tie_break, _json(decision.preempt_plan),
                 _json(decision.fallbacks), _json(decision.reason_codes),
                 decision.eta_seconds, decision.price_minor, decision.outcome,
                 decision.fallback_used, decision.decided_at or clock.utcnow()))
            created = cur.rowcount == 1
    except Exception as exc:                                 # pragma: no cover - 熔断分支
        log.error("scheduling.decision.log_write_failed",
                  extra={"event": "decision.log_write_failed",
                         "decision_id": str(decision.decision_id)})
        raise DecisionLogUnavailable("决策日志写入失败：已熔断本次决策（INV-11）",
                                     reason="decision_log_unavailable") from exc

    if created:
        return decision, True
    existing = get(c, decision.decision_id)
    log.info("scheduling.decision.reused", extra={"event": "decision.reused",
                                                  "decision_id": str(decision.decision_id)})
    return existing, False


def get(c, decision_id_value: str | uuid.UUID) -> models.Decision:
    try:
        identifier = decision_id_value if isinstance(decision_id_value, uuid.UUID) \
            else uuid.UUID(str(decision_id_value))
    except (ValueError, AttributeError) as exc:
        raise NotFound("决策 ID 形态非法", reason="decision_not_found",
                       object="decision") from exc
    with c.cursor() as cur:
        cur.execute(f"SELECT {SELECT_COLUMNS} FROM routing_decisions WHERE decision_id = %s",
                    (identifier,))
        row = cur.fetchone()
    if row is None:
        raise NotFound("决策不存在", reason="decision_not_found", object="decision")
    return models.Decision.from_row(row)


def find_anchor(c, *, snapshot_ts: datetime, quote_version: int, policy_version: str,
                digest: str) -> models.Decision | None:
    """按四元锚点查既有决策（不含插入；幂等预检 / 排障用）。"""
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {SELECT_COLUMNS} FROM routing_decisions
                 WHERE snapshot_ts = %s AND quote_version = %s AND policy_version = %s
                   AND request_digest = %s""",
            (snapshot_ts, int(quote_version), policy_version, digest))
        row = cur.fetchone()
    return models.Decision.from_row(row) if row else None


def window(c, *, from_ts: datetime, to_ts: datetime, decision_ids: Sequence[str] | None = None,
           limit: int = 10_000) -> list[models.Decision]:
    """复算窗口：按 ``decided_at`` 取一段（可按 decision_id 收窄）；**只读**。"""
    clauses = ["decided_at >= %s", "decided_at < %s"]
    params: list[Any] = [from_ts, to_ts]
    if decision_ids:
        clauses.append("decision_id = ANY(%s)")
        params.append([uuid.UUID(str(item)) for item in decision_ids])
    where = " AND ".join(clauses)
    params.append(int(limit))
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {SELECT_COLUMNS} FROM routing_decisions
                 WHERE {where} ORDER BY decided_at, decision_id LIMIT %s""", params)
        return [models.Decision.from_row(row) for row in cur.fetchall()]


def retention_cutoff(now: datetime | None = None) -> datetime:
    """12 个月归档口径（CR-3）：早于该时刻的决策可导出后删除（T4/M16 作业）。"""
    moment = now or clock.utcnow()
    months = RETENTION_MONTHS
    year = moment.year - (1 if moment.month <= months else 0)
    month = moment.month - months + (12 if moment.month <= months else 0)
    try:
        return moment.replace(year=year, month=month)
    except ValueError:                                       # 2/29 → 2/28（闰日兜底）
        return moment.replace(year=year, month=month, day=28)


def archive_candidates(c, *, now: datetime | None = None) -> list[models.Decision]:
    """待归档决策（早于 cutoff）；只读，删除由归档作业显式执行。"""
    cutoff = retention_cutoff(now)
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {SELECT_COLUMNS} FROM routing_decisions
                 WHERE decided_at < %s ORDER BY decided_at, decision_id""", (cutoff,))
        return [models.Decision.from_row(row) for row in cur.fetchall()]


def count_by_outcome(c, *, from_ts: datetime, to_ts: datetime) -> dict[str, int]:
    """窗口内的决策分布（自检 / 复算报告用）。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT outcome, count(*) FROM routing_decisions
                WHERE decided_at >= %s AND decided_at < %s GROUP BY outcome""",
            (from_ts, to_ts))
        return {str(row[0]): int(row[1]) for row in cur.fetchall()}


def replay_anchor(decision: models.Decision) -> dict[str, Any]:
    """复算用的四元锚点（原样回显，便于对账）。"""
    return {"snapshot_ts": decision.snapshot_ts.isoformat(),
            "quote_version": decision.quote_version,
            "policy_version": decision.policy_version,
            "request_digest": decision.request_digest}


__all__ = ["COLUMNS", "SELECT_COLUMNS", "DECISION_NAMESPACE", "RETENTION_MONTHS",
           "request_digest", "decision_id", "record", "get", "find_anchor", "window",
           "retention_cutoff", "archive_candidates", "count_by_outcome", "replay_anchor"]
