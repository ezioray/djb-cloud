# SPDX-License-Identifier: Apache-2.0
"""P1–P5 决策管线（M04 §6 流程 2 / INV-03 / INV-05 / INV-06 / INV-11）。

分层是刻意的：

* :func:`solve` —— **纯函数**：给定 ``route`` + 候选集快照 + 只读外部状态（配额 / 抢占 /
  队列），返回一条 ``Decision``（含 ``decision_id``）。同一输入必然同一输出，
  复算回放（``replay``）直接复用这条路径（INV-03）。
* :func:`execute` —— 带副作用的编排：收集快照 → ``solve`` → 写决策日志 → 成交锁 →
  配额计数 → 发事件，全部在**同一个本地事务**里（M04 §6「撮合与决策各自本地事务」）。

P1–P5 落点：

===  ==============================================  ==========================
步   本模块落点                                       失败动作
===  ==============================================  ==========================
P1   ``candidates.collect``（F1–F5 淘汰码）            候选集空 → P4 → 拒绝 45001
P2   ``scoring.score_all`` + ``scoring.select``        缺失 ρ/κ → 兜底并标记
P3   ``quota.decide`` + 反亲和（开关控制）            全部违反 → P4
P4   ``preempt.evaluate``                             无对象 → 排队（必给 ETA）
P5   ``decisions.record`` + ``matching.create_booking`` + ``quota.reserve``
===  ==============================================  ==========================

**决策时延预算**（INV-05）在 :func:`execute` 里测量，只写 ``reason_codes``（``budget_exceeded``）
与结构化日志，**不改变** ``chosen`` / ``tie_break`` / ``fallback_used``——否则同一锚点的
两次复算会因为机器快慢不同而出现假差异（复算只比对这三项，见 M04 §6 流程 3）。
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from . import (candidates, clock, config_source, decisions, facts, features, matching, models,
               preempt, quota, scoring)

log = logging.getLogger("djb.scheduling.pipeline")


# --------------------------------------------------------------------------- 上下文
@dataclass(frozen=True)
class RouteContext:
    """``solve`` 的只读外部状态（全部由 :func:`build_context` 收齐，solve 不再碰 DB）。"""

    policy: Mapping[str, Any]
    quota_snapshot: Mapping[str, Any] = field(default_factory=dict)
    platform_concurrency: int | None = None
    terminal_concurrency: int | None = None
    busy_hosts: frozenset[str] = frozenset()
    victims: tuple[Mapping[str, Any], ...] = ()
    preempt_used: int = 0
    checkpoint_age_s: int | None = None
    queue_level_pct: int | None = None
    queue_eta_s: int | None = None


@dataclass(frozen=True)
class SolveResult:
    """solve 的输出 + 落库所需的旁路信息（P5 用）。"""

    decision: models.Decision
    match: matching.MatchPlan | None = None


# --------------------------------------------------------------------------- solve（纯函数）
def solve(route: candidates.RouteInput, snapshot: candidates.SnapshotResult,
          ctx: RouteContext, *, now: datetime | None = None) -> SolveResult:
    """P1–P5 的纯函数求解：同一 (输入, 快照, 上下文) ⇒ 同一决策。"""
    moment = now or clock.utcnow()
    stamp = clock.truncate(moment)
    digest = decisions.request_digest(route)
    identifier = decisions.decision_id(stamp, snapshot.quote_version,
                                       config_source.policy_version(ctx.policy), digest)
    base = dict(decision_id=identifier, trace_id=route.trace_id, attempt_no=route.attempt_no,
                snapshot_ts=stamp, quote_version=snapshot.quote_version,
                policy_version=config_source.policy_version(ctx.policy),
                request_digest=digest, candidates=snapshot.as_inputs(),
                eliminated=list(snapshot.eliminated), decided_at=moment)

    stale = _stale(snapshot, ctx, moment)
    scores = scoring.score_all(snapshot.candidates, tier=route.kind, config=ctx.policy)
    if not scores:
        return _no_candidate_outcome(route, ctx, base, snapshot, stale)

    epsilon = config_source.tie_break_epsilon_bps(ctx.policy)
    selection = scoring.select(scores, epsilon_bps=epsilon)
    ranked = scoring.ranked(scores, epsilon_bps=epsilon)

    feasible: list[models.Score] = []
    blocked: list[str] = []
    visible: list[str] = []          # P3 的可见标记（降权 / 夹取 / 占比），赢家生效
    for scored in ranked:
        candidate = _candidate_by_node(snapshot, scored.node_id)
        if candidate is None:                              # pragma: no cover - 防御
            continue
        verdict = quota.decide(
            snapshot=ctx.quota_snapshot, node_max_qps=candidate.max_qps,
            platform_concurrency=ctx.platform_concurrency,
            terminal_concurrency=ctx.terminal_concurrency,
            limit_pct=config_source.max_tenant_share_pct(ctx.policy),
            required_units=1)
        if not verdict.allowed:
            blocked.extend(verdict.reason_codes or ("quota_exhausted",))
            continue
        if not _affinity_ok(candidate, ctx):
            blocked.append("affinity_violation")
            continue
        if not visible:                                   # 只记首个可行解（= 赢家）的标记
            visible = [code for code in verdict.reason_codes if code != "quota_exhausted"]
        feasible.append(scored)

    if not feasible:
        return _no_feasible_outcome(route, ctx, base, snapshot, ranked, blocked, stale)

    prices = _price_candidates(route, snapshot, feasible, ctx, moment)
    if not prices:
        # 有可行解但都算不出成交价（例如出价区间与报价在 P1 之后又被收紧）：
        # 按「无交集」处理，绝不假装成交（验收 ③）。
        return _no_candidate_outcome(route, ctx, base, snapshot, stale,
                                     base_reason="no_intersection")

    winner_score, match = prices[0]
    fallbacks = [_chosen_payload(route, _candidate_by_node(snapshot, scored.node_id))
                 for scored, _plan in prices[1:1 + facts.MAX_REDISPATCH]
                 if _candidate_by_node(snapshot, scored.node_id) is not None]
    reason_codes = list(dict.fromkeys(visible + blocked + list(_visible_flags(winner_score))))
    if stale:
        reason_codes.append("stale_snapshot")
    outcome = "fallback" if stale else "routed"

    decision = models.Decision(
        **base, score_breakdown=[item.as_breakdown() for item in scores],
        chosen=_chosen_payload(route, _candidate_by_node(snapshot, winner_score.node_id)),
        tie_break=selection.tie_break, price_minor=match.price_minor,
        fallbacks=fallbacks, reason_codes=reason_codes, outcome=outcome,
        fallback_used=stale, eta_seconds=_eta_seconds(route, ctx))
    return SolveResult(decision=decision, match=match)


def _candidate_by_node(snapshot: candidates.SnapshotResult, node_id: str) \
        -> models.Candidate | None:
    for candidate in snapshot.candidates:
        if candidate.node_id == node_id:
            return candidate
    return None


def _stale(snapshot: candidates.SnapshotResult, ctx: RouteContext, moment: datetime) -> bool:
    """报价簿是否「上一版」（M04 §7）：最新报价建立时刻已超刷新窗口。

    只看候选集里的报价——它们的 ``quote_created_at`` 是**输入的一部分**，
    所以复算能原样重算出同一个 ``fallback_used``（INV-03）。
    """
    stamps = [candidate.quote_created_at for candidate in snapshot.candidates
              if candidate.quote_created_at is not None]
    if not stamps:
        return False
    refresh = config_source.quotebook_refresh_s(ctx.policy)
    return (moment - max(stamps)).total_seconds() > refresh


def _visible_flags(scored: models.Score) -> tuple[str, ...]:
    """打分侧的可见标记（缺失兜底；不含阈值）。"""
    flags: list[str] = []
    if scored.rep_missing:
        flags.append("rep_missing")
    if scored.load_missing:
        flags.append("load_missing")
    return tuple(flags)


def _affinity_ok(candidate: models.Candidate, ctx: RouteContext) -> bool:
    """反亲和硬约束（§4.7.4 第 4 条）：开关关闭时不做淘汰（不拿猜测的拓扑动手）。"""
    if not features.enabled("scheduling.affinity_hard_constraint"):
        return True
    host = candidate.physical_host_id
    if host is None:
        return True
    return host not in ctx.busy_hosts


def _price_candidates(route: candidates.RouteInput, snapshot: candidates.SnapshotResult,
                      feasible: list[models.Score], ctx: RouteContext, moment: datetime) \
        -> list[tuple[models.Score, matching.MatchPlan]]:
    """按 P2/tie-break 的顺序算成交价；顺序即兜底链顺序（确定性）。

    取价策略来自 ``billing.price_strategy``（M04 §8.1），缺省 mid。
    """
    strategy = config_source.price_strategy(ctx.policy)
    result: list[tuple[models.Score, matching.MatchPlan]] = []
    for scored in feasible:
        candidate = _candidate_by_node(snapshot, scored.node_id)
        if candidate is None:                              # pragma: no cover - 防御
            continue
        quote = _quote_stub(candidate, moment)
        # route 路径没有「已落库的出价行」：上界取请求的 max_price（spec BidRequest 缺省语义）
        plan = matching.plan(None, [quote], strategy=strategy,
                             request_max_minor=route.max_price_minor)
        if isinstance(plan, matching.NoMatch):
            continue
        result.append((scored, plan))
    return result


def _quote_stub(candidate: models.Candidate, moment: datetime) -> models.Quote:
    """候选里已经带了报价输入（区间 / 单位 + 真实 quote_id），撮合只需要这些字段。

    ``id`` 必须是**真实报价主键**：成交锁 ``bookings.quote_id`` 对 ``quotes(id)`` 有外键。
    """
    return models.Quote(id=_as_uuid(candidate.quote_id), node_id=candidate.node_id,
                        access=candidate.access, model=candidate.model, unit=candidate.unit,
                        ask_price_minor=candidate.ask_price_minor,
                        price_max_minor=candidate.price_max_minor,
                        currency=facts.CURRENCY, ttl_s=facts.BOOKING_TTL_S, state="active",
                        quote_version=candidate.quote_version, created_at=moment,
                        expires_at=moment)


def _as_uuid(value: Any) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):                     # pragma: no cover - 防御
        return uuid.UUID(int=0)


def _chosen_payload(route: candidates.RouteInput, candidate: models.Candidate | None) \
        -> dict[str, Any] | None:
    if candidate is None:                                    # pragma: no cover - 防御
        return None
    return {"node_id": candidate.node_id, "upstream_id": "",
            "access": candidate.access, "model": route.model, "unit": candidate.unit,
            "quote_id": candidate.quote_id}


def _eta_seconds(route: candidates.RouteInput, ctx: RouteContext) -> int | None:
    """ETA：token 档不给数（不排队）；其余用队列估计，缺数据时用成交锁 TTL 兜底。"""
    if route.kind == "realtime":
        return None
    if ctx.queue_eta_s is not None:
        return int(ctx.queue_eta_s)
    return facts.BOOKING_TTL_S


def _no_candidate_outcome(route: candidates.RouteInput, ctx: RouteContext, base: dict[str, Any],
                          snapshot: candidates.SnapshotResult, stale: bool,
                          *, base_reason: str = "no_candidates") -> SolveResult:
    """P1 空 / 无交集：走 P4（抢占 → 排队 → 拒绝），拒绝必须给 45001 + 三个动作。"""
    outcome = preempt.evaluate(tier=route.kind, victims=ctx.victims,
                               budget_used=ctx.preempt_used,
                               budget_limit=config_source.preempt_budget_per_h(ctx.policy),
                               checkpoint_age_s=ctx.checkpoint_age_s,
                               queue_level_pct=ctx.queue_level_pct,
                               eta_seconds=ctx.queue_eta_s)
    reason_codes = list(dict.fromkeys((base_reason,) + tuple(outcome.reason_codes)))
    if stale:
        reason_codes.append("stale_snapshot")

    if outcome.outcome == "preempt":
        # 抢占成功等价于「换节点失败但抢到了位置」：仍按排队处理（T4 才真正执行让路）
        decision = models.Decision(**base, score_breakdown=[], chosen=None,
                                   preempt_plan=list(outcome.plan), outcome="queued",
                                   eta_seconds=outcome.eta_seconds or facts.PREEMPT_GRACEFUL_S,
                                   reason_codes=reason_codes)
        return SolveResult(decision=decision)

    decision = models.Decision(
        **base, score_breakdown=[], chosen=None, preempt_plan=list(outcome.plan),
        outcome=outcome.outcome, eta_seconds=outcome.eta_seconds, reason_codes=reason_codes)
    return SolveResult(decision=decision)


def _no_feasible_outcome(route: candidates.RouteInput, ctx: RouteContext, base: dict[str, Any],
                         snapshot: candidates.SnapshotResult, ranked: list[models.Score],
                         blocked: list[str], stale: bool) -> SolveResult:
    """P3 全部违反：走 P4（§4.7.3 P3 失败动作：冻结建议 / 等待 / 转慢任务）。"""
    outcome = preempt.evaluate(tier=route.kind, victims=ctx.victims,
                               budget_used=ctx.preempt_used,
                               budget_limit=config_source.preempt_budget_per_h(ctx.policy),
                               checkpoint_age_s=ctx.checkpoint_age_s,
                               queue_level_pct=ctx.queue_level_pct,
                               eta_seconds=ctx.queue_eta_s)
    reason_codes = list(dict.fromkeys(tuple(blocked) + ("quota_exhausted",)
                                      + tuple(outcome.reason_codes)))
    if stale:
        reason_codes.append("stale_snapshot")
    decision = models.Decision(
        **base, score_breakdown=[item.as_breakdown() for item in ranked], chosen=None,
        preempt_plan=list(outcome.plan), outcome=outcome.outcome,
        eta_seconds=outcome.eta_seconds, reason_codes=reason_codes)
    return SolveResult(decision=decision)


# --------------------------------------------------------------------------- 上下文收集
def build_context(c, route: candidates.RouteInput, *, policy: Mapping[str, Any] | None = None,
                  platform_concurrency: int | None = None,
                  terminal_concurrency: int | None = None,
                  checkpoint_age_s: int | None = None,
                  queue_level_pct: int | None = None,
                  queue_eta_s: int | None = None) -> RouteContext:
    """把 P3/P4 需要的只读状态收齐（DB 读 + 注入 provider），``solve`` 之后不再碰 DB。"""
    values = dict(policy) if policy is not None else config_source.load(c, route.tenant_id)
    return RouteContext(policy=values,
                        quota_snapshot=quota.snapshot(c, _as_uuid(route.tenant_id), route.model),
                        platform_concurrency=platform_concurrency,
                        terminal_concurrency=terminal_concurrency,
                        busy_hosts=frozenset(),
                        victims=(),
                        preempt_used=0,
                        checkpoint_age_s=checkpoint_age_s,
                        queue_level_pct=queue_level_pct,
                        queue_eta_s=queue_eta_s)


# --------------------------------------------------------------------------- execute（带事务）
def execute(c, route: candidates.RouteInput, *, now: datetime | None = None,
            policy: Mapping[str, Any] | None = None,
            context: RouteContext | None = None,
            platform_concurrency: int | None = None,
            terminal_concurrency: int | None = None,
            checkpoint_age_s: int | None = None,
            queue_level_pct: int | None = None,
            queue_eta_s: int | None = None,
            request_id: str | None = None) -> tuple[models.Decision, bool]:
    """跑完整条管线并落库（调用方负责事务边界）。

    返回 ``(decision, created)``；``created=False`` 表示同锚点已存在（幂等复用，
    **不会**重复锁量 / 重复计数）。
    """
    moment = now or clock.utcnow()
    started = time.perf_counter()
    values = dict(policy) if policy is not None else config_source.load(c, route.tenant_id)
    ctx = context or build_context(c, route, policy=values,
                                   platform_concurrency=platform_concurrency,
                                   terminal_concurrency=terminal_concurrency,
                                   checkpoint_age_s=checkpoint_age_s,
                                   queue_level_pct=queue_level_pct,
                                   queue_eta_s=queue_eta_s)

    snapshot = candidates.collect(
        c, route, now=moment,
        freshness_s=config_source.candidate_freshness_s(values),
        quotebook_refresh_s=config_source.quotebook_refresh_s(values))
    result = solve(route, snapshot, ctx, now=moment)
    decision = result.decision

    elapsed_ms = (time.perf_counter() - started) * 1_000
    budget = facts.DECISION_LATENCY_P99_MS["token"] if route.kind == "realtime" \
        else facts.DECISION_LATENCY_P99_MS["task"]
    if elapsed_ms > budget:
        decision.reason_codes = list(decision.reason_codes) + ["budget_exceeded"]
        log.warning("scheduling.decision.budget_exceeded",
                    extra={"event": "decision.budget_exceeded", "elapsed_ms": round(elapsed_ms, 2),
                           "budget_ms": budget, "kind": route.kind})

    stored, created = decisions.record(c, decision)
    if created and result.match is not None and stored.chosen is not None:
        _commit_p5(c, route, snapshot, result, stored, moment, request_id)
    from . import events

    events.routing_decided(stored, trace_id=route.trace_id or stored.trace_id,
                           occurred_at=moment)
    return stored, created


def _commit_p5(c, route: candidates.RouteInput, snapshot: candidates.SnapshotResult,
               result: SolveResult, stored: models.Decision, moment: datetime,
               request_id: str | None) -> None:
    """P5 落库：成交锁 + 配额计数（与决策日志同事务，M04 §6「P5 提交」）。"""
    match = result.match
    if match is None:                                        # pragma: no cover - 防御
        return
    booking = matching.create_booking(c, match, tenant_id=_as_uuid(route.tenant_id),
                                      request_id=request_id or route.trace_id, now=moment,
                                      trace_id=route.trace_id)
    quota.reserve(c, tenant_id=_as_uuid(route.tenant_id), model=route.model, now=moment,
                  units=1, spend_minor=int(stored.price_minor or 0))
    log.info("scheduling.p5.committed", extra={"event": "p5.committed",
                                               "decision_id": str(stored.decision_id),
                                               "booking_id": booking.booking_id,
                                               "node_id": booking.node_id})


__all__ = ["RouteContext", "SolveResult", "solve", "build_context", "execute"]
