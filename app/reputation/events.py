# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 事件消费与重算（§4.2 消费方 / §6.1 结算计提 / §6.2 邀请奖励 / §4.3 定时重算）。

本模块消费两个已登记事件（02-events §3 已把 M07 列为消费方）：

* ``usage.settled``（M05）→ 追加指标事实 + 计提 COP（``source=usage``，按
  ``points.transfer_lock_days`` 锁定）+ 邀请奖励（``source=invite``，§6.2）；
* ``account.state.changed``（M01）→ 同步 COP 账户状态；``frozen/closing/closed`` 立即
  停止转让与兑换（§7「账户不可用 → 拒绝转让与兑换，已得 COP 保留」）。

幂等（§3「幂等与唯一」）：

* 事件层：``reputation_events (account_id, metric, ref_id)`` 唯一——同一 ``usage_id`` 只落一列事实；
* 账本层：``points_journal.request_id`` 唯一——同一 ``usage_id`` 的计提只记一次；
* 两层都命中时直接返回 ``duplicate``，**不改余额**（§7「事件重复 → 幂等丢弃」）。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from app import points as cop_ledger

from . import clock, cop, errors, invites, outbox, score, store
from .facts import DEFAULT_CONFIG, ReputationConfig
from .models import ReputationScore

__all__ = [
    "consume_usage_settled", "consume_account_state_changed", "record_metrics",
    "latest_metrics", "refresh_score", "recompute_account", "METRIC_KEYS",
]

METRIC_KEYS = ("success_rate", "latency_ok_rate", "online_rate", "yield_response")
_ACCOUNT_STATES = ("normal", "frozen", "closing", "closed")


def _payload(envelope: Mapping[str, Any]) -> dict[str, Any]:
    payload = envelope.get("payload")
    return dict(payload) if isinstance(payload, Mapping) else dict(envelope)


def _occurred_at(envelope: Mapping[str, Any], fallback: datetime) -> datetime:
    raw = envelope.get("occurred_at")
    parsed = clock.parse_datetime(raw) if isinstance(raw, str) else raw
    return clock.as_utc(parsed) if isinstance(parsed, datetime) else fallback


# --------------------------------------------------------------------------- 消费
def consume_usage_settled(conn: Any, envelope: Mapping[str, Any], *,
                          config: ReputationConfig = DEFAULT_CONFIG,
                          now: datetime | None = None) -> dict[str, Any]:
    """``usage.settled`` → 事实 + 计提（+ 邀请奖励）。返回处理摘要（含 ``duplicate`` 标记）。"""
    moment = clock.as_utc(now)
    payload = _payload(envelope)
    account_id = str(payload.get("account_id") or envelope.get("aggregate_id") or "")
    usage_id = str(payload.get("usage_id") or "")
    if not account_id or not usage_id:
        raise errors.InvalidArgument("usage.settled 缺少 account_id / usage_id")
    occurred_at = _occurred_at(envelope, moment)
    try:
        amount_minor = int(payload.get("final_amount_minor") or 0)
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument("final_amount_minor 必须是整数") from exc

    inserted = store.insert_event(conn, account_id, metric="usage_settled",
                                  value=amount_minor, weight=0, delta=0, ref_id=usage_id,
                                  occurred_at=occurred_at)
    if not inserted:
        return {"status": "duplicate", "account_id": account_id, "usage_id": usage_id,
                "units": 0, "invite_units": 0}

    pol = cop.policy(conn)
    units = config.accrual_units(amount_minor, pol.redeem_cop_per_usd)
    result: dict[str, Any] = {"status": "settled", "account_id": account_id,
                              "usage_id": usage_id, "units": units, "invite_units": 0}
    if units <= 0:
        return result

    earned = cop.post_earn(conn, account_id, units, source="usage", ref_id=usage_id,
                           request_id=f"m07:usage:{usage_id}", lock_days=pol.lock_days,
                           now=occurred_at)
    outbox.enqueue(conn, outbox.cop_earned(
        account_id=account_id, units=units, source="usage", ref_id=usage_id,
        lock_until=earned["lock_until"], occurred_at=occurred_at,
        journal_id=earned["journal_id"]))
    result["journal_id"] = earned["journal_id"]
    result["lock_until"] = clock.isoformat(earned["lock_until"])

    # §6.2 邀请奖励：只对「已绑定且未过窗口」的被邀请人生效，不追溯
    bound = invites.bound_invite_of(conn, account_id)
    if bound is not None and bound.bound_at is not None:
        window_end = invites.reward_window_end(bound.bound_at, config.invite_months)
        if occurred_at < window_end:
            reward = config.invite_reward_units(units)
            if reward > 0:
                inviter_earned = cop.post_earn(
                    conn, bound.inviter_id, reward, source="invite", ref_id=usage_id,
                    request_id=f"m07:invite:{usage_id}", now=occurred_at)
                outbox.enqueue(conn, outbox.cop_earned(
                    account_id=bound.inviter_id, units=reward, source="invite",
                    ref_id=usage_id, lock_until=None, occurred_at=occurred_at,
                    journal_id=inviter_earned["journal_id"]))
                result["invite_units"] = reward
                result["inviter_id"] = bound.inviter_id
    return result


def consume_account_state_changed(conn: Any, envelope: Mapping[str, Any], *,
                                  now: datetime | None = None) -> dict[str, Any]:  # noqa: ARG001
    """``account.state.changed`` → 同步 COP 账户状态（拒绝转让 / 兑换的依据）。"""
    payload = _payload(envelope)
    account_id = str(payload.get("account_id") or envelope.get("aggregate_id") or "")
    to_state = str(payload.get("to") or "")
    if not account_id:
        raise errors.InvalidArgument("account.state.changed 缺少 account_id")
    if to_state not in _ACCOUNT_STATES:
        raise errors.InvalidArgument(f"未知账户状态：{to_state or '(空)'}")
    cop.ensure_account(conn, account_id)
    cop_ledger.set_account_state(conn, account_id, to_state, actor="system:m01")
    return {"account_id": account_id, "state": to_state,
            "event_id": str(envelope.get("event_id") or "")}


# --------------------------------------------------------------------------- 指标
def record_metrics(conn: Any, account_id: str, metrics: Mapping[str, Any], *,
                   ref_id: str, occurred_at: datetime | None = None,
                   config: ReputationConfig = DEFAULT_CONFIG) -> int:
    """把四项分项写成指标事实（每项一条；同一 ``ref_id`` 幂等）。返回落库条数。"""
    moment = clock.as_utc(occurred_at)
    readings = score.metrics_from(metrics)
    written = 0
    for key in METRIC_KEYS:
        if store.insert_event(conn, account_id, metric=key, value=getattr(readings, key),
                              weight=int(config.weights[key]),
                              delta=int(getattr(readings, key)) * int(config.weights[key]) // 10_000,
                              ref_id=f"{ref_id}:{key}", occurred_at=moment):
            written += 1
    return written


def latest_metrics(conn: Any, account_id: str) -> dict[str, int]:
    """读每项指标的最新观测（没有就是 0；不猜、不插补）。"""
    values = {key: 0 for key in METRIC_KEYS}
    with conn.cursor() as cur:
        for key in METRIC_KEYS:
            cur.execute(
                """SELECT value FROM reputation_events
                    WHERE account_id = %s AND metric = %s
                    ORDER BY occurred_at DESC, id DESC LIMIT 1""", (account_id, key))
            row = cur.fetchone()
            if row is not None:
                values[key] = int(row[0])
    return values


def penalties_from_events(conn: Any, account_id: str, *, since: datetime | None = None
                          ) -> dict[str, int]:
    """惩罚项次数（``metric='penalty'`` 的事实的 ``ref_id`` 前缀即惩罚类型）。"""
    params: list[Any] = [account_id]
    clause = ""
    if since is not None:
        clause = " AND occurred_at >= %s"
        params.append(since)
    counts: dict[str, int] = {}
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT value, ref_id FROM reputation_events
                 WHERE account_id = %s AND metric = 'penalty'{clause}""", tuple(params))
        for value, ref_id in cur.fetchall():
            kind = str(ref_id or "").split(":", 1)[0]
            counts[kind] = counts.get(kind, 0) + int(value or 1)
    return counts


def _cumulative_cop(conn: Any, account_id: str) -> int:
    """累计 COP（只算「赚来」的：``usage`` / ``invite``；转让与人工授予不计入等级门槛）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT COALESCE(SUM(amount), 0) FROM v_m07_cop_ledger
                WHERE account_id = %s AND direction = 'credit'
                  AND source IN ('usage', 'invite')""", (account_id,))
        return int(cur.fetchone()[0])


# --------------------------------------------------------------------------- 重算
def refresh_score(conn: Any, account_id: str, *, metrics: Mapping[str, Any] | None = None,
                  penalties: Mapping[str, int] | None = None, stability_bps: int | None = None,
                  config: ReputationConfig = DEFAULT_CONFIG, now: datetime | None = None,
                  manual_tier: bool | None = None) -> ReputationScore:
    """规则重算一个账户（纯函数 + 覆盖写 + 变化才发 ``reputation.changed``）。"""
    moment = clock.as_utc(now)
    previous = store.get_score(conn, account_id)
    readings = metrics if metrics is not None else latest_metrics(conn, account_id)
    penalty_items = penalties if penalties is not None else penalties_from_events(conn, account_id)
    stability = stability_bps if stability_bps is not None else int(
        score.metrics_from(readings).online_rate)
    days = score.days_between(previous.tier_since, moment) if previous else 0
    manual = bool(manual_tier) if manual_tier is not None \
        else bool(previous.manual_tier) if previous else False
    evaluation = score.evaluate(
        metrics=readings, penalties=penalty_items, stability_bps=stability,
        cumulative_cop=_cumulative_cop(conn, account_id),
        previous_score=previous.score if previous else None,
        previous_tier=previous.tier if previous else None,
        tier_since_days=days, manual_tier=manual, config=config)
    tier_since = previous.tier_since if previous and previous.tier == evaluation.tier else moment
    row = store.upsert_score(
        conn, account_id, score=evaluation.score, tier=evaluation.tier,
        quality_coef=evaluation.quality_coef, stability_coef=evaluation.stability_coef,
        window_days=evaluation.window_days, policy_version=evaluation.policy_version,
        computed_at=moment, tier_since=tier_since,
        prev_tier=evaluation.prev_tier, manual_tier=manual,
        reasons=evaluation.reasons)
    if evaluation.changed:
        outbox.enqueue(conn, outbox.reputation_changed(
            account_id=account_id, score=evaluation.score, tier=evaluation.tier,
            reasons=list(evaluation.reasons), policy_version=evaluation.policy_version,
            occurred_at=moment))
    return row


def recompute_account(conn: Any, account_id: str, *,
                      config: ReputationConfig = DEFAULT_CONFIG,
                      now: datetime | None = None) -> dict[str, Any]:
    """单账户复算（§4.3 增量重算的单账户入口；也可被运营按需触发）。"""
    row = refresh_score(conn, account_id, config=config, now=now)
    return {"account_id": account_id, "score": row.score, "tier": row.tier,
            "computed_at": clock.isoformat(row.computed_at)}
