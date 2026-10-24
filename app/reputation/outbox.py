# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 事件 outbox（02-events §1 信封 + §2 至少一次 + §3 事件目录）。

本模块生产四个事件（§4.2）：

===================  =========================================================
事件                  触发
===================  =========================================================
``reputation.changed`` 重算后分数或等级变化（payload 必带 ``reasons[]`` 与
                       ``policy_version``，INV-07）
``cop.earned``        产出计提 / 邀请奖励 / 人工授予
``cop.spent``         兑换扣减 / 扣回
``invite.bound``      邀请绑定成功
===================  =========================================================

硬规则：**业务写入与 outbox 同一事务**（§6「事务边界」）；投递至少一次、消费按
``event_id`` 幂等；payload 只放事实，不放阈值 / PII / 凭据（02-events §1 硬规则）。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Mapping

from . import clock
from .models import new_id

__all__ = [
    "build_envelope", "enqueue", "pending", "mark_published",
    "cop_earned", "cop_spent", "reputation_changed", "invite_bound", "EVENT_TYPES",
]

PRODUCER = "M07"
EVENT_TYPES = ("reputation.changed", "cop.earned", "cop.spent", "invite.bound")


def build_envelope(event_type: str, *, aggregate_id: str, payload: Mapping[str, Any],
                   occurred_at: datetime | None = None, idempotency_key: str,
                   event_id: uuid.UUID | None = None, causation_id: str | None = None,
                   correlation_id: str | None = None, trace_id: str | None = None,
                   version: int = 1, aggregate_type: str = "account") -> dict[str, Any]:
    """构造 02-events §1 信封（缺字段直接拒绝，避免发半成品事件）。"""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"未登记的事件类型：{event_type}")
    if not aggregate_id:
        raise ValueError("aggregate_id 必填")
    if not idempotency_key:
        raise ValueError("idempotency_key 必填")
    moment = clock.as_utc(occurred_at)
    return {
        "event_id": str(event_id or new_id()),
        "type": event_type,
        "version": int(version),
        "occurred_at": clock.isoformat(moment),
        "producer": PRODUCER,
        "aggregate_type": aggregate_type,
        "aggregate_id": str(aggregate_id),
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "trace_id": trace_id or f"m07:{aggregate_id}:{moment.timestamp()}",
        "idempotency_key": idempotency_key,
        "payload": dict(payload),
    }


def enqueue(conn: Any, envelope: Mapping[str, Any]) -> str | None:
    """把事件写进 ``reputation_outbox``（同一事务内调用）。

    返回: 新行 id；``None`` 表示同 ``event_id`` 或同 ``(type, idempotency_key)`` 已入队
    （幂等丢弃，不报错 → 重放不会产生第二条事件）。
    """
    from psycopg.types.json import Jsonb

    payload = dict(envelope)
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO reputation_outbox
                 (id, event_id, type, version, occurred_at, producer, aggregate_type,
                  aggregate_id, correlation_id, causation_id, trace_id, idempotency_key, payload)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT DO NOTHING
               RETURNING id""",
            (new_id(), uuid.UUID(str(payload["event_id"])), payload["type"],
             int(payload["version"]), payload["occurred_at"], payload["producer"],
             payload["aggregate_type"], payload["aggregate_id"], payload.get("correlation_id"),
             payload.get("causation_id"), payload["trace_id"], payload["idempotency_key"],
             Jsonb(payload["payload"])))
        row = cur.fetchone()
    return str(row[0]) if row else None


def pending(conn: Any, *, limit: int = 50, now: datetime | None = None) -> list[dict[str, Any]]:
    """待投递事件（``next_attempt_at <= now``；按入队顺序）。"""
    moment = clock.as_utc(now)
    with conn.cursor() as cur:
        cur.execute(
            """SELECT id, event_id, type, occurred_at, payload, attempts
                 FROM reputation_outbox
                WHERE published_at IS NULL AND next_attempt_at <= %s
                ORDER BY created_at, id LIMIT %s""", (moment, int(limit)))
        rows = cur.fetchall()
    return [{"id": str(row[0]), "event_id": str(row[1]), "type": row[2],
             "occurred_at": clock.isoformat(row[3]), "payload": row[4],
             "attempts": int(row[5])} for row in rows]


def mark_published(conn: Any, row_id: Any, *, now: datetime | None = None) -> None:
    """标记投递成功（唯一允许的 UPDATE 之一，见 706 的 ``reputation_outbox_guard``）。"""
    moment = clock.as_utc(now)
    with conn.cursor() as cur:
        cur.execute("""UPDATE reputation_outbox SET published_at = %s, attempts = attempts + 1
                        WHERE id = %s AND published_at IS NULL""", (moment, row_id))


# --------------------------------------------------------------------------- payload
def cop_earned(*, account_id: str, units: int, source: str, ref_id: str,
               lock_until: datetime | None, occurred_at: datetime | None = None,
               journal_id: str | None = None, causation_id: str | None = None) -> dict[str, Any]:
    """``cop.earned``（02-events §3：account_id / amount / source / ref_id / lock_until）。"""
    if source not in ("usage", "invite", "reward", "transfer_in"):
        raise ValueError(f"cop.earned 不接受 source={source}")
    payload = {"account_id": account_id, "amount": int(units), "source": source,
               "ref_id": ref_id, "lock_until": clock.isoformat(lock_until)}
    if journal_id:
        payload["journal_id"] = journal_id
    return build_envelope("cop.earned", aggregate_id=account_id, payload=payload,
                          occurred_at=occurred_at,
                          idempotency_key=f"cop.earned:{source}:{ref_id}",
                          causation_id=causation_id)


def cop_spent(*, account_id: str, units: int, source: str, ref_id: str,
              occurred_at: datetime | None = None, journal_id: str | None = None,
              causation_id: str | None = None) -> dict[str, Any]:
    """``cop.spent``（兑换扣减 / 扣回冲正 / 转出）。

    转让在 02-events 里没有独立事件类型，§6.3 又要求「两条等额分录 + outbox」，
    因此转出记 ``cop.spent(source=transfer_out)``、转入记
    ``cop.earned(source=transfer_in)``——两边的 source 都在 INV-05 的七值枚举内。
    """
    if source not in ("redeem", "revoke", "transfer_out"):
        raise ValueError(f"cop.spent 不接受 source={source}")
    payload = {"account_id": account_id, "amount": int(units), "source": source,
               "ref_id": ref_id}
    if journal_id:
        payload["journal_id"] = journal_id
    return build_envelope("cop.spent", aggregate_id=account_id, payload=payload,
                          occurred_at=occurred_at,
                          idempotency_key=f"cop.spent:{source}:{ref_id}",
                          causation_id=causation_id)


def reputation_changed(*, account_id: str, score: int, tier: str,
                       reasons: list[str], policy_version: str,
                       occurred_at: datetime | None = None,
                       causation_id: str | None = None) -> dict[str, Any]:
    """``reputation.changed``（INV-07：必带 ``reasons[]`` 与 ``policy_version``）。"""
    if not reasons:
        raise ValueError("reputation.changed 必须带 reasons[]（INV-07）")
    payload = {"account_id": account_id, "score": int(score), "tier": tier,
               "reasons": list(reasons), "policy_version": policy_version}
    return build_envelope("reputation.changed", aggregate_id=account_id, payload=payload,
                          occurred_at=occurred_at,
                          idempotency_key=f"reputation.changed:{account_id}:{score}:{tier}",
                          causation_id=causation_id)


def invite_bound(*, inviter_id: str, invitee_id: str, code: str,
                 occurred_at: datetime | None = None,
                 causation_id: str | None = None) -> dict[str, Any]:
    """``invite.bound``（02-events §3：inviter_id / invitee_id / code）。"""
    payload = {"inviter_id": inviter_id, "invitee_id": invitee_id, "code": code}
    return build_envelope("invite.bound", aggregate_id=inviter_id, payload=payload,
                          occurred_at=occurred_at,
                          idempotency_key=f"invite.bound:{inviter_id}:{invitee_id}",
                          causation_id=causation_id)
