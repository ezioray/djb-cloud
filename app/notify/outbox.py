# SPDX-License-Identifier: Apache-2.0
"""M12 事件 outbox：与通知同事务入队 + 至少一次派发（02-events §2 / INV-08）。

为什么必须同事务：通知落库了但事件丢了，下游（M14 后台、退订统计）就看不到这条通知；
反过来事件发了但通知没落库，用户点进去是 404。所以 ``notifications + notification_outbox``
在**一个库事务**里写（§6 事务边界），投递交给本文件的派发器。

派发器是 S1 骨架：

* 真实下游（Kafka / NATS）由 Lead 在合并期注入 ``publisher``；未接线时 **不静默丢弃**，
  事件原样留在 outbox（``published_at IS NULL``），上线后可直接补发；
* 失败按 02-events §2.3 退避 ``1s/5s/30s/5min/30min``，**最多 8 次**，之后标 ``dlq:`` 前缀
  留在表里等人工重放（只能人工，见 §5 死信要求）；
* 投递失败**不回滚**业务事务（INV-08）。
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable, Mapping

from . import clock, facts
from .models import OutboxEvent
from .store import dict_cursor

__all__ = ["enqueue", "pending", "dispatch", "dead_letters", "DLQ_PREFIX", "Publisher"]

#: 发布器：收到 02-events §1 信封 dict；成功返回、失败抛异常（由本模块记退避）
Publisher = Callable[[dict[str, Any]], None]

DLQ_PREFIX = "dlq:"


def enqueue(conn: Any, event: OutboxEvent, *, now: datetime | None = None) -> bool:
    """入队一条事件（与业务同事务）。重复 ``event_id`` 直接忽略并返回 ``False``。"""
    moment = clock.to_utc(now) if now is not None else clock.now()
    envelope = event.envelope()
    facts.validate_payload(event.payload, scope=facts.SCOPE_INTERNAL)  # 事件同样零 PII
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO notification_outbox
                   (id, event_id, type, version, occurred_at, producer, aggregate_type,
                    aggregate_id, correlation_id, causation_id, trace_id, idempotency_key,
                    payload, attempts, next_attempt_at, published_at, last_error, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, %s, NULL, NULL, %s)
               ON CONFLICT (event_id) DO NOTHING""",
            (_uuid(event.event_id), event.event_id, event.type, event.version,
             clock.to_utc(event.occurred_at), event.producer, event.aggregate_type,
             event.aggregate_id, event.correlation_id, event.causation_id, event.trace_id,
             event.idempotency_key, _jsonb(envelope["payload"]), moment, moment))
        return cur.rowcount > 0


def pending(conn: Any, *, now: datetime, limit: int = facts.DISPATCH_BATCH) -> list[Mapping[str, Any]]:
    """待派发事件（未发布、未进死信、到点）。"""
    with dict_cursor(conn) as cur:
        cur.execute(
            """SELECT id, event_id, type, payload, attempts, next_attempt_at
                 FROM notification_outbox
                WHERE published_at IS NULL
                  AND next_attempt_at <= %s
                  AND (last_error IS NULL OR last_error NOT LIKE %s)
                ORDER BY next_attempt_at, created_at
                LIMIT %s""",
            (now, f"{DLQ_PREFIX}%", int(limit)))
        return cur.fetchall()


def dispatch(conn: Any, publisher: Publisher, *, now: datetime | None = None,
             limit: int = facts.DISPATCH_BATCH) -> dict[str, int]:
    """派发一批事件：成功标 ``published_at``，失败按退避重排，8 次后进死信。"""
    moment = clock.to_utc(now) if now is not None else clock.now()
    rows = pending(conn, now=moment, limit=limit)
    published = retried = dead = 0
    for row in rows:
        envelope = {"event_id": str(row["event_id"]), "type": row["type"],
                    "payload": row["payload"]}
        try:
            publisher(envelope)
        except Exception as exc:                          # noqa: BLE001 - 失败只记短码
            attempts = int(row["attempts"]) + 1
            code = type(exc).__name__[:40]
            if attempts >= facts.EVENT_MAX_ATTEMPTS:
                _reschedule(conn, row["id"], attempts=attempts,
                            next_attempt_at=moment + timedelta(days=365),
                            last_error=f"{DLQ_PREFIX}{code}")
                dead += 1
            else:
                delay = facts.EVENT_BACKOFF_S[min(attempts - 1, len(facts.EVENT_BACKOFF_S) - 1)]
                _reschedule(conn, row["id"], attempts=attempts,
                            next_attempt_at=moment + timedelta(seconds=delay),
                            last_error=code)
                retried += 1
            continue
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE notification_outbox SET published_at = %s, attempts = attempts + 1 "
                "WHERE id = %s", (moment, row["id"]))
        published += 1
    return {"published": published, "retried": retried, "dead": dead, "scanned": len(rows)}


def _reschedule(conn: Any, row_id: Any, *, attempts: int, next_attempt_at: datetime,
                last_error: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE notification_outbox
                  SET attempts = %s, next_attempt_at = %s, last_error = %s
                WHERE id = %s""", (attempts, next_attempt_at, last_error[:200], row_id))


def dead_letters(conn: Any) -> int:
    """死信条数（进 DLQ = 未发布且 ``last_error`` 以 ``dlq:`` 开头）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT count(*) FROM notification_outbox
                WHERE published_at IS NULL AND last_error LIKE %s""", (f"{DLQ_PREFIX}%",))
        return int(cur.fetchone()[0])


def _uuid(value: Any) -> Any:
    import uuid as _uuid_module

    return value if isinstance(value, _uuid_module.UUID) else _uuid_module.UUID(str(value))


def _jsonb(value: Any) -> Any:
    from psycopg.types.json import Jsonb

    return Jsonb(dict(value or {}))
