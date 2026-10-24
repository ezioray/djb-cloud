# SPDX-License-Identifier: AGPL-3.0-or-later
"""事件出站：本地事务 + outbox（02-events §2 / CR-4 已裁决，迁移 407）。

三条语义：

1. **至少一次**：事件与业务事实**同一事务**写进 ``scheduling_outbox``；
   投递失败不回滚业务事务（02-events §2.6），由派发器重试。
2. **幂等**：``idempotency_key`` 唯一——同一事实重复入队不会产生两条事件；
   消费侧再按 ``event_id`` 幂等（02-events §2.1）。
3. **退避 + DLQ**：1s / 5s / 30s / 5min / 30min，最多 8 次；超限停在待投递状态等人工
   重放（``attempts = 8`` 且 ``next_attempt_at`` 不再前进，由运维置位）。

T4 起 ``events.emit`` 默认写本表（T1/T2 的「结构化日志 publisher」降级为**派发器**的
默认实现）：真正的投递由 :func:`dispatch` 完成，测试与 M16 接线共用同一个 publisher 钩子。
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Mapping

from psycopg.types.json import Jsonb

from . import clock, facts

log = logging.getLogger("djb.scheduling.outbox")

Publisher = Callable[[str, dict[str, Any]], None]

#: 02-events §2.3 的退避台阶（秒）；索引 = 已尝试次数
BACKOFF_S: tuple[int, ...] = (1, 5, 30, 300, 1_800)
MAX_ATTEMPTS = 8

_publisher: Publisher | None = None


def set_publisher(publisher: Publisher | None) -> None:
    """注入派发器（``publisher(type, envelope)``）。传 None 恢复默认（结构化日志）。"""
    global _publisher
    _publisher = publisher


def current_publisher() -> Publisher | None:
    return _publisher


def _default_publisher(event_type: str, envelope: Mapping[str, Any]) -> None:
    log.info("scheduling.event.dispatched",
             extra={"event": event_type, "event_id": envelope["event_id"],
                    "aggregate_id": envelope["aggregate_id"],
                    "trace_id": envelope["trace_id"]})


# --------------------------------------------------------------------------- 写入
def append(c, *, event_type: str, envelope: Mapping[str, Any]) -> bool:
    """把信封写进 outbox（同事务）。返回是否真的新入队（幂等键重复 → False）。"""
    payload = envelope.get("payload") or {}
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO scheduling_outbox
                   (event_id, type, version, occurred_at, producer, aggregate_type,
                    aggregate_id, correlation_id, causation_id, trace_id, idempotency_key,
                    payload, next_attempt_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (idempotency_key) DO NOTHING""",
            (uuid.UUID(str(envelope["event_id"])), event_type,
             int(envelope.get("version", facts.EVENT_VERSION)),
             envelope["occurred_at"], facts.EVENT_PRODUCER, envelope["aggregate_type"],
             envelope["aggregate_id"], envelope.get("correlation_id"),
             uuid.UUID(str(envelope["causation_id"])) if envelope.get("causation_id") else None,
             envelope["trace_id"], envelope["idempotency_key"], Jsonb(dict(payload)),
             envelope["occurred_at"]))
        stored = cur.rowcount == 1
    if not stored:
        log.info("scheduling.event.deduped", extra={"event": event_type,
                                                    "key": envelope["idempotency_key"]})
    return stored


# --------------------------------------------------------------------------- 派发
def pending(c, *, limit: int = 100, now: datetime | None = None) -> list[dict[str, Any]]:
    """待投递事件（到期 + 未投递，按 next_attempt_at / created_at 排序）。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            """SELECT event_id, type, version, occurred_at, producer, aggregate_type,
                      aggregate_id, correlation_id, causation_id, trace_id,
                      idempotency_key, payload, attempts
                 FROM scheduling_outbox
                WHERE published_at IS NULL AND next_attempt_at <= %s
                ORDER BY next_attempt_at, created_at
                LIMIT %s""", (moment, int(limit)))
        names = [column.name for column in cur.description]
        return [dict(zip(names, row)) for row in cur.fetchall()]


def mark_published(c, event_id: uuid.UUID, *, now: datetime | None = None) -> None:
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            """UPDATE scheduling_outbox
                  SET published_at = %s, attempts = attempts + 1, last_error = NULL
                WHERE event_id = %s AND published_at IS NULL""", (moment, event_id))


def mark_failed(c, event_id: uuid.UUID, error: str, *, now: datetime | None = None) -> int:
    """记一次失败并排下一次重试（返回新的 attempts）。超限不再前进（进 DLQ 等人工）。

    退避按**本次失败前**的 attempts 取台阶：1s → 5s → 30s → 5min → 30min（02-events §2.3）。
    """
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            """SELECT attempts FROM scheduling_outbox
                WHERE event_id = %s AND published_at IS NULL""", (event_id,))
        row = cur.fetchone()
        if row is None:
            return 0
        attempts = int(row[0])
        new_attempts = min(attempts + 1, MAX_ATTEMPTS)
        delay = backoff_s(attempts) if new_attempts < MAX_ATTEMPTS else None
        cur.execute(
            """UPDATE scheduling_outbox
                  SET attempts = %s, last_error = %s,
                      next_attempt_at = %s + (%s * INTERVAL '1 second')
                WHERE event_id = %s AND published_at IS NULL""",
            (new_attempts, str(error)[:500], moment,
             100 * 365 * 24 * 3600 if delay is None else delay, event_id))
    return new_attempts


def backoff_s(attempts: int) -> int:
    """第 ``attempts`` 次失败后的退避秒数（1/5/30/300/1800）。"""
    return BACKOFF_S[min(max(0, int(attempts)), len(BACKOFF_S) - 1)]


def dispatch(c, *, limit: int = 100, now: datetime | None = None,
             publisher: Publisher | None = None) -> dict[str, int]:
    """派发一轮：成功标 published，失败按退避排下次。返回 {sent, failed}。"""
    moment = now or clock.utcnow()
    consumer = publisher or _publisher or _default_publisher
    sent = failed = 0
    for row in pending(c, limit=limit, now=moment):
        envelope = {"event_id": str(row["event_id"]), "type": row["type"],
                    "version": row["version"],
                    "occurred_at": row["occurred_at"].isoformat(),
                    "producer": row["producer"], "aggregate_type": row["aggregate_type"],
                    "aggregate_id": row["aggregate_id"],
                    "correlation_id": row["correlation_id"],
                    "causation_id": str(row["causation_id"]) if row["causation_id"] else None,
                    "trace_id": row["trace_id"],
                    "idempotency_key": row["idempotency_key"], "payload": row["payload"]}
        try:
            consumer(row["type"], envelope)
        except Exception as exc:                             # pragma: no cover - 防御
            attempts = mark_failed(c, row["event_id"], f"{type(exc).__name__}: {exc}", now=moment)
            failed += 1
            log.warning("scheduling.event.dispatch_failed",
                        extra={"event": row["type"], "attempts": attempts})
        else:
            mark_published(c, row["event_id"], now=moment)
            sent += 1
    return {"sent": sent, "failed": failed}


def dead_letters(c, *, limit: int = 100) -> list[dict[str, Any]]:
    """进 DLQ 的事件（attempts = 8 且未投递）——只能人工重放（02-events §2.4）。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT event_id, type, aggregate_id, attempts, last_error
                 FROM scheduling_outbox
                WHERE published_at IS NULL AND attempts >= 8
                ORDER BY created_at LIMIT %s""", (int(limit),))
        names = [column.name for column in cur.description]
        return [dict(zip(names, row)) for row in cur.fetchall()]


def requeue(c, event_id: uuid.UUID, *, now: datetime | None = None) -> bool:
    """人工重放：把 attempts 归零、下次立即可投（02-events §2.4）。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            """UPDATE scheduling_outbox
                  SET attempts = 0, next_attempt_at = %s, last_error = 'requeued'
                WHERE event_id = %s AND published_at IS NULL""", (moment, event_id))
        return cur.rowcount == 1


def stats(c) -> dict[str, int]:
    with c.cursor() as cur:
        cur.execute(
            """SELECT count(*) FILTER (WHERE published_at IS NULL)                    AS pending,
                      count(*) FILTER (WHERE published_at IS NOT NULL)               AS published,
                      count(*) FILTER (WHERE published_at IS NULL AND attempts >= 8) AS dead
                 FROM scheduling_outbox""")
        row = cur.fetchone()
    return {"pending": int(row[0]), "published": int(row[1]), "dead": int(row[2])}


__all__ = ["Publisher", "BACKOFF_S", "MAX_ATTEMPTS", "set_publisher", "current_publisher",
           "append", "pending", "mark_published", "mark_failed", "backoff_s", "dispatch",
           "dead_letters", "requeue", "stats"]
