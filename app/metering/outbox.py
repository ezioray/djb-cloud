# SPDX-License-Identifier: Apache-2.0
"""事件出站：本地事务 + outbox（02-events §2 / M05 §5 / CR-5，迁移 506）。

三条语义（与 M04/M06 同款，口径必须一致）：

1. **至少一次**：事件与业务事实**同一事务**写进 ``metering_outbox``；投递失败不回滚业务，
   由派发器重试（02-events §2.6）；
2. **幂等**：``idempotency_key`` 唯一——同一事实重复入队不产生两条事件；消费侧再按
   ``event_id`` 幂等（02-events §2.1）；
3. **退避 + 死信**：1s / 5s / 30s / 5min / 30min，最多 8 次；超限后停在待投递状态
   （``attempts = 8``）等人工重放（02-events §2.3/§2.4）。

派发时机：**提交之后**。``append`` 只负责同事务入队；``dispatch`` 由调用方在事务提交后执行
（路由层在响应前做一次尽力派发；定时作业 / 运维 CLI 也可单独跑），因此不会出现
「事务回滚了却已经把事件发出去」的幻影事件。
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Mapping

from psycopg.types.json import Jsonb

from . import clock, facts

log = logging.getLogger("djb.metering.outbox")

Publisher = Callable[[str, dict[str, Any]], None]

_publisher: Publisher | None = None


# --------------------------------------------------------------------------- 接线
def set_publisher(publisher: Publisher | None) -> None:
    """注入派发器（``publisher(type, envelope)``）。传 None 恢复默认（结构化日志）。"""
    global _publisher
    _publisher = publisher


def current_publisher() -> Publisher | None:
    return _publisher


def _default_publisher(event_type: str, envelope: Mapping[str, Any]) -> None:
    log.info("metering.event.dispatched",
             extra={"event": event_type, "event_id": envelope["event_id"],
                    "aggregate_id": envelope["aggregate_id"],
                    "trace_id": envelope["trace_id"]})


# --------------------------------------------------------------------------- 入队
def append(c: Any, envelope: Mapping[str, Any]) -> bool:
    """把信封写进 outbox（**同事务**）。返回是否真的新入队（幂等键重复 → False）。"""
    payload = envelope.get("payload") or {}
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO metering_outbox
                   (event_id, type, version, occurred_at, producer, aggregate_type,
                    aggregate_id, correlation_id, causation_id, trace_id, idempotency_key,
                    payload, next_attempt_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (idempotency_key) DO NOTHING""",
            (uuid.UUID(str(envelope["event_id"])), envelope["type"],
             int(envelope.get("version", facts.EVENT_VERSION)), envelope["occurred_at"],
             facts.EVENT_PRODUCER, envelope["aggregate_type"], envelope["aggregate_id"],
             envelope.get("correlation_id"), envelope.get("causation_id"), envelope["trace_id"],
             envelope["idempotency_key"], Jsonb(dict(payload)),
             envelope["occurred_at"]))
        return cur.rowcount == 1


def append_all(c: Any, envelopes: Iterable[Mapping[str, Any]]) -> int:
    return sum(1 for envelope in envelopes if append(c, envelope))


# --------------------------------------------------------------------------- 排队读取
_PENDING_SQL = """
    SELECT event_id, type, aggregate_id, trace_id, idempotency_key, payload, attempts,
           next_attempt_at, occurred_at
      FROM metering_outbox
     WHERE published_at IS NULL AND next_attempt_at <= %(now)s
     ORDER BY next_attempt_at, occurred_at
     LIMIT %(limit)s
"""


def pending(c: Any, *, limit: int | None = None, now: datetime | None = None) -> list[dict]:
    """取待投递事件（按 next_attempt_at 升序）。"""
    moment = clock.as_utc(now or clock.utcnow())
    page = facts.OUTBOX_PENDING_PAGE_DEFAULT if limit is None else int(limit)
    with c.cursor() as cur:
        cur.execute(_PENDING_SQL, {"now": moment, "limit": page})
        rows = cur.fetchall()
    keys = ("event_id", "type", "aggregate_id", "trace_id", "idempotency_key", "payload",
            "attempts", "next_attempt_at", "occurred_at")
    events = []
    for row in rows:
        item = dict(zip(keys, row))
        item["event_id"] = str(item["event_id"])
        events.append(item)
    return events


# --------------------------------------------------------------------------- 投递记账
def mark_published(c: Any, event_id: str, *, now: datetime | None = None) -> None:
    moment = clock.as_utc(now or clock.utcnow())
    with c.cursor() as cur:
        cur.execute("UPDATE metering_outbox SET published_at = %s WHERE event_id = %s",
                    (moment, uuid.UUID(str(event_id))))


def mark_failed(c: Any, event_id: str, error: str, *, now: datetime | None = None) -> dict:
    """记一次失败：attempts+1、按台阶排下次重试；达上限即死信（不再前进）。"""
    moment = clock.as_utc(now or clock.utcnow())
    message = (error or "")[:facts.OUTBOX_ERROR_MAX_LEN]
    with c.cursor() as cur:
        cur.execute("SELECT attempts FROM metering_outbox WHERE event_id = %s",
                    (uuid.UUID(str(event_id)),))
        row = cur.fetchone()
        attempts = int(row[0]) if row else 0
    attempts = min(attempts + 1, facts.EVENT_MAX_ATTEMPTS)
    dead_letter = attempts >= facts.EVENT_MAX_ATTEMPTS
    delay = facts.EVENT_BACKOFF_S[min(attempts - 1, len(facts.EVENT_BACKOFF_S) - 1)]
    next_at = moment if dead_letter else moment + timedelta(seconds=delay)
    with c.cursor() as cur:
        cur.execute(
            """UPDATE metering_outbox
                  SET attempts = %s, next_attempt_at = %s, last_error = %s
                WHERE event_id = %s""",
            (attempts, next_at, message, uuid.UUID(str(event_id))))
    if dead_letter:
        log.warning("metering.event.dead_letter", extra={"event_id": str(event_id),
                                                         "attempts": attempts})
    return {"event_id": str(event_id), "attempts": attempts, "next_attempt_at": next_at,
            "dead_letter": dead_letter}


# --------------------------------------------------------------------------- 派发
def _commit(c: Any) -> None:
    if not getattr(c, "autocommit", False):
        c.commit()


def _transaction_status(c: Any) -> str:
    info = getattr(c, "info", None)
    status = getattr(info, "transaction_status", None)
    return getattr(status, "name", str(status))


def dispatch(c: Any, *, publisher: Publisher | None = None, limit: int | None = None,
             now: datetime | None = None) -> dict[str, int]:
    """排空待投递队列（**必须在事务提交之后调用**，见模块文档）。

    单条失败只记账不抛错（02-events §2.6：投递失败不得回滚业务）；
    单条成功立即提交，避免「一半已发、一半回滚」。
    """
    if not getattr(c, "autocommit", False) and _transaction_status(c) == "INTRANS":
        raise RuntimeError(
            "outbox.dispatch 必须在业务事务提交之后调用（否则会发出未提交事件，见模块文档）")
    active = publisher if publisher is not None else (_publisher or _default_publisher)
    moment = clock.as_utc(now or clock.utcnow())
    published = failed = dead = 0
    for event in pending(c, limit=limit, now=moment):
        envelope = {"event_id": event["event_id"], "type": event["type"],
                    "aggregate_id": event["aggregate_id"], "trace_id": event["trace_id"],
                    "payload": event["payload"]}
        try:
            active(event["type"], envelope)
        except Exception as exc:                       # noqa: BLE001 - 投递失败只记账
            result = mark_failed(c, event["event_id"], f"{type(exc).__name__}: {exc}", now=moment)
            _commit(c)
            failed += 1
            dead += 1 if result["dead_letter"] else 0
        else:
            mark_published(c, event["event_id"], now=moment)
            _commit(c)
            published += 1
    return {"published": published, "failed": failed, "dead_letter": dead}


# --------------------------------------------------------------------------- 保留期清理
def purge_published(c: Any, *, now: datetime | None = None,
                    older_than_days: int | None = None) -> int:
    """清理**已发布且超过保留期**的事件（M05 §5：已发布 30 天）；未发布行永不删除。"""
    moment = clock.as_utc(now or clock.utcnow())
    days = facts.OUTBOX_PUBLISHED_RETENTION_DAYS if older_than_days is None else int(older_than_days)
    cutoff = moment - timedelta(days=days)
    with c.cursor() as cur:
        cur.execute("DELETE FROM metering_outbox WHERE published_at IS NOT NULL "
                    "AND published_at < %s", (cutoff,))
        return cur.rowcount


__all__ = ["Publisher", "set_publisher", "current_publisher", "append", "append_all", "pending",
           "mark_published", "mark_failed", "dispatch", "purge_published"]
