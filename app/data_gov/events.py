# SPDX-License-Identifier: AGPL-3.0-or-later
"""M14 事件：02-events 信封 + outbox（同事务 / 幂等 / 指数退避）。

生产事件只有两条（02-events §3 已登记）::

    data.export.completed   export_id, requester, rows
    retention.executed      job_id, object, deleted_count

消费事件（M14 §4.2）在 S1 只做**信封与 payload 白名单校验**（健康 / 对账数据仍以
只读视图直取）；本地没有 inbox 表，消费幂等由 M16 / 各 Owner 的 event_id 去重负责，
接线时由 Lead 注入（证据遗留项）。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from . import clock, errors, facts, ids, store

__all__ = [
    "build_envelope", "enqueue", "mark_published", "mark_failed", "backoff_seconds",
    "validate_inbound", "InboundEvent", "MAX_ATTEMPTS",
]

MAX_ATTEMPTS = 8
_BACKOFF = (1, 5, 30, 300, 1800)
_PAYLOAD_TYPES = {**facts.EVENT_PAYLOAD_FIELDS}


def backoff_seconds(attempt: int) -> int:
    if attempt <= 0:
        return _BACKOFF[0]
    if attempt >= MAX_ATTEMPTS:
        return 0
    index = min(attempt - 1, len(_BACKOFF) - 1)
    return _BACKOFF[index]


def build_envelope(event_type: str, payload: Mapping[str, Any], *, aggregate_type: str,
                   aggregate_id: str, trace_id: str, idempotency_key: str,
                   now: datetime, version: int = facts.EVENT_VERSION,
                   correlation_id: str | None = None,
                   causation_id: str | None = None) -> dict[str, Any]:
    if event_type not in _PAYLOAD_TYPES:
        raise errors.BadRequest(f"未登记事件：{event_type}", field="event.type")
    allowed = _PAYLOAD_TYPES[event_type]
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise errors.BadRequest(f"事件 payload 含未登记字段：{unknown}", fields=unknown)
    missing = sorted(allowed - set(payload))
    if missing:
        raise errors.BadRequest(f"事件 payload 缺字段：{missing}", fields=missing)
    if not trace_id or len(trace_id) > 128:
        raise errors.BadRequest("trace_id 必填（≤128）", field="trace_id")
    if not idempotency_key or not (16 <= len(idempotency_key) <= 128):
        raise errors.BadRequest("idempotency_key 必须在 16..128", field="idempotency_key")
    return {
        "event_id": str(ids.uuid7()),
        "type": event_type,
        "version": int(version),
        "occurred_at": clock.iso(now),
        "producer": facts.PRODUCER,
        "aggregate_type": aggregate_type,
        "aggregate_id": str(aggregate_id),
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "trace_id": trace_id,
        "idempotency_key": idempotency_key,
        "payload": dict(payload),
    }


def enqueue(connection: Any, envelope: Mapping[str, Any]) -> bool:
    """同事务写 outbox；event_id / idempotency_key 重复 → False（消费侧幂等）。"""
    return store.insert_outbox(connection, envelope) is not None


def mark_published(connection: Any, event_id: str, *, now: datetime) -> None:
    store.update_outbox(connection, event_id, state="published", published_at=now,
                        next_attempt_at=None)


def mark_failed(connection: Any, event_id: str, *, now: datetime, error: str,
                attempts: int) -> None:
    exhausted = attempts + 1 >= MAX_ATTEMPTS
    delay = backoff_seconds(attempts + 1)
    store.update_outbox(
        connection, event_id,
        state="failed" if exhausted else "pending",
        attempts=attempts + 1,
        last_error=error[:500],
        next_attempt_at=None if exhausted else clock.as_utc(now) + timedelta(seconds=delay),
    )


@dataclass(frozen=True)
class InboundEvent:
    event_id: str
    type: str
    version: int
    occurred_at: datetime
    producer: str
    aggregate_type: str
    aggregate_id: str
    trace_id: str
    idempotency_key: str
    payload: dict[str, Any]


def validate_inbound(event: Mapping[str, Any]) -> InboundEvent:
    """消费侧信封校验（tolerant reader：未知字段忽略，未知事件类型进 DLQ 前拒绝）。"""
    if not isinstance(event, Mapping):
        raise errors.BadRequest("事件必须是对象")
    missing = [name for name in facts.ENVELOPE_REQUIRED_FIELDS if name not in event]
    if missing:
        raise errors.BadRequest(f"事件缺信封字段：{missing}", fields=missing)
    event_type = event.get("type")
    if event_type not in facts.CONSUMED_EVENTS:
        raise errors.BadRequest(f"M14 不消费该事件：{event_type}", field="type")
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        raise errors.BadRequest("事件 payload 必须是对象", field="payload")
    allowed = facts.CONSUMED_PAYLOAD_FIELDS[event_type]
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise errors.BadRequest(f"事件 payload 含未登记字段：{unknown}", fields=unknown)
    try:
        version = int(event.get("version"))
    except (TypeError, ValueError):
        raise errors.BadRequest("事件 version 必须是整数", field="version") from None
    if version < 1:
        raise errors.BadRequest("事件 version 必须 ≥1", field="version")
    return InboundEvent(
        event_id=str(event["event_id"]),
        type=str(event_type),
        version=version,
        occurred_at=clock.parse_datetime(event["occurred_at"], field="occurred_at"),
        producer=str(event["producer"]),
        aggregate_type=str(event["aggregate_type"]),
        aggregate_id=str(event["aggregate_id"]),
        trace_id=str(event["trace_id"]),
        idempotency_key=str(event["idempotency_key"]),
        payload=dict(payload),
    )
