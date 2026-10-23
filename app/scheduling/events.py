# SPDX-License-Identifier: Apache-2.0
"""事件生产（M04 §4.2 / 02-events §1 信封 / §2 至少一次）。

本模块生产 5 个事件::

    quote.created      报价写入（内容变了才有新版本）
    quote.expired      TTL 到期
    booking.created    撮合成交（held）
    booking.expired    成交锁超时
    routing.decided    决策落库之后

**投递方式（T4 起）**：02-events §2.1「本地事务 + outbox」——CR-4 已批准登记
``scheduling_outbox``（迁移 407），因此 :func:`emit` 现在把信封写进该表（**同一事务**），
真正的投递由 ``outbox.dispatch`` 完成（至少一次 + 退避 + DLQ）。
``set_publisher`` 仍保留（转发到 ``outbox.set_publisher``），供测试与 M16 接线用。

**payload 铁律**：只放事实字段；不放正文 / 凭据 / PII / 阈值（INV-12、02-events §1）。
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock, facts, models, outbox

log = logging.getLogger("djb.scheduling.events")

Publisher = outbox.Publisher


# --------------------------------------------------------------------------- 接线
def set_publisher(publisher: Publisher | None) -> None:
    """注入**派发器**（``publisher(type, envelope)``）。传 None 恢复默认（结构化日志）。"""
    outbox.set_publisher(publisher)


def current_publisher() -> Publisher | None:
    return outbox.current_publisher()


def validate_payload(event_type: str, payload: Mapping[str, Any]) -> None:
    """库 / 测试双端校验：必含业务键必须存在（值可为 None）。"""
    if event_type not in facts.EVENT_TYPES:
        raise ValueError(f"未登记的事件类型：{event_type!r}（先在 02-events 登记）")
    required = facts.EVENT_PAYLOAD_KEYS[event_type]
    missing = [key for key in required if key not in payload]
    if missing:
        raise ValueError(f"{event_type} 缺少必含字段：{missing}（02-events §3）")


# --------------------------------------------------------------------------- 信封
def build_envelope(*, event_type: str, aggregate_id: str, payload: Mapping[str, Any],
                   trace_id: str, occurred_at: datetime | None = None,
                   event_id: uuid.UUID | None = None, correlation_id: str | None = None,
                   causation_id: str | None = None,
                   idempotency_key: str | None = None) -> dict[str, Any]:
    """构造 02-events §1 信封（12 个字段齐全）。"""
    validate_payload(event_type, payload)
    moment = occurred_at or clock.utcnow()
    identifier = event_id or models.uuid7(int(moment.timestamp() * 1_000_000))
    trace = (trace_id or "").strip() or identifier.hex
    key = idempotency_key or f"{event_type}:{aggregate_id}:{identifier.hex}"
    if len(aggregate_id) > 128 or len(trace) > 128 or len(key) > 200:
        raise ValueError("aggregate_id / trace_id / idempotency_key 超长（02-events §1）")
    return {
        "event_id": str(identifier),
        "type": event_type,
        "version": facts.EVENT_VERSION,
        "occurred_at": moment.isoformat(),
        "producer": facts.EVENT_PRODUCER,
        "aggregate_type": facts.EVENT_AGGREGATE_TYPE[event_type],
        "aggregate_id": aggregate_id,
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "trace_id": trace,
        "idempotency_key": key,
        "payload": dict(payload),
    }


def emit(c, *, event_type: str, aggregate_id: str, payload: Mapping[str, Any], trace_id: str,
         **kwargs: Any) -> dict[str, Any]:
    """构造信封 + **同事务**写进 ``scheduling_outbox``（02-events §2.1）。

    投递（真正发出去）由 ``outbox.dispatch`` 异步完成；本函数只保证「事实与事件一起提交」。
    """
    envelope = build_envelope(event_type=event_type, aggregate_id=aggregate_id,
                              payload=payload, trace_id=trace_id, **kwargs)
    outbox.append(c, event_type=event_type, envelope=envelope)
    return envelope


# --------------------------------------------------------------------------- 5 个构造器
def quote_created(c, quote: models.Quote, *, trace_id: str,
                  occurred_at: datetime | None = None,
                  event_id: uuid.UUID | None = None) -> dict[str, Any]:
    """``quote.created``：quote_id / node_id / model / price_minor / ttl_s（M04 §4.2）。"""
    return emit(c, event_type="quote.created", aggregate_id=quote.quote_id, trace_id=trace_id,
                occurred_at=occurred_at or quote.created_at, event_id=event_id,
                idempotency_key=f"quote.created:{quote.quote_id}",
                payload={"quote_id": quote.quote_id, "node_id": quote.node_id,
                         "model": quote.model, "price_minor": quote.ask_price_minor,
                         "ttl_s": quote.ttl_s, "access": quote.access,
                         "quote_version": quote.quote_version})


def quote_expired(c, quote: models.Quote, *, trace_id: str,
                  occurred_at: datetime | None = None) -> dict[str, Any]:
    return emit(c, event_type="quote.expired", aggregate_id=quote.quote_id, trace_id=trace_id,
                occurred_at=occurred_at or quote.expires_at,
                idempotency_key=f"quote.expired:{quote.quote_id}",
                payload={"quote_id": quote.quote_id, "node_id": quote.node_id,
                         "model": quote.model, "price_minor": quote.ask_price_minor,
                         "ttl_s": quote.ttl_s, "access": quote.access,
                         "quote_version": quote.quote_version})


def booking_created(c, booking: models.Booking, *, trace_id: str,
                    occurred_at: datetime | None = None) -> dict[str, Any]:
    """``booking.created``：booking_id / node_id / request_id / expires_at（02-events §3）。"""
    return emit(c, event_type="booking.created", aggregate_id=booking.booking_id,
                trace_id=trace_id, occurred_at=occurred_at or booking.created_at,
                idempotency_key=f"booking.created:{booking.booking_id}",
                payload={"booking_id": booking.booking_id, "node_id": booking.node_id,
                         "request_id": booking.request_id,
                         "expires_at": booking.expires_at.isoformat(),
                         "price_minor": booking.price_minor, "strategy": booking.strategy})


def booking_expired(c, booking: models.Booking, *, trace_id: str,
                    occurred_at: datetime | None = None) -> dict[str, Any]:
    return emit(c, event_type="booking.expired", aggregate_id=booking.booking_id,
                trace_id=trace_id, occurred_at=occurred_at or booking.expires_at,
                idempotency_key=f"booking.expired:{booking.booking_id}",
                payload={"booking_id": booking.booking_id, "node_id": booking.node_id,
                         "request_id": booking.request_id,
                         "expires_at": booking.expires_at.isoformat(),
                         "price_minor": booking.price_minor, "strategy": booking.strategy})


def routing_decided(c, decision: models.Decision, *, trace_id: str,
                    occurred_at: datetime | None = None) -> dict[str, Any]:
    """``routing.decided``：request_id / node_id / reason_codes / snapshot_id（02-events §3）。

    ``snapshot_id`` 取 ``decision_id``：它由四元锚点派生（INV-03），是这次决策对应快照的
    可解析引用（``GET /api/v1/schedule/decisions/{decision_id}``）。
    """
    return emit(c, event_type="routing.decided", aggregate_id=str(decision.decision_id),
                trace_id=trace_id, occurred_at=occurred_at or decision.decided_at,
                idempotency_key=f"routing.decided:{decision.decision_id}",
                payload={"request_id": decision.trace_id,
                         "node_id": decision.chosen_node_id,
                         "reason_codes": list(decision.reason_codes),
                         "snapshot_id": str(decision.decision_id),
                         "outcome": decision.outcome,
                         "fallback_used": decision.fallback_used})


__all__ = ["Publisher", "set_publisher", "current_publisher", "validate_payload",
           "build_envelope", "emit", "quote_created", "quote_expired", "booking_created",
           "booking_expired", "routing_decided"]
