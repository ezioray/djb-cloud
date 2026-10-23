# SPDX-License-Identifier: Apache-2.0
"""事件生产（M04 §4.2 / 02-events §1 信封 / §2 至少一次）。

本模块生产 5 个事件::

    quote.created      报价写入（内容变了才有新版本）
    quote.expired      TTL 到期
    booking.created    撮合成交（held）
    booking.expired    成交锁超时
    routing.decided    决策落库之后

**投递方式（T1/T2 边界）**：02-events §2.1 要求「本地事务 + outbox」。M04 §5 只登记了 6 张表，
`<module>_outbox` 尚未在 01-ownership 的 M04 行登记，因此 T1/T2 **不建表**，改用
**依赖注入的 publisher**（默认 = 结构化日志），由 Lead 在合并时接 M16 的事件派发器；
T3/T4 建 ``scheduling_outbox``（迁移 407）后把默认 publisher 换成真正的 outbox 写入
（已作为跨模块待办登记在证据文件）。

**payload 铁律**：只放事实字段；不放正文 / 凭据 / PII / 阈值（INV-12、02-events §1）。
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock, facts, models

log = logging.getLogger("djb.scheduling.events")

Publisher = Callable[[str, dict[str, Any]], None]

_publisher: Publisher | None = None


# --------------------------------------------------------------------------- 接线
def set_publisher(publisher: Publisher | None) -> None:
    """注入事件投递器（``publisher(type, envelope)``）。传 None 恢复默认（结构化日志）。"""
    global _publisher
    _publisher = publisher


def current_publisher() -> Publisher | None:
    return _publisher


def _log_publisher(event_type: str, envelope: dict[str, Any]) -> None:
    """默认投递器：结构化日志（T1/T2 无 outbox 表；派发由 M16 接线）。"""
    log.info("scheduling.event.emitted",
             extra={"event": event_type, "event_id": envelope["event_id"],
                    "aggregate_id": envelope["aggregate_id"],
                    "trace_id": envelope["trace_id"]})


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


def emit(*, event_type: str, aggregate_id: str, payload: Mapping[str, Any], trace_id: str,
         **kwargs: Any) -> dict[str, Any]:
    """构造信封 + 交给投递器（投递失败**不**回滚业务事务，02-events §2.6）。"""
    envelope = build_envelope(event_type=event_type, aggregate_id=aggregate_id,
                              payload=payload, trace_id=trace_id, **kwargs)
    publisher = _publisher or _log_publisher
    try:
        publisher(envelope["type"], envelope)
    except Exception:                                        # pragma: no cover - 防御
        log.error("scheduling.event.publish_failed",
                  extra={"event": envelope["type"], "event_id": envelope["event_id"]})
    return envelope


# --------------------------------------------------------------------------- 5 个构造器
def quote_created(quote: models.Quote, *, trace_id: str, occurred_at: datetime | None = None,
                  event_id: uuid.UUID | None = None) -> dict[str, Any]:
    """``quote.created``：quote_id / node_id / model / price_minor / ttl_s（M04 §4.2）。"""
    return emit(event_type="quote.created", aggregate_id=quote.quote_id, trace_id=trace_id,
                occurred_at=occurred_at or quote.created_at, event_id=event_id,
                payload={"quote_id": quote.quote_id, "node_id": quote.node_id,
                         "model": quote.model, "price_minor": quote.ask_price_minor,
                         "ttl_s": quote.ttl_s, "access": quote.access,
                         "quote_version": quote.quote_version})


def quote_expired(quote: models.Quote, *, trace_id: str,
                  occurred_at: datetime | None = None) -> dict[str, Any]:
    return emit(event_type="quote.expired", aggregate_id=quote.quote_id, trace_id=trace_id,
                occurred_at=occurred_at or quote.expires_at,
                payload={"quote_id": quote.quote_id, "node_id": quote.node_id,
                         "model": quote.model, "price_minor": quote.ask_price_minor,
                         "ttl_s": quote.ttl_s, "access": quote.access,
                         "quote_version": quote.quote_version})


def booking_created(booking: models.Booking, *, trace_id: str,
                    occurred_at: datetime | None = None) -> dict[str, Any]:
    """``booking.created``：booking_id / node_id / request_id / expires_at（02-events §3）。"""
    return emit(event_type="booking.created", aggregate_id=booking.booking_id,
                trace_id=trace_id, occurred_at=occurred_at or booking.created_at,
                payload={"booking_id": booking.booking_id, "node_id": booking.node_id,
                         "request_id": booking.request_id,
                         "expires_at": booking.expires_at.isoformat(),
                         "price_minor": booking.price_minor, "strategy": booking.strategy})


def booking_expired(booking: models.Booking, *, trace_id: str,
                    occurred_at: datetime | None = None) -> dict[str, Any]:
    return emit(event_type="booking.expired", aggregate_id=booking.booking_id,
                trace_id=trace_id, occurred_at=occurred_at or booking.expires_at,
                payload={"booking_id": booking.booking_id, "node_id": booking.node_id,
                         "request_id": booking.request_id,
                         "expires_at": booking.expires_at.isoformat(),
                         "price_minor": booking.price_minor, "strategy": booking.strategy})


def routing_decided(decision: models.Decision, *, trace_id: str,
                    occurred_at: datetime | None = None) -> dict[str, Any]:
    """``routing.decided``：request_id / node_id / reason_codes / snapshot_id（02-events §3）。

    ``snapshot_id`` 取 ``decision_id``：它由四元锚点派生（INV-03），是这次决策对应快照的
    可解析引用（``GET /api/v1/schedule/decisions/{decision_id}``）。
    """
    return emit(event_type="routing.decided", aggregate_id=str(decision.decision_id),
                trace_id=trace_id, occurred_at=occurred_at or decision.decided_at,
                payload={"request_id": decision.trace_id,
                         "node_id": decision.chosen_node_id,
                         "reason_codes": list(decision.reason_codes),
                         "snapshot_id": str(decision.decision_id),
                         "outcome": decision.outcome,
                         "fallback_used": decision.fallback_used})


__all__ = ["Publisher", "set_publisher", "current_publisher", "validate_payload",
           "build_envelope", "emit", "quote_created", "quote_expired", "booking_created",
           "booking_expired", "routing_decided"]
