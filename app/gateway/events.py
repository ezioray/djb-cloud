# SPDX-License-Identifier: AGPL-3.0-or-later
"""事件生产（M03 §4.2 / 02-events §1 信封 / §2 至少一次）。

本模块只发两个事件：

| 事件 | 触发 | payload（只含元数据） |
| --- | --- | --- |
| ``request.completed`` | 请求成功结束（含流式正常收尾） | request_id、model、tokens_in/out、latency_ms、node_id、usage_source |
| ``request.failed`` | 请求失败或流式中断 | request_id、error_code、upstream_error_class、attempts |

**投递方式**：02-events §2.1「本地事务 + outbox」——信封写进 ``m03_outbox``（与
``api_request_log`` 同事务），真正的投递由 :mod:`app.gateway.outbox` 完成
（至少一次 + 退避 + 死信）。``set_publisher`` 留给测试与 M16 接线。

**payload 铁律**：不放正文 / 凭据 / PII（INV-M03-02、02-events §1）；金额用
``amount_minor``（本模块 payload 不含金额：计费值是 M05 的事实）。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Mapping

from . import clock, facts, models, outbox

__all__ = ["Publisher", "set_publisher", "current_publisher", "build_envelope",
           "request_completed_event", "request_failed_event", "validate_payload"]

Publisher = outbox.Publisher


def set_publisher(publisher: Publisher | None) -> None:
    outbox.set_publisher(publisher)


def current_publisher() -> Publisher | None:
    return outbox.current_publisher()


def validate_payload(event_type: str, payload: Mapping[str, Any]) -> None:
    if event_type not in facts.EVENT_TYPES:
        raise ValueError(f"未登记的事件类型：{event_type!r}（先在 02-events 登记）")
    missing = [key for key in facts.EVENT_PAYLOAD_KEYS[event_type] if key not in payload]
    if missing:
        raise ValueError(f"{event_type} 缺少必含字段：{missing}（02-events §3）")


def build_envelope(*, event_type: str, aggregate_id: str, payload: Mapping[str, Any],
                   trace_id: str, occurred_at: datetime | None = None,
                   event_id: uuid.UUID | None = None,
                   correlation_id: str | None = None,
                   causation_id: str | None = None,
                   idempotency_key: str | None = None) -> dict[str, Any]:
    """构造 02-events §1 信封（12 个字段齐全）。"""
    validate_payload(event_type, payload)
    moment = clock.as_utc(occurred_at or clock.utcnow())
    identifier = event_id or models.uuid7(int(moment.timestamp() * 1_000_000))
    trace = (trace_id or "").strip() or identifier.hex
    key = idempotency_key or f"{event_type}:{aggregate_id}"
    if len(aggregate_id) > 128 or len(trace) > 128 or len(key) > 200:
        raise ValueError("aggregate_id / trace_id / idempotency_key 超长（02-events §1）")
    return {
        "event_id": str(identifier),
        "type": event_type,
        "version": facts.EVENT_VERSION,
        "occurred_at": clock.iso(moment),
        "producer": facts.EVENT_PRODUCER,
        "aggregate_type": facts.EVENT_AGGREGATE_TYPE[event_type],
        "aggregate_id": str(aggregate_id),
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "trace_id": trace,
        "idempotency_key": key,
        "payload": dict(payload),
    }


def request_completed_event(*, request_id: str, model: str, tokens_in: int, tokens_out: int,
                            latency_ms: int, node_id: str, usage_source: str,
                            trace_id: str, occurred_at: datetime | None = None,
                            envelope_id: uuid.UUID | None = None) -> dict[str, Any]:
    """``request.completed``（M03 §4.2 / 02-events §3）。"""
    payload = {"request_id": request_id, "model": model, "tokens_in": int(tokens_in),
               "tokens_out": int(tokens_out), "latency_ms": int(latency_ms),
               "node_id": node_id, "usage_source": usage_source}
    return build_envelope(event_type="request.completed", aggregate_id=request_id,
                          payload=payload, trace_id=trace_id, occurred_at=occurred_at,
                          event_id=envelope_id)


def request_failed_event(*, request_id: str, error_code: int | None,
                         upstream_error_class: str | None, attempts: int,
                         trace_id: str, occurred_at: datetime | None = None,
                         envelope_id: uuid.UUID | None = None) -> dict[str, Any]:
    """``request.failed``（M03 §4.2；``error_code`` 用对外数字码，不含内部栈）。"""
    payload = {"request_id": request_id,
               "error_code": None if error_code is None else int(error_code),
               "upstream_error_class": upstream_error_class,
               "attempts": int(attempts)}
    return build_envelope(event_type="request.failed", aggregate_id=request_id,
                          payload=payload, trace_id=trace_id, occurred_at=occurred_at,
                          event_id=envelope_id)
