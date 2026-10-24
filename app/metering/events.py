# SPDX-License-Identifier: AGPL-3.0-or-later
"""M05 生产事件的信封（02-events §1 / §3 / M05 §4.2）。

本模块只负责**把事实变成合规信封**（纯函数），投递方式按 02-events §2.1「本地事务 + outbox」：

* T1/T2：受理时的信封随返回值交给调用方（``BatchOutcome.events``），不落库——本模块的
  ``metering_outbox`` 属于 T3 交付（需先在 01-ownership 登记，见证据「未做项」）；
* T3：``receipts`` 在**同一事务**里写 outbox，再由派发器按至少一次语义投递。

payload 铁律（INV-10 / 02-events §1）：只放事实字段与金额（``amount_minor``），
不放 prompt / response / 凭据 / 阈值，也不放完整签名（只放短指纹 ``signature_ref``）。
"""
from __future__ import annotations

import uuid
from typing import Any, Mapping

from . import clock, facts, models


def validate_payload(event_type: str, payload: Mapping[str, Any]) -> None:
    """必含字段校验（键必须存在，值可为 None）；未登记的事件直接拒绝。"""
    if event_type not in facts.EVENT_PAYLOAD_KEYS:
        raise ValueError(f"未登记的事件类型：{event_type!r}（先在 02-events / facts 登记）")
    missing = [key for key in facts.EVENT_PAYLOAD_KEYS[event_type] if key not in payload]
    if missing:
        raise ValueError(f"{event_type} 缺少必含字段：{missing}（02-events §3）")


def build_envelope(*, event_type: str, aggregate_id: str, payload: Mapping[str, Any],
                   trace_id: str, occurred_at: Any = None, event_id: uuid.UUID | None = None,
                   correlation_id: str | None = None, causation_id: str | None = None,
                   idempotency_key: str | None = None) -> dict[str, Any]:
    """构造 02-events §1 的 12 字段信封（金额只用整数最小单位）。"""
    validate_payload(event_type, payload)
    moment = clock.as_utc(occurred_at or clock.utcnow())
    identifier = event_id or models.uuid7(moment)
    trace = (trace_id or "").strip() or identifier.hex
    key = idempotency_key or f"{event_type}:{aggregate_id}"
    if len(aggregate_id) > facts.MAX_ID_LEN or len(trace) > facts.MAX_TRACE_LEN:
        raise ValueError("aggregate_id / trace_id 超长（02-events §1 / facts 长度上限）")
    return {
        "event_id": str(identifier),
        "type": event_type,
        "version": facts.EVENT_VERSION,
        "occurred_at": models.iso(moment),
        "producer": facts.EVENT_PRODUCER,
        "aggregate_type": facts.EVENT_AGGREGATE_TYPE[event_type],
        "aggregate_id": aggregate_id,
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "trace_id": trace,
        "idempotency_key": key,
        "payload": dict(payload),
    }


def receipt_signed_event(*, draft: models.ReceiptDraft, usage_id: str, signature_ref: str,
                         trace_id: str, occurred_at: Any = None,
                         causation_id: str | None = None) -> dict[str, Any]:
    """``receipt.signed``：两侧验签通过并落库（M05 §4.2）。"""
    payload = {"receipt_id": draft.receipt_id, "usage_id": usage_id, "node_id": draft.node_id,
               "signature_ref": signature_ref}
    return build_envelope(event_type="receipt.signed", aggregate_id=draft.receipt_id,
                          payload=payload, trace_id=trace_id, occurred_at=occurred_at,
                          idempotency_key=f"receipt.signed:{draft.receipt_id}",
                          causation_id=causation_id)


def usage_recorded_event(*, usage_id: str, account_id: str, request_id: str,
                         amount_minor: int, source: str, trace_id: str,
                         occurred_at: Any = None,
                         causation_id: str | None = None) -> dict[str, Any]:
    """``usage.recorded``：可计费事实（M06 消费后按 E6 落一条分录，幂等键 usage_settle）。"""
    payload = {"usage_id": usage_id, "account_id": account_id, "request_id": request_id,
               "amount_minor": int(amount_minor), "source": source,
               "currency": facts.CURRENCY}
    return build_envelope(event_type="usage.recorded", aggregate_id=usage_id, payload=payload,
                          trace_id=trace_id, occurred_at=occurred_at,
                          idempotency_key=f"usage.recorded:{usage_id}",
                          causation_id=causation_id)


def usage_settled_event(*, usage_id: str, final_amount_minor: int,
                        correction_id: str | None, trace_id: str, occurred_at: Any = None,
                        causation_id: str | None = None) -> dict[str, Any]:
    """``usage.settled``：校正完成 / 上游账单核对完（T4 发；M05 不写分录）。"""
    payload = {"usage_id": usage_id, "final_amount_minor": int(final_amount_minor),
               "correction_id": correction_id, "currency": facts.CURRENCY}
    key = f"usage.settled:{usage_id}:{correction_id or 'final'}"
    return build_envelope(event_type="usage.settled", aggregate_id=usage_id, payload=payload,
                          trace_id=trace_id, occurred_at=occurred_at,
                          idempotency_key=key, causation_id=causation_id)


__all__ = ["validate_payload", "build_envelope", "receipt_signed_event", "usage_recorded_event",
           "usage_settled_event"]
