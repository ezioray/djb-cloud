# SPDX-License-Identifier: Apache-2.0
"""``audit.appended`` 事件信封（02-events §1 信封 / §3 目录 / M16 §4.2）。

payload 铁律：只放运维事实 ``audit_id / actor / action / hash / seq``，
不放 prompt / response / 凭据 / 金额（M16 §1「不承载业务数据」）。
投递语义见 02-events §2：本地事务 + outbox，至少一次，消费按 event_id 幂等。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Mapping

from . import clock, facts, models


def validate_payload(payload: Mapping[str, Any]) -> None:
    """必含字段校验（键必须存在，值可为 None）。"""
    missing = [key for key in facts.EVENT_PAYLOAD_KEYS if key not in payload]
    if missing:
        raise ValueError(f"{facts.EVENT_TYPE} 缺少必含字段：{missing}（02-events §3）")


def audit_appended_envelope(entry: Mapping[str, Any], *, trace_id: str,
                            occurred_at: datetime | None = None,
                            event_id: uuid.UUID | None = None) -> dict[str, Any]:
    """把一条已上链的审计条目变成 ``audit.appended`` 信封。"""
    moment = clock.as_utc(occurred_at or clock.utcnow())
    identifier = event_id or models.uuid7(moment)
    entry_id = str(entry.get("entry_id"))
    trace = (trace_id or "").strip() or identifier.hex
    payload = {
        "audit_id": entry_id,
        "actor": entry.get("actor"),
        "action": entry.get("action"),
        "hash": entry.get("hash"),
        "seq": int(entry.get("seq") or 0),
    }
    validate_payload(payload)
    if len(entry_id) > 128 or len(trace) > 128:
        raise ValueError("aggregate_id / trace_id 超长（02-events §1 长度上限）")
    return {
        "event_id": str(identifier),
        "type": facts.EVENT_TYPE,
        "version": facts.EVENT_VERSION,
        "occurred_at": moment,
        "producer": facts.EVENT_PRODUCER,
        "aggregate_type": facts.EVENT_AGGREGATE_TYPE,
        "aggregate_id": entry_id,
        "correlation_id": entry.get("ticket"),
        "causation_id": None,
        "trace_id": trace,
        "idempotency_key": f"{facts.EVENT_TYPE}:{entry_id}",
        "payload": payload,
    }


__all__ = ["audit_appended_envelope", "validate_payload"]
