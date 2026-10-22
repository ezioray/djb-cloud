# SPDX-License-Identifier: Apache-2.0
"""本地事件投递（m06_outbox）：事件构造 + 同事务落库（02-events §1/§2/§3）。

M06 只生产三个事件（02-events §3）：
    journal.posted   凭证提交成功      journal_id, event_type, amount_minor, ref_id
    ledger.reversed  冲正提交成功      journal_id, reverse_of, reason_code     （T3 使用）
    merkle.anchored  周期根发布        root, kind, period, anchored_at         （T4 使用）

纪律：
  · 投递语义是「至少一次」：写入与业务同事务（outbox 表），投递失败不回滚业务；
  · 库里 604 迁移对 type / aggregate_type / payload 必含键有 CHECK 兜底，本模块先做
    同样的校验再写，让错误在 Python 侧就带清晰信息（不把 DB 约束当唯一防线）；
  · ``idempotency_key`` 由业务键派生，重复追加不会产生第二行（ON CONFLICT DO NOTHING）。
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .constants import (
    MAX_AGGREGATE_ID_LEN,
    MAX_IDEMPOTENCY_KEY_LEN,
    MAX_TRACE_ID_LEN,
    MERKLE_KINDS_OWNED,
    PENDING_PAGE_DEFAULT,
)
from .errors import LedgerError

PRODUCER = "M06"

# 02-events §3 的业务键（与 604 迁移的 m06_outbox_payload_ck 一一对应）
REQUIRED_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    "journal.posted": ("journal_id", "event_type", "amount_minor", "ref_id"),
    "ledger.reversed": ("journal_id", "reverse_of", "reason_code"),
    "merkle.anchored": ("root", "kind", "period", "anchored_at"),
}
AGGREGATE_TYPE: dict[str, str] = {
    "journal.posted": "journal_entry",
    "ledger.reversed": "journal_entry",
    "merkle.anchored": "merkle_commitment",
}


class OutboxEventInvalid(LedgerError):
    """事件不符合 02-events 契约（缺字段 / 类型未登记 / 聚合根不匹配）。"""

    code = "42223"


@dataclass(frozen=True)
class OutboxEvent:
    type: str
    aggregate_type: str
    aggregate_id: str
    payload: dict
    idempotency_key: str
    trace_id: str
    version: int = 1
    occurred_at: datetime | None = None
    correlation_id: str | None = None
    causation_id: str | None = None
    producer: str = PRODUCER


def validate_event(event: OutboxEvent) -> OutboxEvent:
    if event.type not in REQUIRED_PAYLOAD_KEYS:
        raise OutboxEventInvalid(f"未登记的事件类型：{event.type!r}（02-events §3）")
    expected_aggregate = AGGREGATE_TYPE[event.type]
    if event.aggregate_type != expected_aggregate:
        raise OutboxEventInvalid(
            f"{event.type} 的 aggregate_type 必须是 {expected_aggregate}，收到 {event.aggregate_type!r}")
    missing = [key for key in REQUIRED_PAYLOAD_KEYS[event.type] if key not in event.payload]
    if missing:
        raise OutboxEventInvalid(f"{event.type} 的 payload 缺业务键：{missing}",
                                 detail={"required": list(REQUIRED_PAYLOAD_KEYS[event.type])})
    if not isinstance(event.payload, Mapping):
        raise OutboxEventInvalid("payload 必须是 object")
    if not (1 <= len(event.aggregate_id) <= MAX_AGGREGATE_ID_LEN):
        raise OutboxEventInvalid(f"aggregate_id 长度必须是 1..{MAX_AGGREGATE_ID_LEN}")
    if not (1 <= len(event.idempotency_key) <= MAX_IDEMPOTENCY_KEY_LEN):
        raise OutboxEventInvalid(f"idempotency_key 长度必须是 1..{MAX_IDEMPOTENCY_KEY_LEN}")
    if not (1 <= len(event.trace_id) <= MAX_TRACE_ID_LEN):
        raise OutboxEventInvalid(f"trace_id 长度必须是 1..{MAX_TRACE_ID_LEN}")
    if event.version < 1:
        raise OutboxEventInvalid("version 从 1 开始")
    if event.producer != PRODUCER:
        raise OutboxEventInvalid(f"producer 必须是 {PRODUCER}（本表只装 M06 的事件）")
    return event


# ────────────────────────────────────────────── 统一构造出口
def emit_event(event_type: str, *, aggregate_id: str, payload: Mapping, idempotency_key: str,
               trace_id: str, occurred_at: datetime | None = None,
               correlation_id: str | None = None, causation_id: str | None = None,
               version: int = 1) -> OutboxEvent:
    """按事件名构造一条 outbox 事件（aggregate_type 由 02-events §3 的登记表推导）。

    事件名的字面量集中在三个构造器里、只经本函数出口 —— ``tools/ci/event_schema.py``
    会扫 ``emit_event("…")`` 的字面量并核对 02-events §3，未登记即 CI 红。
    """
    if event_type not in AGGREGATE_TYPE:
        raise OutboxEventInvalid(f"未登记的事件类型：{event_type!r}（02-events §3）")
    return validate_event(OutboxEvent(
        type=event_type, aggregate_type=AGGREGATE_TYPE[event_type],
        aggregate_id=str(aggregate_id), payload=dict(payload),
        idempotency_key=idempotency_key, trace_id=trace_id, version=version,
        occurred_at=occurred_at, correlation_id=correlation_id, causation_id=causation_id))


# ────────────────────────────────────────────── 三个事件的构造器
def journal_posted_event(*, journal_id: str, event_type: str, amount_minor: int, ref_id: str,
                         trace_id: str | None = None, correlation_id: str | None = None,
                         occurred_at: datetime | None = None) -> OutboxEvent:
    payload = {"journal_id": str(journal_id), "event_type": event_type,
               "amount_minor": int(amount_minor), "ref_id": ref_id}
    return emit_event("journal.posted", aggregate_id=str(journal_id), payload=payload,
                      idempotency_key=f"journal.posted:{journal_id}",
                      trace_id=trace_id or uuid.uuid4().hex, correlation_id=correlation_id,
                      occurred_at=occurred_at or datetime.now(timezone.utc))


def ledger_reversed_event(*, journal_id: str, reverse_of: str, reason_code: str,
                          trace_id: str | None = None, correlation_id: str | None = None,
                          occurred_at: datetime | None = None) -> OutboxEvent:
    """冲正事件（T3 在冲正事务里调用；聚合根是**冲正凭证** journal_id）。"""
    payload = {"journal_id": str(journal_id), "reverse_of": str(reverse_of),
               "reason_code": reason_code}
    return emit_event("ledger.reversed", aggregate_id=str(journal_id), payload=payload,
                      idempotency_key=f"ledger.reversed:{journal_id}",
                      trace_id=trace_id or uuid.uuid4().hex, correlation_id=correlation_id,
                      occurred_at=occurred_at or datetime.now(timezone.utc))


def merkle_anchored_event(*, root: str, kind: str, period: str, anchored_at: datetime,
                          trace_id: str | None = None) -> OutboxEvent:
    """期间根发布事件（T4 在发布事务里调用；kind 只能是 M06 拥有的两类）。"""
    if kind not in MERKLE_KINDS_OWNED:
        raise OutboxEventInvalid(f"kind {kind!r} 不属于 M06（只允许 {MERKLE_KINDS_OWNED}）")
    payload = {"root": root, "kind": kind, "period": period,
               "anchored_at": anchored_at.astimezone(timezone.utc).isoformat()}
    return emit_event("merkle.anchored", aggregate_id=f"{kind}:{period}", payload=payload,
                      idempotency_key=f"merkle.anchored:{kind}:{period}",
                      trace_id=trace_id or uuid.uuid4().hex, occurred_at=anchored_at)


# ────────────────────────────────────────────── 落库（与业务同事务）
def append_event(conn, event: OutboxEvent) -> str:
    """把事件写进 m06_outbox，返回 event_id（同 idempotency_key 重复调用返回既有 id）。"""
    validate_event(event)
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO m06_outbox
                 (type, version, occurred_at, producer, aggregate_type, aggregate_id,
                  correlation_id, causation_id, trace_id, idempotency_key, payload)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
               ON CONFLICT (idempotency_key) DO NOTHING
               RETURNING event_id""",
            (event.type, event.version,
             event.occurred_at or datetime.now(timezone.utc), event.producer,
             event.aggregate_type, event.aggregate_id, event.correlation_id,
             event.causation_id, event.trace_id, event.idempotency_key,
             json.dumps(dict(event.payload), ensure_ascii=False, sort_keys=True)))
        row = cur.fetchone()
        if row is not None:
            return str(row[0])
        cur.execute("SELECT event_id FROM m06_outbox WHERE idempotency_key = %s",
                    (event.idempotency_key,))
        existing = cur.fetchone()
    if existing is None:                                   # 理论上不可达：冲突必有既有行
        raise OutboxEventInvalid(f"outbox 写入失败：{event.idempotency_key}")
    return str(existing[0])


def pending_events(conn, limit: int = PENDING_PAGE_DEFAULT) -> list[dict]:
    """待投递事件（投递器由 T4/运维消费；本模块只提供只读查询）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT event_id, type, aggregate_id, trace_id, payload, created_at
                 FROM m06_outbox WHERE published_at IS NULL
                ORDER BY created_at LIMIT %s""", (int(limit),))
        return [
            {"event_id": str(eid), "type": type_, "aggregate_id": agg, "trace_id": trace,
             "payload": payload, "created_at": created}
            for eid, type_, agg, trace, payload, created in cur.fetchall()
        ]
