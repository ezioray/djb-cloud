# SPDX-License-Identifier: Apache-2.0
"""M10 事件 outbox（config_outbox，1005）：事件构造 + 同事务落库 + 待投递查询。

02-events §3 登记 M10 只生产三个事件：

    config.published        版本转 active 且快照落库
                            namespace, key, version, risk_level, policy_version, effective_at
    config.rolled_back      回滚版本生效
                            namespace, key, version, rollback_to, reason_code
    config.drift_detected   漂移扫描命中
                            namespace, key, expected, actual, detected_at

纪律：
  · **同事务**：事件与 config_versions / config_publish_requests 在同一事务写（M10 §6）；
    投递失败不回滚业务（02-events §2 至少一次），由 outbox 补偿；
  · **幂等**：``idempotency_key`` 由业务键派生（``config.published:<key>:<scope>:<version>``），
    重复追加 ON CONFLICT DO NOTHING，不产生第二行；
  · **库里也兜底**：1005 迁移对 type / producer / aggregate_type / payload 必含键有 CHECK；
    本模块先做同样的校验，让错误在 Python 侧带清晰信息。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

import psycopg
from psycopg.types.json import Jsonb

from .errors import ValidationFailed

__all__ = [
    "PRODUCER",
    "AGGREGATE_TYPE",
    "EVENT_TYPES",
    "REQUIRED_PAYLOAD_KEYS",
    "OutboxEvent",
    "OutboxEventInvalid",
    "validate_event",
    "append_event",
    "pending_events",
    "mark_published",
    "published_event",
    "rolled_back_event",
    "drift_detected_event",
]

PRODUCER = "M10"
AGGREGATE_TYPE = "config_key"
EVENT_TYPES: tuple[str, ...] = (
    "config.published", "config.rolled_back", "config.drift_detected")

#: 与 1005 迁移的 config_outbox_payload_ck 一一对应（02-events §3 / M10 §4.2）
REQUIRED_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    "config.published": ("namespace", "key", "version", "risk_level", "policy_version",
                         "effective_at"),
    "config.rolled_back": ("namespace", "key", "version", "rollback_to", "reason_code"),
    "config.drift_detected": ("namespace", "key", "expected", "actual", "detected_at"),
}

MAX_AGGREGATE_ID_LEN = 128
MAX_TRACE_ID_LEN = 128
MAX_IDEMPOTENCY_KEY_LEN = 200


class OutboxEventInvalid(ValidationFailed):
    """事件不符合 02-events 契约（缺字段 / 类型未登记 / 聚合根不匹配）。"""


@dataclass(frozen=True)
class OutboxEvent:
    type: str
    aggregate_id: str
    payload: dict[str, Any]
    idempotency_key: str
    trace_id: str
    version: int = 1
    occurred_at: datetime | None = None
    correlation_id: str | None = None
    causation_id: str | None = None
    producer: str = PRODUCER
    aggregate_type: str = AGGREGATE_TYPE


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise OutboxEventInvalid("occurred_at 必须带时区（UTC）")
    return value.astimezone(timezone.utc)


def validate_event(event: OutboxEvent) -> OutboxEvent:
    """校验事件是否符合 02-events §1 信封 + §3 业务键。"""
    if event.type not in REQUIRED_PAYLOAD_KEYS:
        raise OutboxEventInvalid(f"未登记的事件类型：{event.type!r}（02-events §3）")
    if event.producer != PRODUCER:
        raise OutboxEventInvalid(f"producer 必须是 {PRODUCER}")
    if event.aggregate_type != AGGREGATE_TYPE:
        raise OutboxEventInvalid(f"aggregate_type 必须是 {AGGREGATE_TYPE}")
    if not isinstance(event.payload, Mapping):
        raise OutboxEventInvalid("payload 必须是 object")
    missing = [key for key in REQUIRED_PAYLOAD_KEYS[event.type] if key not in event.payload]
    if missing:
        raise OutboxEventInvalid(
            f"{event.type} 的 payload 缺业务键：{missing}",
            details=[{"field": key} for key in missing])
    if not 1 <= len(event.aggregate_id) <= MAX_AGGREGATE_ID_LEN:
        raise OutboxEventInvalid(f"aggregate_id 长度必须是 1..{MAX_AGGREGATE_ID_LEN}")
    if not 1 <= len(event.idempotency_key) <= MAX_IDEMPOTENCY_KEY_LEN:
        raise OutboxEventInvalid(f"idempotency_key 长度必须是 1..{MAX_IDEMPOTENCY_KEY_LEN}")
    if not 1 <= len(event.trace_id) <= MAX_TRACE_ID_LEN:
        raise OutboxEventInvalid(f"trace_id 长度必须是 1..{MAX_TRACE_ID_LEN}")
    if event.version < 1:
        raise OutboxEventInvalid("version 从 1 开始")
    if event.occurred_at is not None:
        _as_utc(event.occurred_at)
    return event


def append_event(conn: psycopg.Connection, event: OutboxEvent) -> dict[str, Any]:
    """同事务写 outbox（幂等键冲突时返回既有行，不重复写）。"""
    validate_event(event)
    occurred_at = _as_utc(event.occurred_at) if event.occurred_at else datetime.now(timezone.utc)
    cur = conn.execute(
        """INSERT INTO config_outbox
             (type, version, occurred_at, producer, aggregate_type, aggregate_id,
              correlation_id, causation_id, trace_id, idempotency_key, payload)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (idempotency_key) DO NOTHING
           RETURNING *""",
        (event.type, event.version, occurred_at, event.producer, event.aggregate_type,
         event.aggregate_id, event.correlation_id, event.causation_id, event.trace_id,
         event.idempotency_key, Jsonb(event.payload)),
    )
    row = cur.fetchone()
    columns = [desc.name for desc in cur.description or ()]
    if row is not None:
        return dict(zip(columns, row))
    cur = conn.execute(
        "SELECT * FROM config_outbox WHERE idempotency_key = %s", (event.idempotency_key,))
    row = cur.fetchone()
    columns = [desc.name for desc in cur.description or ()]
    if row is None:  # pragma: no cover - ON CONFLICT 后必然存在
        raise ValidationFailed(f"outbox 幂等键冲突但读不到既有行：{event.idempotency_key}")
    return dict(zip(columns, row))


def pending_events(conn: psycopg.Connection, *, limit: int = 100) -> list[dict[str, Any]]:
    """待投递事件（按 created_at 升序；投递器用）。"""
    if limit < 1 or limit > 1000:
        raise ValidationFailed(f"limit 越界 1..1000：{limit}")
    cur = conn.execute(
        """SELECT * FROM config_outbox
            WHERE published_at IS NULL AND dead_lettered_at IS NULL
            ORDER BY created_at, event_id LIMIT %s""", (limit,))
    columns = [desc.name for desc in cur.description or ()]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def mark_published(conn: psycopg.Connection, event_id: str,
                   *, published_at: datetime | None = None) -> int:
    """投递完成标记（只允许 NULL → NOT NULL，重复标记由触发器拒绝）。"""
    moment = _as_utc(published_at) if published_at else datetime.now(timezone.utc)
    cur = conn.execute(
        "UPDATE config_outbox SET published_at = %s WHERE event_id = %s AND published_at IS NULL",
        (moment, event_id))
    return cur.rowcount


# ───────────────────────────────────────────────────────────── 事件构造器
def _trace(trace_id: str | None) -> str:
    return trace_id or uuid.uuid4().hex


def published_event(*, namespace: str, key: str, version: int, risk_level: str,
                    policy_version: str, effective_at: datetime, scope: str = "global",
                    scope_id: str = "", request_id: str | None = None,
                    trace_id: str | None = None, occurred_at: datetime | None = None,
                    version_no: int = 1, snapshot_digest: str | None = None,
                    emergency: bool = False) -> OutboxEvent:
    payload = {
        "namespace": namespace,
        "key": key,
        "version": version,
        "risk_level": risk_level,
        "policy_version": policy_version,
        "effective_at": _as_utc(effective_at).isoformat(),
        "scope": scope,
        "scope_id": scope_id,
    }
    if snapshot_digest is not None:
        payload["snapshot_digest"] = snapshot_digest      # R-14：事件可独立核对快照
    if emergency:
        payload["emergency"] = True
    return OutboxEvent(
        type="config.published",
        aggregate_id=key,
        payload=payload,
        idempotency_key=f"config.published:{key}:{scope}:{scope_id}:{version}",
        trace_id=_trace(trace_id),
        occurred_at=occurred_at or datetime.now(timezone.utc),
        correlation_id=request_id,
        version=version_no,
    )


def rolled_back_event(*, namespace: str, key: str, version: int, rollback_to: int,
                      reason_code: str, scope: str = "global", scope_id: str = "",
                      request_id: str | None = None, trace_id: str | None = None,
                      occurred_at: datetime | None = None,
                      version_no: int = 1, snapshot_digest: str | None = None) -> OutboxEvent:
    payload = {
        "namespace": namespace,
        "key": key,
        "version": version,
        "rollback_to": rollback_to,
        "reason_code": reason_code,
        "scope": scope,
        "scope_id": scope_id,
    }
    if snapshot_digest is not None:
        payload["snapshot_digest"] = snapshot_digest
    return OutboxEvent(
        type="config.rolled_back",
        aggregate_id=key,
        payload=payload,
        idempotency_key=f"config.rolled_back:{key}:{scope}:{scope_id}:{version}",
        trace_id=_trace(trace_id),
        occurred_at=occurred_at or datetime.now(timezone.utc),
        correlation_id=request_id,
        version=version_no,
    )


def drift_detected_event(*, namespace: str, key: str, expected: Any, actual: Any,
                         detected_at: datetime, scope: str = "global", scope_id: str = "",
                         scan_id: str | None = None, trace_id: str | None = None,
                         occurred_at: datetime | None = None,
                         version_no: int = 1) -> OutboxEvent:
    payload = {
        "namespace": namespace,
        "key": key,
        "expected": expected,
        "actual": actual,
        "detected_at": _as_utc(detected_at).isoformat(),
        "scope": scope,
        "scope_id": scope_id,
    }
    return OutboxEvent(
        type="config.drift_detected",
        aggregate_id=key,
        payload=payload,
        idempotency_key=f"config.drift_detected:{key}:{scope}:{scope_id}:"
                        f"{_as_utc(detected_at).isoformat()}",
        trace_id=_trace(trace_id),
        occurred_at=occurred_at or datetime.now(timezone.utc),
        correlation_id=scan_id,
        version=version_no,
    )
