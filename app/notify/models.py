# SPDX-License-Identifier: Apache-2.0
"""M12 领域对象（dataclass）+ 行映射 + 对客序列化（spec 1.2.3 schemas）。

分层原则：

* **本文件不写 SQL、不发请求**，只负责「行 → 对象 → JSON」的形状；
* 对外字段严格按 spec：``Notification`` / ``NotificationPreferences`` /
  ``WebhookSubscription``；多出来的字段只能是 ``additionalProperties: true`` 允许的扩展；
* **secret 永远不进对象**：``WebhookSubscription`` 只持有 ``secret_hash``，
  明文只在 :func:`app.notify.webhooks.create` 的返回值里出现一次（INV-05）。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from . import clock, facts

__all__ = ["Notification", "DeliveryAttempt", "WebhookSubscription", "Preference",
           "OutboxEvent", "as_uuid", "as_json"]


def as_uuid(value: Any) -> uuid.UUID:
    """统一 UUID 解析（``str`` / ``UUID`` 都收；非法抛 ``ValueError``）。"""
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))


def _json(value: Any) -> Any:
    if isinstance(value, datetime):
        return clock.isoformat(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_json(item) for item in value]
    if isinstance(value, Mapping):
        return {key: _json(item) for key, item in value.items()}
    return value


def as_json(value: Any) -> Any:
    """递归把 datetime / UUID / tuple 转成 JSON 可序列化形态。"""
    return _json(value)


@dataclass
class Notification:
    """通知主体（规格 §3 实体 + §5 表；一行 = 一条站内记录）。"""

    id: uuid.UUID
    account_id: uuid.UUID
    level: str
    type: str
    template_key: str
    template_scope: str
    payload: dict[str, Any]
    channels: tuple[str, ...]
    channel_count: int
    dedupe_bucket: int
    status: str
    created_at: datetime
    source_event_id: uuid.UUID | None = None
    merged_event_ids: tuple[uuid.UUID, ...] = ()
    sent_at: datetime | None = None
    read_at: datetime | None = None

    @property
    def unread(self) -> bool:
        return self.read_at is None

    @property
    def is_terminal(self) -> bool:
        return self.status in facts.TERMINAL_STATUSES

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "Notification":
        return cls(
            id=as_uuid(row["id"]),
            account_id=as_uuid(row["account_id"]),
            level=row["level"],
            type=row["type"],
            template_key=row["template_key"],
            template_scope=row.get("template_scope", facts.SCOPE_CUSTOMER),
            payload=dict(row.get("payload_ref") or {}),
            channels=tuple(row["channels"]),
            channel_count=int(row["channel_count"]),
            dedupe_bucket=int(row["dedupe_bucket"]),
            status=row["status"],
            created_at=clock.to_utc(row["created_at"]),
            source_event_id=as_uuid(row["source_event_id"]) if row.get("source_event_id") else None,
            merged_event_ids=tuple(as_uuid(item) for item in (row.get("merged_event_ids") or ())),
            sent_at=clock.to_utc(row.get("sent_at")),
            read_at=clock.to_utc(row.get("read_at")),
        )

    def to_api(self) -> dict[str, Any]:
        """spec ``Notification``（``channel_count`` 即 INV-03 的合并条数）。"""
        return {
            "id": str(self.id),
            "level": self.level,
            "type": self.type,
            "template_key": self.template_key,
            "template_scope": self.template_scope,
            "channels": list(self.channels),
            "channel_count": self.channel_count,
            "status": self.status,
            "created_at": clock.isoformat(self.created_at),
            "sent_at": clock.isoformat(self.sent_at),
            "read_at": clock.isoformat(self.read_at),
            "payload": as_json(self.payload),
        }


@dataclass
class DeliveryAttempt:
    """一次投递尝试（INV-04：只追加，重试复用同一 notification_id）。"""

    id: uuid.UUID
    notification_id: uuid.UUID
    channel: str
    attempt_no: int
    status: str
    occurred_at: datetime
    error_code: str | None = None
    provider_ref: str | None = None
    latency_ms: int | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "DeliveryAttempt":
        return cls(
            id=as_uuid(row["id"]),
            notification_id=as_uuid(row["notification_id"]),
            channel=row["channel"],
            attempt_no=int(row["attempt_no"]),
            status=row["status"],
            occurred_at=clock.to_utc(row["occurred_at"]),
            error_code=row.get("error_code"),
            provider_ref=row.get("provider_ref"),
            latency_ms=row.get("latency_ms"),
        )

    def to_api(self) -> dict[str, Any]:
        return {
            "notification_id": str(self.notification_id),
            "channel": self.channel,
            "attempt_no": self.attempt_no,
            "status": self.status,
            "error_code": self.error_code,
            "provider_ref": self.provider_ref,
            "latency_ms": self.latency_ms,
            "occurred_at": clock.isoformat(self.occurred_at),
        }


@dataclass
class WebhookSubscription:
    """Webhook 订阅（§5 表）。**明文 secret 不在对象里**，只有哈希（INV-05）。"""

    id: uuid.UUID
    account_id: uuid.UUID
    url: str
    events: tuple[str, ...]
    status: str
    created_at: datetime
    updated_at: datetime
    description: str | None = None
    secret_hash: str = ""
    paused_until: datetime | None = None
    failure_count: int = 0

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "WebhookSubscription":
        return cls(
            id=as_uuid(row["id"]),
            account_id=as_uuid(row["account_id"]),
            url=row["url"],
            events=tuple(row["events"]),
            status=row["status"],
            created_at=clock.to_utc(row["created_at"]),
            updated_at=clock.to_utc(row.get("updated_at", row["created_at"])),
            description=row.get("description"),
            secret_hash=row.get("secret_hash", ""),
            paused_until=clock.to_utc(row.get("paused_until")),
            failure_count=int(row.get("failure_count") or 0),
        )

    def to_api(self) -> dict[str, Any]:
        """spec ``WebhookSubscription``：**不含** secret / secret_hash（§4.1「不含密钥」）。"""
        payload = {
            "id": str(self.id),
            "url": self.url,
            "events": list(self.events),
            "status": self.status,
            "created_at": clock.isoformat(self.created_at),
        }
        if self.description:
            payload["description"] = self.description
        if self.paused_until is not None:
            payload["paused_until"] = clock.isoformat(self.paused_until)
        return payload


@dataclass
class Preference:
    """通知偏好（§5 第 5 张表 / spec ``NotificationPreferences``）。"""

    account_id: uuid.UUID | None = None
    email: bool = True
    in_app: bool = True
    webhook: bool = False
    quiet_hours: Mapping[str, str] | None = None
    digest: str = "realtime"
    p0_opt_out: bool = False
    updated_at: datetime | None = None

    @classmethod
    def defaults(cls, account_id: uuid.UUID | None = None) -> "Preference":
        return cls(account_id=account_id)

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "Preference":
        return cls(
            account_id=as_uuid(row["account_id"]),
            email=bool(row["email"]),
            in_app=bool(row["in_app"]),
            webhook=bool(row["webhook"]),
            quiet_hours=dict(row["quiet_hours"]) if row.get("quiet_hours") else None,
            digest=row["digest"],
            p0_opt_out=bool(row["p0_opt_out"]),
            updated_at=clock.to_utc(row.get("updated_at")),
        )

    def to_api(self) -> dict[str, Any]:
        """spec ``NotificationPreferences``（``p0_opt_out`` 恒 false，只读项）。"""
        return {
            "email": self.email,
            "in_app": self.in_app,
            "webhook": self.webhook,
            "quiet_hours": dict(self.quiet_hours) if self.quiet_hours else None,
            "digest": self.digest,
            "p0_opt_out": self.p0_opt_out,
        }


@dataclass
class OutboxEvent:
    """本模块待发事件（02-events §1 信封；payload 只放短字段，INV-07）。"""

    event_id: uuid.UUID
    type: str
    occurred_at: datetime
    aggregate_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    version: int = 1
    producer: str = "M12"
    aggregate_type: str = "notification"
    correlation_id: str | None = None
    causation_id: str | None = None
    trace_id: str = ""
    idempotency_key: str = ""

    def __post_init__(self) -> None:
        if not self.trace_id:
            self.trace_id = str(self.event_id)
        if not self.idempotency_key:
            self.idempotency_key = f"{self.type}:{self.aggregate_id}"

    def envelope(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "type": self.type,
            "version": self.version,
            "occurred_at": clock.isoformat(self.occurred_at),
            "producer": self.producer,
            "aggregate_type": self.aggregate_type,
            "aggregate_id": self.aggregate_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "trace_id": self.trace_id,
            "idempotency_key": self.idempotency_key,
            "payload": as_json(self.payload),
        }
