# SPDX-License-Identifier: AGPL-3.0-or-later
"""事件消费与事件矩阵（M12 §4.2 / §6.1 / INV-03 / INV-08 / INV-09）。

一行摘要：**事件到达 → 查矩阵（级别 / 模板 / 渠道）→ 算 dedupe_bucket → 命中就累加次数、
否则落 notifications + outbox（同事务）→ 提交后由派发器发 ``notification.requested``。**

三条硬约束：

1. **事件幂等**（02-events §5）：同一 ``event_id`` 重放只返回既有通知，不落第二条；
2. **合并去重**（INV-03）：同 ``(account_id, type, dedupe_bucket)`` 只落一条，``channel_count``
   记录合并次数；合并进来的 event_id 进 ``merged_event_ids``，重放同样识别；
3. **对客 / 内部模板分开**（INV-09）：``customer.*`` 模板只允许 id / 金额 / 时间 / 原因码；
   内部处置字段（批次号 / 钱包 / 异常 / 账本科目）只出现在 ``internal.*`` 模板里。

矩阵覆盖 02-events §3 里把 M12 列为消费方的全部事件（含 CR-1 已登记的
``recon.completed`` / ``exception.*`` / ``wallet.switched`` / ``risk.limit.hit``）。
未登记的事件按 tolerant reader 忽略（不报错、不进 DLQ），等契约补齐再上线。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from . import clock, config_source, facts, outbox, preferences, store, webhooks
from .models import Notification, OutboxEvent, Preference, as_uuid

__all__ = ["Template", "EVENT_TEMPLATES", "WEBHOOK_EVENT_MAP", "template_for",
           "webhook_event_for", "render_payload", "channels_for", "consume",
           "request_notification", "ConsumptionResult", "CUSTOMER_DROP_KEYS"]

#: 对客模板**禁止**出现的内部字段（INV-09）；内部模板不受此限
CUSTOMER_DROP_KEYS: frozenset[str] = frozenset({
    "txid", "batch_no", "run_id", "wallet_id", "pool_id", "exception_id", "case_id",
    "session_id", "snapshot_id", "severity", "risk_type", "limit_type", "tier", "source",
    "action", "result", "from", "to", "template", "template_key", "p0", "p1", "p2",
})


@dataclass(frozen=True)
class Template:
    """事件 → 通知的映射（级别 / 模板 / 渠道 / 受众域）。"""

    event_type: str
    level: str
    key: str
    channels: tuple[str, ...]
    scope: str = facts.SCOPE_CUSTOMER

    @property
    def audience(self) -> str:
        return "internal" if self.scope == facts.SCOPE_INTERNAL else "account"


def _customer(event_type: str, level: str, channels: tuple[str, ...]) -> Template:
    return Template(event_type=event_type, level=level, key=f"customer.{event_type}",
                    channels=channels, scope=facts.SCOPE_CUSTOMER)


def _internal(event_type: str, level: str, channels: tuple[str, ...]) -> Template:
    return Template(event_type=event_type, level=level, key=f"internal.{event_type}",
                    channels=channels, scope=facts.SCOPE_INTERNAL)


#: 事件矩阵（02-events §3 中 M12 为消费方的条目；级别按 M12 §3 / §8.2 的时效口径）
EVENT_TEMPLATES: Mapping[str, Template] = {
    # ── 账户与安全（P0：安全类必须立即送达，且不可退订）
    "account.created": _customer("account.created", "P1", ("in_app", "email")),
    "session.revoked": _customer("session.revoked", "P0", ("in_app", "email")),
    # ── COP / 邀请
    "cop.earned": _customer("cop.earned", "P2", ("in_app", "email")),
    "cop.spent": _customer("cop.spent", "P2", ("in_app",)),
    # ── 资金（充值 / 分润 / 退款：P1 ≤300 s）
    "payment.created": _customer("payment.created", "P2", ("in_app", "email")),
    "payment.paid": _customer("payment.paid", "P1", ("in_app", "email")),
    "payment.failed": _customer("payment.failed", "P1", ("in_app", "email")),
    "payout.paid": _customer("payout.paid", "P1", ("in_app", "email")),
    "refund.completed": _customer("refund.completed", "P1", ("in_app", "email")),
    "por.published": _customer("por.published", "P2", ("in_app",)),
    # ── 风控（限额命中 / 账户被处置：P0）
    "risk.case.opened": _customer("risk.case.opened", "P0", ("in_app", "email")),
    "risk.case.closed": _customer("risk.case.closed", "P1", ("in_app", "email")),
    "risk.limit.hit": _customer("risk.limit.hit", "P0", ("in_app", "email")),
    # ── 对账 / 钱包 / 运维（内部：可含批次号、txid、账本科目，INV-09）
    "recon.completed": _internal("recon.completed", "P1", ("in_app",)),
    "exception.opened": _internal("exception.opened", "P1", ("in_app",)),
    "exception.closed": _internal("exception.closed", "P2", ("in_app",)),
    "wallet.switched": _internal("wallet.switched", "P1", ("in_app",)),
    "deploy.completed": _internal("deploy.completed", "P2", ("in_app",)),
    "backup.completed": _internal("backup.completed", "P2", ("in_app",)),
    "ticket.created": _internal("ticket.created", "P2", ("in_app",)),
    "ticket.updated": _internal("ticket.updated", "P2", ("in_app",)),
    "ticket.closed": _internal("ticket.closed", "P2", ("in_app",)),
}


#: CR-5（M12 §10.3）：spec 的 Webhook 事件名与 02-events 的通知类型不是一套命名。
#: 订阅白名单用的是 spec 枚举（task.completed / payment.settled / payout.sent /
#: security.alert …），派发前必须走这张映射；内部事件不外发（None）。
WEBHOOK_EVENT_MAP: Mapping[str, str] = {
    "payment.created": "payment.settled",
    "payment.paid": "payment.settled",
    "payment.failed": "payment.settled",
    "refund.completed": "payment.settled",
    "payout.paid": "payout.sent",
    "cop.earned": "task.completed",
    "cop.spent": "task.completed",
    "por.published": "task.completed",
    "account.created": "task.completed",
    "session.revoked": "security.alert",
    "risk.case.opened": "security.alert",
    "risk.case.closed": "security.alert",
    "risk.limit.hit": "security.alert",
}


def webhook_event_for(event_type: str) -> str | None:
    """通知类型 → spec 的 Webhook 事件名（内部事件返回 ``None``，不外发）。"""
    return WEBHOOK_EVENT_MAP.get(event_type)


@dataclass(frozen=True)
class ConsumptionResult:
    """一次消费的结果：``created`` / ``merged`` / ``replay`` / ``ignored``。"""

    status: str
    notification_id: str | None = None
    channel_count: int = 0
    level: str | None = None
    template_key: str | None = None
    reason: str = ""
    event_id: str | None = None

    @property
    def created(self) -> bool:
        return self.status == "created"


def template_for(event_type: str) -> Template | None:
    return EVENT_TEMPLATES.get(event_type)


def render_payload(template: Template, raw: Mapping[str, Any] | None) -> dict[str, Any]:
    """按模板域裁剪 payload：对客模板去掉内部处置字段后再过 INV-07 校验。"""
    source = dict(raw or {})
    if template.scope == facts.SCOPE_CUSTOMER:
        source = {key: value for key, value in source.items()
                  if key.lower() not in CUSTOMER_DROP_KEYS}
    return facts.validate_payload(source, scope=template.scope)


def channels_for(template: Template, pref: Preference) -> tuple[str, ...]:
    """渠道裁剪（§8.2：站内恒发、邮件必有、Webhook 可选；P0 不受偏好影响）。"""
    channels = ["in_app"]
    if template.level == "P0":
        channels.append("email")                 # P0 不可退订：邮件渠道恒发（INV-01）
        return tuple(channels)
    if "email" in template.channels and pref.email:
        channels.append("email")
    if "webhook" in template.channels and pref.webhook:
        channels.append("webhook")
    return tuple(channels)


def _envelope(event: Mapping[str, Any]) -> tuple[uuid.UUID, str, datetime, dict[str, Any]]:
    """解析 02-events 信封（tolerant reader：未知字段忽略，缺关键字段抛 40001）。"""
    if not isinstance(event, Mapping):
        raise ValueError("event 必须是对象")
    try:
        event_id = as_uuid(event.get("event_id"))
    except (TypeError, ValueError) as exc:
        raise ValueError("event_id 必须是 UUID") from exc
    event_type = event.get("type")
    if not isinstance(event_type, str) or not event_type:
        raise ValueError("type 必填")
    raw_occurred = event.get("occurred_at")
    if isinstance(raw_occurred, datetime):
        occurred_at = clock.to_utc(raw_occurred)
    elif isinstance(raw_occurred, str) and raw_occurred:
        try:
            occurred_at = clock.to_utc(datetime.fromisoformat(raw_occurred))
        except ValueError as exc:
            raise ValueError("occurred_at 必须是 RFC 3339") from exc
    else:
        raise ValueError("occurred_at 必填")
    payload = event.get("payload") or {}
    if not isinstance(payload, Mapping):
        raise ValueError("payload 必须是对象")
    return event_id, event_type, occurred_at, dict(payload)


def _account_of(payload: Mapping[str, Any], event: Mapping[str, Any]) -> uuid.UUID | None:
    raw = payload.get("account_id")
    if raw in (None, "") and event.get("aggregate_type") == "account":
        raw = event.get("aggregate_id")
    if raw in (None, ""):
        return None
    try:
        return as_uuid(raw)
    except (TypeError, ValueError):
        return None


def consume(conn: Any, event: Mapping[str, Any], *, now: datetime | None = None,
            config: config_source.NotifyConfig | None = None) -> ConsumptionResult:
    """消费一条业务事件（**不提交事务**：调用方负责 commit / rollback）。"""
    cfg = config or config_source.snapshot()
    event_id, event_type, occurred_at, payload = _envelope(event)

    existing = store.find_by_source_event(conn, event_id)
    if existing is not None:                              # 02-events §5：重放不落第二条
        return ConsumptionResult(status="replay", notification_id=str(existing.id),
                                 channel_count=existing.channel_count, level=existing.level,
                                 template_key=existing.template_key, reason="event_replayed",
                                 event_id=str(event_id))

    template = template_for(event_type)
    if template is None:                                  # 未登记 → 忽略（等契约补齐）
        return ConsumptionResult(status="ignored", reason="unregistered_event",
                                 event_id=str(event_id))

    account_id = _account_of(payload, event)
    if account_id is None:                                # 没有收件账户 → 不落站内记录
        return ConsumptionResult(status="ignored", reason="no_recipient",
                                 event_id=str(event_id), template_key=template.key)

    rendered = render_payload(template, payload)
    bucket = facts.dedupe_bucket(occurred_at, cfg.merge_window_s)
    pref = preferences.get(conn, account_id)
    channels = channels_for(template, pref)
    # §8.2：Webhook 可选——只有账户开了偏好**且**有 active 订阅时才加这个渠道
    webhook_event = webhook_event_for(event_type)
    if (pref.webhook and template.scope == facts.SCOPE_CUSTOMER and webhook_event
            and webhooks.active_for_event(conn, account_id, webhook_event, now=occurred_at)):
        channels = tuple(dict.fromkeys((*channels, "webhook")))

    merged = store.find_by_dedupe(conn, account_id, event_type, bucket)
    if merged is not None:                                # INV-03：同窗口合并，不再发事件
        merged = store.bump_merged(conn, merged.id, event_id)
        return ConsumptionResult(status="merged", notification_id=str(merged.id),
                                 channel_count=merged.channel_count, level=merged.level,
                                 template_key=merged.template_key, reason="dedupe_window",
                                 event_id=str(event_id))

    notification = Notification(
        id=uuid.uuid4(),
        account_id=account_id,
        level=template.level,
        type=event_type,
        template_key=template.key,
        template_scope=template.scope,
        payload=rendered,
        channels=channels,
        channel_count=1,
        dedupe_bucket=bucket,
        status="queued",
        created_at=occurred_at,
        source_event_id=event_id,
        merged_event_ids=(),
        # INV-02：in_app=false 只表示「不产生未读提醒」——落库时就置已读，记录仍然保留
        read_at=None if pref.in_app else occurred_at,
    )
    created = store.insert_notification(conn, notification)
    _emit_requested(conn, created, cfg, now=now)
    return ConsumptionResult(status="created", notification_id=str(created.id),
                             channel_count=created.channel_count, level=created.level,
                             template_key=created.template_key, reason="created",
                             event_id=str(event_id))


def request_notification(conn: Any, *, account_id: uuid.UUID | str, type: str,
                         payload: Mapping[str, Any] | None = None,
                         occurred_at: datetime | None = None,
                         event_id: uuid.UUID | str | None = None,
                         config: config_source.NotifyConfig | None = None,
                         now: datetime | None = None) -> ConsumptionResult:
    """模块内/跨模块触发入口（§6.1 的第 1 步）：等价于「构造一条事件再 consume」。

    ``type`` 必须已在事件矩阵登记——未登记的触发一律拒绝（不落库、不发明等级）。
    """
    moment = clock.to_utc(occurred_at) if occurred_at is not None else (
        clock.to_utc(now) if now is not None else clock.now())
    template = template_for(type)
    if template is None:
        raise ValueError(f"未登记的通知类型：{type!r}（先在 events.EVENT_TEMPLATES 登记）")
    event = {
        "event_id": event_id or uuid.uuid4(),
        "type": type,
        "occurred_at": moment,
        "aggregate_type": "account",
        "aggregate_id": str(account_id),
        "payload": {**dict(payload or {}), "account_id": str(account_id)},
    }
    return consume(conn, event, now=now, config=config)


def _emit_requested(conn: Any, notification: Notification,
                    cfg: config_source.NotifyConfig, *, now: datetime | None = None) -> None:
    """同事务写 ``notification.requested``（INV-08：投递异步，失败不回滚业务）。"""
    event = OutboxEvent(
        event_id=uuid.uuid4(),
        type="notification.requested",
        occurred_at=notification.created_at,
        aggregate_id=str(notification.id),
        payload={"notification_id": str(notification.id),
                 "template": notification.template_key,
                 "account_id": str(notification.account_id),
                 "channels": list(notification.channels),
                 "recipients_count": 1,
                 "level": notification.level},
        trace_id=str(notification.id),
    )
    outbox.enqueue(conn, event, now=now or notification.created_at)
