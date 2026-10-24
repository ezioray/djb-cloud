# SPDX-License-Identifier: AGPL-3.0-or-later
"""分派与投递（M12 §6.2 / INV-04 / INV-06 / INV-08 的 S1 骨架）。

一次 ``dispatch_batch`` 做的事：

1. ``queued → sending`` 领一批（``FOR UPDATE SKIP LOCKED``，多实例安全）；
2. 按 ``channels`` 顺序（站内 → 邮件 → Webhook）逐个尝试；**每次尝试写一条**
   ``delivery_attempts``（INV-04：只追加、重试复用同一 notification_id）；
3. 可重试失败按渠道退避（Webhook 1 s / 10 s / 60 s，邮件 3 次）**在本批内**重试，
   最多 ``MAX_ATTEMPTS_PER_CHANNEL`` 次；仍失败 → 按 INV-06 降级（站内信已在，
   Webhook 订阅转 ``paused`` 并记 P1 事件），**不静默**；
4. 写终态 ``delivered / partial / failed`` 并发 ``notification.delivered / .failed`` 事件。

S1 明确不做：真实 SMTP / 真实出网（见 :mod:`app.notify.channels`）、跨进程延迟队列。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import channels, clock, config_source, facts, outbox, store, webhooks
from .channels import ChannelResult, WebhookTarget
from .models import DeliveryAttempt, Notification, OutboxEvent

__all__ = ["deliver_notification", "dispatch_batch", "decide_status", "default_adapters",
           "DEFAULT_ADAPTERS"]

Sleeper = Callable[[float], None]


def default_adapters(*, transport_webhook: Any = None, transport_email: Any = None,
                     webhook_timeout_s: int = 10) -> dict[str, Any]:
    """默认适配器：站内必成功；邮件 / Webhook 默认未接线（``transport=None``）。"""
    return {
        "in_app": channels.InAppChannel(),
        "email": channels.EmailChannel(transport=transport_email),
        "webhook": channels.WebhookChannel(transport=transport_webhook,
                                           timeout_s=webhook_timeout_s),
    }


#: 只读默认值（模块级常量，便于测试比对；真正投递请用 :func:`default_adapters`）
DEFAULT_ADAPTERS: Mapping[str, Any] = default_adapters()


def decide_status(results: Sequence[ChannelResult]) -> str:
    """整单终态（§6.2）：全成功 ``delivered``、部分成功 ``partial``、全失败 ``failed``。"""
    if not results:
        return "failed"
    succeeded = sum(1 for result in results if result.status == "success")
    if succeeded == len(results):
        return "delivered"
    return "partial" if succeeded else "failed"


def _attempt(conn: Any, notification: Notification, channel: str, attempt_no: int,
             result: ChannelResult, now: datetime) -> DeliveryAttempt:
    attempt = DeliveryAttempt(
        id=uuid.uuid4(), notification_id=notification.id, channel=channel,
        attempt_no=attempt_no, status=result.status, occurred_at=now,
        error_code=result.error_code, provider_ref=result.provider_ref,
        latency_ms=result.latency_ms)
    return store.insert_attempt(conn, attempt)


def _retry_delays(channel: str, config: config_source.NotifyConfig) -> tuple[int, ...]:
    if channel == "webhook":
        return tuple(config.webhook_retry_delays_s)
    if channel == "email":
        return tuple(config.webhook_retry_delays_s)[: int(config.email_retry_count)]
    return ()


def deliver_notification(conn: Any, notification: Notification, *,
                         adapters: Mapping[str, Any],
                         webhook_targets: Callable[[Notification], WebhookTarget | None] | None = None,
                         now: datetime | None = None,
                         config: config_source.NotifyConfig | None = None,
                         sleeper: Sleeper | None = None) -> dict[str, Any]:
    """按渠道投递一条通知；返回 ``{status, results, attempts}``（不提交事务）。"""
    cfg = config or config_source.snapshot()
    moment = clock.to_utc(now) if now is not None else clock.now()
    results: list[ChannelResult] = []
    attempts: list[DeliveryAttempt] = []
    final: list[tuple[str, int, ChannelResult]] = []
    permanent_failures: list[tuple[str, str]] = []

    for channel in notification.channels:
        adapter = adapters.get(channel)
        done = store.attempts_count(conn, notification.id, channel)
        if done >= facts.MAX_ATTEMPTS_PER_CHANNEL:
            exhausted = ChannelResult(status="permanent", error_code="attempts_exhausted")
            results.append(exhausted)
            final.append((channel, done, exhausted))
            permanent_failures.append((channel, "attempts_exhausted"))
            continue
        target = webhook_targets(notification) if channel == "webhook" and webhook_targets else None
        delays = _retry_delays(channel, cfg)
        attempt_no = done
        while True:
            attempt_no += 1
            if adapter is None:
                result = ChannelResult(status="permanent", error_code="channel_not_wired")
            else:
                result = adapter.deliver(notification, target=target, now=moment, config=cfg)
            attempts.append(_attempt(conn, notification, channel, attempt_no, result, moment))
            retryable = result.status == "retryable"
            if retryable and attempt_no < facts.MAX_ATTEMPTS_PER_CHANNEL:
                delay = delays[min(attempt_no - 1, len(delays) - 1)] if delays else 0
                if sleeper is not None:
                    sleeper(float(delay))
                continue
            if retryable:                                  # 3 次仍失败 → 终态失败（INV-06）
                result = ChannelResult(status="permanent", error_code=result.error_code,
                                       provider_ref=result.provider_ref,
                                       latency_ms=result.latency_ms)
                attempts[-1] = _rewrite_status(attempts[-1], "permanent", result.error_code)
            results.append(result)
            final.append((channel, attempt_no, result))
            if result.status == "permanent":
                permanent_failures.append((channel, result.error_code or "permanent"))
            break

    status = decide_status(results)
    store.finish(conn, notification.id, status, moment)
    for channel, error_code in permanent_failures:
        _on_permanent_failure(conn, notification, channel, error_code, moment)
    _emit_delivery_events(conn, notification, final, moment)
    return {"status": status, "results": results, "attempts": attempts}


def _rewrite_status(attempt: DeliveryAttempt, status: str, error_code: str | None) -> DeliveryAttempt:
    """把「最后一次可重试」改记为终态失败（attempts 表只追加，所以这里改的是内存对象）。"""
    attempt.status = status
    attempt.error_code = error_code or attempt.error_code
    return attempt


def _on_permanent_failure(conn: Any, notification: Notification, channel: str,
                          error_code: str, now: datetime) -> None:
    """INV-06 降级：Webhook 永久失败 → 订阅转 paused（对客仍有站内信，不静默）。"""
    if channel == "webhook" and notification.channels.count("webhook"):
        subscription_id = _webhook_subscription_of(conn, notification)
        if subscription_id is not None:
            webhooks.register_failure(conn, subscription_id, permanent=True, now=now)


def _webhook_subscription_of(conn: Any, notification: Notification) -> uuid.UUID | None:
    """最近一次 webhook 尝试里带的订阅 id（没有就说明从未投递过）。"""
    for attempt in reversed(store.attempts_for(conn, notification.id)):
        if attempt.channel == "webhook" and attempt.provider_ref:
            try:
                return uuid.UUID(str(attempt.provider_ref))
            except ValueError:                            # pragma: no cover - 防御
                return None
    return None


def _emit_delivery_events(conn: Any, notification: Notification,
                          final: Iterable[tuple[str, int, ChannelResult]],
                          now: datetime) -> None:
    """每个渠道的**终态**各发一条事件（不是每次尝试都发，避免事件刷屏）。

    4.2 的 payload 就是 ``notification_id / channel / attempt (error_code)``。
    """
    for channel, attempt_no, result in final:
        if result.status == "success":
            event = OutboxEvent(
                event_id=uuid.uuid4(), type="notification.delivered", occurred_at=now,
                aggregate_id=str(notification.id),
                payload={"notification_id": str(notification.id), "channel": channel,
                         "attempt": attempt_no, "account_id": str(notification.account_id)})
        else:
            event = OutboxEvent(
                event_id=uuid.uuid4(), type="notification.failed", occurred_at=now,
                aggregate_id=str(notification.id),
                payload={"notification_id": str(notification.id), "channel": channel,
                         "attempt": attempt_no, "error_code": result.error_code,
                         "account_id": str(notification.account_id)})
        outbox.enqueue(conn, event, now=now)


def dispatch_batch(conn: Any, *, adapters: Mapping[str, Any] | None = None,
                   webhook_targets: Callable[[Notification], WebhookTarget | None] | None = None,
                   now: datetime | None = None, limit: int = facts.DISPATCH_BATCH,
                   config: config_source.NotifyConfig | None = None,
                   sleeper: Sleeper | None = None) -> dict[str, Any]:
    """领一批并发完：返回 ``{scanned, delivered, partial, failed}``。"""
    cfg = config or config_source.snapshot()
    moment = clock.to_utc(now) if now is not None else clock.now()
    resolved = adapters or DEFAULT_ADAPTERS
    claimed = store.claim_batch(conn, now=moment, limit=limit)
    summary = {"scanned": len(claimed), "delivered": 0, "partial": 0, "failed": 0}
    for notification in claimed:
        outcome = deliver_notification(conn, notification, adapters=resolved,
                                       webhook_targets=webhook_targets, now=moment,
                                       config=cfg, sleeper=sleeper)
        summary[outcome["status"]] = summary.get(outcome["status"], 0) + 1
    return summary
