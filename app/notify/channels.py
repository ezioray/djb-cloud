# SPDX-License-Identifier: Apache-2.0
"""渠道适配器（S1 骨架：**不发真实邮件、不出网**，但把语义与留痕做全）。

为什么先做骨架：M12 §4.3 的邮件供应商与出网白名单属于 T4（S2），S1 的验收重点是
「站内必达 + 每次尝试都留痕 + 失败可降级」。因此三个适配器都遵守同一契约：

* 返回 :class:`ChannelResult`（``success`` / ``retryable`` / ``permanent``）；
* **运输层由外部注入**（``transport``）：缺省 ``None`` 表示未接线 → ``retryable`` +
  短码 ``transport_not_wired``，由 ``dispatch`` 记进 ``delivery_attempts``（可观测、可重放）；
* 不读环境变量、不建连接、不打日志里的收件地址（INV-07）。

返回值口径（§6.3）：2xx 成功；4xx（除 429）永久失败；429 / 5xx / 超时 / 连接错误按重试处理。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from . import facts, signing
from .models import Notification

__all__ = ["ChannelResult", "Channel", "InAppChannel", "EmailChannel", "WebhookChannel",
           "WebhookTarget", "classify_http_status", "webhook_body"]

#: HTTP 传输层：``(url, headers, body, timeout_s) -> int``（抛异常视为可重试）
WebhookTransport = Callable[[str, Mapping[str, str], bytes, float], int]
#: 邮件传输层：``(notification) -> bool``（True=成功；抛异常 / False 视为可重试）
EmailTransport = Callable[[Notification], bool]


@dataclass(frozen=True)
class ChannelResult:
    """一次渠道尝试的结果（直接决定 ``delivery_attempts.status``）。"""

    status: str
    error_code: str | None = None
    provider_ref: str | None = None
    latency_ms: int | None = None

    def __post_init__(self) -> None:
        if self.status not in facts.ATTEMPT_STATUSES:
            raise ValueError(f"未知尝试状态：{self.status!r}")
        if self.status == "success" and self.error_code is not None:
            raise ValueError("成功尝试不得带 error_code")
        if self.status != "success" and not self.error_code:
            raise ValueError("失败尝试必须带短码 error_code")


class Channel(Protocol):
    name: str

    def deliver(self, notification: Notification, **kwargs: Any) -> ChannelResult:  # pragma: no cover
        ...


@dataclass(frozen=True)
class WebhookTarget:
    """投递目标（订阅 + **调用方注入的 secret**）。

    注意（S1 事实）：库里只有 ``secret_hash``（INV-05），派发器拿不到明文，
    所以真实投递需要 S2 用 KMS 封装的密钥引用（见证据文件「遗留项」）。
    """

    subscription_id: str
    url: str
    secret: str
    event: str = "notification"


class InAppChannel:
    """站内信：记录在触发时已落库（INV-02），这里只做「已读提醒」的投递确认。"""

    name = "in_app"

    def deliver(self, notification: Notification, **_: Any) -> ChannelResult:
        return ChannelResult(status="success", provider_ref=f"in_app:{notification.id}",
                             latency_ms=0)


class EmailChannel:
    """邮件：S1 只留接口。``transport=None`` → ``retryable / transport_not_wired``。"""

    name = "email"

    def __init__(self, transport: EmailTransport | None = None) -> None:
        self.transport = transport

    def deliver(self, notification: Notification, **_: Any) -> ChannelResult:
        if self.transport is None:
            return ChannelResult(status="retryable", error_code="transport_not_wired")
        started = time.monotonic()
        try:
            ok = self.transport(notification)
        except TimeoutError:
            return ChannelResult(status="retryable", error_code="smtp_timeout",
                                 latency_ms=_ms(started))
        except Exception as exc:                          # noqa: BLE001 - 只记类型短码
            return ChannelResult(status="retryable",
                                 error_code=f"smtp_{type(exc).__name__[:24].lower()}",
                                 latency_ms=_ms(started))
        if ok:
            return ChannelResult(status="success", provider_ref="email:accepted",
                                 latency_ms=_ms(started))
        return ChannelResult(status="retryable", error_code="smtp_rejected",
                             latency_ms=_ms(started))


class WebhookChannel:
    """Webhook：签名头 + 状态码分类；``transport=None`` → 未接线（不出网）。"""

    name = "webhook"

    def __init__(self, transport: WebhookTransport | None = None,
                 timeout_s: int = 10) -> None:
        self.transport = transport
        self.timeout_s = timeout_s

    def deliver(self, notification: Notification, *, target: WebhookTarget | None = None,
                now: Any = None, **_: Any) -> ChannelResult:
        if target is None:
            return ChannelResult(status="retryable", error_code="no_active_subscription")
        if self.transport is None:
            return ChannelResult(status="retryable", error_code="transport_not_wired",
                                 provider_ref=target.subscription_id)
        body = webhook_body(notification, event=target.event)
        headers = signing.sign_headers(target.secret, target.event, body, now=now)
        headers["Content-Type"] = "application/json"
        started = time.monotonic()
        try:
            status_code = int(self.transport(target.url, headers, body,
                                             float(self.timeout_s)))
        except TimeoutError:
            return ChannelResult(status="retryable", error_code="webhook_timeout",
                                 provider_ref=target.subscription_id, latency_ms=_ms(started))
        except Exception as exc:                          # noqa: BLE001 - 只记类型短码
            return ChannelResult(status="retryable",
                                 error_code=f"transport_{type(exc).__name__[:24].lower()}",
                                 provider_ref=target.subscription_id, latency_ms=_ms(started))
        verdict = classify_http_status(status_code)
        return ChannelResult(status=verdict,
                             error_code=None if verdict == "success" else f"http_{status_code}",
                             provider_ref=target.subscription_id, latency_ms=_ms(started))


def classify_http_status(status_code: int) -> str:
    """§6.3：2xx 成功；4xx（除 429）永久失败；429 / 5xx 可重试。"""
    if 200 <= status_code < 300:
        return "success"
    if status_code == 429:
        return "retryable"
    if 400 <= status_code < 500:
        return "permanent"
    return "retryable"


def webhook_body(notification: Notification, *, event: str) -> bytes:
    """对端收到的 body（原始字节参与验签）：只放 id / 模板 / 时间 / payload 短字段。"""
    payload = {
        "event": event,
        "notification_id": str(notification.id),
        "level": notification.level,
        "type": notification.type,
        "template_key": notification.template_key,
        "created_at": notification.created_at.isoformat(),
        "payload": notification.payload,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))
