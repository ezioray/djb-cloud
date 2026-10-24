# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12 常量、枚举与口径校验（规格 §5 枚举 / §8.2 常量 / INV-03 / INV-07）。

这一层是**纯函数 + 常量**，不碰数据库、不碰网络，方便单测把边界钉死：

* ``LEVELS`` / ``CHANNELS`` / 状态机枚举 —— 与 M12 §5 逐字对齐，只加不改；
* ``dedupe_bucket()`` —— INV-03 的 ``floor(created_at / notify.merge_window_s)``；
* ``validate_payload()`` —— INV-07 零正文 / 零 PII 的最后一道闸（DB 约束是兜底）。

金额一律整数最小单位（``amount_minor``，03-facts §6 / 00-conventions §3），本模块不解析小数。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

__all__ = [
    "LEVELS", "CHANNELS", "CHANNEL_ORDER", "NOTIFICATION_STATUSES", "ATTEMPT_STATUSES",
    "SUBSCRIPTION_STATUSES", "DIGESTS", "WEBHOOK_EVENTS", "TERMINAL_STATUSES", "SCOPE_CUSTOMER",
    "SCOPE_INTERNAL", "SIGNATURE_ALG", "SIGNATURE_WINDOW_S", "DEFAULT_LIMIT", "MAX_LIMIT",
    "DISPATCH_BATCH", "MAX_ATTEMPTS_PER_CHANNEL", "WEBHOOK_RETRY_DELAYS_S", "EMAIL_RETRY_COUNT",
    "WEBHOOK_MAX_PER_ACCOUNT", "MERGE_WINDOW_S", "INBOX_RETENTION_DAYS", "EVENT_BACKOFF_S",
    "EVENT_MAX_ATTEMPTS", "PII_KEYS", "dedupe_bucket", "validate_level", "validate_channels",
    "validate_events", "validate_digest", "validate_payload", "looks_like_email",
    "looks_like_phone", "normalize_hhmm",
]

# ── §5 枚举（只加不改）
LEVELS: tuple[str, ...] = ("P0", "P1", "P2")
CHANNELS: tuple[str, ...] = ("in_app", "email", "webhook")
#: §6.2 分派顺序：站内 → 邮件 → Webhook
CHANNEL_ORDER: tuple[str, ...] = ("in_app", "email", "webhook")
NOTIFICATION_STATUSES: tuple[str, ...] = ("queued", "sending", "delivered", "partial",
                                          "failed", "dead")
ATTEMPT_STATUSES: tuple[str, ...] = ("success", "retryable", "permanent")
SUBSCRIPTION_STATUSES: tuple[str, ...] = ("active", "paused", "disabled")
DIGESTS: tuple[str, ...] = ("realtime", "daily", "weekly")
#: spec 1.2.3 ``WebhookSubscription.events`` 枚举（CR-5：以 spec 为准）
WEBHOOK_EVENTS: tuple[str, ...] = ("task.completed", "task.failed", "payment.settled",
                                   "payout.sent", "security.alert")
#: 终态：不再自动重投，只能人工重放（§3 状态机）
TERMINAL_STATUSES: tuple[str, ...] = ("delivered", "partial", "dead")

SCOPE_CUSTOMER = "customer"
SCOPE_INTERNAL = "internal"
SCOPES: tuple[str, ...] = (SCOPE_CUSTOMER, SCOPE_INTERNAL)

# ── §8.2 常量（算法与工程参数）
SIGNATURE_ALG = "sha256"
SIGNATURE_WINDOW_S = 300                 # 时间戳偏差 ≤300 s
DEFAULT_LIMIT = 50                        # 00-conventions §5 分页默认
MAX_LIMIT = 200                           # 分页上限
DISPATCH_BATCH = 200                      # dispatcher 批大小
MAX_ATTEMPTS_PER_CHANNEL = 3              # 每通知每渠道最大尝试
WEBHOOK_RETRY_DELAYS_S: tuple[int, ...] = (1, 10, 60)
EMAIL_RETRY_COUNT = 3
WEBHOOK_MAX_PER_ACCOUNT = 5
MERGE_WINDOW_S = 3600                     # notify.merge_window_s 默认
INBOX_RETENTION_DAYS = 180
#: 02-events §2.3 退避（1s/5s/30s/5min/30min，最多 8 次 → DLQ）
EVENT_BACKOFF_S: tuple[int, ...] = (1, 5, 30, 300, 1800)
EVENT_MAX_ATTEMPTS = 8

#: INV-07：这些键一旦出现即视为 PII / 正文 / 凭据泄漏（DB 层同样有约束兜底）
PII_KEYS: frozenset[str] = frozenset({
    "email", "email_address", "phone", "phone_number", "mobile", "msisdn",
    "secret", "password", "token", "api_key", "private_key", "mnemonic", "seed",
    "body", "content", "html", "text", "message", "subject", "attachment",
    "ip", "address", "full_name", "real_name", "id_card", "passport",
})

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
#: 只认「明显是手机号」的形态：E.164 带加号，或中国大陆 11 位手机号
_PHONE_RE = re.compile(r"^(\+[1-9][0-9]{6,14}|1[3-9][0-9]{9})$")
_HHMM_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

#: payload 里**允许**出现的键（INV-07：id / 金额 / 时间 / 原因码 + 少量计数与短码）
_ALLOWED_KEYS: frozenset[str] = frozenset({
    "id", "notification_id", "account_id", "event_id", "order_no", "refund_no", "batch_no",
    "payout_no", "intent_id", "run_id", "period", "wallet_id", "pool_id", "case_id",
    "exception_id", "snapshot_id", "session_id", "api_key_id", "subject_id", "txid",
    "amount_minor", "currency", "amount", "total_minor", "item_count", "count",
    "occurred_at", "paid_at", "created_at", "at", "period_start", "period_end",
    "reason_code", "error_code", "status", "channel", "channels", "attempt", "level", "type",
    "risk_type", "severity", "limit_type", "coverage_pct", "tier", "source",
    "template", "template_key", "recipients_count", "p0", "p1", "p2", "from", "to",
    "action", "result",
})


def dedupe_bucket(created_at: datetime, window_s: int = MERGE_WINDOW_S) -> int:
    """INV-03：``dedupe_bucket = floor(created_at / notify.merge_window_s)``（UTC 秒）。

    ``naive`` 时间按 UTC 处理，**不跟随服务器本地时区**——否则同一事件在不同机器上
    会算出不同 bucket，合并去重就失效了。
    """
    if window_s <= 0:
        raise ValueError("merge_window_s 必须为正整数")
    moment = created_at if created_at.tzinfo is not None else created_at.replace(
        tzinfo=timezone.utc)
    return int(moment.timestamp()) // int(window_s)


def looks_like_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value))


def looks_like_phone(value: str) -> bool:
    return bool(_PHONE_RE.match(value))


def normalize_hhmm(value: str) -> str:
    """``HH:MM``（00:00–23:59）；返回原串，不合法抛 ``ValueError``。"""
    if not isinstance(value, str) or not _HHMM_RE.match(value):
        raise ValueError(f"时间必须是 HH:MM（00:00–23:59）：{value!r}")
    return value


def validate_level(level: str) -> str:
    if level not in LEVELS:
        raise ValueError(f"level 必须是 {LEVELS} 之一：{level!r}")
    return level


def validate_channels(channels: Iterable[str]) -> tuple[str, ...]:
    """渠道集合：非空、去重、在枚举内、**必含 in_app**（INV-02 站内必留）。"""
    if isinstance(channels, str):
        raise ValueError("channels 必须是数组（不是字符串）")
    ordered = [channel for channel in CHANNEL_ORDER if channel in set(channels)]
    unknown = set(channels) - set(CHANNELS)
    if unknown:
        raise ValueError(f"未知渠道：{sorted(unknown)}")
    if "in_app" not in ordered:
        raise ValueError("channels 必含 in_app（INV-02 站内记录必留）")
    return tuple(ordered)


def validate_events(events: Iterable[str]) -> tuple[str, ...]:
    if isinstance(events, str):
        raise ValueError("events 必须是数组（不是字符串）")
    values = list(dict.fromkeys(events))
    if not values:
        raise ValueError("events 不能为空（spec minItems=1）")
    unknown = [event for event in values if event not in WEBHOOK_EVENTS]
    if unknown:
        raise ValueError(f"未登记的事件：{unknown}（spec 枚举 {list(WEBHOOK_EVENTS)}）")
    return tuple(values)


def validate_digest(digest: str) -> str:
    if digest not in DIGESTS:
        raise ValueError(f"digest 必须是 {DIGESTS} 之一：{digest!r}")
    return digest


def validate_payload(payload: Mapping[str, Any] | None, *, scope: str = SCOPE_CUSTOMER) -> dict:
    """INV-07 / INV-09：payload 只允许 id、金额、时间、原因码与短码。

    * 键必须在白名单里（``_ALLOWED_KEYS``）且不在 ``PII_KEYS`` 里；
    * 值只允许 ``str | int | float | bool | None`` 以及它们的**一维列表**；
    * 字符串长度 ≤128（不许塞正文），且不得是邮箱 / 手机号；
    * 对客模板（``scope='customer'``）额外拒绝内部处置字段（判定逻辑 / 阈值 / 处置动作）。
    """
    if scope not in SCOPES:
        raise ValueError(f"未知模板域：{scope!r}")
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise ValueError("payload 必须是对象")
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not _KEY_RE.match(key):
            raise ValueError(f"payload 键不合法：{key!r}")
        lowered = key.lower()
        if lowered in PII_KEYS:
            raise ValueError(f"payload 含 PII / 正文键：{key!r}（INV-07）")
        if lowered not in _ALLOWED_KEYS:
            raise ValueError(f"payload 键未登记：{key!r}（先在 facts._ALLOWED_KEYS 登记）")
        if scope == SCOPE_CUSTOMER and lowered in {"decision", "rule", "threshold",
                                                   "internal_note", "handling", "action"}:
            raise ValueError(f"对客模板不得包含内部处置字段：{key!r}（INV-09）")
        cleaned[key] = _clean_value(key, value)
    return cleaned


def _clean_value(key: str, value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return [_clean_scalar(key, item) for item in value]
    return _clean_scalar(key, value)


def _clean_scalar(key: str, value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if not isinstance(value, str):
        raise ValueError(f"payload 值类型不支持（{key}）：{type(value).__name__}")
    if len(value) > 128:
        raise ValueError(f"payload 值过长（{key}）：疑似正文（INV-07）")
    if looks_like_email(value) or looks_like_phone(value):
        raise ValueError(f"payload 值疑似邮箱 / 手机号（{key}）：{value[:6]}…（INV-07）")
    return value
