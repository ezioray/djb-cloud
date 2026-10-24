# SPDX-License-Identifier: AGPL-3.0-or-later
"""M05 领域模型：UUIDv7、收据解析（spec ``ReceiptInput``）、受理结论与用量行。

这里只做**纯函数**（无 DB、无网络、无时钟副作用）：把上报 JSON 变成 :class:`ReceiptDraft`，
并做一切形态 / 精度 / 枚举校验；验签与窗口判定在 :mod:`app.metering.receipts`。

形状约定（spec 1.2.0 ``ReceiptInput`` + M05 §8.2）：

* 规范字段 6 个：``receipt_id / task_id / access / usage_amount / usage_unit / price_amount``；
  spec 的嵌套写法 ``usage: {amount, unit}`` / ``price: Amount`` 与 M05 §8.2 的扁平写法
  （``usage_amount`` / ``usage_unit`` / ``price_amount``）**都接受**，落库一律存**上报原样字符串**
  （签名要用的就是它，不能拿 NUMERIC 回读值重排）。
* 非规范字段（不进签名）：``node_id`` / ``request_id`` / ``model`` / ``tokens_in`` /
  ``tokens_out`` / ``usage_source`` / ``account_id`` / ``reported_at`` / ``attempt_no``。
* 金额：``price_amount`` 是**应收总额**（S1 只收 USD；M05 不定价，价由 M04 成交价给出），
  入口即转整数分；``price.unit = usd_minor`` 时数字本身就是整数分（内部/测试便捷写法）。
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from typing import Any, Mapping

from . import amounts, clock, errors, facts


# ───────────────────────────────────────────────────────────────────── UUIDv7
def uuid7(moment: datetime | None = None) -> uuid.UUID:
    """UUIDv7（时间有序，00-conventions §2）：48 bit 毫秒时间戳 + 版本/变体 + 80 bit 随机。"""
    epoch_ms = int(clock.as_utc(moment or clock.utcnow()).timestamp() * 1_000) & ((1 << 48) - 1)
    random_bits = int.from_bytes(os.urandom(10), "big")
    value = (epoch_ms << 80) | (0x7 << 76)
    value |= ((random_bits >> 68) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= random_bits & ((1 << 62) - 1)
    return uuid.UUID(int=value)


# ───────────────────────────────────────────────────────────────────── 文本 / 时间工具
def require_text(value: Any, *, field: str, max_len: int, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise errors.InvalidArgument(f"缺 {field}", field=field)
        return None
    if not isinstance(value, str):
        raise errors.InvalidArgument(f"{field} 必须是字符串", field=field)
    text = value.strip()
    if not text or len(text) > max_len:
        raise errors.InvalidArgument(f"{field} 长度必须是 1..{max_len}", field=field)
    return text


def require_enum(value: Any, *, field: str, allowed: tuple[str, ...],
                 default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str):
        raise errors.InvalidArgument(f"{field} 必须是字符串", field=field, allowed=list(allowed))
    text = value.strip()
    if text not in allowed:
        raise errors.InvalidArgument(f"{field} 取值非法：{text!r}", field=field,
                                     allowed=list(allowed))
    return text


def parse_moment(value: Any, *, field: str, end_of_day: bool = False) -> datetime:
    """解析 ``YYYY-MM-DD`` 或 RFC 3339；日期按 UTC 日界（``to`` 含端点取当日末）。"""
    if isinstance(value, datetime):
        return clock.as_utc(value)
    if not isinstance(value, str) or not value.strip():
        raise errors.InvalidArgument(f"{field} 必须是日期或 RFC 3339 时间", field=field)
    text = value.strip()
    try:
        if len(text) == len("YYYY-MM-DD"):
            day = date.fromisoformat(text)
            moment = datetime.combine(day, time.max if end_of_day else time.min)
            return moment.replace(tzinfo=timezone.utc)
        normalised = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        return clock.as_utc(datetime.fromisoformat(normalised))
    except ValueError as exc:
        raise errors.InvalidArgument(
            f"{field} 不是合法时间（要 YYYY-MM-DD 或 RFC 3339）：{text!r}", field=field) from exc


def iso(moment: datetime | None) -> str | None:
    """UTC ISO-8601（带 Z）。"""
    if moment is None:
        return None
    return clock.as_utc(moment).isoformat().replace("+00:00", "Z")


# ───────────────────────────────────────────────────────────────────── 收据
@dataclass(frozen=True)
class ReceiptDraft:
    """一条通过**形态校验**的收据（尚未验签）。``*_amount`` 保留上报原样字符串。"""

    receipt_id: str
    task_id: str
    access: str
    usage_amount: str
    usage_unit: str
    price_amount: str
    price_minor: int
    usage_qty: int
    sig_provider: str
    sig_consumer: str
    request_id: str
    model: str
    tokens_in: int
    tokens_out: int
    usage_source: str
    attempt_no: int = 1
    node_id: str | None = None
    account_id: str | None = None
    reported_at: datetime = field(default_factory=clock.utcnow)

    def canonical_fields(self) -> dict[str, str]:
        """参与签名的 6 个字段（原样字符串；顺序由 :mod:`signing` 决定）。"""
        return {name: getattr(self, name) for name in facts.CANONICAL_FIELDS}


def _amount_block(raw: Mapping[str, Any]) -> tuple[Any, Any, Any, Any]:
    """取 (usage_amount, usage_unit, price_amount, price_unit)；兼容嵌套与扁平两种写法。"""
    usage = raw.get("usage") if isinstance(raw.get("usage"), Mapping) else {}
    price = raw.get("price") if isinstance(raw.get("price"), Mapping) else {}
    usage_amount = usage.get("amount", raw.get("usage_amount"))
    usage_unit = usage.get("unit", raw.get("usage_unit"))
    price_amount = price.get("amount", raw.get("price_amount"))
    price_unit = price.get("unit", raw.get("price_unit"))
    return usage_amount, usage_unit, price_amount, price_unit


def _original_text(value: Any, *, field: str) -> str:
    """规范串要用的**原样文本**：字符串保持原样，整数转十进制（float 直接拒绝）。"""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise errors.InvalidArgument(f"缺 {field}", field=field)
        return text
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        raise errors.InvalidArgument(f"{field} 不接受浮点（会丢精度），请传十进制字符串",
                                     field=field)
    raise errors.InvalidArgument(f"缺 {field}", field=field)


def _price_minor(original: str, unit: Any) -> int:
    unit_text = (unit or facts.CURRENCY)
    if not isinstance(unit_text, str):
        raise errors.InvalidArgument("price.unit 必须是字符串", field="price.unit")
    normalised = unit_text.strip().lower()
    if normalised in {facts.CURRENCY.lower(), "usd"}:
        try:
            return amounts.parse_minor(original, field="price_amount")
        except amounts.AmountError as exc:
            raise _amount_error(exc, field="price_amount") from exc
    if normalised == f"{facts.CURRENCY.lower()}_minor":
        try:
            return amounts.parse_quantity(original, field="price_amount")
        except amounts.AmountError as exc:
            raise _amount_error(exc, field="price_amount") from exc
    raise errors.UnsupportedCurrency(
        f"S1 只收 {facts.CURRENCY} 计价，收到 price.unit={unit_text!r}（不做汇率换算）")


def _amount_error(exc: amounts.AmountError, *, field: str) -> errors.MeteringError:
    if exc.reason == "amount_precision":
        return errors.AmountPrecisionRejected(f"{field}: {exc}", field=field)
    if exc.reason == "amount_negative":
        return errors.InvalidArgument(f"{field}: {exc}", field=field, code_hint="negative")
    if exc.reason == "amount_type":
        return errors.InvalidArgument(f"{field}: {exc}", field=field)
    return errors.InvalidArgument(f"{field}: {exc}", field=field)


def parse_receipt(raw: Any, *, now: datetime | None = None) -> ReceiptDraft:
    """把一条上报收据解析成 :class:`ReceiptDraft`；任何形态问题 → ``InvalidArgument``（40001）。"""
    if not isinstance(raw, Mapping):
        raise errors.InvalidArgument("收据必须是 JSON 对象")
    moment = clock.as_utc(now or clock.utcnow())

    receipt_id = require_text(raw.get("receipt_id"), field="receipt_id", max_len=facts.MAX_ID_LEN)
    task_id = require_text(raw.get("task_id"), field="task_id", max_len=facts.MAX_ID_LEN)
    access = require_enum(raw.get("access"), field="access", allowed=facts.ACCESS_MODES)

    usage_amount_raw, usage_unit_raw, price_amount_raw, price_unit = _amount_block(raw)
    usage_amount = _original_text(usage_amount_raw, field="usage.amount")
    usage_unit = require_text(usage_unit_raw, field="usage.unit", max_len=facts.MAX_UNIT_LEN)
    price_amount = _original_text(price_amount_raw, field="price.amount")
    price_minor = _price_minor(price_amount, price_unit)

    try:
        usage_qty = amounts.parse_quantity(usage_amount, field="usage.amount")
    except amounts.AmountError as exc:
        raise _amount_error(exc, field="usage.amount") from exc

    tokens_in = _non_negative_int(raw.get("tokens_in", 0), field="tokens_in")
    tokens_out = _non_negative_int(raw.get("tokens_out", 0), field="tokens_out")
    if usage_unit == "token" and tokens_in + tokens_out != usage_qty:
        raise errors.InvalidArgument(
            f"usage.amount({usage_qty}) 必须等于 tokens_in + tokens_out({tokens_in + tokens_out})",
            field="usage.amount")

    request_id = require_text(raw.get("request_id"), field="request_id",
                              max_len=facts.MAX_ID_LEN)
    model = require_text(raw.get("model"), field="model", max_len=facts.MAX_ID_LEN)
    sig_provider = raw.get("sig_provider")
    sig_consumer = raw.get("sig_consumer")
    for name, value in (("sig_provider", sig_provider), ("sig_consumer", sig_consumer)):
        if value is not None and not isinstance(value, str):
            raise errors.InvalidArgument(f"{name} 必须是字符串", field=name)

    attempt_no = _non_negative_int(raw.get("attempt_no", 1), field="attempt_no")
    if attempt_no < 1:
        raise errors.InvalidArgument("attempt_no 从 1 开始", field="attempt_no")

    reported_raw = raw.get("reported_at")
    reported_at = parse_moment(reported_raw, field="reported_at") if reported_raw else moment
    # 未来时间按服务端 now 截断（00-conventions §4.4：时间比较只用服务端时间）
    if reported_at > moment:
        reported_at = moment

    account_id = raw.get("account_id")
    if account_id is not None:
        try:
            account_id = str(uuid.UUID(str(account_id)))
        except (ValueError, AttributeError, TypeError) as exc:
            raise errors.InvalidArgument("account_id 必须是 UUID", field="account_id") from exc

    return ReceiptDraft(
        receipt_id=receipt_id, task_id=task_id, access=access, usage_amount=usage_amount,
        usage_unit=usage_unit, price_amount=price_amount, price_minor=price_minor,
        usage_qty=usage_qty, sig_provider=sig_provider or "", sig_consumer=sig_consumer or "",
        request_id=request_id, model=model, tokens_in=tokens_in, tokens_out=tokens_out,
        usage_source=require_enum(raw.get("usage_source"), field="usage_source",
                                  allowed=facts.USAGE_SOURCES, default="dual"),
        attempt_no=attempt_no,
        node_id=require_text(raw.get("node_id"), field="node_id",
                             max_len=facts.MAX_ID_LEN, required=False),
        account_id=account_id, reported_at=reported_at)


def _non_negative_int(value: Any, *, field: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise errors.InvalidArgument(f"{field} 必须是非负整数", field=field)
    if isinstance(value, int):
        if value < 0:
            raise errors.InvalidArgument(f"{field} 必须是非负整数", field=field)
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    raise errors.InvalidArgument(f"{field} 必须是非负整数", field=field)


# ───────────────────────────────────────────────────────────────────── 受理结论
@dataclass(frozen=True)
class ReceiptVerdict:
    """单条收据的受理结论（逐条受理，INV-02）。"""

    receipt_id: str
    state: str                                   # accepted / rejected / expired
    usage_id: str | None = None
    code: int | None = None
    reason: str | None = None
    message: str | None = None
    duplicate: bool = False

    @property
    def accepted(self) -> bool:
        return self.state == "accepted"


@dataclass(frozen=True)
class BatchOutcome:
    """整批受理结果（spec ``ReceiptBatchResponse`` + 事件信封；T3 负责投递）。"""

    accepted: tuple[str, ...] = ()
    rejected: tuple[ReceiptVerdict, ...] = ()
    duplicates: tuple[str, ...] = ()
    events: tuple[dict[str, Any], ...] = ()
    verdicts: tuple[ReceiptVerdict, ...] = ()

    def as_response(self) -> dict[str, Any]:
        """``{accepted: [...], rejected: [{receipt_id, code, message}], duplicates: [...]}``。"""
        return {
            "accepted": list(self.accepted),
            "rejected": [{"receipt_id": item.receipt_id, "code": int(item.code or 40001),
                          "message": item.message or "收据未受理",
                          **({"reason": item.reason} if item.reason else {})}
                         for item in self.rejected],
            "duplicates": list(self.duplicates),
        }


@dataclass(frozen=True)
class UsageRow:
    """``usage_records`` 的一行（只读视图，供明细 / 汇总）。"""

    usage_id: str
    request_id: str
    attempt_no: int
    account_id: str
    node_id: str
    model: str
    access: str
    tokens_in: int
    tokens_out: int
    amount_minor: int
    usage_source: str
    state: str
    receipt_id: str | None
    correction_id: str | None
    recorded_at: datetime

    def as_dict(self) -> dict[str, Any]:
        """spec ``UsageRecord`` 形状（金额是 ``Amount`` 对象）。"""
        return {
            "usage_id": self.usage_id,
            "request_id": self.request_id,
            "attempt_no": self.attempt_no,
            "node_id": self.node_id,
            "model": self.model,
            "access": self.access,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "amount": {"amount": amounts.format_minor(self.amount_minor),
                       "unit": facts.CURRENCY},
            "usage_source": self.usage_source,
            "state": self.state,
            "receipt_id": self.receipt_id,
            "correction_id": self.correction_id,
            "recorded_at": iso(self.recorded_at),
        }


__all__ = [
    "uuid7", "require_text", "require_enum", "parse_moment", "iso", "ReceiptDraft",
    "parse_receipt", "ReceiptVerdict", "BatchOutcome", "UsageRow",
]
