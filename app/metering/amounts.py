# SPDX-License-Identifier: AGPL-3.0-or-later
"""金额与用量的**精确整数**换算（00-conventions §3 / INV-05 / 03-facts §6）。

三条硬规则：

1. **不做浮点**：入口只接受 ``int`` 或十进制**字符串**；``float`` 直接拒绝（避免 0.1+0.2 类漂移）。
2. **超精度直接拒绝，不四舍五入**：金额最多 2 位小数（USD 分），单价最多 6 位（micro-USD）；
   多一位就 ``AmountError(reason="amount_precision")``，由域层翻成 40001。
3. **金额 = 用量 × 单价 必须整除**：``compute_amount_minor`` 用整数乘 + ``divmod``，余数非 0
   即拒绝——这是 INV-05「超精度直接拒绝」在乘法侧的落点，也保证与 M06 E6 的整数分完全可复算。

单位口径：金额 ``amount_minor`` 是 USD 分（1e-2 USD）；单价 ``*_micro`` 是 micro-USD
（1e-6 USD，与 M06 ``unit_scale=6`` 同源）；``MICRO_PER_MINOR = 10^4``。
"""
from __future__ import annotations

import re
from typing import Any

from . import facts

_AMOUNT_RE = re.compile(r"^-?[0-9]+(?:\.[0-9]+)?$")


class AmountError(ValueError):
    """金额 / 用量解析失败；``reason`` 与 :mod:`app.metering.errors` 的 reason 同词表。"""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _digits(value: Any, *, field: str, max_scale: int, allow_negative: bool) -> tuple[int, int]:
    """把 ``int`` / 十进制字符串拆成 (整数部分, 小数位数)，并做精度与符号校验。"""
    if isinstance(value, bool):
        raise AmountError(f"{field} 不接受布尔值", reason="amount_type")
    if isinstance(value, int):
        if value < 0 and not allow_negative:
            raise AmountError(f"{field} 不能为负（{value}）", reason="amount_negative")
        return value, 0
    if isinstance(value, float):
        raise AmountError(f"{field} 不接受浮点（会丢精度）：请传十进制字符串",
                          reason="amount_type")
    if not isinstance(value, str):
        raise AmountError(f"{field} 必须是整数或十进制字符串，收到 {type(value).__name__}",
                          reason="amount_type")
    text = value.strip()
    if not text or len(text) > facts.MAX_AMOUNT_STR_LEN:
        raise AmountError(f"{field} 长度非法（1..{facts.MAX_AMOUNT_STR_LEN}）",
                          reason="amount_invalid")
    if not _AMOUNT_RE.match(text):
        raise AmountError(f"{field} 不是合法十进制数：{text!r}", reason="amount_invalid")
    negative = text.startswith("-")
    body = text[1:] if negative else text
    whole, _, frac = body.partition(".")
    if len(frac) > max_scale:
        raise AmountError(
            f"{field} 超出精度上限（最多 {max_scale} 位小数）：{text!r}（INV-05 不四舍五入）",
            reason="amount_precision")
    if negative and not allow_negative:
        raise AmountError(f"{field} 不能为负：{text!r}", reason="amount_negative")
    return int(whole), len(frac)


def parse_minor(value: Any, *, field: str = "amount", allow_negative: bool = False) -> int:
    """金额 → 整数最小单位（USD 分）。

    两种输入语义（刻意区分，避免「1234 到底是美元还是分」的歧义）：

    * **字符串** = spec ``Amount.amount`` 的形状，按**主单位**（USD）解析：
      ``"12.34"`` → ``1234``；``"12.3"`` → ``1230``；``"1234"`` → ``123400``（= 1234 USD）；
    * **整数** = 内部已换算好的**最小单位**（分）直传：``1234`` → ``1234``。
    """
    whole, scale = _digits(value, field=field, max_scale=facts.MINOR_UNIT_SCALE,
                           allow_negative=allow_negative)
    if isinstance(value, int):
        return whole
    negative = str(value).strip().startswith("-")
    magnitude = abs(whole) * facts.MINOR_PER_MAJOR
    frac_digits = str(value).strip().lstrip("-").partition(".")[2]
    if scale:
        magnitude += int(frac_digits.ljust(facts.MINOR_UNIT_SCALE, "0"))
    return -magnitude if negative else magnitude


def parse_micro(value: Any, *, field: str = "unit_price", allow_negative: bool = False) -> int:
    """单价 → micro-USD（1e-6 USD）。``"0.0005"`` → ``500``。"""
    whole, scale = _digits(value, field=field, max_scale=facts.PRICE_MICRO_SCALE,
                           allow_negative=allow_negative)
    if isinstance(value, int):
        return whole * 10 ** facts.PRICE_MICRO_SCALE
    text = str(value).strip()
    negative = text.startswith("-")
    body = text.lstrip("-")
    whole_text, _, frac_text = body.partition(".")
    magnitude = int(whole_text) * 10 ** facts.PRICE_MICRO_SCALE
    magnitude += int(frac_text.ljust(facts.PRICE_MICRO_SCALE, "0") or "0")
    return -magnitude if negative else magnitude


def parse_quantity(value: Any, *, field: str = "quantity") -> int:
    """计量值（tokens / 请求数）→ 非负整数；小数（哪怕 ``"1000.0"`` 之外）一律拒绝。"""
    if isinstance(value, bool):
        raise AmountError(f"{field} 不接受布尔值", reason="amount_type")
    if isinstance(value, int):
        if value < 0:
            raise AmountError(f"{field} 不能为负（{value}）", reason="amount_negative")
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text or len(text) > facts.MAX_AMOUNT_STR_LEN:
            raise AmountError(f"{field} 长度非法", reason="amount_invalid")
        whole, _, frac = text.partition(".")
        if not whole.isdigit() or (frac and (not frac.isdigit() or int(frac) != 0)):
            raise AmountError(f"{field} 必须是非负整数（收到 {text!r}）", reason="amount_invalid")
        return int(whole)
    raise AmountError(f"{field} 必须是整数或十进制字符串", reason="amount_type")


def format_minor(minor: int) -> str:
    """整数分 → 十进制字符串（API 里 ``Amount.amount`` 的形状；不丢精度）。"""
    if not isinstance(minor, int) or isinstance(minor, bool):
        raise AmountError("format_minor 只接受整数分", reason="amount_type")
    sign = "-" if minor < 0 else ""
    magnitude = abs(minor)
    whole, frac = divmod(magnitude, facts.MINOR_PER_MAJOR)
    return f"{sign}{whole}.{frac:0{facts.MINOR_UNIT_SCALE}d}"


def compute_amount_minor(*, tokens_in: int, tokens_out: int,
                         in_price_micro: int, out_price_micro: int) -> int:
    """``amount = tokens_in × in_price + tokens_out × out_price``（INV-05，整数精确）。

    单价是 micro-USD/token，结果是 USD 分；**余数非 0 即拒绝**（不能用四舍五入凑数）。
    """
    for name, value in (("tokens_in", tokens_in), ("tokens_out", tokens_out),
                        ("in_price_micro", in_price_micro),
                        ("out_price_micro", out_price_micro)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise AmountError(f"{name} 必须是非负整数（收到 {value!r}）", reason="amount_invalid")
    total_micro = tokens_in * in_price_micro + tokens_out * out_price_micro
    amount_minor, remainder = divmod(total_micro, facts.MICRO_PER_MINOR)
    if remainder:
        raise AmountError(
            f"金额不是整数分：{total_micro} micro-USD 余 {remainder}（INV-05 不四舍五入）",
            reason="amount_precision")
    return amount_minor


def is_integral_minor(value: Any) -> bool:
    """``value`` 是否可无损换算成整数分（单价复算前的形状检查）。"""
    try:
        parse_minor(value)
    except AmountError:
        return False
    return True


__all__ = ["AmountError", "parse_minor", "parse_micro", "parse_quantity", "format_minor",
           "compute_amount_minor", "is_integral_minor"]
