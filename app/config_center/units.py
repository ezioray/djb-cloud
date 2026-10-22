# SPDX-License-Identifier: Apache-2.0
"""单位与量纲校验（§21.3.2「单位与量纲强制」）。

这一层只回答「这个值在它声明的量纲下合不合法、规范化成什么」，不回答「这个键该取多少」：
键级范围 / 枚举 / 跨字段在 :mod:`app.config_center.validators`。分开的理由是 §21.3.2 的
硬规则对**所有**同类键一致（bps > 10000 一律拒绝），不该由每个键各写一遍。

量纲清单（单位进 key 名是防单位错的第一道，§21.1.3）：

| unit | 唯一表示 | 例子 | 本模块用途 |
| --- | --- | --- | --- |
| boolean | JSON 布尔（不接受 0/1/"true"） | true | 开关 |
| bps | 万分之一整数，0–10000 | 1500 = 15% | 费率 / 分成 / 兑换率 |
| pct | 百分数，整数或 ≤2 位小数字符串，0–100 | 30 = 30% | 预留池 / 折扣 / 上限 |
| usd | **十进制字符串**，最多 2 位小数（§21.3.2） | "10000.00" | 金额型配置 |
| usd_minor | **整数最小单位**（USD 分，04-api-contracts §2.5） | 1000000 = 10,000 USD | 与 amount_minor 对齐的内部口径 |
| seconds / minutes / hours / days | 整数，单位进 key 名 | 86400 | 冷却 / 锁定 |
| count | 非负整数 | 1000 | 数量上限 |
| clock | ``HH:MM``（24h） | "10:00" | 每日发送时刻 |
| window | 对象 {start,end,timezone,weekdays} | 见 :func:`normalize_window` | 发布窗口 |
| enum / text | 字符串（enum 由键级枚举收口） | "INTERNAL" | 模式 / 版本号 |
| json | 对象或数组 | [1,5,25,100] | 灰度步长 / 词表 |

禁止（本层直接拒绝）：浮点数（含 JSON 的 ``1.0``）、科学计数法、无单位小数、布尔冒充整数。
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

from .errors import RangeViolation, TypeMismatch, UnitViolation

__all__ = [
    "UNITS",
    "VALUE_TYPES",
    "UNIT_VALUE_TYPES",
    "BPS_MAX",
    "PCT_MAX",
    "json_type",
    "value_type_matches",
    "is_known_unit",
    "normalize",
    "normalize_amount",
    "normalize_pct",
    "normalize_window",
    "parse_clock",
]

# ───────────────────────────────────────────────────────────── 常量与枚举
BPS_MAX = 10_000        # §21.3.2：_bps 类值 >10000 直接拒绝
PCT_MAX = 100           # §21.3.2：_pct 类值 >100 或 <0 直接拒绝

UNITS: tuple[str, ...] = (
    "boolean", "bps", "pct", "usd", "usd_minor",
    "seconds", "minutes", "hours", "days",
    "count", "clock", "window", "enum", "text", "json",
)

VALUE_TYPES: tuple[str, ...] = ("string", "integer", "number", "boolean", "json")

#: 单位 → 允许的 value_type（spec/openapi.yaml ConfigItem.value_type 五值）
UNIT_VALUE_TYPES: dict[str, tuple[str, ...]] = {
    "boolean": ("boolean",),
    "bps": ("integer",),
    "pct": ("integer", "string"),
    "usd": ("string",),
    "usd_minor": ("integer",),
    "seconds": ("integer",),
    "minutes": ("integer",),
    "hours": ("integer",),
    "days": ("integer",),
    "count": ("integer",),
    "clock": ("string",),
    "window": ("json",),
    "enum": ("string",),
    "text": ("string",),
    "json": ("json",),
}

_NUMERIC_UNITS = frozenset({
    "bps", "pct", "usd", "usd_minor", "count", "seconds", "minutes", "hours", "days",
})
_DIGITS = re.compile(r"^-?\d+$")
_USD = re.compile(r"^\d{1,15}(?:\.\d{1,2})?$")
_PCT = re.compile(r"^\d{1,3}(?:\.\d{1,2})?$")
_CLOCK = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_TZ_OFFSET = re.compile(r"^[+-](?:0\d|1[0-4]):[0-5]\d$")


def is_known_unit(unit: str) -> bool:
    return unit in UNIT_VALUE_TYPES


def json_type(value: Any) -> str | None:
    """值的 spec value_type；不确定返回 None（由调用方报错，不猜）。"""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (dict, list)):
        return "json"
    return None


def value_type_matches(value_type: str, value: Any) -> bool:
    actual = json_type(value)
    if value_type == "integer":
        return actual == "integer"                 # 1.0 是 number 不是 integer（防浮点）
    if value_type == "number":
        return actual in ("integer", "number")
    return actual == value_type


# ───────────────────────────────────────────────────────────── 各量纲规范化
def normalize_amount(value: Any, *, unit: str = "usd", key: str | None = None) -> str:
    """金额十进制字符串（§21.3.2）：拒绝浮点 / 科学计数法 / 无币种小数。

    返回规范化字符串：小数位补齐到 2 位（``"15000"`` → ``"15000.00"``）。
    """
    if isinstance(value, float):
        raise UnitViolation(f"{key or '金额'} 不接受浮点数（{value!r}）；用十进制字符串，§21.3.2",
                            key=key)
    if not isinstance(value, str) or not _USD.match(value):
        raise UnitViolation(
            f"{key or '金额'} 必须是十进制字符串（最多 2 位小数，USD）：{value!r}（§21.3.2）",
            key=key)
    head, _, tail = value.partition(".")
    return f"{int(head)}.{tail.ljust(2, '0')}"


def normalize_usd_minor(value: Any, *, key: str | None = None) -> int:
    """USD 分（整数最小单位，04-api-contracts §2.5 的 amount_minor 口径）。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeMismatch(f"{key or '金额'} 的 usd_minor 必须是整数（USD 分）：{value!r}", key=key)
    if value < 0:
        raise RangeViolation(f"{key or '金额'} 的 usd_minor 不得为负：{value}", key=key)
    return value


def normalize_pct(value: Any, *, key: str | None = None) -> int | str:
    """百分数（§21.3.2）：整数，或 ≤2 位小数的字符串；范围 0–100。

    整数值归一化成 int（存库友好）；带小数的保留字符串（不用 float，防止精度漂移）。
    """
    if isinstance(value, bool):
        raise TypeMismatch(f"{key or '百分数'} 不接受布尔：{value!r}", key=key)
    if isinstance(value, float):
        raise UnitViolation(f"{key or '百分数'} 不接受浮点数（{value!r}）；_pct 用整数或 2 位小数字符串",
                            key=key)
    if isinstance(value, int):
        number: int | Decimal = value
        raw = str(value)
    elif isinstance(value, str) and _PCT.match(value):
        number = Decimal(value)
        raw = value
    else:
        raise UnitViolation(f"{key or '百分数'} 必须是 0–100 的整数或 2 位小数字符串：{value!r}",
                            key=key)
    if number < 0 or number > PCT_MAX:
        raise RangeViolation(f"{key or '百分数'} 越界 0–100：{value!r}（§21.3.2）", key=key)
    if isinstance(number, int) or number == number.to_integral_value():
        return int(number)
    return raw


def normalize_integer(value: Any, *, key: str | None = None, unit: str = "integer") -> int:
    """整数类量纲（bps / 秒 / 分 / 时 / 天 / count）的入口检查：拒绝布尔、浮点、字符串数字。"""
    if isinstance(value, bool):
        raise TypeMismatch(f"{key or unit} 不接受布尔：{value!r}", key=key)
    if isinstance(value, float):
        raise UnitViolation(f"{key or unit} 不接受浮点数（{value!r}）；用整数", key=key)
    if not isinstance(value, int):
        raise TypeMismatch(f"{key or unit} 必须是整数：{value!r}", key=key)
    return value


def parse_clock(value: Any, *, key: str | None = None) -> str:
    """``HH:MM``（24 小时制）；拒绝本地时区后缀与时间戳数字（§21.3.2「时间」）。"""
    if not isinstance(value, str) or not _CLOCK.match(value):
        raise UnitViolation(f"{key or '时刻'} 必须是 HH:MM（24h）：{value!r}", key=key)
    return value


def normalize_window(value: Any, *, key: str | None = None) -> dict[str, Any]:
    """发布窗口对象。

    只允许四个字段 ``{start, end, timezone, weekdays}``（多字段 = 400，不猜语义）；
    ``start < end``（跨零点窗口不支持，S1 单一窗口）；``weekdays`` 是 ISO 周几，
    非空、去重、升序；``timezone`` 是固定偏移 ``+08:00`` 形态（不随主机 tz 漂移）。
    """
    if not isinstance(value, dict):
        raise UnitViolation(f"{key or '窗口'} 必须是对象：{value!r}", key=key)
    extra = sorted(set(value) - {"start", "end", "timezone", "weekdays"})
    if extra:
        raise UnitViolation(f"{key or '窗口'} 含未定义字段：{', '.join(extra)}", key=key,
                            details=[{"field": field} for field in extra])
    missing = [field for field in ("start", "end", "timezone", "weekdays") if field not in value]
    if missing:
        raise UnitViolation(f"{key or '窗口'} 缺字段：{', '.join(missing)}", key=key,
                            details=[{"field": field} for field in missing])
    start = parse_clock(value["start"], key=f"{key}.start" if key else "start")
    end = parse_clock(value["end"], key=f"{key}.end" if key else "end")
    if start >= end:
        raise UnitViolation(f"{key or '窗口'} start 必须早于 end：{start}–{end}", key=key)
    timezone = value["timezone"]
    if not isinstance(timezone, str) or not _TZ_OFFSET.match(timezone):
        raise UnitViolation(f"{key or '窗口'} timezone 必须是 ±HH:MM 固定偏移：{timezone!r}", key=key)
    weekdays = value["weekdays"]
    if not isinstance(weekdays, list) or not weekdays:
        raise UnitViolation(f"{key or '窗口'} weekdays 必须是非空数组：{weekdays!r}", key=key)
    if any(isinstance(day, bool) or not isinstance(day, int) or not 1 <= day <= 7 for day in weekdays):
        raise UnitViolation(f"{key or '窗口'} weekdays 必须是 1–7 的整数：{weekdays!r}", key=key)
    if weekdays != sorted(set(weekdays)):
        raise UnitViolation(f"{key or '窗口'} weekdays 必须去重且升序：{weekdays!r}", key=key)
    return {"start": start, "end": end, "timezone": timezone, "weekdays": list(weekdays)}


# ───────────────────────────────────────────────────────────── 统一入口
def normalize(
    unit: str,
    value: Any,
    *,
    key: str | None = None,
    minimum: Any = None,
    maximum: Any = None,
    multiple_of: int | None = None,
    max_length: int | None = None,
) -> Any:
    """按量纲校验并规范化；键级 ``minimum`` / ``maximum`` 在量纲硬规则之后叠加。"""
    if not is_known_unit(unit):
        raise UnitViolation(f"{key or '值'} 的单位未登记：{unit!r}", key=key)
    if (minimum is not None or maximum is not None) and unit not in _NUMERIC_UNITS:
        raise UnitViolation(
            f"{key or '值'} 的单位 {unit} 不支持数值范围（用 enum / max_length 约束）", key=key)

    if unit == "bps":
        number = normalize_integer(value, key=key, unit="bps")
        if not 0 <= number <= BPS_MAX:
            raise RangeViolation(f"{key or 'bps'} 越界 0–{BPS_MAX}：{number}（§21.3.2）", key=key)
        normalized: Any = number
    elif unit == "boolean":
        if not isinstance(value, bool):
            raise TypeMismatch(f"{key or '开关'} 必须是布尔：{value!r}", key=key)
        normalized = value
    elif unit == "pct":
        normalized = normalize_pct(value, key=key)
    elif unit == "usd":
        normalized = normalize_amount(value, key=key)
    elif unit == "usd_minor":
        normalized = normalize_usd_minor(value, key=key)
    elif unit in ("seconds", "minutes", "hours", "days", "count"):
        normalized = normalize_integer(value, key=key, unit=unit)
        if unit == "count" and normalized < 0:
            raise RangeViolation(f"{key or 'count'} 不得为负：{normalized}", key=key)
    elif unit == "clock":
        normalized = parse_clock(value, key=key)
    elif unit == "window":
        normalized = normalize_window(value, key=key)
    elif unit in ("enum", "text"):
        if not isinstance(value, str):
            raise TypeMismatch(f"{key or unit} 必须是字符串：{value!r}", key=key)
        normalized = value
    elif unit == "json":
        if not isinstance(value, (dict, list)):
            raise TypeMismatch(f"{key or 'json'} 必须是对象或数组：{value!r}", key=key)
        normalized = value
    else:  # pragma: no cover - is_known_unit 已拦住
        raise UnitViolation(f"单位未实现：{unit}", key=key)

    # 键级范围：金额按字符串比较会错（"9.00" > "10000.00"），统一换成 Decimal 再比
    if minimum is not None or maximum is not None:
        _check_range(unit, normalized, minimum, maximum, key=key)
    if multiple_of is not None:
        _check_multiple(unit, normalized, multiple_of, key=key)
    if max_length is not None and isinstance(normalized, str) and len(normalized) > max_length:
        raise RangeViolation(f"{key or '值'} 长度超过 {max_length}：{len(normalized)}", key=key)
    return normalized


def _comparable(unit: str, value: Any) -> Any:
    if unit in ("usd", "usd_minor", "bps", "count", "seconds", "minutes", "hours", "days"):
        return Decimal(str(value))
    if unit == "pct":
        return Decimal(str(value))
    return value


def _check_range(unit: str, value: Any, minimum: Any, maximum: Any, *, key: str | None) -> None:
    current = _comparable(unit, value)
    if minimum is not None and current < _comparable(unit, minimum):
        raise RangeViolation(f"{key or '值'} 小于下限 {minimum}：{value!r}", key=key)
    if maximum is not None and current > _comparable(unit, maximum):
        raise RangeViolation(f"{key or '值'} 大于上限 {maximum}：{value!r}", key=key)


def _check_multiple(unit: str, value: Any, multiple_of: int, *, key: str | None) -> None:
    if multiple_of <= 0:
        raise ValueError(f"multiple_of 必须为正：{multiple_of}")
    current = _comparable(unit, value)
    if isinstance(current, Decimal):
        if (current / multiple_of) != (current / multiple_of).to_integral_value():
            raise RangeViolation(f"{key or '值'} 必须是 {multiple_of} 的整数倍：{value!r}", key=key)
    elif not isinstance(current, int) or current % multiple_of:
        raise RangeViolation(f"{key or '值'} 必须是 {multiple_of} 的整数倍：{value!r}", key=key)
