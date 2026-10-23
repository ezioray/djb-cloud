# SPDX-License-Identifier: Apache-2.0
"""``metering.*`` 配置的**注入式只读视图**（M05 §8.1 / 00-conventions §1.5 / §6）。

规则：

1. 模块不读环境变量里的业务常量，也不把默认值散落在业务代码里——这里只做
   「注入 provider → 取值 → 夹到 §8.1 范围 → 生成不可变快照」；
2. provider 由 Lead 合并时接到 M10 的 config-center（``provider(namespace, key)``
   或直接给整包 dict 都支持），T1/T2 与测试用默认值（= §8.1 表格原文）；
3. 取值非法（缺键 / 非数字 / 越界）**不抛错、不静默取大**：回落到默认值并按边界夹取，
   同时把 ``source`` 标成 ``default``，方便排障（配置中心已做两道 schema 校验）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from . import facts

#: ``provider(namespace) -> Mapping[str, Any] | None``：一次拿整个 ``metering`` 命名空间
ConfigProvider = Callable[[str], "Mapping[str, Any] | None"]

_config_provider: ConfigProvider | None = None


def set_config_provider(provider: ConfigProvider | None) -> None:
    """注入配置只读 provider（传 None 复位：用 §8.1 默认值）。"""
    global _config_provider
    _config_provider = provider


def current_provider() -> ConfigProvider | None:
    return _config_provider


@dataclass(frozen=True)
class MeteringConfig:
    """``metering.*`` 的生效快照（不可变；一次请求用一份，避免中途漂移）。"""

    overbill_tolerance_pct: float = facts.CONFIG_DEFAULTS["metering.overbill_tolerance_pct"]
    correction_dual_threshold_usd: float = facts.CONFIG_DEFAULTS[
        "metering.correction_dual_threshold_usd"]
    estimated_alert_pct: float = facts.CONFIG_DEFAULTS["metering.estimated_alert_pct"]
    receipt_late_h: float = facts.CONFIG_DEFAULTS["metering.receipt_late_h"]
    source: str = "default"

    def as_dict(self) -> dict[str, Any]:
        return {"overbill_tolerance_pct": self.overbill_tolerance_pct,
                "correction_dual_threshold_usd": self.correction_dual_threshold_usd,
                "estimated_alert_pct": self.estimated_alert_pct,
                "receipt_late_h": self.receipt_late_h, "source": self.source}


def _number(value: Any) -> float | None:
    """接受 int / float / 数字字符串；bool 与其它一律视为非法（不猜）。"""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _resolve(key: str, raw: Mapping[str, Any] | None) -> tuple[float, bool]:
    """返回 (生效值, 是否来自 provider)。越界夹取、非法回落默认值。"""
    default = float(facts.CONFIG_DEFAULTS[key])
    low, high = facts.CONFIG_RANGES[key]
    value = _number((raw or {}).get(key, (raw or {}).get(key.split(".", 1)[1])))
    if value is None:
        return default, False
    return min(max(value, low), high), True


def snapshot(provider: ConfigProvider | None = None) -> MeteringConfig:
    """取一份生效配置；``provider`` 缺省用已注入的那个，再缺省用 §8.1 默认值。"""
    active = provider if provider is not None else _config_provider
    raw: Mapping[str, Any] | None = None
    if active is not None:
        try:
            raw = active(facts.CONFIG_NAMESPACE) or None
        except Exception:                                  # pragma: no cover - 防御
            raw = None
    values: dict[str, float] = {}
    from_provider = False
    for key in facts.CONFIG_KEYS:
        value, found = _resolve(key, raw)
        values[key.split(".", 1)[1]] = value
        from_provider = from_provider or found
    return MeteringConfig(source="config_center" if from_provider else "default", **values)


def receipt_late_hours(provider: ConfigProvider | None = None) -> float:
    """受理窗口（小时）：M05 §8.1 的 ``metering.receipt_late_h``，范围 1–168。"""
    return snapshot(provider).receipt_late_h


__all__ = ["ConfigProvider", "MeteringConfig", "set_config_provider", "current_provider",
           "snapshot", "receipt_late_hours"]
