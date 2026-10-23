# SPDX-License-Identifier: Apache-2.0
"""配置来源（M04 §8.1 九个键；Owner = M10）。

边界（00-conventions §1.5 / §1.2）：

* 业务常量**只从 config-center 取**，本模块不读环境变量里的业务值；
* 跨模块**只走 API**：M04 不 import ``app.config_center``、也不直连它的基表，
  而是通过**依赖注入的只读 provider** 拿当前生效值（合并时由 Lead 把 M10 的
  ``/api/v1/admin/config`` 读侧或内部快照读函数接进 :func:`set_provider`）。

没有 provider 时（T1/T2 独立跑、单测、M10 未接线）：返回 ``facts`` 里登记的 §8.1 默认值，
并在越界时**夹取到该键的合法区间**（M10 负责校验，M04 只做防御性夹取 + 结构化告警）。

配置键注册现状（2026-10-23 勘察）：M10 的 registry 已登记 ``billing.service_fee_bps`` 与
``routing.policy_version``，**其余 routing.* 键尚未登记**；因此本模块的默认值就是实际生效值，
待 M10 补登记后由 provider 覆盖（已在 DEV-M04-T1T2 证据文件登记为跨模块待办）。
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from . import facts

log = logging.getLogger("djb.scheduling.config")

Provider = Callable[[Any, Any], Mapping[str, Any]]

_provider: Provider | None = None

#: M04 §8.1：整数键 → (默认值, 下限, 上限)
INT_RANGES: dict[str, tuple[int, int, int]] = {
    facts.CONFIG_KEYS["candidate_freshness_s"]: (facts.CANDIDATE_FRESHNESS_S, 30, 120),
    facts.CONFIG_KEYS["quotebook_refresh_s"]: (facts.QUOTEBOOK_REFRESH_S, 30, 120),
    facts.CONFIG_KEYS["max_tenant_share_pct"]: (facts.MAX_TENANT_SHARE_PCT, 5, 50),
    facts.CONFIG_KEYS["preempt_budget_per_h"]: (facts.PREEMPT_BUDGET_PER_H, 1, 12),
    facts.CONFIG_KEYS["tie_break_epsilon_bps"]: (facts.TIE_BREAK_EPSILON_BPS, 0, 1_000),
}

#: 浮点键 → (默认值, 下限, 上限)；用 milli 整数解析，避免浮点进判定
MILLI_RANGES: dict[str, tuple[int, int, int]] = {
    # routing.latency_lambda 默认 1.0（全局倍率），范围 0.5–10.0
    facts.CONFIG_KEYS["latency_lambda"]: (int(facts.LATENCY_LAMBDA_DEFAULT * 1_000), 500, 10_000),
}

#: 枚举键
ENUM_VALUES: dict[str, tuple[str, ...]] = {
    facts.CONFIG_KEYS["price_strategy"]: facts.PRICE_STRATEGIES,
}


def set_provider(provider: Provider | None) -> None:
    """注入配置只读 provider（``provider(conn, tenant) -> {key: value}``）。传 None 复位。"""
    global _provider
    _provider = provider


def current_provider() -> Provider | None:
    return _provider


def raw(c, context: Any = None) -> dict[str, Any]:
    """当前生效配置（provider 缺省 → 空 dict，由 :func:`resolve` 落到 §8.1 默认值）。"""
    if _provider is None:
        return {}
    try:
        values = _provider(c, context)
    except Exception:                                        # pragma: no cover - 防御
        log.warning("scheduling.config.provider_failed",
                    extra={"event": "config.provider_failed"})
        return {}
    if not isinstance(values, Mapping):
        log.warning("scheduling.config.provider_invalid",
                    extra={"event": "config.provider_invalid"})
        return {}
    return dict(values)


def _int_value(values: Mapping[str, Any], key: str) -> int:
    default, low, high = INT_RANGES[key]
    value = values.get(key, default)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        log.warning("scheduling.config.not_int", extra={"event": "config.not_int", "key": key})
        return default
    if parsed < low or parsed > high:
        clamped = max(low, min(high, parsed))
        log.warning("scheduling.config.out_of_range",
                    extra={"event": "config.out_of_range", "key": key, "value": parsed,
                           "clamped": clamped})
        return clamped
    return parsed


def _milli_value(values: Mapping[str, Any], key: str) -> int:
    """provider 给的是**十进制**（如 1.0），默认值本身已经是 milli，不能再乘 1000。"""
    default, low, high = MILLI_RANGES[key]
    value = values.get(key)
    if value is None:
        return default
    try:
        parsed = int(round(float(value) * 1_000))
    except (TypeError, ValueError):
        log.warning("scheduling.config.not_number",
                    extra={"event": "config.not_number", "key": key})
        return default
    if parsed < low or parsed > high:
        clamped = max(low, min(high, parsed))
        log.warning("scheduling.config.out_of_range",
                    extra={"event": "config.out_of_range", "key": key, "value": parsed,
                           "clamped": clamped})
        return clamped
    return parsed


def _enum_value(values: Mapping[str, Any], key: str) -> str:
    allowed = ENUM_VALUES[key]
    value = values.get(key, allowed[0])
    text = str(value).strip().lower()
    if text not in allowed:
        log.warning("scheduling.config.not_enum",
                    extra={"event": "config.not_enum", "key": key, "value": text})
        return allowed[0]
    return text


def resolve(values: Mapping[str, Any] | None) -> dict[str, Any]:
    """把 provider 原值解析成 §8.1 的生效值（缺省 / 越界 / 非法枚举都被兜住）。"""
    source = values or {}
    resolved: dict[str, Any] = {key: _int_value(source, key) for key in INT_RANGES}
    resolved.update({key: _milli_value(source, key) for key in MILLI_RANGES})
    resolved.update({key: _enum_value(source, key) for key in ENUM_VALUES})
    resolved[facts.CONFIG_KEYS["policy_version"]] = _policy_version(source)
    return resolved


def _policy_version(values: Mapping[str, Any]) -> str:
    """``routing.policy_version``（M10 生成：snapshot_digest 前 12 位）。

    未接线 / 形态不符 → :data:`facts.DEFAULT_POLICY_VERSION`，保证锚点稳定可复算（INV-03）。
    """
    key = facts.CONFIG_KEYS["policy_version"]
    value = values.get(key)
    if value is None:
        return facts.DEFAULT_POLICY_VERSION
    text = str(value).strip().lower()
    import re

    if not re.fullmatch(facts.POLICY_VERSION_PATTERN, text):
        log.warning("scheduling.config.bad_policy_version",
                    extra={"event": "config.bad_policy_version"})
        return facts.DEFAULT_POLICY_VERSION
    return text


def load(c, context: Any = None) -> dict[str, Any]:
    """:func:`raw` + :func:`resolve` 的组合（路由 / 领域层用这个）。"""
    return resolve(raw(c, context))


# --------------------------------------------------------------------------- 便捷取值
def candidate_freshness_s(values: Mapping[str, Any]) -> int:
    return int(values[facts.CONFIG_KEYS["candidate_freshness_s"]])


def quotebook_refresh_s(values: Mapping[str, Any]) -> int:
    return int(values[facts.CONFIG_KEYS["quotebook_refresh_s"]])


def max_tenant_share_pct(values: Mapping[str, Any]) -> int:
    return int(values[facts.CONFIG_KEYS["max_tenant_share_pct"]])


def preempt_budget_per_h(values: Mapping[str, Any]) -> int:
    return int(values[facts.CONFIG_KEYS["preempt_budget_per_h"]])


def tie_break_epsilon_bps(values: Mapping[str, Any]) -> int:
    return int(values[facts.CONFIG_KEYS["tie_break_epsilon_bps"]])


def latency_lambda_milli(values: Mapping[str, Any]) -> int:
    return int(values[facts.CONFIG_KEYS["latency_lambda"]])


def price_strategy(values: Mapping[str, Any]) -> str:
    return str(values[facts.CONFIG_KEYS["price_strategy"]])


def policy_version(values: Mapping[str, Any]) -> str:
    return str(values[facts.CONFIG_KEYS["policy_version"]])


__all__ = ["Provider", "INT_RANGES", "MILLI_RANGES", "ENUM_VALUES", "set_provider",
           "current_provider", "raw", "resolve", "load", "candidate_freshness_s",
           "quotebook_refresh_s", "max_tenant_share_pct", "preempt_budget_per_h",
           "tie_break_epsilon_bps", "latency_lambda_milli", "price_strategy",
           "policy_version"]
