# SPDX-License-Identifier: Apache-2.0
"""配置来源（M02 §8.1 五个键；Owner = M10）。

边界（00-conventions §1.5 / §1.2）：

* 业务常量**只从 config-center 取**，本模块不读环境变量里的业务值；
* 跨模块**只走 API**：M02 不 import ``app.config_center``、也不直连它的基表，
  而是通过**依赖注入的只读 provider** 拿当前生效值（合并时由 Lead 把 M10 的
  ``/api/v1/admin/config`` 读侧或内部快照读函数接进 :func:`set_provider`）。

没有 provider 时（T3 独立跑、单测、M10 未接线）：返回 ``facts`` 里登记的 §8.1 默认值，
并在越界时**夹取到该键的合法区间**（M10 负责校验，M02 只做防御性夹取 + 结构化告警）。
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from . import facts

log = logging.getLogger("djb.supply.config")

Provider = Callable[[Any, Any], Mapping[str, Any]]

_provider: Provider | None = None

#: M02 §8.1：键 → (默认值, 下限, 上限)。运行时值来自 config-center；这里是**兜底**。
RANGES: dict[str, tuple[int, int, int]] = {
    facts.CONFIG_KEYS["heartbeat_interval_s"]: (facts.HEARTBEAT_INTERVAL_S, 10, 120),
    facts.CONFIG_KEYS["stale_after_s"]: (facts.STALE_AFTER_S, 30, 300),
    facts.CONFIG_KEYS["announcement_ttl_s"]: (facts.ANNOUNCEMENT_TTL_S, 30, 300),
    facts.CONFIG_KEYS["max_nodes_per_account"]: (facts.MAX_NODES_PER_ACCOUNT, 1, 1000),
    facts.CONFIG_KEYS["review_sla_h"]: (facts.REVIEW_SLA_H, 1, 72),
}


def set_provider(provider: Provider | None) -> None:
    """注入配置只读 provider（``provider(conn, node) -> {key: value}``）。传 None 复位。"""
    global _provider
    _provider = provider


def current_provider() -> Provider | None:
    return _provider


def raw(c, node: Any = None) -> dict[str, Any]:
    """当前生效配置（provider 缺省 → 空 dict，由 :func:`resolve` 落到 §8.1 默认值）。"""
    if _provider is None:
        return {}
    values = _provider(c, node)
    if not isinstance(values, Mapping):
        log.warning("supply.config.provider_invalid", extra={"event": "config.provider_invalid"})
        return {}
    return dict(values)


def _int_value(values: Mapping[str, Any], key: str) -> int:
    default, low, high = RANGES[key]
    value = values.get(key, default)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        log.warning("supply.config.not_int", extra={"event": "config.not_int", "key": key})
        return default
    if parsed < low or parsed > high:
        clamped = max(low, min(high, parsed))
        log.warning("supply.config.out_of_range",
                    extra={"event": "config.out_of_range", "key": key, "value": parsed,
                           "clamped": clamped})
        return clamped
    return parsed


def resolve(values: Mapping[str, Any] | None) -> dict[str, int]:
    """把 provider 原值解析成 §8.1 的五个整数（缺省 / 越界都被兜住）。"""
    source = values or {}
    return {key: _int_value(source, key) for key in RANGES}


def load(c, node: Any = None) -> dict[str, int]:
    """:func:`raw` + :func:`resolve` 的组合（路由 / 领域层用这个）。"""
    return resolve(raw(c, node))


def heartbeat_interval_s(values: Mapping[str, int]) -> int:
    return values[facts.CONFIG_KEYS["heartbeat_interval_s"]]


def stale_after_s(values: Mapping[str, int]) -> int:
    return values[facts.CONFIG_KEYS["stale_after_s"]]


def announcement_ttl_s(values: Mapping[str, int]) -> int:
    return values[facts.CONFIG_KEYS["announcement_ttl_s"]]


def max_nodes_per_account(values: Mapping[str, int]) -> int:
    return values[facts.CONFIG_KEYS["max_nodes_per_account"]]


def review_sla_h(values: Mapping[str, int]) -> int:
    return values[facts.CONFIG_KEYS["review_sla_h"]]


__all__ = ["Provider", "RANGES", "set_provider", "current_provider", "raw", "resolve", "load",
           "heartbeat_interval_s", "stale_after_s", "announcement_ttl_s",
           "max_nodes_per_account", "review_sla_h"]
