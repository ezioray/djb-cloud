# SPDX-License-Identifier: Apache-2.0
"""配置来源（M03 §8.1 两个键；Owner = M10）。

边界（00-conventions §1.5 / §1.2）：

* 业务常量**只从 config-center 取**，本模块不读环境变量里的业务值；
* 跨模块**只走 API**：M03 不 import ``app.config_center``、也不直连它的基表，
  而是通过**依赖注入的只读 provider** 拿当前生效值（合并时由 Lead 把 M10 的
  ``/api/v1/admin/config`` 读侧或内部快照读函数接进 :func:`set_provider`）。

没有 provider 时（T1/T2 独立跑、单测、M10 未接线）：两个键都返回 ``None`` ——
**不内置业务默认值**（M03 §8.1 明确「默认 = M10 基线」，模块不得自造）。
调用方按 ``None`` = 「本次不下发该限制」处理：
``gateway.rate_limit_qps`` 为 None 时只按 M01 配额快照的 Key / 租户 qps 限流；
``gateway.stream_timeout_s`` 为 None 时流式超时取 M04 决策的 ETA（T3 使用）。
数值若越界，**夹取到 §8.1 合法区间并结构化告警**（M10 负责校验，M03 只做防御性夹取）。
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from . import facts

log = logging.getLogger("djb.gateway.config")

Provider = Callable[[], Mapping[str, Any]]

_provider: Provider | None = None


def set_provider(provider: Provider | None) -> None:
    """注入配置只读 provider（``provider() -> {key: value}``）。传 None 复位。"""
    global _provider
    _provider = provider


def current_provider() -> Provider | None:
    return _provider


def raw() -> dict[str, Any]:
    """当前生效配置（provider 缺省 → 空 dict）。"""
    if _provider is None:
        return {}
    try:
        values = _provider()
    except Exception:                                          # pragma: no cover - 防御
        log.warning("gateway.config.provider_failed", extra={"event": "config.provider_failed"})
        return {}
    if not isinstance(values, Mapping):
        log.warning("gateway.config.provider_invalid", extra={"event": "config.provider_invalid"})
        return {}
    return dict(values)


def _int_value(values: Mapping[str, Any], key: str) -> int | None:
    """取整型配置；缺省 / 非法 → None；越界 → 夹取 + 告警。"""
    if key not in values:
        return None
    raw_value = values[key]
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        log.warning("gateway.config.invalid_value",
                    extra={"event": "config.invalid_value", "key": key})
        return None
    low, high = facts.CONFIG_KEY_RANGES.get(key, (None, None))
    if low is not None and high is not None and not low <= value <= high:
        clamped = min(max(value, low), high)
        log.warning("gateway.config.clamped",
                    extra={"event": "config.clamped", "key": key,
                           "value": value, "clamped": clamped})
        return clamped
    return value


def rate_limit_qps(values: Mapping[str, Any] | None = None) -> int | None:
    """``gateway.rate_limit_qps``（M10 基线；None = 本模块不下发全局 QPS 限制）。"""
    return _int_value(values if values is not None else raw(), facts.CONFIG_KEYS["rate_limit_qps"])


def stream_timeout_s(values: Mapping[str, Any] | None = None) -> int | None:
    """``gateway.stream_timeout_s``（M10 基线；None = 不额外限制，取 M04 决策 ETA）。"""
    return _int_value(values if values is not None else raw(),
                      facts.CONFIG_KEYS["stream_timeout_s"])


def snapshot() -> dict[str, int | None]:
    """一次性读取本次请求要用的两个键（同一请求内不自相矛盾）。"""
    values = raw()
    return {"rate_limit_qps": rate_limit_qps(values),
            "stream_timeout_s": stream_timeout_s(values)}


__all__ = ["Provider", "set_provider", "current_provider", "raw", "rate_limit_qps",
           "stream_timeout_s", "snapshot"]
