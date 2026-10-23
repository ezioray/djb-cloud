# SPDX-License-Identifier: Apache-2.0
"""配额口径：``min(租户, Key, 节点)`` + 每日花费上限（M03 §4.4 的 ``42902``）。

分工（M03 §1 / §4「判定结果由 M01 / M11 的 API 或配额快照提供」）：

* **租户 / Key 层**：来自 M01 ``quota_snapshot`` 的 ``effective``（``QUOTA_KINDS`` =
  ``qps`` / ``daily_usd_minor`` / ``concurrency``）与 ``policy_version``；
* **节点层**：来自 M04 决策的 ``node_qps``（携带时生效；开关
  ``gateway.node_layer_rate_limit`` 关闭时不下发节点层限流）；
* **每日花费**：``daily_spend_minor``（当前已花）与 ``effective.daily_usd_minor``（上限）
  都来自快照；达到上限即 429 / ``42902``，不自动降级到免费模型（M03 §7）。

本模块是**纯函数**：不 import 任何业务模块，也不读数据库/环境变量；
``min`` 语义与 M01 ``effective_quotas`` 一致（缺的档位视为无该档上限）——独立实现，
避免跨模块 import（00-conventions §1.2），并在 ``tests/gateway/test_quota.py`` 用
对照用例锁死同一语义。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from . import errors

__all__ = ["QuotaState", "from_snapshot", "resolve", "assert_daily_cap", "scope_keys",
           "QUOTA_KINDS"]

QUOTA_KINDS: tuple[str, ...] = ("qps", "daily_usd_minor", "concurrency")
"""M01 ``QUOTA_KINDS`` 同口径（M01 §6.5）；网关只消费 ``qps`` 与 ``daily_usd_minor``。"""


@dataclass(frozen=True)
class QuotaState:
    """一次请求的配额快照（只读）。"""

    limits: Mapping[str, int] = field(default_factory=dict)
    policy_version: str | None = None
    daily_spend_minor: int | None = None
    sources: tuple[str, ...] = ()

    @property
    def qps(self) -> int | None:
        value = self.limits.get("qps")
        return None if value is None else int(value)

    @property
    def daily_cap_minor(self) -> int | None:
        value = self.limits.get("daily_usd_minor")
        return None if value is None else int(value)


def _as_int_map(source: Any) -> dict[str, int]:
    """把 ``{kind: value}`` / ``[{kind, value}, ...]`` 规整成 ``{kind: int}``。"""
    if isinstance(source, Mapping):
        out: dict[str, int] = {}
        for key, value in source.items():
            try:
                out[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
        return out
    if isinstance(source, (list, tuple)):
        out = {}
        for item in source:
            kind = item.get("kind") if isinstance(item, Mapping) else getattr(item, "kind", None)
            value = item.get("value") if isinstance(item, Mapping) else getattr(item, "value", None)
            if kind is None or value is None:
                continue
            try:
                out[str(kind)] = int(value)
            except (TypeError, ValueError):
                continue
        return out
    return {}


def resolve(*layers: Mapping[str, int] | None) -> dict[str, int]:
    """``min(租户, Key, 节点)``：按 kind 取各层最小值，缺层视为无该档上限。"""
    merged: dict[str, int] = {}
    for layer in layers:
        if not layer:
            continue
        for kind, value in _as_int_map(layer).items():
            merged[kind] = value if kind not in merged else min(merged[kind], value)
    return merged


def from_snapshot(snapshot: Mapping[str, Any] | None) -> QuotaState:
    """M01 ``quota_snapshot`` 返回体 → :class:`QuotaState`。

    兼容两种形态：

    * ``{"effective": {kind: value}, "policy_version": ..., "spend": {...}}``（M01 现行返回体
      + 可选 ``spend``，供 M11/M04 的花费读数合并进来）；
    * ``{"quotas": [{"key_id":.., "kind":.., "value":..}], ...}``（只有明细时按层取 min）。
    """
    values = dict(snapshot or {})
    effective = _as_int_map(values.get("effective"))
    if not effective and values.get("quotas"):
        # 没有 effective 时，用明细自己算 min（租户层 key_id 为 None）
        tenant_layer: dict[str, int] = {}
        key_layer: dict[str, int] = {}
        for row in values.get("quotas") or []:
            kind = row.get("kind") if isinstance(row, Mapping) else None
            value = row.get("value") if isinstance(row, Mapping) else None
            key_id = row.get("key_id") if isinstance(row, Mapping) else None
            if kind is None or value is None:
                continue
            try:
                numeric = int(value)
            except (TypeError, ValueError):
                continue
            if key_id is None:
                tenant_layer[kind] = numeric
            else:
                key_layer[kind] = numeric
        effective = resolve(tenant_layer, key_layer)
    spend_block = values.get("spend") if isinstance(values.get("spend"), Mapping) else {}
    spend = values.get("daily_spend_minor")
    if spend is None and isinstance(spend_block, Mapping):
        spend = spend_block.get("daily_spend_minor")
    node_layer = _as_int_map(values.get("node_caps"))
    limits = resolve(effective, node_layer) if node_layer else dict(effective)
    return QuotaState(
        limits=limits,
        policy_version=None if values.get("policy_version") is None
        else str(values.get("policy_version")),
        daily_spend_minor=None if spend is None else int(spend),
        sources=tuple(sorted(limits)),
    )


def assert_daily_cap(state: QuotaState, *, kind: str = "daily_usd_minor") -> None:
    """每日花费上限：``已花 ≥ 上限`` → 429 / 42902（不自动降级到免费模型）。"""
    cap = state.limits.get(kind)
    if cap is None or state.daily_spend_minor is None:
        return
    if int(state.daily_spend_minor) < int(cap):
        return
    raise errors.GatewayError(
        "daily_spend_cap", "已触发每日花费上限，请调整配额或次日再试",
        reason="quota_exceeded", retry_after_s=60,
        details={"limit": int(cap), "spend": int(state.daily_spend_minor)},
    )


def scope_keys(principal: Any, *, include_key: bool = True) -> list[tuple[str, int | None]]:
    """限流作用域（tenant / key 两层）；节点层在拿到决策后由调用方补。"""
    spans: list[tuple[str, int | None]] = []
    tenant_id = getattr(principal, "tenant_id", None)
    if tenant_id:
        spans.append((f"tenant:{tenant_id}", None))
    if include_key:
        api_key_id = getattr(principal, "api_key_id", None)
        if api_key_id is not None:
            spans.append((f"key:{api_key_id}", None))
    return spans


def effective_qps(*layers: int | None) -> int | None:
    """``min`` 语义的便捷入口（None 忽略）；用于把节点层并进租户 / Key 层。"""
    values = [int(value) for value in layers if value is not None]
    return min(values) if values else None


__all__ += ["effective_qps"]
