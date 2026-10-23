# SPDX-License-Identifier: Apache-2.0
"""M10 配置只读绑定（M08 §8.1 / 00-conventions §1.5 / 01-ownership §6）。

规则：

* 本模块**不读环境变量里的业务常量**，也不写配置；只从注入的 M10 provider 读「已发布的
  生效值」，读不到就退默认值（source = default / invalid），并把来源写进快照供审计。
* 配置快照（TreasuryConfig）随批次落库：payout_batch.gas_mode / policy_version 是**当时**
  的快照；下一批生效、不追溯（INV-14）。
* 值域校验在本层完成：越界值不生效（退默认 + source=invalid），不静默采用。

provider 形状（合并期由 Lead 注入 M10 只读快照 / 内存快照）::

    provider.value("treasury.wallet_pool.polygon.hot.customer.min_spare") -> Any | None
    provider.config_version(key) -> int | None
    provider.published_at(key) -> datetime | None

未注入时 NullConfigProvider 恒返回 None → 全部默认值（S1/S2 可用，来源可追溯）。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Protocol

from . import clock, facts

__all__ = [
    "ConfigProvider", "NullConfigProvider", "MemoryConfigProvider", "TreasuryConfig",
    "pool_key", "pool_config_key", "gas_mode_for", "load", "provider_from_mapping",
    "DEFAULTS",
]


class ConfigProvider(Protocol):                       # pragma: no cover - 结构协议
    def value(self, key: str) -> Any | None: ...
    def config_version(self, key: str) -> int | None: ...
    def published_at(self, key: str) -> datetime | None: ...


class NullConfigProvider:
    """默认实现：未接线 M10 → 全默认值（source=default），不读任何环境变量。"""

    def value(self, key: str) -> Any | None:
        return None

    def config_version(self, key: str) -> int | None:
        return None

    def published_at(self, key: str) -> datetime | None:
        return None


class MemoryConfigProvider:
    """测试 / 本地演练用：内存快照 + 可选发布时间（用于 LKG 过期用例）。"""

    def __init__(self, values: Mapping[str, Any] | None = None, *,
                 version: int | None = 1, published_at: datetime | None = None) -> None:
        self._values = dict(values or {})
        self._version = version
        self._published_at = published_at

    def value(self, key: str) -> Any | None:
        return self._values.get(key)

    def config_version(self, key: str) -> int | None:
        return self._version if key in self._values else None

    def published_at(self, key: str) -> datetime | None:
        return self._published_at if key in self._values else None


def provider_from_mapping(values: Mapping[str, Any] | None, **kwargs: Any):
    if not values:
        return None
    return MemoryConfigProvider(values, **kwargs)


#: 配置键（M08 §8.1；{chain}/{role}/{fund_class} 由 pool_key 填）
KEY_MIN_SPARE = "treasury.wallet_pool.{pool}.min_spare"
KEY_MAX_ACTIVE = "treasury.wallet_pool.{pool}.max_active"
KEY_SWITCH_PCT = "treasury.wallet_pool.{pool}.switch_threshold_pct"
KEY_ACTIVATE_BATCH = "treasury.wallet_pool.{pool}.activate_batch_size"
KEY_LEAD_TIME = "treasury.wallet_pool.{pool}.provision_lead_time_h"
KEY_AUTO_EXPAND = "treasury.wallet_pool.{pool}.auto_expand"
KEY_FORECAST_WINDOW = "treasury.wallet_pool.{pool}.forecast_window_d"
KEY_CAPACITY_BUFFER = "treasury.wallet_pool.{pool}.capacity_buffer_pct"
KEY_REFUND_WINDOW = "payment.refund_window_days"
KEY_WEBHOOK_SKEW = "payment.webhook_skew_s"
KEY_GAS_MODE = "billing.gas_fee_mode"
KEY_GAS_BEARER = "billing.gas_fee_bearer"
KEY_GAS_MODE_LEGACY = "treasury.gas_fee_mode"              # 03-facts §9 legacy 别名（只读兼容）
KEY_PLATFORM_SHARE = "billing.platform_share_bps"
KEY_PLATFORM_SHARE_ALT = "billing.service_fee_bps"

#: 未配置时的默认值（M08 §8.1 / 03-facts §2 / §4 / §5）
DEFAULTS: dict[str, Any] = {
    "min_spare": facts.MIN_SPARE,
    "max_active_hot": facts.MAX_ACTIVE_HOT,
    "max_active_warm": facts.MAX_ACTIVE_WARM,
    "switch_threshold_pct": facts.SWITCH_THRESHOLD_PCT,
    "activate_batch_size": facts.ACTIVATE_BATCH_SIZE,
    "provision_lead_time_h": facts.PROVISION_LEAD_TIME_H,
    "auto_expand": True,
    "forecast_window_d": facts.FORECAST_WINDOW_DAYS,
    "capacity_buffer_pct": facts.CAPACITY_BUFFER_PCT,
    "refund_window_days": facts.REFUND_WINDOW_DAYS,
    "webhook_skew_s": facts.WEBHOOK_SKEW_S,
    "gas_mode": facts.GAS_MODE_INTERNAL,
    "gas_bearer": "PLATFORM",
    "platform_share_bps": facts.PLATFORM_FEE_BPS,
}


def pool_key(chain: str, role: str, fund_class: str) -> str:
    """池键：chain:role:fund_class（M08 §3 INV-01；一期 3 池）。"""
    return f"{chain}:{role}:{fund_class}"


def pool_config_key(pool: str, attr: str) -> str:
    """treasury.wallet_pool.{chain}.{role}.{fund_class}.{attr} 的键名构造。"""
    parts = pool.split(":")
    if len(parts) != 3:
        raise ValueError(f"池键必须是 chain:role:fund_class，收到 {pool!r}")
    return f"treasury.wallet_pool.{parts[0]}.{parts[1]}.{parts[2]}.{attr}"


def gas_mode_for(mode: Any, bearer: Any) -> str:
    """规范化 gas 模式：三分量 ⟵ 03-facts §9 legacy（EXTERNAL + bearer）。"""
    text = str(mode).strip().upper() if mode is not None else ""
    bearer_text = str(bearer).strip().upper() if bearer is not None else "PLATFORM"
    if text in facts.GAS_MODES:
        return text
    if text in ("INTERNAL", "EXTERNAL"):
        return facts.GAS_MODE_LEGACY.get((text, bearer_text), facts.GAS_MODE_INTERNAL)
    return facts.GAS_MODE_INTERNAL


@dataclass(frozen=True)
class TreasuryConfig:
    """一次配置解析结果（**没有密钥、没有业务数字以外的东西**）。"""

    pool: str
    min_spare: int
    max_active: int
    switch_threshold_pct: int
    activate_batch_size: int
    provision_lead_time_h: int
    auto_expand: bool
    forecast_window_d: int
    capacity_buffer_pct: int
    refund_window_days: int
    webhook_skew_s: int
    gas_mode: str
    gas_bearer: str
    platform_share_bps: int
    policy_version: str
    source: str                       # m10 / default / invalid
    config_version: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "pool": self.pool,
            "min_spare": self.min_spare,
            "max_active": self.max_active,
            "switch_threshold_pct": self.switch_threshold_pct,
            "activate_batch_size": self.activate_batch_size,
            "provision_lead_time_h": self.provision_lead_time_h,
            "auto_expand": self.auto_expand,
            "forecast_window_d": self.forecast_window_d,
            "capacity_buffer_pct": self.capacity_buffer_pct,
            "refund_window_days": self.refund_window_days,
            "webhook_skew_s": self.webhook_skew_s,
            "gas_mode": self.gas_mode,
            "gas_bearer": self.gas_bearer,
            "platform_share_bps": self.platform_share_bps,
            "policy_version": self.policy_version,
            "source": self.source,
        }


def _int_in_range(provider: ConfigProvider, key: str, default: int, low: int,
                  high: int) -> tuple[int, bool]:
    raw = provider.value(key)
    if raw is None:
        return default, False
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default, True
    if not (low <= value <= high):
        return default, True
    return value, False


def _bool(provider: ConfigProvider, key: str, default: bool) -> tuple[bool, bool]:
    raw = provider.value(key)
    if raw is None:
        return default, False
    if isinstance(raw, bool):
        return raw, False
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True, False
    if text in ("0", "false", "no", "off"):
        return False, False
    return default, True


def load(provider: ConfigProvider | None = None, *, chain: str = facts.CHAIN_ID,
         role: str = "hot", fund_class: str = "customer") -> TreasuryConfig:
    """解析一个池 + 全局键的生效配置（值域越界退默认并标记 invalid）。"""
    source = provider or NullConfigProvider()
    pool = pool_key(chain, role, fund_class)
    invalid = False

    def key(attr: str) -> str:
        return pool_config_key(pool, attr)

    min_spare, bad = _int_in_range(source, key("min_spare"), facts.MIN_SPARE, 0,
                                   facts.MAX_BATCH_SIZE)
    invalid |= bad
    default_max = facts.MAX_ACTIVE_HOT if role == "hot" else facts.MAX_ACTIVE_WARM
    max_active, bad = _int_in_range(source, key("max_active"), default_max, 1,
                                    facts.MAX_ACTIVE_HARD_CAP)
    invalid |= bad
    switch_pct, bad = _int_in_range(source, key("switch_threshold_pct"),
                                    facts.SWITCH_THRESHOLD_PCT,
                                    facts.SWITCH_THRESHOLD_MIN_PCT,
                                    facts.SWITCH_THRESHOLD_MAX_PCT)
    invalid |= bad
    batch_size, bad = _int_in_range(source, key("activate_batch_size"),
                                    facts.ACTIVATE_BATCH_SIZE, facts.ACTIVATE_BATCH_MIN,
                                    facts.ACTIVATE_BATCH_MAX)
    invalid |= bad
    lead_h, bad = _int_in_range(source, key("provision_lead_time_h"),
                                facts.PROVISION_LEAD_TIME_H,
                                facts.PROVISION_LEAD_TIME_MIN_H,
                                facts.PROVISION_LEAD_TIME_MAX_H)
    invalid |= bad
    auto_expand, bad = _bool(source, key("auto_expand"), True)
    invalid |= bad
    window_d, bad = _int_in_range(source, key("forecast_window_d"),
                                  facts.FORECAST_WINDOW_DAYS, 1, 90)
    invalid |= bad
    buffer_pct, bad = _int_in_range(source, key("capacity_buffer_pct"),
                                    facts.CAPACITY_BUFFER_PCT, 0, 500)
    invalid |= bad
    refund_days, bad = _int_in_range(source, KEY_REFUND_WINDOW, facts.REFUND_WINDOW_DAYS,
                                     facts.REFUND_WINDOW_MIN_DAYS,
                                     facts.REFUND_WINDOW_MAX_DAYS)
    invalid |= bad
    skew_s, bad = _int_in_range(source, KEY_WEBHOOK_SKEW, facts.WEBHOOK_SKEW_S, 60, 600)
    invalid |= bad

    if source.value(KEY_PLATFORM_SHARE) is not None:
        share_key = KEY_PLATFORM_SHARE
    else:
        share_key = KEY_PLATFORM_SHARE_ALT
    share, bad = _int_in_range(source, share_key, facts.PLATFORM_FEE_BPS, 0, facts.FEE_BPS_MAX)
    invalid |= bad

    gas_mode = gas_mode_for(source.value(KEY_GAS_MODE), source.value(KEY_GAS_BEARER))
    if source.value(KEY_GAS_MODE) is None and source.value(KEY_GAS_MODE_LEGACY) is not None:
        gas_mode = gas_mode_for(source.value(KEY_GAS_MODE_LEGACY),
                                source.value(KEY_GAS_BEARER))
    bearer = str(source.value(KEY_GAS_BEARER) or "PLATFORM").strip().upper()
    if bearer not in ("PLATFORM", "PAYER"):
        bearer = "PLATFORM"
        invalid = True

    versions = [v for v in (source.config_version(key(attr)) for attr in (
        "min_spare", "max_active", "switch_threshold_pct", "activate_batch_size",
        "provision_lead_time_h")) if v is not None]
    version = max(versions) if versions else None
    if version is None:
        result_source = "invalid" if invalid else "default"
    else:
        result_source = "invalid" if invalid else "m10"
    policy_version = f"m08-pool-v{version}" if version is not None else "m08-pool-default"
    return TreasuryConfig(
        pool=pool, min_spare=min_spare, max_active=max_active,
        switch_threshold_pct=switch_pct, activate_batch_size=batch_size,
        provision_lead_time_h=lead_h, auto_expand=auto_expand, forecast_window_d=window_d,
        capacity_buffer_pct=buffer_pct, refund_window_days=refund_days,
        webhook_skew_s=skew_s, gas_mode=gas_mode, gas_bearer=bearer,
        platform_share_bps=share, policy_version=policy_version, source=result_source,
        config_version=version)
