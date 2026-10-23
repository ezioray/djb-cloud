# SPDX-License-Identifier: Apache-2.0
"""M10 私有 risk-config 的**只读绑定**（INV-01 / M11 §7 LKG / §8.1）。

本模块**永远不持有阈值数值**：这里只解析「某个 ``risk.*`` 键当前是哪一版」，
用于给案件盖 ``config_ref`` + ``rule_version`` 戳。取不到（未接线 / M10 不可用）时
按 §7 降级为 LKG（只监控）——降级只影响「要不要自动处置」，不影响任何数值。

``provider`` 由合并期注入（读 M10 只读快照 / 内存快照），形状::

    provider.config_version("risk.limit.qps") -> int | None
    provider.published_at("risk.limit.qps") -> datetime | None

未注入时 ``NullConfigProvider`` 恒返回 ``None`` → ``source="lkg"``。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from . import clock, facts

__all__ = ["ConfigStamp", "ConfigProvider", "NullConfigProvider", "stamp_for", "is_stale"]


class ConfigProvider(Protocol):                       # pragma: no cover - 结构协议
    def config_version(self, config_ref: str) -> int | None: ...
    def published_at(self, config_ref: str) -> datetime | None: ...


@dataclass(frozen=True)
class ConfigStamp:
    """一次绑定结果：只有键、版本、来源；**没有值**。"""

    config_ref: str | None
    version: int | None
    source: str                                        # m10 / lkg / none
    published_at: datetime | None = None

    def as_dict(self) -> dict:
        return {"config_ref": self.config_ref, "config_version": self.version,
                "config_source": self.source}


class NullConfigProvider:
    """默认实现：未接线 M10 → 一律 LKG（只监控，不自动处置）。"""

    def config_version(self, config_ref: str) -> int | None:
        return None

    def published_at(self, config_ref: str) -> datetime | None:
        return None


def stamp_for(config_ref: str | None, provider: ConfigProvider | None = None, *,
              now: datetime | None = None) -> ConfigStamp:
    """把规则的 ``config_ref`` 绑定到当前 M10 版本；不读值、不落值（INV-01）。"""
    if config_ref is None:
        return ConfigStamp(config_ref=None, version=None, source="none")
    source = provider or NullConfigProvider()
    version = source.config_version(config_ref)
    published = source.published_at(config_ref)
    if version is None:
        return ConfigStamp(config_ref=config_ref, version=None, source="lkg")
    if published is not None and is_stale(published, now=now):
        # 规则包版本过期 → §7 降级为 LKG（只监控）；仍不读任何阈值
        return ConfigStamp(config_ref=config_ref, version=version, source="lkg",
                           published_at=clock.as_utc(published))
    return ConfigStamp(config_ref=config_ref, version=version, source="m10",
                       published_at=clock.as_utc(published) if published else None)


def is_stale(published_at: datetime, *, now: datetime | None = None) -> bool:
    """LKG TTL（§8.2 LKG_TTL_H=24h）：超过即视为过期。"""
    current = clock.as_utc(now or clock.utcnow())
    delta = current - clock.as_utc(published_at)
    return delta.total_seconds() > facts.LKG_TTL_H * 3600
