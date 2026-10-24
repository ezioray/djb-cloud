# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12 配置来源（规格 §8.1 ``notify.*``）：默认值 + 注入钩子，S1 不直连 M10。

为什么不在读取时直连 M10：配置中心自己也要在“配置可用”之前启动；M12 只依赖
``notify.*`` 十来个键，S1 先把**默认值**写死在这里并留一个只读 provider 钩子，
T4（接 M10）只需 ``set_provider(config_center.snapshot_provider)``，不改业务代码。

**只读**：本模块没有任何写入面；改配置走 M10 的发布单（47001–47011 码段），
不通过 M12 的表或 API（否则就是绕过复核与审计）。
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

from . import facts

__all__ = ["NotifyConfig", "DEFAULTS", "snapshot", "set_provider", "validate_config"]


@dataclass(frozen=True)
class NotifyConfig:
    """§8.1 的九个键（默认值与范围逐字取自规格）。"""

    merge_window_s: int = 3600                  # 60–86400
    report_daily_send_at: str = "09:00"         # 00:00–23:59（当地时间）
    p0_email_template: str = "p0.four_section"  # 四段式模板标识
    email_retry_count: int = 3                  # 1–5
    webhook_retry_delays_s: tuple[int, ...] = (1, 10, 60)
    webhook_timeout_s: int = 10                 # 3–30
    webhook_max_per_account: int = 5            # 1–20
    quiet_hours_default: Mapping[str, str] | None = None
    digest_default: str = "realtime"            # realtime / daily / weekly

    def as_dict(self) -> dict[str, Any]:
        return {
            "notify.merge_window_s": self.merge_window_s,
            "notify.report.daily_send_at": self.report_daily_send_at,
            "notify.p0.email_template": self.p0_email_template,
            "notify.email_retry_count": self.email_retry_count,
            "notify.webhook_retry_delays_s": list(self.webhook_retry_delays_s),
            "notify.webhook_timeout_s": self.webhook_timeout_s,
            "notify.webhook_max_per_account": self.webhook_max_per_account,
            "notify.quiet_hours_default": dict(self.quiet_hours_default)
            if self.quiet_hours_default else None,
            "notify.digest_default": self.digest_default,
        }


DEFAULTS = NotifyConfig()

#: 只读 provider 钩子：T4 由 Lead 接到 M10（返回 ``Mapping`` 或 ``NotifyConfig``）
_config_provider: Callable[[], Mapping[str, Any] | NotifyConfig] | None = None


def set_provider(provider: Callable[[], Mapping[str, Any] | NotifyConfig] | None) -> None:
    """接线/卸载配置来源（测试与合并期用；不是运行时可写配置面）。"""
    global _config_provider
    _config_provider = provider


def validate_config(config: NotifyConfig) -> NotifyConfig:
    """§8.1 的范围校验：越界直接 ``ValueError``（宁可启动失败，也不带着错配置跑）。"""
    if not 60 <= int(config.merge_window_s) <= 86400:
        raise ValueError("notify.merge_window_s 必须在 60–86400")
    if not 1 <= int(config.email_retry_count) <= 5:
        raise ValueError("notify.email_retry_count 必须在 1–5")
    delays = tuple(int(value) for value in config.webhook_retry_delays_s)
    if len(delays) != 3 or any(left >= right for left, right in zip(delays, delays[1:])):
        raise ValueError("notify.webhook_retry_delays_s 必须是 3 项且递增")
    if not 3 <= int(config.webhook_timeout_s) <= 30:
        raise ValueError("notify.webhook_timeout_s 必须在 3–30")
    if not 1 <= int(config.webhook_max_per_account) <= 20:
        raise ValueError("notify.webhook_max_per_account 必须在 1–20")
    facts.validate_digest(config.digest_default)
    if config.quiet_hours_default is not None:
        for field in ("start", "end"):
            facts.normalize_hhmm(config.quiet_hours_default.get(field, ""))
    return config


def snapshot() -> NotifyConfig:
    """当前生效配置：provider 有值则用之（缺失键回落默认），否则用 §8.1 默认值。"""
    provider = _config_provider
    if provider is None:
        return DEFAULTS
    raw = provider()
    if isinstance(raw, NotifyConfig):
        return validate_config(raw)
    values: dict[str, Any] = {}
    if "notify.merge_window_s" in raw:
        values["merge_window_s"] = int(raw["notify.merge_window_s"])
    if "notify.report.daily_send_at" in raw:
        values["report_daily_send_at"] = str(raw["notify.report.daily_send_at"])[:5]
    if "notify.p0.email_template" in raw:
        values["p0_email_template"] = str(raw["notify.p0.email_template"])
    if "notify.email_retry_count" in raw:
        values["email_retry_count"] = int(raw["notify.email_retry_count"])
    if "notify.webhook_retry_delays_s" in raw:
        values["webhook_retry_delays_s"] = tuple(int(item) for item in
                                                 raw["notify.webhook_retry_delays_s"])
    if "notify.webhook_timeout_s" in raw:
        values["webhook_timeout_s"] = int(raw["notify.webhook_timeout_s"])
    if "notify.webhook_max_per_account" in raw:
        values["webhook_max_per_account"] = int(raw["notify.webhook_max_per_account"])
    if "notify.quiet_hours_default" in raw:
        raw_quiet = raw["notify.quiet_hours_default"]
        values["quiet_hours_default"] = dict(raw_quiet) if raw_quiet else None
    if "notify.digest_default" in raw:
        values["digest_default"] = str(raw["notify.digest_default"])
    return validate_config(replace(DEFAULTS, **values))
