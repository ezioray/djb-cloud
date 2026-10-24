# SPDX-License-Identifier: AGPL-3.0-or-later
"""本模块的特性开关登记（硬约束第 4 条：**三字段 + 默认关闭 + 无可写面**）。

与 M02 ``app/supply/features.py`` / M04 ``app/scheduling/features.py`` 同款理由：
发布节奏不属于业务配置，不能塞进配置中心业务表（会自举）。因此这里只做两件事：

1. **登记**：每个开关必须有 ``owner`` / ``expire_at`` / ``rollback_rule``，缺一个导入期报错；
2. **默认关闭**：``default`` 只能是 ``False``；只提供 :func:`enabled` 只读判定，
   **没有任何写入函数 / 表 / API**（``WRITE_SURFACE = ()``）。

T1/T2 登记的三个开关都是 T3/T4 新口径的闸门：关着时保持「只记事实、不外发、不自动入池」
的保守行为，打开必须改代码 + 过评审，并同时更新三字段。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

__all__ = ["FeatureSwitch", "FEATURE_SWITCHES", "WRITE_SURFACE", "switches", "get", "enabled"]

#: 没有可写面：本模块不引入任何运行时可写开关（硬约束第 4 条）
WRITE_SURFACE: tuple[str, ...] = ()


@dataclass(frozen=True)
class FeatureSwitch:
    """一个特性开关：三字段必填、默认关闭、到期必须处理。"""

    name: str
    owner: str
    expire_at: date
    rollback_rule: str
    default: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name or "." not in self.name:
            raise ValueError(f"开关名必须是 <模块>.<特性> 形式：{self.name!r}")
        if not self.owner.strip():
            raise ValueError(f"{self.name}: owner 必填（硬约束第 4 条）")
        if not isinstance(self.expire_at, date):
            raise ValueError(f"{self.name}: expire_at 必须是 date")
        if len(self.rollback_rule.strip()) < 8:
            raise ValueError(f"{self.name}: rollback_rule 必填且要说清怎么回滚")
        if self.default is not False:
            raise ValueError(f"{self.name}: 特性开关默认必须关闭（default=False）")

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "owner": self.owner,
                "expire_at": self.expire_at.isoformat(),
                "rollback_rule": self.rollback_rule, "default": self.default,
                "description": self.description}


#: 开关登记表（全部关闭；打开需改代码 + 评审 + 更新三字段）
FEATURE_SWITCHES: tuple[FeatureSwitch, ...] = (
    FeatureSwitch(
        name="metering.usage_settle_sync_fallback",
        owner="metering-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后 M05 只发 usage.recorded 事件、不直连 M06 入账；E6 仍由 M06 消费事件产生",
        description=("T3 的同步兜底：M06 事件投递失败时由 M05 调 /internal/ledger 补一条 E6。"
                     "关闭时保持纯事件驱动（至少一次 + 幂等键 usage_settle/usage_id/1）"),
    ),
    FeatureSwitch(
        name="metering.estimated_usage_from_gateway",
        owner="metering-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后缺收据的 request.completed 只记日志、不落 estimated usage；已有行不受影响",
        description=("M05 §7「收据缺失」：按网关计量落 usage 并标 estimated。关闭时保持"
                     "「无收据不计量」，等收据到达再落库"),
    ),
    FeatureSwitch(
        name="metering.loss_pool_auto_entry",
        owner="metering-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后亏损池只能人工入池（admin 端点），自动检测不再写 loss_pool_entries",
        description=("M05 §6 流程 3 第 3 步：兜底切换 / 流式中断导致上游已消耗而用户未计费时自动入池。"
                     "关闭时只产差异工单，由人工确认后入池"),
    ),
)


def switches() -> tuple[FeatureSwitch, ...]:
    return FEATURE_SWITCHES


def get(name: str) -> FeatureSwitch:
    for switch in FEATURE_SWITCHES:
        if switch.name == name:
            return switch
    raise KeyError(f"未登记的开关：{name!r}（先在 features.py 登记三字段）")


def enabled(name: str) -> bool:
    """只读判定：恒为默认值（False）。没有写入口——打开必须改代码 + 评审。"""
    return get(name).default
