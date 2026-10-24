# SPDX-License-Identifier: AGPL-3.0-or-later
"""本模块的特性开关登记（硬约束：三字段 + 默认关闭 + T1/T2 不提供可写面）。

为什么单独一个文件：M10 的**业务**配置走 config_items / config_versions（可发布、可回滚、有审计）；
而「这段代码要不要启用」属于**发布节奏**，不能塞进配置中心自己的业务表（否则就是自举：
要读配置才能知道能不能读配置）。所以特性开关只做两件事：

1. **登记**：每个开关必须有 ``owner`` / ``expire_at`` / ``rollback_rule`` 三字段，缺一个导入期报错；
2. **默认关闭**：``default`` 只能是 False；T1/T2 只提供 :func:`enabled` 只读判定，
   **不提供任何写入函数/表/API**（``WRITE_SURFACE = ()``）。要开某个开关，必须改代码 + 过评审，
   并同时更新三字段（不是后台点一下）。

T3/T4 会用到这些开关（灰度、漂移扫描、kill switch）；它们在这里先把契约定好，
避免「先加一个偷偷打开的可写开关、上线后再补 owner」。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

__all__ = [
    "FeatureSwitch",
    "FEATURE_SWITCHES",
    "WRITE_SURFACE",
    "switches",
    "get",
    "enabled",
]

#: 没有可写面：T1/T2 不引入任何运行时可写开关（硬约束第 4 条）
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
        return {
            "name": self.name,
            "owner": self.owner,
            "expire_at": self.expire_at.isoformat(),
            "rollback_rule": self.rollback_rule,
            "default": self.default,
            "description": self.description,
        }


#: 开关登记表（T1/T2 全部关闭；T3/T4 实现时按此契约接线）
FEATURE_SWITCHES: tuple[FeatureSwitch, ...] = (
    FeatureSwitch(
        name="config_center.gray_rollout",
        owner="config-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭开关即回到单桶全量发布（S1 行为）；灰度桶记录保留不回删",
        description="S2 灰度发布（1→5→25→100）；T3 接线，S1 不启用",
    ),
    FeatureSwitch(
        name="config_center.drift_scan",
        owner="config-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后停止三源扫描任务；已写入 config_drifts 的记录保留（只追加）",
        description="三源漂移扫描（T4）；关闭时不影响发布与回滚",
    ),
    FeatureSwitch(
        name="config_center.kill_switch",
        owner="config-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后 kill-switch 端点返回 47004（危险键禁改口径）；已有紧急版本按 TTL 到期回退",
        description="kill switch 紧急收紧入口（T4）；只收紧、ttl ≤ 86400s",
    ),
    FeatureSwitch(
        name="config_center.publish_from_git",
        owner="config-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后回退到「发布单只认人工提交」；source=git 的版本仍可按 digest 复算",
        description="配置仓（git）作为 desired 源的直连发布（S2）",
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
    """只读判定：T1/T2 恒为默认值（False）。没有写入口——要打开必须改代码 + 评审。"""
    return get(name).default
