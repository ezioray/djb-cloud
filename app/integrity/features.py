# SPDX-License-Identifier: AGPL-3.0-or-later
"""本模块的特性开关登记（硬约束：三字段 + 默认关闭 + 无运行时可写面）。

与 M02/M10 的 features.py 同款理由：「这段代码要不要启用」属于**发布节奏**，不是业务配置；
不能塞进可发布的配置表（否则自举：要先读配置才知道能不能读配置）。

本模块的开关（M17 §9，全部默认关闭、无写面）：

``supply.freeze.enabled``（C14 冻结）
``supply.attestation.enabled``（C12 证明）——原文档段：

* owner = ``risk-seat``（风险席，因为冻结是风控处置动作）；
* expire_at = ``2026-12-31``；到期未清理要计数并回写；
* rollback_rule = 关闭 → **释放全部 active hold（只改 state，不改账本）**；保留案件与事件记录；
* default = ``False``：未打开时**写路径 fail-closed**（503 / 50001 + reason=feature_disabled），
  读路径（列表 / 详情 / 冻结总额）保持只读可用——按 rollback_rule「保留可查」。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

__all__ = [
    "FeatureSwitch", "FEATURE_SWITCHES", "WRITE_SURFACE", "switches", "get", "enabled",
    "describe",
]

#: 没有可写面：开关只能改代码 + 过评审，不能后台点开（硬约束第 4 条）
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


FEATURE_SWITCHES: tuple[FeatureSwitch, ...] = (
    FeatureSwitch(
        name="supply.freeze.enabled",
        owner="risk-seat",
        expire_at=date(2026, 12, 31),
        rollback_rule=("关闭 → 释放全部 active hold（只改 state=released + 事件，不改账本）；"
                       "已冻结金额随 hold 解除自然回到原待分润；保留案件 / 事件记录可查"),
        description=("M17 §6.1 待分润冻结（C14，S2 只冻结不罚没）：关闭时 create/release 一律 "
                     "fail-closed（503/50001），GET 只读保留"),
    ),
    FeatureSwitch(
        name="supply.attestation.enabled",
        owner="lead",
        expire_at=date(2026, 12, 31),
        rollback_rule=("关闭 → 停止签发新挑战与客户端上报（写接口 503/50001，fail-closed）；"
                       "已存证明保留只读，按 TTL 自然过期；不删除挑战 / 事件记录；不改账本"),
        description=("M17 §5 模型身份证明（C12 服务端 L3+ 核心）：默认关闭，S2 测试网用 "
                     "DJB_ATTEST=1 显式激活；关闭时读接口只读"),
    ),
    FeatureSwitch(
        name="supply.sampling.enabled",
        owner="lead",
        expire_at=date(2026, 12, 31),
        rollback_rule=("关闭 → 停止开新轮次 / 揭示 / 回填结果（写接口 503/50001，fail-closed）；"
                       "已揭示轮次的承诺、抽样框与抽签结果保留只读、可继续复算；"
                       "未完成的 pending 抽检不再推进（不判 missed、不改账本）"),
        description=("M17 §5.10 可验证随机抽检（C14b commit-reveal + 贡献加权）：默认关闭，"
                     "S2 测试网用 DJB_SAMPLING=1 显式激活；关闭时读接口只读"),
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
    """只读判定（当前恒为默认值 False；打开必须改代码 + 评审）。"""
    return get(name).default


def describe() -> dict[str, object]:
    """给 status / 诊断 / 证据文件的开关视图（三字段齐全 + 生效值）。"""
    return {
        "switches": [switch.as_dict() for switch in FEATURE_SWITCHES],
        "write_surface": list(WRITE_SURFACE),
        "all_default_off": all(switch.default is False for switch in FEATURE_SWITCHES),
        "expire_at": sorted({switch.expire_at.isoformat() for switch in FEATURE_SWITCHES}),
    }
