# SPDX-License-Identifier: AGPL-3.0-or-later
"""本模块的特性开关登记（硬约束：三字段 + 默认关闭 + 不提供可写面）。

与 M02 ``app/supply/features.py`` / M10 ``app/config_center/features.py`` 同款理由：
**发布节奏**不属于业务配置，不能塞进配置中心的业务表（否则自举）。所以这里只做两件事：

1. **登记**：每个开关必须有 ``owner`` / ``expire_at`` / ``rollback_rule`` 三字段，缺一个导入期报错；
2. **默认关闭**：``default`` 只能是 ``False``；只提供 :func:`enabled` 只读判定，
   **不提供任何写入函数 / 表 / API**（``WRITE_SURFACE = ()``）。

T1/T2 引入的三个开关都是「新口径上线的闸门」：关着时走旧的、更保守的行为，
打开必须改代码 + 过评审，并同时更新三字段。
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
        name="scheduling.p4_preemption",
        owner="scheduler-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后 P4 只产出 preempt_plan=[] 并按排队处理（给 ETA），不中断任何 batch",
        description=("P4 抢占执行开关（T4 落地）：关着时 realtime 只排队 / 拒绝，不抢 batch；"
                     "决策日志与 ETA 计算仍然照常，语义可直接回退"),
    ),
    FeatureSwitch(
        name="scheduling.affinity_hard_constraint",
        owner="scheduler-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后反亲和只降权（cost 惩罚）不淘汰，候选集与决策结果回到硬约束之前",
        description=("反亲和硬约束（M04 §4.7.4 第 4 条）：需要 physical_host_id 来源；"
                     "来源未接线时保持关闭，避免用猜测的拓扑淘汰候选"),
    ),
    FeatureSwitch(
        name="scheduling.quota_soft_stop",
        owner="scheduler-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后配额触顶只拒绝该请求（不冻结租户 60 s），冻结与纠偏逻辑整体失效",
        description=("配额触顶软停（§4.7.3 P3：冻结该租户 60 s）：关闭时按最小口径只拒绝当前请求"),
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
