# SPDX-License-Identifier: Apache-2.0
"""本模块的特性开关登记（硬约束：三字段 + 默认关闭 + T1/T2 不提供可写面）。

与 M10 ``app/config_center/features.py`` 同款理由：**发布节奏**不属于业务配置，不能塞进
配置中心自己的业务表（否则自举：要先读配置才知道能不能读配置）。所以这里只做两件事：

1. **登记**：每个开关必须有 ``owner`` / ``expire_at`` / ``rollback_rule`` 三字段，缺一个导入期报错；
2. **默认关闭**：``default`` 只能是 False；T1/T2 只提供 :func:`enabled` 只读判定，
   **不提供任何写入函数 / 表 / API**（``WRITE_SURFACE = ()``）。要打开某个开关必须改代码 +
   过评审，并同时更新三字段。

T3–T6 会用到这些开关（心跳运行态、公告快照、策略 304、弃用强制）；先把契约定好，
避免「先加一个偷偷打开的可写开关、上线后再补 owner」。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

__all__ = ["FeatureSwitch", "FEATURE_SWITCHES", "WRITE_SURFACE", "switches", "get", "enabled"]

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
        return {"name": self.name, "owner": self.owner,
                "expire_at": self.expire_at.isoformat(),
                "rollback_rule": self.rollback_rule, "default": self.default,
                "description": self.description}


#: 开关登记表（T1/T2 全部关闭；T3–T6 实现时按此契约接线）
FEATURE_SWITCHES: tuple[FeatureSwitch, ...] = (
    FeatureSwitch(
        name="supply.heartbeat_runtime_state",
        owner="supply-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后心跳忽略 runtime_state 字段（只登记不落库），已写入的历史值保留不改",
        description="CR-5 可选 runtime_state 上报（T3）；关闭时心跳行为回到 1.2.0 之前的字段集",
    ),
    FeatureSwitch(
        name="supply.capacity_snapshot_view",
        owner="supply-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后 M04 回退到直接读公告表的最新 seq；已生成的快照视图保留只读",
        description="容量公告快照视图（T3，供 M04 候选集）；关闭不影响公告落库",
    ),
    FeatureSwitch(
        name="supply.policy_etag_304",
        owner="supply-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后策略接口一律 200 全量下发（不返回 304），客户端 LKG 仍可用",
        description="策略 ETag / If-None-Match 304（T5）；关闭时只退化缓存收益，不改语义",
    ),
    FeatureSwitch(
        name="supply.protocol_deprecation_enforce",
        owner="supply-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后弃用清单只读展示、不拒绝请求（42601 仍按 N/N-1/N-2 硬矩阵生效）",
        description="弃用到期强制拒绝（T6）；关闭时弃用只提示不阻断",
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
    """只读判定：T1/T2 恒为默认值（False）。没有写入口——打开必须改代码 + 评审。"""
    return get(name).default
