# SPDX-License-Identifier: Apache-2.0
"""本模块的特性开关登记（硬约束第 4 条：**三字段 + 默认关闭 + 无可写面**）。

与 M02 ``app/supply/features.py`` / M04 ``app/scheduling/features.py`` /
M05 ``app/metering/features.py`` 同款理由：发布节奏不属于业务配置，不能塞进配置中心
业务表（会自举）。因此这里只做两件事：

1. **登记**：每个开关必须有 ``owner`` / ``expire_at`` / ``rollback_rule``，缺一个导入期报错；
2. **默认关闭**：``default`` 只能是 ``False``；只提供 :func:`enabled` 只读判定，
   **没有任何写入函数 / 表 / API**（``WRITE_SURFACE = ()``）。

三个开关都是 T2→T3/T4 新口径的闸门：关着时保持 T1/T2 已验证的保守行为，
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
        name="gateway.protocol_version_strict",
        owner="gateway-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule=("关闭后忽略 DJB-Protocol-Version 的不兼容值（不返回 426/42601），"
                       "按当前 MAJOR 兼容读取；已发出的 426 不影响，客户端重试即可"),
        description=("T4 的协议版本闸门：打开后校验 DJB-Protocol-Version 的 MAJOR 是否在 "
                     "facts.PROTOCOL_MAJOR_SUPPORTED 内，不兼容返回 426 / 42601"),
    ),
    FeatureSwitch(
        name="gateway.node_layer_rate_limit",
        owner="gateway-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule=("关闭后只按 min(租户, Key) 限流，不再对节点层 qps 做网关侧二次限流；"
                       "节点层准入仍由 M04 P3 负责，不产生超额计费"),
        description=("min(租户, Key, 节点) 的**节点层**闸门：打开后对决策返回的 node_qps 做"
                     "网关侧滑动窗口限流（429/42901），关闭时节点层只依赖 M04 的配额判定"),
    ),
    FeatureSwitch(
        name="gateway.stream_sse",
        owner="gateway-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule=("关闭后 stream=true 一律 400/40001（T2 行为，明确不支持流式），"
                       "不产生半截 SSE；已建立的连接按 stream_timeout_s 自然结束"),
        description=("T3 的流式闸门：打开后 stream=true 走 text/event-stream 与 "
                     "data: [DONE] 收尾、中断计 44101；关闭时显式拒绝流式请求"),
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
