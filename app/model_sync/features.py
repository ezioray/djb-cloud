# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 特性开关登记（硬约束：三字段 + 默认关闭 + 无运行时可写面）。

与 M02/M10/M17 的 features.py 同款理由：「这段代码要不要启用」属于**发布节奏**，不是业务配置；
不能塞进可发布的配置表（否则自举：要先读配置才知道能不能读配置）。

本模块的开关（M18 §9，全部默认关闭、无写面）：

``model.sync.enabled``（C17 服务端同步）
* owner = ``lead``；expire_at = ``2026-12-31``；
* rollback_rule = 关闭 → 停新 bundle 发布（写接口 503 / 50001，fail-closed）；
  客户端保留已应用版本，node catalog 回退到内置快照（``version=0, not_modified=true``）；
* default = ``False``：S2 测试网用 ``DJB_MODEL_SYNC=1`` 显式激活。

``model.sync.auto_publish``（自动发布）
* owner = ``server-seat``；expire_at = ``2026-12-31``；
* rollback_rule = 关闭 → 只生成草稿（draft），发布必须人工调 publish；
* default = ``False``；**不受** ``DJB_MODEL_SYNC`` 影响（自动发布必须单独显式打开）。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date

from . import facts

__all__ = [
    "FeatureSwitch", "FEATURE_SWITCHES", "WRITE_SURFACE", "switches", "get", "enabled",
    "active", "describe",
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
        name=facts.ENABLED_FLAG,
        owner="lead",
        expire_at=date(2026, 12, 31),
        rollback_rule=("关闭 → 停新 bundle 发布（create/publish/rollback 一律 503/50001 "
                       "fail-closed）；客户端保留已应用版本，node catalog 回退到内置快照"
                       "（version=0, not_modified=true）；不删除已发布 bundle 与事件，不改账本"),
        description=("C17 服务端模型/tokenizer 同步（M18 §9）：默认关闭，S2 测试网用 "
                     "DJB_MODEL_SYNC=1 显式激活；关闭时读接口（admin 列表 / 状态）保持只读"),
    ),
    FeatureSwitch(
        name=facts.AUTO_PUBLISH_FLAG,
        owner="server-seat",
        expire_at=date(2026, 12, 31),
        rollback_rule=("关闭 → 只生成草稿（draft），发布必须人工 POST .../publish；"
                       "已发布 bundle 不受影响；不接受 DJB_MODEL_SYNC 代开"),
        description="M18 §4 自动发布（S3 厂商适配器用）：默认关闭，本卡只留开关与分支",
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


def active(name: str) -> bool:
    """生效判定：默认值 **或** S2 测试网显式激活（``DJB_MODEL_SYNC=1``）。

    只有主开关 ``model.sync.enabled`` 吃环境变量；``model.sync.auto_publish`` 必须
    单独改代码/评审打开（决策单：自动发布不进测试网默认路径）。
    """
    if enabled(name):
        return True
    return name == facts.ENABLED_FLAG and os.environ.get(facts.ACTIVATION_ENV) == "1"


def describe() -> dict[str, object]:
    """给 status / 诊断 / 证据文件的开关视图（三字段齐全 + 生效值）。"""
    return {
        "switches": [dict(switch.as_dict(), active=active(switch.name))
                     for switch in FEATURE_SWITCHES],
        "write_surface": list(WRITE_SURFACE),
        "all_default_off": all(switch.default is False for switch in FEATURE_SWITCHES),
        "expire_at": sorted({switch.expire_at.isoformat() for switch in FEATURE_SWITCHES}),
        "activation_env": facts.ACTIVATION_ENV,
    }
