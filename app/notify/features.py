# SPDX-License-Identifier: AGPL-3.0-or-later
"""本模块的特性开关登记（硬约束第 4 条：**三字段 + 默认关闭 + 无可写面**）。

与 M02 ``app/supply/features.py`` / M04 / M05 同款理由：发布节奏不属于业务配置，
不能塞进配置中心业务表（会自举）。因此这里只做两件事：

1. **登记**：每个开关必须有 ``owner`` / ``expire_at`` / ``rollback_rule``，缺一个导入期报错；
2. **默认关闭**：``default`` 只能是 ``False``；只提供 :func:`enabled` 只读判定，
   **没有任何写入函数 / 表 / API**（``WRITE_SURFACE = ()``）。

三个开关都是「真投递」的闸门：关着时 M12 仍完整落库、写尝试记录、发事件（可观测、可回放），
但**不发真实邮件、不发真实 Webhook、不启用静默时段**——S1 的发信供应商与出网白名单
还没接（§4.3 / T4），开着关都会保留同一套数据与接口。
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
        name="notify.email_dispatch",
        owner="notify-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后邮件渠道只记 retryable/transport_not_wired 尝试、不发信；"
                      "站内信与 Webhook 不受影响，已发邮件不回滚",
        description=("S2 邮件适配器闸门：打开才允许调用真实供应商（密钥只存引用）。"
                     "关闭时保持「站内必达 + 邮件尝试留痕」的保守行为（INV-06 降级路径仍可测）"),
    ),
    FeatureSwitch(
        name="notify.webhook_dispatch",
        owner="notify-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后 Webhook 渠道只写 attempt=retryable/transport_not_wired，不出网；"
                      "订阅与签名头照常生成，可用于对端自测",
        description=("S2 Webhook 出网闸门：打开才发真实 HTTP（含出网白名单 / DNS 二次校验）。"
                     "关闭时订阅管理、SSRF 校验、签名与重试排期仍全部生效"),
    ),
    FeatureSwitch(
        name="notify.quiet_hours_enforced",
        owner="notify-seat",
        expire_at=date(2027, 6, 30),
        rollback_rule="关闭后静默时段只保存不生效（P1/P2 立即投递）；"
                      "P0 本来就不受静默时段影响（INV-01），无行为变化",
        description=("静默时段 / 摘要聚合的生效闸门：打开后 P1/P2 在 quiet_hours 内延后、"
                     "按 digest 聚合；P0 永远立即投递（INV-01）"),
    ),
    FeatureSwitch(
        name="notify.node_push.enabled",
        owner="lead",
        expire_at=date(2026, 12, 31),
        rollback_rule=("关闭后停止新入队与新投递（enqueue / pull 返回 503 / 50001），"
                       "已排队的通知保留可查（ack / read / unread_count / 管理面列表仍可用）；"
                       "已投递的行不回滚、不删除，保留期照常 180 天"),
        description=("C15 节点通知队列闸门：打开后服务端为**节点**排队并投递通知"
                     "（GET /api/v1/node/notifications 拉取 + ack/read）；"
                     "S2 由显式 DJB_NODE_PUSH=1 激活，生产打开需改代码 + 评审"),
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
