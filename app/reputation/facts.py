# SPDX-License-Identifier: Apache-2.0
"""M07 本模块常量与可注入配置（规格 §8.1 配置键 / §8.2 本模块常量）。

**为什么常量单独一处**：00-conventions §10「禁止硬编码常量」指的是散落数字；
本文件是唯一出处，每个值都标注来源（§8.2 / §8.1），并且全部通过 :class:`ReputationConfig`
注入——测试可以整组替换，业务代码不写死任何阈值。

S1 口径（Lead 已裁决 / 规格 §8.1）：

* ``reputation.weights``：四项权重 bps，**和必须 = 10000**（成功率 4000 / 延迟达标 3000 /
  在线率 2000 / 让路响应 1000）；
* ``reputation.window_days``：7–90，默认 30；
* ``points.invite_bps``：0–1000，默认 400（= 被邀请人每笔 COP 的 4% 给邀请人）；
* ``points.invite_months``：1–24，默认 12；
* ``points.transfer_lock_days`` / ``points.transfer_per_tx_cap`` / ``points.transfer_daily_*``：
  转让受 ``points_policy`` 表（既有 COP 台账）约束，**本模块只读**，见 :mod:`app.reputation.cop`。

COP 计提口径（**引用既有配置，不新造业务事实**）：一条 ``usage.settled`` 计提的 COP 单位数 =
``final_amount_minor × points_policy.redeem_cop_per_usd / 100``，即 1 USD 结算对应
``redeem_cop_per_usd``（默认 100）COP。该比例是既有 ``points_policy`` 的生效值，
本模块不新增 ``accrual_bps`` 之类未登记的业务常量（如需调整走 M10 配置键 + CR）。
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Mapping

__all__ = [
    "WEIGHTS_BPS", "PENALTY_WEIGHTS", "PENALTY_CYCLE_CAP", "TIER_ORDER", "TIERS",
    "COEFF_MIN_TENTHS", "COEFF_MAX_TENTHS", "SCORE_MIN", "SCORE_MAX",
    "ReputationConfig", "DEFAULT_CONFIG", "COEFFICIENT_BANDS",
]

# --------------------------------------------------------------------------- §8.2 常量
#: 四项权重（bps）；§8.1 ``reputation.weights`` 默认 4000/3000/2000/1000，和 = 10000
WEIGHTS_BPS: dict[str, int] = {
    "success_rate": 4000,        # 成功率
    "latency_ok_rate": 3000,     # 延迟达标率
    "online_rate": 2000,         # 在线率
    "yield_response": 1000,      # 让路响应
}

#: 惩罚项（§8.2）：违规 −200 / 虚假申报 −500 / 恶意占用 −300
PENALTY_WEIGHTS: dict[str, int] = {
    "violation": 200,
    "false_report": 500,
    "malicious_occupancy": 300,
}

#: 单周期惩罚累计上限 −1000（§8.2）
PENALTY_CYCLE_CAP = 1000

#: 评分值域 0–1000 整数（§8.2）
SCORE_MIN, SCORE_MAX = 0, 1000

#: 等级（§3 状态机 L1→L2→L3→L4，L5 仅人工）
TIERS: tuple[str, ...] = ("L1", "L2", "L3", "L4", "L5")
TIER_ORDER: dict[str, int] = {tier: index for index, tier in enumerate(TIERS)}

#: 系数区间 0.5–1.2 步长 0.1（§8.2）；内部用「十分位」整数 5..12 表达，避免浮点误差
COEFF_MIN_TENTHS, COEFF_MAX_TENTHS = 5, 12

#: 分数 → 质量系数（十分位）的单调分段；阈值属 §8.2「系数区间」的实现口径
COEFFICIENT_BANDS: tuple[tuple[int, int], ...] = (
    (900, 12), (800, 11), (700, 10), (600, 9),
    (500, 8), (400, 7), (300, 6), (0, 5),
)


def _validate_weights(weights: Mapping[str, int]) -> dict[str, int]:
    missing = set(WEIGHTS_BPS) - set(weights)
    if missing:
        raise ValueError(f"reputation.weights 缺项：{sorted(missing)}")
    extra = set(weights) - set(WEIGHTS_BPS)
    if extra:
        raise ValueError(f"reputation.weights 未登记项：{sorted(extra)}")
    resolved = {key: int(value) for key, value in weights.items()}
    if any(value < 0 for value in resolved.values()):
        raise ValueError("reputation.weights 不得为负")
    if sum(resolved.values()) != 10_000:
        raise ValueError("reputation.weights 四项之和必须 = 10000 bps（§8.1）")
    return resolved


@dataclass(frozen=True)
class ReputationConfig:
    """可注入的评分配置（默认值全部来自 §8.1 / §8.2，测试可整组替换）。"""

    weights: Mapping[str, int] = field(default_factory=lambda: dict(WEIGHTS_BPS))
    window_days: int = 30                          # §8.1 reputation.window_days
    penalty_weights: Mapping[str, int] = field(default_factory=lambda: dict(PENALTY_WEIGHTS))
    penalty_cycle_cap: int = PENALTY_CYCLE_CAP
    invite_bps: int = 400                          # §8.1 points.invite_bps
    invite_months: int = 12                        # §8.1 points.invite_months
    # 等级门槛（§8.2）：默认值就是常量，注入只为测试可翻转分支
    l2_online_rate: int = 950
    l2_cumulative_cop: int = 10_000
    l3_quality_tenths: int = 10                    # 质量系数 ≥1.0
    l3_days_at_l2: int = 30
    l4_days_at_l3: int = 90
    l4_online_rate: int = 990
    policy_version: str = "rep-v1"

    def validated(self) -> "ReputationConfig":
        weights = _validate_weights(self.weights)
        if not 7 <= int(self.window_days) <= 90:
            raise ValueError("reputation.window_days 必须在 7..90（§8.1）")
        if not 0 <= int(self.invite_bps) <= 1000:
            raise ValueError("points.invite_bps 必须在 0..1000（§8.1）")
        if not 1 <= int(self.invite_months) <= 24:
            raise ValueError("points.invite_months 必须在 1..24（§8.1）")
        for name in ("penalty_weights",):
            weights_bad = [value for value in getattr(self, name).values() if value < 0]
            if weights_bad:
                raise ValueError(f"{name} 不得为负")
        if int(self.penalty_cycle_cap) <= 0:
            raise ValueError("penalty_cycle_cap 必须 > 0")
        return replace(self, weights=weights,
                       penalty_weights={key: int(value)
                                        for key, value in self.penalty_weights.items()})

    # ------------------------------------------------------------ 派生口径（纯函数）
    def accrual_units(self, amount_minor: int, cop_per_usd: int) -> int:
        """``usage.settled`` 计提：``amount_minor × cop_per_usd / 100``（向下取整）。

        引用的 ``cop_per_usd`` 是既有 ``points_policy.redeem_cop_per_usd``（1 USD = N COP），
        本模块不新造汇率常量。
        """
        if amount_minor <= 0 or cop_per_usd <= 0:
            return 0
        return int(Decimal(int(amount_minor)) * Decimal(int(cop_per_usd))
                   // Decimal(100))

    def invite_reward_units(self, earned_units: int) -> int:
        """邀请奖励：被邀请人每笔计提 COP 的 ``points.invite_bps``（默认 4%），向下取整。"""
        if earned_units <= 0:
            return 0
        return int(Decimal(int(earned_units)) * Decimal(int(self.invite_bps))
                   // Decimal(10_000))


DEFAULT_CONFIG = ReputationConfig().validated()
