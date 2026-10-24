# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 评分引擎（**纯函数**；规则 + 指标事件重算，配置可注入）。

对应规格：

* §3 **INV-07**：信誉分只由规则 + 指标事件计算；产出必须带 ``reasons[]`` 与 ``policy_version``；
* §3 **INV-08**：本模块**只输出等级**，不输出费率 / 折扣（折扣表在 03-facts §4，由消费方查）；
* §3 状态机：``L1→L2→L3→L4`` 按 §8.2 规则升降（**会掉级**，掉级即时生效），``L5`` 仅人工授予；
* §8.2：四项分项各 0–1000、加权（4000/3000/2000/1000 bps）后减惩罚项；
  惩罚 违规 −200 / 虚假申报 −500 / 恶意占用 −300，单周期累计上限 −1000；
  系数区间 0.5–1.2 步长 0.1。

设计要点：本模块**不碰数据库**（不 import psycopg），入参是「指标 + 上一次结果」，
出参是「新结果 + 原因」，因此可单测到每个分支（§9「关键分支 100%」）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Mapping, Sequence

from .facts import (
    COEFFICIENT_BANDS,
    COEFF_MAX_TENTHS,
    COEFF_MIN_TENTHS,
    DEFAULT_CONFIG,
    SCORE_MAX,
    SCORE_MIN,
    TIER_ORDER,
    TIERS,
    ReputationConfig,
)

__all__ = [
    "Metrics", "Evaluation", "metrics_from", "weighted_score", "penalty_units",
    "coefficient_tenths", "eligible_tier", "next_tier", "evaluate",
    "days_between", "COEFFICIENT_BANDS",
]


# --------------------------------------------------------------------------- 入参
@dataclass(frozen=True)
class Metrics:
    """四项分项（各 0–1000 整数，§8.2）。"""

    success_rate: int = 0        # 成功率
    latency_ok_rate: int = 0     # 延迟达标率
    online_rate: int = 0         # 在线率（本项同时是 L2 / L4 的门槛指标）
    yield_response: int = 0      # 让路响应

    def as_dict(self) -> dict[str, int]:
        return {"success_rate": self.success_rate, "latency_ok_rate": self.latency_ok_rate,
                "online_rate": self.online_rate, "yield_response": self.yield_response}

    def clamped(self) -> "Metrics":
        return Metrics(**{key: max(SCORE_MIN, min(SCORE_MAX, int(value)))
                          for key, value in self.as_dict().items()})


def metrics_from(values: Mapping[str, Any] | Metrics | None) -> Metrics:
    """从 dict / Metrics 构造并夹到 0–1000（API 校验之外的最后一道）。"""
    if isinstance(values, Metrics):
        return values.clamped()
    mapping = dict(values or {})
    return Metrics(**{key: int(mapping.get(key, 0) or 0)
                      for key in ("success_rate", "latency_ok_rate", "online_rate",
                                  "yield_response")}).clamped()


# --------------------------------------------------------------------------- 分数
def weighted_score(metrics: Metrics, config: ReputationConfig = DEFAULT_CONFIG) -> int:
    """加权分（bps 归一，向下取整）：``Σ(metric × weight) // 10000``。"""
    total = sum(int(getattr(metrics, key)) * int(weight)
                for key, weight in config.weights.items())
    return max(SCORE_MIN, min(SCORE_MAX, total // 10_000))


def penalty_units(penalties: Mapping[str, int] | Sequence[tuple[str, int]] | None,
                  config: ReputationConfig = DEFAULT_CONFIG) -> int:
    """惩罚扣分（正数，表示「要扣多少」）：单周期累计上限 ``penalty_cycle_cap``（§8.2）。"""
    if not penalties:
        return 0
    items = penalties.items() if isinstance(penalties, Mapping) else penalties
    total = 0
    for kind, count in items:
        if kind not in config.penalty_weights:
            raise ValueError(f"未登记的惩罚项：{kind}")
        count = int(count)
        if count < 0:
            raise ValueError("惩罚次数不得为负")
        total += int(config.penalty_weights[kind]) * count
    return min(total, int(config.penalty_cycle_cap))


def coefficient_tenths(value: int) -> int:
    """把 0–1000 的观测值映射到系数「十分位」（5..12，即 0.5–1.2，步长 0.1）。"""
    value = int(value)
    for floor_value, tenths in COEFFICIENT_BANDS:
        if value >= floor_value:
            return max(COEFF_MIN_TENTHS, min(COEFF_MAX_TENTHS, tenths))
    return COEFF_MIN_TENTHS


# --------------------------------------------------------------------------- 等级
def eligible_tier(*, online_rate: int, cumulative_cop: int, quality_tenths: int,
                  days_at_l2: int, days_at_l3: int,
                  config: ReputationConfig = DEFAULT_CONFIG) -> str:
    """按 §8.2 规则算「当前条件够得上的最高等级」（L5 不在规则内，只能人工）。"""
    if days_at_l3 >= int(config.l4_days_at_l3) and int(online_rate) >= int(config.l4_online_rate):
        return "L4"
    if (quality_tenths >= int(config.l3_quality_tenths)
            and days_at_l2 >= int(config.l3_days_at_l2)):
        return "L3"
    if (int(online_rate) >= int(config.l2_online_rate)
            and int(cumulative_cop) >= int(config.l2_cumulative_cop)):
        return "L2"
    return "L1"


def next_tier(current: str | None, eligible: str, *, manual_tier: bool = False) -> str:
    """升降判定：规则等级立即生效（**会掉级**）；``manual_tier`` 保持 L5（§8.2 / CR-5）。"""
    if current is not None and current not in TIER_ORDER:
        raise ValueError(f"非法等级：{current}")
    if eligible not in TIER_ORDER:
        raise ValueError(f"非法等级：{eligible}")
    if manual_tier or current == "L5":
        # L5 只能人工授予，也只能人工撤销；撤销后回到规则等级
        return "L5" if manual_tier else eligible
    return eligible


def days_between(start: Any, end: Any) -> int:
    """整日差（向下取整，负数按 0）：连续天数口径，不看墙上时钟。"""
    if start is None or end is None:
        return 0
    delta = end - start
    return max(0, int(delta.total_seconds() // 86_400))


# --------------------------------------------------------------------------- 编排
@dataclass(frozen=True)
class Evaluation:
    """一次重算的结果（纯数据，不含 DB 句柄）。"""

    score: int
    tier: str
    quality_coef: Decimal
    stability_coef: Decimal
    window_days: int
    policy_version: str
    reasons: tuple[str, ...] = ()
    prev_score: int | None = None
    prev_tier: str | None = None

    @property
    def changed(self) -> bool:
        """分数或等级是否变化（决定是否发 ``reputation.changed``）。"""
        return self.prev_score is None or self.prev_score != self.score \
            or self.prev_tier != self.tier

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score, "tier": self.tier,
            "quality_coef": float(self.quality_coef), "stability_coef": float(self.stability_coef),
            "window_days": self.window_days, "policy_version": self.policy_version,
            "reasons": list(self.reasons),
        }


def evaluate(*, metrics: Mapping[str, Any] | Metrics,
             penalties: Mapping[str, int] | Sequence[tuple[str, int]] | None = None,
             stability_bps: int = 0,
             cumulative_cop: int = 0,
             previous_score: int | None = None,
             previous_tier: str | None = None,
             tier_since_days: int = 0,
             days_at_l2: int | None = None,
             days_at_l3: int | None = None,
             manual_tier: bool = False,
             config: ReputationConfig = DEFAULT_CONFIG) -> Evaluation:
    """规则重算（纯函数）。

    ``tier_since_days`` 是「当前等级已持续天数」的便捷入参；需要精确控制时分别传
    ``days_at_l2`` / ``days_at_l3``（L3 / L4 的门槛各自不同）。
    """
    readings = metrics_from(metrics)
    base = weighted_score(readings, config)
    deduct = penalty_units(penalties, config)
    score = max(SCORE_MIN, min(SCORE_MAX, base - deduct))
    quality_tenths = coefficient_tenths(score)
    stability_tenths = coefficient_tenths(stability_bps)

    if days_at_l2 is None:
        days_at_l2 = tier_since_days if previous_tier == "L2" else 0
    if days_at_l3 is None:
        days_at_l3 = tier_since_days if previous_tier == "L3" else 0

    eligible = eligible_tier(
        online_rate=readings.online_rate, cumulative_cop=int(cumulative_cop),
        quality_tenths=quality_tenths, days_at_l2=int(days_at_l2),
        days_at_l3=int(days_at_l3), config=config)
    tier = next_tier(previous_tier, eligible, manual_tier=manual_tier)

    reasons: list[str] = []
    if deduct:
        reasons.append("penalty_applied")
        if deduct >= int(config.penalty_cycle_cap):
            reasons.append("penalty_cap_reached")
    if previous_tier is None:
        reasons.append("initial_assessment")
    elif TIER_ORDER[tier] > TIER_ORDER[previous_tier]:
        reasons.append("tier_promoted")
        reasons.append(_promotion_reason(tier))
    elif TIER_ORDER[tier] < TIER_ORDER[previous_tier]:
        reasons.append("tier_demoted")
        reasons.append(_demotion_reason(readings, quality_tenths, config))
    elif previous_score is not None and previous_score != score:
        reasons.append("score_changed")
    if manual_tier and tier == "L5":
        reasons.append("manual_l5")

    return Evaluation(
        score=score, tier=tier,
        quality_coef=Decimal(quality_tenths) / Decimal(10),
        stability_coef=Decimal(stability_tenths) / Decimal(10),
        window_days=int(config.window_days), policy_version=str(config.policy_version),
        reasons=tuple(reasons), prev_score=previous_score, prev_tier=previous_tier)


def _promotion_reason(tier: str) -> str:
    """升级原因（人类可读、**不含阈值**——INV-07 / spec ``ReputationProfile.reasons``）。"""
    return {
        "L2": "online_and_cop_targets_met",
        "L3": "quality_and_sustained_l2",
        "L4": "sustained_l3_and_high_online",
        "L5": "manual_grant",
    }.get(tier, "tier_targets_met")


def _demotion_reason(metrics: Metrics, quality_tenths: int,
                     config: ReputationConfig) -> str:
    """掉级原因（同上：只给方向，不给具体数字）。"""
    if metrics.online_rate < int(config.l4_online_rate):
        return "online_rate_below_target"
    if quality_tenths < int(config.l3_quality_tenths):
        return "quality_below_target"
    return "sustained_duration_lost"
