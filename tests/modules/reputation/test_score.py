# SPDX-License-Identifier: Apache-2.0
"""评分引擎单元测试（纯函数，不连库）：§8.2 规则 / INV-07 / INV-08。

覆盖点：加权、惩罚上限、系数区间与步长、等级升降（**会掉级**）、L5 只能人工、
``reasons`` 不含阈值、配置注入（改门槛即改判定）。
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from app.reputation import facts, score


# --------------------------------------------------------------------------- 加权
def test_weighted_score_uses_bps_weights():
    assert score.weighted_score(score.Metrics(1000, 1000, 1000, 1000)) == 1000
    assert score.weighted_score(score.Metrics(0, 0, 0, 0)) == 0
    # 只满足在线率：2000/10000 = 200
    assert score.weighted_score(score.Metrics(online_rate=1000)) == 200
    # 只满足让路响应：1000/10000 = 100
    assert score.weighted_score(score.Metrics(yield_response=1000)) == 100


def test_weighted_score_is_floored_not_rounded():
    # 1×4000//10000 = 0（向下取整，不四舍五入）
    assert score.weighted_score(score.Metrics(success_rate=1)) == 0
    assert score.weighted_score(score.Metrics(success_rate=3)) == 1


def test_metrics_are_clamped_to_domain():
    readings = score.metrics_from({"success_rate": 5000, "online_rate": -20})
    assert readings.success_rate == 1000
    assert readings.online_rate == 0


# --------------------------------------------------------------------------- 惩罚
def test_penalty_weights_and_cycle_cap():
    assert score.penalty_units({"violation": 1}) == 200
    assert score.penalty_units({"false_report": 1}) == 500
    assert score.penalty_units({"malicious_occupancy": 1}) == 300
    # 单周期累计上限 −1000（§8.2）
    assert score.penalty_units({"violation": 6}) == 1000
    assert score.penalty_units([("violation", 2), ("false_report", 2)]) == 1000


def test_unknown_penalty_kind_is_rejected():
    with pytest.raises(ValueError):
        score.penalty_units({"unknown": 1})
    with pytest.raises(ValueError):
        score.penalty_units({"violation": -1})


def test_score_never_goes_negative():
    evaluation = score.evaluate(metrics=score.Metrics(success_rate=100), penalties={"violation": 5})
    assert evaluation.score == 0
    assert "penalty_cap_reached" in evaluation.reasons


# --------------------------------------------------------------------------- 系数
def test_coefficient_bands_and_step():
    assert score.coefficient_tenths(1000) == 12
    assert score.coefficient_tenths(950) == 12
    assert score.coefficient_tenths(900) == 12
    assert score.coefficient_tenths(899) == 11
    assert score.coefficient_tenths(700) == 10
    assert score.coefficient_tenths(500) == 8
    assert score.coefficient_tenths(0) == 5


def test_coefficients_stay_inside_contract_range():
    for value in range(0, 1001, 37):
        tenths = score.coefficient_tenths(value)
        assert 5 <= tenths <= 12
        assert Decimal(tenths) / Decimal(10) == Decimal(f"{tenths / 10:.1f}")


# --------------------------------------------------------------------------- 等级
def test_eligible_tier_ladder():
    # L2：在线率 ≥950‰ 且累计 COP ≥10000
    assert score.eligible_tier(online_rate=950, cumulative_cop=10_000, quality_tenths=5,
                               days_at_l2=0, days_at_l3=0) == "L2"
    assert score.eligible_tier(online_rate=949, cumulative_cop=10_000, quality_tenths=5,
                               days_at_l2=0, days_at_l3=0) == "L1"
    assert score.eligible_tier(online_rate=950, cumulative_cop=9_999, quality_tenths=5,
                               days_at_l2=0, days_at_l3=0) == "L1"
    # L3：质量系数 ≥1.0 且连续 30 天 L2
    assert score.eligible_tier(online_rate=900, cumulative_cop=10_000, quality_tenths=10,
                               days_at_l2=30, days_at_l3=0) == "L3"
    assert score.eligible_tier(online_rate=900, cumulative_cop=10_000, quality_tenths=10,
                               days_at_l2=29, days_at_l3=0) == "L1"
    # L4：连续 90 天 L3 且在线率 ≥990‰
    assert score.eligible_tier(online_rate=990, cumulative_cop=10_000, quality_tenths=10,
                               days_at_l2=30, days_at_l3=90) == "L4"
    assert score.eligible_tier(online_rate=989, cumulative_cop=10_000, quality_tenths=10,
                               days_at_l2=30, days_at_l3=90) == "L3"


def test_tier_idempotent_when_conditions_hold():
    assert score.next_tier("L3", "L3") == "L3"


def test_demotion_is_immediate():
    assert score.next_tier("L4", "L2") == "L2"
    assert score.next_tier("L3", "L1") == "L1"


def test_l5_is_manual_only():
    # 规则永远判不出 L5
    assert score.eligible_tier(online_rate=1000, cumulative_cop=10**9, quality_tenths=12,
                               days_at_l2=999, days_at_l3=999) == "L4"
    # 人工授予后保持 L5；撤销后回到规则等级
    assert score.next_tier("L4", "L4", manual_tier=True) == "L5"
    assert score.next_tier("L5", "L4", manual_tier=False) == "L4"


def test_invalid_tier_rejected():
    with pytest.raises(ValueError):
        score.next_tier("L9", "L1")
    with pytest.raises(ValueError):
        score.next_tier("L1", "L9")


# --------------------------------------------------------------------------- 编排
def test_evaluate_reports_change_and_initial():
    first = score.evaluate(metrics=score.Metrics(900, 900, 960, 900))
    assert first.prev_tier is None and first.changed is True
    assert "initial_assessment" in first.reasons
    assert first.tier == "L1"                    # 累计 COP 不足 10000 → 仍是 L1

    promoted = score.evaluate(metrics=score.Metrics(900, 900, 960, 900), cumulative_cop=20_000,
                              previous_score=900, previous_tier="L1")
    assert promoted.tier == "L2"
    assert "tier_promoted" in promoted.reasons

    demoted = score.evaluate(metrics=score.Metrics(900, 900, 100, 900),
                             previous_score=promoted.score, previous_tier="L2")
    assert demoted.tier == "L1"
    assert "tier_demoted" in demoted.reasons
    assert "online_rate_below_target" in demoted.reasons


def test_evaluate_marks_score_only_change():
    result = score.evaluate(metrics=score.Metrics(500, 500, 500, 500),
                            previous_score=100, previous_tier="L1")
    assert "score_changed" in result.reasons
    assert result.changed is True

    same = score.evaluate(metrics=score.Metrics(500, 500, 500, 500),
                          previous_score=result.score, previous_tier="L1")
    assert same.changed is False


def test_reasons_are_human_readable_and_threshold_free():
    """INV-07 / spec ``ReputationProfile.reasons``：原因里**不得出现阈值数字**。"""
    for evaluation in (
            score.evaluate(metrics=score.Metrics(1000, 1000, 1000, 1000), cumulative_cop=10**6,
                           previous_tier="L1"),
            score.evaluate(metrics=score.Metrics(0, 0, 0, 0), previous_tier="L4"),
            score.evaluate(metrics=score.Metrics(100, 100, 100, 100), penalties={"violation": 9})):
        for reason in evaluation.reasons:
            assert not any(char.isdigit() for char in reason), reason
            assert reason.islower() and " " not in reason


def test_policy_version_is_carried():
    evaluation = score.evaluate(metrics=score.Metrics(1, 1, 1, 1))
    assert evaluation.policy_version == facts.DEFAULT_CONFIG.policy_version


def test_no_rate_is_emitted_inv08():
    """INV-08：本模块只输出等级，不输出费率 / 折扣。"""
    payload = score.evaluate(metrics=score.Metrics(900, 900, 900, 900)).as_dict()
    forbidden = ("rate", "discount", "price", "fee", "bps")
    assert not [key for key in payload if any(word in key for word in forbidden)]
    assert payload["tier"] in facts.TIERS


# --------------------------------------------------------------------------- 配置注入
def test_config_injection_changes_decisions():
    strict = facts.ReputationConfig(l2_online_rate=1000, l2_cumulative_cop=1).validated()
    evaluation = score.evaluate(metrics=score.Metrics(online_rate=990), cumulative_cop=10,
                                config=strict)
    assert evaluation.tier == "L1"               # 990 < 注入的 1000 门槛
    loose = facts.ReputationConfig(l2_online_rate=900, l2_cumulative_cop=1).validated()
    assert score.evaluate(metrics=score.Metrics(online_rate=990), cumulative_cop=10,
                          config=loose).tier == "L2"


def test_config_validation_rejects_bad_weights():
    with pytest.raises(ValueError):
        facts.ReputationConfig(weights={"success_rate": 1, "latency_ok_rate": 1,
                                        "online_rate": 1, "yield_response": 1}).validated()
    with pytest.raises(ValueError):
        facts.ReputationConfig(window_days=3).validated()
    with pytest.raises(ValueError):
        facts.ReputationConfig(invite_bps=2000).validated()
    with pytest.raises(ValueError):
        facts.ReputationConfig(invite_months=36).validated()


def test_accrual_and_invite_rates_come_from_existing_config():
    config = facts.DEFAULT_CONFIG
    # 1 USD（100 minor）× 100 COP/USD / 100 = 100 COP
    assert config.accrual_units(100, 100) == 100
    assert config.accrual_units(0, 100) == 0
    assert config.accrual_units(100, 0) == 0
    # 邀请奖励 = 被邀请人 COP 的 4%（默认 points.invite_bps=400）
    assert config.invite_reward_units(10_000) == 400
    assert config.invite_reward_units(0) == 0
    assert facts.ReputationConfig(invite_bps=1000).validated().invite_reward_units(100) == 10


def test_days_between():
    from datetime import datetime, timedelta, timezone

    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    assert score.days_between(start, start + timedelta(days=30, hours=5)) == 30
    assert score.days_between(start, start - timedelta(days=1)) == 0
    assert score.days_between(None, start) == 0
