# SPDX-License-Identifier: Apache-2.0
"""P2 打分 / INV-04 tie-break / P3 配额 / P4 抢占（纯函数，不需要 DB）。

这一组是「决策可解释、可复算」的地基：全整数、无浮点、固定顺序。
"""
from __future__ import annotations

import pytest

from app.scheduling import facts, models, preempt, quota, scoring


def _candidate(node_id="n1", *, ask=800, rho=1_000, kappa=1_000, affinity=False,
               rep_missing=False, load_missing=False):
    return models.Candidate(node_id=node_id, access="A1", model="m1", unit="token",
                            ask_price_minor=ask, rho_milli=rho, kappa_milli=kappa,
                            affinity_hit=affinity, rep_missing=rep_missing,
                            load_missing=load_missing)


# --------------------------------------------------------------------------- λ
def test_lambda_per_channel_and_multiplier():
    assert scoring.lambda_micro("realtime") == 1_000_000
    assert scoring.lambda_micro("batch") == 2_500_000
    assert scoring.lambda_micro("fabric") == 4_000_000
    # 全局倍率（routing.latency_lambda）
    assert scoring.lambda_micro("realtime", 2_000) == 2_000_000
    assert scoring.lambda_micro("realtime", 500) == 500_000


def test_lambda_rejects_unknown_channel():
    with pytest.raises(ValueError):
        scoring.lambda_micro("slow")


# --------------------------------------------------------------------------- 公式
def test_effective_cost_formula():
    """cost = 报价 ÷ ρ ÷ κ + λ，全整数（微分）。"""
    # 800 分 / (1.0 × 1.0) + 1 分 = 801 分 = 801_000_000 微分
    assert scoring.effective_cost_micro(800, 1_000, 1_000, 1_000_000) == 801_000_000
    # 800 / (1.2 × 1.0) = 666.66… 分（整除）→ 666_666_666 + 1_000_000
    assert scoring.effective_cost_micro(800, 1_200, 1_000, 1_000_000) == 667_666_666
    # κ 惩罚：κ = 2.0 让成本减半
    assert scoring.effective_cost_micro(800, 1_000, 2_000, 0) == 400_000_000


def test_effective_cost_is_pure_and_clamps_coefficients():
    """ρ / κ 越界会被夹取到 §8.2 区间，而不是放大成本。"""
    assert scoring.effective_cost_micro(800, 100, 1_000, 0) == \
        scoring.effective_cost_micro(800, facts.RHO_MIN_MILLI, 1_000, 0)
    assert scoring.effective_cost_micro(800, 1_000, 99_000, 0) == \
        scoring.effective_cost_micro(800, 1_000, facts.KAPPA_MAX_MILLI, 0)


def test_effective_cost_rejects_negative_price():
    with pytest.raises(ValueError):
        scoring.effective_cost_micro(-1, 1_000, 1_000, 0)


def test_score_all_keeps_missing_flags_visible():
    scores = scoring.score_all([_candidate("n1", rep_missing=True, load_missing=True)],
                               tier="realtime")
    assert scores[0].rep_missing is True and scores[0].load_missing is True
    assert set(scores[0].as_breakdown()) >= {"node_id", "ask_price_minor", "rho_milli",
                                             "kappa_milli", "lambda_micro", "cost_micro",
                                             "rep_missing", "load_missing"}


# --------------------------------------------------------------------------- tie-break
def test_argmin_prefers_lower_cost():
    scores = scoring.score_all([_candidate("n1", ask=800), _candidate("n2", ask=700)],
                               tier="realtime")
    selection = scoring.select(scores)
    assert selection.winner.node_id == "n2"
    assert selection.tie_break == "cost"


def test_tie_break_prefers_affinity_hit():
    """INV-04 ①：内网亲和命中优先。"""
    scores = scoring.score_all([_candidate("n1", ask=800),
                               _candidate("n2", ask=805, affinity=True)], tier="realtime")
    selection = scoring.select(scores)
    assert selection.tie_break == "affinity"
    assert selection.winner.node_id == "n2"


def test_tie_break_prefers_higher_rho():
    """INV-04 ②：ρ 更高优先（构造成本完全相等的两个候选：960×(1.0/1.2) = 800）。"""
    scores = scoring.score_all([_candidate("n1", ask=800, rho=1_000),
                                _candidate("n2", ask=960, rho=1_200)], tier="realtime")
    assert scores[0].cost_micro == scores[1].cost_micro      # 同分前提成立
    selection = scoring.select(scores)
    assert selection.tie_break == "rho"
    assert selection.winner.node_id == "n2"


def test_tie_break_falls_back_to_node_id():
    """INV-04 ③：node_id 字典序（且规则里没有平台收入因子）。"""
    scores = scoring.score_all([_candidate("n_bbb", ask=800),
                               _candidate("n_aaa", ask=800)], tier="realtime")
    selection = scoring.select(scores)
    assert selection.tie_break == "node_id"
    assert selection.winner.node_id == "n_aaa"
    assert "revenue" not in selection.tie_break and "平台收入" not in selection.tie_break


def test_tie_band_is_epsilon_bps():
    """同分带宽：3% 之内视为同分（默认 300 bps）。"""
    # 成本差 < 3% → 同分，按 node_id
    scores = scoring.score_all([_candidate("n_aaa", ask=800), _candidate("n_bbb", ask=820)],
                               tier="realtime")
    assert scoring.select(scores, epsilon_bps=300).tied == ("n_aaa", "n_bbb")
    # 关掉带宽 → 不同分，直接按成本
    assert scoring.select(scores, epsilon_bps=0).tie_break == "cost"


def test_select_requires_candidates():
    with pytest.raises(ValueError):
        scoring.select([])


def test_ranked_orders_all_candidates_deterministically():
    scores = scoring.score_all([_candidate("n3", ask=900), _candidate("n1", ask=800),
                                _candidate("n2", ask=800)], tier="realtime")
    order = [item.node_id for item in scoring.ranked(scores)]
    assert order[0] == "n1"
    assert sorted(order) == ["n1", "n2", "n3"]
    assert order == [item.node_id for item in scoring.ranked(list(reversed(scores)))]


# --------------------------------------------------------------------------- P3 并发
def test_concurrency_is_the_minimum_of_three():
    """INV-07：并发 = min(平台下发, 终端上报, 节点 max_qps)。"""
    assert quota.resolve_concurrency(100, 50, 20) == (20, False)
    assert quota.resolve_concurrency(100, 50, 20) == (20, False)
    assert quota.resolve_concurrency(100, 5, 20) == (5, False)
    assert quota.resolve_concurrency(None, 50, 20) == (20, False)
    assert quota.resolve_concurrency(100, None, 20) == (20, False)
    assert quota.resolve_concurrency(100, 50, None) == (50, False)
    assert quota.resolve_concurrency(None, None, None) == (0, False)


def test_terminal_cannot_widen_concurrency():
    """INV-07：终端只能收紧；放宽 → 按平台值夹取 + 告警标记。"""
    effective, widened = quota.resolve_concurrency(10, 50, 20)
    assert widened is True
    assert effective == 10


def test_concurrency_rejects_negative():
    with pytest.raises(ValueError):
        quota.resolve_concurrency(-1, 5, 5)


# --------------------------------------------------------------------------- P3 配额
def test_quota_decision_allows_when_unlimited():
    verdict = quota.decide(snapshot=None, node_max_qps=20, platform_concurrency=100,
                           terminal_concurrency=None, limit_pct=25)
    assert verdict.allowed is True
    assert verdict.reason_codes == ()


def test_quota_decision_blocks_when_remaining_is_zero():
    verdict = quota.decide(snapshot={"remaining": 0}, node_max_qps=20,
                           platform_concurrency=100, terminal_concurrency=None, limit_pct=25)
    assert verdict.allowed is False
    assert "quota_exhausted" in verdict.reason_codes


def test_quota_decision_blocks_when_concurrency_is_zero():
    verdict = quota.decide(snapshot=None, node_max_qps=0, platform_concurrency=None,
                           terminal_concurrency=None, limit_pct=25)
    assert verdict.allowed is False


def test_spend_cap_raises_42902():
    with pytest.raises(Exception) as excinfo:
        quota.decide(snapshot={"daily_spend_minor": 200, "daily_cap_minor": 100},
                     node_max_qps=20, platform_concurrency=None, terminal_concurrency=None,
                     limit_pct=25)
    assert int(excinfo.value.code) == 42902


def test_share_limit_is_25_percent_by_default():
    """INV-08：单租户同模型并发占比 ≤25%（2500 bps）。"""
    assert quota.share_exceeded(2_500, 25) is False
    assert quota.share_exceeded(2_501, 25) is True
    assert quota.share_exceeded(None, 25) is False
    verdict = quota.decide(snapshot={"share_pct_bps": 3_000}, node_max_qps=20,
                           platform_concurrency=None, terminal_concurrency=None, limit_pct=25)
    assert verdict.share_exceeded is True
    assert "share_exceeded" in verdict.reason_codes
    assert verdict.allowed is True                     # 超限只降权，不淘汰


def test_widening_is_visible_in_the_verdict():
    verdict = quota.decide(snapshot=None, node_max_qps=20, platform_concurrency=10,
                           terminal_concurrency=50, limit_pct=25)
    assert verdict.widening_rejected is True
    assert "tenant_widened" in verdict.reason_codes


# --------------------------------------------------------------------------- P3 窗口
def test_window_starts():
    from datetime import datetime, timezone

    moment = datetime(2026, 10, 23, 15, 30, tzinfo=timezone.utc)   # 周五
    assert quota.window_start(moment, "day") == datetime(2026, 10, 23, tzinfo=timezone.utc)
    assert quota.window_start(moment, "week") == datetime(2026, 10, 19, tzinfo=timezone.utc)
    assert quota.window_start(moment, "month") == datetime(2026, 10, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        quota.window_start(moment, "hour")


# --------------------------------------------------------------------------- P4 抢占
def test_preemption_requires_real_time_tier():
    """INV-09：只允许 realtime 抢 batch，batch 互不抢占。"""
    outcome = preempt.evaluate(tier="batch", checkpoint_age_s=10, victims=[
        {"node_id": "n1", "request_id": "r1", "tier": "batch", "checkpoint_age_s": 5}],
        preempt_enabled=True)
    assert outcome.outcome == "queued"
    assert outcome.plan == ()
    assert outcome.eta_seconds is not None             # 排队必给 ETA


def test_batch_without_checkpoint_is_rejected():
    """INV-09：无可用检查点禁止入组网队列。"""
    assert preempt.evaluate(tier="batch").outcome == "rejected"
    assert preempt.evaluate(tier="batch").reason_codes == ("no_checkpoint",)
    assert preempt.evaluate(tier="batch", checkpoint_age_s=31).outcome == "rejected"


def test_realtime_rejects_when_preemption_disabled():
    outcome = preempt.evaluate(tier="realtime")
    assert outcome.outcome == "rejected"
    assert outcome.reason_codes == ("preempt_disabled",)


def test_realtime_preempts_batch_with_checkpoint():
    outcome = preempt.evaluate(
        tier="realtime", preempt_enabled=True,
        victims=[{"node_id": "n1", "request_id": "r2", "tier": "batch",
                  "checkpoint_age_s": 10, "started_at": "2026-10-23T00:00:02"},
                 {"node_id": "n1", "request_id": "r1", "tier": "batch",
                  "checkpoint_age_s": 12, "started_at": "2026-10-23T00:00:01"}])
    assert outcome.outcome == "preempt"
    assert [item["request_id"] for item in outcome.plan] == ["r1"]     # 等待最久优先
    assert outcome.eta_seconds == facts.PREEMPT_GRACEFUL_S


def test_preempt_budget_is_respected():
    """INV-10：每节点每小时 ≤6 次。"""
    outcome = preempt.evaluate(tier="realtime", preempt_enabled=True, budget_used=6,
                              victims=[{"node_id": "n1", "request_id": "r1", "tier": "batch",
                                        "checkpoint_age_s": 5}])
    assert outcome.outcome == "rejected"
    assert outcome.reason_codes == ("preempt_budget_exhausted",)
    assert preempt.budget_exhausted(6) is True
    assert preempt.budget_exhausted(5) is False


def test_queue_watermark_95_keeps_only_realtime():
    """§8.2：队列水位 95% → 只保实时。"""
    assert preempt.evaluate(tier="batch", checkpoint_age_s=5,
                            queue_level_pct=96).reason_codes == ("queue_full",)
    assert preempt.evaluate(tier="realtime", preempt_enabled=True,
                            queue_level_pct=96).outcome == "rejected"
    tight = preempt.evaluate(tier="batch", checkpoint_age_s=5, queue_level_pct=86)
    assert tight.reason_codes == ("queue_tight",)


def test_pick_victims_filters_and_sorts():
    victims = [
        {"node_id": "n1", "request_id": "r3", "tier": "batch", "checkpoint_age_s": None},
        {"node_id": "n1", "request_id": "r4", "tier": "realtime", "checkpoint_age_s": 5},
        {"node_id": "n1", "request_id": "r1", "tier": "batch", "checkpoint_age_s": 5,
         "started_at": "2026-10-23T00:00:01"},
        {"node_id": "n1", "request_id": "r2", "tier": "batch", "checkpoint_age_s": 5,
         "started_at": "2026-10-23T00:00:00"},
    ]
    picked = preempt.pick_victims(victims, limit=2)
    assert [item["request_id"] for item in picked] == ["r2", "r1"]


def test_checkpoint_usable_window():
    assert preempt.checkpoint_usable(0) is True
    assert preempt.checkpoint_usable(facts.PREEMPT_GRACEFUL_S) is True
    assert preempt.checkpoint_usable(facts.PREEMPT_GRACEFUL_S + 1) is False
    assert preempt.checkpoint_usable(None) is False
    assert preempt.checkpoint_usable(-1) is False
