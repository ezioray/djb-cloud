# SPDX-License-Identifier: Apache-2.0
"""撮合与取价（INV-01 / INV-02 / §9 验收 ①③）。

先说清楚两件事：

* **验收 ①**：供方 [8.00,10.00] × 用方 [6.00,9.50] → 成交价 ∈ [8.00,9.50]，mid = 8.75；
* **验收 ③**：无交集 → 给价差与三个建议，**不产生 booking**（这里验纯函数，
  落库不产生 booking 由 ``test_booking`` 用「bookings 计数」独立验证）。
"""
from __future__ import annotations

import uuid

import pytest

from app.scheduling import facts, matching, models
from app.scheduling.errors import InvalidArgument


def _quote(node_id: str, low: int, high: int | None) -> models.Quote:
    return models.Quote(id=uuid.uuid4(), node_id=node_id, access="A1", model="m1", unit="token",
                        ask_price_minor=low, price_max_minor=high, currency="USD", ttl_s=600,
                        state="active", quote_version=1, created_at=None, expires_at=None)


def _bid(low: int, high: int | None) -> models.Bid:
    return models.Bid(id=uuid.uuid4(), tenant_id=uuid.uuid4(), model="m1",
                      min_price_minor=low, max_price_minor=high, strategy="mid",
                      currency="USD", state="active", bid_version=1, created_at=None,
                      expires_at=None)


# --------------------------------------------------------------------------- INV-01
@pytest.mark.parametrize("a_lo,a_hi,b_lo,b_hi,expected", [
    (800, 1_000, 600, 950, (800, 950)),        # 部分重叠（验收 ①）
    (800, 1_000, 900, 1_100, (900, 1_000)),    # 反向部分重叠
    (800, 1_000, 700, 1_100, (800, 1_000)),    # 出价完全覆盖报价
    (800, 1_000, 800, 1_000, (800, 1_000)),    # 完全重合
    (800, 1_000, 1_000, 1_000, (1_000, 1_000)),  # 单点相交（a_lo ≤ b_hi ∧ b_lo ≤ a_hi）
])
def test_intersection_of_four_overlap_shapes(a_lo, a_hi, b_lo, b_hi, expected):
    assert matching.intersection(a_lo, a_hi, b_lo, b_hi) == expected


@pytest.mark.parametrize("a_lo,a_hi,b_lo,b_hi", [
    (800, 900, 950, 1_000),      # 出价整体高于报价
    (800, 900, 600, 700),        # 出价整体低于报价
])
def test_intersection_empty(a_lo, a_hi, b_lo, b_hi):
    assert matching.intersection(a_lo, a_hi, b_lo, b_hi) is None
    assert matching.matched(a_lo, a_hi, b_lo, b_hi) is False


def test_intersection_single_sided_upper_bounds():
    """上界缺省 = +∞：成交上界取另一侧（INV-01 单边退化）。"""
    assert matching.intersection(800, None, 600, 950) == (800, 950)
    assert matching.intersection(800, 1_000, 600, None) == (800, 1_000)
    assert matching.intersection(800, None, 600, None) == (800, None)
    assert matching.intersection(1_200, None, 600, 1_100) is None


def test_intersection_rejects_inverted_ranges():
    with pytest.raises(InvalidArgument):
        matching.intersection(1_000, 800, 0, None)
    with pytest.raises(InvalidArgument):
        matching.intersection(800, 1_000, 950, 600)
    with pytest.raises(InvalidArgument):
        matching.intersection(-1, 1_000, 0, None)


# --------------------------------------------------------------------------- INV-02
def test_mid_price_matches_acceptance_scenario():
    """验收 ①：mid(800, 950) = 875 = 8.75 元。"""
    assert matching.take_price("mid", 800, 950) == 875


@pytest.mark.parametrize("strategy,low,high,expected", [
    ("mid", 800, 950, 875),
    ("floor", 800, 950, 800),
    ("ceiling", 800, 950, 950),
    ("mid", 800, 801, 800),          # 向下取整，仍在 [lo, hi] 内
    ("mid", 800, None, 800),         # 上界缺省 → 退化为下界（无穷区间没有中点）
    ("floor", 800, None, 800),
    ("ceiling", 800, None, 800),
])
def test_take_price_strategies(strategy, low, high, expected):
    assert matching.take_price(strategy, low, high) == expected


def test_take_price_stays_inside_the_intersection():
    for strategy in facts.PRICE_STRATEGIES:
        price = matching.take_price(strategy, 800, 950)
        assert 800 <= price <= 950


def test_take_price_rejects_unknown_strategy():
    with pytest.raises(InvalidArgument):
        matching.take_price("auction", 800, 950)
    with pytest.raises(InvalidArgument):
        matching.take_price("mid", 950, 800)


# --------------------------------------------------------------------------- plan
def test_plan_picks_the_cheapest_then_node_id():
    """确定性撮合：价低优先，同价按 node_id 字典序。"""
    quotes = [_quote("n_bbb", 850, 1_000), _quote("n_aaa", 850, 1_000),
              _quote("n_ccc", 900, 1_000)]
    result = matching.plan(_bid(600, 950), quotes)
    assert isinstance(result, matching.MatchPlan)
    assert result.quote.node_id == "n_aaa"
    assert result.price_minor == 900          # mid(max(850,600), min(1000,950)) = mid(850, 950)


def test_plan_without_bid_uses_request_ceiling():
    quotes = [_quote("n_aaa", 800, 1_000)]
    result = matching.plan(None, quotes, request_max_minor=900)
    assert isinstance(result, matching.MatchPlan)
    assert result.price_minor == 850          # mid(800, 900)


def test_plan_returns_no_match_with_gap_and_three_suggestions():
    """验收 ③：无交集 → 价差 + 三个建议 + 价格带，不产生成交。"""
    quotes = [_quote("n_aaa", 800, 1_000)]
    result = matching.plan(_bid(600, 700), quotes)
    assert isinstance(result, matching.NoMatch)
    payload = result.as_dict()
    assert payload["reason"] == "no_intersection"
    assert payload["gap_minor"] == 100        # 800 - 700
    assert len(payload["suggestions"]) == 3
    assert payload["band_minor"] == [800, 1_000]


def test_plan_no_match_when_floor_above_supply():
    quotes = [_quote("n_aaa", 800, 900)]
    result = matching.plan(_bid(950, 1_000), quotes)
    assert isinstance(result, matching.NoMatch)
    assert result.gap_minor == 50             # 950 - 900


def test_plan_skips_other_units():
    quotes = [_quote("n_aaa", 800, 1_000)]
    result = matching.plan(_bid(600, 950), quotes, unit="gpu_second")
    assert isinstance(result, matching.NoMatch)


def test_plan_is_deterministic_across_calls():
    bid = _bid(600, 950)
    quotes = [_quote("n_bbb", 850, 1_000), _quote("n_aaa", 850, 1_000)]
    first = matching.plan(bid, quotes)
    second = matching.plan(bid, list(reversed(quotes)))
    assert first.as_dict() == second.as_dict()
    assert first.quote.node_id == "n_aaa"      # 同价按 node_id 字典序


def test_book_summary_counts_and_bands():
    summary = matching.book_summary([_quote("n1", 800, 1_000), _quote("n2", 900, None)])
    assert summary["quote_count"] == 2
    assert summary["min_ask_minor"] == 800
    assert summary["max_ask_minor"] == 900
    assert summary["models"] == ["m1"]
    assert matching.book_summary([])["quote_count"] == 0
