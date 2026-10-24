# SPDX-License-Identifier: AGPL-3.0-or-later
"""金额 / ID / 归一化（INV-13 / 00-conventions §2–§3）。

全部纯函数，不需要 DB：这里是「超精度直接拒绝」「不出现浮点」两道闸的守门用例。
"""
from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from app.scheduling import facts, models
from app.scheduling.errors import AmountPrecisionRejected, IntervalInvalid, InvalidArgument


# --------------------------------------------------------------------------- uuid7
def test_uuid7_is_time_ordered_and_rfc_compliant():
    earlier = models.uuid7(1_700_000_000_000_000)
    later = models.uuid7(1_700_000_001_000_000)
    assert earlier.version == 7
    assert earlier.variant == uuid.RFC_4122
    assert earlier < later                                  # 时间有序（00-conventions §2）
    assert models.uuid7().version == 7


def test_uuid7_embeds_millisecond_timestamp():
    now_us = 1_700_000_123_456_000                          # 1_700_000_123.456 s
    value = models.uuid7(now_us)
    assert value.int >> 80 == 1_700_000_123_456          # 毫秒时间戳进高 48 bit


# --------------------------------------------------------------------------- 金额
@pytest.mark.parametrize("value,expected", [
    ({"amount": "8.75", "unit": "token"}, 875),
    ({"amount": "0", "unit": "token"}, 0),
    ({"amount": "10.00", "unit": "token"}, 1_000),
    ("6.5", 650),
    (900, 900),
    (Decimal("1.23"), 123),
])
def test_parse_amount_accepts_spec_shapes(value, expected):
    assert models.parse_amount(value) == expected


@pytest.mark.parametrize("value", ["8.005", "0.001", "1.2345"])
def test_over_precision_is_rejected_not_rounded(value):
    """INV-13：超精度直接拒绝，不四舍五入。"""
    with pytest.raises(AmountPrecisionRejected) as excinfo:
        models.parse_amount(value, field_name="price_min")
    assert excinfo.value.reason == "amount_precision"
    assert excinfo.value.code == "40001"


@pytest.mark.parametrize("value", ["-1.00", -1])
def test_negative_amount_is_rejected(value):
    with pytest.raises(InvalidArgument):
        models.parse_amount(value)


def test_float_is_rejected():
    """不接受 float：客户端必须传十进制字符串（否则会引入二进制误差）。"""
    with pytest.raises(InvalidArgument) as excinfo:
        models.parse_amount(8.75)
    assert "浮点" in excinfo.value.message


@pytest.mark.parametrize("value", ["abc", "", "1,5", {"unit": "token"}, None, True])
def test_malformed_amount_is_rejected(value):
    with pytest.raises(InvalidArgument):
        models.parse_amount(value)


def test_amount_over_cap_is_rejected():
    with pytest.raises(InvalidArgument) as excinfo:
        models.parse_amount(facts.MAX_PRICE_MINOR + 1)
    assert excinfo.value.details["max_minor"] == facts.MAX_PRICE_MINOR


def test_format_amount_round_trips():
    assert models.format_amount(875, "token") == {"amount": "8.75", "unit": "token"}
    assert models.format_amount(0, "token") == {"amount": "0.00", "unit": "token"}
    assert models.format_amount(1_000, "token") == {"amount": "10.00", "unit": "token"}
    assert models.parse_amount(models.format_amount(8_123, "token")) == 8_123


def test_price_pair_rejects_inverted_interval():
    with pytest.raises(IntervalInvalid) as excinfo:
        models.parse_price_pair({"price_min": "10.00", "price_max": "9.00"},
                                low_key="price_min", high_key="price_max")
    assert excinfo.value.reason == "interval_invalid"


def test_price_pair_supports_single_sided_intervals():
    """INV-01 单边退化：未设端取 0 / +∞。"""
    assert models.parse_price_pair({}, low_key="price_min", high_key="price_max") == (0, None)
    assert models.parse_price_pair({"price_min": "8.00"}, low_key="price_min",
                                   high_key="price_max") == (800, None)
    assert models.parse_price_pair({"price_max": "9.00"}, low_key="price_min",
                                   high_key="price_max") == (0, 900)


def test_currency_is_usd_only():
    assert models.check_currency({}) == "USD"
    assert models.check_currency({"currency": "usd"}) == "USD"
    with pytest.raises(Exception) as excinfo:
        models.check_currency({"currency": "USDT"})
    assert excinfo.value.reason == "unsupported_currency"


# --------------------------------------------------------------------------- 归一化
@pytest.mark.parametrize("raw,expected", [
    ("  Qwen   Max  ", "qwen max"),
    ("GPT-4O", "gpt-4o"),
    ("m1", "m1"),
])
def test_normalize_model(raw, expected):
    """M04 §6 F1：能力匹配用归一后的 slug 比较。"""
    assert models.normalize_model(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", None, 123, "x" * 201])
def test_normalize_model_rejects_bad_input(raw):
    with pytest.raises(InvalidArgument):
        models.normalize_model(raw)


# --------------------------------------------------------------------------- 聚合
def test_quote_signature_covers_content_only():
    """内容不变不升版本：signature 不含状态 / 版本 / 时间。"""
    quote = models.Quote(id=uuid.uuid4(), node_id="n1", access="A1", model="m1", unit="token",
                         ask_price_minor=800, price_max_minor=1_000, currency="USD", ttl_s=600,
                         state="active", quote_version=1, created_at=None, expires_at=None)
    other = models.Quote(id=uuid.uuid4(), node_id="n1", access="A1", model="m1", unit="token",
                         ask_price_minor=800, price_max_minor=1_000, currency="USD", ttl_s=600,
                         state="consumed", quote_version=7, created_at=None, expires_at=None)
    assert quote.signature() == other.signature()
    changed = models.Quote(id=uuid.uuid4(), node_id="n1", access="A1", model="m1", unit="token",
                           ask_price_minor=801, price_max_minor=1_000, currency="USD", ttl_s=600,
                           state="active", quote_version=1, created_at=None, expires_at=None)
    assert changed.signature() != quote.signature()


def test_quote_interval_helpers():
    quote = models.Quote(id=uuid.uuid4(), node_id="n1", access="A1", model="m1", unit="token",
                         ask_price_minor=800, price_max_minor=None, currency="USD", ttl_s=60,
                         state="active", quote_version=1, created_at=None, expires_at=None)
    assert quote.a_lo == 800 and quote.a_hi is None
    assert quote.quote_id == str(quote.id)


def test_candidate_round_trips_through_input_snapshot():
    """决策日志里的候选快照必须能无损还原（复算回放的前提）。"""
    candidate = models.Candidate(node_id="n1", access="A1", model="m1", unit="token",
                                 ask_price_minor=800, price_max_minor=1_000, max_qps=20,
                                 region="cn-east", rho_milli=1_100, kappa_milli=1_200,
                                 affinity_hit=True, quote_id=str(uuid.uuid4()),
                                 quote_version=3)
    restored = models.Candidate.from_input(candidate.as_input())
    assert restored == candidate
    assert restored.as_input() == candidate.as_input()


def test_decision_as_dict_matches_spec_shape():
    decision = models.Decision(
        decision_id=uuid.uuid4(), trace_id="trace-1", attempt_no=1,
        snapshot_ts=__import__("datetime").datetime(2026, 10, 23, tzinfo=__import__("datetime").timezone.utc),
        quote_version=3, policy_version="000000000000", request_digest="a" * 64,
        chosen={"node_id": "n1", "upstream_id": "", "access": "A1", "model": "m1",
                "unit": "token"},
        price_minor=875, outcome="routed", tie_break="cost", eta_seconds=None,
        reason_codes=["rep_missing"])
    payload = decision.as_dict()
    # spec RouteDecision 必填
    for key in ("decision_id", "chosen", "quote_version", "decided_at"):
        assert key in payload
    assert payload["price"] == {"amount": "8.75", "unit": "token"}
    assert payload["chosen"]["node_id"] == "n1"
