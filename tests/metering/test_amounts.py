# SPDX-License-Identifier: Apache-2.0
"""金额 / 用量 / 单价的整数换算（INV-05 / 00-conventions §3）。不需要 DB。"""
from __future__ import annotations

import pytest

from app.metering import amounts, facts


# ─────────────────────────────────────────────────────── parse_minor
@pytest.mark.parametrize("value,expected", [
    # 整数 = 已是最小单位（分）直传；字符串 = spec Amount 的主单位（USD）
    (1234, 1234), ("1234", 123400), ("12.34", 1234), ("12.3", 1230), ("12", 1200),
    ("0.05", 5), ("0", 0), ("0.5", 50), ("100.00", 10000), ("-0.05", -5),
])
def test_parse_minor_accepts_integer_and_decimal_strings(value, expected):
    allow_negative = str(value).startswith("-")
    assert amounts.parse_minor(value, allow_negative=allow_negative) == expected


@pytest.mark.parametrize("value", ["1.234", "0.001", "-1.005"])
def test_parse_minor_rejects_extra_precision_instead_of_rounding(value):
    with pytest.raises(amounts.AmountError) as exc:
        amounts.parse_minor(value, allow_negative=True)
    assert exc.value.reason == "amount_precision"


@pytest.mark.parametrize("value", [1.25, 0.1 + 0.2, True, None, {"a": 1}, [1]])
def test_parse_minor_rejects_floats_bools_and_non_numbers(value):
    with pytest.raises(amounts.AmountError) as exc:
        amounts.parse_minor(value)
    assert exc.value.reason in {"amount_type", "amount_invalid"}


def test_parse_minor_rejects_negative_unless_allowed():
    with pytest.raises(amounts.AmountError) as exc:
        amounts.parse_minor("-0.01")
    assert exc.value.reason == "amount_negative"


@pytest.mark.parametrize("value", ["", "  ", "1e3", "12,34", "0x10", "--1", "1.", "."])
def test_parse_minor_rejects_malformed_strings(value):
    with pytest.raises(amounts.AmountError):
        amounts.parse_minor(value)


def test_parse_minor_rejects_overlong_string():
    with pytest.raises(amounts.AmountError) as exc:
        amounts.parse_minor("9" * (facts.MAX_AMOUNT_STR_LEN + 1))
    assert exc.value.reason == "amount_invalid"


# ─────────────────────────────────────────────────────── format_minor
@pytest.mark.parametrize("minor,text", [(0, "0.00"), (5, "0.05"), (1234, "12.34"),
                                        (-5, "-0.05"), (-1234, "-12.34"), (100000, "1000.00")])
def test_format_minor_is_exact_decimal(minor, text):
    assert amounts.format_minor(minor) == text


@pytest.mark.parametrize("text", ["0.00", "0.05", "12.34", "1000.00"])
def test_format_then_parse_roundtrips(text):
    assert amounts.format_minor(amounts.parse_minor(text)) == text


def test_format_minor_rejects_non_integer():
    with pytest.raises(amounts.AmountError):
        amounts.format_minor(1.5)                        # type: ignore[arg-type]


# ─────────────────────────────────────────────────────── parse_micro
@pytest.mark.parametrize("value,expected", [
    ("0.0005", 500), ("0.001", 1000), ("1.5", 1_500_000), ("0", 0), (0, 0), (7, 7_000_000),
])
def test_parse_micro_accepts_six_decimals(value, expected):
    assert amounts.parse_micro(value) == expected


@pytest.mark.parametrize("value", ["0.0000005", "1.1234567"])
def test_parse_micro_rejects_seventh_decimal(value):
    with pytest.raises(amounts.AmountError) as exc:
        amounts.parse_micro(value)
    assert exc.value.reason == "amount_precision"


# ─────────────────────────────────────────────────────── parse_quantity
@pytest.mark.parametrize("value,expected", [(0, 0), (1000, 1000), ("1000", 1000),
                                            ("1000.0", 1000), ("1000.000", 1000)])
def test_parse_quantity_accepts_integral_values(value, expected):
    assert amounts.parse_quantity(value) == expected


@pytest.mark.parametrize("value", ["1000.5", "-1", "-1.0", "1e3", "  ", "", True, 1.0])
def test_parse_quantity_rejects_fractional_negative_or_typed(value):
    with pytest.raises(amounts.AmountError):
        amounts.parse_quantity(value)


# ─────────────────────────────────────────────────────── compute_amount_minor（INV-05）
def test_compute_amount_matches_invariant_formula():
    """验收场景②：1000 tokens × 单价 + 500 tokens × 单价 = amount_minor（整数分）。"""
    amount = amounts.compute_amount_minor(tokens_in=1000, tokens_out=500,
                                          in_price_micro=800, out_price_micro=1000)
    # 1000×800 + 500×1000 = 1,300,000 micro-USD = 130 分 = $1.30
    assert amount == 130
    assert amounts.format_minor(amount) == "1.30"


def test_compute_amount_rejects_non_integral_minor():
    """余数非 0 即拒绝（不许四舍五入凑数）。"""
    with pytest.raises(amounts.AmountError) as exc:
        amounts.compute_amount_minor(tokens_in=1, tokens_out=0,
                                     in_price_micro=1, out_price_micro=0)
    assert exc.value.reason == "amount_precision"


@pytest.mark.parametrize("kwargs", [
    {"tokens_in": -1, "tokens_out": 0, "in_price_micro": 100, "out_price_micro": 100},
    {"tokens_in": 1, "tokens_out": 0, "in_price_micro": -100, "out_price_micro": 100},
    {"tokens_in": 1, "tokens_out": 0, "in_price_micro": 1.5, "out_price_micro": 100},
])
def test_compute_amount_rejects_negative_or_non_integer_inputs(kwargs):
    with pytest.raises(amounts.AmountError) as exc:
        amounts.compute_amount_minor(**kwargs)
    assert exc.value.reason == "amount_invalid"


def test_compute_amount_zero_tokens_is_zero():
    assert amounts.compute_amount_minor(tokens_in=0, tokens_out=0,
                                        in_price_micro=999, out_price_micro=999) == 0


# ─────────────────────────────────────────────────────── 其它
def test_is_integral_minor():
    assert amounts.is_integral_minor("1.25") is True
    assert amounts.is_integral_minor("1.255") is False
    assert amounts.is_integral_minor(1.25) is False


def test_micro_per_minor_matches_facts():
    """单价与金额的换算比必须来自 facts（不许在模块里另写一个数）。"""
    assert facts.MICRO_PER_MINOR == 10 ** (facts.PRICE_MICRO_SCALE - facts.MINOR_UNIT_SCALE)
    assert facts.MINOR_PER_MAJOR == 100
