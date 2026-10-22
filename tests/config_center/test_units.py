# SPDX-License-Identifier: Apache-2.0
"""单位与量纲校验（§21.3.2）：bps / pct / USD / USD 分 / 秒 / 分 / 时 / 天 / count / clock / window。"""
from __future__ import annotations

import pytest

from app.config_center import units
from app.config_center.errors import RangeViolation, TypeMismatch, UnitViolation


# ─────────────────────────────────────────────── bps（万分之一整数）
def test_bps_accepts_integers_in_range():
    assert units.normalize("bps", 0) == 0
    assert units.normalize("bps", 1500) == 1500
    assert units.normalize("bps", 10000) == 10000


@pytest.mark.parametrize("value", [10001, -1])
def test_bps_rejects_out_of_range(value):
    with pytest.raises(RangeViolation):
        units.normalize("bps", value)


@pytest.mark.parametrize("value", [15.0, "1500", True])
def test_bps_rejects_float_string_bool(value):
    with pytest.raises((UnitViolation, TypeMismatch)):
        units.normalize("bps", value)


# ─────────────────────────────────────────────── pct（0–100，最多 2 位小数）
def test_pct_accepts_int_and_decimal_string():
    assert units.normalize("pct", 30) == 30
    assert units.normalize("pct", "15.5") == "15.5"
    assert units.normalize("pct", "15.50") == "15.50"
    assert units.normalize("pct", 100) == 100


@pytest.mark.parametrize("value", [101, -1, "100.01"])
def test_pct_rejects_out_of_range(value):
    with pytest.raises(RangeViolation):
        units.normalize("pct", value)


@pytest.mark.parametrize("value", [15.5, "15.555", "abc", True])
def test_pct_rejects_float_and_bad_strings(value):
    with pytest.raises((UnitViolation, TypeMismatch)):
        units.normalize("pct", value)


# ─────────────────────────────────────────────── USD（十进制字符串，§21.3.2）
def test_usd_normalizes_decimal_strings():
    assert units.normalize("usd", "10000.00") == "10000.00"
    assert units.normalize("usd", "10000") == "10000.00"
    assert units.normalize("usd", "0") == "0.00"


@pytest.mark.parametrize("value", [10000.0, "1e5", "-1.00", "10.001", "abc", 100])
def test_usd_rejects_float_scientific_negative(value):
    with pytest.raises((UnitViolation, TypeMismatch)):
        units.normalize("usd", value)


# ─────────────────────────────────────────────── USD 分（整数最小单位）
def test_usd_minor_accepts_integer_cents():
    assert units.normalize("usd_minor", 0) == 0
    assert units.normalize("usd_minor", 1_000_000) == 1_000_000


@pytest.mark.parametrize("value", [-1, 1.5, "100", True])
def test_usd_minor_rejects_bad_values(value):
    with pytest.raises((RangeViolation, TypeMismatch, UnitViolation)):
        units.normalize("usd_minor", value)


# ─────────────────────────────────────────────── 时长 / 数量
@pytest.mark.parametrize("unit", ["seconds", "minutes", "hours", "days"])
def test_duration_units_accept_integers(unit):
    assert units.normalize(unit, 0) == 0
    assert units.normalize(unit, 60) == 60
    with pytest.raises((UnitViolation, TypeMismatch)):
        units.normalize(unit, 1.5)


def test_count_rejects_negative():
    assert units.normalize("count", 1000) == 1000
    with pytest.raises(RangeViolation):
        units.normalize("count", -1)


# ─────────────────────────────────────────────── clock / boolean / enum / text / json
def test_clock_shape():
    assert units.normalize("clock", "10:00") == "10:00"
    assert units.normalize("clock", "00:00") == "00:00"
    for bad in ("24:00", "9:00", "10:60", "10:00Z", 1000):
        with pytest.raises(UnitViolation):
            units.normalize("clock", bad)


def test_boolean_is_strict():
    assert units.normalize("boolean", True) is True
    assert units.normalize("boolean", False) is False
    for bad in (0, 1, "true", None):
        with pytest.raises(TypeMismatch):
            units.normalize("boolean", bad)


def test_enum_and_text_require_strings():
    assert units.normalize("enum", "INTERNAL") == "INTERNAL"
    with pytest.raises(TypeMismatch):
        units.normalize("enum", 1)
    with pytest.raises(TypeMismatch):
        units.normalize("text", {"a": 1})


def test_json_requires_object_or_array():
    assert units.normalize("json", [1, 5, 25, 100]) == [1, 5, 25, 100]
    assert units.normalize("json", {"a": 1}) == {"a": 1}
    with pytest.raises(TypeMismatch):
        units.normalize("json", "not-json")


# ─────────────────────────────────────────────── window（发布窗口）
def test_window_valid_and_normalized():
    window = {"start": "10:00", "end": "17:00", "timezone": "+08:00",
              "weekdays": [1, 2, 3, 4, 5]}
    assert units.normalize("window", window) == window


@pytest.mark.parametrize("window", [
    {"start": "17:00", "end": "10:00", "timezone": "+08:00", "weekdays": [1]},   # 起止倒挂
    {"start": "10:00", "end": "17:00", "timezone": "Asia/Shanghai", "weekdays": [1]},
    {"start": "10:00", "end": "17:00", "timezone": "+08:00", "weekdays": []},
    {"start": "10:00", "end": "17:00", "timezone": "+08:00", "weekdays": [1, 1]},
    {"start": "10:00", "end": "17:00", "timezone": "+08:00", "weekdays": [8]},
    {"start": "10:00", "end": "17:00", "timezone": "+08:00", "weekdays": [1], "extra": 1},
    {"start": "10:00", "end": "17:00", "timezone": "+08:00"},                   # 缺字段
    "10:00-17:00",
])
def test_window_rejects_bad_shapes(window):
    with pytest.raises(UnitViolation):
        units.normalize("window", window)


# ─────────────────────────────────────────────── 键级范围叠加
def test_key_level_minimum_maximum_are_applied():
    assert units.normalize("pct", 30, minimum=10, maximum=50) == 30
    with pytest.raises(RangeViolation):
        units.normalize("pct", 9, minimum=10, maximum=50)
    with pytest.raises(RangeViolation):
        units.normalize("pct", 51, minimum=10, maximum=50)
    # 金额按数值比较而不是字符串比较（"9.00" 不能大于 "10000.00"）
    assert units.normalize("usd", "9.00", minimum="0.00", maximum="10000.00") == "9.00"
    with pytest.raises(RangeViolation):
        units.normalize("usd", "10000.01", maximum="10000.00")


def test_multiple_of_and_max_length():
    assert units.normalize("count", 10, multiple_of=5) == 10
    with pytest.raises(RangeViolation):
        units.normalize("count", 11, multiple_of=5)
    assert units.normalize("text", "abc", max_length=3) == "abc"
    with pytest.raises(RangeViolation):
        units.normalize("text", "abcd", max_length=3)
    with pytest.raises(ValueError):
        units.normalize("count", 10, multiple_of=0)


def test_unknown_unit_rejected():
    with pytest.raises(UnitViolation):
        units.normalize("furlongs", 1)


def test_value_type_helpers():
    assert units.json_type(True) == "boolean"
    assert units.json_type(1) == "integer"
    assert units.json_type(1.0) == "number"
    assert units.json_type("x") == "string"
    assert units.json_type({}) == "json"
    assert units.json_type(None) is None
    assert units.value_type_matches("integer", 1) is True
    assert units.value_type_matches("integer", 1.0) is False     # 浮点不算 integer
    assert units.value_type_matches("number", 1.0) is True
    assert units.value_type_matches("json", []) is True
    assert units.value_type_matches("string", 1) is False
