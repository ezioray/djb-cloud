# SPDX-License-Identifier: Apache-2.0
"""契约 fixtures 对齐（contracts/fixtures/M10，只读）：键已注册、风险级一致、边界值来自 facts。

fixtures 是契约（只读投影），模块测试用它反查实现：
* success：``billing.gas_fee_mode = INTERNAL`` 能过校验，且该键是 P0；
* error：缺 step-up → 过渡口径 403 + 47009 / 目标口径 424 + 42401（CR-3）；
* boundary：P0 冷却 24h 正好是 facts 里的值（证明边界不是随手写的）。
"""
from __future__ import annotations

import json
import pathlib

import pytest

from app.config_center import facts, registry, validators
from app.config_center.errors import StepUpRequired

FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "contracts" / "fixtures" / "M10"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_fixture_set_covers_three_cases():
    cases = {}
    for path in sorted(FIXTURES.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert doc["module"] == "M10"
        cases[doc["case"]] = doc
    assert set(cases) == {"success", "error", "boundary"}


def test_success_fixture_key_and_value_are_valid():
    doc = load("success_publish_config.json")
    key = doc["input"]["key"]
    item = registry.load().require(key)
    assert item.risk == "P0"
    result = validators.validate_value(key, doc["input"]["value"])
    assert result.value == doc["input"]["value"]
    # 复核人 ≠ 发起人（fixture 里 approver=u2）——INV-03 的输入侧约束
    assert doc["input"]["approver"] != "u1"
    validators.check_publishable(key)


def test_error_fixture_maps_to_step_up_codes():
    doc = load("error_step_up_missing.json")
    key = doc["input"]["key"]
    registry.load().require(key)
    validators.validate_value(key, doc["input"]["value"])      # 值本身合法，失败点是 step-up
    assert doc["expect"] == {"http": 424, "error": "42401"}
    error = StepUpRequired("缺 step-up")
    assert (error.spec_http_status, error.spec_code) == (424, 42401)
    assert (error.http_status, error.code) == (403, 47009)     # CR-3 过渡口径


def test_boundary_fixture_uses_facts_cooldown():
    doc = load("boundary_p0_cooldown_24h.json")
    key = doc["input"]["key"]
    assert registry.load().require(key).risk == "P0"
    cooldown_hours = facts.cooldowns()["P0"] // 3600
    elapsed = doc["input"]["elapsed_hours"]
    assert elapsed == cooldown_hours                             # 24h 来自 facts
    assert doc["expect"]["allowed"] is (elapsed >= cooldown_hours)
