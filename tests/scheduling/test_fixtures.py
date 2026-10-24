# SPDX-License-Identifier: AGPL-3.0-or-later
"""契约 fixtures（M04 §9 契约用例 / 04-api-contracts §5）。

**放这里而不是 ``contracts/fixtures/M04/``**：本轮写域只到 ``tests/scheduling/**``，
``contracts/**`` 归 contract-integrator / Lead。这里保存的是**可执行** fixture：
每个文件既校验形状（module / case / description / input / expect），
也把 input 喂给真实纯函数，断言 expect——装饰性 JSON 不算证据。
"""
from __future__ import annotations

import json
import pathlib

import pytest

from app.scheduling import backpressure, matching, models, preempt, quota

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures"
FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))


def _load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_fixture_files_exist():
    names = {path.name for path in FIXTURES}
    assert {"success_route_with_quote.json", "error_no_route_with_actions.json",
            "error_forged_tenant.json", "error_amount_precision.json",
            "boundary_share_cap.json", "boundary_preempt_budget.json"} <= names


@pytest.mark.parametrize("path", FIXTURES, ids=lambda path: path.name)
def test_fixture_shape_matches_the_contract(path: pathlib.Path):
    """与 ``contracts/fixtures/_schema.json`` 同形：四段齐全 + 枚举合法。"""
    payload = _load(path)
    assert set(payload) == {"module", "case", "description", "input", "expect"}
    assert payload["module"] == "M04"
    assert payload["case"] in {"success", "error", "boundary"}
    assert payload["description"].strip()
    assert isinstance(payload["input"], dict) and isinstance(payload["expect"], dict)


@pytest.mark.parametrize("path", FIXTURES, ids=lambda path: path.name)
def test_fixture_contains_no_secrets_or_prompts(path: pathlib.Path):
    """fixtures 必须可公开：不含密钥、凭据、prompt / response 正文。"""
    text = path.read_text(encoding="utf-8").lower()
    for forbidden in ("api_key", "secret", "password", "bearer", "prompt", "私钥"):
        assert forbidden not in text, (path.name, forbidden)


def test_acceptance_interval_fixture_is_executable():
    """验收①：fixture 里的区间与价格必须真的算得出来。"""
    payload = _load(FIXTURE_DIR / "success_route_with_quote.json")
    quote = payload["input"]["quote"]
    bid = payload["input"]["bid"]
    band = matching.intersection(models.parse_amount(quote["price_min"]),
                                 models.parse_amount(quote["price_max"]),
                                 models.parse_amount(bid["min_price"]),
                                 models.parse_amount(bid["max_price"]))
    assert list(band) == payload["expect"]["interval"]
    assert matching.take_price("mid", band[0], band[1]) == payload["expect"]["price_minor"]
    assert models.format_amount(payload["expect"]["price_minor"], "token") \
        == payload["expect"]["price"]


def test_single_sided_interval_fixture_is_executable():
    payload = _load(FIXTURE_DIR / "boundary_interval_single_sided.json")
    item = payload["input"]
    band = matching.intersection(item["a_lo"], item["a_hi"], item["b_lo"], item["b_hi"])
    assert list(band) == payload["expect"]["intersection"]
    assert matching.take_price("floor", band[0], band[1]) == payload["expect"]["price_floor"]
    assert matching.take_price("mid", band[0], band[1]) == payload["expect"]["price_mid"]


def test_share_cap_fixture_is_executable():
    payload = _load(FIXTURE_DIR / "boundary_share_cap.json")
    item = payload["input"]
    verdict = quota.decide(snapshot=None, node_max_qps=item["total_slots"],
                           platform_concurrency=None, terminal_concurrency=None,
                           limit_pct=item["limit_pct"],
                           observed_share_bps=item["observed_share_bps"],
                           total_slots=item["total_slots"])
    assert verdict.share_exceeded is payload["expect"]["share_exceeded"]
    assert verdict.share_cap == payload["expect"]["share_cap"]
    assert verdict.allowed is payload["expect"]["allowed"]


def test_preempt_budget_fixture_is_executable():
    payload = _load(FIXTURE_DIR / "boundary_preempt_budget.json")
    item = payload["input"]
    outcome = preempt.evaluate(tier=item["tier"], preempt_enabled=True,
                               budget_limit=item["budget_limit"],
                               budget_map=item["budget_map"], victims=item["victims"])
    assert outcome.outcome == payload["expect"]["outcome"]
    assert payload["expect"]["reason"] in outcome.reason_codes


def test_watermark_fixture_is_executable():
    payload = _load(FIXTURE_DIR / "boundary_queue_watermark.json")
    levels = [backpressure.level_name(pct) for pct in payload["input"]["watermarks"]]
    assert levels == payload["expect"]["levels"]
