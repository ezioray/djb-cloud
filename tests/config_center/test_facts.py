# SPDX-License-Identifier: AGPL-3.0-or-later
"""facts 读取层测试：形状、解析、失败即报错、与 yaml 交叉验证（防静默读空）。

对照 M06 的同名测试：这里额外覆盖「owner 不唯一」（M08 同时是 §1 与 §2 的 owner）与
「两段同一组事实」（§9 points.transfer_* 与 §12 转让限额）两种真实形状。
"""
from __future__ import annotations

from decimal import Decimal

import pytest

yaml = pytest.importorskip("yaml")

from app.config_center import facts


def test_parse_matches_yaml_safe_load():
    """最小解析器与 yaml.safe_load 的 section/facts 逐项一致（形状换了两边一起红）。"""
    doc = facts.parse(facts.facts_path().read_text(encoding="utf-8"))
    reference = yaml.safe_load(facts.facts_path().read_text(encoding="utf-8"))

    assert [sec["id"] for sec in doc["sections"]] == [sec["id"] for sec in reference["sections"]]
    for parsed, raw in zip(doc["sections"], reference["sections"]):
        assert parsed["title"] == raw["title"]
        assert parsed["owner"] == raw["owner"]
        assert [(f["key"], f["value"]) for f in parsed["facts"]] == [
            (f["key"], f["value"]) for f in raw["facts"]]
    assert doc["top"]["generated_from"] == reference["generated_from"]


def test_sections_and_owner_collision():
    """owner 不唯一：M08 在 §1 与 §2 两段；按 owner 合并后两段的事实都在。"""
    m08 = facts.section_facts("M08")
    assert m08["一期链"] == "Polygon PoS"          # §1
    assert "单钱包 cap" in m08                      # §2
    assert facts.section("M08")["id"] == 1          # 文档化：默认返回第一段
    assert facts.section("M08", section_id=2)["id"] == 2
    with pytest.raises(facts.FactsError):
        facts.section("M08", section_id=99)


def test_missing_owner_and_fact_raise():
    with pytest.raises(facts.FactsError):
        facts.section("M99")
    with pytest.raises(facts.FactsError):
        facts.fact("不存在的键", "M10")


def test_cooldowns_parse():
    assert facts.cooldowns() == {"P0": 86400, "P1": 3600, "P2": 0}


def test_publish_window_parse():
    window = facts.publish_window()
    assert window.start == "10:00" and window.end == "17:00"
    assert window.timezone == "+08:00"
    assert window.weekdays == (1, 2, 3, 4, 5)
    assert window.as_default() == {"start": "10:00", "end": "17:00",
                                   "timezone": "+08:00", "weekdays": [1, 2, 3, 4, 5]}


def test_rollback_gray_drift():
    assert facts.p0_rollback_modes() == ("manual",)
    assert facts.gray_steps() == (1, 5, 25, 100)
    assert "每日扫描" in facts.drift_scan_policy()


def test_gas_defaults():
    gas = facts.gas_defaults()
    assert gas == {"mode": "INTERNAL", "bearer": "PLATFORM", "scope": "global",
                   "channel_fee_bps": 0}


def test_points_defaults_and_cross_section_consistency():
    points = facts.points_defaults()
    assert points == {
        "transfer_enabled": False,
        "transfer_per_tx_cap": 1000,
        "transfer_daily_out_cap": 10000,
        "transfer_daily_in_cap": 10000,
        "transfer_lock_days": 7,
        "redeem_rate_bps": 10000,
    }
    # §12 与 §9 是同一组事实的两处表述：任何一处改了另一处没改 → 红
    limits = facts.transfer_limits()
    assert limits["per_tx_cap"] == points["transfer_per_tx_cap"]
    assert limits["daily_out_cap"] == points["transfer_daily_out_cap"]
    assert limits["daily_in_cap"] == points["transfer_daily_in_cap"]
    assert limits["lock_days"] == points["transfer_lock_days"]


def test_fee_share_pool_and_wallet_cap():
    assert facts.platform_fee_default_bps() == 1500
    assert facts.platform_fee_range_bps() == (0, 10000, 3000)
    assert facts.share_defaults_bps() == (1500, 8500, 10000)
    assert facts.reserved_pool() == {"default": 30, "min": 10, "max": 50, "public_floor": 50}
    assert facts.slow_task_discount_pcts() == (40, 50)
    assert facts.wallet_cap_usd() == Decimal("10000")


# ─────────────────────────────────────────────── 失败路径（形状坏 → 明确报错）
def _write(tmp_path, text: str):
    path = tmp_path / "facts.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _with_facts(monkeypatch, path):
    monkeypatch.setenv("DJB_FACTS_FILE", str(path))
    facts._load_cached.cache_clear()


def test_missing_file_raises(monkeypatch, tmp_path):
    _with_facts(monkeypatch, tmp_path / "nope.yaml")
    with pytest.raises(facts.FactsError):
        facts.load()


def test_empty_sections_raise(monkeypatch, tmp_path):
    _with_facts(monkeypatch, _write(tmp_path, "version: 1\nsections: []\n"))
    with pytest.raises(facts.FactsError):
        facts.load()


def test_bad_cooldown_shape_raises(monkeypatch, tmp_path):
    text = facts.DEFAULT_FACTS_PATH.read_text(encoding="utf-8").replace(
        "value: P0 24h / P1 60min / P2 无", "value: P0 24h / 一小时 / 无")
    _with_facts(monkeypatch, _write(tmp_path, text))
    with pytest.raises(facts.FactsError):
        facts.cooldowns()


def test_bad_gray_steps_raise(monkeypatch, tmp_path):
    text = facts.DEFAULT_FACTS_PATH.read_text(encoding="utf-8").replace(
        "value: S2–S3；1% → 5% → 25% → 100%，每步观测窗",
        "value: S2–S3；1% → 5% → 25% → 90%，每步观测窗")
    _with_facts(monkeypatch, _write(tmp_path, text))
    with pytest.raises(facts.FactsError):
        facts.gray_steps()


def test_bad_publish_window_raises(monkeypatch, tmp_path):
    text = facts.DEFAULT_FACTS_PATH.read_text(encoding="utf-8").replace(
        "value: 工作日 10:00–17:00（UTC+8）", "value: 每天 17:00–10:00（UTC+8）")
    _with_facts(monkeypatch, _write(tmp_path, text))
    with pytest.raises(facts.FactsError):
        facts.publish_window()


def test_auto_rollback_would_be_detected(monkeypatch, tmp_path):
    """产品若放开自动回滚，本模块必须红（P0 只允许人工是硬约束）。"""
    text = facts.DEFAULT_FACTS_PATH.read_text(encoding="utf-8").replace(
        "value: 只允许人工", "value: 允许自动")
    _with_facts(monkeypatch, _write(tmp_path, text))
    with pytest.raises(facts.FactsError):
        facts.p0_rollback_modes()
