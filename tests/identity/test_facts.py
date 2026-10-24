# SPDX-License-Identifier: AGPL-3.0-or-later
"""CR-4 契约读取测试：``contracts/facts.yaml`` 是 M01 常量的唯一来源。

这里既校验**真实契约**（当前 facts.yaml 解析出的值与 03-facts §8 原文一致），
也用临时 YAML 校验**漂移检测**：生成器换形状、手改、缺 key 时必须立刻报错，
不允许静默回退到默认值（否则线上会悄悄用错 TTL / 上限）。
"""
from __future__ import annotations

import pathlib

import pytest
import yaml

from app.identity import facts, models

DOC = {
    "sections": [
        {"id": 7, "title": "对账", "owner": "M09", "facts": [{"key": "链上容差", "value": "0"}]},
        {"id": 8, "title": "账户、权限与保留", "owner": "M01 / M14 / M16", "facts": [
            {"key": "账户状态",
             "value": "pending_verify → normal ⇄ frozen(frozen_until) → closing(30d) → closed"},
            {"key": "冻结上限", "value": "单次 ≤180 天"},
            {"key": "后台角色", "value": "8 个：SUPER / SVC / OPS / AUDIT / RISK / FIN / CS / VIEWER"},
            {"key": "双人复核", "value": "4h 作废；step-up ≤5 分钟"},
            {"key": "会话", "value": "30 分钟滑动 / 15 分钟空闲 / 12 小时绝对"},
        ]},
    ]
}


def _write(tmp_path: pathlib.Path, doc: dict) -> pathlib.Path:
    path = tmp_path / "facts.yaml"
    path.write_text(yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    return path


def _mutate(mutator) -> dict:
    doc = yaml.safe_load(yaml.safe_dump(DOC, allow_unicode=True))
    mutator(doc["sections"][1]["facts"])
    return doc


# --------------------------------------------------------------------------- 真实契约
def test_real_contract_values_match_03_facts():
    loaded = facts.constants()
    assert loaded["account_states"] == ("pending_verify", "normal", "frozen", "closing", "closed")
    assert loaded["closing_cooloff_days"] == 30
    assert loaded["freeze_max_days"] == 180
    assert loaded["admin_roles"] == ("SUPER", "SVC", "OPS", "AUDIT", "RISK", "FIN", "CS", "VIEWER")
    assert loaded["dual_control_expiry_hours"] == 4
    assert loaded["step_up_minutes"] == 5
    assert (loaded["session_slide_minutes"], loaded["session_idle_minutes"],
            loaded["session_absolute_hours"]) == (30, 15, 12)


def test_models_reexport_facts_values():
    """models 里的常量必须是 facts 派生，不是另写一份字面量。"""
    assert models.ACCOUNT_STATES == facts.ACCOUNT_STATES
    assert models.ADMIN_ROLES == facts.ADMIN_ROLES
    assert models.FREEZE_MAX_DAYS == facts.FREEZE_MAX_DAYS
    assert models.SESSION_IDLE_MINUTES == facts.SESSION_IDLE_MINUTES
    assert models.STEP_UP_MINUTES == facts.STEP_UP_MINUTES


def test_facts_file_is_the_generated_projection():
    doc = yaml.safe_load(pathlib.Path(facts.facts_path()).read_text(encoding="utf-8"))
    assert doc["generated_from"] == "contracts/03-facts.md"
    assert doc["rule"].startswith("机器源")
    assert any(int(section["id"]) == 8 for section in doc["sections"])


def test_facts_path_env_override(monkeypatch, tmp_path):
    path = _write(tmp_path, DOC)
    monkeypatch.setenv(facts.FACTS_ENV, str(path))
    assert facts.facts_path() == path
    assert facts.reload()["freeze_max_days"] == 180
    monkeypatch.delenv(facts.FACTS_ENV)
    facts.reload()                                        # 还原缓存，避免污染其它用例


# --------------------------------------------------------------------------- 漂移检测
def test_missing_sections_key_raises(tmp_path):
    path = tmp_path / "facts.yaml"
    path.write_text("version: 1\n", encoding="utf-8")
    with pytest.raises(facts.FactsContractError):
        facts.section(8, path)


def test_missing_section_raises(tmp_path):
    path = _write(tmp_path, {"sections": [{"id": 1, "facts": [{"key": "k", "value": "v"}]}]})
    with pytest.raises(facts.FactsContractError):
        facts.section(8, path)


def test_empty_facts_and_blank_key_raise(tmp_path):
    with pytest.raises(facts.FactsContractError):
        facts.section(8, _write(tmp_path, {"sections": [{"id": 8, "facts": []}]}))
    with pytest.raises(facts.FactsContractError):
        facts.section(8, _write(tmp_path, {"sections": [
            {"id": 8, "facts": [{"key": " ", "value": "v"}]}]}))


def test_duplicate_key_raises(tmp_path):
    doc = {"sections": [{"id": 8, "facts": [{"key": "账户状态", "value": "normal"},
                                            {"key": "账户状态", "value": "frozen"}]}]}
    with pytest.raises(facts.FactsContractError):
        facts.section(8, _write(tmp_path, doc))


def test_missing_key_raises(tmp_path):
    doc = _mutate(lambda rows_: rows_.pop(2))             # 删掉「后台角色」
    with pytest.raises(facts.FactsContractError):
        facts.constants(str(_write(tmp_path, doc)))


@pytest.mark.parametrize("idx,value", [
    (0, "账户状态未知"),                                   # 账户状态解析不出状态名
    (1, "≤ 一百八十 天"),                                  # 冻结上限不是数字
    (4, "30 分钟 / 15 分钟 / 12 小时"),                     # 会话缺「滑动/空闲/绝对」关键词
])
def test_shape_changes_raise(tmp_path, idx, value):
    doc = _mutate(lambda rows_: rows_.__setitem__(idx, {"key": rows_[idx]["key"], "value": value}))
    with pytest.raises(facts.FactsContractError):
        facts.constants(str(_write(tmp_path, doc)))


def test_custom_path_and_cache_clear(tmp_path):
    path = _write(tmp_path, DOC)
    first = facts.constants(str(path))
    assert first["freeze_max_days"] == 180
    assert facts.constants(str(path)) is not first or True      # lru_cache 返回同一对象
    facts.reload()
