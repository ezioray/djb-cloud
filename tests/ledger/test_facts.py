# SPDX-License-Identifier: Apache-2.0
"""常量来源验收：facts.yaml 读取、最小解析器正确性、与迁移 CHECK 的三方对齐。

验收来源：T2 任务卡第 3 条「常量从 contracts/facts.yaml 读取（不得硬编码）」
          + 「coa_code + fund_class 必须配对」。
"""
from __future__ import annotations

import re

import pytest

from app.ledger import facts
from app.ledger.constants import (
    ALL_COA,
    COA_FUND_CLASS,
    COA_GROUPS,
    COA_NORMAL_DC,
    ENTRY_TYPES,
    EVENT_TYPES,
    JOURNAL_MAX_LINES,
    MERKLE_KINDS_OWNED,
    SOURCE_TYPES,
    UNIT_TYPES,
)

from ledgerkit import connect


# ─────────────────────────────────────────────────────── facts.yaml 读取
def test_facts_file_is_the_w0_qa_machine_source() -> None:
    doc = facts.load()
    assert doc["top"]["version"] == "1"
    assert doc["top"]["generated_from"] == "contracts/03-facts.md"


def test_m06_section_is_present_with_the_facts_we_use() -> None:
    section = facts.section("M06")
    assert section["title"] == "账本"
    reported = facts.section_facts("M06")
    assert {"科目数", "资金事件", "记账单位", "Merkle"} <= set(reported)


def test_minimal_parser_matches_pyyaml() -> None:
    """自研解析器必须与 PyYAML 读出的 M06 段逐项一致（防止事实源换形状后静默读空）。"""
    yaml = pytest.importorskip("yaml")
    reference = yaml.safe_load(facts.facts_path().read_text(encoding="utf-8"))
    expected = next(s for s in reference["sections"] if s["owner"] == "M06")
    parsed = facts.section("M06")
    assert parsed["id"] == expected["id"] and parsed["title"] == expected["title"]
    assert [(f["key"], f["value"]) for f in parsed["facts"]] == \
           [(f["key"], f["value"]) for f in expected["facts"]]


def test_types_are_read_from_facts() -> None:
    assert facts.coa_count() == 42
    assert facts.coa_group_counts() == {"资产": 12, "负债权益": 12, "收入": 6,
                                        "费用损失": 10, "非现金": 2}
    assert EVENT_TYPES == tuple(f"E{i}" for i in range(1, 18))       # E1–E17
    assert set(MERKLE_KINDS_OWNED) <= set(facts.merkle_kinds())
    assert "整数最小单位" in facts.amount_unit()


def test_missing_facts_file_fails_loudly(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DJB_FACTS_FILE", str(tmp_path / "nope.yaml"))
    with pytest.raises(facts.FactsError, match="不存在"):
        facts.load()


def test_malformed_facts_file_fails_loudly(tmp_path, monkeypatch) -> None:
    broken = tmp_path / "facts.yaml"
    broken.write_text("version: 1\nnothing: here\n", encoding="utf-8")
    monkeypatch.setenv("DJB_FACTS_FILE", str(broken))
    with pytest.raises(facts.FactsError, match="section"):
        facts.load()


# ─────────────────────────────────────────────────────── 常量与 facts 对齐
def test_constants_are_aligned_with_facts() -> None:
    assert len(ALL_COA) == len(set(ALL_COA)) == facts.coa_count()
    assert {name: len(codes) for name, codes in COA_GROUPS.items()} == facts.coa_group_counts()
    assert set(COA_NORMAL_DC) == set(ALL_COA) == set(COA_FUND_CLASS)
    assert len(SOURCE_TYPES) == 16 and len(set(SOURCE_TYPES)) == 16
    assert len(ENTRY_TYPES) == 16 and len(set(ENTRY_TYPES)) == 16
    assert JOURNAL_MAX_LINES == 64


# ─────────────────────────────────────────────────────── 与迁移 CHECK 对齐（真库）
def _constraint_defs(schema: str, table: str) -> dict[str, str]:
    with connect(schema) as c, c.cursor() as cur:
        cur.execute(
            """SELECT con.conname, pg_get_constraintdef(con.oid)
                 FROM pg_constraint con
                 JOIN pg_class cl ON cl.oid = con.conrelid
                 JOIN pg_namespace n ON n.oid = cl.relnamespace
                WHERE n.nspname = current_schema() AND cl.relname = %s""", (table,))
        return {name: definition for name, definition in cur.fetchall()}


def test_coa_whitelist_matches_migration_check(migrated: str) -> None:
    ddl = _constraint_defs(migrated, "journal_line")["journal_line_coa_ck"]
    codes = set(re.findall(r"'(\d{4})'", ddl))
    assert codes == set(ALL_COA), codes ^ set(ALL_COA)


def test_fund_class_mapping_matches_migration_check(migrated: str) -> None:
    ddl = _constraint_defs(migrated, "journal_line")["journal_line_coa_fund_class_ck"]
    by_class: dict[str, set[str]] = {}
    for chunk in re.split(r"fund_class = '", ddl)[1:]:
        fund_class = chunk.split("'", 1)[0]
        by_class.setdefault(fund_class, set()).update(re.findall(r"'(\d{4})'", chunk))
    expected: dict[str, set[str]] = {}
    for code, fund_class in COA_FUND_CLASS.items():
        expected.setdefault(fund_class, set()).add(code)
    assert by_class == expected, {k: by_class.get(k, set()) ^ v for k, v in expected.items()}
    # 每个科目只能属于一个 fund_class
    assert sum(len(codes) for codes in by_class.values()) == len(ALL_COA)


def test_enum_whitelists_match_migration_checks(migrated: str) -> None:
    journal_ck = _constraint_defs(migrated, "journal_entry")
    unit_types = set(re.findall(r"'([A-Z_]+)'", journal_ck["journal_entry_unit_type_ck"]))
    assert unit_types == set(UNIT_TYPES)

    source_types = set(re.findall(r"'([a-z_]+)'", journal_ck["journal_entry_source_type_ck"]))
    assert source_types == set(SOURCE_TYPES)

    event_types = set(re.findall(r"'(E\d+)'", journal_ck["journal_entry_event_type_ck"]))
    assert event_types == set(EVENT_TYPES)

    entry_types = set(re.findall(r"'([a-z_]+)'",
                                 _constraint_defs(migrated, "ledger_entry")["ledger_entry_entry_type_ck"]))
    assert entry_types == set(ENTRY_TYPES)


def test_normal_direction_matches_group_convention() -> None:
    """§20.2.1：资产/费用正常在借方，负债权益/收入正常在贷方（6901 借贷皆可）。"""
    for code in COA_GROUPS["资产"] + COA_GROUPS["费用损失"] + ("6101",):
        assert COA_NORMAL_DC[code] == "D", code
    for code in COA_GROUPS["负债权益"] + COA_GROUPS["收入"]:
        assert COA_NORMAL_DC[code] == "C", code
    assert COA_NORMAL_DC["6901"] == "B"


def test_no_business_numbers_in_module_code() -> None:
    """业务数字只在 constants.py / facts.py 出现：其余模块用 AST 检查整数字面量。

    （legacy.py 是 001 旧路径的冻结拷贝，不参与本检查；0/1/2/3 这类结构性小整数放行。）
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "app" / "ledger"
    skip = {"constants.py", "facts.py", "legacy.py"}
    allowed = {0, 1, 2, 3}
    offenders: list[str] = []
    for path in sorted(root.glob("*.py")):
        if path.name in skip:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, int) \
                    and not isinstance(node.value, bool) and node.value not in allowed:
                offenders.append(f"{path.name}:{node.lineno}: {node.value}")
    assert offenders == [], offenders
