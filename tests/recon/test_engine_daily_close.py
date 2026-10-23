# SPDX-License-Identifier: Apache-2.0
"""scope=daily_close 对账引擎：M06 试算平衡 + 科目余额漂移（按单位各一条 run）。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.recon import facts
from reconkit import (FIXED_NOW, daily_close_spec, fetch_exceptions, post_journal,
                      simple_journal_lines, snapshot_balances)

ENTRY_TIMEOUT = 5


def _run(conn, spec=None, *, now=FIXED_NOW):
    from app.recon import engine

    return engine.run(conn, spec or daily_close_spec(), now=now)


def test_balanced_ledger_produces_matched_run(conn) -> None:
    post_journal(conn, simple_journal_lines(250_000), ts=FIXED_NOW - timedelta(hours=2))
    results = _run(conn)
    assert len(results) == 1
    run = results[0]["run"]
    assert run["subject_ref"] == "USD"
    assert run["book_minor"] == 250_000        # Σ借
    assert run["external_minor"] == 250_000    # Σ贷
    assert run["diff_minor"] == 0
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert results[0]["metrics"]["entry_count"] == 1
    assert fetch_exceptions(conn, str(run["run_id"])) == []


def test_imbalance_is_structural_p0(conn) -> None:
    """借贷不平 → P0（INV-02），且阻断签核。

    故障注入：M06 的平衡校验是 DEFERRABLE 约束触发器，正常写入路径造不出不平的账。
    这里在**测试 schema 内、事务内**临时 DISABLE 该触发器造一条不平凭证，用例结束整体回滚
    （不修改任何迁移文件，也不碰共享 schema 之外的库）。
    """
    conn.execute("ALTER TABLE journal_entry DISABLE TRIGGER journal_entry_balanced")
    post_journal(conn, [dict(coa_code="1101", dc="D", amount_minor=1_000, account_id="coa:1101",
                             qty_minor=1_000, entry_type="consume", fund_class="CLIENT",
                             unit_scale=6, wallet_id=None, reverse_of=None),
                        dict(coa_code="2101", dc="C", amount_minor=1_000, account_id="coa:2101",
                             qty_minor=None, entry_type="consume", fund_class="CLIENT",
                             unit_scale=6, wallet_id=None, reverse_of=None)],
                ts=FIXED_NOW - timedelta(hours=3))
    # 再插一条只有借方行的凭证 → Σ借 ≠ Σ贷（同样是注入）
    with conn.cursor() as cur:
        import uuid

        from reconkit import new_hash

        journal_id = str(uuid.uuid4())
        cur.execute(
            """INSERT INTO journal_entry (journal_id, ts, event_type, unit_type, source_type,
                                          source_id, event_seq, policy_version, hash)
               VALUES (%s,%s,'E6','USD','usage_settle',%s,0,'m09-test',%s)""",
            (journal_id, FIXED_NOW - timedelta(hours=2), f"src-{uuid.uuid4().hex[:8]}",
             new_hash(journal_id)))
        entry_id = str(uuid.uuid4())
        cur.execute(
            """INSERT INTO ledger_entry (entry_id, journal_id, line_no, account_id, entry_type,
                                         unit_type, dc, amount_minor, qty_minor, fund_class)
               VALUES (%s,%s,1,'coa:1102','consume','USD','D',777,777,'CLIENT')""",
            (entry_id, journal_id))
        cur.execute(
            """INSERT INTO journal_line (journal_id, line_no, ledger_entry_id, account_id,
                                         coa_code, dc, amount_minor, unit_scale, qty_minor,
                                         fund_class)
               VALUES (%s,1,%s,'coa:1102','1102','D',777,6,777,'CLIENT')""",
            (journal_id, entry_id))

    results = _run(conn)
    run = results[0]["run"]
    assert run["diff_minor"] == 777                       # 借 − 贷 = 1000 + 777 − 1000
    exceptions = fetch_exceptions(conn, str(run["run_id"]))
    kinds = {item["kind"]: item for item in exceptions}
    assert "trial_imbalance" in kinds
    assert kinds["trial_imbalance"]["severity"] == "P0"
    assert kinds["trial_imbalance"]["diff_minor"] == 777
    assert kinds["trial_imbalance"]["sla_due"] == FIXED_NOW + timedelta(minutes=15)


def test_balance_drift_is_structural_p0(conn) -> None:
    """派生余额缓存与分录不一致（INV-10）→ P0 balance_drift。"""
    post_journal(conn, simple_journal_lines(100_000), ts=FIXED_NOW - timedelta(hours=5))
    snapshot_balances(conn, created_at=FIXED_NOW - timedelta(hours=4))   # 缓存对齐截止时刻
    post_journal(conn, simple_journal_lines(1_000), ts=FIXED_NOW - timedelta(hours=1))
    # 故意不 snapshot → 分录侧比缓存多 1000 → 漂移

    results = _run(conn)
    exceptions = fetch_exceptions(conn, str(results[0]["run"]["run_id"]))
    drift = [item for item in exceptions if item["kind"] == "balance_drift"]
    assert len(drift) == 1
    assert drift[0]["severity"] == "P0"
    assert drift[0]["diff_minor"] == 2_000                 # 两个键各差 1000
    assert results[0]["metrics"]["drift_keys"] == 2
    # 试算仍然平（只开漂移，不误报借贷不平）
    assert [item["kind"] for item in exceptions] == ["balance_drift"]


def test_multiple_units_get_one_run_each(conn) -> None:
    post_journal(conn, simple_journal_lines(1_000), unit_type="USD",
                 ts=FIXED_NOW - timedelta(hours=2))
    post_journal(conn, simple_journal_lines(2_000), unit_type="COP",
                 ts=FIXED_NOW - timedelta(hours=2))
    results = _run(conn)
    assert {result["run"]["subject_ref"] for result in results} == {"USD", "COP"}
    assert all(result["run"]["diff_minor"] == 0 for result in results)
    # 同 scope 不同单位：INV-04 唯一键靠 subject_ref 区分
    assert len({str(result["run"]["run_id"]) for result in results}) == 2


def test_empty_ledger_still_records_a_run(conn) -> None:
    """空账本也留痕（0 差异 matched），不抛错也不造假数据。"""
    results = _run(conn)
    run = results[0]["run"]
    assert run["subject_ref"] == "USD"
    assert run["book_minor"] == 0 and run["external_minor"] == 0
    assert run["status"] == facts.RUN_STATUS_MATCHED


def test_subject_ref_narrows_to_single_unit(conn) -> None:
    post_journal(conn, simple_journal_lines(1_000), unit_type="USD",
                 ts=FIXED_NOW - timedelta(hours=2))
    post_journal(conn, simple_journal_lines(2_000), unit_type="COP",
                 ts=FIXED_NOW - timedelta(hours=2))
    results = _run(conn, daily_close_spec(subject_ref="COP"))
    assert len(results) == 1
    assert results[0]["run"]["subject_ref"] == "COP"
    assert results[0]["run"]["book_minor"] == 2_000


def test_entries_after_cutoff_are_ignored(conn) -> None:
    post_journal(conn, simple_journal_lines(1_000), ts=FIXED_NOW - timedelta(hours=1))
    post_journal(conn, simple_journal_lines(9_000), ts=FIXED_NOW + timedelta(hours=1))
    results = _run(conn)
    assert results[0]["run"]["book_minor"] == 1_000


def test_daily_close_replay_is_idempotent(conn) -> None:
    post_journal(conn, simple_journal_lines(1_000), ts=FIXED_NOW - timedelta(hours=1))
    first = _run(conn)
    second = _run(conn)
    assert second[0]["duplicate"] is True
    assert second[0]["run"]["run_id"] == first[0]["run"]["run_id"]


@pytest.mark.parametrize("field", ["book_minor", "external_minor"])
def test_totals_are_integers(conn, field: str) -> None:
    """金额一律整数最小单位（INV-08）：不返回浮点。"""
    post_journal(conn, simple_journal_lines(1_234), ts=FIXED_NOW - timedelta(hours=1))
    run = _run(conn)[0]["run"]
    assert isinstance(run[field], int)
