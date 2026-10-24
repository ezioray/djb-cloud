# SPDX-License-Identifier: AGPL-3.0-or-later
"""余额派生一致性（INV-10）与新账本复算 diff=0。

口径（见 migrations/602_account_balances.sql 头注释）：
  balance_minor = Σ借 − Σ贷（借方为正）；
  派生键 = (account_id, unit_type, sub_account)；测试里一个科目一个账户（account_id = coa:<科目码>）。
"""
from __future__ import annotations

from ledgerkit import (
    session,
    assert_db_error,
    connect,
    derive_balances,
    line,
    post_journal,
    run_ok,
    simple_lines,
    snapshot_balances,
    stored_balances,
    write_balances,
)


def _e2_lines(amount: int = 100) -> list[dict]:
    """E2「USDT 收款确认入账」四行：借 1101 + 借 2990 / 贷 1111 + 贷 2101。"""
    return [
        line("1101", "D", amount, qty_minor=amount, entry_type="deposit"),
        line("2990", "D", amount, entry_type="deposit"),
        line("1111", "C", amount, entry_type="deposit"),
        line("2101", "C", amount, entry_type="deposit"),
    ]


def _e6_lines(amount: int = 30) -> list[dict]:
    """E6「计量消耗」两行：借 2101 / 贷 4101（毛额法，全额确认收入）。"""
    return [line("2101", "D", amount, entry_type="consume"),
            line("4101", "C", amount, entry_type="consume")]


def _recompute_new_ledger(schema: str) -> dict:
    """新账本侧的复算：借贷平衡、行数、行↔分录 1:1、余额派生的全局净额必须为 0。"""
    with session(schema) as c, c.cursor() as cur:
        cur.execute(
            """SELECT j.journal_id,
                      count(*) AS lines,
                      COALESCE(sum(l.amount_minor) FILTER (WHERE l.dc = 'D'), 0) AS debit,
                      COALESCE(sum(l.amount_minor) FILTER (WHERE l.dc = 'C'), 0) AS credit,
                      count(DISTINCT l.ledger_entry_id) AS entries
                 FROM journal_entry j JOIN journal_line l ON l.journal_id = j.journal_id
                GROUP BY j.journal_id""")
        rows = cur.fetchall()
        bad = [{"journal_id": str(j), "lines": n, "entries": e, "debit": int(d), "credit": int(cr)}
               for j, n, d, cr, e in rows if n != e or d != cr or n < 2]
        cur.execute(
            """SELECT count(*) FROM journal_entry j
                WHERE NOT EXISTS (SELECT 1 FROM journal_line l WHERE l.journal_id = j.journal_id)""")
        orphans = cur.fetchone()[0]
    return {"journals": len(rows), "bad": bad, "orphan_journals": orphans,
            "diff": len(bad) + orphans}


def test_balances_rebuilt_from_lines_match_snapshots(migrated: str) -> None:
    """INV-10：从分录全量重建的余额与 account_balances 最新快照完全一致（差异 0）。"""
    def _write(c):
        post_journal(c, _e2_lines(100), event_type="E2", source_type="chain_tx", source_id="tx-1")
        post_journal(c, _e6_lines(30), event_type="E6", source_type="usage_settle", source_id="u-1")

    run_ok(migrated, _write)

    with session(migrated) as c, c.cursor() as cur:
        derived = derive_balances(cur)
        # 借方为正：资产 1101 +100、2990 +100、在途 1111 -100、
        # 负债 2101 = -100（E2 贷）+ 30（E6 借）= -70、收入 4101 = -30
        assert derived[("coa:1101", "USD", "AVAILABLE")] == 100
        assert derived[("coa:2990", "USD", "AVAILABLE")] == 100
        assert derived[("coa:1111", "USD", "AVAILABLE")] == -100
        assert derived[("coa:2101", "USD", "AVAILABLE")] == -70
        assert derived[("coa:4101", "USD", "AVAILABLE")] == -30
        # 全局净额必须为 0（复式记账的底线）
        assert sum(derived.values()) == 0

        snapshot_balances(cur)
        assert stored_balances(cur) == derived

    with session(migrated) as c, c.cursor() as cur:
        assert stored_balances(cur) == derive_balances(cur), "余额快照与分录重建不一致（INV-10）"


def test_balance_versions_track_each_journal(migrated: str) -> None:
    """每笔凭证产生下一版本；最新视图取最大 version，历史版本保持不变。"""
    def _first(c):
        ids = post_journal(c, _e2_lines(100), event_type="E2", source_type="chain_tx", source_id="tx-v1")
        with c.cursor() as cur:
            snapshot_balances(cur, journal_id=ids["journal_id"])

    run_ok(migrated, _first)

    def _second(c):
        ids = post_journal(c, _e6_lines(30), event_type="E6", source_type="usage_settle", source_id="u-v2")
        with c.cursor() as cur:
            snapshot_balances(cur, journal_id=ids["journal_id"])

    run_ok(migrated, _second)

    with session(migrated) as c, c.cursor() as cur:
        cur.execute(
            "SELECT account_id, version, balance_minor FROM account_balances "
            "WHERE account_id = 'coa:2101' ORDER BY version")
        history = [(v, int(b)) for _, v, b in cur.fetchall()]
        assert history == [(1, -100), (2, -70)], history
        assert stored_balances(cur) == derive_balances(cur)


def test_new_ledger_recompute_is_clean(migrated: str) -> None:
    """新账本复算：无不平、无孤儿凭证、行↔分录 1:1（diff=0）。"""
    def _write(c):
        post_journal(c, simple_lines(1_000))
        for i in range(5):
            post_journal(c, _e6_lines(10 + i), source_id=f"recompute-{i}")
        post_journal(c, _e2_lines(7), event_type="E2", source_type="chain_tx", source_id="recompute-tx")

    run_ok(migrated, _write)
    assert _recompute_new_ledger(migrated)["diff"] == 0, _recompute_new_ledger(migrated)


def test_balance_snapshot_cannot_be_rewritten(migrated: str) -> None:
    """快照是只追加：改历史版本或删行都被拒绝（余额可复算，不需要就地改数）。"""
    run_ok(migrated, lambda c: write_balances(c, {("coa:2101", "USD", "AVAILABLE"): -100}))
    assert_db_error(migrated, "append-only", lambda c: c.cursor().execute(
        "UPDATE account_balances SET balance_minor = -1 WHERE version = 1"))
    assert_db_error(migrated, "append-only",
                    lambda c: c.cursor().execute("DELETE FROM account_balances"))
