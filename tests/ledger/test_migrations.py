# SPDX-License-Identifier: AGPL-3.0-or-later
"""迁移验收：空库建库、重复执行幂等、账本指纹不变、兼容视图。

验收来源：W1-EXECUTION-PLAN §2 DEV-M06-T1 验收 1（空库 001–604 全通过 / 单文件重复执行幂等）
         与验收 4（空账本复算 diff=0）。
"""
from __future__ import annotations

import uuid

from app.ledger import post_entry, recompute as legacy_recompute

from ledgerkit import (
    session,
    M06_MIGRATIONS,
    M06_TABLES,
    M06_VIEWS,
    apply_migrations,
    assert_db_error,
    connect,
    derive_balances,
    line,
    m06_migration_files,
    post_journal,
    migration_files,
    run_ok,
    simple_lines,
    table_names,
    tx,
    view_names,
    fingerprint,
)


def _legacy_ledger_fingerprint(schema: str) -> dict:
    """存量账本（001 的 ledger_entries）的数据指纹：条数 / 金额合计 / hash 串。"""
    with session(schema) as c, c.cursor() as cur:
        cur.execute(
            "SELECT count(*), COALESCE(sum(amount_micro), 0), "
            "COALESCE(md5(string_agg(hash, ',' ORDER BY seq)), '') FROM ledger_entries")
        n, total, digest = cur.fetchone()
        cur.execute("SELECT count(*), COALESCE(sum(balance_micro), 0) FROM accounts")
        accounts_n, accounts_total = cur.fetchone()
    return {"entries": n, "amount_micro": int(total), "hash_digest": digest,
            "accounts": accounts_n, "balance_micro": int(accounts_total)}


def test_empty_database_applies_001_to_604(migrated: str) -> None:
    """空库顺序执行 001–604 全部通过（每个文件 rc=0），五张表与两个读视图就位。"""
    outputs = apply_migrations(migrated)  # 已在 fixture 里跑过一次，这里显式再跑一次收输出
    assert [o["name"] for o in outputs] == [p.name for p in migration_files()]
    assert [o["name"] for o in outputs][-5:] == list(M06_MIGRATIONS)
    assert all(o["rc"] == 0 for o in outputs), outputs

    tables = table_names(migrated)
    for name in M06_TABLES:
        assert name in tables, f"缺表 {name}"
    views = view_names(migrated)
    for name in M06_VIEWS:
        assert name in views, f"缺视图 {name}"
    # 存量表仍在（不重建、不改名）
    assert {"ledger_entries", "accounts", "receipts"} <= tables


def test_single_file_rerun_is_idempotent(migrated: str) -> None:
    """单文件重复执行幂等：结构指纹逐项不变。"""
    before = fingerprint(migrated)
    for _ in range(2):
        for path in m06_migration_files():
            from ledgerkit import run_migration
            r = run_migration(path, migrated)
            assert r.returncode == 0, f"{path.name} 重跑失败：{r.stderr}\n{r.stdout}"
    after = fingerprint(migrated)
    assert after == before, {
        k: (set(before[k]) ^ set(after[k])) for k in before if before[k] != after[k]
    }


def test_m06_migrations_do_not_touch_legacy_ledger(schema: str) -> None:
    """600–604 前后：存量账本数据指纹与复算差异都不变（只加不改）。"""
    from ledgerkit import MIGRATIONS_DIR, run_migration
    for name in ("001_init.sql", "002_api_keys.sql", "003_nodes.sql", "004_wallet_pool.sql",
                 "005_chain.sql", "006_points.sql"):
        r = run_migration(MIGRATIONS_DIR / name, schema)
        assert r.returncode == 0, r.stderr

    def _recompute():
        with session(schema) as c:
            return legacy_recompute(c)

    def _seed():
        # 用真实写入口（app.ledger.post_entry）种一条自洽的历史分录：链与余额都成立
        with tx(schema) as c:
            with c.cursor() as cur:
                cur.execute(
                    "INSERT INTO accounts (id, kind) VALUES ('user:t1','user'),('node:t1','node') "
                    "ON CONFLICT DO NOTHING")
            post_entry(c, "user:t1", "node:t1", 7, memo="m06-t1-before")

    _seed()
    before_fp = _legacy_ledger_fingerprint(schema)
    before_diff = _recompute()
    assert before_diff["diff"] == 0, before_diff

    for path in m06_migration_files():
        r = run_migration(path, schema)
        assert r.returncode == 0, f"{path.name} 迁移失败：{r.stderr}"

    after_fp = _legacy_ledger_fingerprint(schema)
    after_diff = _recompute()
    assert after_fp == before_fp, (before_fp, after_fp)
    assert after_diff == before_diff, (before_diff, after_diff)
    assert after_diff["diff"] == 0, after_diff


def test_empty_ledger_recompute_diff_zero(migrated: str) -> None:
    """验收 4：空账本复算 diff=0（存量账本 + 新账本两侧都为 0）。"""
    with session(migrated) as c:
        legacy = legacy_recompute(c)
    assert legacy["entries"] == 0
    assert legacy["chain_bad"] == [] and legacy["balance_bad"] == {}
    assert legacy["diff"] == 0, legacy

    with session(migrated) as c, c.cursor() as cur:
        assert derive_balances(cur) == {}
        cur.execute("SELECT count(*) FROM account_balances")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT count(*) FROM journal_entry")
        assert cur.fetchone()[0] == 0


def test_compat_view_shows_both_generations_and_is_readonly(migrated: str) -> None:
    """ledger_entries 兼容视图：历史行（legacy）+ 新分录（journal）并集，且不可写。"""
    tag = uuid.uuid4().hex[:8]

    def _write(c):
        with c.cursor() as cur:
            cur.execute(
                "INSERT INTO accounts (id, kind) VALUES ('user:v','user'),('node:v','node') "
                "ON CONFLICT DO NOTHING")
            cur.execute(
                """INSERT INTO ledger_entries (debit, credit, amount_micro, memo, prev_hash, hash)
                   VALUES ('user:v','node:v', 11, %s, NULL, %s)""",
                (f"compat-{tag}", f"h-compat-{tag}"))
            post_journal(cur, simple_lines(42), source_id=f"compat-{tag}")

    run_ok(migrated, _write)

    with session(migrated) as c, c.cursor() as cur:
        cur.execute(
            "SELECT origin, count(*), min(amount_minor), bool_or(journal_id IS NOT NULL) "
            "FROM ledger_entries_compat GROUP BY origin ORDER BY origin")
        rows = dict((o, (n, int(amt), has_journal)) for o, n, amt, has_journal in cur.fetchall())
    assert rows["legacy"] == (1, 11, False), rows
    assert rows["journal"] == (2, 42, True), rows

    assert_db_error(migrated, "cannot delete from view",
                    lambda c: c.cursor().execute("DELETE FROM ledger_entries_compat"))
    assert_db_error(migrated, "cannot update view",
                    lambda c: c.cursor().execute("UPDATE ledger_entries_compat SET amount_minor = 1"))


def test_legacy_ledger_entries_still_append_only(migrated: str) -> None:
    """兼容层不削弱旧护栏：001 的 ledger_entries 仍然拒绝 UPDATE / DELETE。"""
    def _seed(c):
        with c.cursor() as cur:
            cur.execute(
                "INSERT INTO accounts (id, kind) VALUES ('user:g','user'),('node:g','node') "
                "ON CONFLICT DO NOTHING")
            cur.execute(
                """INSERT INTO ledger_entries (debit, credit, amount_micro, memo, hash)
                   VALUES ('user:g','node:g', 5, 'guard', 'h-guard')""")

    def _update(c):
        _seed(c)
        c.cursor().execute("UPDATE ledger_entries SET amount_micro = 1")

    def _delete(c):
        _seed(c)
        c.cursor().execute("DELETE FROM ledger_entries")

    assert_db_error(migrated, "append-only", _update)
    assert_db_error(migrated, "append-only", _delete)
