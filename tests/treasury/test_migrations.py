# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08 迁移：空库 / 幂等 / 升级 / 回滚 / 账本指纹不变 + CLI（up/down/status/seed）。

为控制 NAS 上的 DDL 成本，三个用例各用一个 fresh schema，但每个 schema 只做**一次**全量迁移：
空库与幂等合在一跑、升级与账本指纹合在一跑、回滚与 CLI 合在一跑（四跑口径不变）。
"""
from __future__ import annotations

import pytest

from app.treasury import migrate

import m08kit


def test_empty_database_full_migration_and_idempotent(fresh):
    applied = m08kit.apply_migrations(fresh)
    assert "800_payment_orders.sql" in applied and "805_m08_outbox.sql" in applied
    tables = m08kit.table_names(fresh)
    for table in m08kit.M08_TABLES:
        assert table in tables, table
    for table in m08kit.M08_LEGACY_TABLES:
        assert table in tables, table
    for view in m08kit.M08_VIEWS:
        assert view in m08kit.view_names(fresh), view
    before = m08kit.column_signature(fresh, m08kit.M08_TABLES)
    for _ in range(2):
        m08kit.apply_migrations(fresh, m08kit.m08_migration_files())
    assert m08kit.column_signature(fresh, m08kit.M08_TABLES) == before
    constraints = m08kit.constraint_names(fresh, "payment_orders")
    assert {"payment_orders_status_ck", "payment_orders_credited_ck"} <= constraints
    # 库层护栏：provider_txn_id 唯一 + 退款未结唯一
    with m08kit.connect(fresh) as conn:
        indexes = {row[0] for row in conn.execute(
            "SELECT indexname FROM pg_indexes WHERE schemaname = %s", (fresh,)).fetchall()}
    assert "payment_attempts_txn_uq" in indexes
    assert "uq_refund_open" in indexes


def test_upgrade_from_base_only_and_ledger_fingerprint(fresh):
    m08kit.apply_migrations(fresh, m08kit.prerequisite_files())
    base_signature = m08kit.column_signature(fresh, m08kit.M08_LEGACY_TABLES)
    adapter = m08kit.LedgerAdapter()
    from app.treasury import clock, ledger as ledger_mod

    request = ledger_mod.e3_request(
        attempt={"provider_txn_id": "txn-fp", "amount_minor": 100},
        order={"account_id": "acct-1", "order_no": "PO-FP", "amount_minor": 100},
        policy_version="m08-pool-default", occurred_at=clock.utcnow())
    with m08kit.connect(fresh, autocommit=False) as conn:
        adapter.post(conn, request)
        conn.commit()
    before = m08kit.ledger_fingerprint(fresh)
    migrate.up(migrate.connect(fresh), with_base=False)
    tables = m08kit.table_names(fresh)
    assert "payment_orders" in tables and "wallet_transfers" in tables
    after = m08kit.ledger_fingerprint(fresh)
    assert before == after
    assert before["debit"] == before["credit"] > 0
    upgraded = m08kit.column_signature(fresh, m08kit.M08_LEGACY_TABLES)
    for table, columns in base_signature.items():
        assert columns == upgraded[table][:len(columns)], table


def test_rollback_and_cli(fresh):
    m08kit.apply_migrations(fresh)
    removed = migrate.down(migrate.connect(fresh))
    assert len(removed) == 6
    tables = m08kit.table_names(fresh)
    for table in m08kit.M08_TABLES:
        assert table not in tables, table
    for table in m08kit.M08_LEGACY_TABLES:
        assert table in tables, table
    assert "v_m08_pool_depth" not in m08kit.view_names(fresh)
    migrate.down(migrate.connect(fresh))
    migrate.up(migrate.connect(fresh), with_base=False)
    assert "payment_orders" in m08kit.table_names(fresh)
    with migrate.connect(fresh) as conn:
        state = migrate.status(conn)
        assert all(value == "OK" for value in state.values()), state
        seeded = migrate.seed(conn)
        assert all(item.endswith(":exists") for item in seeded)
    assert migrate.main(["--schema", fresh, "--status"]) == 0
    assert migrate.main(["--schema", fresh, "--seed"]) == 0
    assert migrate.main(["--schema", fresh, "--down"]) == 0
    assert "payment_orders" not in m08kit.table_names(fresh)
    assert migrate.main(["--schema", fresh, "--up-only"]) == 0
    assert "payment_orders" in m08kit.table_names(fresh)
