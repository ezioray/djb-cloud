# SPDX-License-Identifier: AGPL-3.0-or-later
"""1710 迁移用例：空库 / 升级只加不改 / 回滚可重复 / 重跑幂等 / 账本 diff=0 / 库层护栏。

DDL 在 PostgreSQL 里是事务性的：升级与回滚演练都在**一个事务**里做完再回滚，
共享 ``base_schema`` 因此始终停在 1700 段之前（NAS 上只跑一次基线迁移，省时间）。
"""
from __future__ import annotations

import pytest

from app.integrity import facts, migrate

import psycopg

from kit import (apply_m17_in_transaction, base_migration_files, connect,
                 ledger_snapshot, m17_migration_files, relation_fingerprint_on,
                 rollback_m17_in_transaction, table_names_on, function_names_on,
                 index_names_on, M17_TABLES)


def test_m17_objects_exist_in_fully_migrated_schema(migrated):
    tables = table_names_on(connect(migrated), migrated)
    assert set(M17_TABLES) <= tables
    functions = function_names_on(connect(migrated), migrated)
    assert set(migrate.M17_FUNCTIONS) <= functions
    indexes = index_names_on(connect(migrated), migrated)
    assert {"uq_integrity_holds_active", "idx_integrity_holds_node",
            "idx_integrity_holds_expiry"} <= indexes
    numbers = [int(path.name.split("_", 1)[0]) for path in m17_migration_files()]
    assert numbers == [1710, 1711, 1720, 1721, 1730, 1740]
    base = [int(path.name.split("_", 1)[0]) for path in base_migration_files()]
    assert base == sorted(base)
    assert max(base) < 1700


def test_hold_columns_and_constraints(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        apply_m17_in_transaction(conn)
        columns = {row[0] for row in conn.execute(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_schema = %s AND table_name = 'supplier_integrity_holds'",
            (base_schema,)).fetchall()}
        assert columns == {
            "id", "node_id", "upstream_id", "model", "level", "ratio_bp",
            "base_amount_micro", "frozen_amount_micro", "state", "reason", "evidence_ref",
            "created_at", "expires_at", "released_at", "release_reason", "reviewer_a",
            "reviewer_b", "version", "updated_at"}
        event_columns = {row[0] for row in conn.execute(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_schema = %s AND table_name = 'supplier_integrity_events'",
            (base_schema,)).fetchall()}
        assert event_columns == {"event_id", "hold_id", "node_id", "model", "event",
                                "from_level", "to_level", "detail", "actor", "created_at"}
        conn.rollback()


def test_upgrade_only_adds_m17_objects(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        before_tables = table_names_on(conn, base_schema)
        before_indexes = index_names_on(conn, base_schema)
        before_functions = function_names_on(conn, base_schema)
        before_fingerprint = relation_fingerprint_on(conn, base_schema,
                                                    sorted(before_tables))

        apply_m17_in_transaction(conn)

        after_tables = table_names_on(conn, base_schema)
        assert after_tables - before_tables == set(M17_TABLES)
        assert before_tables <= after_tables                    # 零张表被删
        after_fingerprint = relation_fingerprint_on(conn, base_schema, sorted(before_tables))
        assert after_fingerprint == before_fingerprint, "1710 改动了上游对象结构"
        assert set(migrate.M17_FUNCTIONS) <= function_names_on(conn, base_schema)
        from kit import M17_INDEXES

        assert index_names_on(conn, base_schema) - before_indexes == set(M17_INDEXES)
        assert function_names_on(conn, base_schema) - before_functions == set(
            migrate.M17_FUNCTIONS)
        conn.rollback()


def test_rollback_is_clean_and_repeatable(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        before_tables = table_names_on(conn, base_schema)
        before_fingerprint = relation_fingerprint_on(conn, base_schema, sorted(before_tables))
        apply_m17_in_transaction(conn)
        assert set(M17_TABLES) <= table_names_on(conn, base_schema)

        rollback_m17_in_transaction(conn, times=1)
        assert not (set(M17_TABLES) & table_names_on(conn, base_schema))
        assert not (set(migrate.M17_FUNCTIONS) & function_names_on(conn, base_schema))

        rollback_m17_in_transaction(conn, times=1)             # 再回滚一次：可重复
        assert not (set(M17_TABLES) & table_names_on(conn, base_schema))

        apply_m17_in_transaction(conn)                          # 回滚后还能再升级
        assert set(M17_TABLES) <= table_names_on(conn, base_schema)
        assert relation_fingerprint_on(conn, base_schema, sorted(before_tables)) == \
            before_fingerprint
        conn.rollback()


def test_migration_up_twice_is_idempotent(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        apply_m17_in_transaction(conn)
        apply_m17_in_transaction(conn)                          # 重跑：IF NOT EXISTS / OR REPLACE
        assert set(M17_TABLES) <= table_names_on(conn, base_schema)
        # 只有一套护栏函数（没有被重跑搞出重复对象）
        assert function_names_on(conn, base_schema) >= set(migrate.M17_FUNCTIONS)
        conn.rollback()


def test_ledger_fingerprint_and_rows_unchanged(base_schema):
    """账本 diff=0：结构指纹 + 真实行摘要，迁移前后完全一致。"""
    with connect(base_schema, autocommit=False) as conn:
        conn.execute(
            """
            INSERT INTO loss_pool_entries
              (entry_id, request_id, attempt_no, amount_minor, reason, evidence_ref,
               recorded_at)
            VALUES (gen_random_uuid(), 'req-m17-ledger-1', 1, 880000, 'upstream_consumed',
                    'bill-1', now())
            """)
        before_rows = ledger_snapshot(conn, facts.LEDGER_TABLES)
        before_structure = relation_fingerprint_on(conn, base_schema,
                                                  sorted(facts.LEDGER_TABLES))
        assert before_rows["loss_pool_entries"]["count"] == 1

        apply_m17_in_transaction(conn)

        after_rows = ledger_snapshot(conn, facts.LEDGER_TABLES)
        after_structure = relation_fingerprint_on(conn, base_schema,
                                                  sorted(facts.LEDGER_TABLES))
        assert after_rows == before_rows, "迁移改动了账本数据"
        assert after_structure == before_structure, "迁移改动了账本结构"
        conn.rollback()


def test_holds_table_guards_identity_and_monotonic_version(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        apply_m17_in_transaction(conn)
        conn.execute(
            """
            INSERT INTO supplier_integrity_holds
              (id, node_id, upstream_id, model, level, ratio_bp, base_amount_micro,
               frozen_amount_micro, state, reason, evidence_ref, created_at, expires_at)
            VALUES (gen_random_uuid(), 'node-1', NULL, 'openai/gpt-4o', 'I2', 8000,
                    1000000, 800000, 'active', 'tokenizer_mismatch', 'risk-case-1',
                    now(), NULL)
            """)
        with pytest.raises(psycopg.Error) as excinfo:
            with conn.transaction():
                conn.execute("UPDATE supplier_integrity_holds SET version = version + 2")
        assert "version" in str(excinfo.value)
        with pytest.raises(psycopg.Error) as excinfo:
            with conn.transaction():
                conn.execute("UPDATE supplier_integrity_holds"
                             " SET level = 'I1', ratio_bp = 5000,"
                             " frozen_amount_micro = 500000, version = version + 1")
        assert "只升不降" in str(excinfo.value)
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM supplier_integrity_holds")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("TRUNCATE supplier_integrity_holds")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("UPDATE supplier_integrity_holds SET node_id = 'node-2',"
                             " version = version + 1")
        conn.rollback()


def test_holds_ratio_and_frozen_amount_checks(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        apply_m17_in_transaction(conn)
        insert = """
            INSERT INTO supplier_integrity_holds
              (id, node_id, model, level, ratio_bp, base_amount_micro, frozen_amount_micro,
               state, reason, evidence_ref, created_at, expires_at)
            VALUES (gen_random_uuid(), 'node-1', 'openai/gpt-4o', %s, %s, %s, %s,
                    'active', 'r', 'e', now(), %s)
        """
        # I2 必须 8000
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.transaction():
                conn.execute(insert, ("I2", 5000, 1000, 500, None))
        # 冻结额必须等于 base * ratio / 10000
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.transaction():
                conn.execute(insert, ("I2", 8000, 1000, 1, None))
        # I1 必须有 expires_at；I2+ 必须没有
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.transaction():
                conn.execute(insert, ("I1", 5000, 1000, 500, None))
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.transaction():
                conn.execute(insert, ("I3", 10000, 1000, 1000, "2026-11-01T00:00:00Z"))
        conn.rollback()


def test_events_are_append_only(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        apply_m17_in_transaction(conn)
        conn.execute(
            """
            INSERT INTO supplier_integrity_events
              (event_id, hold_id, node_id, model, event, from_level, to_level, detail,
               actor, created_at)
            VALUES (gen_random_uuid(), NULL, 'node-1', 'openai/gpt-4o', 'created', NULL,
                    'I0', '{"hold": false}'::jsonb, 'risk-bot', now())
            """)
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("UPDATE supplier_integrity_events SET actor = 'tamper'")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM supplier_integrity_events")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("TRUNCATE supplier_integrity_events")
        # detail 不得出现正文/凭据类键
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO supplier_integrity_events
                      (event_id, hold_id, node_id, model, event, from_level, to_level,
                       detail, actor, created_at)
                    VALUES (gen_random_uuid(), NULL, 'node-1', 'openai/gpt-4o', 'created',
                            NULL, 'I0', '{"prompt": "用户正文"}'::jsonb, 'risk-bot', now())
                    """)
        conn.rollback()
