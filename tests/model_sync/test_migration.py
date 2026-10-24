# SPDX-License-Identifier: AGPL-3.0-or-later
"""1800 迁移用例：空库 / 升级只加不改 / 回滚可重复 / 重跑幂等 / 账本 diff=0 / 库层护栏。

DDL 在 PostgreSQL 里是事务性的：升级与回滚演练都在**一个事务**里做完再回滚，
共享 ``base_schema`` 因此始终停在 1800 段之前（NAS 上只跑一次基线迁移，省时间）。
"""
from __future__ import annotations

import ast
import pathlib
import uuid

import psycopg
import pytest

from app.model_sync import facts, migrate, store

from kit import (LEDGER_TABLES, M18_FUNCTIONS, M18_TABLES, apply_m18_in_transaction,
                 connect, function_names_on, index_names_on, ledger_snapshot,
                 m18_migration_files, relation_fingerprint_on, rollback_m18_in_transaction,
                 table_names_on)

APP_DIR = pathlib.Path(__file__).resolve().parents[2] / "app" / "model_sync"
EXPECTED_COLUMNS = {
    "vendor", "canonical", "aliases", "context_window", "tokenizer_family",
    "tokenizer_version", "tokenizer_hash", "effective_at", "source", "state",
    "created_at", "updated_at"}


_GUARD_ERRORS = (psycopg.errors.RaiseException, psycopg.errors.InsufficientPrivilege)


def _expect_raise(conn, sql: str, params: tuple = (), *, error=_GUARD_ERRORS):
    """在 SAVEPOINT 内跑一条应失败的语句（PG 事务被异常打脏后仍可继续）。"""
    name = f"sp_{uuid.uuid4().hex[:8]}"
    conn.execute(f"SAVEPOINT {name}")
    try:
        with pytest.raises(error):
            conn.execute(sql, params)
    finally:
        conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
        conn.execute(f"RELEASE SAVEPOINT {name}")


# --------------------------------------------------------------------------- 对象与段号
def test_m18_objects_exist_in_fully_migrated_schema(migrated):
    conn = connect(migrated)
    try:
        assert set(M18_TABLES) <= table_names_on(conn, migrated)
        assert set(M18_FUNCTIONS) <= function_names_on(conn, migrated)
        indexes = index_names_on(conn, migrated)
        assert {"vendor_models_uq", "model_sync_bundles_version_uq",
                "idx_bundles_published"} <= indexes
        status = migrate.status(conn)
        assert set(status.values()) == {"OK"}
    finally:
        conn.close()

    numbers = [int(path.name.split("_", 1)[0]) for path in m18_migration_files()]
    assert numbers == [1800]
    assert set(migrate.M18_TABLES) == set(M18_TABLES)
    assert [name for name, _ in migrate.DOWN_SQL] == list(reversed(migrate.MODULE_MIGRATIONS))


def test_columns_and_constraints(base_conn, base_schema):
    apply_m18_in_transaction(base_conn)
    columns = {row[0] for row in base_conn.execute(
        "SELECT column_name FROM information_schema.columns"
        " WHERE table_schema = %s AND table_name = 'vendor_models'", (base_schema,))}
    assert EXPECTED_COLUMNS <= columns
    constraints = {row[0] for row in base_conn.execute(
        "SELECT conname FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid"
        " JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname = %s AND c.relname IN ('vendor_models', 'model_sync_bundles',"
        "                                         'node_model_sync_state')", (base_schema,))}
    assert {"vendor_models_uq", "vendor_models_hash_ck", "model_sync_bundles_version_uq",
            "model_sync_bundles_signature_ck", "node_model_sync_state_drift_keys_ck"} <= constraints


# --------------------------------------------------------------------------- 升级 / 回滚 / 重跑
def test_upgrade_only_adds_and_keeps_baseline(base_conn, base_schema):
    sentinel = tuple(LEDGER_TABLES) + ("nodes", "node_upstreams", "capacity_announcements")
    before = relation_fingerprint_on(base_conn, base_schema, sentinel)
    apply_m18_in_transaction(base_conn)
    after = relation_fingerprint_on(base_conn, base_schema, sentinel)
    assert after == before, "1800 不得改动任何前置表的结构"


def test_ledger_diff_is_zero(base_conn, base_schema):
    """M18 不触账：升级前后账本行数 / 行摘要 / 结构指纹都必须逐字节相同。"""
    before = ledger_snapshot(base_conn, LEDGER_TABLES)
    before_structure = relation_fingerprint_on(base_conn, base_schema, LEDGER_TABLES)
    apply_m18_in_transaction(base_conn)
    assert ledger_snapshot(base_conn, LEDGER_TABLES) == before
    assert relation_fingerprint_on(base_conn, base_schema, LEDGER_TABLES) == before_structure


def test_rollback_is_repeatable_and_reapplies(base_conn, base_schema):
    apply_m18_in_transaction(base_conn)
    assert set(M18_TABLES) <= table_names_on(base_conn, base_schema)
    rollback_m18_in_transaction(base_conn, times=2)          # 可重复
    tables = table_names_on(base_conn, base_schema)
    assert not (set(M18_TABLES) & tables)
    assert not (set(M18_FUNCTIONS) & function_names_on(base_conn, base_schema))
    assert {"ledger_entry", "nodes"} <= tables              # 前置对象仍在
    apply_m18_in_transaction(base_conn)                     # 回滚后能再升级
    assert set(M18_TABLES) <= table_names_on(base_conn, base_schema)


# --------------------------------------------------------------------------- 库层护栏
def test_append_only_and_immutability_guards(conn, now):
    bundle = store.create_draft(conn, actor="admin:t", now=now)
    _expect_raise(conn, "UPDATE model_sync_events SET event = 'published'")
    _expect_raise(conn, "DELETE FROM model_sync_events")
    _expect_raise(conn, "TRUNCATE model_sync_events")
    _expect_raise(conn, "DELETE FROM model_sync_bundles")
    _expect_raise(conn, "UPDATE model_sync_bundles SET payload = '{\"models\": []}'::jsonb"
                        " WHERE id = %s", (bundle["id"],))
    _expect_raise(conn, "UPDATE model_sync_bundles SET version = 99 WHERE id = %s",
                  (bundle["id"],))


def test_invalid_bundle_payload_is_rejected(conn, now):
    _expect_raise(
        conn,
        """INSERT INTO model_sync_bundles (id, version, payload, payload_hash, source,
                                           state, created_at)
           VALUES (%s, 1, '[]'::jsonb, %s, 'registry', 'draft', %s)""",
        (uuid.uuid4(), "0" * 64, now), error=psycopg.errors.CheckViolation)
    _expect_raise(
        conn,
        """INSERT INTO model_sync_bundles (id, version, payload, payload_hash, source,
                                           state, created_at)
           VALUES (%s, 1, '{"models": []}'::jsonb, 'not-a-hash', 'registry', 'draft', %s)""",
        (uuid.uuid4(), now), error=psycopg.errors.CheckViolation)


def test_event_detail_rejects_content_keys(conn, now):
    _expect_raise(
        conn,
        """INSERT INTO model_sync_events (id, event, detail, actor, created_at)
           VALUES (%s, 'published', '{"content": "hello"}'::jsonb, 'admin:t', %s)""",
        (uuid.uuid4(), now), error=psycopg.errors.CheckViolation)


# --------------------------------------------------------------------------- 不触账（静态）
def test_module_has_no_ledger_paths():
    offenders: list[str] = []
    for path in sorted(APP_DIR.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [f"{path.name}: {alias.name}" for alias in node.names
                              if alias.name.startswith("app.ledger")]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                module = node.module or ""
                if module.startswith("app.ledger"):
                    offenders.append(f"{path.name}: {module}")
        for table in LEDGER_TABLES:
            if table in source:
                offenders.append(f"{path.name}: mentions {table}")
    assert offenders == [], f"M18 不得触账：{offenders}"
    assert facts.MODULE_RANGE == (1800, 1899)
