# SPDX-License-Identifier: Apache-2.0
"""迁移验收（M03 §5 / 04-api-contracts §4 migration 门禁）：空库 / 升级 / 回滚三跑 exit=0。"""
from __future__ import annotations

import pathlib
import re

import psycopg
import pytest

from app.gateway import migrate as gateway_migrate
from gatewaykit import (BASE_TABLES, M03_FUNCTIONS, M03_MIGRATIONS, M03_TABLES, ROOT,
                        apply_migrations, column_names, function_names, index_names,
                        m03_migration_files, migration_files, migration_number,
                        prerequisite_files, run_migrations, session, table_names)


def _fingerprint(schema: str, tables: tuple[str, ...]) -> dict[str, list[tuple]]:
    """前置对象的「结构 + 数据」指纹（升级 / 回滚前后必须逐字节一致）。"""
    out: dict[str, list[tuple]] = {}
    with session(schema) as conn:
        for table in tables:
            columns = [row[0] for row in conn.execute(
                "SELECT column_name FROM information_schema.columns"
                " WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (schema, table)).fetchall()]
            constraints = conn.execute(
                """SELECT con.conname || ':' || pg_get_constraintdef(con.oid)
                     FROM pg_constraint con
                     JOIN pg_class c ON c.oid = con.conrelid
                     JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = %s AND c.relname = %s ORDER BY 1""",
                (schema, table)).fetchall()
            indexes = conn.execute(
                "SELECT indexname || ':' || indexdef FROM pg_indexes"
                " WHERE schemaname = %s AND tablename = %s ORDER BY 1",
                (schema, table)).fetchall()
            count = conn.execute(f'SELECT count(*) FROM "{schema}"."{table}"').fetchone()[0]
            out[table] = [tuple(columns), tuple(constraints), tuple(indexes), count]
    return out


# ─────────────────────────────────────────────────────── 空库 + 升级 + 回滚
def test_empty_database_runs_all_migrations_in_numeric_order(schema):
    """空库：前置段（<300）+ 301–305 全部 exit=0。"""
    paths = list(prerequisite_files()) + list(m03_migration_files())
    result = run_migrations(paths, schema)
    assert result.returncode == 0, result.stderr
    assert set(M03_TABLES) <= table_names(schema)
    assert set(M03_FUNCTIONS) <= function_names(schema)


def test_migrations_are_repeatable(schema):
    """同一 schema 再跑一遍：不报错、不重复建对象（IF NOT EXISTS / CREATE OR REPLACE）。"""
    apply_migrations(schema)
    before = table_names(schema)
    apply_migrations(schema)
    assert table_names(schema) == before


def test_upgrade_path_leaves_upstream_objects_untouched(schema):
    """升级：只加不改——前置对象的结构与数据零差异。"""
    apply_migrations(schema, prerequisite_files())
    baseline = _fingerprint(schema, BASE_TABLES)
    apply_migrations(schema, m03_migration_files())
    after = _fingerprint(schema, BASE_TABLES)
    assert after == baseline, "3xx 迁移改动了前置对象（只加不改被违反）"
    assert set(M03_TABLES) <= table_names(schema)


def test_rollback_removes_only_module_objects(schema):
    """回滚：3xx 对象全部消失，前置对象结构 / 数据零差异。"""
    apply_migrations(schema, prerequisite_files())
    baseline = _fingerprint(schema, BASE_TABLES)
    baseline_tables = table_names(schema)
    apply_migrations(schema, m03_migration_files())
    assert set(M03_TABLES) <= table_names(schema)

    gateway_migrate.apply_down(schema)

    remaining = table_names(schema)
    assert not (set(M03_TABLES) & remaining)
    assert remaining == baseline_tables
    assert _fingerprint(schema, BASE_TABLES) == baseline
    # 护栏函数也回收
    assert not (set(M03_FUNCTIONS) & function_names(schema))


def test_rollback_is_repeatable(schema):
    apply_migrations(schema)
    gateway_migrate.apply_down(schema)
    gateway_migrate.apply_down(schema)                   # 幂等：不存在的对象直接跳过
    assert not (set(M03_TABLES) & table_names(schema))


def test_cli_up_down_status_three_runs(schema):
    """CLI 三跑（与运维同一入口）：up → status → down，全部 exit=0。"""
    assert gateway_migrate.main(["--schema", schema, "--up"]) == 0
    assert gateway_migrate.main(["--schema", schema, "--status"]) == 0
    info = gateway_migrate.status(schema)
    assert all(row["applied"] for row in info["module_migrations"])
    assert gateway_migrate.main(["--schema", schema, "--down"]) == 0
    assert not (set(M03_TABLES) & table_names(schema))


# ─────────────────────────────────────────────────────── 编号段与文件
def test_migration_numbers_stay_in_the_m03_segment():
    for name in M03_MIGRATIONS:
        number = int(name.split("_", 1)[0])
        assert 300 <= number <= 399, name


def test_module_migration_list_matches_the_files_on_disk():
    on_disk = {path.name for path in migration_files() if 300 <= migration_number(path) <= 399}
    assert on_disk == set(M03_MIGRATIONS)


def test_numeric_order_differs_from_lexicographic_and_we_use_numeric():
    """数字序是本模块的唯一执行序（3xx 段内不会有 30x/31x 混排的歧义）。"""
    numeric = [migration_number(path) for path in m03_migration_files()]
    assert numeric == sorted(numeric)
    assert [int(name.split("_", 1)[0]) for name in M03_MIGRATIONS] == [301, 302, 303, 304, 305,
                                                                      306, 307]


def test_migrations_create_only_m03_tables(schema):
    apply_migrations(schema, m03_migration_files())
    created: set[str] = set()
    for name in M03_MIGRATIONS:
        sql = (pathlib.Path(__file__).resolve().parents[2] / "migrations" / name).read_text(
            encoding="utf-8")
        created |= {match.group(1) for match in
                    re.finditer(r"CREATE TABLE IF NOT EXISTS ([a-z_][a-z0-9_]*)", sql)}
    assert created == set(M03_TABLES)


def test_migrations_never_recreate_or_alter_upstream_tables():
    root = pathlib.Path(__file__).resolve().parents[2]
    for name in M03_MIGRATIONS:
        sql = (root / "migrations" / name).read_text(encoding="utf-8")
        for table in BASE_TABLES:
            assert f"CREATE TABLE IF NOT EXISTS {table}" not in sql, (name, table)
            assert f"DROP TABLE IF EXISTS {table}" not in sql, (name, table)
            assert f"ALTER TABLE {table} " not in sql, (name, table)


# ─────────────────────────────────────────────────────── 对象细节
def test_request_log_has_metadata_columns_and_indexes(schema):
    apply_migrations(schema, m03_migration_files())
    columns = column_names(schema, "api_request_log")
    assert {"request_id", "account_id", "api_key_id", "model", "service_tier", "stream",
            "status", "http_status", "error_code", "node_id", "latency_ms", "first_byte_ms",
            "tokens_in", "tokens_out", "usage_source", "batch_id", "created_at"} <= columns
    # 正文 / 密钥列不存在（INV-M03-02）
    assert not {"prompt", "response", "content", "api_key", "messages"} & columns
    indexes = index_names(schema, "api_request_log")
    assert {"api_request_log_request_uq", "api_request_log_key_time_idx",
            "api_request_log_account_time_idx", "api_request_log_batch_idx"} <= indexes


def test_batch_tables_have_state_machine_and_idempotency_indexes(schema):
    apply_migrations(schema, m03_migration_files())
    assert {"batch_id", "status", "checkpoint_resumes", "results_ref", "cost_estimate_minor",
            "cost_actual_minor", "eta_seconds"} <= column_names(schema, "batch_jobs")
    assert {"item_id", "batch_id", "seq", "custom_id", "status", "usage_id"} <= column_names(
        schema, "batch_items")
    batch_indexes = index_names(schema, "batch_jobs")
    assert {"batch_jobs_idempotency_uq", "batch_jobs_active_idx"} <= batch_indexes
    item_indexes = index_names(schema, "batch_items")
    assert {"batch_items_batch_seq_uq", "batch_items_batch_custom_uq"} <= item_indexes


def test_outbox_and_idempotency_tables_exist(schema):
    apply_migrations(schema, m03_migration_files())
    assert "m03_outbox_idempotency_uq" in index_names(schema, "m03_outbox")
    assert "m03_idempotency_scope_key_uq" in index_names(schema, "m03_idempotency")
    assert {"scope", "key", "request_hash", "status_code", "response", "expires_at"} <= \
        column_names(schema, "m03_idempotency")


def test_rls_is_not_enabled_by_accident(schema):
    """S1 不做多租户 RLS（隔离靠应用层 + 视图）；确认没有半开状态。"""
    apply_migrations(schema, m03_migration_files())
    with session(schema) as conn:
        rows = conn.execute(
            "SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = %s AND c.relrowsecurity", (schema,)).fetchall()
    assert rows == []


# ─────────────────────────────────────────────────────── 307（C9a 双计枚举扩展）
def _insert_usage_source(conn, request_id: str, usage_source: str | None) -> None:
    """插一行最小元数据（只给必填列 + usage_source；正文列本表没有）。"""
    import uuid as _uuid

    conn.execute("INSERT INTO api_request_log (id, request_id, status, http_status, usage_source)"
                 " VALUES (%s, %s, 'completed', 200, %s)",
                 (str(_uuid.uuid4()), request_id, usage_source))


def test_307_widens_usage_source_enum_without_rewriting_history(schema):
    """C9a（PROBE-TOKEN-AUDIT §5）：307 只**放宽**枚举——新行 dual 可插、非法值仍拒、
    约束仍是 NOT VALID（历史行不校验、不重写表）。"""
    apply_migrations(schema, m03_migration_files())
    with session(schema) as conn:
        _insert_usage_source(conn, "r-legacy", "actual")              # 301 口径照旧
        _insert_usage_source(conn, "r-dual", "dual")                  # 307 之后新增值
        with pytest.raises(psycopg.errors.CheckViolation):
            _insert_usage_source(conn, "r-bad", "client_reported")    # 非法值仍拒（23514）
        definition = conn.execute(
            "SELECT pg_get_constraintdef(con.oid) FROM pg_constraint con"
            " JOIN pg_class c ON c.oid = con.conrelid"
            " JOIN pg_namespace n ON n.oid = con.connamespace"
            " WHERE n.nspname = %s AND c.relname = 'api_request_log'"
            " AND con.conname = 'api_request_log_usage_source_ck'", (schema,)).fetchone()[0]
    assert "dual" in definition
    assert "NOT VALID" in definition


def test_307_is_repeatable_and_reversible(schema):
    """307 重跑幂等；status 能识别；回滚后旧两值 CHECK 生效且**不重写**已有 dual 行。"""
    apply_migrations(schema, m03_migration_files())
    path = ROOT / "migrations" / "307_api_request_log_usage_source_dual.sql"
    assert run_migrations([path], schema).returncode == 0            # 幂等重跑

    marker = "307_api_request_log_usage_source_dual.sql"
    applied = {row["name"]: row["applied"]
               for row in gateway_migrate.status(schema)["module_migrations"]}
    assert applied[marker] is True                                   # 约束定义已含 dual

    rollback = dict(gateway_migrate.DOWN_SQL)[marker]
    with session(schema) as conn:
        _insert_usage_source(conn, "r-keep", "dual")                 # 回滚前的 dual 行
        conn.execute(rollback)                                       # 只改 CHECK，不重写表
        with pytest.raises(psycopg.errors.CheckViolation):
            _insert_usage_source(conn, "r-after", "dual")            # 旧两值 CHECK 生效
        kept = conn.execute("SELECT usage_source FROM api_request_log"
                            " WHERE request_id = 'r-keep'").fetchone()[0]
    assert kept == "dual"                                            # 历史行不动

    applied = {row["name"]: row["applied"]
               for row in gateway_migrate.status(schema)["module_migrations"]}
    assert applied[marker] is False
