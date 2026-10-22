# SPDX-License-Identifier: Apache-2.0
"""DEV-M10 T1/T2 测试工具：迁移执行、结构指纹、断言小工具。

只读契约：
* 迁移文件是唯一 DDL 来源，测试只用 ``psql -f`` 执行（与 CI / 生产同一条路径），
  不在 Python 里手写建表语句；
* 每个测试进程用独立 schema（默认 ``m10_t12_<pid>_<hex>``，``M10_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不读写 public，也不碰别人的 schema；
* 缺 ``DJB_DSN`` 或库不可达时 DB 用例 skip（纯函数用例照跑）。
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Iterable, Sequence

import psycopg
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "migrations"

#: 本任务的迁移（1000–1004）
M10_MIGRATIONS = (
    "1000_config_items.sql",
    "1001_config_versions.sql",
    "1002_config_publish_requests.sql",
    "1003_config_snapshots.sql",
    "1004_config_drifts.sql",
    "1005_config_outbox.sql",
    "1006_publish_request_flow.sql",
)

M10_TABLES = ("config_items", "config_versions", "config_publish_requests",
              "config_snapshots", "config_drifts", "config_outbox")

M10_FUNCTIONS = (
    "m10_config_items_guard", "m10_forbid_truncate", "m10_versions_guard",
    "m10_versions_monotonic_trg", "m10_versions_secret_trg", "m10_snapshots_guard",
    "m10_drifts_guard", "m10_outbox_guard", "m10_requests_guard",
)

#: 001–604 的存量表（升级测试要在这些表上证明「只加不改」）
BASE_TABLES = (
    "accounts", "api_keys", "nodes", "wallet_pool", "chain_tx", "points",
    "users", "orgs", "user_accounts", "org_members", "sessions", "role_bindings",
    "tenant_quotas", "identity_outbox", "tenant_quota_history", "identity_idempotency",
    "identity_scan_tickets", "identity_auth", "journal_entry", "journal_line",
    "ledger_entry", "account_balances", "merkle_commitments", "ledger_entries", "receipts",
)


# ─────────────────────────────────────────────────────── 连接与迁移
def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（见 W1-EXECUTION-PLAN §3）")
    return value


def connect(schema: str, autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m10-t12-tests",
                           options=f"-c search_path={schema} -c synchronous_commit=off")


@contextmanager
def session(schema: str):
    """autocommit 只读/单语句会话；退出即 close（psycopg 的 with 只提交，不关闭连接）。"""
    conn = connect(schema, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def create_schema(name: str) -> None:
    conn = psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m10-t12-tests")
    try:
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '10s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
            cur.execute(f'CREATE SCHEMA "{name}"')
    finally:
        conn.close()


def drop_schema(name: str) -> None:
    conn = psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m10-t12-tests")
    try:
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '15s'")
            cur.execute("SET statement_timeout = '120s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
    finally:
        conn.close()


def _migration_number(path: pathlib.Path) -> int:
    return int(path.name.split("_", 1)[0])


def migration_files(order: str = "numeric") -> list[pathlib.Path]:
    """默认按**数字**排序（CI 的 shell glob 是字典序，见 test_empty_database_applies_in_glob_order_too）。"""
    files = list(MIGRATIONS_DIR.glob("*.sql"))
    if order == "numeric":
        return sorted(files, key=_migration_number)
    if order == "lexicographic":
        return sorted(files)
    raise ValueError(f"未知排序：{order}")


def base_migration_files() -> list[pathlib.Path]:
    return [p for p in migration_files() if not re.match(r"^10\d\d_", p.name)]


def m10_migration_files() -> list[pathlib.Path]:
    return [MIGRATIONS_DIR / name for name in M10_MIGRATIONS]


def run_migration(path: pathlib.Path, schema: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema} -c synchronous_commit=off")
    return subprocess.run(
        ["psql", dsn(), "-v", "ON_ERROR_STOP=1", "-q", "-f", str(path)],
        capture_output=True, text=True, env=env, timeout=180,
    )


def run_migrations(paths: Sequence[pathlib.Path], schema: str) -> subprocess.CompletedProcess:
    """一个 psql 进程按序执行多个文件（同一连接），省掉每文件一次进程启动。"""
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema} -c synchronous_commit=off")
    args = ["psql", dsn(), "-v", "ON_ERROR_STOP=1", "-q"]
    for path in paths:
        args += ["-f", str(path)]
    return subprocess.run(args, capture_output=True, text=True, env=env, timeout=300)


def apply_migrations(schema: str, files: Sequence[pathlib.Path] | None = None) -> list[dict]:
    """顺序执行 001–1004（单进程），返回 [{name, rc, stderr}]；失败立刻断言。"""
    paths = list(files if files is not None else migration_files())
    result = run_migrations(paths, schema)
    out = [{"name": p.name, "rc": result.returncode,
            "stderr": (result.stderr or "").strip()} for p in paths]
    assert result.returncode == 0, f"迁移失败（rc={result.returncode}）：\n{result.stderr}"
    return out


# ─────────────────────────────────────────────────────── 结构指纹
def _rows(conn: psycopg.Connection, sql: str, params: Any = ()) -> list[tuple]:
    cur = conn.execute(sql, params)
    return list(cur.fetchall())


def table_names(schema: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT table_name FROM information_schema.tables"
                  " WHERE table_schema = %s AND table_type = 'BASE TABLE'", (schema,))}


def view_names(schema: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT viewname FROM pg_views WHERE schemaname = %s", (schema,))}


def function_names(schema: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, """SELECT p.proname FROM pg_proc p
                       JOIN pg_namespace n ON n.oid = p.pronamespace
                      WHERE n.nspname = %s""", (schema,))}


_FINGERPRINT_SQL = {
    "columns": """
        SELECT table_name || '.' || column_name || ':' || data_type || ':' || is_nullable
               || ':' || COALESCE(column_default, '-') || ':' || is_generated
          FROM information_schema.columns
         WHERE table_schema = %(s)s {table_filter} ORDER BY 1""",
    "constraints": """
        SELECT c.relname || '.' || con.conname || ':' || pg_get_constraintdef(con.oid)
          FROM pg_constraint con
          JOIN pg_class c ON c.oid = con.conrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %(s)s {rel_filter} ORDER BY 1""",
    "indexes": """
        SELECT indexname || ':' || indexdef FROM pg_indexes
         WHERE schemaname = %(s)s {index_filter} ORDER BY 1""",
    "triggers": """
        SELECT t.tgname || ':' || c.relname || ':' || pg_get_triggerdef(t.oid)
          FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %(s)s AND NOT t.tgisinternal {rel_filter} ORDER BY 1""",
    "functions": """
        SELECT p.proname || ':' || md5(p.prosrc) FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = %(s)s ORDER BY 1""",
}


def fingerprint(schema: str, tables: Sequence[str] | None = None) -> dict[str, list[str]]:
    """schema 结构指纹；``tables`` 给定时只算这些表的列/约束/索引/触发器（升级对比用）。"""
    if tables is None:
        params: dict[str, Any] = {"s": schema}
        filters = {"table_filter": "", "rel_filter": "", "index_filter": ""}
    else:
        params = {"s": schema, "tables": list(tables)}
        filters = {
            "table_filter": "AND table_name = ANY(%(tables)s)",
            "rel_filter": "AND c.relname = ANY(%(tables)s)",
            "index_filter": "AND tablename = ANY(%(tables)s)",
        }
    result: dict[str, list[str]] = {}
    with session(schema) as conn:
        for key, template in _FINGERPRINT_SQL.items():
            if tables is not None and key == "functions":
                continue
            sql = template.format(**filters)
            result[key] = [row[0] for row in _rows(conn, sql, params)]
    return result


# ─────────────────────────────────────────────────────── 断言小工具
@contextmanager
def tx(conn: psycopg.Connection):
    """嵌套事务（连接已在事务里时即 SAVEPOINT）：异常自动回滚到保存点。"""
    with conn.transaction():
        yield conn


def assert_db_error(conn: psycopg.Connection, match: str,
                    fn: Callable[[psycopg.Connection], Any]) -> psycopg.Error:
    """期望数据库报错（含触发器 42501 / 约束 23514），且错误信息包含 match。"""
    with pytest.raises(psycopg.Error) as excinfo:
        with conn.transaction():
            fn(conn)
    message = str(excinfo.value)
    assert match.lower() in message.lower(), f"期望错误信息包含 {match!r}，实际：{message!r}"
    return excinfo.value


def scalar(conn: psycopg.Connection, sql: str, params: Iterable[Any] = ()) -> Any:
    row = conn.execute(sql, tuple(params)).fetchone()
    return row[0] if row else None


def new_idempotency_key() -> str:
    return f"idem-{uuid.uuid4().hex}"
