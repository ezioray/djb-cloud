# SPDX-License-Identifier: Apache-2.0
"""tests/supply 测试工具：迁移执行、结构指纹、账户夹具、断言小工具。

只读契约：

* 迁移文件是唯一 DDL 来源，测试只用 ``psql -f`` 执行（与 CI / 生产同一条路径），
  不在 Python 里手写建表语句；
* 每个测试进程用独立 schema（默认 ``m02_t12_<pid>_<hex>``，``M02_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不读写 public，也不碰别人的 schema；
* 缺 ``DJB_DSN`` 或库不可达时 DB 用例 skip（纯函数用例照跑）。
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable, Sequence

import psycopg
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "migrations"

#: 本任务新增的迁移（200–209）
M02_MIGRATIONS = (
    "200_supply_nodes.sql",
    "201_supply_upstreams.sql",
    "202_supply_policies.sql",
    "203_supply_events.sql",
    "204_supply_capacity.sql",
    "205_supply_outbox.sql",
    "206_supply_idempotency.sql",
    "207_supply_binding_codes.sql",
    "208_supply_heartbeat.sql",
    "209_supply_verified_view.sql",
)

#: M02 拥有的表（01-ownership §2 + 本模块 outbox / 幂等 / 绑定码）
M02_TABLES = ("nodes", "node_upstreams", "node_policies", "node_events",
              "capacity_announcements", "supply_outbox", "supply_idempotency",
              "node_binding_codes")

#: 本模块新增的函数（触发器函数）
M02_FUNCTIONS = ("m02_node_policies_guard", "m02_node_events_append_only",
                 "m02_capacity_append_only", "m02_outbox_guard")

#: 003 基线（升级测试要在这些表上证明「只加不改」）
BASE_TABLES = ("nodes", "node_receipts", "receipts", "api_keys", "wallet_pool",
               "chain_tx", "points_account", "users", "user_accounts",
               "v_identity_accounts")


# ─────────────────────────────────────────────────────── 连接与迁移
def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（见 W1-EXECUTION-PLAN §3）")
    return value


def connect(schema: str, autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m02-t12-tests",
                           options=f"-c search_path={schema} -c synchronous_commit=off")


@contextmanager
def session(schema: str):
    """autocommit 只读/单语句会话；退出即 close（psycopg 的 with 只提交，不关闭连接）。"""
    conn = connect(schema, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def _admin_connect() -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m02-t12-tests")


def create_schema(name: str) -> None:
    conn = _admin_connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '10s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
            cur.execute(f'CREATE SCHEMA "{name}"')
    finally:
        conn.close()


def drop_schema(name: str) -> None:
    conn = _admin_connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '15s'")
            cur.execute("SET statement_timeout = '120s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
    finally:
        conn.close()


def migration_number(path: pathlib.Path) -> int:
    return int(path.name.split("_", 1)[0])


def migration_files(order: str = "numeric") -> list[pathlib.Path]:
    """默认按**数字**排序（CI 用 ``sort -V``；字典序另有用例覆盖）。"""
    files = list(MIGRATIONS_DIR.glob("*.sql"))
    if order == "numeric":
        return sorted(files, key=migration_number)
    if order == "lexicographic":
        return sorted(files)
    raise ValueError(f"未知排序：{order}")


def m02_migration_files() -> list[pathlib.Path]:
    return [MIGRATIONS_DIR / name for name in M02_MIGRATIONS]


def base_migration_files() -> list[pathlib.Path]:
    """基线：不跑 2xx 的其它迁移（升级测试用）。"""
    return [p for p in migration_files() if not re.match(r"^2\d\d_", p.name)]


def run_migrations(paths: Sequence[pathlib.Path], schema: str) -> subprocess.CompletedProcess:
    """一个 psql 进程按序执行多个文件（同一连接），省掉每文件一次进程启动。"""
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema} -c synchronous_commit=off")
    args = ["psql", dsn(), "-v", "ON_ERROR_STOP=1", "-q"]
    for path in paths:
        args += ["-f", str(path)]
    return subprocess.run(args, capture_output=True, text=True, env=env, timeout=300)


def run_migration(path: pathlib.Path, schema: str) -> subprocess.CompletedProcess:
    return run_migrations([path], schema)


def apply_migrations(schema: str, files: Sequence[pathlib.Path] | None = None) -> list[dict]:
    """顺序执行迁移，返回 [{name, rc, stderr}]；失败立刻断言。"""
    paths = list(files if files is not None else migration_files())
    result = run_migrations(paths, schema)
    out = [{"name": p.name, "rc": result.returncode,
            "stderr": (result.stderr or "").strip()} for p in paths]
    assert result.returncode == 0, f"迁移失败（rc={result.returncode}）：\n{result.stderr}"
    return out


# ─────────────────────────────────────────────────────── 结构查询
def _rows(conn: psycopg.Connection, sql: str, params: Any = ()) -> list[tuple]:
    cur = conn.execute(sql, params)
    return list(cur.fetchall())


def table_names(schema: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT table_name FROM information_schema.tables"
                  " WHERE table_schema = %s AND table_type = 'BASE TABLE'", (schema,))}


def column_names(schema: str, table: str = "nodes") -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT column_name FROM information_schema.columns"
                  " WHERE table_schema = %s AND table_name = %s", (schema, table))}


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
    """schema 结构指纹；``tables`` 给定时只算这些表（升级前后对比用）。"""
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


# ─────────────────────────────────────────────────────── 上游夹具（M02 自有表）
def seed_verified_upstream(conn: psycopg.Connection, node_id: str, *,
                           access: str = "A1",
                           models: Iterable[str] = ("gpt-4o-mini",),
                           state: str = "verified",
                           verified_at: datetime | None = None,
                           base_url: str | None = None) -> uuid.UUID:
    """在**测试连接**上种一条上游（默认 ``state='verified'``）。

    C9b 起容量公告与调度候选都只认「已验证且新鲜」的上游，所以凡是要发公告的用例
    都必须先有这条上游。用**测试自己的连接**写（事务型 ``conn`` 也能用），
    避免跨连接等 FK 锁；``verified_at`` 缺省用**库内 now()**（不写死用例时钟，
    免得与固定 ``NOW`` 相撞）。

    ``state`` 传 ``declared`` / ``rejected`` / ``probing`` 可造负例；
    ``verified_at`` 传旧时刻可造「verified 但过期」。
    """
    model_list = [str(item) for item in models]
    url = base_url or f"http://127.0.0.1:9/{access.lower()}/" + "+".join(model_list)
    identifier = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO node_upstreams
                   (id, node_id, access_type, base_url, models, state, verified_at,
                    rejected_reason_code)
               VALUES (%s, %s, %s, %s, %s::jsonb, %s,
                       CASE WHEN %s = 'verified' THEN COALESCE(%s::timestamptz, now()) END,
                       CASE WHEN %s = 'rejected' THEN 'unreachable' END)
               ON CONFLICT (node_id, access_type, base_url) DO NOTHING
               RETURNING id""",
            (identifier, node_id, access, url, json.dumps(model_list), state,
             state, verified_at, state))
        row = cur.fetchone()
        if row is None:                                  # 已存在（同 node/access/base_url）
            cur.execute(
                """SELECT id FROM node_upstreams
                    WHERE node_id = %s AND access_type = %s AND base_url = %s""",
                (node_id, access, url))
            row = cur.fetchone()
    return row[0]


# ─────────────────────────────────────────────────────── 账户夹具（M01 只读依赖）
def seed_account(schema: str, account_id: uuid.UUID | None = None, *,
                 state: str = "normal") -> uuid.UUID:
    """在隔离 schema 里种一个可用账户（M01 表；M02 只读 ``v_identity_accounts``）。"""
    identifier = account_id or uuid.uuid4()
    user_id = uuid.uuid4()
    frozen = state == "frozen"
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO users (id, display_name) VALUES (%s, %s)
               ON CONFLICT (id) DO NOTHING""", (user_id, f"acct-{identifier.hex[:8]}"))
        # M01 的 user_accounts_frozen_chk：frozen 必须有 frozen_until / reason / by / approval
        conn.execute(
            """INSERT INTO user_accounts
                   (id, user_id, type, state, tenant_id, frozen_until, frozen_reason,
                    frozen_by, frozen_approval)
               VALUES (%s, %s, 'personal', %s, %s,
                       CASE WHEN %s THEN now() + interval '1 day' END,
                       CASE WHEN %s THEN '风控冻结（夹具）' END,
                       CASE WHEN %s THEN %s END,
                       CASE WHEN %s THEN '{"rule": "fixture"}'::jsonb END)
               ON CONFLICT (id) DO NOTHING""",
            (identifier, user_id, state, identifier, frozen, frozen, frozen, user_id, frozen))
    return identifier


__all__ = [
    "M02_MIGRATIONS", "M02_TABLES", "M02_FUNCTIONS", "BASE_TABLES",
    "dsn", "connect", "session", "create_schema", "drop_schema",
    "migration_number", "migration_files", "m02_migration_files", "base_migration_files",
    "run_migration", "run_migrations", "apply_migrations",
    "table_names", "column_names", "function_names", "fingerprint", "seed_account",
    "seed_verified_upstream",
]
