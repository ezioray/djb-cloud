# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/model_sync 脚手架：schema 隔离 / 迁移三跑 / 账本指纹 / 路由客户端。

隔离约定（与 tests/integrity / tests/supply 同款）：

* 每个测试进程独立 schema（``m18_t_<pid>_<hex>``，``M18_SCHEMA`` 可覆盖），结束 DROP；
* 迁移用**同一份 migrations/*.sql** 执行（与 CI / `python -m app.model_sync.migrate` 同路径）；
* 缺 ``DJB_DSN`` 时 DB 用例 skip（纯函数用例照跑）；
* 账本 diff 用「结构指纹 + 行摘要」两路（都是 md5），证明 M18 不触账。

**测试用签名密钥**：``TEST_SIGNING_KEY`` 是**假密钥**（仅测试环境，写死在 kit 里不构成凭据）；
真实密钥只从 ``DJB_MODEL_SYNC_KEY`` 读，测试里由 monkeypatch 注入。
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

import psycopg
from psycopg.rows import dict_row

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

FIXED_NOW = datetime(2026, 10, 25, 0, 0, tzinfo=timezone.utc)

#: 测试专用**假密钥**（不是凭据；真实密钥只从 DJB_MODEL_SYNC_KEY 读）
TEST_SIGNING_KEY = "test-only-model-sync-key-" + "k" * 24

M18_TABLES: tuple[str, ...] = (
    "vendor_models", "model_sync_bundles", "model_sync_events", "node_model_sync_state")
M18_FUNCTIONS: tuple[str, ...] = ("m18_bundles_guard", "m18_events_guard", "m18_forbid_truncate")
M18_INDEXES: tuple[str, ...] = (
    "vendor_models_uq", "idx_vendor_models_lookup", "idx_vendor_models_state",
    "model_sync_bundles_version_uq", "idx_bundles_state_version", "idx_bundles_published",
    "model_sync_events_seq_key", "idx_model_sync_events_bundle", "idx_model_sync_events_event",
    "node_model_sync_state_pkey", "idx_node_model_sync_state_version",
    "vendor_models_pkey", "model_sync_bundles_pkey", "model_sync_events_pkey",
)

#: 账本对象（M18 **只读不写**；用于迁移 diff=0 的机器证明）
LEDGER_TABLES: tuple[str, ...] = (
    "journal_entry", "journal_line", "ledger_entry", "account_balances",
    "merkle_commitments", "m06_outbox", "loss_pool_entries")

NODE_PRINCIPAL: dict[str, Any] = {"node_id": "node-m18-alpha", "client_key_id": "kid-m18-1"}
OTHER_NODE_PRINCIPAL: dict[str, Any] = {"node_id": "node-m18-beta", "client_key_id": "kid-m18-2"}
ADMIN_PRINCIPAL: dict[str, Any] = {"admin_id": "admin-m18-1",
                                   "scopes": ["model_sync.read", "model_sync.write"]}
READONLY_PRINCIPAL: dict[str, Any] = {"admin_id": "admin-m18-ro", "scopes": ["model_sync.read"]}
NO_SCOPE_PRINCIPAL: dict[str, Any] = {"admin_id": "admin-m18-none", "scopes": []}


# ───────────────────────────────────────────────────────── 连接 / schema
def dsn() -> str:
    from tests.pgdsn import safe_dsn

    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（凭据只注入环境，不入库 / 不入提交）")
    return safe_dsn(value)


def connect(schema: str | None, *, autocommit: bool = True) -> psycopg.Connection:
    options = f"-c search_path={schema}" if schema else None
    return psycopg.connect(dsn(), autocommit=autocommit, options=options, connect_timeout=15,
                           application_name="m18-model-sync-tests")


def create_schema(name: str) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
        conn.execute(f'CREATE SCHEMA "{name}"')


def drop_schema(name: str) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')


# ───────────────────────────────────────────────────────── 迁移
def _number(name: str) -> int:
    head = name.split("_", 1)[0]
    return int(head) if head.isdigit() else -1


def _sorted(files: Iterable[pathlib.Path]) -> list[pathlib.Path]:
    return sorted(files, key=lambda path: (_number(path.name), path.name))


def all_migration_files() -> list[pathlib.Path]:
    return _sorted(MIGRATIONS_DIR.glob("*.sql"))


def base_migration_files() -> list[pathlib.Path]:
    """1800 段之前的所有迁移（= 升级演练的前置基线）。"""
    return [path for path in all_migration_files() if _number(path.name) < 1800]


def m18_migration_files() -> list[pathlib.Path]:
    return [path for path in all_migration_files() if 1800 <= _number(path.name) <= 1899]


def strip_transaction(sql: str) -> str:
    """只去掉文件**首尾**的 ``BEGIN;`` / ``COMMIT;``（在显式事务里应用 DDL 时不能提交外层）。"""
    lines = sql.splitlines()
    for index, line in enumerate(lines):
        if line.strip().upper() == "BEGIN;":
            lines.pop(index)
            break
    for index in range(len(lines) - 1, -1, -1):
        if lines[index].strip().upper() == "COMMIT;":
            lines.pop(index)
            break
    return "\n".join(lines)


def apply_migrations(schema: str, files: Iterable[pathlib.Path] | None = None, *,
                     strip_txn: bool = False) -> list[str]:
    applied: list[str] = []
    with connect(schema) as conn:
        for path in (files if files is not None else all_migration_files()):
            sql = path.read_text(encoding="utf-8")
            conn.execute(strip_transaction(sql) if strip_txn else sql)
            applied.append(path.name)
    return applied


# ───────────────────────────────────────────────────────── 结构 / 数据指纹
def table_names_on(conn: Any, schema: str) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname = %s", (schema,)).fetchall()}


def function_names_on(conn: Any, schema: str) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
        " WHERE n.nspname = %s", (schema,)).fetchall()}


def index_names_on(conn: Any, schema: str) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname = %s", (schema,)).fetchall()}


def relation_fingerprint_on(conn: Any, schema: str, tables: Iterable[str]) -> dict[str, str]:
    """表结构指纹：列（名/类型/非空/默认）+ 约束定义，逐表 md5。"""
    wanted = sorted(tables)
    result: dict[str, str] = {}
    columns = conn.execute(
        """
        SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod),
               a.attnotnull, COALESCE(pg_get_expr(d.adbin, d.adrelid), '')
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
        LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
        WHERE n.nspname = %s AND c.relname = ANY(%s)
        ORDER BY c.relname, a.attnum
        """, (schema, wanted)).fetchall()
    constraints = conn.execute(
        """
        SELECT c.relname, con.conname, pg_get_constraintdef(con.oid)
        FROM pg_constraint con
        JOIN pg_class c ON c.oid = con.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relname = ANY(%s)
        ORDER BY c.relname, con.conname
        """, (schema, wanted)).fetchall()
    buckets: dict[str, list[str]] = {name: [] for name in wanted}
    for table, name, type_name, not_null, default in columns:
        buckets.setdefault(table, []).append(f"col:{name}:{type_name}:{not_null}:{default}")
    for table, name, definition in constraints:
        buckets.setdefault(table, []).append(f"con:{name}:{definition}")
    for table, items in buckets.items():
        result[table] = hashlib.md5("\n".join(items).encode("utf-8")).hexdigest()
    return result


def ledger_snapshot(conn: Any, tables: Iterable[str] = LEDGER_TABLES) -> dict[str, dict[str, Any]]:
    """账本现状快照：行数 + 全行摘要（``t::text`` 按序拼接再 md5）。"""
    snapshot: dict[str, dict[str, Any]] = {}
    with conn.cursor() as cur:
        for table in tables:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            count = int(cur.fetchone()[0])
            cur.execute(
                f"SELECT COALESCE(md5(string_agg(t::text, '|' ORDER BY t::text)), '')"
                f" FROM {table} t")
            snapshot[table] = {"count": count, "digest": cur.fetchone()[0]}
    return snapshot


def apply_m18_in_transaction(conn: Any) -> list[str]:
    """在**当前事务**内应用 1800 段（DDL 可回滚；用于升级 / 回滚 / 账本 diff 演练）。"""
    applied: list[str] = []
    for path in m18_migration_files():
        conn.execute(strip_transaction(path.read_text(encoding="utf-8")))
        applied.append(path.name)
    return applied


def rollback_m18_in_transaction(conn: Any, times: int = 1) -> list[str]:
    """在同一事务内执行 DOWN_SQL（可重复；只删本模块对象）。"""
    from app.model_sync.migrate import DOWN_SQL

    removed: list[str] = []
    for _ in range(times):
        for name, sql in DOWN_SQL:
            conn.execute(strip_transaction(sql))
            removed.append(name)
    return removed


# ───────────────────────────────────────────────────────── 路由客户端
def savepoint_factory(connection: Any):
    """请求级连接：显式 SAVEPOINT（绝不提交外层事务）。"""

    counter = {"n": 0}

    @contextmanager
    def factory():
        counter["n"] += 1
        name = f"m18_req_{counter['n']}"
        connection.execute(f"SAVEPOINT {name}")
        try:
            yield connection
        except Exception:
            connection.execute(f"ROLLBACK TO SAVEPOINT {name}")
            raise
        else:
            connection.execute(f"RELEASE SAVEPOINT {name}")

    return factory


def build_client(connection: Any, monkeypatch: Any, *, node: Mapping[str, Any] | None = None,
                 admin: Mapping[str, Any] | None = None, feature: bool = True,
                 auto_publish: bool = False, signing_key: str | None = TEST_SIGNING_KEY,
                 now: datetime | None = None) -> Any:
    """构造带 M18 路由的 ASGI 客户端（SAVEPOINT 连接、时钟钉死、开关/密钥按需）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.model_sync import clock as clock_module
    from app.model_sync import facts, features as features_module, router as router_module

    monkeypatch.setattr(router_module, "_connection", savepoint_factory(connection))
    monkeypatch.setattr(clock_module, "utcnow", lambda: now or FIXED_NOW)
    monkeypatch.delenv(facts.ACTIVATION_ENV, raising=False)      # 环境变量不得污染用例
    enabled_names = {facts.ENABLED_FLAG} if feature else set()
    if auto_publish:
        enabled_names.add(facts.AUTO_PUBLISH_FLAG)
    monkeypatch.setattr(features_module, "enabled", lambda name: name in enabled_names)
    if signing_key is None:
        monkeypatch.delenv(facts.SIGNING_KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(facts.SIGNING_KEY_ENV, signing_key)

    router_module.set_node_authenticator(
        (lambda request: dict(node)) if node is not None else None)
    router_module.set_admin_authenticator(
        (lambda request: dict(admin)) if admin is not None else None)

    app = FastAPI()
    app.include_router(router_module.router)
    app.include_router(router_module.admin_router)
    return TestClient(app)


def reset_authenticators() -> None:
    from app.model_sync import router as router_module

    router_module.set_node_authenticator(None)
    router_module.set_admin_authenticator(None)


__all__ = [
    "FIXED_NOW", "TEST_SIGNING_KEY", "M18_TABLES", "M18_FUNCTIONS", "M18_INDEXES",
    "LEDGER_TABLES", "NODE_PRINCIPAL", "OTHER_NODE_PRINCIPAL", "ADMIN_PRINCIPAL",
    "READONLY_PRINCIPAL", "NO_SCOPE_PRINCIPAL",
    "dsn", "connect", "create_schema", "drop_schema",
    "all_migration_files", "base_migration_files", "m18_migration_files", "strip_transaction",
    "apply_migrations", "table_names_on", "function_names_on", "index_names_on",
    "relation_fingerprint_on", "ledger_snapshot", "apply_m18_in_transaction",
    "rollback_m18_in_transaction", "savepoint_factory", "build_client",
    "reset_authenticators", "uuid",
]
