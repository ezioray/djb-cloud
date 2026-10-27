# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/integrity 脚手架：schema 隔离 / 迁移三跑 / 账本指纹 / 路由客户端。

隔离约定（与 tests/supply / tests/risk 同款）：

* 每个测试进程独立 schema（``m17_t_<pid>_<hex>``，``M17_SCHEMA`` 可覆盖），结束 DROP；
* 迁移用 **同一份 migrations/*.sql** 执行（与 CI / `python -m app.integrity.migrate` 同路径）；
* 缺 ``DJB_DSN`` 时 DB 用例 skip（纯函数用例照跑）；
* 账本 diff 用「结构指纹 + 行摘要」两路：结构指纹抓列/约束，行摘要抓数据（都是 md5）。
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

import psycopg
from psycopg.rows import dict_row

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

FIXED_NOW = datetime(2026, 10, 24, 0, 0, tzinfo=timezone.utc)

M17_TABLES: tuple[str, ...] = (
    "supplier_integrity_holds", "supplier_integrity_events",          # 1710（C14 冻结）
    "supplier_integrity_appeals",                                    # 1712（C14 申诉）
    "model_attestations", "attestation_challenges", "attestation_events",  # 1720（C12 证明）
    "sampling_epochs", "sampling_draws", "sampling_events",           # 1730（C14b 抽检）
    "canary_prompts", "canary_runs", "canary_events",                 # 1740（C13 canary）
)
M17_VIEWS: tuple[str, ...] = ("v_supply_integrity_frozen", "v_supply_model_attested")
M17_FUNCTIONS: tuple[str, ...] = (
    "m17_holds_guard", "m17_events_guard", "m17_forbid_truncate",
    "m17_appeal_guard", "m17_appeals_forbid_truncate",
    "m17_attestation_guard", "m17_challenge_guard", "m17_attest_event_guard",
    "m17_attest_forbid_truncate",
    "m17_sampling_epoch_guard", "m17_sampling_draw_guard", "m17_sampling_event_guard",
    "m17_sampling_forbid_truncate",
    "m17_canary_prompt_guard", "m17_canary_run_guard", "m17_canary_event_guard",
    "m17_canary_forbid_truncate",
)
M17_INDEXES: tuple[str, ...] = (
    # 1710
    "uq_integrity_holds_active", "idx_integrity_holds_node", "idx_integrity_holds_level",
    "idx_integrity_holds_expiry", "idx_integrity_events_hold", "idx_integrity_events_node",
    "supplier_integrity_holds_pkey", "supplier_integrity_events_pkey",
    # 1712
    "uq_integrity_appeals_open", "idx_integrity_appeals_hold",
    "idx_integrity_appeals_node", "supplier_integrity_appeals_pkey",
    # 1720
    "uq_attestations_active", "idx_attestations_node", "idx_attestations_level",
    "idx_attestations_expiry", "idx_challenges_node", "idx_challenges_expiry",
    "idx_attestation_events_attestation", "idx_attestation_events_challenge",
    "idx_attestation_events_node", "model_attestations_pkey",
    "attestation_challenges_pkey", "attestation_challenges_nonce_key",
    "attestation_events_pkey",
    # 1730
    "uq_sampling_draws_epoch_node_model", "idx_sampling_epochs_state",
    "idx_sampling_draws_epoch", "idx_sampling_draws_node", "idx_sampling_draws_challenge",
    "idx_sampling_events_epoch", "idx_sampling_events_draw",
    "sampling_epochs_pkey", "sampling_epochs_epoch_no_key", "sampling_draws_pkey",
    "sampling_events_pkey",
    # 1740
    "idx_canary_prompts_state", "uq_canary_runs_issued", "idx_canary_runs_node",
    "idx_canary_runs_status", "idx_canary_runs_prompt", "idx_canary_events_run",
    "canary_prompts_pkey", "canary_prompts_prompt_key_key", "canary_runs_pkey",
    "canary_events_pkey",
)

ADMIN_PRINCIPAL = {
    "admin_id": "admin-integrity-1",
    "scopes": ["integrity.read", "integrity.write"],
}
HIGH_ADMIN_PRINCIPAL = {
    "admin_id": "admin-integrity-high",
    "scopes": ["integrity.read", "integrity.write", "integrity:release:high"],
}
NODE_PRINCIPAL = {"node_id": "node-alpha", "client_key_id": "kid-alpha-1"}
OTHER_NODE_PRINCIPAL = {"node_id": "node-beta", "client_key_id": "kid-beta-1"}


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
                           application_name="m17-integrity-tests")


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
    """1700 段之前的所有迁移（= 升级演练的前置基线）。"""
    return [path for path in all_migration_files() if _number(path.name) < 1700]


def m17_migration_files() -> list[pathlib.Path]:
    return [path for path in all_migration_files() if 1700 <= _number(path.name) <= 1799]


def strip_transaction(sql: str) -> str:
    """只去掉文件**首尾**的 ``BEGIN;`` / ``COMMIT;``（在显式事务里应用 DDL 时不能提交外层）。

    注意：不能按行全文过滤——PL/pgSQL 函数体里的 ``BEGIN`` 是语法必需（踩过一次）。
    """
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
# 说明：``*_on(conn, ...)`` 变体用**同一连接**内省——迁移 DDL 在事务里未提交时，
# 另开连接看不到，因此升级 / 回滚演练必须用同连接读取。
def table_names_on(conn: Any, schema: str) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname = %s", (schema,)).fetchall()}


def table_names(schema: str) -> set[str]:
    with connect(schema) as conn:
        return table_names_on(conn, schema)


def function_names_on(conn: Any, schema: str) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
        " WHERE n.nspname = %s", (schema,)).fetchall()}


def function_names(schema: str) -> set[str]:
    with connect(schema) as conn:
        return function_names_on(conn, schema)


def index_names_on(conn: Any, schema: str) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname = %s", (schema,)).fetchall()}


def index_names(schema: str) -> set[str]:
    with connect(schema) as conn:
        return index_names_on(conn, schema)


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


def relation_fingerprint(schema: str, tables: Iterable[str]) -> dict[str, str]:
    with connect(schema) as conn:
        return relation_fingerprint_on(conn, schema, tables)


def ledger_snapshot(conn: Any, tables: Iterable[str]) -> dict[str, dict[str, Any]]:
    """账本现状快照：行数 + 全行摘要（``t::text`` 按序拼接再 md5）。

    冻结/解除前后必须完全相同（M17 §6.1「不改账本」的机器证明）。
    """
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


def apply_m17_in_transaction(conn: Any) -> list[str]:
    """在**当前事务**内应用 1710（DDL 可回滚；用于升级 / 回滚 / 账本 diff 演练）。"""
    applied: list[str] = []
    for path in m17_migration_files():
        conn.execute(strip_transaction(path.read_text(encoding="utf-8")))
        applied.append(path.name)
    return applied


def rollback_m17_in_transaction(conn: Any, times: int = 1) -> list[str]:
    """在同一事务内执行 DOWN_SQL（可重复；只删本模块对象）。"""
    from app.integrity.migrate import DOWN_SQL

    removed: list[str] = []
    for _ in range(times):
        for name, sql in DOWN_SQL:
            conn.execute(strip_transaction(sql))
            removed.append(name)
    return removed


# ───────────────────────────────────────────────────────── 路由客户端
def savepoint_factory(connection: Any):
    """请求级连接：显式 SAVEPOINT（绝不提交外层事务，用例结束统一回滚）。

    不用 ``connection.transaction()``：当外层连接**还没有**活动事务时，psycopg 会自己
    BEGIN + COMMIT，把测试数据真提交进共享 schema（2026-10-24 踩过）。这里强制用
    ``SAVEPOINT / RELEASE / ROLLBACK TO``，事务边界永远由用例持有。
    """

    counter = {"n": 0}

    @contextmanager
    def factory():
        counter["n"] += 1
        name = f"m17_req_{counter['n']}"
        connection.execute(f"SAVEPOINT {name}")
        try:
            yield connection
        except Exception:
            connection.execute(f"ROLLBACK TO SAVEPOINT {name}")
            raise
        else:
            connection.execute(f"RELEASE SAVEPOINT {name}")

    return factory


def build_client(connection: Any, monkeypatch: Any, *, admin: Mapping[str, Any] | None = None,
                 now: datetime | None = None, feature: bool = True) -> Any:
    """构造带 M17 路由的 ASGI 客户端（连接指向 SAVEPOINT、时钟钉死、开关按需）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.integrity import clock as clock_module
    from app.integrity import holds as holds_module
    from app.integrity import router as router_module

    monkeypatch.setattr(router_module, "_connection", savepoint_factory(connection))
    monkeypatch.setattr(clock_module, "utcnow", lambda: now or FIXED_NOW)
    monkeypatch.setattr(holds_module.features, "enabled", lambda name: feature)
    router_module.set_admin_authenticator(
        (lambda request: dict(admin)) if admin is not None else None)
    app = FastAPI()
    app.include_router(router_module.router)
    return TestClient(app)


def hold_args(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "node_id": "node-alpha",
        "model": "openai/gpt-4o",
        "level": "I1",
        "base_amount_micro": 1_000_000,
        "reason": "tokenizer_mismatch",
        "evidence_ref": "risk-case-0001",
        "actor": "risk-bot",
    }
    values.update(overrides)
    return values


def build_attest_client(connection: Any, monkeypatch: Any, *, node: Mapping[str, Any] | None = None,
                        admin: Mapping[str, Any] | None = None,
                        now: datetime | None = None, feature: bool = True) -> Any:
    """构造带 C12 证明路由的 ASGI 客户端（SAVEPOINT 连接、时钟钉死、开关按需）。

    ``node=None`` / ``admin=None`` 表示**不注入鉴权钩子**（fail-closed → 401）。
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.integrity import attest_router
    from app.integrity import clock as clock_module
    from app.integrity import features

    monkeypatch.setattr(attest_router, "_connection", savepoint_factory(connection))
    monkeypatch.setattr(clock_module, "utcnow", lambda: now or FIXED_NOW)
    monkeypatch.setattr(features, "enabled", lambda name: feature)
    attest_router.set_node_authenticator(
        (lambda request: dict(node)) if node is not None else None)
    attest_router.set_admin_authenticator(
        (lambda request: dict(admin)) if admin is not None else None)
    app = FastAPI()
    app.include_router(attest_router.router)
    return TestClient(app)


SAMPLING_ADMIN_PRINCIPAL = {
    "admin_id": "admin-sampling-1",
    "scopes": ["integrity.read", "integrity.write"],
}


def build_sampling_client(connection: Any, monkeypatch: Any, *,
                          admin: Mapping[str, Any] | None = None,
                          now: datetime | None = None, feature: bool = True) -> Any:
    """构造带 C14b 抽检路由的 ASGI 客户端（SAVEPOINT 连接、时钟钉死、开关按需）。

    ``admin=None`` 表示**不注入鉴权钩子**（fail-closed → 401）。
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.integrity import clock as clock_module
    from app.integrity import features, sampling_router

    monkeypatch.setattr(sampling_router, "_connection", savepoint_factory(connection))
    monkeypatch.setattr(clock_module, "utcnow", lambda: now or FIXED_NOW)
    monkeypatch.setattr(features, "enabled", lambda name: feature)
    sampling_router.set_admin_authenticator(
        (lambda request: dict(admin)) if admin is not None else None)
    app = FastAPI()
    app.include_router(sampling_router.router)
    return TestClient(app)


def sampling_contributions(*rows: tuple[str, str, int]) -> list[dict[str, Any]]:
    return [{"node_id": node, "model": model, "weight": weight}
            for node, model, weight in rows]


CANARY_ADMIN_PRINCIPAL = {
    "admin_id": "admin-canary-1",
    "scopes": ["integrity.read", "integrity.write"],
}


def build_canary_client(connection: Any, monkeypatch: Any, *,
                        admin: Mapping[str, Any] | None = None,
                        now: datetime | None = None, feature: bool = True) -> Any:
    """构造带 C13 canary 路由的 ASGI 客户端（SAVEPOINT 连接、时钟钉死、开关按需）。

    ``admin=None`` 表示**不注入鉴权钩子**（fail-closed → 401）。
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.integrity import canary_router
    from app.integrity import clock as clock_module
    from app.integrity import features

    monkeypatch.setattr(canary_router, "_connection", savepoint_factory(connection))
    monkeypatch.setattr(clock_module, "utcnow", lambda: now or FIXED_NOW)
    monkeypatch.setattr(features, "enabled", lambda name: feature)
    canary_router.set_admin_authenticator(
        (lambda request: dict(admin)) if admin is not None else None)
    app = FastAPI()
    app.include_router(canary_router.router)
    return TestClient(app)
