# SPDX-License-Identifier: Apache-2.0
"""tests/risk 脚手架：schema 隔离 / 迁移三跑 / 行检查 / 夹具构造 / 阈值扫描。

隔离约定（与 tests/recon 同款）：

* 每个测试进程独立 schema 前缀（``m11_t_<pid>_<hex>``，``M11_SCHEMA`` 可覆盖），结束 DROP；
* 迁移用 psycopg 逐文件执行（与 ``python -m app.risk.migrate`` 同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑；
* 覆盖率（``M11_COVERAGE=1``）必须在导入 ``app.risk`` **之前**启动（见 conftest.py 顶部）。
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

import psycopg
from psycopg.rows import dict_row

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

M11_TABLES: tuple[str, ...] = (
    "risk_rules", "risk_limits", "risk_cases", "risk_appeals", "risk_events", "risk_outbox",
)
M11_VIEWS: tuple[str, ...] = ("v_risk_limits", "v_risk_case_summary")

#: 阈值 / 权重 / 名单 / PII 的**键名**（INV-01 / INV-05 扫描口径）
FORBIDDEN_KEY_RE = re.compile(
    r"(threshold|weight|blocklist|blacklist|allowlist|whitelist|score_weight|"
    r"rule_score|(^|_)score($|_)|(^|_)ip($|_)|email|phone|card_no|(^|_)pan($|_))",
    re.IGNORECASE)
#: 阈值数值常见形态（浮点字面量）——app/risk 里一个都不该有
FLOAT_LITERAL_RE = re.compile(r"(?<![\w.])-?\d+\.\d+(?![\w.])")

FIXED_NOW = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)


# ───────────────────────────────────────────────────────────── 连接 / schema
def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库 / 不入提交）")
    return value


def connect(schema: str, *, autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=autocommit,
                           options=f"-c search_path={schema}", connect_timeout=15,
                           application_name="m11-risk-tests")


@contextmanager
def session(schema: str):
    connection = connect(schema)
    try:
        yield connection
    finally:
        connection.close()


def create_schema(schema: str) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')


def drop_schema(schema: str) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


# ───────────────────────────────────────────────────────────── 迁移
def _number(name: str) -> int:
    head = name.split("_", 1)[0]
    return int(head) if head.isdigit() else -1


def _sorted(files: Iterable[pathlib.Path]) -> list[pathlib.Path]:
    return sorted(files, key=lambda path: (_number(path.name), path.name))


def all_migration_files() -> list[pathlib.Path]:
    return _sorted(MIGRATIONS_DIR.glob("*.sql"))


def m11_migration_files() -> list[pathlib.Path]:
    return [path for path in all_migration_files() if 1100 <= _number(path.name) <= 1199]


def prerequisite_files() -> list[pathlib.Path]:
    return [path for path in all_migration_files() if _number(path.name) < 1100]


def apply_migrations(schema: str, files: Iterable[pathlib.Path] | None = None) -> list[str]:
    applied: list[str] = []
    with connect(schema) as conn:
        for path in (files if files is not None else all_migration_files()):
            conn.execute(path.read_text(encoding="utf-8"))
            applied.append(path.name)
    return applied


def apply_m11_twice(schema: str) -> None:
    """11xx 连跑两遍（幂等验证）。"""
    for _ in range(2):
        apply_migrations(schema, m11_migration_files())


# ───────────────────────────────────────────────────────────── 结构读取
def table_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = %s", (schema,))
        return {row[0] for row in cur.fetchall()}


def view_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT viewname FROM pg_views WHERE schemaname = %s", (schema,))
        return {row[0] for row in cur.fetchall()}


def index_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname = %s", (schema,))
        return {row[0] for row in cur.fetchall()}


def trigger_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
            " JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = %s AND NOT t.tgisinternal", (schema,))
        return {row[0] for row in cur.fetchall()}


def column_signature(schema: str, tables: Iterable[str] | None = None) -> dict[str, Any]:
    """列 + 类型 + nullability 签名（用于「回滚不动前置表」断言）。"""
    names = sorted(tables) if tables is not None else sorted(table_names(schema))
    signature: dict[str, Any] = {}
    with session(schema) as conn, conn.cursor(row_factory=dict_row) as cur:
        for table in names:
            cur.execute(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns"
                " WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (schema, table))
            signature[table] = [dict(row) for row in cur.fetchall()]
    return signature


def constraint_signature(schema: str, tables: Iterable[str] | None = None) -> dict[str, Any]:
    names = sorted(tables) if tables is not None else sorted(table_names(schema))
    signature: dict[str, Any] = {}
    with session(schema) as conn, conn.cursor(row_factory=dict_row) as cur:
        for table in names:
            cur.execute(
                "SELECT conname, contype FROM pg_constraint c"
                " JOIN pg_class r ON r.oid = c.conrelid"
                " JOIN pg_namespace n ON n.oid = r.relnamespace"
                " WHERE n.nspname = %s AND r.relname = %s ORDER BY conname",
                (schema, table))
            signature[table] = [dict(row) for row in cur.fetchall()]
    return signature


def table_columns(schema: str) -> list[dict[str, Any]]:
    with session(schema) as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT table_name, column_name, data_type FROM information_schema.columns"
            " WHERE table_schema = %s AND table_name LIKE 'risk\\_%%' ORDER BY table_name,"
            " ordinal_position", (schema,))
        return [dict(row) for row in cur.fetchall()]


# ───────────────────────────────────────────────────────────── 夹具构造
def make_case(conn: psycopg.Connection, *, tenant_id: str = "tenant-a",
              subject_hash: str = "sha256:" + "a" * 64,
              risk_type: str = "self_trade", severity: str = "P2", status: str = "opened",
              evidence: tuple[str, ...] = ("evt-0001",), opened_by: str = "maker",
              decided_by: str | None = None, decided_at: datetime | None = None,
              rule_key: str | None = "self_trade.ratio", rule_version: int | None = 1,
              config_ref: str | None = "risk.case.auto_action",
              case_id: str | None = None) -> dict[str, Any]:
    """直接落一条案件（可指定状态 / 处置人）；用于 HTTP / 申诉夹具。"""
    from app.risk import ids

    identifier = case_id or str(ids.uuid7())
    entry = {
        "action": "freeze", "reason": "seed", "evidence_refs": list(evidence),
        "decided_by": decided_by or "disposer", "decided_at": None,
        "expires_at": None, "proposal_id": None, "idempotency_key": None,
    }
    decisions = [entry] if status not in ("opened",) else []
    closed_at = decided_at if status in ("closed", "merged", "dismissed") else None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO risk_cases (case_id, tenant_id, subject_type, subject_hash, risk_type,
                                    severity, status, rule_key, rule_version, config_ref,
                                    evidence_refs, decision, decisions, decided_by, decided_at,
                                    opened_by, opened_at, closed_at)
            VALUES (%s, %s, 'account', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s,
                    %s, %s, %s)
            RETURNING *
            """,
            (identifier, tenant_id, subject_hash, risk_type, severity, status, rule_key,
             rule_version, config_ref, list(evidence),
             "freeze" if decisions else None, json.dumps(decisions), decided_by, decided_at,
             opened_by, FIXED_NOW, closed_at))
        return dict(cur.fetchone())


def make_appeal(conn: psycopg.Connection, case_id: str, *, tenant_id: str = "tenant-a",
                status: str = "submitted", submitted_at: datetime | None = None,
                sla_due: datetime | None = None, reason: str = "误伤",
                decided_by: str | None = None, decided_at: datetime | None = None,
                outcome: str | None = None) -> dict[str, Any]:
    from app.risk import ids

    moment = submitted_at or FIXED_NOW
    due = sla_due or (moment + timedelta(days=7))
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO risk_appeals (appeal_id, case_id, tenant_id, status, reason,
                                      submitted_at, sla_due, outcome, decided_by, decided_at,
                                      closed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (str(ids.uuid7()), case_id, tenant_id, status, reason, moment, due, outcome,
             decided_by, decided_at, decided_at if outcome else None))
        return dict(cur.fetchone())


# ───────────────────────────────────────────────────────────── 扫描辅助
def find_forbidden_keys(value: Any, *, path: str = "$") -> list[tuple[str, str]]:
    """递归找禁止键（阈值 / 权重 / 名单 / PII），返回 ``(path, key)``。"""
    hits: list[tuple[str, str]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_path = f"{path}.{key}"
            if FORBIDDEN_KEY_RE.search(str(key)):
                hits.append((key_path, str(key)))
            hits.extend(find_forbidden_keys(child, path=key_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            hits.extend(find_forbidden_keys(child, path=f"{path}[{index}]"))
    return hits


def outbox_events(conn: psycopg.Connection) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM risk_outbox ORDER BY id")
        return [dict(row) for row in cur.fetchall()]


def risk_values(conn: psycopg.Connection, table: str) -> list[str]:
    """把一张 risk_* 表的全部标量值转成字符串（扫描阈值 / PII 用）。"""
    values: list[str] = []
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT * FROM {table}")
        for row in cur.fetchall():
            for value in row.values():
                if value is None:
                    continue
                if isinstance(value, (dict, list)):
                    values.append(json.dumps(value, ensure_ascii=False, default=str))
                else:
                    values.append(str(value))
    return values

# ─────────────────────────────────────────────────────── M11 HTTP 客户端（DEV-TESTINFRA）
# 由 conftest 移到 kit（原因同 reconkit）：测试文件与 conftest 都从这里导入。
ADMIN_PRINCIPAL = {"admin_id": "disposer", "tenant_id": "tenant-a",
                   "scopes": ["risk.read", "risk.write"]}
READONLY_PRINCIPAL = {"admin_id": "auditor", "tenant_id": "tenant-a", "scopes": ["risk.read"]}
OTHER_TENANT_PRINCIPAL = {"admin_id": "disposer-b", "tenant_id": "tenant-b",
                          "scopes": ["risk.read", "risk.write"]}


def savepoint_factory(connection):
    """把一条连接包成 handler 需要的请求级连接（内层 SAVEPOINT，不真提交）。"""

    @contextmanager
    def factory():
        with connection.transaction():
            yield connection

    return factory


def build_client(connection, *, admin=ADMIN_PRINCIPAL, step_up=True, now=None,
                 config_provider=None, audit_sink=None):
    """构造带 M11 路由的 ASGI 客户端（请求级 SAVEPOINT，不真提交）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.risk.router import create_router

    moment = now or FIXED_NOW
    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(connection),
        admin_resolver=(lambda request: dict(admin)) if admin is not None else None,
        step_up_verifier=(lambda request: step_up) if step_up is not None else None,
        now_provider=lambda: moment,
        config_provider=(lambda: config_provider) if config_provider is not None else None,
        audit_sink=audit_sink,
    ))
    return TestClient(app)
