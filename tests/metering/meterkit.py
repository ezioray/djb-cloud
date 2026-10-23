# SPDX-License-Identifier: Apache-2.0
"""DEV-M05 T1+T2 测试工具：迁移执行、schema 隔离、夹具（节点 / 账户 / 收据 / 签名）。

只读契约（本文件不改实现代码）：

* 迁移文件是唯一 DDL 来源，测试只用 ``psql -f`` 执行它们，不在 Python 里手写建表语句；
* 每个 schema 独立（``m05_t12_<pid>_<hex>``），结束 ``DROP SCHEMA ... CASCADE``；
  不读写 public，也不碰别人的 schema；
* 签名密钥是**测试夹具**（固定字面量、明显非生产），生产密钥只以引用注入；
* 固定时钟：``NOW`` 常量 + 显式 ``now=`` 参数，不依赖墙上时间（00-conventions §10）。
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

import psycopg
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "migrations"

M05_MIGRATIONS = (
    "501_usage_records.sql",
    "502_metering_receipts.sql",
    "503_usage_corrections.sql",
    "504_upstream_bills.sql",
    "505_loss_pool_entries.sql",
    "506_metering_outbox.sql",
    "507_usage_corrections_request_key.sql",
    "508_usage_state_settled_to_corrected.sql",
    "509_corrections_review_check.sql",
)
M05_TABLES = ("usage_records", "metering_receipts", "usage_corrections", "upstream_bills",
              "loss_pool_entries", "metering_outbox")
#: 跨模块只读视图（01-ownership §2 / 00-conventions §7.4）
SUPPLY_VIEWS = ("v_supply_node_snapshot", "v_supply_capacity_latest")
IDENTITY_VIEWS = ("v_identity_accounts",)
#: 被 M05 只读依赖、但**不允许**直读的上游基表（架构门禁反例清单）
UPSTREAM_BASE_TABLES = ("nodes", "capacity_announcements", "user_accounts", "tenant_quotas",
                        "journal_entry", "journal_line", "ledger_entry", "config_items",
                        "receipts", "node_receipts", "accounts")

#: 固定时钟（UTC 04:00 = UTC+4 的 08:00，避开日界）
NOW = datetime(2026, 10, 23, 4, 0, 0, tzinfo=timezone.utc)

#: 测试用两侧密钥（**夹具**：固定字面量，长度 ≥32 字节、彼此不同；不是生产凭据）
TEST_PROVIDER_KEY = b"m05-t12-provider-fixture-key-0123456789abcdef"
TEST_CONSUMER_KEY = b"m05-t12-consumer-fixture-key-fedcba9876543210"


# ─────────────────────────────────────────────────────── 连接与迁移
def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（见 product/v4/modules/W1-EXECUTION-PLAN.md §3）")
    return value


def _admin_connect() -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m05-t12-tests")


def connect(schema: str, autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m05-t12-tests",
                           options=f"-c search_path={schema} -c synchronous_commit=off")


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
            cur.execute("SET statement_timeout = '180s'")
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


def prerequisite_files() -> list[pathlib.Path]:
    """前置段：编号 < 500 的全部迁移（空库三跑 / 升级基线用）。"""
    return [path for path in migration_files() if migration_number(path) < 500]


def m05_migration_files() -> list[pathlib.Path]:
    return [MIGRATIONS_DIR / name for name in M05_MIGRATIONS]


def run_migrations(paths: Sequence[pathlib.Path], schema: str) -> subprocess.CompletedProcess:
    """一个 psql 进程按序执行多个文件（同一连接），省掉每文件一次进程启动。"""
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema} -c synchronous_commit=off")
    args = ["psql", dsn(), "-v", "ON_ERROR_STOP=1", "-q"]
    for path in paths:
        args += ["-f", str(path)]
    return subprocess.run(args, capture_output=True, text=True, env=env, timeout=300)


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
    return list(conn.execute(sql, params).fetchall())


def table_names(schema: str) -> set[str]:
    with connect(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT table_name FROM information_schema.tables"
                  " WHERE table_schema = %s AND table_type = 'BASE TABLE'", (schema,))}


def view_names(schema: str) -> set[str]:
    with connect(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT table_name FROM information_schema.views WHERE table_schema = %s",
            (schema,))}


def column_names(schema: str, table: str) -> set[str]:
    with connect(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT column_name FROM information_schema.columns"
                  " WHERE table_schema = %s AND table_name = %s", (schema, table))}


def index_names(schema: str) -> set[str]:
    with connect(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT indexname FROM pg_indexes WHERE schemaname = %s", (schema,))}


def trigger_names(schema: str) -> set[str]:
    with connect(schema) as conn:
        return {row[0] for row in _rows(
            conn, """SELECT t.tgname FROM pg_trigger t
                       JOIN pg_class c ON c.oid = t.tgrelid
                       JOIN pg_namespace n ON n.oid = c.relnamespace
                      WHERE n.nspname = %s AND NOT t.tgisinternal""", (schema,))}


def function_names(schema: str) -> set[str]:
    with connect(schema) as conn:
        return {row[0] for row in _rows(
            conn, """SELECT p.proname FROM pg_proc p
                       JOIN pg_namespace n ON n.oid = p.pronamespace
                      WHERE n.nspname = %s""", (schema,))}


_FINGERPRINT_SQL = {
    "columns": """
        SELECT table_name || '.' || column_name || ':' || data_type || ':' || is_nullable
               || ':' || COALESCE(column_default, '-')
          FROM information_schema.columns
         WHERE table_schema = %(s)s AND table_name = ANY(%(tables)s) ORDER BY 1""",
    "constraints": """
        SELECT c.relname || '.' || con.conname || ':' || pg_get_constraintdef(con.oid)
          FROM pg_constraint con
          JOIN pg_class c ON c.oid = con.conrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %(s)s AND c.relname = ANY(%(tables)s) ORDER BY 1""",
    "indexes": """
        SELECT indexname || ':' || indexdef FROM pg_indexes
         WHERE schemaname = %(s)s AND tablename = ANY(%(tables)s) ORDER BY 1""",
    "triggers": """
        SELECT t.tgname || ':' || c.relname || ':' || pg_get_triggerdef(t.oid)
          FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %(s)s AND NOT t.tgisinternal AND c.relname = ANY(%(tables)s)
         ORDER BY 1""",
}


def fingerprint(schema: str, tables: Sequence[str]) -> dict[str, list[str]]:
    """上游对象的结构指纹（升级前后对比用；只读）。"""
    result: dict[str, list[str]] = {}
    with connect(schema) as conn:
        for key, template in _FINGERPRINT_SQL.items():
            result[key] = [row[0] for row in _rows(conn, template,
                                                   {"s": schema, "tables": list(tables)})]
    return result


# ─────────────────────────────────────────────────────── 夹具：M01 账户 / M02 节点
def seed_account(schema: str, account_id: uuid.UUID | None = None, *, state: str = "normal",
                 tenant_id: uuid.UUID | None = None) -> uuid.UUID:
    """写一个 M01 用户账户（personal：tenant_id = id）；M05 只读依赖，测试里直接种。"""
    identifier = account_id or uuid.uuid4()
    user_id = uuid.uuid4()
    with connect(schema) as conn:
        conn.execute("INSERT INTO users (id, display_name) VALUES (%s, %s)",
                     (user_id, "m05-test-user"))
        conn.execute(
            """INSERT INTO user_accounts (id, user_id, type, state, tenant_id)
               VALUES (%s, %s, 'personal', %s, %s)""",
            (identifier, user_id, state, tenant_id or identifier))
    return identifier


def seed_node(schema: str, node_id: str | None = None, *, state: str = "active",
              account_id: uuid.UUID | None = None) -> str:
    """写一个 M02 节点（M05 只经只读视图校验存在性；测试里直接种基表）。"""
    identifier = node_id or f"n_{uuid.uuid4().hex[:10]}"
    with connect(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash, last_seen_at,
                                  account_id)
               VALUES (%s, 'linux', %s, '0.1.0', '1.2.0', %s, %s, %s, %s, %s)""",
            (identifier, uuid.uuid4().hex, state, identifier[:8],
             uuid.uuid4().hex, NOW, account_id))
    return identifier


# ─────────────────────────────────────────────────────── 夹具：收据 + 签名
def receipt(*, receipt_id: str | None = None, task_id: str = "task-1", access: str = "A1",
            usage_amount: str = "1500", usage_unit: str = "token", price_amount: str = "1.25",
            price_unit: str = "USD", tokens_in: int = 1000, tokens_out: int = 500,
            request_id: str | None = None, model: str = "m1", attempt_no: int = 1,
            account_id: uuid.UUID | str | None = None, node_id: str | None = None,
            usage_source: str | None = None, reported_at: datetime | None = None,
            provider_key: bytes | None = None, consumer_key: bytes | None = None,
            sig_provider: str | None = None, sig_consumer: str | None = None,
            shape: str = "nested") -> dict[str, Any]:
    """造一条 spec ``ReceiptInput``（默认**已签好**）；``shape="flat"`` 用 M05 §8.2 扁平写法。"""
    from app.metering import signing

    fields = {
        "receipt_id": receipt_id or f"rcpt_{uuid.uuid4().hex[:16]}",
        "task_id": task_id, "access": access, "usage_amount": usage_amount,
        "usage_unit": usage_unit, "price_amount": price_amount,
    }
    keys = signing.SignatureKeys(provider_key or TEST_PROVIDER_KEY,
                                 consumer_key or TEST_CONSUMER_KEY)
    signatures = signing.sign(fields, keys)
    body: dict[str, Any] = {
        "receipt_id": fields["receipt_id"], "task_id": task_id, "access": access,
        "request_id": request_id or f"req_{uuid.uuid4().hex[:16]}", "model": model,
        "tokens_in": tokens_in, "tokens_out": tokens_out, "attempt_no": attempt_no,
        "sig_provider": sig_provider if sig_provider is not None
        else signatures["sig_provider"],
        "sig_consumer": sig_consumer if sig_consumer is not None
        else signatures["sig_consumer"],
    }
    if shape == "flat":
        body.update({"usage_amount": usage_amount, "usage_unit": usage_unit,
                     "price_amount": price_amount})
    else:
        body["usage"] = {"amount": usage_amount, "unit": usage_unit}
        body["price"] = {"amount": price_amount, "unit": price_unit}
    if account_id is not None:
        body["account_id"] = str(account_id)
    if node_id is not None:
        body["node_id"] = node_id
    if usage_source is not None:
        body["usage_source"] = usage_source
    if reported_at is not None:
        body["reported_at"] = reported_at.isoformat().replace("+00:00", "Z")
    return body


def resign(body: dict[str, Any], *, provider_key: bytes | None = None,
           consumer_key: bytes | None = None) -> dict[str, Any]:
    """对（可能被改过的）收据重新签名——用于「金额被篡改」类用例。"""
    from app.metering import signing

    usage = body.get("usage") or {}
    price = body.get("price") or {}
    fields = {
        "receipt_id": body["receipt_id"], "task_id": body["task_id"],
        "access": body["access"],
        "usage_amount": body.get("usage_amount", usage.get("amount")),
        "usage_unit": body.get("usage_unit", usage.get("unit")),
        "price_amount": body.get("price_amount", price.get("amount")),
    }
    keys = signing.SignatureKeys(provider_key or TEST_PROVIDER_KEY,
                                 consumer_key or TEST_CONSUMER_KEY)
    body.update(signing.sign(fields, keys))
    return body


def api_headers(**extra: str) -> dict[str, str]:
    """默认请求头（`X-Request-Id` 便于日志对齐）。"""
    headers = {"X-Request-Id": f"req-{uuid.uuid4().hex[:12]}"}
    headers.update({key: value for key, value in extra.items() if value})
    return headers


def hours_ago(hours: float, *, now: datetime = NOW) -> datetime:
    return now - timedelta(hours=hours)


def fetch_all(schema: str, sql: str, params: Any = ()) -> list[tuple]:
    with connect(schema) as conn:
        return _rows(conn, sql, params)


def count(schema: str, table: str) -> int:
    rows = fetch_all(schema, f"SELECT count(*) FROM {table}")
    return int(rows[0][0])


__all__ = [
    "ROOT", "MIGRATIONS_DIR", "M05_MIGRATIONS", "M05_TABLES", "SUPPLY_VIEWS", "IDENTITY_VIEWS",
    "UPSTREAM_BASE_TABLES", "NOW", "TEST_PROVIDER_KEY", "TEST_CONSUMER_KEY", "dsn", "connect",
    "create_schema", "drop_schema", "migration_number", "migration_files", "prerequisite_files",
    "m05_migration_files", "run_migrations", "apply_migrations", "table_names", "view_names",
    "column_names", "index_names", "trigger_names", "function_names", "fingerprint",
    "seed_account", "seed_node", "receipt", "resign", "api_headers", "hours_ago", "fetch_all",
    "count",
]
