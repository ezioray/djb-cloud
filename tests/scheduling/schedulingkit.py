# SPDX-License-Identifier: Apache-2.0
"""tests/scheduling 测试工具：迁移执行、结构指纹、节点 / 容量 / 账户夹具。

只读契约：

* 迁移文件是唯一 DDL 来源，测试只用 ``psql -f`` 执行（与 CI / 生产同一条路径），
  不在 Python 里手写建表语句；
* 每个测试进程用独立 schema（默认 ``m04_t12_<pid>_<hex>``，``M04_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不读写 public，也不碰别人的 schema；
* 缺 ``DJB_DSN`` 或库不可达时 DB 用例 skip（纯函数用例照跑）。

夹具只写**依赖模块**的表（M01 ``users`` / ``user_accounts``、M02 ``nodes`` /
``capacity_announcements``）——这是测试在扮演上游，不是 M04 在写别人的表。
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

import psycopg
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "migrations"

#: 本模块的迁移（401–409）
M04_MIGRATIONS = (
    "401_quotes.sql",
    "402_bids.sql",
    "403_bookings.sql",
    "404_routing_decisions.sql",
    "405_quota_usage.sql",
    "406_model_catalog.sql",
    "407_scheduling_outbox.sql",
    "408_scheduling_idempotency.sql",
    "409_quota_fairness.sql",
)

#: M04 拥有的表（01-ownership §2 + M04 §5 + CR-4/CR-5 登记的辅助表）
M04_TABLES = ("quotes", "bids", "bookings", "routing_decisions", "quota_usage",
              "model_catalog", "scheduling_outbox", "scheduling_idempotency")

#: 本模块新增的函数（触发器函数）
M04_FUNCTIONS = ("m04_quotes_guard", "m04_bids_guard", "m04_bookings_guard",
                 "m04_routing_decisions_guard", "m04_quota_usage_guard", "m04_outbox_guard",
                 "m04_idempotency_guard")

#: 前置段（编号 ≤ 499）里必须存在的对象（升级测试要在这些对象上证明「只加不改」）
BASE_TABLES = ("nodes", "capacity_announcements", "users", "user_accounts", "api_keys",
               "tenant_quotas")

#: M02 提供给 M04 的只读视图（M04 只能读它们，不能读 nodes 基表）
SUPPLY_VIEWS = ("v_supply_node_snapshot", "v_supply_capacity_latest",
                "v_supply_upstream_verified")


# ─────────────────────────────────────────────────────── 连接与迁移
def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（见 W1-EXECUTION-PLAN §3）")
    return value


def connect(schema: str, autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m04-t12-tests",
                           options=f"-c search_path={schema} -c synchronous_commit=off")


@contextmanager
def session(schema: str):
    """autocommit 只读 / 单语句会话；退出即 close。"""
    conn = connect(schema, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def _admin_connect() -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m04-t12-tests")


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


def m04_migration_files() -> list[pathlib.Path]:
    return [MIGRATIONS_DIR / name for name in M04_MIGRATIONS]


def prerequisite_files(to: int = 499) -> list[pathlib.Path]:
    """前置段：编号 ≤ ``to`` 且不属于 4xx 的全部迁移（空库三跑用）。"""
    return [path for path in migration_files() if migration_number(path) <= to]


def base_migration_files() -> list[pathlib.Path]:
    """升级测试的基线：不跑 4xx 的其它迁移。"""
    return [path for path in migration_files() if not re.match(r"^4\d\d_", path.name)]


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
    return list(conn.execute(sql, params).fetchall())


def table_names(schema: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT table_name FROM information_schema.tables"
                  " WHERE table_schema = %s AND table_type = 'BASE TABLE'", (schema,))}


def view_names(schema: str) -> set[str]:
    with session(schema) as conn:
        return {row[0] for row in _rows(
            conn, "SELECT table_name FROM information_schema.views WHERE table_schema = %s",
            (schema,))}


def column_names(schema: str, table: str) -> set[str]:
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
    filters = {"table_filter": "", "rel_filter": "", "index_filter": ""}
    params: dict[str, Any] = {"s": schema}
    if tables is not None:
        params["tables"] = list(tables)
        filters = {"table_filter": "AND table_name = ANY(%(tables)s)",
                   "rel_filter": "AND c.relname = ANY(%(tables)s)",
                   "index_filter": "AND tablename = ANY(%(tables)s)"}
    result: dict[str, list[str]] = {}
    with session(schema) as conn:
        for key, template in _FINGERPRINT_SQL.items():
            if tables is not None and key == "functions":
                continue
            result[key] = [row[0] for row in _rows(conn, template.format(**filters), params)]
    return result


# ─────────────────────────────────────────────────────── 夹具（扮演上游模块）
NOW = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)


def seed_tenant(schema: str, tenant_id: uuid.UUID | None = None) -> uuid.UUID:
    """种一个租户（M01 ``user_accounts``；M04 只通过注入 provider 使用 tenant_id）。"""
    identifier = tenant_id or uuid.uuid4()
    user_id = uuid.uuid4()
    with session(schema) as conn:
        conn.execute("INSERT INTO users (id, display_name) VALUES (%s, %s) "
                     "ON CONFLICT (id) DO NOTHING", (user_id, f"user-{user_id.hex[:8]}"))
        conn.execute(
            """INSERT INTO user_accounts (id, user_id, type, state, tenant_id)
               VALUES (%s, %s, 'personal', 'normal', %s) ON CONFLICT (id) DO NOTHING""",
            (identifier, user_id, identifier))
    return identifier


def seed_node(schema: str, node_id: str, *, account_id: uuid.UUID | None = None,
              tenant_id: uuid.UUID | None = None, state: str = "active",
              region: str = "cn-east", last_seen_at: datetime | None = None,
              lifecycle: str | None = None) -> str:
    """种一个节点（M02 ``nodes``；``lifecycle_state`` 是生成列，只能写 ``state``）。"""
    owner = account_id or uuid.uuid4()
    tenant = tenant_id or owner
    digest = hashlib.sha256(f"{node_id}-{uuid.uuid4()}".encode()).hexdigest()
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash, account_id,
                                  tenant_id, region, last_seen_at)
               VALUES (%s, 'linux', %s, '1.0.0', '1.0.0', %s, 'abcdefgh', %s, %s, %s, %s, %s)
               ON CONFLICT (id) DO NOTHING""",
            (node_id, f"fp-{node_id}-{digest[:12]}", state, digest, owner, tenant, region,
             last_seen_at or NOW))
    return node_id


def seed_upstream(schema: str, node_id: str, *, access: str = "A1",
                  models: Iterable[str] = ("m1",), state: str = "verified",
                  verified_at: datetime | None = None,
                  base_url: str | None = None) -> None:
    """种一条上游（M02 ``node_upstreams``；M04 只经视图 ``v_supply_upstream_verified`` 读）。

    C9b 起调度候选必须命中「已验证且新鲜」的上游（``facts.CANDIDATE_PROBE_FRESH_S``），
    所以 ``seed_capacity`` 默认会顺手种一条 verified 上游。``verified_at`` 缺省用**库内 now()**：
    用例时钟固定在 ``NOW``（2026-10-23），用库时间才不会与固定 NOW 相撞。
    """
    import json

    model_list = [str(item) for item in models]
    url = base_url or f"http://127.0.0.1:9/{access.lower()}/" + "+".join(model_list)
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO node_upstreams
                   (id, node_id, access_type, base_url, models, state, verified_at,
                    rejected_reason_code)
               VALUES (gen_random_uuid(), %s, %s, %s, %s::jsonb, %s,
                       CASE WHEN %s = 'verified' THEN COALESCE(%s::timestamptz, now()) END,
                       CASE WHEN %s = 'rejected' THEN 'unreachable' END)
               ON CONFLICT (node_id, access_type, base_url) DO NOTHING""",
            (node_id, access, url, json.dumps(model_list), state, state, verified_at, state))


def seed_capacity(schema: str, node_id: str, *, models: Iterable[str] = ("m1",),
                  access: str = "A1", kind: str = "token_relay", unit: str = "token",
                  max_qps: int = 20, ask_price: str = "9.00", seq: int = 1,
                  announced_at: datetime | None = None,
                  expires_at: datetime | None = None,
                  verified: bool = True,
                  verified_at: datetime | None = None,
                  upstream_suffix: str = "") -> None:
    """种一条容量公告（M02 ``capacity_announcements``，M04 只读视图）。

    ``verified=True``（默认）顺手种一条**同 access / 同 models** 的 verified 上游——
    这是 C9b 门控上线后的最小可用夹具；负例传 ``verified=False``（declared 上游）
    或用 ``verified_at`` 造「verified 但过期」。
    """
    import json

    model_list = [str(item) for item in models]
    items = [{"kind": kind, "access": access, "model": model, "max_qps": max_qps,
              "ask_price": ask_price, "unit": unit} for model in model_list]
    moment = announced_at or NOW
    expiry = expires_at or moment.replace(day=28)
    if verified is not None:
        seed_upstream(schema, node_id, access=access, models=model_list,
                      state="verified" if verified else "declared",
                      verified_at=verified_at, base_url=(
                          f"http://127.0.0.1:9/{access.lower()}/"
                          + "+".join(model_list) + upstream_suffix))
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO capacity_announcements (node_id, seq, announced_at, expires_at,
                                                  capabilities)
               VALUES (%s, %s, %s, %s, %s::jsonb)
               ON CONFLICT (node_id, seq) DO NOTHING""",
            # 只追加表（204 有 UPDATE 守卫）：重复种同一 (node_id, seq) 直接跳过
            (node_id, seq, moment, expiry, json.dumps(items)))


def seed_quote(schema: str, node_id: str, *, access: str = "A1", model: str = "m1",
               unit: str = "token", low: int = 800, high: int | None = 1_000,
               ttl_s: int = 600, version: int = 1,
               now: datetime | None = None) -> uuid.UUID:
    """种一条**已提交**的报价（用于「回滚证明历史未被改」的用例）。"""
    moment = now or NOW
    identifier = uuid.uuid4()
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO quotes (id, node_id, access, model, unit, ask_price_minor,
                                   price_max_minor, currency, ttl_s, state, quote_version,
                                   created_at, expires_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'USD', %s, 'active', %s, %s,
                       %s + interval '1 second' * %s)""",
            (identifier, node_id, access, model, unit, low, high, ttl_s, version, moment,
             moment, ttl_s))
    return identifier


def quote_row(schema: str, quote_id: str) -> tuple | None:
    with session(schema) as conn:
        return conn.execute(
            "SELECT id, node_id, access, model, unit, ask_price_minor, price_max_minor, "
            "currency, ttl_s, state, quote_version, created_at, expires_at, consumed_at "
            "FROM quotes WHERE id = %s", (quote_id,)).fetchone()


def owner_of(schema: str, table: str) -> str | None:
    """表属主（回滚后应为 None）。"""
    with session(schema) as conn:
        row = conn.execute(
            """SELECT table_schema FROM information_schema.tables
                WHERE table_schema = %s AND table_name = %s""", (schema, table)).fetchone()
    return row[0] if row else None


__all__ = [
    "ROOT", "MIGRATIONS_DIR", "M04_MIGRATIONS", "M04_TABLES", "M04_FUNCTIONS", "BASE_TABLES",
    "SUPPLY_VIEWS", "NOW", "dsn", "connect", "session", "create_schema", "drop_schema",
    "migration_number", "migration_files", "m04_migration_files", "prerequisite_files",
    "base_migration_files", "run_migrations", "run_migration", "apply_migrations",
    "table_names", "view_names", "column_names", "function_names", "fingerprint",
    "seed_tenant", "seed_node", "seed_upstream", "seed_capacity", "seed_quote",
    "quote_row", "owner_of",
]
