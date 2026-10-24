# SPDX-License-Identifier: Apache-2.0
"""M03 迁移执行器：301–307 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚」三跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/3xx_*_down.sql``：
CI 与本地都按 ``sort -V`` 把 ``migrations/*.sql`` 当**正向迁移**执行（M02/M04/M05/M06/M10 同因），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被误当成升级脚本。因此回滚 DDL 由本模块持有，
正向文件里用注释保留同等人可读版本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema）::

    python -m app.gateway.migrate --schema m03_t12_x --up
    python -m app.gateway.migrate --schema m03_t12_x --down
    python -m app.gateway.migrate --schema m03_t12_x --status

``--up`` 先应用**前置段**（编号 < 300 的全部迁移：001–006 / 1xx / 2xx），再按数字序
应用 301–307 —— M03 只依赖 M01（账户 / Key 口径）与 M02（节点视图），其余模块与本模块无关。
``--down`` 只回滚 3xx，**不动**任何前置对象。
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys
from typing import Any, Iterable

import psycopg
from psycopg import sql

MODULE_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = MODULE_DIR.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"


def _number(path: pathlib.Path) -> int:
    return int(path.name.split("_", 1)[0])


#: M03 段（300–399），数字序
MODULE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("3*.sql"), key=_number))

#: 前置段：编号 < 300（存量 001–006 / M01 1xx / M02 2xx）
PREREQUISITE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("*.sql"), key=_number)
    if _number(path) < 300)

#: 每个迁移的「已应用」标记（按对象存在性判定，不依赖迁移版本表）
_MARKERS: dict[str, tuple[str, str, str]] = {
    "301_api_request_log.sql": ("table", "api_request_log", ""),
    "302_batch_jobs.sql": ("table", "batch_jobs", ""),
    "303_batch_items.sql": ("table", "batch_items", ""),
    "304_m03_outbox.sql": ("table", "m03_outbox", ""),
    "305_m03_idempotency.sql": ("table", "m03_idempotency", ""),
    "306_batch_webhook_state.sql": ("column", "batch_jobs", "webhook_state"),
    # 307 的对象是既有 CHECK 的**取值扩展**：标记 = 约束存在且定义里已含 dual
    "307_api_request_log_usage_source_dual.sql": (
        "constraint", "api_request_log", "api_request_log_usage_source_ck:dual"),
}

#: 回滚：逆序删本模块新增对象（**不碰**任何前置对象；可重复执行）
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("307_api_request_log_usage_source_dual.sql", """
        -- 收回 307：usage_source 枚举回到 301 的两值口径（只改 CHECK，不重写表、不删 dual 行；
        -- NOT VALID 只约束新写入，历史行不校验）
        ALTER TABLE IF EXISTS api_request_log
          DROP CONSTRAINT IF EXISTS api_request_log_usage_source_ck;
        ALTER TABLE IF EXISTS api_request_log ADD CONSTRAINT api_request_log_usage_source_ck
          CHECK (usage_source IS NULL OR usage_source IN ('estimated', 'actual')) NOT VALID;
    """),
    ("306_batch_webhook_state.sql", """
        -- 收回 306：删 webhook 台账列，并把状态机护栏恢复为 302 的版本（终态行只允许
        -- 结果/成本/检查点列变化）
        ALTER TABLE IF EXISTS batch_jobs DROP CONSTRAINT IF EXISTS batch_jobs_webhook_meta_ck;
        ALTER TABLE IF EXISTS batch_jobs DROP CONSTRAINT IF EXISTS batch_jobs_webhook_state_ck;
        ALTER TABLE IF EXISTS batch_jobs DROP COLUMN IF EXISTS webhook_delivered_at;
        ALTER TABLE IF EXISTS batch_jobs DROP COLUMN IF EXISTS webhook_last_error;
        ALTER TABLE IF EXISTS batch_jobs DROP COLUMN IF EXISTS webhook_attempts;
        ALTER TABLE IF EXISTS batch_jobs DROP COLUMN IF EXISTS webhook_state;
        CREATE OR REPLACE FUNCTION m03_batch_state_guard() RETURNS trigger AS $$
        DECLARE
          mutable TEXT[] := ARRAY['updated_at', 'results_ref', 'results_expires_at',
                                  'cost_actual_minor', 'checkpoint_resumes', 'error_code'];
        BEGIN
          IF TG_OP = 'DELETE' THEN
            IF OLD.created_at > now() - INTERVAL '7 days' THEN
              RAISE EXCEPTION 'batch_jobs: only rows older than 7 days may be deleted (retention)'
                USING ERRCODE = '42501';
            END IF;
            RETURN OLD;
          END IF;
          IF OLD.status IN ('succeeded', 'failed', 'canceled') THEN
            IF NEW.status IS DISTINCT FROM OLD.status THEN
              RAISE EXCEPTION 'batch_jobs: terminal status % cannot move to % (INV-M03-06)',
                OLD.status, NEW.status USING ERRCODE = '42501';
            END IF;
            IF (to_jsonb(NEW) - mutable) IS DISTINCT FROM (to_jsonb(OLD) - mutable) THEN
              RAISE EXCEPTION 'batch_jobs: terminal row is immutable except delivery columns'
                USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
          END IF;
          IF NEW.status IS DISTINCT FROM OLD.status THEN
            IF NOT ((OLD.status = 'queued' AND NEW.status IN ('running', 'canceled', 'failed'))
                 OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed', 'canceled'))) THEN
              RAISE EXCEPTION 'batch_jobs: illegal transition % -> % (M03 §3.1)',
                OLD.status, NEW.status USING ERRCODE = '42501';
            END IF;
          END IF;
          IF NEW.status = 'canceled' AND NEW.canceled_at IS NULL THEN
            NEW.canceled_at := now();
          END IF;
          IF NEW.status IN ('succeeded', 'failed') AND NEW.completed_at IS NULL THEN
            NEW.completed_at := now();
          END IF;
          NEW.updated_at := now();
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """),
    ("305_m03_idempotency.sql", """
        DROP TRIGGER IF EXISTS m03_idempotency_guard ON m03_idempotency;
        DROP FUNCTION IF EXISTS m03_idempotency_guard();
        DROP INDEX IF EXISTS m03_idempotency_expires_idx;
        DROP INDEX IF EXISTS m03_idempotency_scope_key_uq;
        DROP TABLE IF EXISTS m03_idempotency;
    """),
    ("304_m03_outbox.sql", """
        DROP TRIGGER IF EXISTS m03_outbox_insert_guard ON m03_outbox;
        DROP TRIGGER IF EXISTS m03_outbox_no_truncate ON m03_outbox;
        DROP TRIGGER IF EXISTS m03_outbox_guard ON m03_outbox;
        DROP FUNCTION IF EXISTS m03_outbox_insert_guard();
        DROP FUNCTION IF EXISTS m03_outbox_guard();
        DROP INDEX IF EXISTS m03_outbox_published_idx;
        DROP INDEX IF EXISTS m03_outbox_aggregate_idx;
        DROP INDEX IF EXISTS m03_outbox_pending_idx;
        DROP INDEX IF EXISTS m03_outbox_idempotency_uq;
        DROP TABLE IF EXISTS m03_outbox;
    """),
    ("303_batch_items.sql", """
        DROP TRIGGER IF EXISTS batch_items_no_truncate ON batch_items;
        DROP TRIGGER IF EXISTS batch_items_guard ON batch_items;
        DROP FUNCTION IF EXISTS m03_batch_item_guard();
        DROP INDEX IF EXISTS batch_items_usage_idx;
        DROP INDEX IF EXISTS batch_items_batch_status_idx;
        DROP INDEX IF EXISTS batch_items_batch_custom_uq;
        DROP INDEX IF EXISTS batch_items_batch_seq_uq;
        DROP TABLE IF EXISTS batch_items;
    """),
    ("302_batch_jobs.sql", """
        DROP TRIGGER IF EXISTS batch_jobs_no_truncate ON batch_jobs;
        DROP TRIGGER IF EXISTS batch_jobs_guard ON batch_jobs;
        DROP FUNCTION IF EXISTS m03_batch_state_guard();
        DROP INDEX IF EXISTS batch_jobs_results_expiry_idx;
        DROP INDEX IF EXISTS batch_jobs_active_idx;
        DROP INDEX IF EXISTS batch_jobs_account_time_idx;
        DROP INDEX IF EXISTS batch_jobs_idempotency_uq;
        DROP TABLE IF EXISTS batch_jobs;
    """),
    ("301_api_request_log.sql", """
        DROP TRIGGER IF EXISTS api_request_log_no_truncate ON api_request_log;
        DROP TRIGGER IF EXISTS api_request_log_guard ON api_request_log;
        DROP FUNCTION IF EXISTS m03_request_log_guard();
        DROP INDEX IF EXISTS api_request_log_created_idx;
        DROP INDEX IF EXISTS api_request_log_batch_idx;
        DROP INDEX IF EXISTS api_request_log_account_time_idx;
        DROP INDEX IF EXISTS api_request_log_key_time_idx;
        DROP TABLE IF EXISTS api_request_log;
        DROP FUNCTION IF EXISTS m03_forbid_truncate();
    """),
)


def migration_files() -> tuple[pathlib.Path, ...]:
    """CLI 默认执行顺序：前置段（< 300）+ 本模块段（301–307）。"""
    return tuple(MIGRATIONS_DIR / name for name in PREREQUISITE_MIGRATIONS + MODULE_MIGRATIONS)


def _split_statements(script: str) -> list[str]:
    """按 ``;`` 切语句（``$$`` 包裹的函数体不切分）。"""
    statements: list[str] = []
    buffer: list[str] = []
    in_dollar = False
    for line in script.splitlines():
        if line.count("$$") % 2 == 1:
            in_dollar = not in_dollar
        buffer.append(line)
        if not in_dollar and line.rstrip().endswith(";"):
            statements.append("\n".join(buffer).strip())
            buffer = []
    tail = "\n".join(buffer).strip()
    if tail:
        statements.append(tail)
    return [item for item in statements if item]


def _run_script(conn: psycopg.Connection, script: str) -> list[str]:
    executed: list[str] = []
    for statement in _split_statements(script):
        with conn.cursor() as cur:
            cur.execute(statement)
        executed.append(statement.splitlines()[0][:120])
    conn.commit()
    return executed


# --------------------------------------------------------------------------- 连接
def _dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（postgres 连接串，见 README；凭据不入库）")
    return value


_NAME_RE = __import__("re").compile(r"^[a-z_][a-z0-9_]*$")


def ensure_schema(schema: str) -> None:
    """确保目标 schema 存在（隔离 schema；拒绝非标识符名，防注入）。"""
    if not _NAME_RE.match(schema):
        raise SystemExit(f"非法 schema 名：{schema!r}（只允许 [a-z_][a-z0-9_]*）")
    conn = psycopg.connect(_dsn(), autocommit=True, connect_timeout=15,
                           application_name="m03-gateway-migrate")
    try:
        with conn.cursor() as cur:
            cur.execute("SET lock_timeout = '10s'")
            cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))
    finally:
        conn.close()


def connect(schema: str) -> psycopg.Connection:
    """连到指定 schema（autocommit；``search_path`` 只指向该 schema）。"""
    if not _NAME_RE.match(schema):
        raise SystemExit(f"非法 schema 名：{schema!r}（只允许 [a-z_][a-z0-9_]*）")
    return psycopg.connect(_dsn(), autocommit=True, connect_timeout=15,
                           application_name="m03-gateway-migrate",
                           options=f"-c search_path={schema} -c synchronous_commit=off")


# --------------------------------------------------------------------------- 执行
def apply_up(schema: str, *, files: Iterable[pathlib.Path] | None = None,
             verbose: bool = False) -> dict[str, Any]:
    """按数字序应用迁移（默认：前置段 + 301–307）；返回逐文件结果。"""
    paths = list(files if files is not None else migration_files())
    ensure_schema(schema)
    conn = connect(schema)
    applied: list[dict[str, Any]] = []
    try:
        for path in paths:
            script = path.read_text(encoding="utf-8")
            statements = _run_script(conn, script)
            applied.append({"name": path.name, "statements": len(statements)})
            if verbose:
                print(f"  up  {path.name}: {len(statements)} 条语句")
    finally:
        conn.close()
    return {"schema": schema, "applied": applied}


def apply_down(schema: str, *, verbose: bool = False) -> dict[str, Any]:
    """逆序回滚 3xx（只删本模块对象）。"""
    ensure_schema(schema)
    conn = connect(schema)
    rolled: list[dict[str, Any]] = []
    try:
        for name, script in DOWN_SQL:
            statements = _run_script(conn, script)
            rolled.append({"name": name, "statements": len(statements)})
            if verbose:
                print(f"  down {name}: {len(statements)} 条语句")
    finally:
        conn.close()
    return {"schema": schema, "rolled_back": rolled}


def _exists(conn: psycopg.Connection, kind: str, name: str, extra: str = "") -> bool:
    if kind == "table":
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM information_schema.tables"
                        " WHERE table_schema = current_schema() AND table_name = %s", (name,))
            return cur.fetchone() is not None
    if kind == "column":
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM information_schema.columns"
                        " WHERE table_schema = current_schema() AND table_name = %s"
                        " AND column_name = %s", (name, extra))
            return cur.fetchone() is not None
    if kind == "constraint":
        # extra = "<约束名>:<必须出现的字面量>"（307：必须已含 dual）
        constraint, _, required = extra.partition(":")
        with conn.cursor() as cur:
            cur.execute("SELECT pg_get_constraintdef(con.oid)"
                        " FROM pg_constraint con"
                        " JOIN pg_class c ON c.oid = con.conrelid"
                        " JOIN pg_namespace n ON n.oid = c.relnamespace"
                        " WHERE n.nspname = current_schema() AND c.relname = %s"
                        " AND con.conname = %s", (name, constraint))
            row = cur.fetchone()
        return row is not None and (not required or required in row[0])
    raise ValueError(f"未知标记类型：{kind!r}")                   # pragma: no cover - 编程错误


def status(schema: str) -> dict[str, Any]:
    """逐迁移看对象是否存在（不依赖迁移版本表）。"""
    ensure_schema(schema)
    conn = connect(schema)
    try:
        rows = [{"name": name, "kind": _MARKERS[name][0],
                 "object": _MARKERS[name][1] + ("." + _MARKERS[name][2]
                                                if _MARKERS[name][2] else ""),
                 "applied": _exists(conn, _MARKERS[name][0], _MARKERS[name][1],
                                    _MARKERS[name][2])}
                for name in MODULE_MIGRATIONS if name in _MARKERS]
    finally:
        conn.close()
    return {"schema": schema, "module_migrations": rows,
            "prerequisites": [pathlib.Path(name).name for name in PREREQUISITE_MIGRATIONS]}


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M03 迁移执行器（301–307）")
    parser.add_argument("--schema", required=True, help="目标 schema（隔离，勿用 public）")
    parser.add_argument("--up", action="store_true", help="前置段 + 301–307 正向升级")
    parser.add_argument("--down", action="store_true", help="逆序回滚 3xx")
    parser.add_argument("--status", action="store_true", help="查看对象存在性")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    if not (args.up or args.down or args.status):
        parser.error("至少指定 --up / --down / --status 之一")
    if args.up:
        result = apply_up(args.schema, verbose=args.verbose)
        print(f"up ok: {args.schema} 应用 {len(result['applied'])} 个迁移")
    if args.down:
        result = apply_down(args.schema, verbose=args.verbose)
        print(f"down ok: {args.schema} 回滚 {len(result['rolled_back'])} 个迁移")
    if args.status:
        info = status(args.schema)
        for row in info["module_migrations"]:
            print(f"  {row['name']}: applied={row['applied']}")
    return 0


if __name__ == "__main__":                                   # pragma: no cover
    sys.exit(main())
