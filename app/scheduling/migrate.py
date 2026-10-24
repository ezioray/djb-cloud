# SPDX-License-Identifier: AGPL-3.0-or-later
"""M04 迁移执行器：401–406 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚」三跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/4xx_*_down.sql``：
CI 的执行方式是 ``for f in $(printf '%s\\n' migrations/*.sql | sort -V)``，
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被当成**正向迁移**执行（M02/M06/M10 同因）。
因此回滚 DDL 由本模块持有，正向文件末尾用注释保留同等人可读版本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema）::

    python -m app.scheduling.migrate --schema m04_t12_x --up
    python -m app.scheduling.migrate --schema m04_t12_x --down
    python -m app.scheduling.migrate --schema m04_t12_x --status

``--up`` 先应用**前置段**（编号 < 400 的全部迁移，即 001–208 + 600/1000 段之外的存量），
再按数字序应用 401–406：M04 只依赖 M02 的 ``nodes`` / 容量视图与 M01 的账户表，
其余模块的迁移与本模块无关。``--down`` 只回滚 4xx，**不动**任何前置对象。
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


#: M04 段（400–499），数字序
MODULE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("4*.sql"), key=_number))

#: 前置段：编号 < 400（M01 / M02 / 存量 001–006），升级测试与 CLI 用
PREREQUISITE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("*.sql"), key=_number)
    if _number(path) < 400)


def _table_down(name: str, *, extra: str = "") -> str:
    return f"DROP TABLE IF EXISTS {name};{extra}"


#: 回滚：逆序删本模块新增对象（**不碰**任何前置对象；可重复执行）
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("409_quota_fairness.sql", """
        DROP INDEX IF EXISTS quota_usage_share_idx;
        DROP INDEX IF EXISTS quota_usage_frozen_idx;
        ALTER TABLE IF EXISTS quota_usage DROP CONSTRAINT IF EXISTS quota_usage_frozen_pair_ck;
        ALTER TABLE IF EXISTS quota_usage DROP CONSTRAINT IF EXISTS quota_usage_frozen_reason_ck;
        ALTER TABLE IF EXISTS quota_usage DROP COLUMN IF EXISTS share_updated_at;
        ALTER TABLE IF EXISTS quota_usage DROP COLUMN IF EXISTS wait_started_at;
        ALTER TABLE IF EXISTS quota_usage DROP COLUMN IF EXISTS frozen_reason;
        ALTER TABLE IF EXISTS quota_usage DROP COLUMN IF EXISTS frozen_until;
    """),
    ("408_scheduling_idempotency.sql", """
        DROP INDEX IF EXISTS scheduling_idempotency_expiry_idx;
        DROP TRIGGER IF EXISTS scheduling_idempotency_guard_trg ON scheduling_idempotency;
        DROP FUNCTION IF EXISTS m04_idempotency_guard();
        DROP TABLE IF EXISTS scheduling_idempotency;
    """),
    ("407_scheduling_outbox.sql", """
        DROP INDEX IF EXISTS scheduling_outbox_aggregate_idx;
        DROP INDEX IF EXISTS scheduling_outbox_pending_idx;
        DROP TRIGGER IF EXISTS scheduling_outbox_guard_trg ON scheduling_outbox;
        DROP FUNCTION IF EXISTS m04_outbox_guard();
        DROP TABLE IF EXISTS scheduling_outbox;
    """),
    ("406_model_catalog.sql", """
        DROP INDEX IF EXISTS model_catalog_vendor_idx;
        DROP INDEX IF EXISTS model_catalog_state_idx;
        DROP TABLE IF EXISTS model_catalog;
    """),
    ("405_quota_usage.sql", """
        DROP INDEX IF EXISTS quota_usage_updated_idx;
        DROP INDEX IF EXISTS quota_usage_tenant_model_idx;
        DROP TRIGGER IF EXISTS quota_usage_guard_trg ON quota_usage;
        DROP FUNCTION IF EXISTS m04_quota_usage_guard();
        DROP TABLE IF EXISTS quota_usage;
    """),
    ("404_routing_decisions.sql", """
        DROP INDEX IF EXISTS routing_decisions_chosen_idx;
        DROP INDEX IF EXISTS routing_decisions_outcome_idx;
        DROP INDEX IF EXISTS routing_decisions_decided_idx;
        DROP INDEX IF EXISTS routing_decisions_snapshot_idx;
        DROP TRIGGER IF EXISTS routing_decisions_guard_trg ON routing_decisions;
        DROP FUNCTION IF EXISTS m04_routing_decisions_guard();
        DROP TABLE IF EXISTS routing_decisions;
    """),
    ("403_bookings.sql", """
        DROP INDEX IF EXISTS bookings_quote_idx;
        DROP INDEX IF EXISTS bookings_tenant_idx;
        DROP INDEX IF EXISTS bookings_node_idx;
        DROP INDEX IF EXISTS bookings_expiry_idx;
        DROP TRIGGER IF EXISTS bookings_guard_trg ON bookings;
        DROP FUNCTION IF EXISTS m04_bookings_guard();
        DROP TABLE IF EXISTS bookings;
    """),
    ("402_bids.sql", """
        DROP INDEX IF EXISTS bids_expiry_idx;
        DROP INDEX IF EXISTS bids_book_idx;
        DROP INDEX IF EXISTS bids_tenant_model_state_idx;
        DROP TRIGGER IF EXISTS bids_guard_trg ON bids;
        DROP FUNCTION IF EXISTS m04_bids_guard();
        DROP TABLE IF EXISTS bids;
    """),
    ("401_quotes.sql", """
        DROP INDEX IF EXISTS quotes_created_idx;
        DROP INDEX IF EXISTS quotes_expiry_idx;
        DROP INDEX IF EXISTS quotes_book_idx;
        DROP INDEX IF EXISTS quotes_node_model_state_idx;
        DROP TRIGGER IF EXISTS quotes_guard_trg ON quotes;
        DROP FUNCTION IF EXISTS m04_quotes_guard();
        DROP TABLE IF EXISTS quotes;
    """),
)

#: 每个迁移文件「已应用」的判定对象（status 用）
_MARKERS: dict[str, tuple[str, str, str]] = {
    "401_quotes.sql": ("table", "quotes", ""),
    "402_bids.sql": ("table", "bids", ""),
    "403_bookings.sql": ("table", "bookings", ""),
    "404_routing_decisions.sql": ("table", "routing_decisions", ""),
    "405_quota_usage.sql": ("table", "quota_usage", ""),
    "406_model_catalog.sql": ("table", "model_catalog", ""),
    "407_scheduling_outbox.sql": ("table", "scheduling_outbox", ""),
    "408_scheduling_idempotency.sql": ("table", "scheduling_idempotency", ""),
    "409_quota_fairness.sql": ("column", "quota_usage", "frozen_until"),
}


def migration_files() -> tuple[pathlib.Path, ...]:
    """CLI 默认执行顺序：前置段（< 400）+ 本模块段（401–406）。"""
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


def up(conn: psycopg.Connection, *, files: Iterable[pathlib.Path] | None = None) -> list[dict]:
    """正向迁移（默认 前置段 + 401–406）；每个文件单独提交，失败即停并回滚该文件。"""
    results: list[dict] = []
    for path in (files if files is not None else migration_files()):
        try:
            executed = _run_script(conn, path.read_text(encoding="utf-8"))
            results.append({"name": path.name, "rc": 0, "statements": len(executed)})
        except Exception as exc:                                   # pragma: no cover - 失败即停
            conn.rollback()
            results.append({"name": path.name, "rc": 1,
                            "error": f"{type(exc).__name__}: {exc}"})
            raise
    return results


def down(conn: psycopg.Connection) -> list[dict]:
    """回滚（逆序 406→401）：可重复执行；只删本模块新增对象。"""
    results: list[dict] = []
    for name, script in DOWN_SQL:
        try:
            executed = _run_script(conn, script)
            results.append({"name": name, "rc": 0, "statements": len(executed)})
        except Exception as exc:                                   # pragma: no cover - 失败即停
            conn.rollback()
            results.append({"name": name, "rc": 1,
                            "error": f"{type(exc).__name__}: {exc}"})
            raise
    return results


def _exists(conn: psycopg.Connection, kind: str, table: str, column: str = "") -> bool:
    with conn.cursor() as cur:
        if kind == "table":
            cur.execute(
                """SELECT 1 FROM information_schema.tables
                    WHERE table_schema = current_schema() AND table_name = %s""", (table,))
        else:
            cur.execute(
                """SELECT 1 FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name = %s
                      AND column_name = %s""", (table, column))
        return cur.fetchone() is not None


def status(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """每个 4xx 迁移是否已应用（按对象存在性判定，不依赖迁移版本表）。"""
    report: list[dict[str, Any]] = []
    for name in MODULE_MIGRATIONS:
        kind, table, column = _MARKERS[name]
        report.append({"name": name, "applied": _exists(conn, kind, table, column)})
    return report


def ensure_schema(dsn: str, schema: str) -> None:
    """CLI 用：目标 schema 不存在就建（不写 public；不删既有 schema）。"""
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))


def connect(dsn: str, schema: str) -> psycopg.Connection:
    return psycopg.connect(dsn, autocommit=False, options=f"-c search_path={schema}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M04 迁移（401–406）正向 / 回滚 / 状态")
    parser.add_argument("--schema", required=True, help="目标 schema（隔离用，不写 public）")
    parser.add_argument("--dsn", default=None, help="连接串（缺省读 DJB_DSN）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="正向应用 前置段 + 401–406")
    group.add_argument("--down", action="store_true", help="逆序回滚 4xx（可重复执行）")
    group.add_argument("--status", action="store_true", help="查看 4xx 应用状态")
    args = parser.parse_args(argv)

    dsn = args.dsn or os.environ.get("DJB_DSN")
    if not dsn:
        print("缺 DJB_DSN（或 --dsn）", file=sys.stderr)
        return 2
    ensure_schema(dsn, args.schema)
    conn = connect(dsn, args.schema)
    try:
        if args.up:
            for item in up(conn):
                print(f"up   {item['name']} rc={item['rc']} statements={item['statements']}")
        elif args.down:
            for item in down(conn):
                print(f"down {item['name']} rc={item['rc']} statements={item['statements']}")
        else:
            for item in status(conn):
                print(f"{'applied ' if item['applied'] else 'missing '}{item['name']}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":                                        # pragma: no cover
    raise SystemExit(main())
