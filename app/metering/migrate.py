# SPDX-License-Identifier: Apache-2.0
"""M05 迁移执行器：501–505 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚」三跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/5xx_*_down.sql``：
CI 与本地都按 ``sort -V`` 把 ``migrations/*.sql`` 当**正向迁移**执行（M02/M04/M06/M10 同因），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被误当成升级脚本。因此回滚 DDL 由本模块持有，
正向文件里用注释保留同等人可读版本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema）::

    python -m app.metering.migrate --schema m05_t12_x --up
    python -m app.metering.migrate --schema m05_t12_x --down
    python -m app.metering.migrate --schema m05_t12_x --status

``--up`` 先应用**前置段**（编号 < 500 的全部迁移：001–006 / 1xx / 2xx / 4xx），再按数字序
应用 501–505——M05 只依赖 M02 的节点视图与 M01 的账户口径，其余模块与本模块无关。
``--down`` 只回滚 5xx，**不动**任何前置对象。
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


#: M05 段（500–599），数字序
MODULE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("5*.sql"), key=_number))

#: 前置段：编号 < 500（存量 001–006 / M01 / M02 / M04）
PREREQUISITE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("*.sql"), key=_number)
    if _number(path) < 500)

#: 每个迁移的「已应用」标记（按对象存在性判定，不依赖迁移版本表）
_MARKERS: dict[str, tuple[str, str, str]] = {
    "501_usage_records.sql": ("table", "usage_records", ""),
    "502_metering_receipts.sql": ("table", "metering_receipts", ""),
    "503_usage_corrections.sql": ("table", "usage_corrections", ""),
    "504_upstream_bills.sql": ("table", "upstream_bills", ""),
    "505_loss_pool_entries.sql": ("table", "loss_pool_entries", ""),
}

#: 回滚：逆序删本模块新增对象（**不碰**任何前置对象；可重复执行）
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("505_loss_pool_entries.sql", """
        DROP TRIGGER IF EXISTS loss_pool_no_truncate ON loss_pool_entries;
        DROP TRIGGER IF EXISTS loss_pool_no_mutation ON loss_pool_entries;
        DROP INDEX IF EXISTS loss_pool_recorded_idx;
        DROP INDEX IF EXISTS loss_pool_request_attempt_uq;
        DROP TABLE IF EXISTS loss_pool_entries;
    """),
    ("504_upstream_bills.sql", """
        DROP TRIGGER IF EXISTS upstream_bills_insert_guard ON upstream_bills;
        DROP TRIGGER IF EXISTS upstream_bills_no_truncate ON upstream_bills;
        DROP TRIGGER IF EXISTS upstream_bills_guard ON upstream_bills;
        DROP FUNCTION IF EXISTS m05_bill_insert_guard();
        DROP FUNCTION IF EXISTS m05_bill_guard();
        DROP INDEX IF EXISTS upstream_bills_state_idx;
        DROP INDEX IF EXISTS upstream_bills_provider_period_idx;
        DROP TABLE IF EXISTS upstream_bills;
    """),
    ("503_usage_corrections.sql", """
        DROP TRIGGER IF EXISTS usage_corrections_insert_guard ON usage_corrections;
        DROP TRIGGER IF EXISTS usage_corrections_no_truncate ON usage_corrections;
        DROP TRIGGER IF EXISTS usage_corrections_guard ON usage_corrections;
        DROP FUNCTION IF EXISTS m05_correction_insert_guard();
        DROP FUNCTION IF EXISTS m05_correction_guard();
        DROP INDEX IF EXISTS usage_corrections_state_idx;
        DROP INDEX IF EXISTS usage_corrections_usage_time_idx;
        DROP INDEX IF EXISTS usage_corrections_bill_uq;
        DROP TABLE IF EXISTS usage_corrections;
    """),
    ("502_metering_receipts.sql", """
        DROP TRIGGER IF EXISTS metering_receipts_no_truncate ON metering_receipts;
        DROP TRIGGER IF EXISTS metering_receipts_no_mutation ON metering_receipts;
        DROP INDEX IF EXISTS metering_receipts_receipt_idx;
        DROP INDEX IF EXISTS metering_receipts_node_time_idx;
        DROP INDEX IF EXISTS metering_receipts_usage_uq;
        DROP INDEX IF EXISTS metering_receipts_accepted_uq;
        DROP TABLE IF EXISTS metering_receipts;
    """),
    ("501_usage_records.sql", """
        DROP TRIGGER IF EXISTS usage_records_insert_guard ON usage_records;
        DROP TRIGGER IF EXISTS usage_records_no_truncate ON usage_records;
        DROP TRIGGER IF EXISTS usage_records_state_guard ON usage_records;
        DROP FUNCTION IF EXISTS m05_usage_insert_guard();
        DROP FUNCTION IF EXISTS m05_usage_state_guard();
        DROP INDEX IF EXISTS usage_records_account_time_idx;
        DROP INDEX IF EXISTS usage_records_receipt_uq;
        DROP INDEX IF EXISTS usage_records_request_attempt_uq;
        DROP TABLE IF EXISTS usage_records;
        DROP FUNCTION IF EXISTS m05_forbid_truncate();
        DROP FUNCTION IF EXISTS m05_forbid_mutation();
    """),
)


def migration_files() -> tuple[pathlib.Path, ...]:
    """CLI 默认执行顺序：前置段（< 500）+ 本模块段（501–505）。"""
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
    """正向迁移（默认 前置段 + 501–505）；每个文件单独提交，失败即停。"""
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
    """回滚（逆序 505→501）：可重复执行；只删本模块新增对象。"""
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
    """每个 5xx 迁移是否已应用。"""
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
    parser = argparse.ArgumentParser(description="M05 迁移（501–505）正向 / 回滚 / 状态")
    parser.add_argument("--schema", required=True, help="目标 schema（隔离用，不写 public）")
    parser.add_argument("--dsn", default=None, help="连接串（缺省读 DJB_DSN）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="正向应用 前置段 + 501–505")
    group.add_argument("--down", action="store_true", help="逆序回滚 5xx（可重复执行）")
    group.add_argument("--status", action="store_true", help="查看 5xx 应用状态")
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
                print(f"{'APPLIED ' if item['applied'] else 'MISSING '} {item['name']}")
        return 0
    except Exception as exc:                                       # pragma: no cover - CLI
        print(f"迁移失败：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":                                         # pragma: no cover - CLI
    raise SystemExit(main())
