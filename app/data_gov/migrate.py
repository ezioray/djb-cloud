# SPDX-License-Identifier: Apache-2.0
"""M14 迁移执行器：1301–1304 正向升级 + 可执行回滚（空库 / 升级 / 回滚 / 幂等四跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/13xx_*_down.sql``：
CI 与本地把 ``migrations/*.sql`` 当**正向迁移**执行（与 M02/M04/M05/M06/M09/M10/M11/M12 同因），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被误当成升级脚本。正向文件里用注释保留说明。

用法（``PYTHONPATH=$PWD`` + 独立 schema；口令只走 ``DJB_DSN`` 环境变量，不进 argv）::

    python -m app.data_gov.migrate --schema m14_x --up        # 前置段 + 1301–1304
    python -m app.data_gov.migrate --schema m14_x --up-only   # 只跑 1301–1304（升级演练）
    python -m app.data_gov.migrate --schema m14_x --down      # 只回滚本段（可重复执行）
    python -m app.data_gov.migrate --schema m14_x --status
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import psycopg

__all__ = [
    "MIGRATIONS_DIR", "MODULE_RANGE", "MODULE_MIGRATIONS", "BASE_MIGRATIONS", "DOWN_SQL",
    "M14_TABLES", "M14_FUNCTIONS", "connect", "up", "down", "status", "dsn",
]

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"

#: M14 段（1300–1399；M14 §0 / 01-ownership §5）
MODULE_RANGE = (1300, 1399)

#: 本模块拥有的对象（M14 §5 三张业务表 + 02-events §2 要求的 outbox 基础设施表）
M14_TABLES: tuple[str, ...] = (
    "data_export_requests", "retention_jobs", "admin_saved_views", "data_gov_outbox",
)
M14_FUNCTIONS: tuple[str, ...] = (
    "m14_export_requests_guard", "m14_retention_jobs_guard", "m14_admin_saved_views_guard",
    "m14_outbox_payload_guard", "m14_outbox_guard", "m14_forbid_delete", "m14_forbid_truncate",
)


def _number(name: str) -> int:
    head = name.split("_", 1)[0]
    return int(head) if head.isdigit() else -1


def _sorted_names(predicate) -> tuple[str, ...]:
    paths = [path for path in MIGRATIONS_DIR.glob("*.sql") if predicate(path.name)]
    return tuple(path.name for path in sorted(paths, key=lambda path: _number(path.name)))


def _is_module(name: str) -> bool:
    return MODULE_RANGE[0] <= _number(name) <= MODULE_RANGE[1]


MODULE_MIGRATIONS: tuple[str, ...] = _sorted_names(_is_module)
BASE_MIGRATIONS: tuple[str, ...] = _sorted_names(lambda name: not _is_module(name))

#: 回滚：逆序删本模块对象（1304 → 1301）。全部 IF EXISTS，可重复执行。
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("1304_data_gov_outbox.sql", """
        DROP TRIGGER IF EXISTS data_gov_outbox_payload_guard ON data_gov_outbox;
        DROP TRIGGER IF EXISTS data_gov_outbox_guard ON data_gov_outbox;
        DROP TRIGGER IF EXISTS data_gov_outbox_no_delete ON data_gov_outbox;
        DROP TRIGGER IF EXISTS data_gov_outbox_no_truncate ON data_gov_outbox;
        DROP TABLE IF EXISTS data_gov_outbox;
        DROP FUNCTION IF EXISTS m14_outbox_payload_guard();
        DROP FUNCTION IF EXISTS m14_outbox_guard();
    """),
    ("1303_admin_saved_views.sql", """
        DROP TRIGGER IF EXISTS admin_saved_views_guard ON admin_saved_views;
        DROP TRIGGER IF EXISTS admin_saved_views_no_delete ON admin_saved_views;
        DROP TRIGGER IF EXISTS admin_saved_views_no_truncate ON admin_saved_views;
        DROP TABLE IF EXISTS admin_saved_views;
        DROP FUNCTION IF EXISTS m14_admin_saved_views_guard();
    """),
    ("1302_retention_jobs.sql", """
        DROP TRIGGER IF EXISTS retention_jobs_guard ON retention_jobs;
        DROP TRIGGER IF EXISTS retention_jobs_no_delete ON retention_jobs;
        DROP TRIGGER IF EXISTS retention_jobs_no_truncate ON retention_jobs;
        DROP TABLE IF EXISTS retention_jobs;
        DROP FUNCTION IF EXISTS m14_retention_jobs_guard();
    """),
    ("1301_data_export_requests.sql", """
        DROP TRIGGER IF EXISTS data_export_requests_guard ON data_export_requests;
        DROP TRIGGER IF EXISTS data_export_requests_no_delete ON data_export_requests;
        DROP TRIGGER IF EXISTS data_export_requests_no_truncate ON data_export_requests;
        DROP TABLE IF EXISTS data_export_requests;
        DROP FUNCTION IF EXISTS m14_export_requests_guard();
        DROP FUNCTION IF EXISTS m14_forbid_delete();
        DROP FUNCTION IF EXISTS m14_forbid_truncate();
    """),
)


def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库 / 不入提交）")
    return value


def connect(schema: str | None = None) -> psycopg.Connection:
    options = f"-c search_path={schema}" if schema else None
    return psycopg.connect(dsn(), autocommit=True, options=options, connect_timeout=15,
                           application_name="m14-admin-data-migrate")


def _apply(conn: psycopg.Connection, files, *, direction: str) -> list[str]:
    applied: list[str] = []
    for name in files:
        if direction == "up":
            sql = (MIGRATIONS_DIR / name).read_text(encoding="utf-8")
        else:
            sql = dict(DOWN_SQL)[name]
        conn.execute(sql)
        applied.append(name)
    return applied


def up(conn: psycopg.Connection, *, with_base: bool = True) -> list[str]:
    files = (BASE_MIGRATIONS + MODULE_MIGRATIONS) if with_base else MODULE_MIGRATIONS
    return _apply(conn, files, direction="up")


def down(conn: psycopg.Connection) -> list[str]:
    """逆序回滚本模块（1304 → 1301）；只删本模块对象，可重复执行。"""
    return _apply(conn, tuple(name for name, _ in DOWN_SQL), direction="down")


def status(conn: psycopg.Connection) -> dict[str, str]:
    """按对象存在性判定本段每个迁移的状态（不依赖迁移版本表）。"""
    markers: dict[str, tuple[str, str]] = {
        "1301_data_export_requests.sql": ("table", "data_export_requests"),
        "1302_retention_jobs.sql": ("table", "retention_jobs"),
        "1303_admin_saved_views.sql": ("table", "admin_saved_views"),
        "1304_data_gov_outbox.sql": ("table", "data_gov_outbox"),
        "1301_data_export_requests.sql#guard": ("function", "m14_export_requests_guard"),
        "1304_data_gov_outbox.sql#guard": ("function", "m14_outbox_guard"),
    }
    result: dict[str, str] = {}
    with conn.cursor() as cur:
        for name, (kind, object_name) in markers.items():
            if kind == "table":
                cur.execute("SELECT to_regclass(%s) IS NOT NULL", (object_name,))
            else:
                cur.execute("SELECT to_regprocedure(%s || '()') IS NOT NULL", (object_name,))
            result[name] = "OK" if cur.fetchone()[0] else "MISSING"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.data_gov.migrate",
                                     description="M14 迁移执行器（1301–1304）")
    parser.add_argument("--schema", required=False, default=None,
                        help="目标 schema（测试 / 演练用；缺省用连接默认 search_path）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="前置段 + 1301–1304")
    group.add_argument("--up-only", action="store_true", help="只跑 1301–1304")
    group.add_argument("--down", action="store_true", help="只回滚 1301–1304（可重复）")
    group.add_argument("--status", action="store_true", help="查看本段对象状态")
    args = parser.parse_args(argv)

    if args.schema:
        with connect() as admin:
            admin.execute(f'CREATE SCHEMA IF NOT EXISTS "{args.schema}"')
    with connect(args.schema) as conn:
        if args.up or args.up_only:
            applied = up(conn, with_base=args.up)
            print(f"applied {len(applied)} migrations: {', '.join(applied)}")
        elif args.down:
            removed = down(conn)
            print(f"rolled back {len(removed)} migrations: {', '.join(removed)}")
        else:
            for name, state in status(conn).items():
                print(f"{state:8s} {name}")
    return 0


if __name__ == "__main__":                                # pragma: no cover
    sys.exit(main())
