# SPDX-License-Identifier: AGPL-3.0-or-later
"""M09 迁移执行器：901–905 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚」三跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/9xx_*_down.sql``：
CI 与本地都把 ``migrations/*.sql`` 当**正向迁移**执行（与 M02/M04/M05/M06/M10/M16 同因），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被误当成升级脚本。正向文件里用注释保留
同等人可读的版本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema）::

    python -m app.recon.migrate --schema m09_x --up          # 001…905 基线 + 本段
    python -m app.recon.migrate --schema m09_x --up-only     # 只跑 9xx（升级演练）
    python -m app.recon.migrate --schema m09_x --down        # 只回滚 9xx（可重复执行）
    python -m app.recon.migrate --schema m09_x --status

``--down`` 只删本模块新增对象（表 / 视图 / 触发器 / 函数），**不动**任何前置对象，
且可重复执行。
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import psycopg

__all__ = [
    "MIGRATIONS_DIR", "MODULE_MIGRATIONS", "BASE_MIGRATIONS", "DOWN_SQL", "M09_TABLES",
    "M09_VIEWS", "connect", "up", "down", "status", "dsn",
]

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"

#: M09 段（900–999，M09 §0 / 01-ownership §5）
MODULE_RANGE = (900, 999)

#: 本模块拥有的表（M09 §5）
M09_TABLES: tuple[str, ...] = (
    "reconciliation_runs",
    "reconciliation_exceptions",
    "reconciliation_attestations",
    "por_snapshots",
    "report_renders",
)

#: 本模块拥有的只读视图（M09 §5 视图命名 v_m09_*）
M09_VIEWS: tuple[str, ...] = (
    "v_m09_open_exceptions",
    "v_m09_run_diff",
    "v_m09_valid_attestations",
    "v_m09_latest_por",
    "v_m09_report_versions",
)


def _number(name: str) -> int:
    head = name.split("_", 1)[0]
    return int(head) if head.isdigit() else -1


def _is_module(name: str) -> bool:
    return MODULE_RANGE[0] <= _number(name) <= MODULE_RANGE[1]


def _sorted_names(predicate) -> tuple[str, ...]:
    """按**数字前缀**排序（字典序会把 900 排到 100 前面，迁移必须按编号跑）。"""
    paths = [path for path in MIGRATIONS_DIR.glob("*.sql") if predicate(path.name)]
    return tuple(path.name for path in sorted(paths, key=lambda p: _number(p.name)))


MODULE_MIGRATIONS: tuple[str, ...] = _sorted_names(_is_module)
BASE_MIGRATIONS: tuple[str, ...] = _sorted_names(lambda name: not _is_module(name))

#: 回滚：逆序删本模块对象（905 → 901）。全部 ``IF EXISTS``，可重复执行。
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("905_report_renders.sql", """
        DROP VIEW IF EXISTS v_m09_report_versions;
        DROP TRIGGER IF EXISTS report_renders_guard ON report_renders;
        DROP TRIGGER IF EXISTS report_renders_no_truncate ON report_renders;
        DROP TABLE IF EXISTS report_renders;
        DROP FUNCTION IF EXISTS m09_report_renders_guard();
    """),
    ("904_por_snapshots.sql", """
        DROP VIEW IF EXISTS v_m09_latest_por;
        DROP TRIGGER IF EXISTS por_snapshots_guard ON por_snapshots;
        DROP TRIGGER IF EXISTS por_snapshots_no_truncate ON por_snapshots;
        DROP TABLE IF EXISTS por_snapshots;
        DROP FUNCTION IF EXISTS m09_por_guard();
    """),
    ("903_recon_attestations.sql", """
        DROP VIEW IF EXISTS v_m09_valid_attestations;
        DROP TRIGGER IF EXISTS reconciliation_attestations_guard ON reconciliation_attestations;
        DROP TRIGGER IF EXISTS reconciliation_attestations_no_truncate
          ON reconciliation_attestations;
        DROP TABLE IF EXISTS reconciliation_attestations;
        DROP FUNCTION IF EXISTS m09_attestations_guard();
    """),
    ("902_recon_exceptions.sql", """
        DROP VIEW IF EXISTS v_m09_open_exceptions;
        DROP VIEW IF EXISTS v_m09_run_diff;
        DROP TRIGGER IF EXISTS reconciliation_exceptions_guard ON reconciliation_exceptions;
        DROP TRIGGER IF EXISTS reconciliation_exceptions_insert_guard
          ON reconciliation_exceptions;
        DROP TRIGGER IF EXISTS reconciliation_exceptions_no_truncate
          ON reconciliation_exceptions;
        DROP TRIGGER IF EXISTS reconciliation_exceptions_diff_sync
          ON reconciliation_exceptions;
        DROP TABLE IF EXISTS reconciliation_exceptions;
        DROP FUNCTION IF EXISTS m09_sync_run_diff();
        DROP FUNCTION IF EXISTS m09_exceptions_guard();
        DROP FUNCTION IF EXISTS m09_exceptions_insert_guard();
    """),
    ("901_recon_runs.sql", """
        DROP TRIGGER IF EXISTS reconciliation_runs_guard ON reconciliation_runs;
        DROP TRIGGER IF EXISTS reconciliation_runs_no_truncate ON reconciliation_runs;
        DROP TABLE IF EXISTS reconciliation_runs;
        DROP FUNCTION IF EXISTS m09_recon_runs_guard();
        DROP FUNCTION IF EXISTS m09_forbid_truncate();
    """),
)


def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库 / 不入提交）")
    return value


def connect(schema: str | None = None) -> psycopg.Connection:
    """连接开发库；``schema`` 给定时把 search_path 固定到该 schema（测试 / 演练用）。"""
    options = f"-c search_path={schema}" if schema else None
    return psycopg.connect(dsn(), autocommit=True, options=options, connect_timeout=15,
                           application_name="m09-recon-migrate")


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
    """逆序回滚本模块（905 → 901）；只删本模块对象。

    ``DOWN_SQL`` 本身就按**降序**写（905 在最前），因为 reconciliation_exceptions 有指向
    reconciliation_runs 的外键、视图又依赖两张表 —— 必须先删子对象再删父对象。
    """
    return _apply(conn, tuple(name for name, _ in DOWN_SQL), direction="down")


def status(conn: psycopg.Connection) -> dict:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT table_name FROM information_schema.tables
                WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'""")
        tables = {row[0] for row in cur.fetchall()}
        cur.execute(
            """SELECT table_name FROM information_schema.views
                WHERE table_schema = current_schema()""")
        views = {row[0] for row in cur.fetchall()}
        cur.execute("SELECT count(*) FROM reconciliation_runs") if "reconciliation_runs" in tables \
            else cur.execute("SELECT NULL")
        runs = cur.fetchone()[0]
    return {
        "schema": conn.info.options if hasattr(conn.info, "options") else None,
        "tables_present": sorted(t for t in M09_TABLES if t in tables),
        "tables_missing": sorted(set(M09_TABLES) - tables),
        "views_present": sorted(v for v in M09_VIEWS if v in views),
        "views_missing": sorted(set(M09_VIEWS) - views),
        "runs": runs,
        "module_migrations": list(MODULE_MIGRATIONS),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.recon.migrate",
                                     description="M09 迁移执行器（901–905）")
    parser.add_argument("--schema", default=None, help="固定 search_path 的 schema（演练/测试）")
    parser.add_argument("--up", action="store_true", help="跑基线 + 9xx")
    parser.add_argument("--up-only", action="store_true", help="只跑 9xx（升级演练）")
    parser.add_argument("--down", action="store_true", help="回滚 9xx（可重复执行）")
    parser.add_argument("--status", action="store_true", help="打印本模块对象状态")
    args = parser.parse_args(argv)

    if not any((args.up, args.up_only, args.down, args.status)):
        parser.print_help()
        return 2

    payload: dict = {"schema": args.schema}
    with connect(args.schema) as conn:
        if args.up:
            payload["up"] = up(conn)
        if args.up_only:
            payload["up_only"] = up(conn, with_base=False)
        if args.down:
            payload["down"] = down(conn)
        if args.status:
            payload["status"] = status(conn)

    import json
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI 入口
    sys.exit(main())
