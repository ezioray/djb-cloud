# SPDX-License-Identifier: Apache-2.0
"""M11 迁移执行器：1100–1104 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚」三跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/11xx_*_down.sql``：
CI 与本地都把 ``migrations/*.sql`` 当**正向迁移**执行（与 M02/M04/M05/M06/M09/M10/M12 同因），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被误当成升级脚本。正向文件里用注释保留说明。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema；**口令只走环境变量，不进 argv**）::

    python -m app.risk.migrate --schema m11_x --up          # 001…1104 基线 + 本段
    python -m app.risk.migrate --schema m11_x --up-only     # 只跑 1100–1104（升级演练）
    python -m app.risk.migrate --schema m11_x --down        # 只回滚本段（可重复执行）
    python -m app.risk.migrate --schema m11_x --status

``--down`` 只删本模块新增对象（表 / 视图 / 触发器 / 函数 / 序列），**不动**任何前置对象。
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import psycopg

__all__ = [
    "MIGRATIONS_DIR", "MODULE_RANGE", "MODULE_MIGRATIONS", "BASE_MIGRATIONS", "DOWN_SQL",
    "M11_TABLES", "M11_VIEWS", "connect", "up", "down", "status", "dsn",
]

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"

#: M11 段（1100–1199，M11 §0 / 01-ownership §5）
MODULE_RANGE = (1100, 1199)

#: 本模块拥有的域表（M11 §5；risk_outbox 为 02-events §2 要求的基础设施表）
M11_TABLES: tuple[str, ...] = (
    "risk_rules", "risk_limits", "risk_cases", "risk_appeals", "risk_events", "risk_outbox",
)

#: 本模块拥有的只读视图（M11 §5）
M11_VIEWS: tuple[str, ...] = ("v_risk_limits", "v_risk_case_summary")


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

#: 回滚：逆序删本模块对象（1104 → 1100）。全部 IF EXISTS，可重复执行。
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("1104_risk_events.sql", """
        DROP TABLE IF EXISTS risk_outbox;
        DROP TRIGGER IF EXISTS risk_events_guard ON risk_events;
        DROP TRIGGER IF EXISTS risk_events_no_truncate ON risk_events;
        DROP TABLE IF EXISTS risk_events;
        DROP FUNCTION IF EXISTS m11_events_guard();
        DROP FUNCTION IF EXISTS m11_outbox_guard();
    """),
    ("1103_risk_appeals.sql", """
        DROP TRIGGER IF EXISTS risk_appeals_guard ON risk_appeals;
        DROP TRIGGER IF EXISTS risk_appeals_no_truncate ON risk_appeals;
        DROP TABLE IF EXISTS risk_appeals;
        DROP FUNCTION IF EXISTS m11_appeals_guard();
    """),
    ("1102_risk_cases.sql", """
        DROP VIEW IF EXISTS v_risk_case_summary;
        DROP TRIGGER IF EXISTS risk_cases_guard ON risk_cases;
        DROP TRIGGER IF EXISTS risk_cases_no_truncate ON risk_cases;
        DROP TABLE IF EXISTS risk_cases;
        DROP SEQUENCE IF EXISTS risk_case_no_seq;
        DROP FUNCTION IF EXISTS m11_cases_guard();
    """),
    ("1101_risk_limits.sql", """
        DROP VIEW IF EXISTS v_risk_limits;
        DROP TABLE IF EXISTS risk_limits;
    """),
    ("1100_risk_rules.sql", """
        DROP TRIGGER IF EXISTS risk_rules_guard ON risk_rules;
        DROP TRIGGER IF EXISTS risk_rules_no_truncate ON risk_rules;
        DROP TABLE IF EXISTS risk_rules;
        DROP FUNCTION IF EXISTS m11_rules_guard();
        DROP FUNCTION IF EXISTS m11_forbid_truncate();
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
                           application_name="m11-risk-migrate")


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
    """逆序回滚本模块（1104 → 1100）；只删本模块对象，可重复执行。"""
    return _apply(conn, tuple(name for name, _ in DOWN_SQL), direction="down")


def status(conn: psycopg.Connection) -> dict[str, str]:
    """按对象存在性判定本段每个迁移的状态（不依赖迁移版本表）。"""
    markers: dict[str, tuple[str, str]] = {
        "1100_risk_rules.sql": ("table", "risk_rules"),
        "1101_risk_limits.sql": ("table", "risk_limits"),
        "1102_risk_cases.sql": ("table", "risk_cases"),
        "1103_risk_appeals.sql": ("table", "risk_appeals"),
        "1104_risk_events.sql": ("table", "risk_events"),
        "1104_risk_events.sql#outbox": ("table", "risk_outbox"),
        "1101_risk_limits.sql#view": ("view", "v_risk_limits"),
        "1102_risk_cases.sql#view": ("view", "v_risk_case_summary"),
    }
    result: dict[str, str] = {}
    with conn.cursor() as cur:
        for name, (kind, object_name) in markers.items():
            if kind == "table":
                cur.execute("SELECT to_regclass(%s) IS NOT NULL", (object_name,))
            else:
                cur.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_views WHERE viewname = %s"
                    " AND schemaname = current_schema())", (object_name,))
            result[name] = "OK" if cur.fetchone()[0] else "MISSING"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.risk.migrate",
                                     description="M11 迁移执行器（1100–1104）")
    parser.add_argument("--schema", required=False, default=None,
                        help="目标 schema（测试 / 演练用；缺省用连接默认 search_path）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="前置段 + 1100–1104")
    group.add_argument("--up-only", action="store_true", help="只跑 1100–1104")
    group.add_argument("--down", action="store_true", help="只回滚 1100–1104（可重复）")
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
