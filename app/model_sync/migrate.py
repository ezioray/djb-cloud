# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 model-sync 迁移执行器：1800 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚 / 重跑」）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/1800_*_down.sql``：
CI 与本地都把 ``migrations/*.sql`` 当**正向迁移**执行（与 M02/M04/M05/M06/M09/M10/M11/M12/M17
同因），放在 ``migrations/`` 下的任何 ``*.sql`` 都会被执行器当成升级脚本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema；**口令只走环境变量，不进 argv**）::

    python -m app.model_sync.migrate --schema m18_x --up          # 前置段 + 1800 段
    python -m app.model_sync.migrate --schema m18_x --up-only     # 只跑 1800 段（升级演练）
    python -m app.model_sync.migrate --schema m18_x --down        # 只回滚 1800 段（可重复）
    python -m app.model_sync.migrate --schema m18_x --status

``--down`` 只删本模块对象（4 表 + 护栏函数），**不动**任何前置对象，也不碰账本。
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import psycopg

from . import facts

__all__ = [
    "MIGRATIONS_DIR", "MODULE_RANGE", "MODULE_MIGRATIONS", "BASE_MIGRATIONS", "DOWN_SQL",
    "M18_TABLES", "M18_FUNCTIONS", "connect", "up", "down", "status", "dsn",
]

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"
MODULE_RANGE = facts.MODULE_RANGE                                  # 1800–1899
M18_TABLES = facts.M18_TABLES
M18_FUNCTIONS = facts.M18_FUNCTIONS


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

#: 回滚：逆序删本模块对象（1800）。全部 IF EXISTS，可重复执行；不触碰账本对象。
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("1800_model_sync_registry.sql", """
        DROP TABLE IF EXISTS node_model_sync_state;
        DROP TRIGGER IF EXISTS model_sync_events_no_truncate ON model_sync_events;
        DROP TRIGGER IF EXISTS model_sync_events_guard ON model_sync_events;
        DROP TABLE IF EXISTS model_sync_events;
        DROP TRIGGER IF EXISTS model_sync_bundles_no_truncate ON model_sync_bundles;
        DROP TRIGGER IF EXISTS model_sync_bundles_guard ON model_sync_bundles;
        DROP TABLE IF EXISTS model_sync_bundles;
        DROP TABLE IF EXISTS vendor_models;
        DROP FUNCTION IF EXISTS m18_events_guard();
        DROP FUNCTION IF EXISTS m18_bundles_guard();
        DROP FUNCTION IF EXISTS m18_forbid_truncate();
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
                           application_name="m18-model-sync-migrate")


def _apply(conn: psycopg.Connection, files, *, direction: str) -> list[str]:
    applied: list[str] = []
    for name in files:
        sql = ((MIGRATIONS_DIR / name).read_text(encoding="utf-8")
               if direction == "up" else dict(DOWN_SQL)[name])
        conn.execute(sql)
        applied.append(name)
    return applied


def up(conn: psycopg.Connection, *, with_base: bool = True) -> list[str]:
    files = (BASE_MIGRATIONS + MODULE_MIGRATIONS) if with_base else MODULE_MIGRATIONS
    return _apply(conn, files, direction="up")


def down(conn: psycopg.Connection) -> list[str]:
    """逆序回滚本模块（1800）；只删本模块对象，可重复执行。"""
    return _apply(conn, tuple(name for name, _ in DOWN_SQL), direction="down")


def status(conn: psycopg.Connection) -> dict[str, str]:
    """按对象存在性判定本段迁移状态（不依赖迁移版本表）。"""
    markers: dict[str, tuple[str, str]] = {
        "1800_model_sync_registry.sql#vendor_models": ("table", "vendor_models"),
        "1800_model_sync_registry.sql#bundles": ("table", "model_sync_bundles"),
        "1800_model_sync_registry.sql#events": ("table", "model_sync_events"),
        "1800_model_sync_registry.sql#state": ("table", "node_model_sync_state"),
    }
    result: dict[str, str] = {}
    with conn.cursor() as cur:
        for name, (_kind, object_name) in markers.items():
            cur.execute("SELECT to_regclass(%s) IS NOT NULL", (object_name,))
            result[name] = "OK" if cur.fetchone()[0] else "MISSING"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.model_sync.migrate",
                                     description="M18 迁移执行器（1800–1899）")
    parser.add_argument("--schema", required=False, default=None,
                        help="目标 schema（测试 / 演练用；缺省用连接默认 search_path）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="前置段 + 1800–1899")
    group.add_argument("--up-only", action="store_true", help="只跑 1800–1899（升级演练）")
    group.add_argument("--down", action="store_true", help="只回滚 1800–1899（可重复）")
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
