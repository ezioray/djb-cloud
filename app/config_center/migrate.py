# SPDX-License-Identifier: Apache-2.0
"""M10 迁移执行器（up / down / status），迁移段 1000–1099（01-ownership §5）。

三种跑法（验收「空库 / 升级 / 回滚三跑」）：
* **空库**：全新 schema 按文件名顺序跑 ``migrations/*.sql``（与 CI 的 ``for f in migrations/*.sql``
  一致），证明 M10 段与存量段能共处；
* **升级**：已有 001–604 的 schema 上只跑 1000–1004（``with_base=False``），证明「只加不改」；
* **回滚**：:func:`down` 逆序删除本模块新增对象（含函数与触发器），存量对象零改动，可重复执行。

纪律：迁移文件是唯一 DDL 来源，Python 里不写建表语句；``down`` 只删本模块对象，
不 DROP 存量表、不改存量列（00-conventions §7.2）。
"""
from __future__ import annotations

import argparse
import pathlib

import psycopg

__all__ = [
    "MIGRATIONS_DIR",
    "MODULE_MIGRATIONS",
    "BASE_MIGRATIONS",
    "DOWN_SQL",
    "M10_TABLES",
    "connect",
    "up",
    "down",
    "status",
]

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"


def _is_module(name: str) -> bool:
    """1000–1099 段（注意 ``glob('10*.sql')`` 会把 100–107 也匹配进来，不能用它）。"""
    head = name.split("_", 1)[0]
    return head.isdigit() and 1000 <= int(head) <= 1099


def _sorted_names(predicate) -> tuple[str, ...]:
    """按**数字前缀**排序（字典序会把 1000 排到 600 前面，迁移必须按编号跑）。"""
    paths = [p for p in MIGRATIONS_DIR.glob("*.sql") if predicate(p.name)]
    return tuple(p.name for p in sorted(paths, key=lambda p: int(p.name.split("_", 1)[0])))


MODULE_MIGRATIONS: tuple[str, ...] = _sorted_names(_is_module)
BASE_MIGRATIONS: tuple[str, ...] = _sorted_names(lambda name: not _is_module(name))

#: 本模块拥有的表（01-ownership §2 / M10 §5）
M10_TABLES: tuple[str, ...] = (
    "config_items",
    "config_versions",
    "config_publish_requests",
    "config_snapshots",
    "config_drifts",
)

#: 回滚：逆序删除本模块新增对象（表 → 函数）。存量对象一个都不碰。
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("1004_config_drifts.sql", """
        DROP TABLE IF EXISTS config_drifts;
    """),
    ("1003_config_snapshots.sql", """
        DROP TABLE IF EXISTS config_snapshots;
    """),
    ("1002_config_publish_requests.sql", """
        DROP TABLE IF EXISTS config_publish_requests;
    """),
    ("1001_config_versions.sql", """
        DROP TABLE IF EXISTS config_versions;
    """),
    ("1000_config_items.sql", """
        DROP TABLE IF EXISTS config_items;
        DROP FUNCTION IF EXISTS m10_config_items_guard();
        DROP FUNCTION IF EXISTS m10_forbid_truncate();
        DROP FUNCTION IF EXISTS m10_versions_guard();
        DROP FUNCTION IF EXISTS m10_versions_monotonic_trg();
        DROP FUNCTION IF EXISTS m10_versions_secret_trg();
        DROP FUNCTION IF EXISTS m10_snapshots_guard();
        DROP FUNCTION IF EXISTS m10_drifts_guard();
    """),
)


def dsn() -> str:
    import os

    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库）")
    return value


def connect(schema: str | None = None) -> psycopg.Connection:
    """连接开发库；``schema`` 给定时把 search_path 固定到该 schema（测试 / 演练用）。"""
    options = f"-c search_path={schema}" if schema else None
    return psycopg.connect(dsn(), autocommit=True, options=options)


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
    """正向升级：001–0999（基线，可选）+ 1000–1099（本模块）。可重复执行。"""
    applied: list[str] = []
    if with_base:
        applied += _apply(conn, BASE_MIGRATIONS, direction="up")
    applied += _apply(conn, MODULE_MIGRATIONS, direction="up")
    return applied


def down(conn: psycopg.Connection) -> list[str]:
    """回滚：逆序删除 1000–1099 新增对象（表 + 函数）。"""
    return _apply(conn, [name for name, _ in DOWN_SQL], direction="down")


def status(conn: psycopg.Connection) -> dict[str, list[str]]:
    """列出当前 schema 的表 / 视图 / M10 函数，供证据文件引用。"""
    tables = [r[0] for r in conn.execute(
        """SELECT table_name FROM information_schema.tables
            WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
            ORDER BY 1""").fetchall()]
    views = [r[0] for r in conn.execute(
        """SELECT table_name FROM information_schema.views
            WHERE table_schema = current_schema() ORDER BY 1""").fetchall()]
    functions = [r[0] for r in conn.execute(
        """SELECT p.proname FROM pg_proc p
             JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = current_schema() AND p.proname LIKE 'm10\\_%'
            ORDER BY 1""").fetchall()]
    return {"tables": tables, "views": views, "functions": functions}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M10 config-center 迁移（up / down / status）")
    parser.add_argument("--schema", default=None, help="目标 schema（缺省用连接默认）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="正向升级（含 001–0999 基线）")
    group.add_argument("--up-only", action="store_true", help="只跑 1000–1099（升级演练）")
    group.add_argument("--down", action="store_true", help="回滚本模块对象")
    group.add_argument("--status", action="store_true", help="列出当前 schema 的表 / 视图 / 函数")
    args = parser.parse_args(argv)

    with connect(args.schema) as conn:
        if args.up:
            for name in up(conn):
                print(f"up   {name}")
        elif args.up_only:
            for name in up(conn, with_base=False):
                print(f"up   {name}")
        elif args.down:
            for name in down(conn):
                print(f"down {name}")
        else:
            info = status(conn)
            print(f"tables    ({len(info['tables'])}): {', '.join(info['tables'])}")
            print(f"views     ({len(info['views'])}): {', '.join(info['views']) or '-'}")
            print(f"functions ({len(info['functions'])}): {', '.join(info['functions']) or '-'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
