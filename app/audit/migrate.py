# SPDX-License-Identifier: Apache-2.0
"""M16 迁移执行器：1400–1403 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚」三跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/14xx_*_down.sql``：
CI 与本地都把 ``migrations/*.sql`` 当**正向迁移**执行（M02/M04/M05/M06/M10 同因），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被误当成升级脚本。因此回滚 DDL 由本模块持有，
正向文件里用注释保留同等人可读版本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema）::

    python -m app.audit.migrate --schema m16_x --up          # 001…1008 基线 + 1400–1403
    python -m app.audit.migrate --schema m16_x --up-only     # 只跑 14xx（升级演练）
    python -m app.audit.migrate --schema m16_x --down        # 只回滚 14xx
    python -m app.audit.migrate --schema m16_x --status

``--down`` 只删本模块新增对象（表 / 触发器 / 函数 / 约束），**不动**任何前置对象，且可重复执行。
"""
from __future__ import annotations

import argparse
import os
import pathlib

import psycopg

__all__ = [
    "MIGRATIONS_DIR",
    "MODULE_MIGRATIONS",
    "BASE_MIGRATIONS",
    "DOWN_SQL",
    "M16_TABLES",
    "connect",
    "up",
    "down",
    "status",
]

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"

#: M16 段（1400–1499，01-ownership §5）
MODULE_RANGE = (1400, 1499)

#: 本模块拥有的表（01-ownership §2 / M16 §5）
M16_TABLES: tuple[str, ...] = ("audit_log", "audit_anchors", "m16_outbox")


def _number(name: str) -> int:
    head = name.split("_", 1)[0]
    return int(head) if head.isdigit() else -1


def _is_module(name: str) -> bool:
    number = _number(name)
    return MODULE_RANGE[0] <= number <= MODULE_RANGE[1]


def _sorted_names(predicate) -> tuple[str, ...]:
    """按**数字前缀**排序（字典序会把 1400 排到 600 前面）。"""
    paths = [p for p in MIGRATIONS_DIR.glob("*.sql") if predicate(p.name)]
    return tuple(p.name for p in sorted(paths, key=lambda p: _number(p.name)))


MODULE_MIGRATIONS: tuple[str, ...] = _sorted_names(_is_module)
BASE_MIGRATIONS: tuple[str, ...] = _sorted_names(lambda name: not _is_module(name))

#: 回滚：逆序删本模块对象（1403 → 1400）。全部 ``IF EXISTS``，可重复执行。
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("1403_audit_chain_guards.sql", """
        DROP TRIGGER IF EXISTS audit_log_chain_guard ON audit_log;
        DROP TRIGGER IF EXISTS m16_outbox_audit_ref_guard ON m16_outbox;
        DROP FUNCTION IF EXISTS m16_outbox_audit_ref_guard();
        ALTER TABLE IF EXISTS audit_log DROP CONSTRAINT IF EXISTS audit_log_ts_ck;
    """),
    ("1402_m16_outbox.sql", """
        DROP TRIGGER IF EXISTS m16_outbox_guard ON m16_outbox;
        DROP TRIGGER IF EXISTS m16_outbox_no_truncate ON m16_outbox;
        DROP TABLE IF EXISTS m16_outbox;
        DROP FUNCTION IF EXISTS m16_outbox_guard();
    """),
    ("1401_audit_anchors.sql", """
        DROP TRIGGER IF EXISTS audit_anchors_no_mutation ON audit_anchors;
        DROP TRIGGER IF EXISTS audit_anchors_no_truncate ON audit_anchors;
        DROP TABLE IF EXISTS audit_anchors;
    """),
    ("1400_audit_log.sql", """
        DROP TRIGGER IF EXISTS audit_log_no_mutation ON audit_log;
        DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
        DROP TABLE IF EXISTS audit_log;
        DROP FUNCTION IF EXISTS m16_audit_forbid_mutation();
        DROP FUNCTION IF EXISTS m16_forbid_truncate();
        DROP FUNCTION IF EXISTS m16_audit_chain_guard();
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
                           application_name="m16-audit-migrate")


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
    """正向升级：基线（编号 < 1400，可选）+ 1400–1403。可重复执行。"""
    applied: list[str] = []
    if with_base:
        applied += _apply(conn, BASE_MIGRATIONS, direction="up")
    applied += _apply(conn, MODULE_MIGRATIONS, direction="up")
    return applied


def down(conn: psycopg.Connection) -> list[str]:
    """回滚：逆序删除 1400–1403 新增对象（只删本模块的，可重复执行）。"""
    return _apply(conn, [name for name, _ in DOWN_SQL], direction="down")


def status(conn: psycopg.Connection) -> dict[str, object]:
    """列出当前 schema 的 M16 表 / 函数 / 触发器 + 迁移是否已应用（证据用）。"""
    tables = [row[0] for row in conn.execute(
        """SELECT table_name FROM information_schema.tables
            WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
              AND table_name = ANY(%s) ORDER BY 1""", (list(M16_TABLES),)).fetchall()]
    functions = [row[0] for row in conn.execute(
        """SELECT p.proname FROM pg_proc p
             JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = current_schema() AND p.proname LIKE 'm16%'
            ORDER BY 1""").fetchall()]
    triggers = [row[0] for row in conn.execute(
        """SELECT t.tgname FROM pg_trigger t
             JOIN pg_class c ON c.oid = t.tgrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema() AND NOT t.tgisinternal
              AND c.relname = ANY(%s) ORDER BY 1""", (list(M16_TABLES),)).fetchall()]
    anchors = None
    if "audit_anchors" in tables:
        anchors = conn.execute("SELECT count(*) FROM audit_anchors").fetchone()[0]
    entries = None
    if "audit_log" in tables:
        entries = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    return {"tables": tables, "functions": functions, "triggers": triggers,
            "migrations": list(MODULE_MIGRATIONS),
            "audit_entries": entries, "anchors": anchors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M16 审计链迁移（up / down / status）")
    parser.add_argument("--schema", default=None, help="目标 schema（缺省用连接默认）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="正向升级（含 <1400 基线）")
    group.add_argument("--up-only", action="store_true", help="只跑 1400–1403（升级演练）")
    group.add_argument("--down", action="store_true", help="回滚本模块对象")
    group.add_argument("--status", action="store_true", help="列出本模块对象与已应用迁移")
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
            print(f"tables     ({len(info['tables'])}): {', '.join(info['tables']) or '-'}")
            print(f"functions  ({len(info['functions'])}): {', '.join(info['functions']) or '-'}")
            print(f"triggers   ({len(info['triggers'])}): {', '.join(info['triggers']) or '-'}")
            print(f"migrations : {', '.join(info['migrations'])}")
            print(f"audit_log rows = {info['audit_entries']}, anchors = {info['anchors']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
