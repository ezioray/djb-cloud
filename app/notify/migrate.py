# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12 迁移执行器：1201–1209 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚」三跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/12xx_*_down.sql``：
CI 与本地都按 ``sort -V`` 把 ``migrations/*.sql`` 当**正向迁移**执行（M02/M04/M05/M06/M10 同因），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被误当成升级脚本。因此回滚 DDL 由本模块持有，
正向文件里用注释保留同等人可读版本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema；**口令只走环境变量，不进 argv**）::

    python -m app.notify.migrate --schema m12_t12_x --up
    python -m app.notify.migrate --schema m12_t12_x --down
    python -m app.notify.migrate --schema m12_t12_x --status

``--up`` 先应用**前置段**（编号 < 1200 的全部迁移：001–006 / 1xx–10xx / 14xx 除外），
再按数字序应用 1201–1209——M12 只依赖 M01 的账户口径，其余模块与本模块无关。
``--down`` 只回滚 12xx，**不动**任何前置对象；可重复执行（``IF EXISTS``）。
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


#: M12 段（1200–1299），数字序
MODULE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("12*.sql"), key=_number))

#: 前置段：编号 < 1200（存量 001–006 / M01 / M02 / M03 / M04 / M05 / M06 / M10）
PREREQUISITE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("*.sql"), key=_number)
    if _number(path) < 1200)

#: 每个迁移的「已应用」标记（按对象存在性判定，不依赖迁移版本表）
_MARKERS: dict[str, tuple[str, str, str]] = {
    "1201_notifications.sql": ("table", "notifications", ""),
    "1202_notification_outbox.sql": ("table", "notification_outbox", ""),
    "1203_webhook_subscriptions.sql": ("table", "webhook_subscriptions", ""),
    "1204_delivery_attempts.sql": ("table", "delivery_attempts", ""),
    "1205_notification_preferences.sql": ("table", "notification_preferences", ""),
    "1206_node_notifications.sql": ("table", "node_notifications", ""),
    "1207_node_notification_deliveries.sql": ("table", "node_notification_deliveries", ""),
    "1208_node_notification_events.sql": ("table", "node_notification_events", ""),
    # 1209 的对象是「护栏 + 观测视图」：用视图存在性判定（information_schema.tables 也含视图）
    "1209_node_notifications_guard.sql": ("table", "v_node_notifications_pending", ""),
}

#: 回滚：逆序删本模块新增对象（**不碰**任何前置对象；可重复执行）
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("1209_node_notifications_guard.sql", """
        DROP VIEW IF EXISTS v_node_notifications_pending;
        DROP TRIGGER IF EXISTS node_notifications_no_truncate ON node_notifications;
        DROP TRIGGER IF EXISTS node_notifications_guard ON node_notifications;
        DROP FUNCTION IF EXISTS m12_node_notification_guard();
    """),
    ("1208_node_notification_events.sql", """
        DROP TABLE IF EXISTS node_notification_events;
        DROP FUNCTION IF EXISTS m12_node_event_guard();
    """),
    ("1207_node_notification_deliveries.sql", """
        DROP TABLE IF EXISTS node_notification_deliveries;
        DROP FUNCTION IF EXISTS m12_node_delivery_immutable();
    """),
    ("1206_node_notifications.sql", """
        DROP TABLE IF EXISTS node_notifications;
        DROP FUNCTION IF EXISTS m12_node_payload_bad_key();
    """),
    ("1205_notification_preferences.sql", """
        DROP TABLE IF EXISTS notification_preferences;
    """),
    ("1204_delivery_attempts.sql", """
        DROP TABLE IF EXISTS delivery_attempts;
        DROP FUNCTION IF EXISTS m12_attempt_immutable();
    """),
    ("1203_webhook_subscriptions.sql", """
        DROP TABLE IF EXISTS webhook_subscriptions;
        DROP FUNCTION IF EXISTS m12_webhook_guard();
    """),
    ("1202_notification_outbox.sql", """
        DROP TABLE IF EXISTS notification_outbox;
        DROP FUNCTION IF EXISTS m12_outbox_guard();
        DROP FUNCTION IF EXISTS m12_outbox_insert_guard();
    """),
    ("1201_notifications.sql", """
        DROP TABLE IF EXISTS notifications;
        DROP FUNCTION IF EXISTS m12_notification_guard();
        DROP FUNCTION IF EXISTS m12_notification_insert_guard();
        DROP FUNCTION IF EXISTS m12_forbid_truncate();
    """),
)


def migration_files() -> tuple[pathlib.Path, ...]:
    """CLI 默认执行顺序：前置段（< 1200）+ 本模块段（1201–1205）。"""
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
    """正向迁移（默认 前置段 + 1201–1205）；每个文件单独提交，失败即停。"""
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
    """回滚（逆序 1209→1201）：可重复执行；只删本模块新增对象。"""
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
    """每个 12xx 迁移是否已应用。"""
    report: list[dict[str, Any]] = []
    for name in MODULE_MIGRATIONS:
        kind, table, column = _MARKERS.get(name, ("table", name.split("_", 1)[1].removesuffix(".sql"), ""))
        report.append({"name": name, "applied": _exists(conn, kind, table, column)})
    return report


def ensure_schema(dsn: str, schema: str) -> None:
    """CLI 用：目标 schema 不存在就建（不写 public；不删既有 schema）。"""
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))


def connect(dsn: str, schema: str) -> psycopg.Connection:
    """连到指定 schema。

    ``search_path`` 里的 schema 名必须**带双引号**：不引号会被服务器折叠成小写，
    混合大小写（如 ``m12_evid_20261023T1250Z``）就会变成「没有 schema 被选中」。
    """
    quoted = '"' + schema.replace('"', '""') + '"'
    return psycopg.connect(dsn, autocommit=False, options=f"-c search_path={quoted}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M12 迁移（1201–1205）正向 / 回滚 / 状态")
    parser.add_argument("--schema", required=True, help="目标 schema（隔离用，不写 public）")
    parser.add_argument("--dsn", default=None, help="连接串（缺省读环境变量 DJB_DSN）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="正向应用 前置段 + 1201–1205")
    group.add_argument("--down", action="store_true", help="逆序回滚 12xx（可重复执行）")
    group.add_argument("--status", action="store_true", help="查看 12xx 应用状态")
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
