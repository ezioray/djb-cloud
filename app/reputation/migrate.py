# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 迁移执行器：701/702/704/705/706/707 正向升级 + 可执行回滚 + 结构指纹。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/7xx_*_down.sql``：CI 与本地都按
``sort -V`` 把 ``migrations/*.sql`` 当**正向迁移**执行（M02/M04/M05/M06/M12 同因），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被误当成升级脚本。因此回滚 DDL 由本模块持有，
正向文件里用注释保留同等人可读版本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema；**口令只走环境变量，不进 argv**）::

    python -m app.reputation.migrate --schema m07_x --up
    python -m app.reputation.migrate --schema m07_x --down
    python -m app.reputation.migrate --schema m07_x --status
    python -m app.reputation.migrate --schema m07_x --fingerprint

``--up`` 先应用**前置段**（700–799 之外的全部迁移：001–006 / 1xx–6xx / 9xx–14xx），
再按数字序应用 7xx——COP 台账（006）是本模块的只读依赖，必须先于 707 的视图存在。
``--down`` 只回滚 7xx，**不动**任何前置对象，也不删 ``points_*`` 里已发放的 COP
（§5「回滚用兼容迁移，不回删已发放 COP」）；可重复执行（``IF EXISTS``）。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import sys
from typing import Any, Iterable

import psycopg
from psycopg import sql

MODULE_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = MODULE_DIR.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

#: 本模块段（700–799），数字序
MODULE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("7[0-9][0-9]_*.sql"),
                                 key=lambda item: int(item.name.split("_", 1)[0])))

def _in_module_segment(name: str) -> bool:
    """M07 独占段 700–799。注意 1xxx（M10/M12/M16）与 9xx（M09）**不是** M07 的段。"""
    return 700 <= int(name.split("_", 1)[0]) <= 799


#: 前置段：除 700–799 之外的全部迁移（含 COP 台账 006；M07 依赖它建只读视图）
PREREQUISITE_MIGRATIONS: tuple[str, ...] = tuple(
    path.name for path in sorted(MIGRATIONS_DIR.glob("*.sql"),
                                 key=lambda item: int(item.name.split("_", 1)[0]))
    if not _in_module_segment(path.name)
)

#: 每个迁移的「已应用」标记（按对象存在性判定，不依赖迁移版本表）
_MARKERS: dict[str, tuple[str, str, str]] = {
    "701_reputation_scores.sql": ("table", "reputation_scores", ""),
    "702_reputation_events.sql": ("table", "reputation_events", ""),
    "704_invites.sql": ("table", "invites", ""),
    "705_reward_grants.sql": ("table", "reward_grants", ""),
    "706_reputation_outbox.sql": ("table", "reputation_outbox", ""),
    "707_m07_cop_ledger_view.sql": ("view", "v_m07_cop_ledger", ""),
}

#: 回滚：逆序删本模块新增对象（**不碰**前置对象与 points_* 数据；可重复执行）
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("707_m07_cop_ledger_view.sql", """
        DROP VIEW IF EXISTS v_m07_cop_ledger;
        DROP VIEW IF EXISTS v_m07_cop_status;
    """),
    ("706_reputation_outbox.sql", """
        DROP TABLE IF EXISTS reputation_outbox;
        DROP FUNCTION IF EXISTS m07_outbox_guard();
        DROP FUNCTION IF EXISTS m07_outbox_insert_guard();
    """),
    ("705_reward_grants.sql", """
        DROP TABLE IF EXISTS reward_grants;
    """),
    ("704_invites.sql", """
        DROP TABLE IF EXISTS invites;
        DROP FUNCTION IF EXISTS m07_invite_single_layer();
        DROP FUNCTION IF EXISTS m07_invite_state_machine();
    """),
    ("702_reputation_events.sql", """
        DROP TABLE IF EXISTS reputation_events;
    """),
    ("701_reputation_scores.sql", """
        DROP TABLE IF EXISTS reputation_scores;
        DROP FUNCTION IF EXISTS m07_forbid_mutation();
        DROP FUNCTION IF EXISTS m07_forbid_truncate();
    """),
)

#: 结构指纹覆盖的表（验收 1：7xx 前后 ``points_*`` 结构必须逐字节一致）
FINGERPRINT_TABLES: tuple[str, ...] = (
    "points_account", "points_policy", "points_journal", "points_ledger", "points_transfer",
)


def migration_files() -> tuple[pathlib.Path, ...]:
    """CLI 默认执行顺序：前置段（< 700）+ 本模块段（7xx）。"""
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
    """正向迁移（默认 前置段 + 7xx）；每个文件单独提交，失败即停。"""
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
    """回滚（逆序 707→701）：可重复执行；只删本模块新增对象。"""
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


def _exists(conn: psycopg.Connection, kind: str, name: str, column: str = "") -> bool:
    with conn.cursor() as cur:
        if kind == "table":
            cur.execute(
                """SELECT 1 FROM information_schema.tables
                    WHERE table_schema = current_schema() AND table_name = %s""", (name,))
        elif kind == "view":
            cur.execute(
                """SELECT 1 FROM information_schema.views
                    WHERE table_schema = current_schema() AND table_name = %s""", (name,))
        else:
            cur.execute(
                """SELECT 1 FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name = %s
                      AND column_name = %s""", (name, column))
        return cur.fetchone() is not None


def status(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """每个 7xx 迁移是否已应用。"""
    report: list[dict[str, Any]] = []
    for name in MODULE_MIGRATIONS:
        kind, target, column = _MARKERS.get(name, ("table", name.split("_", 1)[1].removesuffix(".sql"), ""))
        report.append({"name": name, "applied": _exists(conn, kind, target, column)})
    return report


# --------------------------------------------------------------------------- 结构指纹
def structure_fingerprint(conn: psycopg.Connection,
                          tables: Iterable[str] = FINGERPRINT_TABLES) -> dict[str, Any]:
    """``information_schema`` + ``pg_indexes`` + 约束定义的结构指纹（与数据无关）。

    用途：验收「7xx 前后 ``points_*`` 结构不变」——只比结构，不比数据；
    同一 schema、同一 DDL 状态下多次计算结果一致。
    """
    per_table: dict[str, str] = {}
    for table in tables:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT column_name, data_type, is_nullable, COALESCE(column_default, ''),
                          COALESCE(character_maximum_length, -1),
                          COALESCE(numeric_precision, -1), COALESCE(numeric_scale, -1)
                     FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name = %s
                    ORDER BY ordinal_position""", (table,))
            columns = [tuple(str(value) for value in row) for row in cur.fetchall()]
            cur.execute(
                """SELECT indexname, indexdef FROM pg_indexes
                    WHERE schemaname = current_schema() AND tablename = %s
                    ORDER BY indexname""", (table,))
            indexes = [tuple(str(value) for value in row) for row in cur.fetchall()]
            cur.execute(
                """SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
                    WHERE conrelid = (quote_ident(current_schema()) || '.' || quote_ident(%s))::regclass
                    ORDER BY conname""", (table,))
            constraints = [tuple(str(value) for value in row) for row in cur.fetchall()]
        blob = repr((columns, indexes, constraints)).encode("utf-8")
        per_table[table] = hashlib.sha256(blob).hexdigest()
    digest = hashlib.sha256(
        repr(sorted(per_table.items())).encode("utf-8")).hexdigest()
    return {"tables": per_table, "digest": digest}


# --------------------------------------------------------------------------- CLI
def ensure_schema(dsn: str, schema: str) -> None:
    """CLI 用：目标 schema 不存在就建（不写 public；不删既有 schema）。"""
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))


def connect(dsn: str, schema: str) -> psycopg.Connection:
    """连到指定 schema（schema 名必须带双引号，避免大小写被折叠成「没有 schema」）。"""
    quoted = '"' + schema.replace('"', '""') + '"'
    return psycopg.connect(dsn, autocommit=False, options=f"-c search_path={quoted}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M07 迁移（7xx）正向 / 回滚 / 状态 / 指纹")
    parser.add_argument("--schema", required=True, help="目标 schema（隔离用，不写 public）")
    parser.add_argument("--dsn", default=None, help="连接串（缺省读环境变量 DJB_DSN）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="正向应用 前置段 + 7xx")
    group.add_argument("--down", action="store_true", help="逆序回滚 7xx（可重复执行）")
    group.add_argument("--status", action="store_true", help="查看 7xx 应用状态")
    group.add_argument("--fingerprint", action="store_true", help="打印 points_* 结构指纹")
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
        elif args.fingerprint:
            print(structure_fingerprint(conn))
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
