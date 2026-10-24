# SPDX-License-Identifier: AGPL-3.0-or-later
"""M02 迁移执行器：2xx 正向升级 + 可执行回滚（验收「空库 / 升级 / 回滚」三跑）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/2xx_*_down.sql``：
CI 的执行方式是 ``for f in $(printf '%s\\n' migrations/*.sql | sort -V)``，
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被当成**正向迁移**执行。
因此回滚 DDL 由本模块持有，正向文件末尾用注释保留同等人可读版本。

用法（工作树 ``PYTHONPATH=$PWD`` + 独立 schema）::

    python -m app.supply.migrate --schema m02_t12_x --up
    python -m app.supply.migrate --schema m02_t12_x --down
    python -m app.supply.migrate --schema m02_t12_x --status

``--up`` 会先应用存量基线 001/002/003（``nodes`` 由 **003_nodes.sql** 建立，
M02 §5「迁移：只加不改；003_nodes.sql 保留为历史」）。2xx 段：200–209。

209（``v_supply_upstream_verified``）只加**只读视图**：不新增表 / 列，回滚只 DROP VIEW。
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Any, Iterable

import psycopg
from psycopg import sql

MODULE_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = MODULE_DIR.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

#: 一次正向迁移只属于一个模块（00-conventions §7.1）：M02 段 = 2xx；基线 = 003（nodes）
BASE_MIGRATIONS: tuple[str, ...] = ("001_init.sql", "002_api_keys.sql", "003_nodes.sql")
MODULE_MIGRATIONS: tuple[str, ...] = tuple(
    sorted((path.name for path in MIGRATIONS_DIR.glob("2*.sql")),
           key=lambda name: int(name.split("_", 1)[0])))

#: 回滚：逆序删本模块新增对象；**存量对象只删新增列**（00-conventions §7.2）
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("209_supply_verified_view.sql", """
        DROP VIEW IF EXISTS v_supply_upstream_verified;
    """),
    ("208_supply_heartbeat.sql", """
        DROP VIEW IF EXISTS v_supply_capacity_latest;
        DROP VIEW IF EXISTS v_supply_node_snapshot;
        DROP INDEX IF EXISTS nodes_offline_scan_idx;
        ALTER TABLE IF EXISTS nodes DROP CONSTRAINT IF EXISTS nodes_heartbeat_seq_chk;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS offline_announced_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS heartbeat_seq;
    """),
    ("207_supply_binding_codes.sql", """
        DROP INDEX IF EXISTS node_binding_codes_expiry_idx;
        DROP INDEX IF EXISTS node_binding_codes_node_idx;
        DROP TABLE IF EXISTS node_binding_codes;
    """),
    ("206_supply_idempotency.sql", """
        DROP INDEX IF EXISTS supply_idempotency_expiry_idx;
        DROP TABLE IF EXISTS supply_idempotency;
    """),
    ("205_supply_outbox.sql", """
        DROP INDEX IF EXISTS supply_outbox_aggregate_idx;
        DROP INDEX IF EXISTS supply_outbox_pending_idx;
        DROP TABLE IF EXISTS supply_outbox;
        DROP FUNCTION IF EXISTS m02_outbox_guard();
    """),
    ("204_supply_capacity.sql", """
        DROP INDEX IF EXISTS capacity_announcements_expiry_idx;
        DROP INDEX IF EXISTS capacity_announcements_node_seq_idx;
        DROP TABLE IF EXISTS capacity_announcements;
        DROP FUNCTION IF EXISTS m02_capacity_append_only();
    """),
    ("203_supply_events.sql", """
        DROP INDEX IF EXISTS node_events_kind_idx;
        DROP INDEX IF EXISTS node_events_node_ts_idx;
        DROP TABLE IF EXISTS node_events;
        DROP FUNCTION IF EXISTS m02_node_events_append_only();
    """),
    ("202_supply_policies.sql", """
        DROP INDEX IF EXISTS node_policies_digest_idx;
        DROP INDEX IF EXISTS node_policies_node_idx;
        DROP INDEX IF EXISTS node_policies_node_uq;
        DROP INDEX IF EXISTS node_policies_global_uq;
        DROP TABLE IF EXISTS node_policies;
        DROP FUNCTION IF EXISTS m02_node_policies_guard();
    """),
    ("201_supply_upstreams.sql", """
        DROP INDEX IF EXISTS node_upstreams_node_idx;
        DROP INDEX IF EXISTS node_upstreams_node_state_idx;
        DROP TABLE IF EXISTS node_upstreams;
    """),
    ("200_supply_nodes.sql", """
        DROP INDEX IF EXISTS nodes_prev_key_idx;
        DROP INDEX IF EXISTS nodes_state_seen_idx;
        DROP INDEX IF EXISTS nodes_bound_account_idx;
        DROP INDEX IF EXISTS nodes_account_idx;
        DROP INDEX IF EXISTS nodes_platform_fp_uq;
        ALTER TABLE IF EXISTS nodes DROP CONSTRAINT IF EXISTS nodes_policy_version_chk;
        ALTER TABLE IF EXISTS nodes DROP CONSTRAINT IF EXISTS nodes_retired_chk;
        ALTER TABLE IF EXISTS nodes DROP CONSTRAINT IF EXISTS nodes_key_overlap_ck;
        ALTER TABLE IF EXISTS nodes DROP CONSTRAINT IF EXISTS nodes_binding_pair_ck;
        ALTER TABLE IF EXISTS nodes DROP CONSTRAINT IF EXISTS nodes_access_modes_ck;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS lifecycle_state;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS updated_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS retired_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS retire_requested_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS reviewed_by;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS reviewed_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS prev_key_expires_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS prev_key_hash;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS prev_key_id;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS key_revoked_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS key_issued_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS key_id;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS revoked_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS bound_at;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS bound_account_id;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS runtime_state;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS labels;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS region;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS policy_version;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS capabilities;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS access_modes;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS tenant_id;
        ALTER TABLE IF EXISTS nodes DROP COLUMN IF EXISTS account_id;
    """),
)

#: 每个迁移文件「已应用」的判定对象（status 用）
_MARKERS: dict[str, tuple[str, str, str]] = {
    "200_supply_nodes.sql": ("column", "nodes", "lifecycle_state"),
    "201_supply_upstreams.sql": ("table", "node_upstreams", ""),
    "202_supply_policies.sql": ("table", "node_policies", ""),
    "203_supply_events.sql": ("table", "node_events", ""),
    "204_supply_capacity.sql": ("table", "capacity_announcements", ""),
    "205_supply_outbox.sql": ("table", "supply_outbox", ""),
    "206_supply_idempotency.sql": ("table", "supply_idempotency", ""),
    "207_supply_binding_codes.sql": ("table", "node_binding_codes", ""),
    "208_supply_heartbeat.sql": ("column", "nodes", "heartbeat_seq"),
    "209_supply_verified_view.sql": ("view", "v_supply_upstream_verified", ""),
}


def migration_files() -> tuple[pathlib.Path, ...]:
    return tuple(MIGRATIONS_DIR / name for name in BASE_MIGRATIONS + MODULE_MIGRATIONS)


def _split_statements(sql: str) -> list[str]:
    """按 ``;`` 切语句（迁移文件里没有函数体分号，202/203/204/205 用 ``$$`` 包裹但不切分）。"""
    statements: list[str] = []
    buffer: list[str] = []
    in_dollar = False
    for line in sql.splitlines():
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


def _run_script(conn: psycopg.Connection, sql: str) -> list[str]:
    executed: list[str] = []
    for statement in _split_statements(sql):
        with conn.cursor() as cur:
            cur.execute(statement)
        executed.append(statement.splitlines()[0][:120])
    conn.commit()
    return executed


def up(conn: psycopg.Connection, *, files: Iterable[pathlib.Path] | None = None) -> list[dict]:
    """正向迁移（默认 001/002/003 + 2xx）；每个文件单独提交，失败即停并回滚该文件。"""
    results: list[dict] = []
    for path in (files if files is not None else migration_files()):
        try:
            executed = _run_script(conn, path.read_text(encoding="utf-8"))
            results.append({"name": path.name, "rc": 0, "statements": len(executed)})
        except Exception as exc:                                   # pragma: no cover - 失败即停
            conn.rollback()
            results.append({"name": path.name, "rc": 1, "error": f"{type(exc).__name__}: {exc}"})
            raise
    return results


def down(conn: psycopg.Connection) -> list[dict]:
    """回滚（逆序 207→200）：可重复执行（幂等）；只删本模块新增对象与新增列。"""
    results: list[dict] = []
    for name, sql in DOWN_SQL:
        try:
            executed = _run_script(conn, sql)
            results.append({"name": name, "rc": 0, "statements": len(executed)})
        except Exception as exc:                                   # pragma: no cover - 失败即停
            conn.rollback()
            results.append({"name": name, "rc": 1, "error": f"{type(exc).__name__}: {exc}"})
            raise
    return results


def _exists(conn: psycopg.Connection, kind: str, table: str, column: str = "") -> bool:
    with conn.cursor() as cur:
        if kind == "table":
            cur.execute(
                """SELECT 1 FROM information_schema.tables
                    WHERE table_schema = current_schema() AND table_name = %s""", (table,))
        elif kind == "view":
            cur.execute(
                """SELECT 1 FROM information_schema.views
                    WHERE table_schema = current_schema() AND table_name = %s""", (table,))
        else:
            cur.execute(
                """SELECT 1 FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name = %s
                      AND column_name = %s""", (table, column))
        return cur.fetchone() is not None


def status(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """每个 2xx 迁移是否已应用（按对象存在性判定，不依赖迁移版本表）。"""
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
    parser = argparse.ArgumentParser(description="M02 迁移（2xx）正向 / 回滚 / 状态")
    parser.add_argument("--schema", required=True, help="目标 schema（隔离用，不写 public）")
    parser.add_argument("--dsn", default=None, help="连接串（缺省读 DJB_DSN）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="正向应用 001/002/003 + 2xx")
    group.add_argument("--down", action="store_true", help="逆序回滚 2xx（可重复执行）")
    group.add_argument("--status", action="store_true", help="查看 2xx 应用状态")
    args = parser.parse_args(argv)

    import os

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
