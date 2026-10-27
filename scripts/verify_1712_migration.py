#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""1712（M17 C14 申诉）迁移验收：空库 / 升级 / 回滚 / 重跑 / 三次一致 / 账本 diff=0。

用法（口令只走环境变量，不进 argv）::

    set -a; . ~/.djb/secrets/dev.env; set +a
    export DJB_DSN="postgresql://$DJB_DEV_PG_USER:$DJB_DEV_DB_PASSWORD@$DJB_DEV_PG_HOST:$DJB_DEV_PG_PORT/$DJB_DEV_PG_DB"
    cd repos/djb-cloud && PYTHONPATH=. .venv/bin/python scripts/verify_1712_migration.py

输出：JSON（stdout）。任何一项不满足 → 退出码 1。
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys
import uuid

import psycopg

from app.integrity import migrate
from app.wiring.db import migration_files

MIGRATIONS = pathlib.Path(__file__).resolve().parents[1] / "migrations"
TARGET = "1712_supplier_integrity_appeals.sql"
GUARDED = ("supplier_integrity_holds", "supplier_integrity_events")


def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        print("缺 DJB_DSN（凭据只注入环境）", file=sys.stderr)
        raise SystemExit(2)
    return value


def apply_file(conn: psycopg.Connection, path: pathlib.Path) -> None:
    conn.execute(path.read_text(encoding="utf-8"))


def ledger_digest(conn: psycopg.Connection) -> dict[str, object]:
    """账本指纹：行数 + 金额合计 + 全表行哈希（任一变化都会变）。"""
    rows = conn.execute(
        "SELECT count(*), coalesce(sum(amount_micro), 0) FROM ledger_entries").fetchone()
    digest = conn.execute(
        "SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY t.seq), ''))"
        " FROM ledger_entries t").fetchone()[0]
    balances = conn.execute(
        "SELECT count(*), md5(coalesce(string_agg(t::text, '|' ORDER BY t.account_id::text), ''))"
        " FROM account_balances t").fetchone()
    return {"entries": int(rows[0]), "amount_micro": int(rows[1]),
            "entries_md5": digest, "balances": int(balances[0]),
            "balances_md5": balances[1]}


def relation_shape(conn: psycopg.Connection, schema: str, table: str) -> dict[str, object]:
    columns = conn.execute(
        "SELECT column_name, data_type FROM information_schema.columns"
        " WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
        (schema, table)).fetchall()
    constraints = conn.execute(
        "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint"
        " WHERE connamespace = %s::regnamespace AND conrelid = %s::regclass"
        " ORDER BY conname", (schema, f"{schema}.{table}")).fetchall()
    indexes = conn.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname = %s AND tablename = %s"
        " ORDER BY indexname", (schema, table)).fetchall()
    return {"columns": columns, "constraints": constraints,
            "indexes": [row[0] for row in indexes]}


def main() -> int:
    schema = f"m17_1712_{uuid.uuid4().hex[:8]}"
    result: dict[str, object] = {"schema": schema, "checks": {}, "ok": False}
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA "{schema}"')
        try:
            conn.execute(f'SET search_path TO "{schema}", public')
            for path in migration_files():
                if path.name == TARGET:        # 先停在 1711，再演练 1712 的升级
                    continue
                apply_file(conn, path)
            # 种两笔账本数据（accounts / ledger / balances），让 diff=0 有实际载荷
            conn.execute("INSERT INTO accounts (id, kind, balance_micro)"
                         " VALUES ('acc-node', 'node', 1234), ('acc-user', 'user', -1234)")
            conn.execute(
                "INSERT INTO ledger_entries (entry_id, debit, credit, amount_micro, hash)"
                " VALUES (gen_random_uuid(), 'acc-user', 'acc-node', 1234, 'seed-hash')")
            conn.execute(
                "INSERT INTO account_balances"
                " (account_id, unit_type, sub_account, version, balance_minor)"
                " VALUES ('acc-node', 'USD', 'AVAILABLE', 1, 1234),"
                "        ('acc-user', 'USD', 'AVAILABLE', 1, -1234)")
            before_ledger = ledger_digest(conn)
            before_shape = {table: relation_shape(conn, schema, table)
                            for table in GUARDED}
            before_tables = {row[0] for row in conn.execute(
                "SELECT table_name FROM information_schema.tables"
                " WHERE table_schema = %s", (schema,)).fetchall()}

            # ── 三次重跑（幂等；每次都在同一 schema 上）───────────────
            runs = []
            for _ in range(3):
                apply_file(conn, MIGRATIONS / TARGET)
                runs.append(True)
            after_shape = {table: relation_shape(conn, schema, table)
                           for table in GUARDED}
            after_ledger = ledger_digest(conn)

            # 1710 对象结构不变（列 / 约束 / 索引逐字比较）
            result["checks"]["reruns"] = runs
            result["checks"]["guarded_shape_unchanged"] = before_shape == after_shape
            result["checks"]["ledger_diff_zero"] = before_ledger == after_ledger
            result["checks"]["ledger"] = {"before": before_ledger, "after": after_ledger}

            # 新表存在 + 窗口边界（deadline_at == created_at 允许）
            after_tables = {row[0] for row in conn.execute(
                "SELECT table_name FROM information_schema.tables"
                " WHERE table_schema = %s", (schema,)).fetchall()}
            result["checks"]["appeals_table_added"] = (
                "supplier_integrity_appeals" in after_tables - before_tables)
            hold_id = uuid.uuid4()
            conn.execute(
                "INSERT INTO supplier_integrity_holds"
                " (id, node_id, model, level, ratio_bp, base_amount_micro,"
                "  frozen_amount_micro, state, reason, evidence_ref, created_at,"
                "  expires_at, version, updated_at)"
                " VALUES (%s, 'n', 'm', 'I1', 5000, 1000, 500, 'active', 'r', 'e',"
                " now(), now() + interval '7 days', 1, now())", (hold_id,))
            conn.execute(
                "INSERT INTO supplier_integrity_appeals"
                " (id, hold_id, node_id, model, state, reason, appellant, created_at,"
                "  deadline_at, version, updated_at)"
                " VALUES (%s, %s, 'n', 'm', 'open', 'r', 'a', now(), now(), 1, now())",
                (uuid.uuid4(), hold_id))
            result["checks"]["window_edge_accepted"] = True
            try:
                conn.execute("DELETE FROM supplier_integrity_appeals")
            except psycopg.errors.InsufficientPrivilege:
                result["checks"]["delete_blocked"] = True
            else:
                result["checks"]["delete_blocked"] = False

            # ── 回滚：只删 1712 新增对象 ─────────────────────────────
            conn.execute(migrate.DOWN_SQL_BY_NAME[TARGET])
            rolled = {row[0] for row in conn.execute(
                "SELECT table_name FROM information_schema.tables"
                " WHERE table_schema = %s", (schema,)).fetchall()}
            result["checks"]["rollback_removes_only_1712"] = (
                "supplier_integrity_appeals" not in rolled
                and {t for t in GUARDED} <= rolled)
            result["checks"]["ledger_after_rollback_zero"] = (
                ledger_digest(conn) == before_ledger)

            # 回滚后可重跑（回到干净终态）
            apply_file(conn, MIGRATIONS / TARGET)
            result["checks"]["reapply_after_rollback"] = conn.execute(
                "SELECT to_regclass(%s) IS NOT NULL", (f"{schema}.supplier_integrity_appeals",)
            ).fetchone()[0]
            result["ok"] = all(value is True for key, value in result["checks"].items()
                               if isinstance(value, bool))
        finally:
            conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
