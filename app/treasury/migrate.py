# SPDX-License-Identifier: Apache-2.0
"""M08 迁移执行器：800–805 正向升级 + 可执行回滚 + seed（验收「空库 / 升级 / 回滚 / 幂等」四跑）。

为什么回滚 SQL 放在 Python 里而不是 migrations/8xx_*_down.sql：
CI 与本地都把 migrations/*.sql 当**正向迁移**执行（与 M02/M04/M05/M06/M09/M10/M11/M12 同因），
放在 migrations/ 下的任何 *.sql 都会被误当成升级脚本。正向文件里用注释保留说明。

用法（工作树 PYTHONPATH=$PWD + 独立 schema；**口令只走环境变量，不进 argv**）::

    python -m app.treasury.migrate --schema m08_x --up          # 001…805 基线 + 本段
    python -m app.treasury.migrate --schema m08_x --up-only     # 只跑 800–805（升级演练）
    python -m app.treasury.migrate --schema m08_x --down        # 只回滚本段（可重复执行）
    python -m app.treasury.migrate --schema m08_x --status
    python -m app.treasury.migrate --schema m08_x --seed        # 一期 3 池幂等 seed

--down 只删本模块新增对象（表 / 视图 / 触发器 / 函数 / 序列 / 追加列），不动任何前置对象；
回滚后重跑 --up-only 必须仍然成功（幂等）。
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import psycopg

__all__ = [
    "MIGRATIONS_DIR", "MODULE_RANGE", "MODULE_MIGRATIONS", "BASE_MIGRATIONS", "DOWN_SQL",
    "M08_TABLES", "M08_LEGACY_TABLES", "M08_VIEWS", "SEED_POOLS", "connect", "up", "down",
    "status", "seed", "dsn",
]

MIGRATIONS_DIR = pathlib.Path(__file__).resolve().parents[2] / "migrations"

#: M08 段（800–899；M08 §0 / 01-ownership §5）
MODULE_RANGE = (800, 899)

#: 本模块**新增**的表（规格 §5 + 805 outbox + CR-P6 白名单表）
M08_TABLES: tuple[str, ...] = (
    "payment_orders", "payment_attempts", "wallet_transfers", "payout_batches",
    "payout_items", "payout_addresses", "refund_requests", "treasury_intents",
    "signing_intents", "signing_events", "m08_outbox",
)
#: 004 / 005 已建、归 M08 的存量表（只加列 / 不改名，01-ownership §7）
M08_LEGACY_TABLES: tuple[str, ...] = (
    "wallet_pool", "wallet", "wallet_provision_batch", "wallet_activation",
    "wallet_pool_event", "deposit_address", "chain_tx", "chain_tx_event",
)
M08_VIEWS: tuple[str, ...] = ("v_m08_pool_depth", "v_m08_refund_open", "v_m08_signing_progress")

#: 一期 3 池（平台热池不建，决策 K5；与 004 的 seed 一致）
SEED_POOLS: tuple[dict[str, object], ...] = (
    {"pool_id": "polygon:hot:customer", "chain_id": "polygon", "role": "hot",
     "fund_class": "customer"},
    {"pool_id": "polygon:warm:customer", "chain_id": "polygon", "role": "warm",
     "fund_class": "customer"},
    {"pool_id": "polygon:warm:platform", "chain_id": "polygon", "role": "warm",
     "fund_class": "platform"},
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

#: 回滚：逆序删本模块对象（805 → 800）。全部 IF EXISTS，可重复执行。
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("805_m08_outbox.sql", """
        DROP TRIGGER IF EXISTS m08_outbox_guard ON m08_outbox;
        DROP TRIGGER IF EXISTS m08_outbox_no_truncate ON m08_outbox;
        DROP TABLE IF EXISTS m08_outbox;
        DROP FUNCTION IF EXISTS m08_outbox_guard();
    """),
    ("804_treasury_intents.sql", """
        DROP VIEW IF EXISTS v_m08_signing_progress;
        DROP TRIGGER IF EXISTS signing_events_guard ON signing_events;
        DROP TRIGGER IF EXISTS signing_events_no_truncate ON signing_events;
        DROP TABLE IF EXISTS signing_events;
        DROP TRIGGER IF EXISTS signing_intents_no_truncate ON signing_intents;
        DROP TABLE IF EXISTS signing_intents;
        DROP TRIGGER IF EXISTS m08_intents_guard ON treasury_intents;
        DROP TRIGGER IF EXISTS treasury_intents_no_truncate ON treasury_intents;
        DROP TABLE IF EXISTS treasury_intents;
        DROP SEQUENCE IF EXISTS treasury_intent_nonce_seq;
        DROP FUNCTION IF EXISTS m08_intents_guard();
        DROP FUNCTION IF EXISTS m08_signing_events_guard();
    """),
    ("803_refund_requests.sql", """
        DROP VIEW IF EXISTS v_m08_refund_open;
        DROP TRIGGER IF EXISTS m08_refunds_guard ON refund_requests;
        DROP TRIGGER IF EXISTS refund_requests_no_truncate ON refund_requests;
        DROP TABLE IF EXISTS refund_requests;
        DROP SEQUENCE IF EXISTS refund_no_seq;
        DROP FUNCTION IF EXISTS m08_refunds_guard();
    """),
    ("802_payout_batches.sql", """
        DROP TRIGGER IF EXISTS payout_addresses_no_truncate ON payout_addresses;
        DROP TRIGGER IF EXISTS m08_payout_addresses_guard ON payout_addresses;
        DROP TABLE IF EXISTS payout_addresses;
        DROP TRIGGER IF EXISTS payout_batches_no_truncate ON payout_batches;
        DROP TRIGGER IF EXISTS m08_payouts_guard ON payout_batches;
        DROP TABLE IF EXISTS payout_items;
        DROP TABLE IF EXISTS payout_batches;
        DROP SEQUENCE IF EXISTS payout_batch_no_seq;
        DROP FUNCTION IF EXISTS m08_payouts_guard();
        DROP FUNCTION IF EXISTS m08_payout_addresses_guard();
    """),
    ("801_wallet_pool_ext.sql", """
        DROP VIEW IF EXISTS v_m08_pool_depth;
        DROP TRIGGER IF EXISTS wallet_transfers_no_truncate ON wallet_transfers;
        DROP TRIGGER IF EXISTS m08_transfers_guard ON wallet_transfers;
        DROP TABLE IF EXISTS wallet_transfers;
        DROP TRIGGER IF EXISTS m08_batch_guard ON wallet_provision_batch;
        DROP TRIGGER IF EXISTS wallet_provision_batch_no_truncate ON wallet_provision_batch;
        DROP TRIGGER IF EXISTS m08_wallet_guard ON wallet;
        DROP TRIGGER IF EXISTS wallet_no_truncate ON wallet;
        DROP FUNCTION IF EXISTS m08_transfers_guard();
        DROP FUNCTION IF EXISTS m08_batch_guard();
        DROP FUNCTION IF EXISTS m08_wallet_guard();
        ALTER TABLE wallet_provision_batch DROP CONSTRAINT IF EXISTS wallet_provision_batch_status_m08_ck;
        ALTER TABLE wallet DROP CONSTRAINT IF EXISTS wallet_cap_ck;
        ALTER TABLE wallet DROP CONSTRAINT IF EXISTS wallet_standby_balance_ck;
        ALTER TABLE wallet DROP COLUMN IF EXISTS cap_minor;
        ALTER TABLE wallet DROP COLUMN IF EXISTS policy_version;
        ALTER TABLE wallet DROP COLUMN IF EXISTS last_switched_at;
        ALTER TABLE wallet DROP COLUMN IF EXISTS retired_reason;
        ALTER TABLE wallet DROP COLUMN IF EXISTS updated_at;
        ALTER TABLE wallet_provision_batch DROP COLUMN IF EXISTS batch_no;
        ALTER TABLE wallet_provision_batch DROP COLUMN IF EXISTS created_by;
        ALTER TABLE wallet_provision_batch DROP COLUMN IF EXISTS idempotency_key;
        ALTER TABLE wallet_provision_batch DROP COLUMN IF EXISTS signing_request_id;
        ALTER TABLE wallet_provision_batch DROP COLUMN IF EXISTS policy_version;
        ALTER TABLE wallet_provision_batch DROP COLUMN IF EXISTS updated_at;
    """),
    ("800_payment_orders.sql", """
        DROP TRIGGER IF EXISTS payment_attempts_guard ON payment_attempts;
        DROP TRIGGER IF EXISTS payment_attempts_no_truncate ON payment_attempts;
        DROP TABLE IF EXISTS payment_attempts;
        DROP TRIGGER IF EXISTS payment_orders_guard ON payment_orders;
        DROP TRIGGER IF EXISTS payment_orders_no_truncate ON payment_orders;
        DROP TABLE IF EXISTS payment_orders;
        DROP SEQUENCE IF EXISTS payment_order_no_seq;
        DROP FUNCTION IF EXISTS m08_orders_guard();
        DROP FUNCTION IF EXISTS m08_attempts_guard();
        DROP FUNCTION IF EXISTS m08_forbid_truncate();
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
                           application_name="m08-treasury-migrate")


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
    """逆序回滚本模块（805 → 800）；只删本模块对象，可重复执行。"""
    return _apply(conn, tuple(name for name, _ in DOWN_SQL), direction="down")


def status(conn: psycopg.Connection) -> dict[str, str]:
    """按对象存在性判定本段每个迁移的状态（不依赖迁移版本表）。"""
    markers: dict[str, tuple[str, str]] = {
        "800_payment_orders.sql": ("table", "payment_orders"),
        "800_payment_orders.sql#attempts": ("table", "payment_attempts"),
        "801_wallet_pool_ext.sql": ("table", "wallet_transfers"),
        "801_wallet_pool_ext.sql#view": ("view", "v_m08_pool_depth"),
        "802_payout_batches.sql": ("table", "payout_batches"),
        "802_payout_batches.sql#items": ("table", "payout_items"),
        "802_payout_batches.sql#addresses": ("table", "payout_addresses"),
        "803_refund_requests.sql": ("table", "refund_requests"),
        "804_treasury_intents.sql": ("table", "treasury_intents"),
        "804_treasury_intents.sql#signing": ("table", "signing_intents"),
        "804_treasury_intents.sql#events": ("table", "signing_events"),
        "805_m08_outbox.sql": ("table", "m08_outbox"),
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


def seed(conn: psycopg.Connection) -> list[str]:
    """一期 3 池幂等 seed（004 已建则跳过）；不改任何既有参数。"""
    seeded: list[str] = []
    with conn.cursor() as cur:
        for pool in SEED_POOLS:
            cur.execute(
                """
                INSERT INTO wallet_pool (pool_id, chain_id, role, fund_class,
                                         min_spare_count, max_active_count,
                                         switch_threshold_pct, activate_batch_size,
                                         provision_lead_time_h, pool_cap_minor,
                                         switch_policy, policy_version)
                VALUES (%s, %s, %s, %s, 3, %s, 70, 4, 12, 5000000, 'least_utilized', 'v4.0')
                ON CONFLICT (pool_id) DO NOTHING
                RETURNING pool_id
                """,
                (pool["pool_id"], pool["chain_id"], pool["role"], pool["fund_class"],
                 8 if pool["role"] == "hot" else 4))
            row = cur.fetchone()
            seeded.append(f"{pool['pool_id']}:{'created' if row else 'exists'}")
    return seeded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.treasury.migrate",
                                     description="M08 迁移执行器（800–805）")
    parser.add_argument("--schema", required=False, default=None,
                        help="目标 schema（测试 / 演练用；缺省用连接默认 search_path）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="前置段 + 800–805")
    group.add_argument("--up-only", action="store_true", help="只跑 800–805")
    group.add_argument("--down", action="store_true", help="只回滚 800–805（可重复）")
    group.add_argument("--status", action="store_true", help="查看本段对象状态")
    group.add_argument("--seed", action="store_true", help="一期 3 池幂等 seed")
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
        elif args.seed:
            for item in seed(conn):
                print(f"seed {item}")
        else:
            for name, state in status(conn).items():
                print(f"{state:8s} {name}")
    return 0


if __name__ == "__main__":                                # pragma: no cover
    sys.exit(main())
