# SPDX-License-Identifier: Apache-2.0
"""tests/treasury 脚手架：schema 隔离 / 迁移四跑 / 夹具构造 / M06 posting 适配器。

隔离约定（与 tests/risk / tests/recon 同款）：

* 每个测试进程独立 schema 前缀（m08_t_<pid>_<hex>，M08_SCHEMA 可覆盖），结束 DROP；
* 迁移用 psycopg 逐文件执行（与 python -m app.treasury.migrate 同一路径），DSN 由 DJB_DSN 注入；
* 缺 DJB_DSN 时 DB 用例整体 skip，纯函数用例照跑；
* 覆盖率（M08_COVERAGE=1）必须在导入 app.treasury **之前**启动（见 conftest.py 顶部）。

**测试侧**才允许 import app.ledger（M08 模块本体不 import 其他模块；E3/E4/E5 走注入的
posting 适配器，这里用真实 M06 网关验证凭证形状与借贷平衡）。
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

import psycopg
from psycopg.rows import dict_row

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

M08_TABLES: tuple[str, ...] = (
    "payment_orders", "payment_attempts", "wallet_transfers", "payout_batches",
    "payout_items", "payout_addresses", "refund_requests", "treasury_intents",
    "signing_intents", "signing_events", "m08_outbox",
)
M08_LEGACY_TABLES: tuple[str, ...] = (
    "wallet_pool", "wallet", "wallet_provision_batch", "wallet_activation",
    "wallet_pool_event", "deposit_address", "chain_tx", "chain_tx_event",
)
M08_VIEWS: tuple[str, ...] = ("v_m08_pool_depth", "v_m08_refund_open", "v_m08_signing_progress")

FIXED_NOW = datetime(2026, 10, 24, 1, 0, tzinfo=timezone.utc)


# ───────────────────────────────────────────────────────────── 连接 / schema
def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库 / 不入提交）")
    return value


def connect(schema: str, *, autocommit: bool = True) -> psycopg.Connection:
    # 测试 schema 用完即 DROP：synchronous_commit=off 避免每条 DDL 都等 WAL flush（NAS 上 10x+）
    return psycopg.connect(dsn(), autocommit=autocommit,
                           options=f"-c search_path={schema} -c synchronous_commit=off",
                           connect_timeout=15, application_name="m08-treasury-tests")


@contextmanager
def session(schema: str):
    connection = connect(schema)
    try:
        yield connection
    finally:
        connection.close()


def create_schema(schema: str) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')


def drop_schema(schema: str) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


# ───────────────────────────────────────────────────────────── 迁移
def _number(name: str) -> int:
    head = name.split("_", 1)[0]
    return int(head) if head.isdigit() else -1


def _sorted(files: Iterable[pathlib.Path]) -> list[pathlib.Path]:
    return sorted(files, key=lambda path: (_number(path.name), path.name))


def all_migration_files() -> list[pathlib.Path]:
    return _sorted(MIGRATIONS_DIR.glob("*.sql"))


def m08_migration_files() -> list[pathlib.Path]:
    return [path for path in all_migration_files() if 800 <= _number(path.name) <= 899]


def prerequisite_files() -> list[pathlib.Path]:
    return [path for path in all_migration_files() if _number(path.name) < 800]


def apply_migrations(schema: str, files: Iterable[pathlib.Path] | None = None) -> list[str]:
    applied: list[str] = []
    with connect(schema) as conn:
        for path in (files if files is not None else all_migration_files()):
            conn.execute(path.read_text(encoding="utf-8"))
            applied.append(path.name)
    return applied


def apply_m08_twice(schema: str) -> None:
    for _ in range(2):
        apply_migrations(schema, m08_migration_files())


# ───────────────────────────────────────────────────────────── 结构读取
def table_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = %s", (schema,))
        return {row[0] for row in cur.fetchall()}


def view_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT viewname FROM pg_views WHERE schemaname = %s", (schema,))
        return {row[0] for row in cur.fetchall()}


def column_signature(schema: str, tables: Iterable[str] | None = None) -> dict[str, Any]:
    names = sorted(tables) if tables is not None else sorted(table_names(schema))
    signature: dict[str, Any] = {}
    with session(schema) as conn, conn.cursor(row_factory=dict_row) as cur:
        for table in names:
            cur.execute(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns"
                " WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (schema, table))
            signature[table] = [dict(row) for row in cur.fetchall()]
    return signature


def constraint_names(schema: str, table: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT c.conname FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid"
            " JOIN pg_namespace n ON n.oid = r.relnamespace"
            " WHERE n.nspname = %s AND r.relname = %s", (schema, table))
        return {row[0] for row in cur.fetchall()}


def ledger_fingerprint(schema: str) -> dict[str, Any]:
    """M06 账本指纹：凭证数 / 行数 / 借贷合计（迁移前后必须完全一致）。"""
    with session(schema) as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT count(*) AS journals,"
            " COALESCE(max(seq), 0) AS max_seq"
            " FROM journal_entry")
        journals = dict(cur.fetchone())
        cur.execute(
            "SELECT count(*) AS lines,"
            " COALESCE(sum(amount_minor) FILTER (WHERE dc = 'D'), 0) AS debit,"
            " COALESCE(sum(amount_minor) FILTER (WHERE dc = 'C'), 0) AS credit"
            " FROM journal_line")
        lines = dict(cur.fetchone())
        cur.execute("SELECT COALESCE(sum(balance_minor), 0) AS total FROM account_balances_latest")
        balances = int(cur.fetchone()["total"])
    return {**journals, **lines, "balances_total": balances}


# ───────────────────────────────────────────────────────────── M06 posting 适配器（测试侧）
class LedgerAdapter:
    """把 M08 的 PostingRequest 转成 M06 JournalDraft 并落账（真实网关，仅测试使用）。"""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def post(self, conn: Any, request: Any) -> Mapping[str, Any]:
        from app.ledger import JournalDraft, JournalLine, post_journal

        payload = request.as_dict()
        lines = [
            JournalLine(account_id=line["account_id"], coa_code=line["coa_code"],
                        dc=line["dc"], amount_minor=int(line["amount_minor"]),
                        entry_type=line["entry_type"], qty_minor=line["qty_minor"],
                        unit_scale=int(line["unit_scale"]), wallet_id=line["wallet_id"])
            for line in payload["lines"]
        ]
        draft = JournalDraft(
            event_type=payload["event_type"], unit_type=payload["unit_type"],
            source_type=payload["source_type"], source_id=payload["source_id"],
            event_seq=int(payload["event_seq"]), policy_version=payload["policy_version"],
            lines=lines, ts=payload["occurred_at"], ref_id=payload["ref_id"],
            trace_id=payload["trace_id"] or uuid.uuid4().hex,
            correlation_id=payload["correlation_id"],
            idempotency_key=payload["idempotency_key"])
        result = post_journal(conn, draft)
        self.calls.append(payload)
        return {"journal_id": result.journal_id, "idempotent": result.idempotent,
                "seq": int(result.seq)}


class FailingPoster:
    def post(self, conn: Any, request: Any) -> Mapping[str, Any]:  # pragma: no cover - 由用例调用
        raise AssertionError("ledger poster 不应被调用")


# ───────────────────────────────────────────────────────────── 夹具构造
def make_order(conn: psycopg.Connection, *, order_no: str = "PO-20261024-000001",
               account_id: str = "acct-1", amount_minor: int = 100_00,
               currency: str = "USD", method: str = "card", provider: str = "mock",
               status: str = "created", credited_minor: int = 0,
               paid_at: datetime | None = None, now: datetime | None = None,
               idempotency_key: str | None = None) -> dict[str, Any]:
    moment = now or FIXED_NOW
    order_id = str(uuid.uuid4())
    paid = paid_at or (moment if status in ("paid", "credited") else None)
    credited = moment if status == "credited" else None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO payment_orders (order_id, order_no, account_id, amount_minor, currency,
                                        method, provider, status, credited_minor, policy_version,
                                        idempotency_key, request_hash, trace_id, created_by,
                                        paid_at, credited_at, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'm08-pool-default', %s, 'fp', 'trace',
                    'tester', %s, %s, %s, %s)
            RETURNING *
            """,
            (order_id, order_no, account_id, int(amount_minor), currency, method, provider,
             status, int(credited_minor), idempotency_key, paid, credited, moment, moment))
        return dict(cur.fetchone())


def make_attempt(conn: psycopg.Connection, order: Mapping[str, Any], *,
                 provider_txn_id: str = "txn-0001", status: str = "succeeded",
                 signature_verified: bool = True, now: datetime | None = None) -> dict[str, Any]:
    moment = now or FIXED_NOW
    attempt_id = str(uuid.uuid4())
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO payment_attempts (attempt_id, order_id, provider, provider_txn_id,
                                          provider_status, status, amount_minor, fee_minor,
                                          net_minor, currency, signature_verified, payload_hash,
                                          created_at, updated_at)
            VALUES (%s, %s, %s, %s, 'succeeded', %s, %s, 0, %s, %s, %s, 'hash', %s, %s)
            RETURNING *
            """,
            (attempt_id, str(order["order_id"]), order["provider"], provider_txn_id, status,
             int(order["amount_minor"]), int(order["amount_minor"]), order["currency"],
             bool(signature_verified), moment, moment))
        return dict(cur.fetchone())




def make_paid_order(conn: psycopg.Connection, *, order_no: str = "PO-20261024-000009",
                    account_id: str = "acct-1", amount_minor: int = 100_00,
                    currency: str = "USD", method: str = "card", provider: str = "mock",
                    provider_txn_id: str = "txn-0009",
                    now: datetime | None = None) -> dict[str, Any]:
    """已入账订单 + 成功尝试（退款 / 结算用例）。"""
    moment = now or FIXED_NOW
    order = make_order(conn, order_no=order_no, account_id=account_id,
                       amount_minor=amount_minor, currency=currency, method=method,
                       provider=provider, status="credited", credited_minor=int(amount_minor),
                       paid_at=moment, now=moment)
    attempt = make_attempt(conn, order, provider_txn_id=provider_txn_id, now=moment)
    return {"order": order, "attempt": attempt}


def webhook_body(order: Mapping[str, Any], *, provider_txn_id: str = "txn-0001",
                 amount_minor: int | None = None, currency: str | None = None,
                 status: str = "1", timestamp: int | None = None,
                 key: bytes | str = b"test-only-mock-key",
                 mer_id: str = "m08-merchant") -> bytes:
    """构造 UPG / GIFPay 形态回调并签名（原始字节参与验签）。"""
    from app.treasury import provider as provider_mod

    moment = FIXED_NOW
    fields = {
        "merId": mer_id,
        "merOrderId": order["order_no"],
        "platformOrderId": provider_txn_id,
        "amount": int(amount_minor if amount_minor is not None else order["amount_minor"]),
        "currency": currency or order["currency"],
        "status": status,
        "timestamp": int(timestamp if timestamp is not None else moment.timestamp()),
        "payTime": clock_iso(moment),
    }
    if isinstance(key, str):
        key = key.encode("utf-8")
    fields["sign"] = provider_mod.sign(fields, key)
    return json.dumps(fields, ensure_ascii=False).encode("utf-8")


def clock_iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_wallet(conn: psycopg.Connection, *, pool_id: str = "polygon:hot:customer",
                wallet_id: str | None = None, address: str | None = None,
                status: str = "active", switch_state: str = "in_service",
                balance_minor: int = 0, gas_ok: bool = True,
                cap_minor: int = 1_000_000, role: str | None = None,
                fund_class: str | None = None) -> dict[str, Any]:
    wallet_id = wallet_id or str(uuid.uuid4())
    address = address or ("0x" + hashlib.sha256(wallet_id.encode()).hexdigest()[:40])
    chain, default_role, default_class = pool_id.split(":")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO wallet (wallet_id, chain_id, address, pool_id, pool_role, fund_class,
                                custody_kind, status, switch_state, signer_set_ref,
                                descriptor_hash, balance_minor, gas_ok, cap_minor,
                                policy_version, provisioned_at, activated_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'self_custody_hot', %s, %s, 'signers:test',
                    'dh', %s, %s, %s, 'm08-pool-default', %s, %s, %s)
            RETURNING *
            """,
            (wallet_id, chain, address.lower(), pool_id, role or default_role,
             fund_class or default_class, status, switch_state, int(balance_minor),
             bool(gas_ok), int(cap_minor), FIXED_NOW, FIXED_NOW, FIXED_NOW))
        return dict(cur.fetchone())


def make_payout_address(conn: psycopg.Connection, *, account_id: str = "acct-1",
                        address: str | None = None, status: str = "whitelisted",
                        cooldown_until: datetime | None = None,
                        risk_level: str = "low",
                        first_transfer_at: datetime | None = None,
                        label: str | None = None) -> dict[str, Any]:
    address = address or ("0x" + hashlib.sha256(f"payee-{account_id}".encode()).hexdigest()[:40])
    moment = FIXED_NOW
    cooldown = cooldown_until or (moment - timedelta(days=4))
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO payout_addresses (address_id, account_id, chain_id, address, status,
                                          ownership_challenge_ref, ownership_verified_at,
                                          risk_level, cooldown_until, first_transfer_at,
                                          changed_at, approved_by, approved_at, label,
                                          created_at, updated_at)
            VALUES (%s, %s, 'polygon', %s, %s, 'challenge-ref', %s, %s, %s, %s, %s,
                    'auditor', %s, %s, %s, %s)
            RETURNING *
            """,
            (str(uuid.uuid4()), account_id, address.lower(), status, moment - timedelta(days=5),
             risk_level, cooldown, first_transfer_at, moment - timedelta(days=5),
             moment - timedelta(days=5), label, moment, moment))
        return dict(cur.fetchone())


def insert_provision_batch(conn: psycopg.Connection, *, pool_id: str = "polygon:hot:customer",
                           status: str = "draft", count: int = 2,
                           expires_at: datetime | None = None,
                           signing_request_id: str | None = None,
                           wallet_ids: list[str] | None = None,
                           addresses: list[str] | None = None) -> dict[str, Any]:
    batch_id = str(uuid.uuid4())
    wallet_ids = wallet_ids or [str(uuid.uuid4()) for _ in range(count)]
    addresses = addresses or [
        "0x" + hashlib.sha256(f"batch-{batch_id}-{index}".encode()).hexdigest()[:40]
        for index in range(count)]
    descriptors = [
        {"wallet_id": wallet_id, "address": address, "role": pool_id.split(":")[1],
         "fund_class": pool_id.split(":")[2], "chain_id": "polygon",
         "signer_set_ref": "signers:test", "threshold": 2}
        for wallet_id, address in zip(wallet_ids, addresses)
    ]
    moment = FIXED_NOW
    expiry = expires_at or (moment + timedelta(hours=24))
    created_at = expiry - timedelta(hours=24) if expires_at is not None else moment
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO wallet_provision_batch (batch_id, pool_id, batch_no, kind, wallet_count,
                                                descriptor_merkle_root, cap_params, dedupe_key,
                                                status, expires_at, created_at, created_by,
                                                policy_version, signing_request_id, updated_at)
            VALUES (%s, %s, %s, 'WALLET_PROVISION', %s, %s, %s, %s, %s, %s, %s, 'maker',
                    'm08-pool-default', %s, %s)
            RETURNING *
            """,
            (batch_id, pool_id, f"WB-20261024-{uuid.uuid4().hex[:6]}", count,
             hashlib.sha256(json.dumps(descriptors, sort_keys=True).encode()).hexdigest(),
             json.dumps({"wallet_cap_minor": 1_000_000, "descriptors": descriptors}),
             f"dedupe-{uuid.uuid4().hex[:8]}", status, expiry, created_at,
             signing_request_id, created_at))
        return dict(cur.fetchone())


def outbox_events(conn: psycopg.Connection) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM m08_outbox ORDER BY id")
        return [dict(row) for row in cur.fetchall()]


def event_types(conn: psycopg.Connection) -> list[str]:
    return [row["type"] for row in outbox_events(conn)]


def wallet_row(conn: psycopg.Connection, wallet_id: str) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM wallet WHERE wallet_id = %s", (wallet_id,))
        return dict(cur.fetchone())


def count(conn: psycopg.Connection, table: str) -> int:
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {table}")
        return int(cur.fetchone()[0])
# ─────────────────────────────────────────────────── HTTP 客户端（DEV-TESTINFRA）
# 由 conftest 移到 kit（原因同 reconkit/riskkit）：测试文件与 conftest 都从这里导入。
USER_PRINCIPAL = {"account_id": "acct-1", "tenant_id": "tenant-a", "user_id": "u-1"}
OTHER_USER_PRINCIPAL = {"account_id": "acct-2", "tenant_id": "tenant-a", "user_id": "u-2"}
PROVIDER_PRINCIPAL = {"account_id": "acct-1", "tenant_id": "tenant-a"}
ADMIN_PRINCIPAL = {"admin_id": "fin-officer", "tenant_id": "tenant-a",
                   "scopes": ["*"]}
READONLY_PRINCIPAL = {"admin_id": "auditor", "tenant_id": "tenant-a",
                      "scopes": ["treasury.read", "treasury.wallet.read"]}


def savepoint_factory(connection):
    """把一条连接包成 handler 需要的请求级连接（内层 SAVEPOINT，不真提交）。"""

    @contextmanager
    def factory():
        with connection.transaction():
            yield connection

    return factory


def build_client(connection, *, user=USER_PRINCIPAL, provider=PROVIDER_PRINCIPAL,
                 admin=ADMIN_PRINCIPAL, step_up=True, now=None, config_provider=None,
                 ledger_poster=None, provider_registry=None, attestation_verifier=None,
                 revenue_verifier=None, risk_check=None, consumed_provider=None,
                 address_allocator=None, audit_sink=None):
    """构造带 M08 路由的 ASGI 客户端（请求级 SAVEPOINT，不真提交）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.treasury.provider import MockProvider, UpgProvider, build_registry
    from app.treasury.router import create_router

    moment = now or FIXED_NOW
    registry = provider_registry or build_registry([MockProvider(), UpgProvider()])
    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(connection),
        user_resolver=(lambda request: dict(user)) if user is not None else None,
        provider_resolver=(lambda request: dict(provider)) if provider is not None else None,
        admin_resolver=(lambda request: dict(admin)) if admin is not None else None,
        step_up_verifier=(lambda request: step_up) if step_up is not None else None,
        now_provider=lambda: moment,
        config_provider=(lambda: config_provider) if config_provider is not None else None,
        ledger_poster=ledger_poster,
        provider_registry=registry,
        address_allocator=address_allocator,
        attestation_verifier=attestation_verifier,
        revenue_verifier=revenue_verifier,
        risk_check=risk_check,
        consumed_provider=consumed_provider,
        audit_sink=audit_sink,
    ))
    # 管理面写操作先要求 step-up 头（值由注入的 verifier 判定）；缺头时 424 由专门用例覆盖
    headers = {"X-Admin-Step-Up": "test-step-up"} if step_up else None
    return TestClient(app, headers=headers)
