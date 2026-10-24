# SPDX-License-Identifier: Apache-2.0
"""DEV-M09 测试工具：隔离 schema、psql 迁移、结构指纹、M05/M06 只读夹具。

只读契约（与 tests/infra / tests/ledger / tests/metering 同款）：

* 迁移文件是**唯一** DDL 来源，测试只用 ``psql -f`` 执行（与 CI / 生产同一路径），
  不在 Python 里手写 M09 的建表语句；
* 每个测试进程用独立 schema（默认 ``m09_t_<pid>_<hex>``，``M09_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不读写 public，也不碰别人的 schema；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip（纯函数用例照跑）；
* **夹具只写 M05/M06 的存量表**（造数据用），M09 自己的表一律走被测代码写；
  这不违反「只读依赖」——被测代码不写它们，测试夹具是造数。

凭据纪律（INC-20261023）：``DJB_DSN`` 由 ``~/.djb/secrets/dev.env`` 五个字段在启动脚本里
拼装，**口令只走 ``PGPASSWORD`` 环境变量**；本文件从不打印 DSN，psql 只收到去掉口令的 DSN。
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

import psycopg
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "migrations"

M09_TABLES = (
    "reconciliation_runs",
    "reconciliation_exceptions",
    "reconciliation_attestations",
    "por_snapshots",
    "report_renders",
)
M09_VIEWS = (
    "v_m09_open_exceptions",
    "v_m09_run_diff",
    "v_m09_valid_attestations",
    "v_m09_latest_por",
    "v_m09_report_versions",
)

#: 库层护栏拒绝写入时 psycopg 抛的异常类型（42501 → InsufficientPrivilege，
#: 23514 → CheckViolation，23505 → UniqueViolation；有的驱动版本给 RaiseException 兜底）
GUARD_DENIED = (psycopg.errors.InsufficientPrivilege, psycopg.errors.RaiseException)

#: 存量表（升级 / 回滚用例要在这些表上证明「只加不改」）
BASE_TABLES = (
    "usage_records", "metering_receipts", "usage_corrections", "upstream_bills",
    "loss_pool_entries", "journal_entry", "journal_line", "ledger_entry",
    "account_balances", "merkle_commitments", "m06_outbox", "accounts", "nodes",
)


# ─────────────────────────────────────────────────────── 连接与 schema
def dsn() -> str:
    from tests.pgdsn import safe_dsn
    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（凭据只注入环境，不入库 / 不入提交）")
    return safe_dsn(value)


def connect(schema: str | None = None, autocommit: bool = True) -> psycopg.Connection:
    options = None
    if schema:
        options = f"-c search_path={schema} -c synchronous_commit=off"
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m09-recon-tests", options=options)


def _admin() -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m09-recon-tests")


def create_schema(name: str) -> None:
    connection = _admin()
    try:
        with connection.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '10s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
            cur.execute(f'CREATE SCHEMA "{name}"')
    finally:
        connection.close()


def drop_schema(name: str) -> None:
    connection = _admin()
    try:
        with connection.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '15s'")
            cur.execute("SET statement_timeout = '180s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
    finally:
        connection.close()


@contextmanager
def session(schema: str):
    connection = connect(schema, autocommit=True)
    try:
        yield connection
    finally:
        connection.close()


# ─────────────────────────────────────────────────────── 迁移清单 / 执行
def migration_number(path: pathlib.Path) -> int:
    return int(path.name.split("_", 1)[0])


def migration_files(order: str = "numeric") -> list[pathlib.Path]:
    files = list(MIGRATIONS_DIR.glob("*.sql"))
    if order == "numeric":
        return sorted(files, key=migration_number)
    if order == "lexicographic":
        return sorted(files)
    raise ValueError(f"未知排序：{order}")


def m09_migration_files() -> list[pathlib.Path]:
    return [path for path in migration_files() if 900 <= migration_number(path) <= 999]


def prerequisite_files() -> list[pathlib.Path]:
    """9xx 之前的全部迁移（升级 / 结构对比用）。"""
    return [path for path in migration_files() if migration_number(path) < 900]


def run_migrations(paths: Sequence[pathlib.Path], schema: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema} -c synchronous_commit=off")
    argv = ["psql", dsn(), "-v", "ON_ERROR_STOP=1", "-q"]
    for path in paths:
        argv += ["-f", str(path)]
    return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=300)


def apply_migrations(schema: str, files: Sequence[pathlib.Path] | None = None) -> None:
    paths = list(files if files is not None else migration_files())
    result = run_migrations(paths, schema)
    assert result.returncode == 0, f"迁移失败（rc={result.returncode}）：\n{result.stderr}"


def apply_m09_twice(schema: str) -> list[str]:
    """9xx 连跑两遍（幂等验收）。返回两遍的输出片段，失败即断言。"""
    output = []
    for attempt in (1, 2):
        result = run_migrations(m09_migration_files(), schema)
        assert result.returncode == 0, f"9xx 第 {attempt} 遍失败：\n{result.stderr}"
        output.append(result.stderr.strip())
    return output


# ─────────────────────────────────────────────────────── 结构查询
def _rows(connection: psycopg.Connection, sql: str, params: Any = ()) -> list[tuple]:
    with connection.cursor() as cur:
        cur.execute(sql, params)
        return list(cur.fetchall())


def table_names(schema: str) -> set[str]:
    with session(schema) as connection:
        return {row[0] for row in _rows(
            connection,
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = %s AND table_type = 'BASE TABLE'", (schema,))}


def view_names(schema: str) -> set[str]:
    with session(schema) as connection:
        return {row[0] for row in _rows(
            connection, "SELECT table_name FROM information_schema.views WHERE table_schema = %s",
            (schema,))}


def index_names(schema: str) -> set[str]:
    with session(schema) as connection:
        return {row[0] for row in _rows(
            connection, "SELECT indexname FROM pg_indexes WHERE schemaname = %s", (schema,))}


def function_names(schema: str) -> set[str]:
    with session(schema) as connection:
        return {row[0] for row in _rows(
            connection,
            """SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = %s""", (schema,))}


def trigger_names(schema: str) -> set[str]:
    with session(schema) as connection:
        return {row[0] for row in _rows(
            connection,
            """SELECT t.tgname FROM pg_trigger t
                 JOIN pg_class c ON c.oid = t.tgrelid
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND NOT t.tgisinternal""", (schema,))}


def column_signature(schema: str, tables: Iterable[str]) -> dict[str, list[str]]:
    """列结构指纹：``{table: ["col:type:nullable:default", ...]}``（顺序敏感）。"""
    wanted = set(tables)
    with session(schema) as connection:
        rows = _rows(
            connection,
            """SELECT table_name, column_name, data_type, is_nullable, COALESCE(column_default, '-')
                 FROM information_schema.columns
                WHERE table_schema = %s ORDER BY table_name, ordinal_position""", (schema,))
    signature: dict[str, list[str]] = {}
    for table, column, dtype, nullable, default in rows:
        if table not in wanted:
            continue
        signature.setdefault(table, []).append(f"{column}:{dtype}:{nullable}:{default}")
    return signature


def constraint_signature(schema: str, tables: Iterable[str]) -> dict[str, list[str]]:
    wanted = set(tables)
    with session(schema) as connection:
        rows = _rows(
            connection,
            """SELECT rel.relname, con.conname, pg_get_constraintdef(con.oid)
                 FROM pg_constraint con
                 JOIN pg_class rel ON rel.oid = con.conrelid
                 JOIN pg_namespace n ON n.oid = rel.relnamespace
                WHERE n.nspname = %s ORDER BY rel.relname, con.conname""", (schema,))
    signature: dict[str, list[str]] = {}
    for table, name, definition in rows:
        if table in wanted:
            signature.setdefault(table, []).append(f"{name}:{definition}")
    return signature


# ─────────────────────────────────────────────────────── M05 夹具（只写存量表）
def seed_usage(connection: psycopg.Connection, *, task_id: str, amount_minor: int,
               recorded_at: datetime, node_id: str = "node-a", account_id: str | None = None,
               receipt_id: str | None = None, attempt_no: int = 1,
               state: str = "recorded") -> str:
    """写一条 usage_records（M05 计费事实），返回 usage_id。"""
    usage_id = str(uuid.uuid4())
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO usage_records
                 (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                  tokens_in, tokens_out, usage_amount, usage_unit, amount_minor, usage_source,
                  state, receipt_id, recorded_at)
               VALUES (%s,%s,%s,%s,%s,'test-model','A1',10,20,%s,'token',%s,'server_measured',
                       %s,%s,%s)""",
            (usage_id, task_id, attempt_no, account_id or str(uuid.uuid4()), node_id,
             str(amount_minor), amount_minor, state, receipt_id, recorded_at))
    return usage_id


def seed_receipt(connection: psycopg.Connection, *, task_id: str, price_minor: int,
                 reported_at: datetime, receipt_id: str, usage_id: str | None = None,
                 node_id: str = "node-a", state: str = "accepted",
                 sig_provider: str | None = None, sig_consumer: str | None = None) -> str:
    """写一条 metering_receipts（M05 双签收据），返回 receipt_id。

    M05 502 的 ``metering_receipts_state_ck2`` 要求 accepted 行必须有 usage_id；
    造「平台没有」的 node-only 数据时给一个不在 usage_records 里的随机 UUID（软引用、无 FK）。
    """
    sig = "hmac-sha256:" + "a" * 64
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO metering_receipts
                 (submission_id, receipt_id, usage_id, node_id, task_id, access, usage_amount,
                  usage_unit, price_amount, price_minor, sig_provider, sig_consumer, state,
                  reported_at, received_at)
               VALUES (%s,%s,%s,%s,%s,'A1','10','token',%s,%s,%s,%s,%s,%s,%s)""",
            (str(uuid.uuid4()), receipt_id, usage_id or str(uuid.uuid4()), node_id, task_id,
             f"{price_minor / 100:.2f}", price_minor,
             sig_provider or sig, sig_consumer or sig, state, reported_at, reported_at))
    return receipt_id


# ─────────────────────────────────────────────────────── M06 夹具（只写存量表）
COA_FUND_CLASS: dict[str, str] = {
    "1101": "CLIENT", "1102": "CLIENT", "1103": "CLIENT", "1109": "PLATFORM",
    "1111": "CLIENT", "1120": "CLIENT", "1121": "CLIENT", "1130": "CLIENT",
    "1140": "PLATFORM", "1190": "CLIENT", "1901": "CLIENT", "1910": "CLIENT",
    "2101": "CLIENT", "2102": "CLIENT", "2103": "CLIENT", "2201": "CLIENT",
    "2202": "CLIENT", "2203": "CLIENT", "2204": "CLIENT", "2210": "CLIENT",
    "2301": "CLIENT", "2990": "CLIENT", "2901": "FEE", "3101": "PLATFORM",
    "4101": "FEE", "4102": "FEE", "4103": "FEE", "4104": "FEE", "4105": "FEE", "4201": "FEE",
    "5101": "FEE", "5102": "FEE", "5103": "FEE", "5104": "FEE", "5105": "FEE",
    "5106": "FEE", "5201": "FEE", "5301": "FEE", "5401": "FEE", "5501": "FEE",
    "6101": "FEE", "6901": "FEE",
}


def new_hash(seed: str | None = None) -> bytes:
    return hashlib.sha256(f"{seed or ''}{uuid.uuid4().hex}".encode()).digest()


def journal_line_fixture(coa_code: str, dc: str, amount_minor: int, *,
                         account_id: str | None = None, qty_minor: int | None = None,
                         entry_type: str = "consume",
                         wallet_id: str | None = None) -> dict[str, Any]:
    return {"coa_code": coa_code, "dc": dc, "amount_minor": amount_minor,
            "account_id": account_id or f"coa:{coa_code}", "qty_minor": qty_minor,
            "entry_type": entry_type, "fund_class": COA_FUND_CLASS[coa_code],
            "unit_scale": 6, "wallet_id": wallet_id, "reverse_of": None}


def simple_journal_lines(amount_minor: int = 100_000_000, *, debit_coa: str = "1101",
                         credit_coa: str = "2101") -> list[dict[str, Any]]:
    """两行平账夹具：借 1101（链上客户资金）/ 贷 2101（服务预付款）。"""
    return [journal_line_fixture(debit_coa, "D", amount_minor, qty_minor=amount_minor),
            journal_line_fixture(credit_coa, "C", amount_minor)]


def post_journal(connection: psycopg.Connection, lines: Iterable[dict[str, Any]], *,
                 unit_type: str = "USD", event_type: str = "E6",
                 source_type: str = "usage_settle", source_id: str | None = None,
                 ts: datetime | None = None, event_seq: int = 0) -> str:
    """按写入顺序落一张凭证：journal_entry → ledger_entry → journal_line（M06 契约顺序）。

    event_seq 用于三方对账的 E3/E4（1/2/3）与 E8/E11 幂等键；默认 0 保持旧用例不变。
    """
    journal_id = str(uuid.uuid4())
    moment = ts or datetime.now(timezone.utc)
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO journal_entry
                 (journal_id, ts, event_type, unit_type, source_type, source_id, event_seq,
                  policy_version, fx_rate_id, hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,'m09-test',1,%s)""",
            (journal_id, moment, event_type, unit_type, source_type,
             source_id or f"src-{uuid.uuid4().hex[:12]}", int(event_seq), new_hash(journal_id)))
        for line_no, item in enumerate(lines, start=1):
            entry_id = str(uuid.uuid4())
            cur.execute(
                """INSERT INTO ledger_entry
                     (entry_id, journal_id, line_no, account_id, entry_type, unit_type, dc,
                      amount_minor, qty_minor, fund_class, reverse_of, ref_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL)""",
                (entry_id, journal_id, line_no, item["account_id"], item["entry_type"],
                 unit_type, item["dc"], item["amount_minor"], item["qty_minor"],
                 item["fund_class"], item["reverse_of"]))
            cur.execute(
                """INSERT INTO journal_line
                     (journal_id, line_no, ledger_entry_id, account_id, coa_code, dc,
                      amount_minor, unit_scale, qty_minor, fund_class, wallet_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (journal_id, line_no, entry_id, item["account_id"], item["coa_code"], item["dc"],
                 item["amount_minor"], item["unit_scale"], item["qty_minor"], item["fund_class"],
                 item["wallet_id"]))
    return journal_id


def derive_balances(connection: psycopg.Connection, *, as_of: datetime | None = None,
                    unit_type: str = "USD") -> dict[tuple[str, str], int]:
    with connection.cursor() as cur:
        cur.execute(
            """SELECT l.account_id,
                      CASE WHEN l.coa_code = '2102' THEN 'LOCKED' ELSE 'AVAILABLE' END,
                      sum(CASE WHEN l.dc = 'D' THEN l.amount_minor ELSE -l.amount_minor END)
                 FROM journal_line l JOIN journal_entry j ON j.journal_id = l.journal_id
                WHERE j.unit_type = %s AND (%s::timestamptz IS NULL OR j.ts <= %s)
                GROUP BY 1, 2""",
            (unit_type, as_of, as_of))
        return {(row[0], row[1]): int(row[2]) for row in cur.fetchall()}


def snapshot_balances(connection: psycopg.Connection, *, as_of: datetime | None = None,
                      unit_type: str = "USD", created_at: datetime | None = None) -> int:
    """把当前派生余额写成 account_balances 的新版本（模拟 M06 T3 增量落账）。

    ``created_at`` 用来对齐 M09 的 ——  ``account_balances`` 是版本化缓存，M09 的 as-of
    口径是「``created_at <= cutoff`` 的最新版本」，所以造数时要把写入时刻显式对齐到截止时刻
    （M06 真实写入与 journal 同事务，created_at ≈ ts）。
    """
    derived = derive_balances(connection, as_of=as_of, unit_type=unit_type)
    with connection.cursor() as cur:
        cur.execute("SELECT account_id, unit_type, sub_account, max(version) FROM account_balances"
                    " GROUP BY 1, 2, 3")
        versions = {(row[0], row[1], row[2]): int(row[3]) for row in cur.fetchall()}
        for (account_id, sub_account), amount in derived.items():
            cur.execute(
                """INSERT INTO account_balances
                     (account_id, unit_type, sub_account, version, balance_minor, journal_id,
                      created_at)
                   VALUES (%s,%s,%s,%s,%s,NULL,COALESCE(%s, now()))""",
                (account_id, unit_type, sub_account,
                 versions.get((account_id, unit_type, sub_account), 0) + 1, amount, created_at))
    return len(derived)


# ────────────────────────────────────────── M08 / 三方对账夹具（只写存量表）
def seed_payment_attempt(connection: psycopg.Connection, *, provider_txn_id: str,
                         amount_minor: int, created_at: datetime, status: str = "succeeded",
                         currency: str = "USD", fee_minor: int = 0,
                         settled_minor: int | None = None,
                         settlement_fee_minor: int | None = None,
                         account_id: str = "acct-subject", provider: str = "mock") -> dict[str, Any]:
    """写一条 payment_orders + payment_attempts（M08 事实；金额单位分）。

    settled_minor / settlement_fee_minor 必须成对出现（800 的 settlement CHECK）。
    """
    order_id = str(uuid.uuid4())
    order_no = "PO-" + uuid.uuid4().hex[:18].upper()
    attempt_id = str(uuid.uuid4())
    net_minor = max(amount_minor - fee_minor, 0)
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO payment_orders
                 (order_id, order_no, account_id, amount_minor, currency, method, provider,
                  status, credited_minor, policy_version, trace_id, created_by, paid_at,
                  created_at, updated_at)
               VALUES (%s,%s,%s,%s,%s,'card',%s,'paid',0,'m09-test',%s,'m09-test',
                       %s,%s,%s)""",
            (order_id, order_no, account_id, amount_minor, currency, provider,
             f"trace-{uuid.uuid4().hex[:12]}", created_at, created_at, created_at))
        cur.execute(
            """INSERT INTO payment_attempts
                 (attempt_id, order_id, provider, provider_txn_id, provider_status, status,
                  amount_minor, fee_minor, net_minor, currency, signature_verified,
                  settled_minor, settlement_fee_minor, created_at, updated_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,TRUE,%s,%s,%s,%s)""",
            (attempt_id, order_id, provider, provider_txn_id, status, status,
             amount_minor, fee_minor, net_minor, currency, settled_minor,
             settlement_fee_minor, created_at, created_at))
    return {"order_id": order_id, "order_no": order_no, "attempt_id": attempt_id}


def seed_wallet(connection: psycopg.Connection, *, wallet_id: str,
                balance_minor: int = 0, chain_id: str = "polygon", role: str = "hot",
                fund_class: str = "customer", address: str | None = None,
                status: str = "active", switch_state: str = "in_service",
                gas_ok: bool = True) -> str:
    """写 wallet_pool + wallet（M08 只读依赖；金额单位分）。"""
    pool_id = f"{chain_id}:{role}:{fund_class}"
    address = address or ("0x" + hashlib.sha256(wallet_id.encode()).hexdigest()[:40])
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO wallet_pool (pool_id, chain_id, role, fund_class, status,
                                        policy_version)
               VALUES (%s,%s,%s,%s,'active','m09-test')
               ON CONFLICT (pool_id) DO NOTHING""",
            (pool_id, chain_id, role, fund_class))
        cur.execute(
            """INSERT INTO wallet
                 (wallet_id, chain_id, address, pool_id, pool_role, fund_class, custody_kind,
                  status, switch_state, balance_minor, gas_ok, activated_at)
               VALUES (%s,%s,%s,%s,%s,%s,'self_custody_hot',%s,%s,%s,%s,%s)""",
            (wallet_id, chain_id, address, pool_id, role, fund_class, status, switch_state,
             balance_minor, gas_ok, FIXED_NOW))
    return wallet_id


def seed_payout_item(connection: psycopg.Connection, *, net_minor: int, created_at: datetime,
                     gross_minor: int | None = None, fee_minor: int = 0,
                     status: str = "sent", chain_tx_id: str | None = None,
                     journal_id: str | None = None, batch_status: str = "settled",
                     item_id: str | None = None, batch_id: str | None = None,
                     batch_no: str | None = None, total_gross_minor: int | None = None,
                     total_fee_minor: int | None = None,
                     total_net_minor: int | None = None) -> dict[str, Any]:
    """写 payout_batches + payout_items（M08 分润批次；金额单位分）。"""
    item_id = item_id or str(uuid.uuid4())
    batch_id = batch_id or str(uuid.uuid4())
    batch_no = batch_no or ("PB-" + uuid.uuid4().hex[:18].upper())
    gross = net_minor + fee_minor if gross_minor is None else gross_minor
    batch_gross = gross if total_gross_minor is None else total_gross_minor
    batch_fee = fee_minor if total_fee_minor is None else total_fee_minor
    total_net = (batch_gross - batch_fee if total_net_minor is None else total_net_minor)
    payee_address = "0x" + hashlib.sha256(item_id.encode()).hexdigest()[:40]
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO payout_batches
                 (batch_id, batch_no, status, total_gross_minor, total_fee_minor,
                  total_net_minor, item_count, attestation_ref, gas_mode, policy_version,
                  maker_id, checker_id, checked_at, created_at, updated_at)
               VALUES (%s,%s,%s,%s,%s,%s,1,'att:test','INTERNAL','m09-test','maker','checker',
                       %s,%s,%s)""",
            (batch_id, batch_no, batch_status, batch_gross, batch_fee, total_net,
             created_at, created_at, created_at))
        cur.execute(
            """INSERT INTO payout_items
                 (item_id, batch_id, payee_account_id, payee_address, gross_minor, fee_minor,
                  net_minor, status, gas_mode, policy_version, chain_tx_id, journal_id,
                  created_at, updated_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'INTERNAL','m09-test',%s,%s,%s,%s)""",
            (item_id, batch_id, f"acct-{item_id[:8]}", payee_address, gross, fee_minor,
             net_minor, status, chain_tx_id, journal_id, created_at, created_at))
    return {"item_id": item_id, "batch_id": batch_id, "batch_no": batch_no}


def seed_refund_request(connection: psycopg.Connection, *, amount_minor: int,
                        created_at: datetime, status: str = "succeeded",
                        journal_id: str | None = None, currency: str = "USD",
                        payment_ref: str | None = None, refund_no: str | None = None,
                        order_no: str | None = None,
                        refund_request_id: str | None = None) -> dict[str, Any]:
    """写 refund_requests（M08 退款；金额单位分，原路信息不可变）。"""
    refund_request_id = refund_request_id or str(uuid.uuid4())
    refund_no = refund_no or ("RF-" + uuid.uuid4().hex[:18].upper())
    order_no = order_no or ("PO-" + uuid.uuid4().hex[:18].upper())
    payment_ref = payment_ref or ("psp-" + uuid.uuid4().hex[:16])
    approved = status in ("approved", "executing", "succeeded")
    succeeded = status == "succeeded"
    approved_at = created_at + timedelta(hours=25) if approved else None
    succeeded_at = created_at + timedelta(hours=26) if succeeded else None
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO refund_requests
                 (refund_request_id, refund_no, account_id, order_no, payment_ref,
                  amount_minor, currency, reason_code, original_route,
                  original_route_hash, status, deadline_at, requested_by, approved_by,
                  approved_at, cooldown_until, succeeded_at, journal_id, created_at,
                  updated_at)
               VALUES (%s,%s,'acct-subject',%s,%s,%s,%s,'customer_request',
                       'card:tok-test',%s,%s,%s,'maker',%s,%s,%s,%s,%s,%s,%s)""",
            (refund_request_id, refund_no, order_no, payment_ref, amount_minor, currency,
             "a" * 32, status, created_at + timedelta(days=14),
             "checker" if approved else None, approved_at,
             created_at + timedelta(hours=24), succeeded_at, journal_id, created_at,
             created_at))
    return {"refund_request_id": refund_request_id, "refund_no": refund_no,
            "payment_ref": payment_ref, "order_no": order_no}


def recon_spec(scope: str, *, cutoff: datetime | None = None, days: int = 1,
               subject_ref: str | None = None,
               trigger_event_id: str | None = None) -> Any:
    """三方 scope 的 RunSpec（期间 = [cutoff-days, cutoff)）；cutoff 缺省 = 固定时钟。"""
    from app.recon import models

    moment = cutoff or FIXED_NOW
    return models.RunSpec(scope=scope, subject_ref=subject_ref,
                          period_start=moment - timedelta(days=days), period_end=moment,
                          cutoff_at=moment, trigger_event_id=trigger_event_id)


# ─────────────────────────────────────────────────────── 时间夹具
FIXED_NOW = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)
DAY = timedelta(days=1)


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────── M09 行读取（断言用）
def fetch_run(connection: psycopg.Connection, run_id: str) -> dict[str, Any]:
    from psycopg.rows import dict_row

    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM reconciliation_runs WHERE run_id = %s", (run_id,))
        return cur.fetchone()


def fetch_exceptions(connection: psycopg.Connection, run_id: str) -> list[dict[str, Any]]:
    from psycopg.rows import dict_row

    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT * FROM reconciliation_exceptions WHERE run_id = %s"
            " ORDER BY created_at, exception_id", (run_id,))
        return list(cur.fetchall())


def list_all_runs(connection: psycopg.Connection) -> list[dict[str, Any]]:
    from psycopg.rows import dict_row

    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM reconciliation_runs ORDER BY cutoff_at, run_id")
        return list(cur.fetchall())


def receipt_spec(*, cutoff: datetime = FIXED_NOW, days: int = 1, subject_ref: str | None = "m05",
                 grace_seconds: int | None = None, trigger_event_id: str | None = None) -> Any:
    """构造 scope=receipt 的 RunSpec（期间 = [cutoff-days, cutoff)）。"""
    from app.recon import facts, models

    return models.RunSpec(
        scope="receipt",
        subject_ref=subject_ref,
        period_start=cutoff - timedelta(days=days),
        period_end=cutoff,
        cutoff_at=cutoff,
        grace_seconds=(facts.DEFAULT_GRACE_SECONDS if grace_seconds is None else grace_seconds),
        trigger_event_id=trigger_event_id,
    )


def daily_close_spec(*, cutoff: datetime = FIXED_NOW, days: int = 1,
                     subject_ref: str | None = None) -> Any:
    from app.recon import models

    return models.RunSpec(scope="daily_close", subject_ref=subject_ref,
                          period_start=cutoff - timedelta(days=days), period_end=cutoff,
                          cutoff_at=cutoff)

# ─────────────────────────────────────────────────────── M09 HTTP 客户端（DEV-TESTINFRA）
# 由 conftest 移到 kit：单进程全量 pytest 时多个目录的 conftest 会互相覆盖，
# 测试文件统一从本模块导入 helper / 客户端构造器（conftest 只留 pytest fixture）。
ADMIN_PRINCIPAL = {"admin_id": "admin-maker", "tenant_id": "tenant-a",
                   "scopes": ["recon.read", "recon.write"]}
SERVICE_PRINCIPAL = {"service_id": "M08-payout", "scopes": ["recon.attestation.validate"]}


def savepoint_factory(connection):
    """把一条连接包成 handler 需要的请求级连接（内层 SAVEPOINT，不真提交）。"""

    @contextmanager
    def factory():
        with connection.transaction():
            yield connection

    return factory


def build_client(connection, *, admin=ADMIN_PRINCIPAL, service=SERVICE_PRINCIPAL,
                 step_up=True, now=None, engine_deps=None):
    """构造带 M09 路由的 ASGI 客户端（请求级 SAVEPOINT，不真提交）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.recon.router import create_router

    moment = now or FIXED_NOW
    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(connection),
        admin_resolver=(lambda request: dict(admin)) if admin is not None else None,
        service_resolver=(lambda request: dict(service)) if service is not None else None,
        step_up_verifier=(lambda request: step_up) if step_up is not None else None,
        now_provider=lambda: moment,
        engine_deps=engine_deps,
    ))
    return TestClient(app)
