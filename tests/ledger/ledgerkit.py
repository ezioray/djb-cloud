# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-M06-T1 账本测试工具：迁移执行、结构指纹、凭证夹具、余额派生。

只读契约（本文件不改实现代码）：
  · 迁移文件是唯一 DDL 来源，测试只用 psql -f 执行它们，不在 Python 里手写建表语句；
  · 凭证夹具严格走「journal_entry → ledger_entry → journal_line」的写入顺序（与 T2 网关一致）；
  · 余额派生：balance_minor = Σ借 − Σ贷（借方为正），见 migrations/602_account_balances.sql 注释。
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

import psycopg
import pytest

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "migrations"

M06_MIGRATIONS = (
    "600_ledger_journal.sql",
    "601_ledger_entry.sql",
    "602_account_balances.sql",
    "603_merkle_commitments.sql",
    "604_ledger_outbox.sql",
)

M06_TABLES = ("journal_entry", "journal_line", "ledger_entry", "account_balances", "merkle_commitments")
M06_VIEWS = ("ledger_entries_compat", "account_balances_latest")

# 42 科目白名单与 fund_class 归属（product/v4/src/20-payment-ledger.md §20.2.2–§20.2.6；INV-03）
# 资产 12 / 负债与权益 12 / 收入 6 / 费用与损失 10 / 非现金与调整 2 = 42（03-facts §6）
COA_FUND_CLASS: dict[str, str] = {
    # 资产（12）：1109/1140 属平台自有，其余客户资金
    "1101": "CLIENT", "1102": "CLIENT", "1103": "CLIENT", "1109": "PLATFORM",
    "1111": "CLIENT", "1120": "CLIENT", "1121": "CLIENT", "1130": "CLIENT",
    "1140": "PLATFORM", "1190": "CLIENT", "1901": "CLIENT", "1910": "CLIENT",
    # 负债与权益（12）：2901 尾差归 FEE，3101 累计留存归 PLATFORM
    "2101": "CLIENT", "2102": "CLIENT", "2103": "CLIENT", "2201": "CLIENT",
    "2202": "CLIENT", "2203": "CLIENT", "2204": "CLIENT", "2210": "CLIENT",
    "2301": "CLIENT", "2990": "CLIENT", "2901": "FEE", "3101": "PLATFORM",
    # 收入（6）
    "4101": "FEE", "4102": "FEE", "4103": "FEE", "4104": "FEE", "4105": "FEE", "4201": "FEE",
    # 费用与损失（10）
    "5101": "FEE", "5102": "FEE", "5103": "FEE", "5104": "FEE", "5105": "FEE",
    "5106": "FEE", "5201": "FEE", "5301": "FEE", "5401": "FEE", "5501": "FEE",
    # 非现金费用与调整（2）
    "6101": "FEE", "6901": "FEE",
}

UNIT_TYPES = ("USD", "COP", "STABLE_USDT", "FIAT_CNY")
SOURCE_TYPES = (
    "chain_tx", "payment_attempt", "conversion_trade", "usage_settle", "lock_expiry",
    "payout_accrual", "payout_item", "payout_batch", "wallet_transfer", "refund",
    "chargeback", "rebate", "fx_reval", "loss_pool", "void", "unidentified",
)
ENTRY_TYPES = (
    "earn", "redeem", "adjust", "freeze", "unfreeze", "void",
    "deposit", "consume", "payout", "refund", "chargeback", "transfer", "gas", "conversion",
    "fx_reval", "writeoff",
)


# ─────────────────────────────────────────────────────── 连接与迁移
def dsn() -> str:
    from tests.pgdsn import safe_dsn
    v = os.environ.get("DJB_DSN")
    if not v:
        raise RuntimeError("缺环境变量 DJB_DSN（见 product/v4/modules/W1-EXECUTION-PLAN.md §3）")
    return safe_dsn(v)


def connect(schema: str, autocommit: bool = True) -> psycopg.Connection:
    # connect_timeout：库被别的席位重活占住时快速失败，而不是挂死整个套件
    # synchronous_commit=off：测试 schema 不要求崩溃持久性，省掉 NAS 上每条 DDL/DML 的 fsync
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m06-t1-tests",
                           options=f"-c search_path={schema} -c synchronous_commit=off")


@contextmanager
def session(schema: str):
    """autocommit 只读/单语句会话；退出即 close()。

    psycopg 的 ``with connect(...)`` 只提交事务、**不关闭连接**，同一进程里反复使用会把
    dev 库的 max_connections（40）打满，后续连接只能排队等待 —— 这里显式关闭。
    """
    c = connect(schema, autocommit=True)
    try:
        yield c
    finally:
        c.close()


@contextmanager
def tx(schema: str):
    """显式事务；退出时 commit —— 借贷平衡等 DEFERRABLE 约束在此刻才校验。"""
    c = connect(schema, autocommit=False)
    try:
        yield c
        c.commit()
    finally:
        c.close()


def create_schema(name: str) -> None:
    c = psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                        application_name="m06-t1-tests")
    try:
        with c.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '10s'")
            cur.execute(f'CREATE SCHEMA "{name}"')
    finally:
        c.close()


def drop_schema(name: str) -> None:
    c = psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                        application_name="m06-t1-tests")
    try:
        with c.cursor() as cur:
            # 锁等待上限：别人占着库时宁可报错，也不让收尾把整个套件挂住
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '15s'")
            cur.execute("SET statement_timeout = '120s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
    finally:
        c.close()


def migration_files() -> list[Path]:
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def run_migration(path: Path, schema: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema} -c synchronous_commit=off")
    return subprocess.run(
        ["psql", dsn(), "-v", "ON_ERROR_STOP=1", "-q", "-f", str(path)],
        capture_output=True, text=True, env=env, timeout=180,
    )


def run_migrations(paths: Sequence[Path], schema: str) -> subprocess.CompletedProcess:
    """一个 psql 进程按序执行多个文件（同一连接），省掉每个文件一次进程启动。"""
    env = dict(os.environ, PGOPTIONS=f"-c search_path={schema} -c synchronous_commit=off")
    args = ["psql", dsn(), "-v", "ON_ERROR_STOP=1", "-q"]
    for path in paths:
        args += ["-f", str(path)]
    return subprocess.run(args, capture_output=True, text=True, env=env, timeout=300)


def apply_migrations(schema: str, files: Sequence[Path] | None = None) -> list[dict]:
    """顺序执行 001–604（单进程），返回 [{name, rc, stderr}]；失败立刻断言。

    逐文件 rc 由 run_migrations 的 ON_ERROR_STOP 统一保证；需要「单文件重复执行」的用例
    自己调用 run_migration。
    """
    paths = list(files if files is not None else migration_files())
    r = run_migrations(paths, schema)
    out = [{"name": p.name, "rc": r.returncode, "stderr": (r.stderr or "").strip()} for p in paths]
    assert r.returncode == 0, f"迁移失败（rc={r.returncode}）：\n{r.stderr}"
    return out


def m06_migration_files() -> list[Path]:
    return [MIGRATIONS_DIR / name for name in M06_MIGRATIONS]


# ─────────────────────────────────────────────────────── 结构指纹 / 只读探测
_FINGERPRINT_SQL = {
    "columns": """
        SELECT table_name || '.' || column_name || ':' || data_type || ':' || is_nullable
               || ':' || COALESCE(column_default, '-') || ':' || is_generated
          FROM information_schema.columns
         WHERE table_schema = %(s)s ORDER BY 1""",
    "constraints": """
        SELECT c.relname || '.' || con.conname || ':' || pg_get_constraintdef(con.oid)
          FROM pg_constraint con
          JOIN pg_class c ON c.oid = con.conrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %(s)s ORDER BY 1""",
    "indexes": """
        SELECT indexname || ':' || indexdef FROM pg_indexes
         WHERE schemaname = %(s)s ORDER BY 1""",
    "triggers": """
        SELECT t.tgname || ':' || c.relname || ':' || pg_get_triggerdef(t.oid)
          FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %(s)s AND NOT t.tgisinternal ORDER BY 1""",
    "views": """
        SELECT viewname || ':' || md5(definition) FROM pg_views
         WHERE schemaname = %(s)s ORDER BY 1""",
    "functions": """
        SELECT p.proname || ':' || md5(p.prosrc) FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = %(s)s ORDER BY 1""",
    "sequences": """
        SELECT sequencename || ':' || COALESCE(data_type, '-') FROM pg_sequences
         WHERE schemaname = %(s)s ORDER BY 1""",
}


def fingerprint(schema: str) -> dict[str, list[str]]:
    """当前 schema 的完整结构指纹（列 / 约束 / 索引 / 触发器 / 视图 / 函数 / 序列）。"""
    fp: dict[str, list[str]] = {}
    with session(schema) as c, c.cursor() as cur:
        for key, sql in _FINGERPRINT_SQL.items():
            cur.execute(sql, {"s": schema})
            fp[key] = [row[0] for row in cur.fetchall()]
    return fp


def table_names(schema: str) -> set[str]:
    with session(schema) as c, c.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = %s AND table_type = 'BASE TABLE'", (schema,))
        return {r[0] for r in cur.fetchall()}


def view_names(schema: str) -> set[str]:
    with session(schema) as c, c.cursor() as cur:
        cur.execute("SELECT viewname FROM pg_views WHERE schemaname = %s", (schema,))
        return {r[0] for r in cur.fetchall()}


# ─────────────────────────────────────────────────────── 断言小工具
def run_ok(schema: str, fn: Callable[[psycopg.Connection], object]):
    """事务成功提交，返回 fn 的返回值。"""
    with tx(schema) as c:
        return fn(c)


def assert_db_error(schema: str, match: str, fn: Callable[[psycopg.Connection], object]):
    """期望事务失败（含提交时刻失败），且错误信息包含 match（大小写不敏感）。"""
    with pytest.raises(psycopg.Error) as ei:
        with tx(schema) as c:
            fn(c)
    msg = str(ei.value)
    assert match.lower() in msg.lower(), f"期望错误信息包含 {match!r}，实际：{msg!r}"
    return ei.value


# ─────────────────────────────────────────────────────── 凭证夹具
def new_hash(seed: str | None = None) -> bytes:
    return hashlib.sha256(f"{seed or ''}{uuid.uuid4().hex}".encode()).digest()


def line(coa_code: str, dc: str, amount_minor: int, *, account_id: str | None = None,
         qty_minor: int | None = None, entry_type: str | None = None,
         fund_class: str | None = None, unit_scale: int = 6,
         wallet_id: str | None = None, reverse_of: str | None = None) -> dict:
    """构造一行凭证（默认 account_id 用科目账户 coa:<code>，一个科目一个账户）。"""
    return {
        "coa_code": coa_code,
        "dc": dc,
        "amount_minor": amount_minor,
        "account_id": account_id or f"coa:{coa_code}",
        "qty_minor": qty_minor,
        "entry_type": entry_type or "consume",
        "fund_class": fund_class or COA_FUND_CLASS[coa_code],
        "unit_scale": unit_scale,
        "wallet_id": wallet_id,
        "reverse_of": reverse_of,
    }


def post_journal(cur, lines: Iterable[dict], *, unit_type: str = "USD", event_type: str = "E6",
                 source_type: str = "usage_settle", source_id: str | None = None,
                 event_seq: int = 0, policy_version: str = "v4.0-t1", fx_rate_id: int = 1,
                 reversal_of: str | None = None, merkle_period: str | None = None,
                 ts: datetime | None = None) -> dict:
    """按写入顺序落一张凭证：journal_entry → ledger_entry → journal_line。返回 id 集合。"""
    journal_id = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO journal_entry
             (journal_id, ts, event_type, unit_type, source_type, source_id, event_seq,
              policy_version, fx_rate_id, reversal_of_journal, merkle_period, hash)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (journal_id, ts or datetime.now(timezone.utc), event_type, unit_type, source_type,
         f"src-{uuid.uuid4().hex[:12]}" if source_id is None else source_id,
         event_seq, policy_version, fx_rate_id, reversal_of, merkle_period, new_hash(journal_id)),
    )
    entry_ids = []
    for line_no, ln in enumerate(lines, start=1):
        entry_id = str(uuid.uuid4())
        cur.execute(
            """INSERT INTO ledger_entry
                 (entry_id, journal_id, line_no, account_id, entry_type, unit_type, dc,
                  amount_minor, qty_minor, fund_class, reverse_of, ref_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (entry_id, journal_id, line_no, ln["account_id"], ln["entry_type"], unit_type,
             ln["dc"], ln["amount_minor"], ln["qty_minor"], ln["fund_class"], ln["reverse_of"],
             ln.get("ref_id")),
        )
        cur.execute(
            """INSERT INTO journal_line
                 (journal_id, line_no, ledger_entry_id, account_id, coa_code, dc,
                  amount_minor, unit_scale, qty_minor, fund_class, wallet_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (journal_id, line_no, entry_id, ln["account_id"], ln["coa_code"], ln["dc"],
             ln["amount_minor"], ln["unit_scale"], ln["qty_minor"], ln["fund_class"],
             ln["wallet_id"]),
        )
        entry_ids.append(entry_id)
    return {"journal_id": journal_id, "entry_ids": entry_ids}


def simple_lines(amount_minor: int = 100_000_000, *, debit_coa: str = "1101", credit_coa: str = "2101",
                 qty_minor: int | None = None) -> list[dict]:
    """两行平账夹具：默认 借 1101（链上客户资金）/ 贷 2101（服务预付款）。"""
    qty = qty_minor if qty_minor is not None else amount_minor
    return [line(debit_coa, "D", amount_minor, qty_minor=qty), line(credit_coa, "C", amount_minor)]


def derive_balances(cur, unit_type: str | None = None) -> dict[tuple[str, str, str], int]:
    """从分录全量重建余额（INV-10）：(account_id, unit_type, sub_account) → Σ借 − Σ贷。"""
    sql = """
        SELECT l.account_id, j.unit_type, 'AVAILABLE',
               COALESCE(sum(CASE WHEN l.dc = 'D' THEN l.amount_minor ELSE -l.amount_minor END), 0)
          FROM journal_line l
          JOIN journal_entry j ON j.journal_id = l.journal_id
         {where}
         GROUP BY 1, 2, 3"""
    where = "WHERE j.unit_type = %s" if unit_type else ""
    cur.execute(sql.format(where=where), (unit_type,) if unit_type else ())
    return {(a, u, s): int(v) for a, u, s, v in cur.fetchall()}


def stored_balances(cur) -> dict[tuple[str, str, str], int]:
    """account_balances_latest 视图（增量写入后的最新版本）。"""
    cur.execute("SELECT account_id, unit_type, sub_account, balance_minor FROM account_balances_latest")
    return {(a, u, s): int(v) for a, u, s, v in cur.fetchall()}


def snapshot_balances(cur, journal_id: str | None = None) -> int:
    """按分录全量重建余额，并为每个键写「上一版本 + 1」（T3 增量写余额的最小正确形态）。

    返回写入行数。已存在但本轮消失的键不写（余额只增不减：凭证只追加，余额不可能凭空消失）。
    """
    cur.execute(
        "SELECT account_id, unit_type, sub_account, max(version) FROM account_balances "
        "GROUP BY 1, 2, 3")
    versions = {(a, u, s): int(v) for a, u, s, v in cur.fetchall()}
    derived = derive_balances(cur)
    for (account_id, unit_type, sub_account), amount in derived.items():
        cur.execute(
            """INSERT INTO account_balances
                 (account_id, unit_type, sub_account, version, balance_minor, journal_id)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (account_id, unit_type, sub_account,
             versions.get((account_id, unit_type, sub_account), 0) + 1, amount, journal_id))
    return len(derived)


def write_balances(cur, balances: dict[tuple[str, str, str], int], journal_id: str | None = None,
                   version: int = 1) -> None:
    for (account_id, unit_type, sub_account), amount in balances.items():
        cur.execute(
            """INSERT INTO account_balances
                 (account_id, unit_type, sub_account, version, balance_minor, journal_id)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (account_id, unit_type, sub_account, version, amount, journal_id),
        )
