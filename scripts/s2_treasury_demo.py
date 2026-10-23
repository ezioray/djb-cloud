#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""S2 资金闭环 demo（M08 支付/资金 ↔ M06 账本 ↔ M09 对账），按 ops/runbooks/S2-TREASURY-LOOP.md 十二步。

运行（独立 schema，结束自动 DROP）::

    PYTHONPATH=. python scripts/s2_treasury_demo.py --json
    PYTHONPATH=. python scripts/s2_treasury_demo.py --json --keep-schema

隔离与凭据
----------
* 独立 schema `s2_treasury_<utc ts>_<pid>`，空库全链迁移（001…1403，数字序），结束 DROP；
  `--keep-schema` 保留供排查（输出里给 schema 名）。
* DSN 只从环境变量 `DJB_DSN` 取；本脚本不打印、不落盘任何凭据；不接主网、不真钱。

自组 app（不改 app/api.py）
--------------------------
* M08：`app.treasury.router.create_router` + 可推进时钟 / MockProvider(scripted_status) /
  SyntheticAddressAllocator / M06LedgerPoster / attestation verifier；
* M09：`app.recon.router.create_router`（sign-off / attestation / validate 走真实 HTTP 层）。

链路（runbook 十二步）
----------------------
0 空库迁移 + 3 池 seed → 1 钱包池激活（2 热 + 温池 + 平台温池，2/3 签名）→ 2 出款地址 72h
冷却 → 3 下单 → 4 签名回调（+负例）→ 5 E3 → 6 E4 两步 → 7 E5 两步 → 8 归集（E9）→
9 分润（attestation 前置 → E8）→ 10 退款（E11）→ 11 对账 + attestation + validate →
12 复算（verify diff / trial / outbox / 幂等）。

金额一律整数 micro-USD；M08 表是 USD 分（unit_scale=2），账本边界 ×10,000（03-facts §6）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.ledger import gateway as ledger_gateway
from app.ledger.balances import check_negative_liabilities
from app.ledger.validate import JournalDraft, JournalLine
from app.ledger.verify import verify_ledger
from app.recon import engine as recon_engine
from app.recon import facts as recon_facts
from app.recon import models as recon_models
from app.recon.router import create_router as create_recon_router
from app.treasury import config_source as m08_config
from app.treasury import ledger as m08_ledger
from app.treasury import models as m08_models
from app.treasury import order as m08_order
from app.treasury import payout as m08_payout
from app.treasury import policy as m08_policy
from app.treasury import provider as m08_provider
from app.treasury import refund as m08_refund
from app.treasury import router as m08_router_mod
from app.treasury import signing as m08_signing
from app.treasury import store as m08_store
from app.treasury import wallet as m08_wallet
from app.wiring import db as wiring_db
from app.wiring.treasury import M06LedgerPoster, make_attestation_verifier
from app.wiring.treasury_events import consume

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SCHEMA_RE = re.compile(r"^[a-z0-9_]+$")

#: 场景常量（runbook 金额示例；micro-USD / USD 分两套口径）
ORDER_MINOR = 100_00                 # 订单 100.00 USD（分）
SETTLED_MINOR = 98_50                # PSP 结算 98.50
PSP_FEE_MINOR = 1_50                 # PSP 手续费 1.50
CONVERSION_FEE_MINOR = 20            # 兑换费 0.20（到账 99.80）
SWEEP_GROSS_MINOR = 50_00            # 归集 50.00
SWEEP_GAS_MICRO = 30_000             # 归集 gas 0.03 USD（micro）
PAYOUT_GROSS_MINOR = 85_00           # 分润 gross 85.00
PAYOUT_FEE_MINOR = 50                # 分润 fee 0.50
REFUND_MINOR = 50_00                 # 退款 50.00
REFUND_GAS_MICRO = 200_000           # 退款 gas 0.20 USD（runbook 场景；见风险 R3）
HOT_WALLET_CAP_MINOR = 8_000         # 热钱包 cap 80.00（50.00+尘埃 可触发 60% 归集阈值）
HOT_WALLET_BALANCE_MINOR = 51_00     # 热钱包余额 51.00（归集 50.00 后留 1.00 尘埃）

POLICY_VERSION = "m08-pool-default"

USER = {"account_id": "demo", "tenant_id": "tenant-a", "user_id": "u-demo"}
PROVIDER = {"account_id": "demo", "tenant_id": "tenant-a"}
ADMIN_MAKER = {"admin_id": "fin-maker", "tenant_id": "tenant-a", "scopes": ["*"]}
ADMIN_CHECKER = {"admin_id": "fin-checker", "tenant_id": "tenant-a", "scopes": ["*"]}
RECON_ADMIN = {"admin_id": "recon-reviewer", "tenant_id": "tenant-a",
               "scopes": ["recon.read", "recon.write"]}
RECON_SERVICE = {"service_id": "M08-payout",
                 "scopes": ["recon.attestation.validate"]}


class DemoClock:
    """可推进的 UTC 时钟（demo 的 now_provider 唯一来源）。"""

    def __init__(self, moment: datetime) -> None:
        self.moment = _as_utc(moment)

    def now(self) -> datetime:
        return self.moment

    def advance(self, **kwargs: Any) -> datetime:
        self.moment = self.moment + timedelta(**kwargs)
        return self.moment


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return _as_utc(moment).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class DemoSchema:
    """一次性 schema：创建 / 全链迁移 / 连接 / DROP。"""

    def __init__(self, name: str, dsn: str) -> None:
        if not _SCHEMA_RE.match(name):
            raise ValueError(f"非法 schema 名：{name!r}")
        self.name = name
        self.dsn = dsn

    @classmethod
    def fresh(cls) -> "DemoSchema":
        value = os.environ.get("DJB_DSN")
        if not value:
            raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库 / 不落盘）")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return cls(f"s2_treasury_{stamp}_{os.getpid()}", value)

    def connect(self, *, autocommit: bool = True) -> psycopg.Connection:
        return psycopg.connect(
            self.dsn, autocommit=autocommit,
            options=f"-c search_path={self.name} -c synchronous_commit=off",
            connect_timeout=15, application_name="s2-treasury-demo")

    def migrate(self) -> list[str]:
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
                sql.Identifier(self.name)))
        applied: list[str] = []
        with self.connect() as conn:
            for path in wiring_db.migration_files():
                conn.execute(path.read_text(encoding="utf-8"))
                applied.append(path.name)
        return applied

    def drop(self) -> None:
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                sql.Identifier(self.name)))


# ═══════════════════════════════════════════════════════════ 自组 app
def _request_connection_factory(schema: DemoSchema) -> Callable[[], Any]:
    """请求级连接（与生产 `app.db.conn()` 同语义：正常出口 commit，异常 rollback）。

    注意：M09 的 attestation 路由把写入放在 `attestations.submit` 内部的
    `with conn.transaction()` 里（在隐式事务中会退化成 SAVEPOINT），因此请求连接
    **必须**在正常出口显式 commit，否则凭证会在 close 时被回滚。
    """

    @contextmanager
    def factory():
        connection = schema.connect(autocommit=False)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    return factory


def _m08_client(schema: DemoSchema, clock: DemoClock,
                registry: m08_provider.ProviderRegistry, *,
                user: Mapping[str, Any] = USER,
                provider: Mapping[str, Any] = PROVIDER,
                admin: Mapping[str, Any] = ADMIN_MAKER) -> TestClient:
    app = FastAPI(title="s2-demo-m08")
    app.include_router(m08_router_mod.create_router(
        connection_factory=_request_connection_factory(schema),
        user_resolver=lambda request: dict(user),
        provider_resolver=lambda request: dict(provider),
        admin_resolver=lambda request: dict(admin),
        step_up_verifier=lambda request: True,
        now_provider=clock.now,
        config_provider=None,
        ledger_poster=M06LedgerPoster(),
        provider_registry=registry,
        address_allocator=m08_wallet.SyntheticAddressAllocator(),
        attestation_verifier=make_attestation_verifier(
            lambda: schema.connect(autocommit=False)),
    ))
    return TestClient(app, headers={"X-Admin-Step-Up": "demo-step-up"})


def _m09_client(schema: DemoSchema, clock: DemoClock, *,
                admin: Mapping[str, Any] = RECON_ADMIN,
                service: Mapping[str, Any] = RECON_SERVICE) -> TestClient:
    app = FastAPI(title="s2-demo-m09")
    app.include_router(create_recon_router(
        connection_factory=_request_connection_factory(schema),
        admin_resolver=lambda request: dict(admin),
        service_resolver=lambda request: dict(service),
        step_up_verifier=lambda request: True,
        now_provider=clock.now,
    ))
    return TestClient(app, headers={"X-Admin-Step-Up": "demo-step-up"})


# ═══════════════════════════════════════════════════════════ 断言 / HTTP 小工具
def _check(condition: Any, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _json(response: Any, *, expected: tuple[int, ...] = (200, 201), what: str = "") -> dict:
    if response.status_code not in expected:
        raise AssertionError(
            f"{what or 'HTTP'} 期望 {expected}，实际 {response.status_code}：{response.text[:400]}")
    return response.json()


def _error_code(response: Any) -> int | None:
    try:
        body = response.json()
    except Exception:                                     # noqa: BLE001
        return None
    error = body.get("error") if isinstance(body, Mapping) else None
    return None if not isinstance(error, Mapping) else error.get("code")


def _sign_all(conn: Any, signing_request_id: str, moment: datetime) -> dict[str, Any]:
    """记录签名四事件（requested 已在 request_signature 时落库）→ 2/3 签齐。"""
    steps = (
        m08_models.SigningEventDraft(event="presented", signer_type="owner"),
        m08_models.SigningEventDraft(event="signed", signer_type="owner",
                                     signature_hash="a" * 64),
        m08_models.SigningEventDraft(event="verified", signer_type="company"),
        m08_models.SigningEventDraft(event="co_signed", signer_type="reviewer",
                                     signature_hash="b" * 64),
    )
    result: dict[str, Any] | None = None
    for item in steps:
        result = m08_signing.record_event(conn, signing_request_id, item, now=moment)
    _check(result is not None and result.get("complete") is True,
           "2/3 签名未签齐（signing 事件序列异常）")
    return result


def _webhook_body(order_no: str, provider_txn_id: str, *, amount_minor: int,
                  moment: datetime, status: str = "1",
                  key: bytes = b"test-only-mock-key",
                  mer_id: str = "m08-merchant", currency: str = "USD") -> bytes:
    fields = {
        "merId": mer_id,
        "merOrderId": order_no,
        "platformOrderId": provider_txn_id,
        "amount": int(amount_minor),
        "currency": currency,
        "status": str(status),
        "timestamp": int(_as_utc(moment).timestamp()),
        "payTime": _iso(moment),
    }
    fields["sign"] = m08_provider.sign(fields, key)
    return json.dumps(fields, ensure_ascii=False).encode("utf-8")


def _post_webhook(client: TestClient, body: bytes) -> Any:
    return client.post("/api/v1/pay/webhooks/mock", content=body,
                       headers={"Content-Type": "application/json"})


# ═══════════════════════════════════════════════════════════ 账本 / 发件箱读取
def _journals(conn: Any) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT j.journal_id, j.seq, j.event_type, j.source_type, j.source_id,
                   j.event_seq,
                   COALESCE(sum(l.amount_minor) FILTER (WHERE l.dc = 'D'), 0) AS debit,
                   COALESCE(sum(l.amount_minor) FILTER (WHERE l.dc = 'C'), 0) AS credit,
                   count(l.line_no) AS line_count
              FROM journal_entry j LEFT JOIN journal_line l ON l.journal_id = j.journal_id
             GROUP BY 1,2,3,4,5,6
             ORDER BY j.seq
            """)
        return [dict(row) for row in cur.fetchall()]


def _coa_balances(conn: Any) -> dict[str, int]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT coa_code,
                   sum(CASE WHEN dc = 'D' THEN amount_minor ELSE -amount_minor END) AS net
              FROM journal_line GROUP BY coa_code ORDER BY coa_code
            """)
        return {row["coa_code"]: int(row["net"]) for row in cur.fetchall()}


def _account_balances(conn: Any) -> dict[str, int]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT account_id,
                   sum(CASE WHEN dc = 'D' THEN amount_minor ELSE -amount_minor END) AS net
              FROM journal_line GROUP BY account_id ORDER BY account_id
            """)
        return {row["account_id"]: int(row["net"]) for row in cur.fetchall()}


def _outbox_counts(conn: Any) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT type, status, count(*) AS n
              FROM m08_outbox GROUP BY type, status ORDER BY type, status
            """)
        rows = [dict(row) for row in cur.fetchall()]
        cur.execute("SELECT count(*) AS n FROM m08_outbox")
        total = int(cur.fetchone()["n"])
    by_type: dict[str, dict[str, int]] = {}
    by_status: dict[str, int] = {}
    for row in rows:
        by_type.setdefault(row["type"], {})[row["status"]] = int(row["n"])
        by_status[row["status"]] = by_status.get(row["status"], 0) + int(row["n"])
    return {"total": total, "by_type": by_type, "by_status": by_status,
            "dead": by_status.get("dead", 0), "pending": by_status.get("pending", 0),
            "published": by_status.get("published", 0)}


def _payable_total(conn: Any) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COALESCE(sum(CASE WHEN dc = 'C' THEN amount_minor ELSE -amount_minor END), 0)
              FROM journal_line WHERE coa_code = ANY(%s)
            """, (["2101", "2102", "2103", "2201", "2202", "2203"],))
        return int(cur.fetchone()[0])


def _ledger_root(conn: Any) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT hash FROM journal_entry ORDER BY seq")
        hashes = b"".join(bytes(row[0]) for row in cur.fetchall())
    return hashlib.sha256(hashes).hexdigest()


def _post_e2_preset(conn: Any, *, clock: DemoClock, amount_micro: int,
                    tx_hash: str) -> str:
    """E2 预置：USDT 收款确认入账（借 1101 + 2990 / 贷 1111 + 2101，§20.3.1）。"""
    draft = JournalDraft(
        event_type="E2", unit_type="USD", source_type="chain_tx", source_id=tx_hash,
        event_seq=2, policy_version=POLICY_VERSION,
        lines=[
            JournalLine(account_id="coa:1101", coa_code="1101", dc="D",
                        amount_minor=int(amount_micro), entry_type="deposit",
                        qty_minor=int(amount_micro), unit_scale=6),
            JournalLine(account_id="coa:2990", coa_code="2990", dc="D",
                        amount_minor=int(amount_micro), entry_type="deposit",
                        unit_scale=6),
            JournalLine(account_id="coa:1111", coa_code="1111", dc="C",
                        amount_minor=int(amount_micro), entry_type="deposit",
                        unit_scale=6),
            JournalLine(account_id="acct:demo", coa_code="2101", dc="C",
                        amount_minor=int(amount_micro), entry_type="deposit",
                        unit_scale=6),
        ],
        ts=clock.now(), idempotency_key=f"chain_tx:{tx_hash}:2",
        trace_id="s2-demo-e2", correlation_id=tx_hash, ref_id=tx_hash)
    result = ledger_gateway.post_journal(conn, draft)
    return str(result.journal_id)


def _demo_gas_resolver(event: Mapping[str, Any], conn: Any) -> int:
    """E11② 的链上 gas（runbook 场景 0.20 USD）；E9 的 gas 在 wallet_transfers 上已有。"""
    if str(event.get("type")) == "refund.completed":
        return REFUND_GAS_MICRO
    return 0


def _consume(schema: DemoSchema, runs: list[dict[str, Any]], *,
             poster: Callable[[Any, JournalDraft], Any] | None = None) -> dict[str, Any]:
    """跑一次事件消费（连接非 autocommit；每条事件一个事务由 consume 管理）。"""
    with schema.connect(autocommit=False) as connection:
        summary = consume(connection, gas_resolver=_demo_gas_resolver, poster=poster)
    runs.append(summary)
    return summary


def _recon_and_attest(client: TestClient, schema: DemoSchema, clock: DemoClock, *,
                      label: str, period_start: datetime, period_end: datetime,
                      cutoff: datetime) -> dict[str, Any]:
    """M09 daily_close run（幂等）→ 双人 sign-off → attestation → validate。"""
    spec = recon_models.RunSpec(
        scope="daily_close", period_start=_as_utc(period_start),
        period_end=_as_utc(period_end), cutoff_at=_as_utc(cutoff),
        subject_ref=None, created_by="recon-maker", policy_version=POLICY_VERSION,
        rule_version=recon_facts.RULE_VERSION)
    with schema.connect(autocommit=False) as connection:
        results = recon_engine.run(connection, spec)
        run_row = results[0]["run"]
        run_id = str(run_row["run_id"])
        _check(not results[0]["exception_ids"],
               f"{label}: daily_close 产生差异 {results[0]['exception_ids']}")
        _check(run_row["status"] == recon_facts.RUN_STATUS_MATCHED,
               f"{label}: 对账批次状态 {run_row['status']}")
        ledger_root = _ledger_root(connection)
        payable = _payable_total(connection)
    sign_off = _json(client.post(
        f"/api/v1/admin/treasury/recon/runs/{run_id}/sign-off",
        json={"reviewer_note": f"S2 demo {label} 复核"}), what=f"sign-off {label}")
    _check(sign_off["status"] == "signed_off", f"{label}: sign-off 状态 {sign_off['status']}")
    attestation = _json(client.post(
        "/api/v1/admin/treasury/recon/attestations",
        json={
            "period_start": _iso(period_start), "period_end": _iso(period_end),
            "ledger_root": ledger_root,
            "batch_hash": hashlib.sha256(run_id.encode()).hexdigest()[:32],
            "payable_total_minor": int(payable),
            "signature_ref": f"hsm:recon-reviewer:{label}",
            # M09 的 insert_attestation 只落 draft.maker_id（不落 maker_for_period 的推导值），
            # 这里显式带上制单人，保证「复核人 ≠ 制单人」在凭证行上可审计。
            "maker_id": "recon-maker",
        }), expected=(201,), what=f"attestation {label}")
    _check(attestation["status"] == "valid", f"{label}: attestation 状态 {attestation['status']}")
    validate = _json(client.get(
        f"/api/v1/admin/treasury/recon/attestations/{attestation['attestation_id']}/validate"),
        what=f"validate {label}")
    _check(validate["valid"] is True, f"{label}: validate 结论 {validate}")
    return {"run": {"run_id": run_id, "scope": run_row["scope"],
                    "status": sign_off["status"],
                    "book_minor": int(run_row["book_minor"]),
                    "external_minor": int(run_row["external_minor"]),
                    "matched_count": int(run_row["matched_count"]),
                    "unmatched_count": int(run_row["unmatched_count"]),
                    "ledger_root": ledger_root, "payable_total_minor": int(payable)},
            "attestation": {"attestation_id": attestation["attestation_id"],
                            "status": attestation["status"],
                            "reviewer_id": attestation["reviewer_id"],
                            "maker_id": attestation["maker_id"],
                            "valid": bool(validate["valid"])},
            "validate": validate}


def run(*, keep_schema: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    schema = DemoSchema.fresh()
    steps: list[dict[str, Any]] = []
    negatives: list[dict[str, Any]] = []
    consumer_runs: list[dict[str, Any]] = []
    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    clock = DemoClock(t0)
    tx_hash = "0x" + hashlib.sha256(b"s2-treasury-e2").hexdigest()
    provider_txn = "TXN-S2-" + hashlib.sha256(b"s2-treasury-paid").hexdigest()[:12].upper()
    trade_id = "TRD-S2-" + hashlib.sha256(b"s2-treasury-e5").hexdigest()[:12].upper()
    sweep_tx = "0x" + hashlib.sha256(b"s2-treasury-sweep").hexdigest()
    payout_tx = "0x" + hashlib.sha256(b"s2-treasury-payout").hexdigest()
    registrar = m08_provider.ProviderRegistry([
        m08_provider.MockProvider(scripted_status={provider_txn: "1"})])

    def record(step: int, name: str, detail: Mapping[str, Any] | None = None) -> None:
        steps.append({"step": step, "name": name, "ok": True,
                      "detail": dict(detail or {})})

    def negative(name: str, code_expected: int, response: Any, *, path: str) -> None:
        actual = _error_code(response)
        entry = {"case": name, "expected": int(code_expected), "actual": actual,
                 "status_code": int(response.status_code), "path": path,
                 "ok": actual == int(code_expected)}
        negatives.append(entry)
        _check(entry["ok"],
               f"负例 {name} 期望 {code_expected}，实际 {actual}（HTTP {response.status_code}）")

    try:
        applied = schema.migrate()
        _check(len(applied) >= 40, f"迁移文件过少：{len(applied)}")
        with schema.connect() as connection:
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM wallet_pool")
                pool_seed = int(cur.fetchone()[0])
        _check(pool_seed == 3, f"wallet_pool seed 不是 3 池：{pool_seed}")
        record(0, "schema + 全链迁移 + seed(3 池)",
               {"schema": schema.name, "migrations": len(applied), "pools": pool_seed})

        maker = _m08_client(schema, clock, registrar, admin=ADMIN_MAKER)
        checker = _m08_client(schema, clock, registrar, admin=ADMIN_CHECKER)
        recon_client = _m09_client(schema, clock)
        poster = M06LedgerPoster()

        # ── 1 钱包池激活（2 热 + 1 温 + 1 平台温；2/3 签名 → gas_ok → ready）
        provisioned: list[dict[str, Any]] = []
        depth: dict[str, dict[str, int]] = {}
        for pool_id, count in (("polygon:hot:CLIENT", 2),
                               ("polygon:warm:CLIENT", 1),
                               ("polygon:warm:PLATFORM", 1)):
            created = _json(maker.post("/api/v1/admin/treasury/provision",
                                       json={"pool_id": pool_id, "wallet_count": count}),
                            what=f"provision {pool_id}")
            batch_id = created["batch_id"]
            with schema.connect(autocommit=False) as connection, connection.transaction():
                signature = m08_wallet.request_provision_signature(
                    connection, batch_id, actor="fin-maker", now=clock.now())
                signing_request_id = str(
                    signature["signing_request"]["signing_request_id"])
                _sign_all(connection, signing_request_id, clock.now())
            activated = _json(maker.post(
                f"/api/v1/admin/treasury/activate/{batch_id}",
                json={"signing_request_id": signing_request_id}),
                what=f"activate {pool_id}")
            _check(activated["status"] == "activated",
                   f"{pool_id} 批次未激活：{activated['status']}")
            storage_pool = m08_policy.storage_pool_key(pool_id)
            with schema.connect(autocommit=False) as connection, connection.transaction():
                with connection.cursor(row_factory=dict_row) as cur:
                    cur.execute("SELECT wallet_id FROM wallet WHERE pool_id = %s"
                                " AND status = 'active' ORDER BY address", (storage_pool,))
                    rows = [dict(row) for row in cur.fetchall()]
                for row in rows:
                    m08_store.update_wallet(connection, str(row["wallet_id"]), gas_ok=True)
            _check(len(rows) == count, f"{pool_id} 激活只数 {len(rows)} != {count}")
            provisioned.append({"pool_id": pool_id, "batch_id": batch_id,
                                "wallet_count": count,
                                "wallets": [str(row["wallet_id"]) for row in rows]})
        with schema.connect() as connection:
            for pool_id in ("polygon:hot:CLIENT", "polygon:warm:CLIENT",
                            "polygon:warm:PLATFORM"):
                detail = m08_wallet.pool_detail(connection, pool_id)
                depth[pool_id] = {"depth_ready": int(detail["depth_ready"]),
                                  "in_service": int(detail["in_service_count"])}
        _check(depth["polygon:hot:CLIENT"]["depth_ready"] == 2, f"热池 ready 不是 2：{depth}")
        _check(depth["polygon:warm:CLIENT"]["depth_ready"] == 1, f"温池 ready 不是 1：{depth}")
        record(1, "钱包池激活（2/3 签名 + gas_ok → ready）",
               {"batches": provisioned, "depth": depth})

        # ── 2 出款地址：pending → 72h 冷却 → 审批 whitelisted
        payee_address = "0x" + hashlib.sha256(b"s2-demo-payee").hexdigest()[:40]
        submitted = _json(maker.post("/api/v1/provider/payout-address", json={
            "chain": "polygon", "address": payee_address,
            "ownership_challenge_ref": "challenge-s2-demo",
            "label": "demo-payee"}), what="payout-address")
        _check(submitted["status"] == "pending", f"地址不是 pending：{submitted['status']}")
        cooldown_until = submitted["cooldown_until"]
        clock.advance(hours=73)
        with schema.connect(autocommit=False) as connection, connection.transaction():
            approved_address = m08_payout.approve_payout_address(
                connection, submitted["address_id"], approver="fin-approver",
                risk_check=None, now=clock.now())
        _check(approved_address["address"]["status"] == "whitelisted",
               "地址审批后不是 whitelisted")
        record(2, "出款地址登记 + 72h 冷却 + 审批",
               {"address": payee_address, "cooldown_until": cooldown_until,
                "status": "whitelisted", "clock": _iso(clock.now())})

        # ── 3 下单（100.00 USD，mock）
        order = _json(maker.post("/api/v1/pay/orders", json={
            "amount_minor": ORDER_MINOR, "currency": "USD", "method": "card",
            "provider": "mock", "description": "S2 demo order"}), what="create order")
        _check(order["status"] == "created", f"订单初始状态不是 created：{order['status']}")
        order_no = order["order_no"]
        record(3, "下单（100.00 USD / mock）",
               {"order_no": order_no, "status": order["status"]})

        # ── 4 签名回调 + 负例
        negative("webhook 金额不符", 40911, _post_webhook(maker, _webhook_body(
            order_no, provider_txn, amount_minor=9_900, moment=clock.now())),
                 path="POST /pay/webhooks/mock")
        bad = json.loads(_webhook_body(order_no, provider_txn, amount_minor=ORDER_MINOR,
                                       moment=clock.now()))
        bad["sign"] = "0" * 64
        negative("webhook 验签失败", 40001,
                 _post_webhook(maker, json.dumps(bad).encode()), path="POST /pay/webhooks/mock")
        negative("webhook 订单不存在", 40401, _post_webhook(maker, _webhook_body(
            "PO-NOT-EXIST", provider_txn, amount_minor=ORDER_MINOR, moment=clock.now())),
                 path="POST /pay/webhooks/mock")
        paid_body = _webhook_body(order_no, provider_txn, amount_minor=ORDER_MINOR,
                                  moment=clock.now())
        ack = _json(_post_webhook(maker, paid_body), what="webhook paid")
        _check(ack["received"] is True and ack["status"] == "credited",
               f"回调后订单未 credited：{ack}")
        negative("webhook 重复回调", 40910, _post_webhook(maker, paid_body),
                 path="POST /pay/webhooks/mock")
        record(4, "签名回调 → credited + 负例",
               {"order_no": order_no, "status": ack["status"],
                "provider_txn_id": provider_txn})

        # ── 5 E3（webhook 同一业务事务同步落账）
        with schema.connect() as connection:
            journals = _journals(connection)
        e3 = [item for item in journals if item["event_type"] == "E3"]
        _check(len(e3) == 1, f"E3 凭证数 {len(e3)} != 1")
        _check(int(e3[0]["debit"]) == ORDER_MINOR * 10_000,
               f"E3 借方 {e3[0]['debit']} != 订单 micro")
        record(5, "E3：借 1120 / 贷 2101",
               {"journal_id": e3[0]["journal_id"], "amount_micro": int(e3[0]["debit"])})

        # ── 6 E4 两步（PSP 结算到账 + 平台补足手续费）
        with schema.connect(autocommit=False) as connection, connection.transaction():
            e4 = m08_order.settle_attempt(
                connection, identifier=order_no, provider_txn_id=provider_txn,
                settled_minor=SETTLED_MINOR, fee_minor=PSP_FEE_MINOR,
                provider_registry=registrar,
                config=m08_config.load(None, chain="polygon", role="hot",
                                       fund_class="CLIENT"),
                ledger_poster=poster, now=clock.now(), trace_id="s2-demo-e4")
        _check(len(e4["journal_ids"]) == 2, f"E4 凭证数 {len(e4['journal_ids'])} != 2")
        record(6, "E4 两步（1121+1910/1120；1121+5103/1109+1910）",
               {"journal_ids": e4["journal_ids"],
                "settled_minor": SETTLED_MINOR, "fee_minor": PSP_FEE_MINOR})

        # ── 7 E5 两步（法币兑换 USDT 入客户温钱包）
        with schema.connect(autocommit=False) as connection, connection.transaction():
            e5_requests = m08_ledger.e5_requests(
                trade={"trade_id": trade_id, "amount_minor": ORDER_MINOR,
                       "fee_minor": CONVERSION_FEE_MINOR},
                policy_version=POLICY_VERSION, occurred_at=clock.now(),
                trace_id="s2-demo-e5")
            e5 = m08_ledger.post_many(connection, poster, e5_requests)
        _check(len(e5) == 2, f"E5 凭证数 {len(e5)} != 2")
        record(7, "E5 两步（1102+1910/1121；1102+5106/1109+1910）",
               {"journal_ids": [str(item["journal_id"]) for item in e5],
                "amount_minor": ORDER_MINOR, "fee_minor": CONVERSION_FEE_MINOR})

        # ── 8 归集：E2 预置热钱包 → sweep_plan → 六事件 → complete_sweep → 消费 E9
        with schema.connect(autocommit=False) as connection, connection.transaction():
            with connection.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT wallet_id FROM wallet WHERE pool_id = %s"
                            " AND status = 'active' AND switch_state = 'in_service'"
                            " ORDER BY address LIMIT 1",
                            (m08_policy.storage_pool_key("polygon:hot:CLIENT"),))
                hot_wallet_id = str(cur.fetchone()["wallet_id"])
            m08_store.update_wallet(connection, hot_wallet_id,
                                    cap_minor=HOT_WALLET_CAP_MINOR,
                                    balance_minor=HOT_WALLET_BALANCE_MINOR,
                                    gas_ok=True)
            e2_journal = _post_e2_preset(
                connection, clock=clock,
                amount_micro=SWEEP_GROSS_MINOR * 10_000, tx_hash=tx_hash)
            sweep = m08_wallet.sweep_plan(connection, pool_id="polygon:hot:CLIENT",
                                          config_provider=None, actor="treasury-ops",
                                          now=clock.now())
            _check(bool(sweep["transfers"]), f"归集未产出转账：{sweep}")
            transfer_id = str(sweep["transfers"][0]["transfer_id"])
            with connection.cursor() as cur:
                cur.execute("UPDATE wallet_transfers SET gas_fee_minor = %s"
                            " WHERE transfer_id = %s", (SWEEP_GAS_MICRO, transfer_id))
            _sign_all(connection, str(sweep["signing_request"]["signing_request_id"]),
                      clock.now())
            m08_wallet.complete_sweep(connection, transfer_id, txid=sweep_tx,
                                      actor="treasury-ops", now=clock.now())
        sweep_consume = _consume(schema, consumer_runs)
        with schema.connect() as connection:
            journals = _journals(connection)
        e9 = [item for item in journals if item["event_type"] == "E9"]
        _check(len(e9) == 1, f"E9 凭证数 {len(e9)} != 1（归集事件未消费？）")
        _check(int(e9[0]["debit"]) == SWEEP_GROSS_MINOR * 10_000 + SWEEP_GAS_MICRO,
               f"E9 借方 {e9[0]['debit']} != 归集 + gas")
        record(8, "归集（E2 预置 → sweep_plan → 签名 → complete_sweep → E9）",
               {"e2_journal_id": e2_journal, "transfer_id": transfer_id, "txid": sweep_tx,
                "sweep_amount_micro": SWEEP_GROSS_MINOR * 10_000,
                "gas_micro": SWEEP_GAS_MICRO, "consume": _consume_brief(sweep_consume),
                "e9_journal_id": e9[0]["journal_id"]})

        # ── 9 分润：attestation 前置 → create/approve/sign-request → 六事件 → broadcast → settle → E8
        pre_gate = _recon_and_attest(recon_client, schema, clock, label="payout-gate",
                                     period_start=clock.now() - timedelta(days=1),
                                     period_end=clock.now() + timedelta(hours=1),
                                     cutoff=clock.now())
        _check(pre_gate["attestation"]["valid"] is True, "出款前 attestation 不是 valid")
        attestation_ref = pre_gate["attestation"]["attestation_id"]

        payout_body = {
            "items": [{"payee_account_id": "demo", "payee_address": payee_address,
                       "gross_minor": PAYOUT_GROSS_MINOR, "fee_minor": PAYOUT_FEE_MINOR}],
            "attestation_ref": attestation_ref,
        }
        gate_batch = _json(maker.post("/api/v1/admin/treasury/payouts", json={
            "items": payout_body["items"]}), what="create payout (no attestation)")
        negative("出款复核人=制单人", 40919, maker.post(
            f"/api/v1/admin/treasury/payouts/{gate_batch['batch_no']}/approve", json={}),
                 path="POST /admin/treasury/payouts/{id}/approve")
        negative("出款缺 attestation", 40916, checker.post(
            f"/api/v1/admin/treasury/payouts/{gate_batch['batch_no']}/approve", json={}),
                 path="POST /admin/treasury/payouts/{id}/approve")
        negative("出款收款地址未准入", 42210, maker.post(
            "/api/v1/admin/treasury/payouts", json={
                "items": [{"payee_account_id": "demo",
                           "payee_address": "0x" + hashlib.sha256(b"nope").hexdigest()[:40],
                           "gross_minor": PAYOUT_GROSS_MINOR,
                           "fee_minor": PAYOUT_FEE_MINOR}],
                "attestation_ref": attestation_ref}),
                 path="POST /admin/treasury/payouts")

        payout = _json(maker.post("/api/v1/admin/treasury/payouts", json=payout_body),
                       what="create payout")
        batch_no = payout["batch_no"]
        checked = _json(checker.post(
            f"/api/v1/admin/treasury/payouts/{batch_no}/approve", json={"note": "对账已平"}),
            what="approve payout")
        _check(checked["status"] == "checked", f"复核后不是 checked：{checked['status']}")
        signature = _json(checker.post(
            f"/api/v1/admin/treasury/payouts/{batch_no}/sign-request", json={}),
            what="payout sign-request")
        signing_request_id = signature["signing_request_id"]
        with schema.connect(autocommit=False) as connection, connection.transaction():
            _sign_all(connection, signing_request_id, clock.now())
        with schema.connect(autocommit=False) as connection, connection.transaction():
            broadcast = m08_payout.broadcast_payout_batch(
                connection, batch_no, txid=payout_tx, actor="fin-checker", now=clock.now())
            _check(broadcast["batch"]["status"] == "broadcast", "批次未广播")
            settled = m08_payout.settle_payout_batch(
                connection, batch_no, txid=payout_tx, actor="fin-checker", now=clock.now())
            _check(settled["batch"]["status"] == "settled",
                   f"批次结算状态不是 settled：{settled['batch']['status']}")
        payout_consume = _consume(schema, consumer_runs)
        with schema.connect() as connection:
            journals = _journals(connection)
        e8 = [item for item in journals if item["event_type"] == "E8"]
        _check(len(e8) == 4, f"E8 凭证数 {len(e8)} != 4（计提 + 2a/2b/2c）")
        record(9, "分润（attestation → 复核 → 2/3 签名 → 广播 → settled → E8 四张）",
               {"batch_no": batch_no, "status": "settled", "txid": payout_tx,
                "attestation_ref": attestation_ref,
                "consume": _consume_brief(payout_consume),
                "journal_ids": [item["journal_id"] for item in e8]})

        # ── 10 退款：requested → 冷却负例 → +25h approve → execute → complete → E11
        refund = _json(maker.post("/api/v1/pay/refund-requests", json={
            "order_no": order_no, "amount_minor": REFUND_MINOR,
            "reason_code": "customer_request",
            "original_route": f"psp:mock:{provider_txn}"}), what="refund request")
        _check(refund["status"] == "requested", f"退款申请状态不是 requested：{refund['status']}")
        refund_id = refund["refund_request_id"]
        negative("退款 24h 冷却未到", 40919, _refund_early_approve(
            schema, refund_id, clock.now() + timedelta(hours=1)),
                 path="refund.approve_refund_request(domain)")
        clock.advance(hours=25)
        with schema.connect(autocommit=False) as connection, connection.transaction():
            approved = m08_refund.approve_refund_request(
                connection, refund_id, approver="fin-checker", now=clock.now())
            _check(approved["refund"]["status"] == "approved", "退款审批未通过")
            executing = m08_refund.execute_refund_request(
                connection, refund_id, actor="fin-checker", now=clock.now(),
                trace_id="s2-demo-refund")
            _check(executing["refund"]["status"] == "executing", "退款未进入 executing")
            completed = m08_refund.complete_refund_request(
                connection, refund_id, now=clock.now(), trace_id="s2-demo-refund")
            _check(completed["refund"]["status"] == "succeeded", "退款未 succeeded")

        def _boom(conn: Any, draft: JournalDraft) -> Any:
            raise RuntimeError("drill: M06 暂不可用")

        drill = _consume(schema, consumer_runs, poster=_boom)
        _check(drill["failed"] == 1 and drill["retry"] == 1 and drill["published"] == 0,
               f"失败 drill 未按预期退避：{_consume_brief(drill)}")
        with schema.connect() as connection:
            with connection.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status, attempts FROM m08_outbox"
                            " WHERE aggregate_id = %s", (refund_id,))
                row = dict(cur.fetchone())
        _check(row["status"] == "pending" and int(row["attempts"]) == 1,
               f"失败事件状态不对：{row}")
        time.sleep(1.3)  # 退避 1s（events.mark_failed 的 _BACKOFF_SECONDS[0]）
        refund_consume = _consume(schema, consumer_runs)
        with schema.connect() as connection:
            journals = _journals(connection)
        e11 = [item for item in journals if item["event_type"] == "E11"]
        _check(len(e11) == 2, f"E11 凭证数 {len(e11)} != 2（受理 + 打款）")
        record(10, "退款（14 天窗口 / 原路 / 双人 + 24h 冷却 / 失败退避重试 → E11）",
               {"refund_no": refund["refund_no"], "status": "succeeded",
                "retry_drill": {"state": row["status"], "attempts": int(row["attempts"])},
                "consume": _consume_brief(refund_consume),
                "journal_ids": [item["journal_id"] for item in e11]})

        # ── 11 对账（daily_close）+ sign-off + attestation + validate
        final_gate = _recon_and_attest(recon_client, schema, clock, label="final",
                                       period_start=clock.now() - timedelta(days=1),
                                       period_end=clock.now() + timedelta(hours=1),
                                       cutoff=clock.now())
        _check(final_gate["attestation"]["valid"] is True, "最终 attestation 不是 valid")
        record(11, "对账 daily_close + sign-off + attestation + validate",
               {"run": final_gate["run"], "attestation": final_gate["attestation"],
                "validate": final_gate["validate"],
                "payout_gate_attestation": attestation_ref})

        # ── 12 复算：verify / trial / 余额表 / outbox / 重复消费 + 重复操作
        with schema.connect() as connection:
            verify = verify_ledger(connection)
            journals = _journals(connection)
            coa = _coa_balances(connection)
            accounts = _account_balances(connection)
            outbox = _outbox_counts(connection)
            payable_total = _payable_total(connection)
            i4 = check_negative_liabilities(connection)
            with connection.cursor() as cur:
                cur.execute("SELECT count(*) FROM journal_line")
                line_count = int(cur.fetchone()[0])
                cur.execute("SELECT count(*) FROM account_balances")
                balance_versions = int(cur.fetchone()[0])
        trial = {"debit": sum(int(item["debit"]) for item in journals),
                 "credit": sum(int(item["credit"]) for item in journals)}
        trial["diff"] = trial["debit"] - trial["credit"]
        by_event: dict[str, int] = {}
        unbalanced: list[str] = []
        for item in journals:
            by_event[item["event_type"]] = by_event.get(item["event_type"], 0) + 1
            if int(item["debit"]) != int(item["credit"]) or int(item["debit"]) <= 0:
                unbalanced.append(str(item["journal_id"]))
        _check(not unbalanced, f"凭证借贷不平：{unbalanced}")
        _check(trial["diff"] == 0, f"全库试算不平：{trial}")
        _check(int(verify["diff"]) == 0, f"verify_ledger diff != 0：{verify}")
        _check(outbox["dead"] == 0, f"outbox 有 dead 事件：{outbox}")
        _check(outbox["pending"] == 0, f"outbox 还有 pending 事件：{outbox}")
        _check(not i4, f"I-4 违反（负负债）：{i4}")

        journal_count_before = len(journals)
        with schema.connect(autocommit=False) as connection, connection.transaction():
            with connection.cursor() as cur:
                cur.execute("UPDATE m08_outbox SET status = 'pending', next_attempt_at = NULL"
                            " WHERE type = 'sweep.completed'")
        replay = _consume(schema, consumer_runs)
        with schema.connect() as connection:
            journals_after = _journals(connection)
            outbox_after = _outbox_counts(connection)
            with connection.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status FROM payout_batches WHERE batch_no = %s",
                            (batch_no,))
                payout_status = cur.fetchone()["status"]
                cur.execute("SELECT status FROM refund_requests WHERE refund_request_id = %s",
                            (refund_id,))
                refund_status = cur.fetchone()["status"]
                cur.execute("SELECT count(*) AS n FROM signing_events")
                signing_events = int(cur.fetchone()["n"])
        replay_journals = [entry for entry in replay["journals"]
                           if entry["type"] == "sweep.completed"]
        replay_idempotent = bool(replay_journals) and all(
            item["idempotent"] for item in replay_journals[0]["journals"])
        _check(len(journals_after) == journal_count_before,
               f"重复消费新增了凭证：{journal_count_before} → {len(journals_after)}")
        _check(replay_idempotent, f"回放消费未命中 M06 幂等：{replay_journals}")
        _check(outbox_after["pending"] == 0, f"回放后 outbox 仍有 pending：{outbox_after}")
        _check(payout_status == "settled" and refund_status == "succeeded",
               f"终态不对：payout={payout_status} refund={refund_status}")
        _check(len(negatives) == 8, f"负例数量 {len(negatives)} != 8")

        expected = {1101: 0, 1102: 14_800_000, 1109: -1_700_000, 1120: 0, 1121: 0,
                    1140: -30_000, 1910: 0, 5102: 230_000, 5103: 1_500_000,
                    5106: 200_000, 5501: 85_000_000, 2201: 0, 2203: 0}
        comparison = {str(code): {"expected": value, "actual": int(coa.get(str(code), 0)),
                                  "ok": int(coa.get(str(code), 0)) == value}
                      for code, value in expected.items()}
        for code, item in comparison.items():
            _check(item["ok"], f"科目 {code} 余额 {item['actual']} != runbook {item['expected']}")
        deviations = {key: value for key, value in comparison.items() if not value["ok"]}
        total_journals = len(journals_after)
        _check(total_journals == 13, f"凭证总数 {total_journals} != 13")

        summary = {
            "ok": True,
            "schema": schema.name,
            "schema_kept": bool(keep_schema),
            "migrations": len(applied),
            "elapsed_s": round(time.monotonic() - started, 2),
            "steps": steps,
            "journals": {
                "count": total_journals,
                "by_event_type": by_event,
                "line_count": line_count,
                "balance_versions": balance_versions,
                "all_balanced": not unbalanced,
                "trial": trial,
                "vouchers": [
                    {"journal_id": item["journal_id"], "event_type": item["event_type"],
                     "source_type": item["source_type"], "source_id": item["source_id"],
                     "event_seq": int(item["event_seq"]), "debit": int(item["debit"]),
                     "credit": int(item["credit"]), "line_count": int(item["line_count"])}
                    for item in journals_after],
            },
            "balances_micro": {
                "coa": {key: int(value) for key, value in sorted(coa.items())},
                "accounts": {key: int(value) for key, value in sorted(accounts.items())},
                "runbook_comparison": comparison,
                "deviations": deviations,
            },
            "zero_accounts": {str(code): int(coa.get(str(code), 0)) == 0
                              for code in (1101, 1120, 1121, 1910, 2201, 2203)},
            "payable_total_micro": payable_total,
            "i4_violations": i4,
            "states": {
                "order": ack["status"],
                "payout_batch": payout_status,
                "refund": refund_status,
                "sweep_transfer": "confirmed",
                "signing_events": signing_events,
                "wallets_ready": {
                    "hot": depth["polygon:hot:CLIENT"]["depth_ready"],
                    "warm": depth["polygon:warm:CLIENT"]["depth_ready"],
                    "platform_warm": depth["polygon:warm:PLATFORM"]["depth_ready"]},
            },
            "outbox": outbox_after,
            "consumer": {
                "runs": consumer_runs,
                "replay_idempotent": replay_idempotent,
                "journals_delta_on_replay": len(journals_after) - journal_count_before,
            },
            "recon": {"payout_gate": pre_gate, "final": final_gate},
            "verify": {"diff": int(verify["diff"]),
                       "chain_diff": int(verify["chain"]["diff"]),
                       "balance_diff": int(verify["balances"]["diff"]),
                       "net_minor": int(verify["net_minor"]),
                       "journals": int(verify["chain"]["journals"]),
                       "chain_bad": len(verify["chain"]["chain_bad"]),
                       "hash_bad": len(verify["chain"]["hash_bad"])},
            "negative_cases": negatives,
            "risks": [
                "R1 runbook §3 期望 acct:<demo> -150M 与 §20.3.1/§20.3.4 口径不一致："
                "E11① 借 2101 50M 必须落在同一主体账户（否则 coa:2101 出现借方余额违反 I-4）；"
                "按规范实现后 acct:<demo> 实际 -100M（= 2101 贷方发生额 150M - 退款受理借方 50M），"
                "i4_violations=0。已报 Lead，不自行改分录方向。",
                "R2 E8 计提幂等键在 §20.3.1 写「原 journal」，但 payout.paid 信封 / payout_batches"
                " 都没有该引用 -> source_id 取 batch_id（需 M08 补字段 / 事件的 CR）。",
                "R3 E11② 的 5102 gas 无 M08 数据落点（refund_requests 无 gas 列 / 信封无字段）"
                " -> demo 注入 gas_resolver（0.20 USD 场景）；生产需 M08 记录链上实付 gas。",
                "R4 E2 预置只记 E2（E1 不在 S2 范围）-> 1111 / 2990 各留 50M 在途残差，"
                "生产由 E1->E2 两笔闭合。",
                "R5 M09 三方对账 scope（psp / chain / bank）仍 deferred，只有 receipt / "
                "daily_close；本次放款闸门只用 daily_close attestation。",
                "R6 M08 签名六事件：requested + presented + signed + verified + co_signed 由 "
                "signing 落库；第 6 个 broadcast 在 M08 无落库入口（未改 M08）。",
                "R7 demo 场景把热钱包 cap 调成 80.00 / 余额 51.00，才让 50.00+1.00 尘埃越过 "
                "归集 60% 阈值；生产 cap 由池配置（cap_plan）给出。",
            ],
        }
        record(12, "复算（verify / trial / outbox / 幂等回放）",
               {"verify_diff": int(verify["diff"]), "trial": trial,
                "outbox": outbox_after, "replay_idempotent": replay_idempotent,
                "negative_cases": len(negatives)})
        return summary
    finally:
        if not keep_schema:
            try:
                schema.drop()
            except Exception:                          # noqa: BLE001 - DROP 失败不掩盖主错
                pass


def _refund_early_approve(schema: DemoSchema, refund_id: str, moment: datetime) -> Any:
    """退款冷却期审批（期望 40919）；返回带 status_code/code 的错误信封。"""
    from app.treasury import errors as m08_errors

    class _Failure:
        status_code = 0
        text = ""

        def __init__(self, code: int, status: int) -> None:
            self.status_code = status
            self._code = code

        def json(self) -> dict[str, Any]:
            return {"error": {"code": self._code}}

    try:
        with schema.connect(autocommit=False) as connection:
            m08_refund.approve_refund_request(connection, refund_id,
                                              approver="fin-checker", now=moment)
    except m08_errors.TreasuryError as exc:
        return _Failure(int(getattr(exc, "code", 0)), int(getattr(exc, "status_code", 0)))
    raise AssertionError("退款冷却期审批未按预期抛错（24h 冷却失效）")


def _consume_brief(summary: Mapping[str, Any]) -> dict[str, Any]:
    return {"scanned": summary.get("scanned", 0),
            "published": summary.get("published", 0),
            "consumed": summary.get("consumed", {}),
            "skipped": summary.get("skipped", {}),
            "failed": summary.get("failed", 0),
            "retry": summary.get("retry", 0),
            "dead": summary.get("dead", 0),
            "dead_total": summary.get("dead_total", 0)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DJB S2 treasury loop demo")
    parser.add_argument("--keep-schema", action="store_true", help="保留 demo schema")
    parser.add_argument("--json", action="store_true", help="输出 JSON 摘要（默认即 JSON）")
    args = parser.parse_args(argv)
    try:
        summary = run(keep_schema=args.keep_schema)
    except Exception as exc:                           # noqa: BLE001 - CLI 只打印摘要
        print(json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        raise
    print(json.dumps({"ok": True, **summary}, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
