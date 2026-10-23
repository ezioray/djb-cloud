# SPDX-License-Identifier: Apache-2.0
"""M08 补充用例：审计钩子 / 时钟 / 取消 / 只查询 / 归集 / 签名视图 / 数据映射分支。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.treasury import audit, clock, config_source, errors, facts, models, order, payout
from app.treasury import provider as provider_mod
from app.treasury import signing, store, wallet

import m08kit

NOW = m08kit.FIXED_NOW


def test_audit_hook_emits_and_can_be_skipped():
    records: list[dict] = []
    record = audit.AuditRecord(action="payout_propose", object_type="payout_batch",
                               object_id="b1", actor="fin", reason="propose",
                               occurred_at=NOW, details={"amount_minor": 100})
    assert audit.emit(records.append, record) is True
    assert records[0]["producer"] == "M08" and records[0]["amount_minor"] == 100
    assert records[0]["occurred_at"].endswith("Z")
    assert audit.emit(None, record) is False


def test_clock_helpers_and_parse_errors():
    assert clock.as_utc(NOW) == NOW
    assert clock.as_utc(NOW.replace(tzinfo=None)).tzinfo is not None
    assert clock.iso(None) is None
    assert clock.iso(NOW).endswith("Z")
    assert clock.iso_micros(NOW).endswith("+00:00")
    assert clock.add_seconds(NOW, 60) == NOW + timedelta(seconds=60)
    assert clock.add_days(NOW, 1) == NOW + timedelta(days=1)
    day_start = clock.utc4_day_start(NOW + timedelta(hours=2))
    assert day_start.hour == 20 and day_start.day == 23      # UTC+4 的 00:00 = UTC 20:00
    assert clock.parse_datetime("2026-10-24T01:00:00Z") == NOW
    with pytest.raises(errors.BadRequest):
        clock.parse_datetime("not-a-time")
    with pytest.raises(errors.BadRequest):
        clock.parse_datetime("")


def test_cancel_order_and_requery_paths(savepoint_conn):
    from app.treasury import ledger

    cfg = config_source.load(None)
    registry = provider_mod.build_registry([provider_mod.MockProvider()])
    draft = models.parse_order({"amount_minor": 100, "currency": "USD", "method": "card"},
                               account_id="acct-c")
    created = order.create_order(savepoint_conn, draft, account_id="acct-c", tenant_id=None,
                                 idempotency_key=None, provider_registry=registry,
                                 config=cfg, ledger_poster=None, now=NOW, trace_id="t",
                                 created_by="acct-c")
    cancelled = order.cancel_order(savepoint_conn, created["order"]["order_no"],
                                   account_id="acct-c", reason="user", now=NOW)
    assert cancelled["status"] == "closed"
    with pytest.raises(errors.Conflict):
        order.cancel_order(savepoint_conn, created["order"]["order_no"],
                           account_id="acct-c", reason=None, now=NOW)
    with pytest.raises(errors.NotFound):
        order.cancel_order(savepoint_conn, "PO-NOPE", account_id="acct-c", reason=None, now=NOW)
    # 只查询：无通道单号 → 409；查询不可用 → 500
    draft2 = models.parse_order({"amount_minor": 100, "currency": "USD", "method": "card"},
                                account_id="acct-c")
    second = order.create_order(savepoint_conn, draft2, account_id="acct-c", tenant_id=None,
                                idempotency_key=None, provider_registry=registry,
                                config=cfg, ledger_poster=None, now=NOW, trace_id="t",
                                created_by="acct-c")
    with pytest.raises(errors.Conflict):
        order.requery(savepoint_conn, second["order"]["order_no"],
                      provider_registry=registry, ledger_poster=None, config=cfg, now=NOW)
    no_query = provider_mod.build_registry([provider_mod.MockProvider()])
    attempt = store.get_attempt_by_txn(savepoint_conn, "mock", "txn-x") or None
    store.update_attempt(savepoint_conn, str(second["attempt"]["attempt_id"]),
                         provider_txn_id="txn-query")
    with pytest.raises(errors.ServerError):
        order.requery(savepoint_conn, second["order"]["order_no"],
                      provider_registry=no_query, ledger_poster=None, config=cfg, now=NOW)


def test_requery_credits_after_query(savepoint_conn):
    registry = provider_mod.build_registry([
        provider_mod.MockProvider(scripted_status={"txn-requery": "1"})])
    adapter = m08kit.LedgerAdapter()
    cfg = config_source.load(None)
    draft = models.parse_order({"amount_minor": 100, "currency": "USD", "method": "card"},
                               account_id="acct-q")
    created = order.create_order(savepoint_conn, draft, account_id="acct-q", tenant_id=None,
                                 idempotency_key=None, provider_registry=registry,
                                 config=cfg, ledger_poster=adapter, now=NOW, trace_id="t",
                                 created_by="acct-q")
    store.update_attempt(savepoint_conn, str(created["attempt"]["attempt_id"]),
                         provider_txn_id="txn-requery")
    result = order.requery(savepoint_conn, created["order"]["order_no"],
                           provider_registry=registry, ledger_poster=adapter, config=cfg,
                           now=NOW)
    assert result["reason"] == "credited"
    assert result["order"]["status"] == "credited"


def test_wallet_sweep_plan_and_complete(savepoint_conn):
    # 无热钱包 → no_sweep_needed
    plan = wallet.sweep_plan(savepoint_conn, pool_id="polygon:hot:CLIENT",
                             config_provider=None, actor="fin", now=NOW)
    assert plan["reason"] == "no_sweep_needed"
    source = m08kit.make_wallet(savepoint_conn, balance_minor=90_000, gas_ok=True,
                                cap_minor=100_000)
    target = m08kit.make_wallet(savepoint_conn, pool_id="polygon:warm:customer")
    plan = wallet.sweep_plan(savepoint_conn, pool_id="polygon:hot:CLIENT",
                             config_provider=None, actor="fin", now=NOW)
    assert plan["batch_no"] and plan["transfers"]
    transfer = plan["transfers"][0]
    assert transfer["amount_minor"] == (90_000 - facts.DUST_MINOR) * facts.MICRO_PER_MINOR
    completed = wallet.complete_sweep(savepoint_conn, str(transfer["transfer_id"]),
                                      txid="0xsweep", actor="fin", now=NOW)
    assert completed["transfer"]["status"] == "confirmed"
    assert "sweep.completed" in [item["type"] for item in m08kit.outbox_events(savepoint_conn)]
    with pytest.raises(errors.Conflict):
        wallet.complete_sweep(savepoint_conn, str(transfer["transfer_id"]),
                              txid="0xsweep", actor="fin", now=NOW)
    with pytest.raises(errors.BadRequest):
        wallet.sweep_plan(savepoint_conn, pool_id="polygon:warm:CLIENT",
                          config_provider=None, actor="fin", now=NOW)
    with pytest.raises(errors.NotFound):
        wallet.complete_sweep(savepoint_conn, "00000000-0000-7000-8000-000000000000",
                              txid="0x", actor="fin", now=NOW)


def test_signing_view_and_require_signed(savepoint_conn):
    intent = store.insert_intent(
        savepoint_conn, intent_id="33333333-3333-7333-8333-333333333333", kind="PAYOUT",
        chain_id="polygon", asset="USDT", total_amount_minor=100, item_count=1,
        recipients_hash=None, status="signing", policy_version="v", memo_hash=None,
        created_by="fin", correlation_id="PB-1", idempotency_key=None,
        expires_at=NOW + timedelta(minutes=30), now=NOW)
    request = store.insert_signing_request(
        savepoint_conn, signing_request_id="44444444-4444-7444-8444-444444444444",
        intent_id=intent["intent_id"], kind="PAYOUT", status="pending",
        signer_set_ref="signers:test", threshold_n=2, signer_count_n=3, policy_version="v",
        requested_at=NOW, expires_at=NOW + timedelta(minutes=30), created_by="fin",
        idempotency_key=None, now=NOW)
    view = signing.signing_view(savepoint_conn, request["signing_request_id"])
    assert view["complete"] is False and view["signing_request"]["status"] == "pending"
    with pytest.raises(errors.Conflict):
        signing.require_signed(savepoint_conn, request["signing_request_id"])
    with pytest.raises(errors.NotFound):
        signing.signing_view(savepoint_conn, "55555555-5555-7555-8555-555555555555")
    _ = [models.intent_payload(intent), models.signing_request_payload(request, auth_hash="ab" * 32)]


def test_models_payload_branches(savepoint_conn):
    pool = store.get_pool(savepoint_conn, "polygon:hot:customer")
    wallet_row = m08kit.make_wallet(savepoint_conn)
    payload = models.pool_payload(pool, wallets=[wallet_row])
    assert payload["pool_id"] == "polygon:hot:CLIENT"
    assert payload["wallets"][0]["fund_class"] == "CLIENT"
    assert models.deposit_address_payload(None)["address"] == ""
    gas = models.gas_policy_payload(gas_mode="INTERNAL", gas_bearer="PLATFORM",
                                    scope="global", policy_version="v")
    assert gas["gas_bearer"] is None
    switch = models.switch_ack_payload(pool_id="polygon:hot:customer", status="triggered",
                                       from_wallet_id=None, to_wallet_id=None,
                                       switched_at=None, plan={"stop_collection": False})
    assert switch["pool_id"] == "polygon:hot:CLIENT"
    assert switch["pool_empty_plan"]["stop_collection"] is False
    address = m08kit.make_payout_address(savepoint_conn)
    assert models.address_payload(address)["chain"] == "polygon"
    batch = m08kit.insert_provision_batch(savepoint_conn)
    assert models.provision_batch_payload(batch)["pool_id"] == "polygon:hot:CLIENT"


def test_store_listing_helpers(savepoint_conn):
    m08kit.make_order(savepoint_conn, order_no="PO-LIST-1")
    m08kit.make_order(savepoint_conn, order_no="PO-LIST-2")
    rows, has_more, next_cursor = store.list_orders(savepoint_conn, account_id="acct-1", limit=1)
    assert len(rows) == 1 and has_more and next_cursor
    rows2, _, _ = store.list_orders(savepoint_conn, account_id="acct-1", limit=1,
                                    cursor=next_cursor)
    assert rows2 and rows2[0]["order_no"] != rows[0]["order_no"]
    assert store.list_orders(savepoint_conn, account_id="acct-1", status="bogus")[0] == []
    assert store.find_pool_by_key(savepoint_conn, "polygon", "hot", "customer") is not None
    assert store.find_payout_by_intent(savepoint_conn,
                                       "00000000-0000-7000-8000-000000000000") is None
    assert store.list_pools(savepoint_conn, role="warm")


def test_config_source_variants():
    assert config_source.pool_config_key("polygon:hot:CLIENT", "min_spare") == \
        "treasury.wallet_pool.polygon.hot.CLIENT.min_spare"
    with pytest.raises(ValueError):
        config_source.pool_config_key("polygon:hot", "min_spare")
    provider = config_source.MemoryConfigProvider({
        "treasury.wallet_pool.polygon.hot.CLIENT.min_spare": 5,
        "treasury.wallet_pool.polygon.hot.CLIENT.max_active": 99,
        "payment.webhook_skew_s": 120,
        "billing.gas_fee_mode": "EXTERNAL",
        "billing.gas_fee_bearer": "PAYER",
    })
    config = config_source.load(provider, role="hot", fund_class="CLIENT")
    assert config.min_spare == 5
    assert config.max_active == facts.MAX_ACTIVE_HOT       # 越界退默认
    assert config.webhook_skew_s == 120
    assert config.gas_mode == facts.GAS_MODE_EXTERNAL_PAYER
    assert config.source in ("m10", "invalid")
    legacy = config_source.MemoryConfigProvider({"treasury.gas_fee_mode": "EXTERNAL"})
    assert config_source.load(legacy).gas_mode == facts.GAS_MODE_EXTERNAL_PLATFORM
    bad = config_source.MemoryConfigProvider({"payment.refund_window_days": 999})
    assert config_source.load(bad).refund_window_days == facts.REFUND_WINDOW_DAYS
