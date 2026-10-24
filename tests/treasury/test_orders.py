# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08a 支付订单 / 回调 / E3-E4 记账（HTTP + 域内）。"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.treasury import clock, config_source, errors, facts, ledger, models, order, policy
from app.treasury import provider as provider_mod

import m08kit
from m08kit import OTHER_USER_PRINCIPAL, build_client

NOW = m08kit.FIXED_NOW


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def poster():
    return m08kit.LedgerAdapter()


def _rows(conn, sql, params=()):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def test_create_order_and_detail(client, savepoint_conn):
    response = client.post("/api/v1/pay/orders", json={
        "amount_minor": 12_345, "currency": "usd", "method": "card"})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "created" and body["currency"] == "USD"
    assert response.headers.get("X-Request-Id")
    detail = client.get(f"/api/v1/pay/orders/{body['order_no']}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["order"]["order_no"] == body["order_no"]
    assert payload["attempts"][0]["status"] == "initiated"
    # 跨账户 → 404（不泄露存在性）
    with build_client(savepoint_conn, user=OTHER_USER_PRINCIPAL) as other:
        assert other.get(f"/api/v1/pay/orders/{body['order_no']}").status_code == 404


def test_create_order_validation_and_channel_guards(client):
    cases = [
        ({"amount_minor": 100, "currency": "USD", "method": "crypto"}, 400),
        ({"amount_minor": 100.5, "currency": "USD", "method": "card"}, 400),
        ({"amount_minor": 0, "currency": "USD", "method": "card"}, 400),
        ({"amount_minor": 100, "currency": "CHF", "method": "card"}, 400),
        ({"amount_minor": 100, "currency": "USD", "method": "card", "extra": 1}, 400),
        ({"amount_minor": 100, "currency": "USD", "method": "card", "provider": "upg"}, 500),   # 未注入 KMS → fail-closed
        ({"amount_minor": 100, "currency": "USD", "method": "card", "provider": "gifpay"}, 403),
    ]
    for body, status in cases:
        response = client.post("/api/v1/pay/orders", json=body)
        assert response.status_code == status, (body, response.text)
    assert client.post("/api/v1/pay/orders", json={
        "amount_minor": 100, "currency": "USD", "method": "card"},
        headers={"X-DJB-Idempotency-Key": "short"}).status_code == 400
    # 通道未开启：未注册 provider → 40310
    response = client.post("/api/v1/pay/orders", json={
        "amount_minor": 100, "currency": "USD", "method": "card", "provider": "gifpay"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 40310


def test_order_idempotency_replay_and_conflict(client):
    headers = {"X-DJB-Idempotency-Key": "idem-order-00000001"}
    body = {"amount_minor": 500, "currency": "USD", "method": "card"}
    first = client.post("/api/v1/pay/orders", json=body, headers=headers)
    assert first.status_code == 201
    replay = client.post("/api/v1/pay/orders", json=body, headers=headers)
    assert replay.status_code == 201
    assert replay.json()["order_no"] == first.json()["order_no"]
    conflict = client.post("/api/v1/pay/orders", headers=headers,
                           json={**body, "amount_minor": 501})
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == 40919


def test_webhook_credits_once_and_e3_is_posted(client, savepoint_conn, poster):
    created = client.post("/api/v1/pay/orders", json={
        "amount_minor": 10_000, "currency": "USD", "method": "card"}).json()
    row = {"order_no": created["order_no"], "amount_minor": 10_000, "currency": "USD"}
    raw = m08kit.webhook_body(row, provider_txn_id="txn-e3")
    from m08kit import savepoint_factory
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.treasury.router import create_router

    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(savepoint_conn),
        user_resolver=lambda request: {"account_id": "acct-1"},
        admin_resolver=lambda request: {"admin_id": "a", "scopes": ["*"]},
        step_up_verifier=lambda request: True,
        now_provider=lambda: NOW,
        ledger_poster=poster,
    ))
    with TestClient(app) as webhook_client:
        first = webhook_client.post("/api/v1/pay/webhooks/mock", content=raw,
                                    headers={"Content-Type": "application/json"})
        assert first.status_code == 200, first.text
        assert first.json()["received"] is True and first.json()["duplicate"] is False
        duplicate = webhook_client.post("/api/v1/pay/webhooks/mock", content=raw,
                                        headers={"Content-Type": "application/json"})
        assert duplicate.status_code == 409
        assert duplicate.json()["error"]["code"] == 40910
    detail = client.get(f"/api/v1/pay/orders/{created['order_no']}").json()
    assert detail["order"]["status"] == "credited"
    assert detail["order"]["credited_minor"] == 10_000
    assert detail["attempts"][0]["signature_verified"] is True
    journals = _rows(savepoint_conn,
                     "SELECT event_type, source_id, event_seq FROM journal_entry"
                     " WHERE source_id = %s ORDER BY seq", ("txn-e3",))
    assert journals == [("E3", "txn-e3", 1)]
    lines = _rows(savepoint_conn,
                  "SELECT coa_code, dc, amount_minor FROM journal_line l"
                  " JOIN journal_entry j ON j.journal_id = l.journal_id"
                  " WHERE j.source_id = %s ORDER BY l.line_no", ("txn-e3",))
    assert lines == [("1120", "D", 100_000_000), ("2101", "C", 100_000_000)]
    events = [item["type"] for item in m08kit.outbox_events(savepoint_conn)]
    assert "payment.created" in events and "payment.paid" in events


def test_webhook_rejects_bad_signature_and_amount(client, savepoint_conn):
    created = client.post("/api/v1/pay/orders", json={
        "amount_minor": 10_000, "currency": "USD", "method": "card"}).json()
    row = {"order_no": created["order_no"], "amount_minor": 10_000, "currency": "USD"}
    tampered = json.loads(m08kit.webhook_body(row, provider_txn_id="txn-bad").decode())
    tampered["amount"] = 1
    raw = json.dumps(tampered).encode()
    response = client.post("/api/v1/pay/webhooks/mock", content=raw,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001
    bad_amount = json.loads(m08kit.webhook_body(row, provider_txn_id="txn-mismatch",
                                                amount_minor=9_999).decode())
    response = client.post("/api/v1/pay/webhooks/mock", content=json.dumps(bad_amount).encode(),
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40911
    stale = json.loads(m08kit.webhook_body(
        row, provider_txn_id="txn-stale",
        timestamp=int(NOW.timestamp()) - 400).decode())
    response = client.post("/api/v1/pay/webhooks/mock", content=json.dumps(stale).encode(),
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 400 and response.json()["error"]["code"] == 40001
    response = client.post("/api/v1/pay/webhooks/unknown", content=b"{}",
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 400


def test_webhook_unknown_order_and_pending(client):
    raw = m08kit.webhook_body({"order_no": "PO-404404", "amount_minor": 100,
                               "currency": "USD"}, provider_txn_id="txn-404")
    response = client.post("/api/v1/pay/webhooks/mock", content=raw,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 404 and response.json()["error"]["code"] == 40401
    created = client.post("/api/v1/pay/orders", json={
        "amount_minor": 100, "currency": "USD", "method": "card"}).json()
    raw = m08kit.webhook_body(created, provider_txn_id="txn-pending", status="0")
    response = client.post("/api/v1/pay/webhooks/mock", content=raw,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 200
    assert response.json()["status"] == "pending"
    detail = client.get(f"/api/v1/pay/orders/{created['order_no']}").json()
    assert detail["order"]["status"] == "pending"


def test_webhook_failed_and_query_conflict(client, savepoint_conn):
    created = client.post("/api/v1/pay/orders", json={
        "amount_minor": 100, "currency": "USD", "method": "card"}).json()
    raw = m08kit.webhook_body(created, provider_txn_id="txn-fail", status="2")
    response = client.post("/api/v1/pay/webhooks/mock", content=raw,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 200 and response.json()["status"] == "failed"
    # 查询与回调冲突：以查询为准（不猜成功）
    registry = provider_mod.build_registry([
        provider_mod.MockProvider(scripted_status={"txn-conflict": "2"}),
    ])
    draft = models.parse_order({"amount_minor": 100, "currency": "USD", "method": "card"},
                               account_id="acct-conflict")
    result = order.create_order(
        savepoint_conn, draft, account_id="acct-conflict", tenant_id=None,
        idempotency_key=None, provider_registry=registry,
        config=config_source.load(None), ledger_poster=None, now=NOW, trace_id="t",
        created_by="acct-conflict")
    raw = m08kit.webhook_body(result["order"], provider_txn_id="txn-conflict")
    outcome = order.handle_webhook(
        savepoint_conn, provider_name="mock", raw_body=raw, headers={},
        provider_registry=registry, config=config_source.load(None), ledger_poster=None,
        now=NOW, trace_id="t2")
    assert outcome["reason"] == "query_conflict"
    assert outcome["order"]["status"] == "created"


def test_settlement_e4_two_steps_and_idempotent(poster, savepoint_conn):
    paid = m08kit.make_paid_order(savepoint_conn, order_no="PO-E4-1",
                                  provider_txn_id="txn-e4")
    cfg = config_source.load(None)
    result = order.settle_attempt(
        savepoint_conn, identifier="PO-E4-1", provider_txn_id="txn-e4",
        settled_minor=9_900, fee_minor=100, provider_registry=provider_mod.build_registry(),
        ledger_poster=poster, config=cfg, now=NOW, trace_id="t")
    assert len(result["journal_ids"]) == 2
    steps = _rows(savepoint_conn,
                  "SELECT event_seq, count(*) FROM journal_entry WHERE source_id = %s"
                  " GROUP BY event_seq ORDER BY event_seq", ("txn-e4",))
    assert steps == [(2, 1), (3, 1)]
    # 同载荷重放：M06 幂等，不新增凭证
    again = order.settle_attempt(
        savepoint_conn, identifier="PO-E4-1", provider_txn_id="txn-e4",
        settled_minor=9_900, fee_minor=100, provider_registry=provider_mod.build_registry(),
        ledger_poster=poster, config=cfg, now=NOW, trace_id="t")
    assert again["journal_ids"] == result["journal_ids"]
    with pytest.raises(errors.BadRequest):
        order.settle_attempt(
            savepoint_conn, identifier="PO-E4-1", provider_txn_id="txn-e4",
            settled_minor=9_000, fee_minor=500,   # 净额 + 手续费 ≠ 订单金额（容差 0）
            provider_registry=provider_mod.build_registry(), ledger_poster=poster,
            config=cfg, now=NOW, trace_id="t")
    with pytest.raises(errors.NotFound):
        order.settle_attempt(
            savepoint_conn, identifier="PO-E4-1", provider_txn_id="txn-missing",
            settled_minor=1, fee_minor=0, provider_registry=provider_mod.build_registry(),
            ledger_poster=poster, config=cfg, now=NOW, trace_id="t")


def test_ledger_poster_missing_fails_closed(client):
    created = client.post("/api/v1/pay/orders", json={
        "amount_minor": 100, "currency": "USD", "method": "card"}).json()
    raw = m08kit.webhook_body(created, provider_txn_id="txn-noledger")
    response = client.post("/api/v1/pay/webhooks/mock", content=raw,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 500
    assert response.json()["error"]["code"] == 45001
    detail = client.get(f"/api/v1/pay/orders/{created['order_no']}").json()
    assert detail["order"]["status"] in ("created", "pending")     # 未入账
