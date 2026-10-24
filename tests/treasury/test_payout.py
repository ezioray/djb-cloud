# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08c 分润出款 / 白名单 / gas 三模式（HTTP + 域内）。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.treasury import config_source, errors, facts, models, payout, signing, store

import m08kit
from m08kit import ADMIN_PRINCIPAL, build_client, savepoint_factory

NOW = m08kit.FIXED_NOW
ADDR_A = "0x" + "a1" * 20
ADDR_B = "0x" + "b2" * 20


def _payout_payload(address=ADDR_A, *, gross=5_000, fee=100, attestation="att-1",
                    account_id="acct-1"):
    return {"items": [{"payee_account_id": account_id, "payee_address": address,
                       "gross_minor": gross, "fee_minor": fee}],
            "attestation_ref": attestation}


def _sign_all(conn, signing_request_id):
    steps = (
        models.SigningEventDraft(event="presented", signer_type="owner"),
        models.SigningEventDraft(event="signed", signer_type="owner", signature_hash="a" * 64),
        models.SigningEventDraft(event="verified", signer_type="company"),
        models.SigningEventDraft(event="co_signed", signer_type="reviewer",
                                 signature_hash="b" * 64),
    )
    out = None
    for item in steps:
        out = signing.record_event(conn, signing_request_id, item, now=NOW)
    return out


def test_create_payout_batch_requires_whitelist(client, savepoint_conn):
    # 未提交地址 → 42210
    response = client.post("/api/v1/admin/treasury/payouts", json=_payout_payload())
    assert response.status_code == 422
    assert response.json()["error"]["code"] == 42210
    m08kit.make_payout_address(savepoint_conn, address=ADDR_A)
    response = client.post("/api/v1/admin/treasury/payouts", json=_payout_payload())
    assert response.status_code == 201, response.text
    batch = response.json()
    assert batch["status"] == "prepared" and batch["item_count"] == 1
    assert batch["total_net_minor"] == 4_900 and batch["gas_mode"] == "INTERNAL"
    assert batch["items"][0]["net_minor"] == 4_900
    assert batch["attestation_ref"] == "att-1"


def test_carried_item_and_first_transfer_limit(client, savepoint_conn):
    m08kit.make_payout_address(savepoint_conn, address=ADDR_A)
    payload = _payout_payload(gross=5, fee=10)
    response = client.post("/api/v1/admin/treasury/payouts", json=payload)
    assert response.status_code == 201
    body = response.json()
    assert body["items"][0]["status"] == "carried"
    assert body["item_count"] == 0 and body["total_net_minor"] == 0
    # 首笔 >100 USDT → 42210
    m08kit.make_payout_address(savepoint_conn, address=ADDR_B)
    response = client.post("/api/v1/admin/treasury/payouts", json=_payout_payload(
        address=ADDR_B, gross=10_001, fee=0))
    assert response.status_code == 422
    assert response.json()["error"]["reason"] == "first_transfer_limit"


def test_approve_requires_attestation_and_separation(client, savepoint_conn):
    m08kit.make_payout_address(savepoint_conn, address=ADDR_A)
    created = client.post("/api/v1/admin/treasury/payouts", json=_payout_payload(
        attestation=None)).json()
    # 复核人 ≠ 制单人（否则先命中 SoD 40919）；缺 attestation → 40916
    with build_client(savepoint_conn,
                      admin={"admin_id": "auditor-2", "scopes": ["*"]}) as checker:
        missing = checker.post(
            f"/api/v1/admin/treasury/payouts/{created['batch_no']}/approve", json={})
    assert missing.status_code == 409
    assert missing.json()["error"]["code"] == 40916
    created2 = client.post("/api/v1/admin/treasury/payouts", json=_payout_payload()).json()
    with build_client(savepoint_conn, admin=ADMIN_PRINCIPAL) as same:
        # 复核人 = 制单人 → 409
        conflict = same.post(
            f"/api/v1/admin/treasury/payouts/{created2['batch_no']}/approve", json={})
        assert conflict.status_code == 409
        assert conflict.json()["error"]["reason"] == "separation_of_duty"
    with build_client(savepoint_conn,
                      admin={"admin_id": "auditor-2", "scopes": ["*"]},
                      attestation_verifier=lambda ref: ref == "att-1") as checker:
        approved = checker.post(
            f"/api/v1/admin/treasury/payouts/{created2['batch_no']}/approve",
            json={"note": "对账已平"})
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "checked"
        assert approved.json()["checker_id"] == "auditor-2"


def test_sign_request_six_events_broadcast_settle(client, savepoint_conn):
    m08kit.make_payout_address(savepoint_conn, address=ADDR_A)
    created = client.post("/api/v1/admin/treasury/payouts", json=_payout_payload()).json()
    with build_client(savepoint_conn,
                      admin={"admin_id": "auditor-2", "scopes": ["*"]},
                      attestation_verifier=lambda ref: ref == "att-1") as checker:
        checker.post(f"/api/v1/admin/treasury/payouts/{created['batch_no']}/approve",
                     json={})
        sign_response = checker.post(
            f"/api/v1/admin/treasury/payouts/{created['batch_no']}/sign-request", json={})
        assert sign_response.status_code == 201, sign_response.text
        signing_request = sign_response.json()
        assert signing_request["status"] == "pending"
        assert signing_request["signer_threshold"] == 2
        expires = signing_request["expires_at"]
        assert expires and signing_request["intent_id"]
    sid = signing_request["signing_request_id"]
    advanced = _sign_all(savepoint_conn, sid)["advanced"]
    assert advanced["owner_type"] == "payout_batch" and advanced["status"] == "signed"
    result = payout.broadcast_payout_batch(savepoint_conn, created["batch_id"],
                                           txid="0xdest", actor="auditor-3", now=NOW)
    assert result["batch"]["status"] == "broadcast"
    settled = payout.settle_payout_batch(savepoint_conn, created["batch_id"],
                                         txid="0xtx", actor="auditor-3", now=NOW)
    assert settled["batch"]["status"] == "settled"
    events = [item["type"] for item in m08kit.outbox_events(savepoint_conn)]
    assert "payout.paid" in events
    address = store.get_payout_address(savepoint_conn, ADDR_A)
    assert address["first_transfer_at"] is not None


def test_approval_window_expiry(savepoint_conn):
    m08kit.make_payout_address(savepoint_conn, address=ADDR_A)
    created = payout.create_payout_batch(
        savepoint_conn, models.PayoutBatchDraft(
            items=(models.PayoutItemDraft(payee_account_id="acct-1", payee_address=ADDR_A,
                                          gross_minor=5_000, fee_minor=0),),
            attestation_ref="att-1"), maker="fin", idempotency_key=None,
        config_provider=None, now=NOW)
    payout.approve_payout_batch(savepoint_conn, created["batch"]["batch_id"], checker="fin2",
                                attestation_checker=lambda ref: True,
                                revenue_verifier=None, now=NOW)
    with pytest.raises(errors.Conflict):
        payout.request_payout_signature(
            savepoint_conn, created["batch"]["batch_id"], actor="fin3",
            now=NOW + timedelta(minutes=45))


def test_provider_payouts_and_address(client, savepoint_conn):
    address = m08kit.make_payout_address(savepoint_conn, address=ADDR_A)
    created = client.post("/api/v1/admin/treasury/payouts", json=_payout_payload()).json()
    listed = client.get("/api/v1/provider/payouts")
    assert listed.status_code == 200
    page = listed.json()
    assert page["page"]["has_more"] is False
    assert any(item["batch_no"] == created["batch_no"] for item in page["data"])
    assert listed.json()["data"][0]["items"][0]["payee_address"] == ADDR_A
    assert "maker_id" not in listed.json()["data"][0]
    assert client.get("/api/v1/provider/payouts?status=bogus").status_code == 400
    submitted = client.post("/api/v1/provider/payout-address", json={
        "chain": "polygon", "address": ADDR_B, "ownership_challenge_ref": "ch-2",
        "label": "vendor-b"})
    assert submitted.status_code == 200, submitted.text
    body = submitted.json()
    assert body["status"] == "pending" and body["label"] == "vendor-b"
    assert body["cooldown_until"]
    with build_client(savepoint_conn, step_up=False) as no_step:
        assert no_step.post("/api/v1/provider/payout-address", json={
            "chain": "polygon", "address": ADDR_B,
            "ownership_challenge_ref": "ch"}).status_code == 424
    high_risk = client.post("/api/v1/provider/payout-address", json={
        "chain": "polygon", "address": "0x" + "f" * 40,
        "ownership_challenge_ref": "ch", "risk_level": "high"})
    assert high_risk.status_code == 422
    assert high_risk.json()["error"]["code"] == 42211


def test_admin_upsert_address_requires_pending(client, savepoint_conn):
    unknown = client.post("/api/v1/admin/treasury/addresses", json={
        "chain": "polygon", "address": "0x" + "9" * 40,
        "ownership_challenge_ref": "ch"})
    assert unknown.status_code == 422
    assert unknown.json()["error"]["code"] == 42210
    m08kit.make_payout_address(savepoint_conn, address=ADDR_A, status="pending")
    approved = client.post("/api/v1/admin/treasury/addresses", json={
        "chain": "polygon", "address": ADDR_A, "ownership_challenge_ref": "ch"})
    assert approved.status_code == 201, approved.text
    assert approved.json()["status"] == "whitelisted"
    assert client.get("/api/v1/admin/treasury/addresses?chain=polygon").status_code == 200
    assert client.get("/api/v1/admin/treasury/addresses?status=bogus").status_code == 400


def test_gas_policy_view_and_update(client, savepoint_conn):
    view = client.get("/api/v1/admin/treasury/gas-policy")
    assert view.status_code == 200, view.text
    body = view.json()
    assert body["gas_mode"] == "INTERNAL" and body["gas_bearer"] is None
    assert body["policy_version"]
    updated = client.post("/api/v1/admin/treasury/gas-policy", json={
        "gas_mode": "EXTERNAL_PLATFORM", "gas_bearer": "PLATFORM", "scope": "global",
        "reason": "外扣-平台承担"})
    assert updated.status_code == 200, updated.text
    policy = updated.json()
    assert policy["gas_mode"] == "INTERNAL"      # 只 propose：生效值仍是当前配置
    assert policy["pending_change"]["gas_mode"] == "EXTERNAL_PLATFORM"
    assert policy["pending_change"]["takes_effect"] == "next_batch"
    assert client.post("/api/v1/admin/treasury/gas-policy", json={
        "gas_mode": "EXTERNAL_PLATFORM"}).status_code == 400
    assert client.post("/api/v1/admin/treasury/gas-policy", json={
        "gas_mode": "INTERNAL", "gas_bearer": "PLATFORM"}).status_code == 400
    # 批次按快照：gas_mode 由批次创建时决定，不受后续提案影响
    m08kit.make_payout_address(savepoint_conn, address=ADDR_A)
    created = client.post("/api/v1/admin/treasury/payouts", json=_payout_payload()).json()
    assert created["gas_mode"] == "INTERNAL"
