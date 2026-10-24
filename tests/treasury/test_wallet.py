# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08b 钱包池：预生成 / 激活 / 切换 / 退休 / 平台收款地址（HTTP + 域内）。"""
from __future__ import annotations

import json

import pytest

from app.treasury import config_source, errors, facts, models, signing, store, wallet

import m08kit
from m08kit import READONLY_PRINCIPAL, build_client

NOW = m08kit.FIXED_NOW


@pytest.fixture
def now():
    return NOW


def _sign_all(conn, signing_request_id, *, start=0):
    steps = (
        models.SigningEventDraft(event="presented", signer_type="owner"),
        models.SigningEventDraft(event="signed", signer_type="owner", signature_hash="a" * 64),
        models.SigningEventDraft(event="verified", signer_type="company"),
        models.SigningEventDraft(event="co_signed", signer_type="reviewer",
                                 signature_hash="b" * 64),
    )
    out = None
    for item in steps[start:]:
        out = signing.record_event(conn, signing_request_id, item, now=NOW)
    return out


def test_list_pools_shape(client):
    response = client.get("/api/v1/admin/treasury/pools")
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    pools = {item["pool_id"]: item for item in data}
    assert "polygon:hot:CLIENT" in pools
    hot = pools["polygon:hot:CLIENT"]
    assert hot["fund_class"] == "CLIENT" and hot["role"] == "hot"
    assert hot["max_active"] == 8 and hot["min_spare"] == 3
    assert hot["pool_cap_minor"] == facts.POOL_CAP_MINOR
    assert hot["depth_ready"] == 0 and "wallets" in hot
    filtered = client.get("/api/v1/admin/treasury/pools?role=warm&status=active")
    assert all(item["role"] == "warm" for item in filtered.json()["data"])
    assert client.get("/api/v1/admin/treasury/pools?status=bogus").status_code == 400


def test_create_pool_idempotent_and_validation(client):
    body = {"chain": "polygon", "role": "hot", "fund_class": "CLIENT",
            "reason": "一期已建"}
    response = client.post("/api/v1/admin/treasury/pools", json=body)
    assert response.status_code == 201, response.text
    assert response.json()["pool_id"] == "polygon:hot:CLIENT"
    again = client.post("/api/v1/admin/treasury/pools", json=body)
    assert again.status_code == 201
    assert client.post("/api/v1/admin/treasury/pools", json={
        "chain": "tron", "role": "hot", "fund_class": "CLIENT"}).status_code == 409
    assert client.post("/api/v1/admin/treasury/pools", json={
        "chain": "polygon", "role": "hot", "fund_class": "PLATFORM"}).status_code == 400
    assert client.post("/api/v1/admin/treasury/pools", json={
        "chain": "polygon", "role": "warm", "fund_class": "CLIENT",
        "max_active": 0}).status_code == 400
    assert client.post("/api/v1/admin/treasury/pools", json={
        "chain": "polygon", "role": "warm", "fund_class": "CLIENT",
        "pool_cap_minor": 10}).status_code == 400


def test_provision_requires_step_up_and_scopes(savepoint_conn):
    with build_client(savepoint_conn, step_up=False) as client:
        response = client.post("/api/v1/admin/treasury/provision", json={
            "pool_id": "polygon:hot:CLIENT", "wallet_count": 2})
        assert response.status_code == 424
        assert response.json()["error"]["code"] == 42401
    with build_client(savepoint_conn, admin=READONLY_PRINCIPAL) as client:
        response = client.post("/api/v1/admin/treasury/provision", json={
            "pool_id": "polygon:hot:CLIENT", "wallet_count": 2})
        assert response.status_code == 403


def test_provision_activate_switch_retire_flow(client, savepoint_conn):
    provision = client.post("/api/v1/admin/treasury/provision", json={
        "pool_id": "polygon:hot:CLIENT", "wallet_count": 2})
    assert provision.status_code == 201, provision.text
    batch = provision.json()
    assert batch["status"] == "draft" and batch["wallet_count"] == 2
    assert batch["descriptor_merkle_root"] and batch["pool_id"] == "polygon:hot:CLIENT"
    # INV-02：批次内不含转账指令
    row = store.get_provision_batch(savepoint_conn, batch["batch_id"])
    cap_params = dict(row["cap_params"])
    for descriptor in cap_params["descriptors"]:
        assert set(descriptor) == {"wallet_id", "address", "role", "fund_class",
                                   "chain_id", "signer_set_ref", "threshold"}
    assert row["contains_transfer"] is False
    # 未绑定签名请求 → 409
    response = client.post(f"/api/v1/admin/treasury/activate/{batch['batch_id']}", json={})
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "signature_missing"
    # 域内发起签名 + 六事件（签名域调用，不在 HTTP 面）
    sig = wallet.request_provision_signature(savepoint_conn, batch["batch_id"], actor="fin",
                                             now=NOW)
    signing_request_id = str(sig["signing_request"]["signing_request_id"])
    _sign_all(savepoint_conn, signing_request_id)
    activated = client.post(f"/api/v1/admin/treasury/activate/{batch['batch_id']}",
                            json={"signing_request_id": signing_request_id})
    assert activated.status_code == 200, activated.text
    assert activated.json()["status"] == "activated"
    wallets = store.list_wallets(savepoint_conn, "polygon:hot:customer")
    assert len(wallets) == 2 and all(item["status"] == "active" for item in wallets)
    states = {item["switch_state"] for item in wallets}
    assert states == {"in_service", "standby"}
    # 激活 ≠ 可用：gas 未到位前 ready=False；切换前先给两只热钱包补 gas（INV-03）
    for item in wallets:
        savepoint_conn.execute("UPDATE wallet SET gas_ok = TRUE WHERE wallet_id = %s",
                               (item["wallet_id"],))
    # 重复激活 → 409
    again = client.post(f"/api/v1/admin/treasury/activate/{batch['batch_id']}", json={})
    assert again.status_code == 409
    # 切换：切到另一只
    switched = client.post("/api/v1/admin/treasury/switch", json={
        "pool_id": "polygon:hot:CLIENT", "reason": "manual"})
    assert switched.status_code == 200, switched.text
    ack = switched.json()
    assert ack["status"] == "done" and ack["from_wallet_id"] and ack["to_wallet_id"]
    # 切换理由必填
    assert client.post("/api/v1/admin/treasury/switch", json={
        "pool_id": "polygon:hot:CLIENT"}).status_code == 400
    # 退休四步
    wallet_id = ack["from_wallet_id"]
    assert client.post("/api/v1/admin/treasury/retire", json={
        "wallet_id": wallet_id, "step": "zero"}).status_code == 409
    assert client.post("/api/v1/admin/treasury/retire", json={
        "wallet_id": wallet_id, "step": "drain"}).status_code == 200
    # 切地址未满 24h → zero 被拒
    assert client.post("/api/v1/admin/treasury/retire", json={
        "wallet_id": wallet_id, "step": "zero"}).status_code == 409


def test_retire_requires_attestation(savepoint_conn):
    from m08kit import savepoint_factory
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.treasury.router import create_router

    wallet_row = m08kit.make_wallet(savepoint_conn, status="frozen", switch_state="draining")
    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(savepoint_conn),
        admin_resolver=lambda request: {"admin_id": "auditor", "scopes": ["*"]},
        step_up_verifier=lambda request: True,
        now_provider=lambda: NOW,
        attestation_verifier=lambda ref: ref == "att-good",
    ))
    with TestClient(app, headers={"X-Admin-Step-Up": "test"}) as client:
        missing = client.post("/api/v1/admin/treasury/retire", json={
            "wallet_id": wallet_row["wallet_id"], "step": "retire"})
        assert missing.status_code == 409
        assert missing.json()["error"]["code"] == 40916
        ok = client.post("/api/v1/admin/treasury/retire", json={
            "wallet_id": wallet_row["wallet_id"], "step": "retire",
            "attestation_ref": "att-good"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["status"] == "retired"
        assert ok.json()["retired_at"]


def test_pool_empty_switch_does_not_stop_collection(client):
    created = client.post("/api/v1/admin/treasury/pools", json={
        "chain": "polygon", "role": "warm", "fund_class": "PLATFORM"}).json()
    response = client.post("/api/v1/admin/treasury/switch", json={
        "pool_id": "polygon:warm:PLATFORM", "reason": "empty"})
    assert response.status_code == 200
    ack = response.json()
    assert ack["status"] == "triggered" and ack["to_wallet_id"] is None
    assert ack["pool_empty_plan"]["stop_collection"] is False


def test_provision_max_active_and_pool_paused(savepoint_conn):
    pool = store.get_pool(savepoint_conn, "polygon:hot:customer")
    for _ in range(int(pool["max_active_count"]) // facts.ACTIVATE_BATCH_SIZE):
        wallet.provision(savepoint_conn, models.ProvisionDraft(
            pool_id="polygon:hot:CLIENT", wallet_count=facts.ACTIVATE_BATCH_SIZE),
            actor="fin", idempotency_key=None, config_provider=None, allocator=None, now=NOW)
    with pytest.raises(errors.Conflict):
        wallet.provision(savepoint_conn, models.ProvisionDraft(
            pool_id="polygon:hot:CLIENT", wallet_count=1), actor="fin",
            idempotency_key=None, config_provider=None, allocator=None, now=NOW)
    with savepoint_conn.transaction():
        savepoint_conn.execute("UPDATE wallet_pool SET status = 'paused'"
                               " WHERE pool_id = 'polygon:warm:customer'")
    with pytest.raises(errors.Conflict):
        wallet.provision(savepoint_conn, models.ProvisionDraft(
            pool_id="polygon:warm:CLIENT", wallet_count=1), actor="fin",
            idempotency_key=None, config_provider=None, allocator=None, now=NOW)


def test_provision_expired_batch(savepoint_conn):
    from datetime import timedelta

    batch = m08kit.insert_provision_batch(
        savepoint_conn, expires_at=NOW - timedelta(hours=1))
    with pytest.raises(errors.ProvisionBatchExpired):
        wallet.request_provision_signature(savepoint_conn, batch["batch_id"], actor="fin",
                                           now=NOW)
    assert store.get_provision_batch(savepoint_conn, batch["batch_id"])["status"] == "expired"


def test_provision_idempotency_and_address_conflict(savepoint_conn):
    first = wallet.provision(savepoint_conn, models.ProvisionDraft(
        pool_id="polygon:hot:CLIENT", wallet_count=2), actor="fin",
        idempotency_key="idem-provision-0001", config_provider=None, allocator=None, now=NOW)
    replay = wallet.provision(savepoint_conn, models.ProvisionDraft(
        pool_id="polygon:hot:CLIENT", wallet_count=2), actor="fin",
        idempotency_key="idem-provision-0001", config_provider=None, allocator=None, now=NOW)
    assert replay["replayed"] is True
    assert replay["batch"]["batch_id"] == first["batch"]["batch_id"]
    # 地址冲突：预先占用一个批次地址
    existing = m08kit.make_wallet(savepoint_conn, address="0x" + "d" * 40)
    from app.treasury.wallet import AddressAllocator

    class FixedAllocator(AddressAllocator):
        synthetic = True

        def allocate(self, *, pool_id, count, start_index):
            return ["0x" + "d" * 40] + ["0x" + "e" * 40] * (count - 1)

    with pytest.raises(errors.AddressConflict):
        wallet.provision(savepoint_conn, models.ProvisionDraft(
            pool_id="polygon:hot:CLIENT", wallet_count=2), actor="fin",
            idempotency_key=None, config_provider=None, allocator=FixedAllocator(), now=NOW)


def test_deposit_address_publish_and_cooldown(client, savepoint_conn):
    empty = client.get("/api/v1/admin/treasury/deposit-address")
    assert empty.status_code == 200
    assert empty.json()["address"] == ""
    first = client.post("/api/v1/admin/treasury/deposit-address", json={
        "chain": "polygon", "address": "0x" + "1" * 40, "reason": "initial",
        "ticket": "TCK-1"})
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "active" and first.json()["chain"] == "polygon"
    cooldown = client.post("/api/v1/admin/treasury/deposit-address", json={
        "chain": "polygon", "address": "0x" + "2" * 40, "reason": "rotate",
        "ticket": "TCK-2"})
    assert cooldown.status_code == 409
    assert cooldown.json()["error"]["reason"] == "address_cooldown"
    assert client.get("/api/v1/admin/treasury/deposit-address?chain=tron").status_code == 409
    assert client.post("/api/v1/admin/treasury/deposit-address", json={
        "chain": "polygon", "address": "0x" + "3" * 40}).status_code == 400
