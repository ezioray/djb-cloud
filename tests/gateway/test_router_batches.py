# SPDX-License-Identifier: Apache-2.0
"""批次 HTTP 层（T4 / spec `BatchAccepted` / `Batch` / `BatchCancelAck`）：状态码、幂等、信封。"""
from __future__ import annotations

import uuid

import pytest

from app.gateway import config_source, facts, features, providers
from gatewaykit import FakeAuth, FakeCatalog, FakeNode, FakeRoute, FakeSigner, FakeStream, \
    FakeUsage, FakeWebhookSender


@pytest.fixture(scope="module")
def batch_api_schema(db, schema_prefix) -> str:         # noqa: ARG001
    from gatewaykit import apply_migrations, create_schema, drop_schema

    name = f"{schema_prefix}_bapi_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def client(batch_api_schema: str):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.gateway import router as router_module
    from gatewaykit import connect

    app = FastAPI()
    app.include_router(router_module.router)

    def _connection():
        return connect(batch_api_schema, autocommit=False)

    original = router_module._connection
    router_module._connection = _connection
    router_module.set_client_ip_resolver(None)
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute(price_minor=250, eta_seconds=30))
    providers.set_node_client(FakeNode())
    providers.set_stream_client(FakeStream())
    providers.set_usage_provider(FakeUsage())
    providers.set_model_catalog_provider(FakeCatalog())
    providers.set_result_signer(FakeSigner())
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        router_module._connection = original


def _auth():
    return {facts.AUTH_HEADER: "Bearer djb_live_abcdefgh"}


def _body(items: int = 2, **overrides):
    body = {"kind": "chat", "model": "m1",
            "items": [{"custom_id": f"c{index}", "input": {"messages": [
                {"role": "user", "content": "hi"}]}} for index in range(items)]}
    body.update(overrides)
    return body


# ─────────────────────────────────────────────────────── 提交 202
def test_create_batch_returns_202_with_location(client):
    response = client.post("/v1/batches", json=_body(2), headers=_auth())
    assert response.status_code == 202
    payload = response.json()
    assert set(payload) >= {"batch_id", "status", "eta_seconds"}
    assert payload["status"] == "queued" and payload["eta_seconds"] == 30
    assert payload["cost_estimate"]["amount"] == "5.00"
    assert response.headers[facts.LOCATION_HEADER] == f"/v1/batches/{payload['batch_id']}"
    uuid.UUID(payload["batch_id"])


def test_create_batch_is_idempotent_with_key(client):
    key = "batch-key-0123456789"
    headers = {**_auth(), facts.IDEMPOTENCY_HEADER: key}
    first = client.post("/v1/batches", json=_body(1), headers=headers)
    second = client.post("/v1/batches", json=_body(1), headers=headers)
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()
    assert second.headers[facts.IDEMPOTENT_REPLAY_HEADER] == "true"


def test_create_batch_conflicting_key_is_409(client):
    key = "batch-key-0123456789"
    headers = {**_auth(), facts.IDEMPOTENCY_HEADER: key}
    client.post("/v1/batches", json=_body(1), headers=headers)
    response = client.post("/v1/batches", json=_body(3), headers=headers)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40919


def test_create_batch_over_ten_usd_requires_confirmation(client):
    providers.set_route_provider(FakeRoute(price_minor=600))
    response = client.post("/v1/batches", json=_body(2), headers=_auth())
    assert response.status_code == 202
    error = response.json()["error"]
    assert error["code"] == 45202 and error["confirm_required"] is True


def test_create_batch_invalid_body_is_400(client):
    response = client.post("/v1/batches", json={"kind": "chat"}, headers=_auth())
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_create_batch_too_many_items_is_413(client):
    payload = _body(1)
    payload["items"] = [{"custom_id": f"c{index}"}
                        for index in range(facts.BATCH_MAX_ITEMS + 1)]
    response = client.post("/v1/batches", json=payload, headers=_auth())
    assert response.status_code == 413
    assert response.json()["error"]["code"] == 40013


def test_create_batch_rate_limited(client):
    config_source.set_provider(lambda: {"gateway.rate_limit_qps": 1})
    assert client.post("/v1/batches", json=_body(1), headers=_auth()).status_code == 202
    second = client.post("/v1/batches", json=_body(2), headers=_auth())
    assert second.status_code == 429
    assert second.json()["error"]["code"] == 42901


def test_create_batch_requires_auth(client):
    response = client.post("/v1/batches", json=_body(1))
    assert response.status_code == 401


# ─────────────────────────────────────────────────────── 轮询 200 / 404
def test_get_batch_returns_spec_fields(client):
    created = client.post("/v1/batches", json=_body(2), headers=_auth()).json()
    response = client.get(f"/v1/batches/{created['batch_id']}", headers=_auth())
    assert response.status_code == 200
    payload = response.json()
    assert payload["batch_id"] == created["batch_id"]
    assert payload["status"] == "queued"
    assert payload["progress"] == {"completed": 0, "total": 2}
    assert payload["created_at"].endswith("Z")
    assert len(payload["items"]) == 2


def test_get_unknown_batch_is_404(client):
    response = client.get(f"/v1/batches/{uuid.uuid4()}", headers=_auth())
    assert response.status_code == 404
    payload = response.json()["error"]
    assert payload["code"] == 40401
    assert payload["type"] == "not_found_error"


def test_get_batch_requires_auth(client):
    assert client.get(f"/v1/batches/{uuid.uuid4()}").status_code == 401


# ─────────────────────────────────────────────────────── 取消 200
def test_cancel_batch_is_idempotent_over_http(client):
    created = client.post("/v1/batches", json=_body(2), headers=_auth()).json()
    batch_id = created["batch_id"]
    first = client.post(f"/v1/batches/{batch_id}/cancel", headers=_auth())
    assert first.status_code == 200
    assert first.json()["status"] == "canceled"
    assert first.json()["canceled_at"].endswith("Z")
    second = client.post(f"/v1/batches/{batch_id}/cancel", headers=_auth())
    assert second.status_code == 200
    assert second.json()["status"] == "canceled"
    assert second.json()["canceled_at"] == first.json()["canceled_at"]


def test_cancel_unknown_batch_is_404(client):
    response = client.post(f"/v1/batches/{uuid.uuid4()}/cancel", headers=_auth())
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


# ─────────────────────────────────────────────────────── 协议 / 流式（HTTP 面）
def test_batch_endpoints_reject_incompatible_protocol_when_gate_on(client, monkeypatch):
    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "gateway.protocol_version_strict")
    response = client.post("/v1/batches", json=_body(1),
                           headers={**_auth(), facts.PROTOCOL_VERSION_HEADER: "9.9.9"})
    assert response.status_code == 426
    assert response.json()["error"]["code"] == 42601


def test_stream_interruption_over_http_yields_error_frame(client):
    providers.set_stream_client(FakeStream(chunks=["a", "b", "c"], fail_after=1))
    with client.stream("POST", "/v1/chat/completions", json=_body(0) | {
            "messages": [{"role": "user", "content": "stream"}]} | {"stream": True},
            headers=_auth()) as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())
    assert "44101" in body
    assert body.rstrip().endswith(f"data: {facts.SSE_DONE}")


def test_stream_pre_first_byte_failure_returns_json_error(client):
    from gatewaykit import FakeStream as StreamStub

    providers.set_stream_client(StreamStub(timeouts=2))
    response = client.post("/v1/chat/completions", json={"model": "m1", "stream": True,
                                                         "messages": [
                                                             {"role": "user", "content": "x"}]},
                           headers=_auth())
    assert response.status_code == 504
    assert response.json()["error"]["code"] == 50902


def test_batch_webhook_delivered_over_http_when_gate_on(client, monkeypatch):
    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "gateway.batch_webhook_delivery")
    sender = FakeWebhookSender()
    providers.set_webhook_sender(sender)
    providers.set_webhook_secret_provider(lambda account_id: "whsec_test")
    body = _body(1, webhook_url="https://example.test/hook")
    response = client.post("/v1/batches", json=body, headers=_auth())
    assert response.status_code == 202
    assert len(sender.calls) == 1
    assert sender.calls[0]["headers"][facts.WEBHOOK_EVENT_HEADER] == "batch.queued"
