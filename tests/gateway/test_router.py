# SPDX-License-Identifier: Apache-2.0
"""HTTP 层（M03 §4.1 / 00-conventions §5 / INV-M03-05 / INV-M03-08）：信封、头、状态码。"""
from __future__ import annotations

import uuid

import pytest

from app.gateway import config_source, errors, facts, providers
from gatewaykit import FakeAuth, FakeCatalog, FakeRoute


@pytest.fixture(scope="module")
def api_schema(db, schema_prefix) -> str:               # noqa: ARG001
    """HTTP 用例专用 schema（路由会真提交，与事务回滚域用例分开最干净）。"""
    from gatewaykit import apply_migrations, create_schema, drop_schema

    name = f"{schema_prefix}_api_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def client(api_schema: str):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.gateway import router as router_module
    from gatewaykit import connect

    app = FastAPI()
    app.include_router(router_module.router)

    def _connection():
        return connect(api_schema, autocommit=False)

    original = router_module._connection
    router_module._connection = _connection
    original_ip = router_module._client_ip_resolver
    router_module.set_client_ip_resolver(None)
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        router_module._connection = original
        router_module.set_client_ip_resolver(original_ip)


@pytest.fixture
def api(wired):
    """接好四个 provider（鉴权 / 路由 / 上游 / 计量），返回可检查的假实现。"""
    providers.set_model_catalog_provider(FakeCatalog())
    return wired


def _body(**overrides):
    body = {"model": "m1", "messages": [{"role": "user", "content": "hi"}]}
    body.update(overrides)
    return body


def _auth(key: str = "djb_live_abcdefgh") -> dict[str, str]:
    return {facts.AUTH_HEADER: f"Bearer {key}"}


# ─────────────────────────────────────────────────────── 成功路径与头
def test_success_echoes_client_request_id(client, api):
    request_id = str(uuid.uuid4())
    response = client.post("/v1/chat/completions", json=_body(),
                           headers={**_auth(), facts.REQUEST_ID_HEADER: request_id})
    assert response.status_code == 200
    assert response.headers[facts.REQUEST_ID_HEADER] == request_id
    payload = response.json()
    assert payload["id"] == request_id
    assert payload["object"] == "chat.completion"
    assert payload["usage"]["total_tokens"] == 5


def test_non_uuid_request_id_is_replaced_by_a_generated_uuid(client, api):
    response = client.post("/v1/chat/completions", json=_body(),
                           headers={**_auth(), facts.REQUEST_ID_HEADER: "not-a-uuid"})
    assert response.status_code == 200
    echoed = response.headers[facts.REQUEST_ID_HEADER]
    assert echoed != "not-a-uuid"
    uuid.UUID(echoed)                                   # 必须是合法 UUID（spec format）


def test_success_carries_rate_limit_headers(client, api):
    response = client.post("/v1/chat/completions", json=_body(), headers=_auth())
    for header in facts.RATE_LIMIT_HEADERS:
        assert header in response.headers


def test_idempotent_replay_is_flagged(client, api):
    key = "idem-key-0123456789"
    first = client.post("/v1/chat/completions", json=_body(),
                        headers={**_auth(), facts.IDEMPOTENCY_HEADER: key})
    second = client.post("/v1/chat/completions", json=_body(),
                         headers={**_auth(), facts.IDEMPOTENCY_HEADER: key})
    assert first.status_code == second.status_code == 200
    assert second.json() == first.json()
    assert second.headers[facts.IDEMPOTENT_REPLAY_HEADER] == "true"


# ─────────────────────────────────────────────────────── 错误信封
def _assert_error(response, *, http: int, code: int):
    assert response.status_code == http
    payload = response.json()
    assert set(payload) == {"error"}
    error = payload["error"]
    assert error["code"] == code
    assert error["type"] in errors.ERROR_TYPES
    assert isinstance(error["message"], str) and error["message"]
    uuid.UUID(error["request_id"])
    assert response.headers[facts.REQUEST_ID_HEADER] == error["request_id"]
    return error


def test_missing_authorization_is_401_40101(client, api):
    response = client.post("/v1/chat/completions", json=_body())
    _assert_error(response, http=401, code=40101)


def test_invalid_key_is_401_40101(client, api):
    response = client.post("/v1/chat/completions", json=_body(),
                           headers=_auth("revoked_key_abcdefgh"))
    _assert_error(response, http=401, code=40101)


def test_ip_outside_allowlist_is_403_40102(client, api):
    providers.set_auth_provider(FakeAuth(ip_allowlist=["10.0.0.0/8"]))
    response = client.post("/v1/chat/completions", json=_body(), headers=_auth())
    error = _assert_error(response, http=403, code=40102)
    assert error["reason"] == "policy_blocked"


def test_malformed_json_is_400_40001(client, api):
    response = client.post("/v1/chat/completions", content=b"{oops",
                           headers={**_auth(), "Content-Type": "application/json"})
    _assert_error(response, http=400, code=40001)


def test_invalid_body_is_400_40001(client, api):
    response = client.post("/v1/chat/completions", json={"model": "m1"}, headers=_auth())
    _assert_error(response, http=400, code=40001)


def test_oversized_body_is_413_40013(client, api):
    payload = {"model": "m1",
               "messages": [{"role": "user", "content": "x" * (facts.CHAT_BODY_MAX_BYTES + 10)}]}
    response = client.post("/v1/chat/completions", json=payload, headers=_auth())
    error = _assert_error(response, http=413, code=40013)
    assert error["max_bytes"] == facts.CHAT_BODY_MAX_BYTES


def test_rate_limit_is_429_with_retry_after(client, api):
    config_source.set_provider(lambda: {"gateway.rate_limit_qps": 1})
    first = client.post("/v1/chat/completions", json=_body(), headers=_auth())
    assert first.status_code == 200
    second = client.post("/v1/chat/completions",
                         json=_body(messages=[{"role": "user", "content": "again"}]),
                         headers=_auth())
    error = _assert_error(second, http=429, code=42901)
    assert facts.RETRY_AFTER_HEADER in second.headers
    assert int(second.headers[facts.RETRY_AFTER_HEADER]) >= 1
    assert error["retry_after"] == int(second.headers[facts.RETRY_AFTER_HEADER])
    assert second.headers[facts.RATE_LIMIT_LIMIT_HEADER] == "1"


def test_conflicting_idempotency_payload_is_409_40919(client, api):
    key = "idem-key-0123456789"
    client.post("/v1/chat/completions", json=_body(),
                headers={**_auth(), facts.IDEMPOTENCY_HEADER: key})
    response = client.post("/v1/chat/completions", json=_body(model="m2"),
                           headers={**_auth(), facts.IDEMPOTENCY_HEADER: key})
    _assert_error(response, http=409, code=40919)


def test_bad_idempotency_key_length_is_40001(client, api):
    response = client.post("/v1/chat/completions", json=_body(),
                           headers={**_auth(), facts.IDEMPOTENCY_HEADER: "short"})
    _assert_error(response, http=400, code=40001)


def test_no_route_is_503_50901_with_retry_after(client, api):
    providers.set_route_provider(FakeRoute(fail_times=99))
    response = client.post("/v1/chat/completions", json=_body(), headers=_auth())
    _assert_error(response, http=503, code=50901)
    assert facts.RETRY_AFTER_HEADER in response.headers


def test_stream_without_stream_client_is_fail_closed(client, api):
    """流式通道未接线 → 503（不再用 400 占位）；接上后见 test_stream_sse_end_to_end。"""
    providers.set_stream_client(None)
    _assert_error(client.post("/v1/chat/completions", json=_body(stream=True),
                              headers=_auth()), http=503, code=45001)


def test_stream_sse_end_to_end(client, api):
    """SSE 全链路：text/event-stream + data: [DONE] + 回显 X-Request-Id。"""
    from gatewaykit import FakeStream

    providers.set_stream_client(FakeStream(chunks=["he", "llo"]))
    request_id = str(uuid.uuid4())
    with client.stream("POST", "/v1/chat/completions", json=_body(stream=True),
                       headers={**_auth(), facts.REQUEST_ID_HEADER: request_id}) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers[facts.REQUEST_ID_HEADER] == request_id
        body = "".join(response.iter_text())
    assert body.rstrip().endswith(f"data: {facts.SSE_DONE}")
    assert '"object":"chat.completion.chunk"' in body.replace(" ", "")


def test_auth_provider_missing_is_503_fail_closed(client):
    providers.reset_providers()
    response = client.post("/v1/chat/completions", json=_body(), headers=_auth())
    _assert_error(response, http=503, code=45001)
    assert facts.RETRY_AFTER_HEADER in response.headers


# ─────────────────────────────────────────────────────── /v1/models
def test_models_returns_the_catalog(client, api):
    response = client.get("/v1/models", headers=_auth())
    assert response.status_code == 200
    payload = response.json()
    assert payload["object"] == "list"
    assert payload["data"][0]["id"] == "m1"
    assert payload["data"][0]["object"] == "model"
    assert payload["data"][0]["owned_by"] == "djb"
    assert payload["data"][0]["price"]["amount"] == "0.02"


def test_models_requires_auth(client, api):
    _assert_error(client.get("/v1/models"), http=401, code=40101)


def test_models_fail_closed_without_catalog(client, api):
    providers.set_model_catalog_provider(None)
    _assert_error(client.get("/v1/models", headers=_auth()), http=503, code=45001)


def test_models_rate_limited(client, api):
    config_source.set_provider(lambda: {"gateway.rate_limit_qps": 1})
    assert client.get("/v1/models", headers=_auth()).status_code == 200
    _assert_error(client.get("/v1/models", headers=_auth()), http=429, code=42901)


# ─────────────────────────────────────────────────────── 健康 / 接线自检
def test_health_reports_wiring_without_leaking_providers():
    from app.gateway import router as router_module

    info = router_module.health()
    assert info["module"] == "M03"
    assert set(info["providers"]) == {"auth", "route", "node", "stream", "usage",
                                     "model_catalog", "webhook_sender", "webhook_secret",
                                     "result_signer"}
    assert all(value is False for value in info["providers"].values())
    assert info["features"] == {"gateway.protocol_version_strict": False,
                               "gateway.node_layer_rate_limit": False,
                               "gateway.stream_estimated_usage_sync": False,
                               "gateway.batch_webhook_delivery": False,
                               "gateway.token.dual.enabled": False}
