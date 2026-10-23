# SPDX-License-Identifier: Apache-2.0
"""HTTP 路由（需要 DJB_DSN）：契约形状、错误码、幂等、鉴权 fail-closed、/healthz。

用真实 ASGI 客户端（TestClient）打，避免"只测函数不测接线"；
每次请求走内层 SAVEPOINT（``savepoint_factory``），用例结束整体回滚，链不会被污染。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import psycopg
import pytest

from app.audit import StaticKeyProvider, clock, create_health_handler, create_router, facts
from infrakit import TEST_KEY
from infrakit import savepoint_factory

FIXED_NOW = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
IDEMPOTENCY = "X-DJB-Idempotency-Key"

ENTRY_BODY = {
    "actor": "infra-seat",
    "actor_type": "agent",
    "role": "INFRA",
    "action": "read.report",
    "target": "nas/guard",
}

HIGH_RISK_BODY = {
    "actor": "release-manager",
    "actor_type": "human",
    "role": "REL",
    "action": "authorize.window",
    "target": "REL-0001",
    "reason_code": "R-OK",
    "ticket": "REL-0001",
    "before": {"window": "closed"},
    "after": {"window": "open"},
    "status": "approved",
    "approval_chain": [
        {"actor": "lead", "decision": "propose"},
        {"actor": "release-manager", "decision": "approve"},
    ],
}


def build_client(connection, *, key_provider=None, principal=None, now=FIXED_NOW):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(connection),
        principal_resolver=principal,
        key_provider=key_provider if key_provider is not None else StaticKeyProvider(TEST_KEY),
        now_provider=lambda: now,
    ))
    return TestClient(app)


def service_principal(request):                       # noqa: ARG001
    return {"service": "M10-config-center",
            "scopes": ["audit:append", "audit:read", "audit:verify"]}


@pytest.fixture
def client(savepoint_conn):
    with build_client(savepoint_conn, principal=service_principal) as test_client:
        yield test_client


# --------------------------------------------------------------------------- 追加
def test_append_returns_contract_fields(client):
    response = client.post("/internal/ops/audit/entries", json=ENTRY_BODY,
                           headers={IDEMPOTENCY: "idem-router-0001"})
    assert response.status_code == 201
    payload = response.json()
    for field in ("entry_id", "seq", "ts", "alg", "prev_hash", "hash"):
        assert field in payload, field
    assert payload["alg"] == facts.ALG
    assert payload["duplicate"] is False
    assert payload["seq"] == 1
    assert payload["prev_hash"] == facts.GENESIS
    assert response.headers["X-Request-Id"]


def test_append_echoes_request_id(client):
    response = client.post("/internal/ops/audit/entries", json=ENTRY_BODY,
                           headers={"X-Request-Id": "req-abc", IDEMPOTENCY: "idem-router-0002"})
    assert response.headers["X-Request-Id"] == "req-abc"


def test_append_is_idempotent(client):
    headers = {IDEMPOTENCY: "idem-router-0003"}
    first = client.post("/internal/ops/audit/entries", json=ENTRY_BODY, headers=headers)
    second = client.post("/internal/ops/audit/entries", json=ENTRY_BODY, headers=headers)
    assert first.status_code == second.status_code == 201
    assert second.json()["duplicate"] is True
    assert second.json()["seq"] == first.json()["seq"]
    assert second.json()["hash"] == first.json()["hash"]


def test_append_without_header_uses_body_fingerprint(client):
    first = client.post("/internal/ops/audit/entries", json=ENTRY_BODY)
    second = client.post("/internal/ops/audit/entries", json=ENTRY_BODY)
    assert first.json()["duplicate"] is False
    assert second.json()["duplicate"] is True
    assert second.json()["seq"] == first.json()["seq"]


def test_short_idempotency_key_is_rejected(client):
    response = client.post("/internal/ops/audit/entries", json=ENTRY_BODY,
                           headers={IDEMPOTENCY: "short"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_high_risk_missing_fields_is_rejected(client):
    body = dict(HIGH_RISK_BODY, ticket=None, before=None)
    response = client.post("/internal/ops/audit/entries", json=body,
                           headers={IDEMPOTENCY: "idem-router-0004"})
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == 40001
    assert error["reason"] == "high_risk_fields_missing"
    assert error["gaps"]


def test_self_approval_is_rejected(client):
    body = dict(HIGH_RISK_BODY, approval_chain=[
        {"actor": "lead", "decision": "propose"},
        {"actor": "lead", "decision": "approve"},
    ])
    response = client.post("/internal/ops/audit/entries", json=body,
                           headers={IDEMPOTENCY: "idem-router-0005"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40901


def test_high_risk_entry_is_accepted(client):
    response = client.post("/internal/ops/audit/entries", json=HIGH_RISK_BODY,
                           headers={IDEMPOTENCY: "idem-router-0006"})
    assert response.status_code == 201
    assert response.json()["alg"] == facts.ALG


def test_malformed_json_is_rejected(client):
    response = client.post("/internal/ops/audit/entries", content=b"{not-json",
                           headers={"Content-Type": "application/json",
                                    IDEMPOTENCY: "idem-router-0007"})
    assert response.status_code == 400
    assert response.json()["error"]["reason"] == "malformed_json"


def test_missing_required_field_is_rejected(client):
    response = client.post("/internal/ops/audit/entries", json={"actor": "x"},
                           headers={IDEMPOTENCY: "idem-router-0008"})
    assert response.status_code == 400
    assert "actor_type" in json.dumps(response.json(), ensure_ascii=False)


# --------------------------------------------------------------------------- 鉴权 / 密钥 fail-closed
def test_unauthenticated_is_rejected(unauth_client):
    response = unauth_client.post("/internal/ops/audit/entries", json=ENTRY_BODY,
                                  headers={IDEMPOTENCY: "idem-router-0009"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == 40101


def test_missing_scope_is_forbidden(savepoint_conn):
    with build_client(savepoint_conn,
                      principal=lambda request: {"service": "M03-gateway",
                                                 "scopes": ["audit:read"]}) as test_client:
        response = test_client.post("/internal/ops/audit/entries", json=ENTRY_BODY,
                                    headers={IDEMPOTENCY: "idem-router-0010"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 40301


def test_missing_key_refuses_writes(savepoint_conn):
    with build_client(savepoint_conn, key_provider=StaticKeyProvider(None),
                      principal=service_principal) as test_client:
        response = test_client.post("/internal/ops/audit/entries", json=ENTRY_BODY,
                                    headers={IDEMPOTENCY: "idem-router-0011"})
    assert response.status_code == 423
    assert response.json()["error"]["code"] == 42301


def test_verify_without_key_returns_not_ok(savepoint_conn):
    with build_client(savepoint_conn, key_provider=StaticKeyProvider(None),
                      principal=service_principal) as test_client:
        response = test_client.post("/internal/ops/audit/verify", json={})
    assert response.status_code == 200
    assert response.json()["ok"] is False


# --------------------------------------------------------------------------- 查询
def test_list_returns_page(client):
    client.post("/internal/ops/audit/entries", json=ENTRY_BODY,
                headers={IDEMPOTENCY: "idem-router-0012"})
    response = client.get("/internal/ops/audit/entries", params={"limit": 1})
    assert response.status_code == 200
    payload = response.json()
    assert payload["data"] and payload["page"]["has_more"] is False
    entry = payload["data"][0]
    for field in ("seq", "entry_id", "ts", "actor", "actor_type", "role", "action", "target",
                  "status", "alg", "prev_hash", "hash"):
        assert field in entry, field


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 999}, {"limit": "x"},
                                    {"from_seq": 0}, {"from_seq": "abc"}])
def test_list_rejects_bad_params(client, params):
    response = client.get("/internal/ops/audit/entries", params=params)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_list_is_read_only(client):
    """审计接口不提供 UPDATE / DELETE（GET / POST 之外一律 405）。"""
    assert client.delete("/internal/ops/audit/entries").status_code == 405
    assert client.put("/internal/ops/audit/entries").status_code == 405


# --------------------------------------------------------------------------- 校验 / 封盘
def test_verify_endpoint(client):
    client.post("/internal/ops/audit/entries", json=ENTRY_BODY,
                headers={IDEMPOTENCY: "idem-router-0013"})
    response = client.post("/internal/ops/audit/verify", json={"period": "2026-10-23"})
    assert response.status_code == 200
    payload = response.json()
    for field in ("ok", "period", "entries", "alg", "checked_at"):
        assert field in payload, field
    assert payload["ok"] is True
    assert payload["period"] == "2026-10-23"
    assert payload["entries"] == 1


def test_verify_seal_writes_anchor(client):
    response = client.post("/internal/ops/audit/verify",
                           json={"period": "2026-10-23", "seal": True})
    assert response.status_code == 200
    payload = response.json()
    assert payload["sealed"] is True
    assert payload["merkle_root"]


def test_verify_rejects_bad_alg_and_period(client):
    bad_alg = client.post("/internal/ops/audit/verify", json={"expected_alg": "sha256"})
    assert bad_alg.status_code == 400
    bad_period = client.post("/internal/ops/audit/verify", json={"period": "2026-13-99"})
    assert bad_period.status_code == 400
    bad_seal = client.post("/internal/ops/audit/verify", json={"seal": "yes"})
    assert bad_seal.status_code == 400


# --------------------------------------------------------------------------- /healthz
def test_healthz_ok(health_client):
    response = health_client.get("/healthz")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["version"]
    assert payload["checks"]["db"] == "ok"
    assert payload["checks"]["audit_key"] == "ok"
    assert "checked_at" in payload


def test_healthz_without_key_is_degraded(savepoint_conn):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.audit import create_health_router

    app = FastAPI()
    app.include_router(create_health_router(
        connection_factory=savepoint_factory(savepoint_conn),
        key_provider=StaticKeyProvider(None)))
    with TestClient(app) as test_client:
        response = test_client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"]["audit_key"] == "missing"


def test_healthz_reports_500_when_database_is_down():
    def broken_factory():
        raise psycopg.OperationalError("database is down")

    handler = create_health_handler(connection_factory=broken_factory,
                                    key_provider=StaticKeyProvider(TEST_KEY),
                                    now=lambda: FIXED_NOW)
    response = handler()
    assert response.status_code == 500
    body = json.loads(response.body)
    assert body["error"]["code"] == 50001


def test_healthz_reports_locked_when_key_permissions_are_wrong(tmp_path, savepoint_conn):
    from app.audit import FileKeyProvider

    path = tmp_path / "audit.key"
    path.write_bytes(b"0123456789abcdef0123456789abcdef")
    path.chmod(0o644)
    handler = create_health_handler(
        connection_factory=savepoint_factory(savepoint_conn),
        key_provider=FileKeyProvider(path), now=lambda: FIXED_NOW)
    body = json.loads(handler().body)
    assert body["status"] == "degraded"
    assert body["checks"]["audit_key"] == "locked"


def test_healthz_checked_at_uses_injected_clock(savepoint_conn):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.audit import create_health_router

    app = FastAPI()
    app.include_router(create_health_router(
        connection_factory=savepoint_factory(savepoint_conn),
        key_provider=StaticKeyProvider(TEST_KEY), now=lambda: FIXED_NOW))
    with TestClient(app) as test_client:
        response = test_client.get("/healthz")
    assert response.json()["checked_at"] == clock.iso_micros(FIXED_NOW)
