# SPDX-License-Identifier: Apache-2.0
"""HTTP 契约（T3/T4）：心跳 / 上游申报 / 体检回执（spec 1.2.x 路径与状态码）。"""
from __future__ import annotations

import uuid

import pytest

from supplykit import connect

from app.supply import models

HEARTBEAT = "/api/v1/node/heartbeat"
UPSTREAM = "/api/v1/node/upstream"
PROBE = "/api/v1/node/upstream/probe"


def _register(api, **overrides):
    payload = {"platform": "linux", "hardware_fingerprint": f"fp-t34-{uuid.uuid4().hex}",
               "client_version": "1.5.0", "protocol_version": "1.0.0"}
    payload.update(overrides)
    response = api.post("/api/v1/node/register", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _active(api, **overrides):
    node = _register(api, **overrides)
    response = api.post(f"/api/v1/admin/supply/nodes/{node['node_id']}/review",
                        json={"decision": "approve", "reason": "材料齐全"},
                        headers={"X-Admin-Step-Up": "token"})
    assert response.status_code == 200, response.text
    return node


def _error(response):
    body = response.json()
    error = body["error"]
    assert set(error) >= {"type", "code", "message", "request_id"}
    return error


def _capacity(**overrides):
    entry = {"kind": "token_relay", "access": "A1", "model": "gpt-4o-mini",
             "max_qps": 6, "unit": "req"}
    entry.update(overrides)
    return [entry]


def _verified_upstream(api, node, *, access="A1", models=("gpt-4o-mini",)):
    """C9b 前置：心跳公告只认已验证上游——先申报再回执体检通过（走真实 API 路径）。"""
    declared = api.post(UPSTREAM, json={"access_type": access,
                                        "base_url": f"http://127.0.0.1:9/{access.lower()}",
                                        "models": list(models)},
                        headers={"X-Client-Key": node["client_key"]})
    assert declared.status_code == 200, declared.text
    ack = api.post(PROBE, json={"upstream_id": declared.json()["upstream_id"],
                                "reachable": True},
                   headers={"X-Client-Key": node["client_key"]})
    assert ack.status_code == 200, ack.text
    return ack.json()


# --------------------------------------------------------------------------- 心跳
def test_heartbeat_returns_spec_fields(api, admin_hook):
    node = _active(api)
    _verified_upstream(api, node)                  # 公告要被「认」（verified + 新鲜）
    response = api.post(HEARTBEAT, json={"node_id": node["node_id"],
                                         "protocol_version": "1.0.0",
                                         "policy_version": "0",
                                         "capacity": _capacity()},
                        headers={"X-Client-Key": node["client_key"],
                                 "X-Request-Id": "rid-hb"})
    assert response.status_code == 200, response.text
    body = response.json()
    for field in ("server_time", "protocol_version", "policy_version",
                  "next_heartbeat_seconds", "policy_updated"):
        assert field in body, field
    assert body["accepted"] is True
    assert body["announcement"]["seq"] == 1
    assert response.headers["X-Request-Id"] == "rid-hb"


def test_heartbeat_requires_key(api, admin_hook):
    node = _active(api)
    response = api.post(HEARTBEAT, json={"node_id": node["node_id"],
                                         "protocol_version": "1.0.0",
                                         "policy_version": "0"})
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_heartbeat_rejects_pending_node(api):
    node = _register(api)
    response = api.post(HEARTBEAT, json={"node_id": node["node_id"],
                                         "protocol_version": "1.0.0",
                                         "policy_version": "0"},
                        headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 403
    error = _error(response)
    assert error["code"] == 40305
    assert error["state"] == "pending"


def test_heartbeat_does_not_write_announcement_for_pending(api):
    node = _register(api)
    api.post(HEARTBEAT, json={"node_id": node["node_id"], "protocol_version": "1.0.0",
                              "policy_version": "0", "capacity": _capacity()},
             headers={"X-Client-Key": node["client_key"]})
    with connect(api.schema) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM capacity_announcements WHERE node_id = %s",
                        (node["node_id"],))
            assert models._one(cur)["n"] == 0


def test_heartbeat_protocol_mismatch_is_426(api, admin_hook):
    node = _active(api)
    response = api.post(HEARTBEAT, json={"node_id": node["node_id"],
                                         "protocol_version": "2.0.0",
                                         "policy_version": "0"},
                        headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 426
    error = _error(response)
    assert error["code"] == 42601
    assert error["min_supported_version"] == "0.0.0"


def test_heartbeat_rate_limit_is_429_with_retry_after(api, admin_hook):
    node = _active(api)
    headers = {"X-Client-Key": node["client_key"]}
    first = api.post(HEARTBEAT, json={"node_id": node["node_id"],
                                      "protocol_version": "1.0.0",
                                      "policy_version": "0"}, headers=headers)
    assert first.status_code == 200
    second = api.post(HEARTBEAT, json={"node_id": node["node_id"],
                                       "protocol_version": "1.0.0",
                                       "policy_version": "0"}, headers=headers)
    assert second.status_code == 429
    assert _error(second)["code"] == 42901
    assert second.headers["Retry-After"] == "5"


def test_heartbeat_idempotency_replay(api, admin_hook):
    node = _active(api)
    headers = {"X-Client-Key": node["client_key"], "X-DJB-Idempotency-Key": "hb-idem-1"}
    payload = {"node_id": node["node_id"], "protocol_version": "1.0.0",
               "policy_version": "0", "capacity": _capacity()}
    first = api.post(HEARTBEAT, json=payload, headers=headers)
    assert first.status_code == 200
    replay = api.post(HEARTBEAT, json=payload, headers=headers)
    assert replay.status_code == 200
    assert replay.json() == first.json()


# --------------------------------------------------------------------------- 上游申报
def test_declare_upstream_returns_probe_hint(api, admin_hook):
    node = _active(api)
    response = api.post(UPSTREAM, json={"access_type": "A2",
                                        "base_url": "http://127.0.0.1:8080/v1",
                                        "models": ["gpt-4o-mini"],
                                        "credential_handle": "keychain:djb"},
                        headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "declared"
    assert body["models_declared"] == ["gpt-4o-mini"]
    assert body["probe_hint"].startswith("probe_locally")
    assert body["created"] is True
    assert "keychain:djb" not in response.text          # 句柄不回显


def test_declare_upstream_rejects_userinfo(api, admin_hook):
    node = _active(api)
    response = api.post(UPSTREAM, json={"access_type": "A1",
                                        "base_url": "https://u:p@up.example/v1",
                                        "models": ["m1"]},
                        headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 400
    assert _error(response)["field"] == "base_url"


def test_declare_upstream_rejects_credential_body_and_audits(api, admin_hook):
    node = _active(api)
    response = api.post(UPSTREAM, json={"access_type": "A1",
                                        "base_url": "https://up.example/v1",
                                        "models": ["m1"],
                                        "api_key": "sk-" + "q" * 40},
                        headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 400
    error = _error(response)
    assert error["code"] == 40001
    assert error["fields"] == ["api_key"]
    assert "sk-" not in response.text

    with connect(api.schema) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT payload FROM node_events WHERE node_id = %s "
                        "AND kind = 'credential_rejected'", (node["node_id"],))
            rows = models._rows(cur)
    assert rows and rows[0]["payload"]["fields"] == ["api_key"]


def test_declare_upstream_requires_active_node(api):
    node = _register(api)
    response = api.post(UPSTREAM, json={"access_type": "A1", "base_url": "https://up.example/v1",
                                        "models": ["m1"]},
                        headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 403
    assert _error(response)["code"] == 40305


def test_declare_upstream_is_idempotent(api, admin_hook):
    node = _active(api)
    payload = {"access_type": "B", "base_url": "https://corp.example/v1", "models": ["m1"]}
    first = api.post(UPSTREAM, json=payload, headers={"X-Client-Key": node["client_key"]})
    second = api.post(UPSTREAM, json={**payload, "models": ["m1", "m2"]},
                      headers={"X-Client-Key": node["client_key"]})
    assert first.status_code == second.status_code == 200
    assert second.json()["upstream_id"] == first.json()["upstream_id"]
    assert second.json()["created"] is False
    assert second.json()["models_declared"] == ["m1", "m2"]


# --------------------------------------------------------------------------- 体检回执
def test_probe_receipt_verifies_upstream(api, admin_hook):
    node = _active(api)
    declared = api.post(UPSTREAM, json={"access_type": "A1", "base_url": "https://up.example/v1",
                                        "models": ["m1"]},
                        headers={"X-Client-Key": node["client_key"]}).json()
    response = api.post(PROBE, json={"upstream_id": declared["upstream_id"],
                                     "reachable": True, "latency_ms": 12,
                                     "model_checks": [{"model": "m1", "ok": True}],
                                     "checked_at": "2026-10-23T00:00:00Z"},
                        headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "verified"
    assert body["recorded_at"].endswith("Z")
    assert set(body) >= {"upstream_id", "state", "recorded_at"}


def test_probe_unknown_upstream_is_404(api, admin_hook):
    node = _active(api)
    response = api.post(PROBE, json={"upstream_id": str(uuid.uuid4()), "reachable": True,
                                     "checked_at": "2026-10-23T00:00:00Z"},
                        headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


@pytest.mark.parametrize("body,field", [
    ({"reachable": True}, "upstream_id"),
    ({"upstream_id": "x", "reachable": True}, "upstream_id"),
    ({"upstream_id": str(uuid.uuid4()), "reachable": "yes", "checked_at": "2026-10-23T00:00:00Z"},
     "reachable"),
])
def test_probe_argument_validation(api, admin_hook, body, field):
    node = _active(api)
    response = api.post(PROBE, json=body, headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 400
    assert _error(response)["field"] == field
