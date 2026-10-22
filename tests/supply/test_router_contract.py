# SPDX-License-Identifier: Apache-2.0
"""HTTP 契约（spec 1.2.0/1.2.1 M02 T2 六端点）：状态码 / 信封 / 幂等 / 认证 / 40305 / 42601。

用法：``api`` fixture 把 ``router._connection`` 指到隔离 schema，并钉死时钟。
"""
from __future__ import annotations

import uuid

import pytest

from supplykit import connect, seed_account

from app.supply import facts, models

REGISTER = "/api/v1/node/register"
PAIR = "/api/v1/node/pair"
BINDING = "/api/v1/node/binding"


def _register_payload(**overrides):
    payload = {"platform": "linux", "hardware_fingerprint": f"fp-api-{uuid.uuid4().hex}",
               "client_version": "1.4.0", "protocol_version": "1.0.0",
               "capabilities": ["capacity_announcement"], "access_modes": ["A1"]}
    payload.update(overrides)
    return payload


def _error(response) -> dict:
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) >= {"type", "code", "message", "request_id"}
    assert isinstance(error["code"], int)
    return error


def _register(api, **overrides):
    response = api.post(REGISTER, json=_register_payload(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


def _approve(api, admin_hook, node_id: str):
    response = api.post(f"/api/v1/admin/supply/nodes/{node_id}/review",
                        json={"decision": "approve", "reason": "材料齐全"},
                        headers={"X-Admin-Step-Up": "token"})
    assert response.status_code == 200, response.text
    return response.json()


def _issue_code(api, node_id: str, account_id: uuid.UUID, ttl: int = 600) -> str:
    with connect(api.schema) as conn:
        code = models.issue_binding_code(conn, node_id=node_id, account_id=account_id,
                                         ttl_seconds=ttl)
    return code.code


# --------------------------------------------------------------------------- 注册
def test_register_returns_201_with_spec_fields(api):
    response = api.post(REGISTER, json=_register_payload(), headers={"X-Request-Id": "rid-1"})
    assert response.status_code == 201
    body = response.json()
    for field in ("node_id", "state", "policy_version", "protocol_version", "server_time"):
        assert field in body, field
    assert body["state"] == "pending"
    assert body["lifecycle_state"] == "pending"
    assert body["protocol_version"] == "1.0.0"
    assert body["server_time"].endswith("Z")
    assert body["client_key"] and body["key_id"] and body["key_prefix"]
    assert body["created"] is True
    assert response.headers["X-Request-Id"] == "rid-1"


def test_register_is_idempotent_by_fingerprint(api):
    payload = _register_payload()
    first = api.post(REGISTER, json=payload).json()
    second = api.post(REGISTER, json=payload).json()

    assert second["node_id"] == first["node_id"]
    assert second["created"] is False
    assert second["client_key"] != first["client_key"]
    assert second["state"] == "pending"


def test_register_rejects_unknown_platform_with_40001(api):
    response = api.post(REGISTER, json=_register_payload(platform="solaris"))
    assert response.status_code == 400
    error = _error(response)
    assert error["code"] == 40001
    assert error["type"] == "invalid_request_error"


def test_register_rejects_too_new_protocol_with_42601(api):
    response = api.post(REGISTER, json=_register_payload(protocol_version="2.0.0"))
    assert response.status_code == 426
    error = _error(response)
    assert error["code"] == 42601
    assert error["type"] == "protocol_error"
    assert error["min_supported_version"] == "0.0.0"
    assert "upgrade_hint" in error


def test_register_rejects_malformed_json(api):
    response = api.post(REGISTER, content=b"{not json", headers={"Content-Type": "text/plain"})
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_register_rejects_credential_body_and_audits_by_field_name_only(api):
    first = _register(api)
    key = first["client_key"]
    response = api.post(REGISTER, headers={"X-Client-Key": key},
                        json=_register_payload(hardware_fingerprint=first["node_id"],
                                               api_key="sk-" + "z" * 40))
    assert response.status_code == 400
    error = _error(response)
    assert error["code"] == 40001
    assert error["fields"] == ["api_key"]
    assert "sk-" not in response.text

    with connect(api.schema) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT payload FROM node_events WHERE node_id = %s "
                        "AND kind = 'credential_rejected'", (first["node_id"],))
            rows = models._rows(cur)
    assert len(rows) == 1
    assert rows[0]["payload"]["fields"] == ["api_key"]


def test_register_idempotency_key_replay_cannot_return_plaintext(api):
    payload = _register_payload()
    headers = {"X-DJB-Idempotency-Key": "idem-register-1"}
    first = api.post(REGISTER, json=payload, headers=headers)
    assert first.status_code == 201
    replay = api.post(REGISTER, json=payload, headers=headers)
    assert replay.status_code == 409
    error = _error(replay)
    assert error["code"] == 40919
    assert error["reason"] == "plaintext_not_replayable"

    different = api.post(REGISTER, json=_register_payload(), headers=headers)
    assert different.status_code == 409
    assert _error(different)["code"] == 40919


def test_register_rejects_bound_fingerprint_without_key(api, admin_hook):
    payload = _register_payload()
    first = api.post(REGISTER, json=payload).json()
    _approve(api, None, first["node_id"])
    account = seed_account(api.schema)
    code = _issue_code(api, first["node_id"], account)
    bound = api.post(BINDING, json={"node_id": first["node_id"], "code": code},
                     headers={"X-Client-Key": first["client_key"]})
    assert bound.status_code == 200, bound.text

    # 同指纹 + 无有效密钥 + 已归属 → 40903（指纹哈希不是秘密，不能凭它接管）
    takeover = api.post(REGISTER, json={**payload, "client_version": "9.9.9"})
    assert takeover.status_code == 409
    assert _error(takeover)["code"] == 40903


# --------------------------------------------------------------------------- pair
def test_pair_requires_client_key(api):
    response = api.post(PAIR, json={"node_id": "n_missing"})
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_pair_rejects_unknown_key(api):
    response = api.post(PAIR, json={"node_id": "n_missing"},
                        headers={"X-Client-Key": "not-a-key"})
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_pair_on_pending_node_is_403_with_40305(api):
    first = _register(api)
    response = api.post(PAIR, json={"node_id": first["node_id"]},
                        headers={"X-Client-Key": first["client_key"]})
    assert response.status_code == 403
    error = _error(response)
    assert error["code"] == 40305
    assert error["state"] == "pending"
    assert error["type"] == "permission_error"


def test_pair_rotates_key_and_invalidates_old_one(api, admin_hook):
    first = _register(api)
    _approve(api, admin_hook, first["node_id"])
    response = api.post(PAIR, json={"node_id": first["node_id"],
                                    "rotate": True, "overlap_seconds": 600},
                        headers={"X-Client-Key": first["client_key"]})
    assert response.status_code == 201, response.text
    body = response.json()
    for field in ("node_id", "key_id", "client_key", "key_prefix", "created_at"):
        assert field in body, field
    assert body["client_key"] != first["client_key"]
    assert body["previous_key_expires_at"].endswith("Z")

    # 旧钥在重叠期内仍可用于验签类接口（binding 查询）
    old_ok = api.get(BINDING, params={"node_id": first["node_id"]},
                     headers={"X-Client-Key": first["client_key"]})
    assert old_ok.status_code == 200
    # 新钥可用
    fresh = api.get(BINDING, params={"node_id": first["node_id"]},
                    headers={"X-Client-Key": body["client_key"]})
    assert fresh.status_code == 200


def test_pair_rejects_overlap_over_24h(api, admin_hook):
    first = _register(api)
    _approve(api, admin_hook, first["node_id"])
    response = api.post(PAIR, json={"node_id": first["node_id"], "rotate": True,
                                    "overlap_seconds": facts.KEY_OVERLAP_MAX_S + 1},
                        headers={"X-Client-Key": first["client_key"]})
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_pair_requires_node_id(api):
    first = _register(api)
    response = api.post(PAIR, json={}, headers={"X-Client-Key": first["client_key"]})
    assert response.status_code == 400
    assert _error(response)["field"] == "node_id"


# --------------------------------------------------------------------------- binding
def test_binding_get_returns_view(api):
    first = _register(api)
    response = api.get(BINDING, params={"node_id": first["node_id"]},
                       headers={"X-Client-Key": first["client_key"]})
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "pending"
    assert body["bound_account_id"] is None


def test_binding_get_requires_node_id_and_key(api):
    first = _register(api)
    missing = api.get(BINDING, headers={"X-Client-Key": first["client_key"]})
    assert missing.status_code == 400
    no_key = api.get(BINDING, params={"node_id": first["node_id"]})
    assert no_key.status_code == 401


def test_binding_get_does_not_leak_other_nodes(api):
    mine = _register(api)
    other = _register(api)
    response = api.get(BINDING, params={"node_id": other["node_id"]},
                       headers={"X-Client-Key": mine["client_key"]})
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


def test_binding_post_binds_with_code(api, admin_hook):
    first = _register(api)
    _approve(api, admin_hook, first["node_id"])
    account = seed_account(api.schema)
    code = _issue_code(api, first["node_id"], account)

    response = api.post(BINDING, json={"node_id": first["node_id"], "code": code},
                        headers={"X-Client-Key": first["client_key"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "bound"
    assert body["bound_account_id"] == str(account)
    assert body["bound_at"].endswith("Z")

    # 一次性码：再用一次 409 / 40905
    replay = api.post(BINDING, json={"node_id": first["node_id"], "code": code},
                      headers={"X-Client-Key": first["client_key"]})
    assert replay.status_code == 409
    assert _error(replay)["code"] == 40905


def test_binding_post_requires_active_node(api, admin_hook):
    first = _register(api)
    account = seed_account(api.schema)
    with connect(api.schema) as conn:
        from app.supply.errors import NodeStateForbidden

        with pytest.raises(NodeStateForbidden):
            models.issue_binding_code(conn, node_id=first["node_id"], account_id=account)
    response = api.post(BINDING, json={"node_id": first["node_id"], "code": "whatever"},
                        headers={"X-Client-Key": first["client_key"]})
    assert response.status_code == 403
    assert _error(response)["code"] == 40305


def test_binding_post_rejects_bad_account_uuid(api, admin_hook):
    first = _register(api)
    _approve(api, admin_hook, first["node_id"])
    response = api.post(BINDING, json={"node_id": first["node_id"], "code": "x",
                                       "account_id": "not-a-uuid"},
                        headers={"X-Client-Key": first["client_key"]})
    assert response.status_code == 400
    assert _error(response)["field"] == "account_id"


def test_binding_delete_unbinds_idempotently(api, admin_hook):
    first = _register(api)
    _approve(api, admin_hook, first["node_id"])
    account = seed_account(api.schema)
    code = _issue_code(api, first["node_id"], account)
    api.post(BINDING, json={"node_id": first["node_id"], "code": code},
             headers={"X-Client-Key": first["client_key"]})

    deleted = api.delete(BINDING, params={"node_id": first["node_id"]},
                         headers={"X-Client-Key": first["client_key"]})
    assert deleted.status_code == 200
    assert deleted.json()["state"] == "revoked"

    again = api.delete(BINDING, params={"node_id": first["node_id"]},
                       headers={"X-Client-Key": first["client_key"]})
    assert again.status_code == 200
    assert again.json()["state"] == "revoked"
    assert again.json()["revoked_at"] == deleted.json()["revoked_at"]


def test_binding_delete_requires_key(api):
    first = _register(api)
    response = api.delete(BINDING, params={"node_id": first["node_id"]})
    assert response.status_code == 401


# --------------------------------------------------------------------------- 准入审核
def test_review_is_fail_closed_without_authenticator(api):
    first = _register(api)
    body = {"decision": "approve", "reason": "ok"}
    response = api.post(f"/api/v1/admin/supply/nodes/{first['node_id']}/review", json=body,
                        headers={"X-Admin-Step-Up": "token"})
    assert response.status_code == 401
    error = _error(response)
    assert error["code"] == 40101
    assert error["reason"] == "admin_auth_unavailable"


def test_review_requires_step_up(api, admin_hook):
    first = _register(api)
    response = api.post(f"/api/v1/admin/supply/nodes/{first['node_id']}/review",
                        json={"decision": "approve", "reason": "ok"})
    assert response.status_code == 424
    error = _error(response)
    assert error["code"] == 42401
    assert error["type"] == "permission_error"


def test_review_approves_and_rejects(api, admin_hook):
    first = _register(api)
    approved = api.post(f"/api/v1/admin/supply/nodes/{first['node_id']}/review",
                        json={"decision": "approve", "reason": "材料齐全"},
                        headers={"X-Admin-Step-Up": "token"})
    assert approved.status_code == 200
    body = approved.json()
    assert body["state"] == "active"
    assert body["reviewed_at"].endswith("Z")
    assert body["policy_version"] == "0"

    # 已 active 再审 → 403 / 40305
    again = api.post(f"/api/v1/admin/supply/nodes/{first['node_id']}/review",
                     json={"decision": "approve", "reason": "再审"},
                     headers={"X-Admin-Step-Up": "token"})
    assert again.status_code == 403
    assert _error(again)["code"] == 40305

    second = _register(api)
    rejected = api.post(f"/api/v1/admin/supply/nodes/{second['node_id']}/review",
                        json={"decision": "reject", "reason": "指纹不完整"},
                        headers={"X-Admin-Step-Up": "token"})
    assert rejected.status_code == 200
    assert rejected.json()["state"] == "pending"


def test_review_unknown_node_is_404(api, admin_hook):
    response = api.post("/api/v1/admin/supply/nodes/n_missing/review",
                        json={"decision": "approve", "reason": "ok"},
                        headers={"X-Admin-Step-Up": "token"})
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


def test_review_requires_reason(api, admin_hook):
    first = _register(api)
    response = api.post(f"/api/v1/admin/supply/nodes/{first['node_id']}/review",
                        json={"decision": "approve"},
                        headers={"X-Admin-Step-Up": "token"})
    assert response.status_code == 400
    assert _error(response)["field"] == "reason"


def test_review_idempotency_key_replays_first_response(api, admin_hook):
    first = _register(api)
    headers = {"X-Admin-Step-Up": "token", "X-DJB-Idempotency-Key": "idem-review-1"}
    payload = {"decision": "approve", "reason": "材料齐全"}
    first_call = api.post(f"/api/v1/admin/supply/nodes/{first['node_id']}/review",
                          json=payload, headers=headers)
    assert first_call.status_code == 200
    replay = api.post(f"/api/v1/admin/supply/nodes/{first['node_id']}/review",
                      json=payload, headers=headers)
    assert replay.status_code == 200
    assert replay.json() == first_call.json()


def test_unknown_idempotency_key_length_is_400(api):
    first = _register(api)
    response = api.post(PAIR, json={"node_id": first["node_id"]},
                        headers={"X-Client-Key": first["client_key"],
                                 "X-DJB-Idempotency-Key": "k" * 200})
    assert response.status_code == 400
    assert _error(response)["code"] == 40001
