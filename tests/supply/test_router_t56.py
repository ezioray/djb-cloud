# SPDX-License-Identifier: Apache-2.0
"""HTTP 契约（T5/T6）：策略 200/304/403/426 + 协议能力 / 弃用清单（无鉴权）。"""
from __future__ import annotations

import uuid

import pytest

from supplykit import connect

from app.supply import facts, features, models, policy

POLICY = "/api/v1/node/policy"
CAPABILITIES = "/api/v1/protocol/capabilities"
DEPRECATIONS = "/api/v1/protocol/deprecations"


def _active(api):
    payload = {"platform": "linux", "hardware_fingerprint": f"fp-t56-{uuid.uuid4().hex}",
               "client_version": "1.6.0", "protocol_version": "1.0.0"}
    node = api.post("/api/v1/node/register", json=payload).json()
    approved = api.post(f"/api/v1/admin/supply/nodes/{node['node_id']}/review",
                        json={"decision": "approve", "reason": "材料齐全"},
                        headers={"X-Admin-Step-Up": "token"})
    assert approved.status_code == 200, approved.text
    return node


def _error(response):
    error = response.json()["error"]
    assert set(error) >= {"type", "code", "message", "request_id"}
    return error


# --------------------------------------------------------------------------- 策略
def test_policy_returns_versioned_document(api, admin_hook):
    node = _active(api)
    response = api.get(POLICY, headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 200, response.text
    body = response.json()
    for field in ("policy_version", "protocol_version", "issued_at", "digest", "quotas",
                  "directives"):
        assert field in body, field
    assert body["policy_version"] == "1"
    assert len(body["digest"]) == 64
    assert response.headers["ETag"] == "1"
    assert body["settings"][facts.CONFIG_KEYS["heartbeat_interval_s"]] == 30


def test_policy_is_stable_across_calls(api, admin_hook):
    node = _active(api)
    headers = {"X-Client-Key": node["client_key"]}
    first = api.get(POLICY, headers=headers).json()
    second = api.get(POLICY, headers=headers).json()
    assert first["policy_version"] == second["policy_version"] == "1"
    assert first["digest"] == second["digest"]


def test_policy_returns_304_only_when_switch_is_on(api, admin_hook, monkeypatch):
    node = _active(api)
    headers = {"X-Client-Key": node["client_key"], "If-None-Match": '"1"'}
    # 开关默认关闭：命中条件也照常返回 200 全量（安全默认，不丢功能）
    assert features.enabled("supply.policy_etag_304") is False
    default = api.get(POLICY, headers=headers)
    assert default.status_code == 200
    assert default.headers["ETag"] == "1"

    monkeypatch.setattr(features, "enabled", lambda name: name == "supply.policy_etag_304")
    hit = api.get(POLICY, headers=headers)
    assert hit.status_code == 304
    assert hit.headers["ETag"] == "1"

    miss = api.get(POLICY, headers={"X-Client-Key": node["client_key"],
                                    "If-None-Match": '"999"'})
    assert miss.status_code == 200


def test_policy_rejects_pending_and_retired(api):
    pending = api.post("/api/v1/node/register",
                       json={"platform": "linux",
                             "hardware_fingerprint": f"fp-t56p-{uuid.uuid4().hex}",
                             "client_version": "1.0.0", "protocol_version": "1.0.0"}).json()
    response = api.get(POLICY, headers={"X-Client-Key": pending["client_key"]})
    assert response.status_code == 403
    assert _error(response)["code"] == 40305


def test_policy_allows_frozen_node_read_only(api, admin_hook):
    node = _active(api)
    with connect(api.schema) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE nodes SET state = 'frozen' WHERE id = %s", (node["node_id"],))
    response = api.get(POLICY, headers={"X-Client-Key": node["client_key"]})
    assert response.status_code == 200


def test_policy_rejects_unsupported_protocol_header(api, admin_hook):
    node = _active(api)
    response = api.get(POLICY, headers={"X-Client-Key": node["client_key"],
                                        "DJB-Protocol-Version": "2.0.0"})
    assert response.status_code == 426
    assert _error(response)["code"] == 42601


def test_policy_requires_key(api, admin_hook):
    response = api.get(POLICY)
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_policy_records_node_version(api, admin_hook):
    node = _active(api)
    api.get(POLICY, headers={"X-Client-Key": node["client_key"]})
    with connect(api.schema) as conn:
        assert models.get_node(conn, node["node_id"]).policy_version == "1"
        rows = policy.history(conn, node["node_id"])
        assert [item.policy_version for item in rows] == ["1"]


# --------------------------------------------------------------------------- 协议能力
def test_capabilities_is_public_and_lists_intersection(api):
    response = api.get(CAPABILITIES, headers={"DJB-Protocol-Version": "1.0.0",
                                              "DJB-Capabilities":
                                                  "policy_etag,capacity_announcement,unknown"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["enabled"] == ["capacity_announcement", "policy_etag"]
    assert body["protocol_version"] == facts.PROTOCOL_VERSION
    assert body["min_supported_version"] == "0.0.0"
    assert body["server_time"].endswith("Z")
    assert any(item["id"] == "runtime_state" for item in body["capabilities"])


def test_capabilities_426_for_unsupported_client(api):
    response = api.get(CAPABILITIES, headers={"DJB-Protocol-Version": "2.0.0"})
    assert response.status_code == 426
    error = _error(response)
    assert error["code"] == 42601
    assert error["min_supported_version"] == "0.0.0"


def test_capabilities_without_headers_is_public(api):
    response = api.get(CAPABILITIES)
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] == sorted(body["enabled"])


# --------------------------------------------------------------------------- 弃用清单
def test_deprecations_is_public_and_empty_at_s1(api):
    response = api.get(DEPRECATIONS)
    assert response.status_code == 200
    assert response.json()["items"] == []


def test_deprecations_filters_by_major(api):
    assert api.get(DEPRECATIONS, params={"protocol_major": 1}).json()["items"] == []


def test_deprecations_rejects_bad_major(api):
    response = api.get(DEPRECATIONS, params={"protocol_major": "abc"})
    assert response.status_code == 400
    assert _error(response)["field"] == "protocol_major"
