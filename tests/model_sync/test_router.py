# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP 路由：node catalog / node state / admin bundles & state。

覆盖：fail-closed 鉴权、scope、开关（feature_disabled）、wire 形状、304-等价
（``not_modified``）、发布 / 回滚、请求 id 回显。
"""
from __future__ import annotations

import uuid

import pytest

from app.model_sync import facts, registry, signing, store

from kit import (ADMIN_PRINCIPAL, NO_SCOPE_PRINCIPAL, NODE_PRINCIPAL, READONLY_PRINCIPAL,
                 build_client)

CATALOG = "/api/v1/node/model-catalog"
STATE = "/api/v1/node/model-sync/state"
BUNDLES = "/api/v1/admin/model-sync/bundles"
ADMIN_STATE = "/api/v1/admin/model-sync/state"


def _error(response):
    error = response.json()["error"]
    assert set(error) >= {"type", "code", "message", "request_id"}
    return error


def _publish(conn, now, *, actor="admin:t"):
    draft = store.create_draft(conn, actor=actor, now=now)
    return store.publish(conn, draft["id"], actor=actor, now=now)


# --------------------------------------------------------------------------- node
def test_node_catalog_requires_auth(anon_client):
    response = anon_client.get(CATALOG)
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_admin_requires_auth(anon_client):
    response = anon_client.get(BUNDLES)
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_node_catalog_falls_back_when_feature_disabled(conn, monkeypatch, now):
    client = build_client(conn, monkeypatch, node=NODE_PRINCIPAL, admin=ADMIN_PRINCIPAL,
                          feature=False, now=now)
    _publish(conn, now)                                   # 即使有已发布 bundle 也不下发
    payload = client.get(CATALOG).json()
    assert payload == {"version": 0, "payload_hash": None, "signature": None,
                       "expires_at": None, "not_modified": True, "models": []}


def test_node_catalog_returns_published_bundle(client, conn, now):
    bundle = _publish(conn, now)
    response = client.get(CATALOG)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == {"version", "payload_hash", "signature", "expires_at",
                            "not_modified", "models"}
    assert payload["version"] == bundle["version"] == 1
    assert payload["not_modified"] is False
    assert len(payload["models"]) == 6
    assert payload["payload_hash"] == bundle["payload_hash"]
    assert signing.verify(payload["payload_hash"], payload["signature"]) is True
    assert set(payload["models"][0]) == {
        "vendor", "canonical", "aliases", "context_window", "tokenizer_family",
        "tokenizer_version", "tokenizer_hash", "effective_at"}


def test_node_catalog_since_current_is_not_modified(client, conn, now):
    bundle = _publish(conn, now)
    payload = client.get(CATALOG, params={"since": bundle["version"]}).json()
    assert payload["version"] == 1 and payload["not_modified"] is True
    assert payload["models"] == []
    older = client.get(CATALOG, params={"since": 0}).json()
    assert older["not_modified"] is False and len(older["models"]) == 6


@pytest.mark.parametrize("since", ["abc", "-1", "1.5"])
def test_node_catalog_rejects_bad_since(client, since):
    response = client.get(CATALOG, params={"since": since})
    assert response.status_code == 400
    assert _error(response)["field"] == "since"


def test_node_state_reports_server_version(client, conn, now):
    _publish(conn, now)
    ok = client.post(STATE, json={"applied_version": 1, "drift": {}})
    assert ok.status_code == 200
    assert ok.json() == {"accepted": True, "server_version": 1}
    behind = client.post(STATE, json={"applied_version": 0,
                                      "drift": {"gpt-4o-mini": "tokenizer_version"}})
    assert behind.json() == {"accepted": False, "server_version": 1}
    errored = client.post(STATE, json={"applied_version": 1, "error_class": "sync_rejected"})
    assert errored.json() == {"accepted": False, "server_version": 1}


def test_node_state_requires_feature(conn, monkeypatch, now):
    client = build_client(conn, monkeypatch, node=NODE_PRINCIPAL, feature=False, now=now)
    response = client.post(STATE, json={"applied_version": 1})
    assert response.status_code == 503
    error = _error(response)
    assert error["code"] == 50001 and error["reason"] == "feature_disabled"


@pytest.mark.parametrize("body,field", [
    ({}, "applied_version"),
    ({"applied_version": -1}, "applied_version"),
    ({"applied_version": True}, "applied_version"),
    ({"applied_version": "1"}, "applied_version"),
    ({"applied_version": 1, "drift": {"content": "x"}}, "drift.content"),
    ({"applied_version": 1, "drift": {"messages": []}}, "drift.messages"),
    ({"applied_version": 1, "error_class": "x" * 65}, "error_class"),
])
def test_node_state_validates_body(client, body, field):
    response = client.post(STATE, json=body)
    assert response.status_code == 400
    assert _error(response)["field"] == field


# --------------------------------------------------------------------------- admin
def test_admin_scope_is_enforced(conn, monkeypatch, now):
    readonly = build_client(conn, monkeypatch, admin=READONLY_PRINCIPAL, node=NODE_PRINCIPAL,
                            now=now)
    assert readonly.get(BUNDLES).status_code == 200
    denied = readonly.post(BUNDLES)
    assert denied.status_code == 403
    assert _error(denied)["code"] == 40301

    none = build_client(conn, monkeypatch, admin=NO_SCOPE_PRINCIPAL, node=NODE_PRINCIPAL,
                        now=now)
    assert none.get(BUNDLES).status_code == 403


def test_admin_create_and_publish_flow(client):
    created = client.post(BUNDLES)
    assert created.status_code == 201, created.text
    bundle = created.json()["bundle"]
    assert bundle["state"] == "draft" and bundle["version"] == 1
    assert bundle["models_count"] == 6
    assert created.json()["auto_published"] is False

    published = client.post(f"{BUNDLES}/{bundle['bundle_id']}/publish")
    assert published.status_code == 200, published.text
    assert published.json()["bundle"]["state"] == "published"
    assert published.json()["bundle"]["signature"].startswith("hmac-sha256:")

    listing = client.get(BUNDLES).json()
    assert [item["version"] for item in listing["items"]] == [1]
    assert listing["has_more"] is False
    state = client.get(ADMIN_STATE).json()
    assert state["server_version"] == 1 and state["items"] == []


def test_admin_create_auto_publish(conn, monkeypatch, now):
    client = build_client(conn, monkeypatch, admin=ADMIN_PRINCIPAL, node=NODE_PRINCIPAL,
                          feature=True, auto_publish=True, now=now)
    created = client.post(BUNDLES)
    assert created.status_code == 201
    assert created.json()["auto_published"] is True
    assert created.json()["bundle"]["state"] == "published"


def test_admin_publish_unknown_bundle_is_404(client):
    response = client.post(f"{BUNDLES}/{uuid.uuid4()}/publish")
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


def test_admin_publish_twice_is_40919(client):
    bundle = client.post(BUNDLES).json()["bundle"]
    assert client.post(f"{BUNDLES}/{bundle['bundle_id']}/publish").status_code == 200
    again = client.post(f"{BUNDLES}/{bundle['bundle_id']}/publish")
    assert again.status_code == 409
    assert _error(again)["code"] == 40919


def test_admin_rollback_flow(client):
    first = client.post(BUNDLES).json()["bundle"]
    client.post(f"{BUNDLES}/{first['bundle_id']}/publish")
    second = client.post(BUNDLES).json()["bundle"]
    client.post(f"{BUNDLES}/{second['bundle_id']}/publish")

    rolled = client.post(f"{BUNDLES}/{first['bundle_id']}/rollback")
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["bundle"]["version"] == 3
    assert rolled.json()["bundle"]["source"] == "rollback"
    current = client.get(CATALOG).json()
    assert current["version"] == 3
    # 版本号 / TTL 参与 hash，所以 hash 会变；回滚的语义是「models 快照回到 v1」
    assert [m["canonical"] for m in current["models"]] == [
        "claude-3-5-sonnet", "deepseek-chat", "glm-4-plus", "gpt-4o", "gpt-4o-mini",
        "qwen2.5-72b-instruct"]                       # 按 (vendor, canonical) 排序


def test_admin_rollback_to_current_is_conflict(client):
    bundle = client.post(BUNDLES).json()["bundle"]
    client.post(f"{BUNDLES}/{bundle['bundle_id']}/publish")
    response = client.post(f"{BUNDLES}/{bundle['bundle_id']}/rollback")
    assert response.status_code == 409


def test_admin_state_lists_node_state(client):
    _publish_draft = client.post(BUNDLES).json()["bundle"]
    client.post(f"{BUNDLES}/{_publish_draft['bundle_id']}/publish")
    client.post(STATE, json={"applied_version": 1})
    payload = client.get(ADMIN_STATE).json()
    assert payload["server_version"] == 1
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert item["node_id"] == NODE_PRINCIPAL["node_id"]
    assert item["applied_version"] == 1 and item["in_sync"] is True
    assert item["error_class"] is None


def test_request_id_is_echoed(client):
    node = client.get(CATALOG, headers={"X-Request-Id": "rid-m18-node"})
    admin = client.get(BUNDLES, headers={"X-Request-Id": "rid-m18-admin"})
    assert node.headers["X-Request-Id"] == "rid-m18-node"
    assert admin.headers["X-Request-Id"] == "rid-m18-admin"
    failed = client.get(CATALOG, params={"since": "bad"},
                        headers={"X-Request-Id": "rid-m18-bad"})
    assert failed.status_code == 400
    assert failed.headers["X-Request-Id"] == "rid-m18-bad"
    assert failed.json()["error"]["request_id"] == "rid-m18-bad"
