# SPDX-License-Identifier: AGPL-3.0-or-later
"""C12 证明路由用例（3 条端点 / NodeAuth·AdminAuth fail-closed / 错误信封 / 开关）。

覆盖：401（未接线 / 主体非法）/ 403（缺 scope）/ 40001（坏 body）/ 404（跨 node）/
409（重放 / 跨 model）/ 503+50001（开关关闭 / tokenizer 未接线）/ 200 形状（Lead 1.2.11 定稿）。
"""
from __future__ import annotations

import pytest

from app.integrity import facts

from kit import (ADMIN_PRINCIPAL, NODE_PRINCIPAL, OTHER_NODE_PRINCIPAL, build_attest_client)

CHALLENGE = "/api/v1/node/upstream/attest/challenge"
EVIDENCE = "/api/v1/node/upstream/attest"
ADMIN_LIST = "/api/v1/admin/supply/integrity/attestations"

ATTESTATION_KEYS = {"id", "node_id", "upstream_id", "model", "level", "state", "source",
                    "tokenizer_version", "evidence_ref", "verified_at", "expires_at"}


@pytest.fixture
def client(conn, monkeypatch, fixed_tokenizer):
    return build_attest_client(conn, monkeypatch, node=NODE_PRINCIPAL,
                               admin=ADMIN_PRINCIPAL, feature=True)


def _challenge(client, **overrides):
    body = {"model": "openai/gpt-4o"}
    body.update(overrides)
    return client.post(CHALLENGE, json=body)


# ───────────────────────────────────────────────────────── 挑战端点
def test_challenge_requires_node_auth(conn, monkeypatch, fixed_tokenizer):
    client = build_attest_client(conn, monkeypatch, node=None, feature=True)
    response = client.post(CHALLENGE, json={"model": "openai/gpt-4o"},
                           headers={"X-Request-Id": "req-c12-1"})
    assert response.status_code == 401
    assert response.headers["X-Request-Id"] == "req-c12-1"
    error = response.json()["error"]
    assert error["code"] == 40101 and error["request_id"] == "req-c12-1"
    assert "未接线" in error["message"]


def test_challenge_invalid_principal_401(conn, monkeypatch, fixed_tokenizer):
    client = build_attest_client(conn, monkeypatch, node={"client_key_id": "kid"}, feature=True)
    assert client.post(CHALLENGE, json={"model": "openai/gpt-4o"}).status_code == 401


def test_challenge_ok_matches_frozen_wire_shape(client):
    response = _challenge(client)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"challenge_id", "model", "upstream_id", "prompt", "nonce",
                         "expires_at"}
    assert body["model"] == "openai/gpt-4o"
    assert body["expires_at"].endswith("Z")
    assert response.headers["X-Request-Id"]


def test_challenge_bad_body_40001(client):
    response = client.post(CHALLENGE, json={"upstream_id": None})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_challenge_feature_off_503(conn, monkeypatch, fixed_tokenizer):
    client = build_attest_client(conn, monkeypatch, node=NODE_PRINCIPAL, feature=False)
    response = _challenge(client)
    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == 50001 and error["reason"] == "feature_disabled"


def test_challenge_tokenizer_unwired_503(conn, monkeypatch):
    client = build_attest_client(conn, monkeypatch, node=NODE_PRINCIPAL, feature=True)
    response = _challenge(client)
    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == 50001 and error["reason"] == "tokenizer_unavailable"


# ───────────────────────────────────────────────────────── 证据端点
def test_evidence_happy_path_l3(client):
    challenge = _challenge(client).json()
    response = client.post(EVIDENCE, json={
        "challenge_id": challenge["challenge_id"], "model": challenge["model"],
        "result": "tokenizer_match", "usage_prompt_tokens": 100,
        "response_hash": "b" * 64, "latency_ms": 42})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"attestation", "event"}
    assert set(body["attestation"]) == ATTESTATION_KEYS
    assert body["attestation"]["level"] == "L3"
    assert set(body["event"]) == {"event_id", "event", "level", "created_at"}
    assert body["event"]["event"] == "level_up"


def test_evidence_mismatch_grades_l2_with_event(client):
    challenge = _challenge(client).json()
    response = client.post(EVIDENCE, json={
        "challenge_id": challenge["challenge_id"], "model": challenge["model"],
        "result": "tokenizer_match", "usage_prompt_tokens": 120})
    assert response.status_code == 200
    body = response.json()
    assert body["attestation"]["level"] == "L2"
    assert body["event"]["event"] == "tokenizer_mismatch"


def test_evidence_replay_returns_409(client):
    challenge = _challenge(client).json()
    payload = {"challenge_id": challenge["challenge_id"], "model": challenge["model"],
               "result": "tokenizer_match", "usage_prompt_tokens": 100}
    assert client.post(EVIDENCE, json=payload).status_code == 200
    replay = client.post(EVIDENCE, json=payload)
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == 40919
    assert replay.json()["error"]["reason"] == "challenge_consumed"


def test_evidence_cross_node_404(client, conn, monkeypatch):
    challenge = _challenge(client).json()
    other = build_attest_client(conn, monkeypatch, node=OTHER_NODE_PRINCIPAL, feature=True)
    response = other.post(EVIDENCE, json={
        "challenge_id": challenge["challenge_id"], "model": challenge["model"],
        "result": "tokenizer_match", "usage_prompt_tokens": 100})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


def test_evidence_bad_body_40001(client):
    response = client.post(EVIDENCE, json={"result": "tokenizer_match"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_evidence_requires_node_auth(conn, monkeypatch, fixed_tokenizer):
    client = build_attest_client(conn, monkeypatch, node=None, feature=True)
    assert client.post(EVIDENCE, json={"model": "x"}).status_code == 401


# ───────────────────────────────────────────────────────── 管理面列表
def test_admin_list_requires_auth(conn, monkeypatch, fixed_tokenizer):
    client = build_attest_client(conn, monkeypatch, node=NODE_PRINCIPAL, admin=None,
                                 feature=True)
    assert client.get(ADMIN_LIST).status_code == 401


def test_admin_list_requires_scope(conn, monkeypatch, fixed_tokenizer):
    client = build_attest_client(conn, monkeypatch, node=NODE_PRINCIPAL,
                                 admin={"admin_id": "admin-1", "scopes": []}, feature=True)
    assert client.get(ADMIN_LIST).status_code == 403
    assert client.get(ADMIN_LIST).json()["error"]["code"] == 40301


def test_admin_list_shape_and_filters(client):
    challenge = _challenge(client).json()
    client.post(EVIDENCE, json={"challenge_id": challenge["challenge_id"],
                                "model": challenge["model"], "result": "inference_ok"})
    listed = client.get(ADMIN_LIST)
    assert listed.status_code == 200
    body = listed.json()
    assert set(body) == {"items", "has_more", "next_cursor"}
    assert len(body["items"]) == 1
    assert set(body["items"][0]) == ATTESTATION_KEYS
    assert body["items"][0]["level"] == "L2"
    assert client.get(ADMIN_LIST, params={"node_id": "node-alpha"}).json()["items"]
    assert client.get(ADMIN_LIST, params={"node_id": "nope"}).json()["items"] == []
    assert client.get(ADMIN_LIST, params={"level": "L3"}).json()["items"] == []
    assert client.get(ADMIN_LIST, params={"level": "bogus"}).status_code == 400


def test_admin_list_readonly_when_feature_off(conn, monkeypatch, fixed_tokenizer):
    enabled = build_attest_client(conn, monkeypatch, node=NODE_PRINCIPAL,
                                  admin=ADMIN_PRINCIPAL, feature=True)
    challenge = _challenge(enabled).json()
    enabled.post(EVIDENCE, json={"challenge_id": challenge["challenge_id"],
                                 "model": challenge["model"], "result": "inference_ok"})
    disabled = build_attest_client(conn, monkeypatch, node=NODE_PRINCIPAL,
                                   admin=ADMIN_PRINCIPAL, feature=False)
    listed = disabled.get(ADMIN_LIST)
    assert listed.status_code == 200
    assert len(listed.json()["items"]) == 1
    assert _challenge(disabled).status_code == 503


def test_routes_only_under_expected_prefixes():
    from app.integrity.attest_router import router as attest_router

    paths = {(route.path, tuple(sorted(route.methods))) for route in attest_router.routes}
    assert (CHALLENGE, ("POST",)) in paths
    assert (EVIDENCE, ("POST",)) in paths
    assert (ADMIN_LIST, ("GET",)) in paths
    assert facts.ATTEST_FLAG == "supply.attestation.enabled"
