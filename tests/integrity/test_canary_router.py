# SPDX-License-Identifier: AGPL-3.0-or-later
"""C13 canary 路由用例（5 条端点 / AdminAuth fail-closed / 错误信封 / 开关）。

覆盖：401 / 403 / 40001 / 40401 / 40919 / 503+50001、issue 201、result passed/replay、
stats、expire、列表过滤、请求 id 回显。
"""
from __future__ import annotations

import pytest

from app.integrity import facts

from kit import CANARY_ADMIN_PRINCIPAL, build_canary_client

RUNS = "/api/v1/admin/supply/integrity/canary/runs"
STATS = "/api/v1/admin/supply/integrity/canary/stats"
EXPIRE = "/api/v1/admin/supply/integrity/canary/expire"

ANSWERS = {
    "arith.2plus2": "4",
    "capital.france": "Paris",
    "echo.token": "Sure — CANARY-7F3A.",
    "sequence.evens": "2, 4, 6, 8",
    "color.hex": "#FF0000",
}

ISSUE_KEYS = {"run_id", "node_id", "upstream_id", "model", "prompt_key", "selection",
              "prompt", "nonce", "max_tokens", "issued_at", "deadline_at", "status"}
RUN_KEYS = {"id", "node_id", "upstream_id", "model", "prompt_id", "status",
            "response_hash", "score", "detail", "created_at", "deadline_at", "resolved_at"}


@pytest.fixture
def client(conn, monkeypatch):
    return build_canary_client(conn, monkeypatch, admin=CANARY_ADMIN_PRINCIPAL)


def _issue(client, *, node="node-alpha", model="openai/gpt-4o"):
    return client.post(RUNS, json={"node_id": node, "model": model})


# ───────────────────────────────────────────────────────── 鉴权
def test_issue_requires_admin_auth(conn, monkeypatch):
    client = build_canary_client(conn, monkeypatch, admin=None)
    response = _issue(client)
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == 40101
    assert "未接线" in error["message"]
    assert response.headers["X-Request-Id"]


def test_write_requires_scope(conn, monkeypatch):
    client = build_canary_client(conn, monkeypatch, admin={
        "admin_id": "admin-readonly", "scopes": ["integrity.read"]})
    assert _issue(client).status_code == 403
    assert client.get(RUNS).status_code == 200


def test_invalid_principal_401(conn, monkeypatch):
    client = build_canary_client(conn, monkeypatch, admin={"scopes": ["*"]})
    assert client.get(RUNS).status_code == 401


# ───────────────────────────────────────────────────────── issue / result
def test_issue_returns_201_with_synthetic_prompt(client):
    response = _issue(client)
    assert response.status_code == 201
    body = response.json()
    assert set(body) == ISSUE_KEYS
    assert body["status"] == "issued"
    assert body["prompt_key"] in facts.CANARY_PROMPT_KEYS
    assert body["nonce"] in body["prompt"]
    assert body["deadline_at"].endswith("Z")


def test_issue_single_issued_conflict(client):
    assert _issue(client).status_code == 201
    second = _issue(client)
    assert second.status_code == 409
    assert second.json()["error"]["code"] == 40919
    assert second.json()["error"]["reason"] == "run_pending"


def test_result_pass_then_replay_409(client):
    issued = _issue(client).json()
    answer = ANSWERS[issued["prompt_key"]]
    response = client.post(f"{RUNS}/{issued['run_id']}/result",
                           json={"node_id": "node-alpha", "response_text": answer,
                                 "usage_prompt_tokens": 9, "latency_ms": 12})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"run", "match"}
    assert set(body["run"]) == RUN_KEYS
    assert body["run"]["status"] == "passed"
    assert body["match"]["passed"] is True
    assert len(body["match"]["response_hash"]) == 64
    replay = client.post(f"{RUNS}/{issued['run_id']}/result",
                         json={"node_id": "node-alpha", "response_text": answer})
    assert replay.status_code == 409
    assert replay.json()["error"]["reason"] == "run_resolved"


def test_result_wrong_answer_failed(client):
    issued = _issue(client).json()
    response = client.post(f"{RUNS}/{issued['run_id']}/result",
                           json={"node_id": "node-alpha",
                                 "response_text": "definitely not the answer"})
    assert response.status_code == 200
    assert response.json()["run"]["status"] == "failed"
    assert response.json()["run"]["score"] == 0.0


def test_result_bad_body_and_unknown_run(client):
    issued = _issue(client).json()
    bad = client.post(f"{RUNS}/{issued['run_id']}/result", json={})
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == 40001
    missing = client.post(f"{RUNS}/00000000-0000-7000-8000-000000000000/result",
                          json={"node_id": "node-alpha", "response_text": "4"})
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == 40401
    invalid = client.post(f"{RUNS}/not-a-uuid/result",
                          json={"node_id": "node-alpha", "response_text": "4"})
    assert invalid.status_code == 400


# ───────────────────────────────────────────────────────── stats / expire / list
def test_stats_and_expire(client):
    _issue(client)
    stats = client.get(STATS, params={"node_id": "node-alpha", "model": "openai/gpt-4o"})
    assert stats.status_code == 200
    body = stats.json()
    assert set(body) == {"node_id", "model", "window", "total", "passed", "failed",
                         "missed", "pass_rate"}
    assert body["total"] == 0
    expired = client.post(EXPIRE)
    assert expired.status_code == 200
    assert expired.json()["runs"] == 0                      # 还没到 deadline
    bad = client.get(STATS, params={"node_id": "node-alpha", "model": "openai/gpt-4o",
                                    "window": "abc"})
    assert bad.status_code == 400


def test_list_filters_and_pagination(client):
    for node in ("node-a", "node-b", "node-c"):
        assert _issue(client, node=node).status_code == 201
    page1 = client.get(RUNS, params={"limit": 2}).json()
    assert len(page1["items"]) == 2 and page1["has_more"] is True
    page2 = client.get(RUNS, params={"limit": 2, "cursor": page1["next_cursor"]}).json()
    assert len(page2["items"]) == 1 and page2["has_more"] is False
    assert client.get(RUNS, params={"node_id": "node-b"}).json()["items"][0]["node_id"] == "node-b"
    assert client.get(RUNS, params={"status": "passed"}).json()["items"] == []
    assert client.get(RUNS, params={"status": "bogus"}).status_code == 400


# ───────────────────────────────────────────────────────── 开关 / 路由表
def test_feature_off_write_503_read_ok(conn, monkeypatch):
    enabled = build_canary_client(conn, monkeypatch, admin=CANARY_ADMIN_PRINCIPAL,
                                  feature=True)
    issued = _issue(enabled).json()
    disabled = build_canary_client(conn, monkeypatch, admin=CANARY_ADMIN_PRINCIPAL,
                                   feature=False)
    write = _issue(disabled, node="node-z")
    assert write.status_code == 503
    assert write.json()["error"]["code"] == 50001
    assert write.json()["error"]["reason"] == "feature_disabled"
    assert disabled.get(RUNS).status_code == 200
    assert disabled.get(RUNS).json()["items"][0]["id"] == issued["run_id"]


def test_route_paths_and_flag_name():
    from app.integrity.canary_router import router as canary_router

    paths = {(route.path, tuple(sorted(route.methods))) for route in canary_router.routes}
    assert (RUNS, ("POST",)) in paths
    assert (RUNS, ("GET",)) in paths
    assert (RUNS + "/{run_id}/result", ("POST",)) in paths
    assert (STATS, ("GET",)) in paths
    assert (EXPIRE, ("POST",)) in paths
    assert facts.CANARY_FLAG == "supply.canary.enabled"
