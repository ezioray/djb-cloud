# SPDX-License-Identifier: AGPL-3.0-or-later
"""C14b 抽检路由用例（6 条端点 / AdminAuth fail-closed / 错误信封 / 开关）。

覆盖：401 / 403 / 40001 / 40401 / 40919 / 503+50001、open 201 含 seed、reveal→verify 一致、
result→passed、请求 id 回显、列表过滤分页。
"""
from __future__ import annotations

import hashlib

import pytest

from app.integrity import facts

from kit import (SAMPLING_ADMIN_PRINCIPAL, build_sampling_client, sampling_contributions)

EPOCHS = "/api/v1/admin/supply/integrity/sampling/epochs"
DRAWS = "/api/v1/admin/supply/integrity/sampling/draws"
VERIFY = "/api/v1/admin/supply/integrity/sampling/verify"

EPOCH_KEYS = {"id", "epoch_no", "seed_commit", "seed_reveal", "contributions", "state",
              "draw_count", "committed_at", "revealed_at", "created_at"}
DRAW_KEYS = {"id", "epoch_id", "node_id", "model", "weight", "rank", "challenge_id",
             "status", "level", "detail", "created_at", "resolved_at"}


@pytest.fixture
def client(conn, monkeypatch, fixed_tokenizer):
    return build_sampling_client(conn, monkeypatch, admin=SAMPLING_ADMIN_PRINCIPAL)


def _open(client, *, epoch_no=1, draw_count=1, contributions=None):
    return client.post(EPOCHS, json={
        "epoch_no": epoch_no, "draw_count": draw_count,
        "contributions": contributions or sampling_contributions(
            ("node-alpha", "openai/gpt-4o", 100))})


def _reveal(client, opened):
    payload = opened.json() if hasattr(opened, "json") else opened
    return client.post(f"{EPOCHS}/{payload['epoch']['id']}/reveal",
                       json={"seed": payload["seed"]})


# ───────────────────────────────────────────────────────── 鉴权
def test_open_requires_admin_auth(conn, monkeypatch, fixed_tokenizer):
    client = build_sampling_client(conn, monkeypatch, admin=None)
    response = _open(client, epoch_no=1)
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == 40101
    assert "未接线" in error["message"]
    assert response.headers["X-Request-Id"]


def test_write_requires_scope(conn, monkeypatch, fixed_tokenizer):
    client = build_sampling_client(conn, monkeypatch, admin={
        "admin_id": "admin-readonly", "scopes": ["integrity.read"]})
    assert _open(client, epoch_no=1).status_code == 403
    assert client.get(EPOCHS).status_code == 200


def test_invalid_principal_401(conn, monkeypatch, fixed_tokenizer):
    client = build_sampling_client(conn, monkeypatch, admin={"scopes": ["*"]})
    assert client.get(EPOCHS).status_code == 401


# ───────────────────────────────────────────────────────── open / reveal
def test_open_returns_201_with_commit_and_seed(client):
    response = _open(client, epoch_no=11)
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"epoch", "seed"}
    assert set(body["epoch"]) == EPOCH_KEYS
    assert body["epoch"]["state"] == "committed"
    assert body["epoch"]["seed_reveal"] is None
    assert body["epoch"]["seed_commit"] == hashlib.sha256(
        bytes.fromhex(body["seed"])).hexdigest()
    assert response.headers["X-Request-Id"]


def test_open_duplicate_epoch_returns_409(client):
    assert _open(client, epoch_no=12).status_code == 201
    response = _open(client, epoch_no=12)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40919
    assert response.json()["error"]["reason"] == "epoch_exists"


def test_reveal_then_verify_consistent(client):
    opened = _open(client, epoch_no=13, draw_count=2, contributions=
                   sampling_contributions(("node-alpha", "openai/gpt-4o", 100),
                                          ("node-beta", "openai/gpt-4o", 50))).json()
    revealed = _reveal(client, opened)
    assert revealed.status_code == 200
    body = revealed.json()
    assert set(body) == {"epoch", "draws", "idempotent"}
    assert body["idempotent"] is False
    assert len(body["draws"]) == 2
    assert all(set(draw) == DRAW_KEYS for draw in body["draws"])
    assert all(draw["status"] == "pending" for draw in body["draws"])

    detail = client.get(f"{EPOCHS}/{opened['epoch']['id']}")
    assert detail.status_code == 200
    assert len(detail.json()["draws"]) == 2

    verified = client.post(VERIFY, json={"epoch_id": opened["epoch"]["id"]})
    assert verified.status_code == 200
    assert verified.json()["consistent"] is True
    assert verified.json()["commit_ok"] is True


def test_reveal_wrong_seed_409(client):
    opened = _open(client, epoch_no=14).json()
    response = client.post(f"{EPOCHS}/{opened['epoch']['id']}/reveal",
                           json={"seed": "00" * 32})
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "seed_mismatch"


def test_reveal_before_epoch_exists_404(client):
    response = client.post(f"{EPOCHS}/00000000-0000-7000-8000-000000000000/reveal",
                           json={"seed": "ab" * 32})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


# ───────────────────────────────────────────────────────── 结果回填
def test_record_result_passed_and_repeat(client):
    opened = _open(client, epoch_no=15).json()
    draw = _reveal(client, opened).json()["draws"][0]
    evidence = {"challenge_id": draw["challenge_id"], "model": draw["model"],
                "result": "tokenizer_match", "usage_prompt_tokens": 100}
    result = client.post(f"{DRAWS}/{draw['id']}/result", json={"evidence": evidence})
    assert result.status_code == 200
    body = result.json()
    assert set(body) == {"draw", "attestation"}
    assert body["draw"]["status"] == "passed"
    assert body["draw"]["level"] == "L3"
    repeat = client.post(f"{DRAWS}/{draw['id']}/result", json={"evidence": evidence})
    assert repeat.status_code == 409
    assert repeat.json()["error"]["reason"] == "draw_resolved"


def test_record_result_requires_evidence(client):
    opened = _open(client, epoch_no=16).json()
    draw = _reveal(client, opened).json()["draws"][0]
    response = client.post(f"{DRAWS}/{draw['id']}/result", json={"evidence": {}})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


# ───────────────────────────────────────────────────────── 入参 / 开关 / 列表
@pytest.mark.parametrize("payload", [
    {"epoch_no": 1, "draw_count": 1},
    {"epoch_no": 0, "draw_count": 1,
     "contributions": [{"node_id": "n", "model": "m", "weight": 1}]},
    {"epoch_no": 1, "draw_count": -1,
     "contributions": [{"node_id": "n", "model": "m", "weight": 1}]},
    {"epoch_no": 1, "draw_count": 1,
     "contributions": [{"node_id": "n", "model": "m", "weight": 1, "x": 2}]},
])
def test_open_bad_body_40001(client, payload):
    response = client.post(EPOCHS, json=payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_bad_epoch_id_40001(client):
    assert client.get(f"{EPOCHS}/not-a-uuid").status_code == 400


def test_feature_off_write_503_read_ok(conn, monkeypatch, fixed_tokenizer):
    enabled = build_sampling_client(conn, monkeypatch, admin=SAMPLING_ADMIN_PRINCIPAL,
                                    feature=True)
    opened = _open(enabled, epoch_no=17).json()
    disabled = build_sampling_client(conn, monkeypatch, admin=SAMPLING_ADMIN_PRINCIPAL,
                                     feature=False)
    write = _open(disabled, epoch_no=18)
    assert write.status_code == 503
    assert write.json()["error"]["code"] == 50001
    assert write.json()["error"]["reason"] == "feature_disabled"
    assert disabled.get(EPOCHS).status_code == 200
    assert disabled.get(EPOCHS).json()["items"][0]["id"] == opened["epoch"]["id"]


def test_list_filters_and_pagination(client):
    for epoch_no in (21, 22, 23):
        assert _open(client, epoch_no=epoch_no).status_code == 201
    page1 = client.get(EPOCHS, params={"limit": 2}).json()
    assert len(page1["items"]) == 2 and page1["has_more"] is True
    page2 = client.get(EPOCHS, params={"limit": 2,
                                       "cursor": page1["next_cursor"]}).json()
    assert len(page2["items"]) == 1 and page2["has_more"] is False
    assert client.get(EPOCHS, params={"state": "revealed"}).json()["items"] == []
    assert client.get(EPOCHS, params={"state": "bogus"}).status_code == 400


def test_routes_and_scopes_are_as_declared():
    from app.integrity.sampling_router import router as sampling_router

    paths = {(route.path, tuple(sorted(route.methods))) for route in sampling_router.routes}
    assert (EPOCHS, ("GET",)) in paths
    assert (EPOCHS, ("POST",)) in paths
    assert (EPOCHS + "/{epoch_id}", ("GET",)) in paths
    assert (EPOCHS + "/{epoch_id}/reveal", ("POST",)) in paths
    assert (DRAWS + "/{draw_id}/result", ("POST",)) in paths
    assert (VERIFY, ("POST",)) in paths
    assert facts.SAMPLING_FLAG == "supply.sampling.enabled"
