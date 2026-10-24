# SPDX-License-Identifier: AGPL-3.0-or-later
"""C14 管理面路由用例（4 条端点 / 鉴权 fail-closed / 错误信封 / 过滤分页 / 开关）。

覆盖：401（未接线）/ 403（缺 scope）/ 40001（坏 body、坏 id）/ 40401（查不到）/
40919（降级 / 同级 / 复核不足）/ 503+50001（开关关闭）/ 201/200 成功路径 / 请求 id 回显。
"""
from __future__ import annotations

import pytest

from app.integrity import facts

from kit import (ADMIN_PRINCIPAL, FIXED_NOW, HIGH_ADMIN_PRINCIPAL, build_client, hold_args)

HOLDS = "/api/v1/admin/supply/integrity/holds"


@pytest.fixture
def make_client(conn, monkeypatch):
    def _make(*, admin=ADMIN_PRINCIPAL, feature=True):
        return build_client(conn, monkeypatch, admin=admin, feature=feature)

    return _make


def _create(client, **overrides):
    return client.post(HOLDS, json=hold_args(**overrides))


# ───────────────────────────────────────────────────────── 鉴权 / 信封
def test_auth_not_wired_returns_401_with_request_id(make_client):
    client = make_client(admin=None)
    response = client.get(HOLDS, headers={"X-Request-Id": "req-fixed-1"})
    assert response.status_code == 401
    assert response.headers["X-Request-Id"] == "req-fixed-1"
    error = response.json()["error"]
    assert error["code"] == 40101
    assert error["type"] == "authentication_error"
    assert error["request_id"] == "req-fixed-1"
    assert "未接线" in error["message"]


def test_missing_scope_returns_403(make_client):
    client = make_client(admin={"admin_id": "admin-1", "scopes": ["integrity.read"]})
    response = client.post(HOLDS, json=hold_args())
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 40301
    # 读接口同一个主体可用
    assert client.get(HOLDS).status_code == 200


def test_invalid_principal_returns_401(make_client):
    client = make_client(admin={"scopes": ["*"]})
    assert client.get(HOLDS).status_code == 401


# ───────────────────────────────────────────────────────── 创建 / 升级
def test_create_hold_returns_201_and_payload(make_client):
    client = make_client()
    response = _create(client, level="I2", base_amount_micro=1_000_000)
    assert response.status_code == 201
    body = response.json()
    assert body["action"] == "created"
    hold = body["hold"]
    assert hold["level"] == "I2"
    assert hold["ratio_bp"] == 8000
    assert hold["frozen_amount_micro"] == 800_000
    assert hold["state"] == "active"
    assert body["event"]["event"] == "created"
    assert response.headers["X-Request-Id"]


def test_i0_post_returns_200_noted_without_hold(make_client):
    response = _create(make_client(), level="I0")
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "noted"
    assert body["hold"] is None
    assert body["event"]["to_level"] == "I0"


def test_escalation_returns_200_and_same_id(make_client):
    client = make_client()
    first = _create(client, level="I1").json()["hold"]
    response = _create(client, level="I4", base_amount_micro=2_000_000)
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "escalated"
    assert body["hold"]["id"] == first["id"]
    assert body["hold"]["ratio_bp"] == 10000


def test_same_level_post_returns_409(make_client):
    client = make_client()
    _create(client, level="I2")
    response = _create(client, level="I2")
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == 40919
    assert error["reason"] == "not_escalation"


@pytest.mark.parametrize("overrides", [
    {"model": ""},
    {"node_id": ""},
    {"level": "X1"},
    {"base_amount_micro": -5},
    {"reason": ""},
    {"evidence_ref": ""},
])
def test_bad_body_returns_40001(make_client, overrides):
    response = _create(make_client(), **overrides)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_non_json_body_returns_40001(make_client):
    response = make_client().post(HOLDS, content=b"not-json",
                                 headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


# ───────────────────────────────────────────────────────── 详情 / 404
def test_get_hold_includes_events(make_client):
    client = make_client()
    hold = _create(client, level="I1").json()["hold"]
    response = client.get(f"{HOLDS}/{hold['id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["hold"]["id"] == hold["id"]
    assert [item["event"] for item in body["events"]] == ["created"]


def test_get_missing_hold_returns_40401(make_client):
    response = make_client().get(f"{HOLDS}/00000000-0000-7000-8000-000000000000")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


def test_invalid_hold_id_returns_40001(make_client):
    response = make_client().get(f"{HOLDS}/not-a-uuid")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


# ───────────────────────────────────────────────────────── 解除
def test_release_flow_and_idempotency(make_client):
    client = make_client()
    hold = _create(client, level="I1").json()["hold"]
    first = client.post(f"{HOLDS}/{hold['id']}/release",
                        json={"reviewers": ["rev-1"], "reason": "clean for 7d"})
    assert first.status_code == 200
    assert first.json()["action"] == "released"
    assert first.json()["hold"]["state"] == "released"
    again = client.post(f"{HOLDS}/{hold['id']}/release",
                        json={"reviewers": ["rev-2"], "reason": "again"})
    assert again.status_code == 200
    assert again.json()["action"] == "unchanged"


def test_release_i2_needs_two_reviewers(make_client):
    client = make_client()
    hold = _create(client, level="I2").json()["hold"]
    response = client.post(f"{HOLDS}/{hold['id']}/release",
                           json={"reviewers": ["rev-1"], "reason": "one"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40919
    assert response.json()["error"]["reason"] == "reviewers_insufficient"


def test_release_i3_requires_high_scope(make_client):
    normal = make_client()
    hold = _create(normal, level="I3").json()["hold"]
    denied = normal.post(f"{HOLDS}/{hold['id']}/release",
                         json={"reviewers": ["rev-1", "rev-2"], "reason": "reviewed"})
    assert denied.status_code == 403
    assert denied.json()["error"]["reason"] == "scope_required"

    high = make_client(admin=HIGH_ADMIN_PRINCIPAL)
    allowed = high.post(f"{HOLDS}/{hold['id']}/release",
                        json={"reviewers": ["rev-1", "rev-2"], "reason": "reviewed"})
    assert allowed.status_code == 200
    assert allowed.json()["hold"]["reviewer_b"] == "rev-2"


def test_release_missing_hold_returns_404(make_client):
    response = make_client().post(
        f"{HOLDS}/00000000-0000-7000-8000-000000000000/release",
        json={"reviewers": ["rev-1"], "reason": "nope"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


# ───────────────────────────────────────────────────────── 列表 / 过滤 / 分页
def test_list_filters_and_pagination(make_client):
    client = make_client()
    for index in range(3):
        assert _create(client, node_id=f"node-{index}", level="I1").status_code == 201

    listed = client.get(HOLDS, params={"state": "active", "node_id": "node-1"})
    assert listed.status_code == 200
    body = listed.json()
    assert [item["node_id"] for item in body["items"]] == ["node-1"]
    assert body["has_more"] is False

    page1 = client.get(HOLDS, params={"state": "all", "limit": 2}).json()
    assert len(page1["items"]) == 2 and page1["has_more"] is True
    page2 = client.get(HOLDS, params={"state": "all", "limit": 2,
                                      "cursor": page1["next_cursor"]}).json()
    assert len(page2["items"]) == 1 and page2["has_more"] is False
    ids = {item["id"] for item in page1["items"]} | {item["id"] for item in page2["items"]}
    assert len(ids) == 3


def test_list_rejects_bad_state_and_limit(make_client):
    client = make_client()
    assert client.get(HOLDS, params={"state": "bogus"}).status_code == 400
    assert client.get(HOLDS, params={"limit": 0}).status_code == 400
    assert client.get(HOLDS, params={"limit": 999}).status_code == 400


# ───────────────────────────────────────────────────────── 开关
def test_feature_disabled_write_is_503_but_reads_work(make_client):
    client = make_client(feature=False)
    response = _create(client, level="I1")
    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == 50001
    assert error["reason"] == "feature_disabled"
    assert client.get(HOLDS).status_code == 200
    assert client.get(HOLDS).json()["items"] == []


def test_feature_disabled_release_is_503(make_client, conn, monkeypatch):
    enabled = make_client()
    hold = _create(enabled, level="I1").json()["hold"]
    disabled = build_client(conn, monkeypatch, admin=ADMIN_PRINCIPAL, feature=False)
    response = disabled.post(f"{HOLDS}/{hold['id']}/release",
                             json={"reviewers": ["rev-1"], "reason": "x"})
    assert response.status_code == 503
    assert response.json()["error"]["reason"] == "feature_disabled"


def test_route_paths_match_task_card(make_client):
    from app.integrity.router import router as integrity_router

    paths = {(route.path, tuple(sorted(route.methods))) for route in integrity_router.routes}
    assert (HOLDS, ("GET",)) in paths
    assert (HOLDS, ("POST",)) in paths
    assert (HOLDS + "/{hold_id}", ("GET",)) in paths
    assert (HOLDS + "/{hold_id}/release", ("POST",)) in paths
    # 只加不改：路由不改 app/api.py，也不出现在 /api/v1 其它前缀下
    assert all(path.startswith("/api/v1/admin/supply/integrity") for path in
               [route.path for route in integrity_router.routes])
    assert facts.MODULE_ID == "M17"
