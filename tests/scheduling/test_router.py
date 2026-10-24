# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP 契约（spec 1.2.x 的 6 个 M04 操作 / 00-conventions §5 / M04 §9 安全）。

重点在三件容易做错的事：

* **fail-closed**：四个鉴权钩子未接线时一律 401，绝不静默放行（只有公开快照免鉴权）；
* **错误信封**：``{error:{type, code, message, request_id}}``，``code`` 是整数；
* **越权**：请求体伪造 ``tenant_id`` → 403，不带进决策。
"""
from __future__ import annotations

import uuid

import pytest

from app.scheduling import facts

QUOTES = "/api/v1/schedule/quotes"
BIDS = "/api/v1/schedule/bids"
ROUTE = "/api/v1/schedule/route"
REPLAY = "/api/v1/schedule/replay"


def _error(response) -> dict:
    payload = response.json()
    assert set(payload) >= {"error"}
    error = payload["error"]
    assert isinstance(error["code"], int)
    assert error["message"]
    assert error["request_id"]
    assert error["type"]
    return error


# --------------------------------------------------------------------------- fail-closed
@pytest.mark.parametrize("method,path,body", [
    ("post", QUOTES, {"access": "A1", "model": "m1", "unit": "token", "price_min": "8.00",
                      "ttl_s": 60}),
    ("post", BIDS, {"model": "m1", "min_price": "6.00", "max_price": "9.50"}),
    ("post", ROUTE, {"model": "m1", "kind": "realtime"}),
    ("post", REPLAY, {"from": "2026-10-23T00:00:00Z", "to": "2026-10-24T00:00:00Z"}),
    ("get", "/api/v1/schedule/decisions/" + str(uuid.uuid4()), None),
])
def test_endpoints_are_fail_closed_without_auth(client, method, path, body):
    response = getattr(client, method)(path, json=body) if body is not None \
        else getattr(client, method)(path)
    assert response.status_code == 401
    error = _error(response)
    assert error["code"] == 40101
    assert error["reason"] == "auth_unavailable"


def test_snapshot_is_public(client, api_schema):
    from schedulingkit import seed_capacity, seed_node

    seed_node(api_schema, "n_pub")
    seed_capacity(api_schema, "n_pub", models=("m_pub",))
    response = client.get("/api/v1/schedule/snapshot/latest")
    assert response.status_code == 200
    assert response.json()["period"] == "latest"


# --------------------------------------------------------------------------- 报价
def test_create_quote_returns_201_and_is_content_idempotent(client, auth):
    body = {"access": "A1", "model": "m1", "unit": "token", "price_min": "8.00",
            "price_max": "10.00", "ttl_s": 600}
    first = client.post(QUOTES, json=body, headers={"X-Request-Id": "req-1"})
    assert first.status_code == 201
    assert first.headers["X-Request-Id"] == "req-1"
    payload = first.json()
    assert set(payload) >= {"quote_id", "state", "quote_version", "expires_at"}
    assert payload["state"] == "active"
    assert payload["created"] is True

    second = client.post(QUOTES, json=body)
    assert second.status_code == 201
    assert second.json()["quote_id"] == payload["quote_id"]
    assert second.json()["quote_version"] == payload["quote_version"]
    assert second.json()["created"] is False


def test_create_quote_rejects_over_precision(client, auth):
    response = client.post(QUOTES, json={"access": "A1", "model": "m1", "unit": "token",
                                        "price_min": "8.005", "ttl_s": 60})
    assert response.status_code == 400
    error = _error(response)
    assert error["code"] == 40001
    assert error["reason"] == "amount_precision"        # INV-13：不四舍五入


@pytest.mark.parametrize("patch", [
    {"ttl_s": None},                                    # 必填
    {"ttl_s": "60"},                                    # 类型错
    {"access": "A9"},                                   # 枚举外
    {"price_min": "10.00", "price_max": "9.00"},        # 区间倒置（INV-01）
    {"unit": ""},                                       # 必填
    {"model": ""},                                      # 必填
])
def test_create_quote_validates_the_request(client, auth, patch):
    body = {"access": "A1", "model": "m1", "unit": "token", "price_min": "8.00", "ttl_s": 60}
    body.update(patch)
    response = client.post(QUOTES, json=body)
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_create_quote_cannot_impersonate_another_node(client, auth):
    response = client.post(QUOTES, json={"node_id": "n_other", "access": "A1", "model": "m1",
                                        "unit": "token", "price_min": "8.00", "ttl_s": 60})
    assert response.status_code == 403
    assert _error(response)["code"] == 40303


def test_quote_for_unknown_node_is_404(client, auth):
    response = client.post(QUOTES, headers={"X-Client-Key": "n_ghost"},
                           json={"access": "A1", "model": "m1", "unit": "token",
                                 "price_min": "8.00", "ttl_s": 60})
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


# --------------------------------------------------------------------------- 出价
def test_create_bid_returns_201(client, auth):
    response = client.post(BIDS, json={"model": "m1", "min_price": "6.00",
                                       "max_price": "9.50", "window_seconds": 600})
    assert response.status_code == 201
    payload = response.json()
    assert set(payload) >= {"bid_id", "state", "expires_at"}
    assert payload["state"] == "active"
    assert payload["strategy"] == "mid"


def test_create_bid_validates_strategy_and_interval(client, auth):
    assert client.post(BIDS, json={"model": "m1", "strategy": "auction"}).status_code == 400
    assert client.post(BIDS, json={"model": "m1", "min_price": "9.00",
                                   "max_price": "6.00"}).status_code == 400


# --------------------------------------------------------------------------- 路由
def test_route_returns_201_with_a_decision(client, auth):
    client.post(QUOTES, json={"access": "A1", "model": "m1", "unit": "token",
                              "price_min": "8.00", "price_max": "10.00", "ttl_s": 600})
    response = client.post(ROUTE, json={"model": "m1", "kind": "realtime",
                                       "max_price": "9.50"})
    assert response.status_code == 201
    payload = response.json()
    assert set(payload) >= {"decision_id", "chosen", "quote_version", "decided_at"}
    assert payload["chosen"]["node_id"] == auth["node_id"]
    assert payload["price"]["amount"] == "8.75"          # mid(8.00, 9.50)

    # 决策下钻
    detail = client.get(f"/api/v1/schedule/decisions/{payload['decision_id']}")
    assert detail.status_code == 200
    assert detail.json()["chosen"]["node_id"] == auth["node_id"]


def test_route_without_supply_returns_45001_with_actions(client, auth):
    response = client.post(ROUTE, json={"model": "unknown-model", "kind": "realtime"})
    assert response.status_code == 503
    error = _error(response)
    assert error["code"] == 45001
    assert error["reason_codes"]
    assert len(error["actions"]) == 3                   # INV-06：三个可选动作


def test_route_rejects_forged_tenant(client, auth):
    """M04 §9 安全：伪造 tenant_id 必须被拒，不能带进决策。"""
    response = client.post(ROUTE, json={"model": "m1", "kind": "realtime",
                                       "tenant_id": str(uuid.uuid4())})
    assert response.status_code == 403
    assert _error(response)["code"] == 40303


@pytest.mark.parametrize("body", [
    {"model": "m1", "kind": "slow"},                        # 档位非法
    {"model": "m1"},                                        # 缺 kind
    {"model": "m1", "kind": "realtime", "attempt_no": 5},    # INV-12 最多 2 次
    {"model": "m1", "kind": "realtime", "required_access": ["A9"]},
    {"model": "m1", "kind": "realtime", "requested_tokens": 0},
    {"model": "m1", "kind": "realtime", "max_price": "1.234"},
])
def test_route_validates_the_request(client, auth, body):
    response = client.post(ROUTE, json=body)
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_route_is_idempotent_on_the_four_anchors(client, auth):
    client.post(QUOTES, json={"access": "A1", "model": "m1", "unit": "token",
                              "price_min": "8.00", "price_max": "10.00", "ttl_s": 600})
    body = {"model": "m1", "kind": "realtime", "max_price": "9.50"}
    first = client.post(ROUTE, json=body)
    second = client.post(ROUTE, json=body)
    assert first.status_code == second.status_code == 201
    assert first.json()["decision_id"] == second.json()["decision_id"]
    assert second.json()["created"] is False


# --------------------------------------------------------------------------- 复算 / 快照
def test_replay_requires_step_up(client, auth):
    response = client.post(REPLAY, json={"from": "2026-10-22T00:00:00Z",
                                        "to": "2026-10-24T00:00:00Z"})
    assert response.status_code == 424
    assert _error(response)["code"] == 42401


def test_replay_runs_and_returns_202(client, auth):
    response = client.post(REPLAY, headers={"X-Admin-Step-Up": "1"},
                           json={"from": "2026-10-22T00:00:00Z", "to": "2026-10-24T00:00:00Z"})
    assert response.status_code == 202
    payload = response.json()
    assert set(payload) >= {"job_id", "state", "requested_at"}
    assert payload["state"] == "succeeded"
    assert payload["inconsistent"] == 0


def test_replay_validates_the_window(client, auth):
    response = client.post(REPLAY, headers={"X-Admin-Step-Up": "1"},
                           json={"from": "2026-10-24T00:00:00Z", "to": "2026-10-22T00:00:00Z"})
    assert response.status_code == 400
    assert client.post(REPLAY, headers={"X-Admin-Step-Up": "1"},
                       json={"from": "not-a-date", "to": "2026-10-24T00:00:00Z"}).status_code \
        == 400


def test_decision_detail_unknown_is_404(client, auth):
    response = client.get("/api/v1/schedule/decisions/" + str(uuid.uuid4()))
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


def test_snapshot_unknown_period_is_404(client, auth):
    response = client.get("/api/v1/schedule/snapshot/yesterday")
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


def test_error_envelope_matches_spec(client):
    response = client.post(QUOTES, json={})
    error = _error(response)
    assert set(error) >= {"type", "code", "message", "request_id"}
    assert error["type"] == "authentication_error"


def test_oversized_idempotency_key_is_rejected(client, auth):
    response = client.post(QUOTES, headers={"X-DJB-Idempotency-Key": "k" * 500},
                           json={"access": "A1", "model": "m1", "unit": "token",
                                 "price_min": "8.00", "ttl_s": 60})
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_malformed_json_is_rejected(client, auth):
    response = client.post(QUOTES, content=b"{not json",
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert _error(response)["reason"] == "malformed_json"
