# SPDX-License-Identifier: AGPL-3.0-or-later
"""十条端点 HTTP 层测试（spec 1.2.4）：错误信封、错误码、鉴权 fail-closed、幂等、分页。

任务卡验收 2/3：十条端点 ⊆ spec、required 字段齐、错误信封 ``{error:{type,code,message,
request_id}}`` 且 ``code`` 为已登记整数；未认证 401/40101；余额不足 402/40201；
锁定期 / 超限 / 自转 422/42240；开关关 409/40902；缺 step-up 424/42401；复核人=发起人 409/40919。
"""
from __future__ import annotations

import uuid

import pytest

from app import points
from app.reputation import cop
from repukit import NOW, as_account, connect, make_client, seed_account

REGISTERED_CODES = {40001, 40101, 40201, 40401, 40902, 40919, 42240, 42401, 50001}


# --------------------------------------------------------------------------- 夹具
@pytest.fixture
def client(migrated):
    return make_client(migrated)


@pytest.fixture
def account(migrated):
    return seed_account(migrated)


def _fund(schema: str, account_id: str, units: int, *, ref: str | None = None) -> None:
    """在独立连接里**提交**一笔计提（路由用另一条连接读，必须已落库）。"""
    ref = ref or f"seed-{uuid.uuid4().hex[:8]}"
    conn = connect(schema)
    try:
        cop.post_earn(conn, account_id, units, source="usage", ref_id=ref,
                      request_id=f"seed-{ref}", lock_days=0, now=NOW)
        conn.commit()
    finally:
        conn.close()


def _enable_transfer(schema: str, **changes) -> None:
    conn = connect(schema)
    try:
        points.update_policy(conn, actor="ops:test", reason="DEV-M07 路由测试",
                             transfer_enabled=True, **changes)
        conn.commit()
    finally:
        conn.close()


def _error(response) -> dict:
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert {"type", "code", "message", "request_id"} <= set(error)
    assert isinstance(error["code"], int) and error["code"] in REGISTERED_CODES
    return error


# --------------------------------------------------------------------------- 读路径
def test_get_reputation_returns_profile_contract(client, account):
    response = client.get("/api/v1/user/reputation", headers=as_account(account))
    assert response.status_code == 200
    body = response.json()
    assert {"score", "tier", "quality_coef", "stability_coef", "window_days",
            "policy_version", "computed_at"} <= set(body)
    assert body["tier"] in ("L1", "L2", "L3", "L4", "L5")
    assert 0 <= body["score"] <= 1000
    assert isinstance(body["reasons"], list)
    assert response.headers["X-Request-Id"]


def test_get_reputation_events_page(client, account):
    response = client.get("/api/v1/user/reputation/events?limit=10", headers=as_account(account))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"data", "page"}
    assert {"has_more", "cursor", "next_cursor"} <= set(body["page"])
    assert body["page"]["has_more"] is False


def test_get_cop_balance_contract(client, account, migrated):
    _fund(migrated, account, 300)
    response = client.get("/api/v1/user/cop", headers=as_account(account))
    assert response.status_code == 200
    body = response.json()
    assert {"available", "locked", "total_earned", "unit", "updated_at"} <= set(body)
    assert body["unit"] == "COP"
    assert body["available"] == 300
    assert body["available"] + body["locked"] == body["total"] == 300


def test_get_cop_ledger_and_pagination(client, account, migrated):
    for index in range(3):
        _fund(migrated, account, 10, ref=f"page-{index}")
    first = client.get("/api/v1/user/cop/ledger?limit=2", headers=as_account(account))
    assert first.status_code == 200
    body = first.json()
    assert set(body) == {"data", "page"}
    assert len(body["data"]) == 2 and body["page"]["has_more"] is True
    for entry in body["data"]:
        assert {"id", "direction", "amount", "source", "status", "created_at"} <= set(entry)
        assert entry["direction"] in ("credit", "debit")
    second = client.get(f"/api/v1/user/cop/ledger?limit=2&cursor={body['page']['next_cursor']}",
                        headers=as_account(account))
    assert second.status_code == 200
    assert len(second.json()["data"]) == 1
    assert second.json()["page"]["has_more"] is False
    assert second.json()["page"]["next_cursor"] is None


def test_ledger_cursor_is_rejected_when_tampered(client, account):
    response = client.get("/api/v1/user/cop/ledger?cursor=not-a-cursor",
                          headers=as_account(account))
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_get_invites_overview(client, account):
    response = client.get("/api/v1/user/cop/invites", headers=as_account(account))
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"data", "totals", "page"}
    assert {"bound", "pending", "earned_units"} <= set(body["totals"])


# --------------------------------------------------------------------------- 兑换
def test_create_redemption_then_read_it(client, account, migrated):
    _fund(migrated, account, 500)
    created = client.post("/api/v1/user/cop/redemptions", headers=as_account(account),
                          json={"units": 120, "target": "service_fee"})
    assert created.status_code == 201
    body = created.json()
    assert {"redemption_id", "units", "state", "created_at"} <= set(body)
    assert body["units"] == 120 and body["state"] == "posted"

    fetched = client.get(f"/api/v1/user/cop/redemptions/{body['redemption_id']}",
                         headers=as_account(account))
    assert fetched.status_code == 200
    assert fetched.json()["redemption_id"] == body["redemption_id"]

    balance = client.get("/api/v1/user/cop", headers=as_account(account)).json()
    assert balance["available"] == 380


def test_redemption_is_idempotent_with_header(client, account, migrated):
    _fund(migrated, account, 500)
    headers = dict(as_account(account), **{"X-DJB-Idempotency-Key": "idem-redeem-0001"})
    first = client.post("/api/v1/user/cop/redemptions", headers=headers, json={"units": 100})
    second = client.post("/api/v1/user/cop/redemptions", headers=headers, json={"units": 100})
    assert first.status_code == second.status_code == 201
    assert first.json()["redemption_id"] == second.json()["redemption_id"]
    balance = client.get("/api/v1/user/cop", headers=as_account(account)).json()
    assert balance["available"] == 400                       # 只扣一次


def test_redemption_without_balance_is_402(client, account):
    response = client.post("/api/v1/user/cop/redemptions", headers=as_account(account),
                           json={"units": 50})
    assert response.status_code == 402
    error = _error(response)
    assert error["code"] == 40201
    assert error["type"] == "permission_error"


def test_redemption_validation_is_400(client, account):
    for payload in ({"units": 0}, {"units": -1}, {"units": "abc"}, {}, {"units": 1, "target": "cash"}):
        response = client.post("/api/v1/user/cop/redemptions", headers=as_account(account),
                               json=payload)
        assert response.status_code == 400, payload
        assert _error(response)["code"] == 40001


def test_redemption_body_must_be_json_object(client, account):
    response = client.post("/api/v1/user/cop/redemptions", headers=as_account(account),
                           content=b"not-json")
    assert response.status_code == 400
    assert _error(response)["code"] == 40001


def test_unknown_redemption_is_404(client, account):
    response = client.get(f"/api/v1/user/cop/redemptions/{uuid.uuid4()}",
                          headers=as_account(account))
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


# --------------------------------------------------------------------------- 转让
def test_transfer_is_409_when_switch_off(client, account, migrated):
    other = seed_account(migrated)
    _fund(migrated, account, 200)
    response = client.post("/api/v1/user/cop/transfers", headers=as_account(account),
                           json={"to_account_id": other, "units": 10})
    assert response.status_code == 409
    error = _error(response)
    assert error["code"] == 40902
    assert error["reason"] == "transfer_disabled"


def test_transfer_succeeds_when_switch_on(client, account, migrated):
    other = seed_account(migrated)
    _fund(migrated, account, 200)
    _enable_transfer(migrated)
    headers = dict(as_account(account), **{"X-DJB-Idempotency-Key": "idem-transfer-0001"})
    response = client.post("/api/v1/user/cop/transfers", headers=headers,
                           json={"to_account_id": other, "units": 50})
    assert response.status_code == 201
    body = response.json()
    assert {"transfer_id", "units", "state", "created_at"} <= set(body)
    assert body["state"] == "posted" and body["units"] == 50

    replay = client.post("/api/v1/user/cop/transfers", headers=headers,
                         json={"to_account_id": other, "units": 50})
    assert replay.status_code == 201
    assert replay.json()["transfer_id"] == body["transfer_id"]

    sender = client.get("/api/v1/user/cop", headers=as_account(account)).json()
    receiver = client.get("/api/v1/user/cop", headers=as_account(other)).json()
    assert sender["available"] == 150
    assert receiver["locked"] == 50 and receiver["available"] == 0


def test_self_transfer_is_422(client, account, migrated):
    _fund(migrated, account, 100)
    _enable_transfer(migrated)
    response = client.post("/api/v1/user/cop/transfers", headers=as_account(account),
                           json={"to_account_id": account, "units": 10})
    assert response.status_code == 422
    error = _error(response)
    assert error["code"] == 42240 and error["reason"] == "self_transfer"


def test_transfer_over_limit_is_422(client, account, migrated):
    other = seed_account(migrated)
    _fund(migrated, account, 5_000)
    _enable_transfer(migrated, per_transfer_max_units=100)
    response = client.post("/api/v1/user/cop/transfers", headers=as_account(account),
                           json={"to_account_id": other, "units": 101})
    assert response.status_code == 422
    assert _error(response)["code"] == 42240


# --------------------------------------------------------------------------- 鉴权 fail-closed
def test_missing_principal_is_401(migrated):
    client = make_client(migrated, with_principal=False)
    response = client.get("/api/v1/user/cop")
    assert response.status_code == 401
    error = _error(response)
    assert error["code"] == 40101
    assert error["type"] == "authentication_error"


def test_missing_admin_resolver_is_401(migrated):
    client = make_client(migrated, with_admin=False)
    response = client.get("/api/v1/admin/reputation/scores")
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_non_admin_role_is_404(migrated):
    client = make_client(migrated, roles=("user",))
    response = client.get("/api/v1/admin/reputation/scores")
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


# --------------------------------------------------------------------------- 后台授予
def test_grant_matrix(client, account):
    headers = dict(as_account("admin:alice"),
                   **{"X-Admin-Step-Up": "stepup-token", "X-Admin-Approver": "admin:bob"})
    body = {"account_id": account, "kind": "grant", "units": 100, "reason": "运营补发",
            "approval_id": "APR-1"}
    response = client.post("/api/v1/admin/reputation/grants", headers=headers, json=body)
    assert response.status_code == 201
    payload = response.json()
    assert {"grant_id", "account_id", "kind", "units", "reason", "created_at"} <= set(payload)
    assert payload["units"] == 100

    balance = client.get("/api/v1/user/cop", headers=as_account(account)).json()
    assert balance["available"] == 100


def test_grant_requires_step_up(client, account):
    response = client.post("/api/v1/admin/reputation/grants", headers=as_account("admin:alice"),
                           json={"account_id": account, "kind": "grant", "units": 1,
                                 "reason": "补发"})
    assert response.status_code == 424
    error = _error(response)
    assert error["code"] == 42401
    assert error["type"] == "authentication_error"


def test_grant_rejects_invalid_step_up(migrated, account):
    client = make_client(migrated, step_up_valid=False)
    response = client.post("/api/v1/admin/reputation/grants",
                           headers={"X-Admin-Step-Up": "expired"},
                           json={"account_id": account, "kind": "grant", "units": 1,
                                 "reason": "补发"})
    assert response.status_code == 424
    assert _error(response)["code"] == 42401


def test_grant_rejects_self_approval(migrated, account):
    client = make_client(migrated, admin_actor="admin:alice")      # 发起人 = 复核人
    headers = dict(as_account("admin:alice"),
                   **{"X-Admin-Step-Up": "ok", "X-Admin-Approver": "admin:alice"})
    response = client.post("/api/v1/admin/reputation/grants", headers=headers,
                           json={"account_id": account, "kind": "grant", "units": 1,
                                 "reason": "补发"})
    assert response.status_code == 409
    error = _error(response)
    assert error["code"] == 40919 and error["reason"] == "approver_is_actor"


def test_grant_unknown_account_is_404(client):
    headers = dict(as_account("admin:alice"),
                   **{"X-Admin-Step-Up": "ok", "X-Admin-Approver": "admin:bob"})
    response = client.post("/api/v1/admin/reputation/grants", headers=headers,
                           json={"account_id": "user:missing", "kind": "grant", "units": 1,
                                 "reason": "补发"})
    assert response.status_code == 404
    assert _error(response)["code"] == 40401


def test_grant_is_idempotent(client, account):
    headers = dict(as_account("admin:alice"),
                   **{"X-Admin-Step-Up": "ok", "X-Admin-Approver": "admin:bob",
                      "X-DJB-Idempotency-Key": "idem-grant-router-1"})
    body = {"account_id": account, "kind": "grant", "units": 30, "reason": "补发"}
    first = client.post("/api/v1/admin/reputation/grants", headers=headers, json=body)
    second = client.post("/api/v1/admin/reputation/grants", headers=headers, json=body)
    assert first.status_code == second.status_code == 201
    assert first.json()["grant_id"] == second.json()["grant_id"]
    assert client.get("/api/v1/user/cop", headers=as_account(account)).json()["available"] == 30


def test_admin_scores_list_and_filters(client, account, migrated):
    _fund(migrated, account, 1)
    from app.reputation import events

    conn = connect(migrated)
    try:
        events.record_metrics(conn, account, {"online_rate": 960}, ref_id="scores-1",
                              occurred_at=NOW)
        events.refresh_score(conn, account, now=NOW)
        conn.commit()
    finally:
        conn.close()

    headers = as_account("admin:alice")
    response = client.get("/api/v1/admin/reputation/scores?limit=10", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"data", "page"}
    row = next(item for item in body["data"] if item["account_id"] == account)
    assert {"account_id", "score", "tier", "computed_at"} <= set(row)

    filtered = client.get("/api/v1/admin/reputation/scores?tier=L2&min_score=0", headers=headers)
    assert filtered.status_code == 200
    assert all(item["tier"] == "L2" for item in filtered.json()["data"])

    bad = client.get("/api/v1/admin/reputation/scores?tier=L9", headers=headers)
    assert bad.status_code == 400
    assert _error(bad)["code"] == 40001


def test_request_id_is_echoed(client, account):
    response = client.get("/api/v1/user/cop", headers=dict(as_account(account),
                                                           **{"X-Request-Id": "req-abc-123"}))
    assert response.headers["X-Request-Id"] == "req-abc-123"


def test_idempotency_key_length_is_validated(client, account):
    response = client.post("/api/v1/user/cop/redemptions",
                           headers=dict(as_account(account), **{"X-DJB-Idempotency-Key": "short"}),
                           json={"units": 1})
    assert response.status_code == 400
    assert _error(response)["code"] == 40001
