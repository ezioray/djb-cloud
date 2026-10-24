# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP 路由：fail-closed 鉴权、错误信封、逐条受理、分页与 spec 形状（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.metering import facts
from meterkit import NOW, api_headers, receipt


def receipts_usage_count(schema, receipt_id):
    from meterkit import fetch_all

    return fetch_all(schema, "SELECT count(*) FROM usage_records WHERE receipt_id = %s",
                     (receipt_id,))[0][0]


def _post(client, batch, headers=None):
    return client.post("/api/v1/node/receipts", json={"receipts": batch},
                       headers=headers or api_headers())


# ─────────────────────────────────────────────────────── 路由表（route-vs-spec 差集 0）
def test_router_exposes_exactly_the_spec_paths():
    from app.metering import router as router_module

    declared = {(method, route.path)
                for route in router_module.router.routes
                for method in (route.methods or set()) - {"HEAD", "OPTIONS"}}
    assert declared == {
        ("POST", "/api/v1/node/receipts"),
        ("GET", "/api/v1/node/receipts/{receipt_id}"),
        ("GET", "/api/v1/user/usage/summary"),
        ("GET", "/api/v1/user/usage/records"),
        ("GET", "/api/v1/user/billing/export"),
        ("POST", "/api/v1/admin/usage/upstream-bills"),
        ("POST", "/api/v1/admin/usage/corrections"),
    }


# ─────────────────────────────────────────────────────── fail-closed 鉴权
def test_receipts_require_node_auth(client):
    response = _post(client, [receipt(account_id=uuid.uuid4())])
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == 40101
    assert body["error"]["type"] == "authentication_error"
    assert body["error"]["request_id"]
    assert response.headers["X-Request-Id"]


def test_usage_endpoints_require_user_auth(client):
    for path in ("/api/v1/user/usage/summary", "/api/v1/user/usage/records"):
        response = client.get(path)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == 40101


def test_receipt_lookup_requires_node_auth(client):
    response = client.get("/api/v1/node/receipts/rcpt_x")
    assert response.status_code == 401


def test_auth_hook_without_account_is_rejected(client):
    from app.metering import router as router_module

    router_module.set_user_authenticator(lambda request: {"tenant_id": "t1"})
    try:
        response = client.get("/api/v1/user/usage/summary")
        assert response.status_code == 401
    finally:
        router_module.set_user_authenticator(None)


# ─────────────────────────────────────────────────────── 收据批受理
def test_submit_receipts_returns_accepted_and_rejected(client, auth, api_account, api_node):
    good = receipt(account_id=api_account, node_id=api_node)
    bad = receipt(account_id=api_account, node_id=api_node, sig_consumer="")
    response = _post(client, [good, bad])

    assert response.status_code == 200                      # spec: 逐条受理结果 200
    body = response.json()
    assert body["accepted"] == [good["receipt_id"]]
    assert body["duplicates"] == []
    assert body["rejected"][0]["receipt_id"] == bad["receipt_id"]
    assert body["rejected"][0]["code"] == 46001
    assert response.headers["X-Request-Id"]


def test_submit_receipts_is_idempotent(client, auth, api_account, api_node):
    body = receipt(account_id=api_account, node_id=api_node)
    first = _post(client, [body]).json()
    second = _post(client, [body]).json()
    assert first["accepted"] == [body["receipt_id"]]
    assert second["accepted"] == [] and second["duplicates"] == [body["receipt_id"]]
    rows = receipts_usage_count(auth["schema"], body["receipt_id"])
    assert rows == 1


def test_submit_receipts_batch_limits(client, auth, api_account, api_node):
    empty = _post(client, [])
    assert empty.status_code == 400 and empty.json()["error"]["code"] == 40001

    too_many = _post(client, [receipt(account_id=api_account, node_id=api_node)
                              for _ in range(facts.BATCH_MAX + 1)])
    assert too_many.status_code == 413
    assert too_many.json()["error"]["code"] == 40013

    not_a_list = client.post("/api/v1/node/receipts", json={"receipts": "nope"},
                             headers=api_headers())
    assert not_a_list.status_code == 400 and not_a_list.json()["error"]["code"] == 40001


def test_submit_receipts_rejects_malformed_json(client, auth):
    response = client.post("/api/v1/node/receipts", content=b"{not json",
                           headers={**api_headers(), "Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["error"]["reason"] == "malformed_json"


def test_submit_receipts_rejects_other_node_claim(client, auth, api_account, api_node):
    body = receipt(account_id=api_account, node_id=f"n_someone_else_{uuid.uuid4().hex[:8]}")
    response = _post(client, [body])
    assert response.status_code == 200
    rejected = response.json()["rejected"][0]
    assert rejected["code"] == 40001 and rejected["reason"] == "node_identity_mismatch"


def test_submit_receipts_uses_client_key_header_when_present(client, auth, api_account):
    """X-Client-Key 指定节点身份（合并时由 M02 的验签钩子注入）。"""
    from meterkit import seed_node

    other_node = f"n_api_{uuid.uuid4().hex[:8]}"
    seed_node(auth["schema"], other_node)
    body = receipt(account_id=api_account, node_id=other_node)
    response = _post(client, [body], headers=api_headers(**{"X-Client-Key": other_node}))
    assert response.json()["accepted"] == [body["receipt_id"]]


# ─────────────────────────────────────────────────────── 单条自查
def test_get_receipt_status(client, auth, api_account, api_node):
    body = receipt(account_id=api_account, node_id=api_node)
    _post(client, [body])
    response = client.get(f"/api/v1/node/receipts/{body['receipt_id']}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["receipt_id"] == body["receipt_id"]
    assert payload["state"] == "accepted" and payload["received_at"].endswith("Z")


def test_get_receipt_unknown_or_foreign_is_404(client, auth, api_account, api_node):
    missing = client.get("/api/v1/node/receipts/rcpt_missing")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == 40401

    body = receipt(account_id=api_account, node_id=api_node)
    _post(client, [body])
    foreign = client.get(f"/api/v1/node/receipts/{body['receipt_id']}",
                         headers=api_headers(**{"X-Client-Key": "n_other_node"}))
    assert foreign.status_code == 404


# ─────────────────────────────────────────────────────── 用量汇总 / 明细
def test_usage_summary_endpoint(client, auth, api_account, api_node):
    body = receipt(account_id=api_account, node_id=api_node, request_id="req_http_sum_1")
    _post(client, [body])
    response = client.get("/api/v1/user/usage/summary")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) >= {"period", "totals", "groups"}
    assert payload["period"]["from"].endswith("Z")
    assert payload["totals"]["requests"] >= 1
    assert payload["totals"]["billable"]["unit"] == "USD"
    assert isinstance(payload["groups"], list)


def test_usage_summary_group_by_day_and_bad_value(client, auth, api_account, api_node):
    _post(client, [receipt(account_id=api_account, node_id=api_node)])
    ok = client.get("/api/v1/user/usage/summary", params={"group_by": "day"})
    assert ok.status_code == 200 and ok.json()["group_by"] == "day"
    bad = client.get("/api/v1/user/usage/summary", params={"group_by": "tenant"})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == 40001


def test_usage_summary_explicit_period(client, auth, api_account, api_node):
    _post(client, [receipt(account_id=api_account, node_id=api_node)])
    day = NOW.date().isoformat()
    response = client.get("/api/v1/user/usage/summary",
                          params={"from": day, "to": day})
    assert response.status_code == 200
    assert response.json()["totals"]["requests"] >= 1


def test_usage_records_pagination_endpoint(client, auth, api_account, api_node):
    for _ in range(3):
        _post(client, [receipt(account_id=api_account, node_id=api_node)])
    first = client.get("/api/v1/user/usage/records", params={"limit": 2})
    assert first.status_code == 200
    payload = first.json()
    assert len(payload["data"]) == 2 and payload["page"]["has_more"] is True
    cursor = payload["page"]["next_cursor"]
    second = client.get("/api/v1/user/usage/records", params={"limit": 2, "cursor": cursor})
    assert second.status_code == 200 and second.json()["page"]["has_more"] is False


@pytest.mark.parametrize("params", [{"limit": "0"}, {"limit": "201"}, {"limit": "abc"},
                                    {"state": "bogus"}, {"cursor": "bogus"}])
def test_usage_records_reject_bad_params(client, auth, params):
    response = client.get("/api/v1/user/usage/records", params=params)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


# ─────────────────────────────────────────────────────── 信封 / 5xx
def test_keys_unavailable_returns_server_error_envelope(client, auth, api_account, api_node,
                                                        monkeypatch):
    """密钥未接线 → 50001（fail-closed），不是 401/46001（不误导节点）。"""
    from app.metering import signing

    monkeypatch.setattr(signing, "_keys_provider", None, raising=False)
    monkeypatch.delenv(signing.ENV_PROVIDER_KEY, raising=False)
    monkeypatch.delenv(signing.ENV_CONSUMER_KEY, raising=False)
    response = _post(client, [receipt(account_id=api_account, node_id=api_node)])
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == 50001 and body["error"]["type"] == "server_error"


def test_request_id_header_is_echoed(client, auth, api_account, api_node):
    response = _post(client, [receipt(account_id=api_account, node_id=api_node)],
                     headers={"X-Request-Id": "req-fixed-1"})
    assert response.headers["X-Request-Id"] == "req-fixed-1"


# ─────────────────────────────────────────────────────── 管理面：上游账单导入
def _usage_id(schema: str, *, amount_minor: int = 10_000) -> str:
    import uuid as _uuid

    from meterkit import NOW, connect

    usage_id = str(_uuid.uuid4())
    with connect(schema) as conn:
        conn.execute(
            """INSERT INTO usage_records
                 (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                  tokens_in, tokens_out, usage_amount, usage_unit, amount_minor, usage_source,
                  state, receipt_id, recorded_at)
               VALUES (%s,%s,1,%s,'n1','m1','A1',1000,500,'1500','token',%s,'dual','recorded',
                       %s,%s)""",
            (usage_id, f"req_{_uuid.uuid4().hex[:10]}", _uuid.uuid4(), amount_minor,
             f"rcpt_{_uuid.uuid4().hex[:10]}", NOW))
    return usage_id


def test_admin_endpoints_are_fail_closed(client):
    for path in ("/api/v1/admin/usage/upstream-bills", "/api/v1/admin/usage/corrections"):
        response = client.post(path, json={})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == 40101


def test_admin_endpoints_require_step_up(client, auth):
    response = client.post("/api/v1/admin/usage/corrections", json={},
                           headers={**api_headers(), "X-DJB-Idempotency-Key": "k1"})
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401


def test_admin_endpoints_require_idempotency_key(client, auth):
    response = client.post("/api/v1/admin/usage/corrections", json={},
                           headers={**api_headers(), "X-Admin-Step-Up": "1"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001
    assert "Idempotency-Key" in response.json()["error"]["message"]


def test_import_bills_endpoint(client, auth):
    usage_id = _usage_id(auth["schema"], amount_minor=10_000)
    row = {"row_id": f"bill_{uuid.uuid4().hex[:8]}", "usage_id": usage_id, "access": "A1",
           "model": "m1", "amount": {"amount": "100.50", "unit": "USD"}}
    response = client.post("/api/v1/admin/usage/upstream-bills",
                           json={"provider": "openai", "period": "2026-10", "rows": [row]},
                           headers={**api_headers(), "X-Admin-Step-Up": "1",
                                    "X-DJB-Idempotency-Key": f"imp-{uuid.uuid4().hex[:8]}"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["rows_accepted"] == 1 and payload["rows_rejected"] == 0
    assert payload["import_id"].startswith("imp_")
    assert payload["total_amount"] == {"amount": "100.50", "unit": "USD"}
    assert payload["imported_at"].endswith("Z")
    assert payload["results"][0]["status"] == "reconciled"


def test_import_bills_reports_per_row_rejection(client, auth):
    usage_id = _usage_id(auth["schema"])
    rows = [{"row_id": f"bad_{uuid.uuid4().hex[:6]}", "usage_id": usage_id,
             "amount": {"amount": "NaN", "unit": "USD"}}]
    response = client.post("/api/v1/admin/usage/upstream-bills",
                           json={"provider": "openai", "period": "2026-10", "rows": rows},
                           headers={**api_headers(), "X-Admin-Step-Up": "1",
                                    "X-DJB-Idempotency-Key": "k-bills"})
    assert response.status_code == 200
    body = response.json()
    assert body["rows_rejected"] == 1 and body["rows_accepted"] == 0
    assert body["rejected"][0]["code"] == 40001


def test_create_correction_endpoint(client, auth):
    usage_id = _usage_id(auth["schema"], amount_minor=100_000)
    headers = {**api_headers(), "X-Admin-Step-Up": "1",
               "X-DJB-Idempotency-Key": f"corr-{uuid.uuid4().hex[:8]}"}
    body = {"usage_id": usage_id, "delta": {"amount": "10.00", "unit": "USD"},
            "reason_code": "underbill"}
    response = client.post("/api/v1/admin/usage/corrections", json=body, headers=headers)
    assert response.status_code == 202
    payload = response.json()
    assert payload["state"] == "proposed" and payload["correction_id"]
    # 同幂等键重放 → 同一校正（不新增）
    replay = client.post("/api/v1/admin/usage/corrections", json=body, headers=headers)
    assert replay.status_code == 202
    assert replay.json()["correction_id"] == payload["correction_id"]
    assert replay.json()["created"] is False


def test_correction_requires_dual_approval_for_big_delta(client, auth):
    usage_id = _usage_id(auth["schema"], amount_minor=1_000_000)
    headers = {**api_headers(), "X-Admin-Step-Up": "1",
               "X-DJB-Idempotency-Key": f"corr-{uuid.uuid4().hex[:8]}"}
    body = {"usage_id": usage_id, "delta": {"amount": "80.00", "unit": "USD"},
            "reason_code": "underbill"}                       # 80 USD ≥ 50 USD 门槛
    response = client.post("/api/v1/admin/usage/corrections", json=body, headers=headers)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40902
    assert response.json()["error"]["reason"] == "dual_approval_required"
    with_second = dict(body, second_approver="fin-2")
    ok = client.post("/api/v1/admin/usage/corrections", json=with_second,
                     headers={**headers, "X-DJB-Idempotency-Key": f"corr-{uuid.uuid4().hex[:8]}"})
    assert ok.status_code == 202 and ok.json()["state"] == "proposed"


def test_correction_can_apply_immediately(client, auth):
    usage_id = _usage_id(auth["schema"], amount_minor=100_000)
    headers = {**api_headers(), "X-Admin-Step-Up": "1",
               "X-DJB-Idempotency-Key": f"corr-{uuid.uuid4().hex[:8]}"}
    body = {"usage_id": usage_id, "delta": {"amount": "5.00", "unit": "USD"},
            "reason_code": "estimate_fix", "apply": True}
    response = client.post("/api/v1/admin/usage/corrections", json=body, headers=headers)
    assert response.status_code == 202
    payload = response.json()
    assert payload["state"] == "applied" and payload["applied_at"].endswith("Z")
