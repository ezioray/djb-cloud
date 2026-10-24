# SPDX-License-Identifier: AGPL-3.0-or-later
"""导出闭环：权限 / step-up / 幂等 / 双人复核 / TTL / 一次性链接 / 水印 / 审计 / 取消 / 过期。"""
from __future__ import annotations

import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest

from admin_kit import (
    FIXED_NOW,
    LINK_SECRET,
    RecordingSink,
    build_client,
    idempotency_key,
    make_export,
    outbox_rows,
    write_headers,
)
from app.data_gov import clock, errors, export as export_service, policy, store

BASE = "/api/v1/admin/data/export-requests"


def _body(*, object_name: str = "usage", rows: int = 0, pii: bool = False,
          reason: str = "审计抽查", fmt=None) -> dict:
    body: dict = {"scope": {"object": object_name}, "reason": reason,
                  "estimated_rows": rows, "contains_personal_data": pii}
    if fmt is not None:
        body["format"] = fmt
    return body


def _create(client, *, key: str = "a", **kwargs):
    return client.post(BASE, json=_body(**kwargs), headers=write_headers(key))


def _flow(connection, *, rows: int = 3, sink=None, trace: str = "trace-1",
          key: str = "svc-a", create_now=FIXED_NOW - timedelta(days=10),
          complete_now=FIXED_NOW, body: dict | None = None,
          config=None) -> dict:
    row = export_service.create_request(
        connection, requester="ops-admin", tenant_id="tenant-a",
        body=body or _body(rows=0), now=create_now,
        idempotency_key=idempotency_key(key), trace_id=trace, audit_sink=sink)
    export_id = str(row["export_id"])
    export_service.approve_request(connection, export_id, approver="ops-approver",
                                   tenant_id="tenant-a", now=create_now,
                                   audit_sink=sink, trace_id=trace)
    export_service.start_request(connection, export_id, now=create_now,
                                 audit_sink=sink, trace_id=trace)
    return export_service.complete_request(connection, export_id, row_count=rows,
                                           now=complete_now, trace_id=trace,
                                           audit_sink=sink, config=config)


# ─────────────────────────────────────────────────────── 权限 / step-up / 幂等
def test_list_requires_authentication(unauth_client) -> None:
    response = unauth_client.get(BASE)
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == 40101 and error["type"] == "authentication_error"
    assert error["request_id"]


def test_list_rejects_non_admin(nonadmin_client) -> None:
    response = nonadmin_client.get(BASE)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 40301


def test_readonly_auditor_can_list_but_not_write(readonly_client) -> None:
    assert readonly_client.get(BASE).status_code == 200
    response = readonly_client.post(BASE, json=_body(), headers=write_headers("ro"))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 40301


def test_create_requires_step_up(no_stepup_client) -> None:
    headers = {"X-DJB-Idempotency-Key": idempotency_key("nostep")}
    response = no_stepup_client.post(BASE, json=_body(), headers=headers)
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401


def test_create_requires_idempotency_key(client) -> None:
    response = client.post(BASE, json=_body(),
                           headers={"X-Admin-Step-Up": "step-up-token"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_create_pending_and_audited(savepoint_conn, sink: RecordingSink) -> None:
    with build_client(savepoint_conn, audit_sink=sink) as test_client:
        response = _create(test_client, key="create-audit", rows=5)
    assert response.status_code == 201
    payload = response.json()
    assert payload["state"] == "pending"
    assert payload["rows"] == 0 and payload["estimated_rows"] == 5
    assert payload["approval_required"] is False
    assert payload["watermark"] is None
    assert "data.export.requested" in sink.actions()


def test_large_export_requires_dual_review(client) -> None:
    response = client.post(BASE, json=_body(rows=1200), headers=write_headers("large1"))
    assert response.status_code == 201
    payload = response.json()
    assert payload["approval_required"] is True
    assert payload["state"] == "pending"


def test_personal_data_requires_dual_review(client) -> None:
    response = client.post(BASE, json=_body(rows=10, pii=True),
                           headers=write_headers("pii1"))
    assert response.status_code == 201
    assert response.json()["approval_required"] is True


def test_create_over_limit_is_49001(savepoint_conn) -> None:
    with build_client(savepoint_conn, config={"data.export_max_rows": 1000}) as test_client:
        response = test_client.post(BASE, json=_body(rows=5000),
                                    headers=write_headers("too-big"))
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == 49001 and error["reason"] == "export_too_large"


def test_daily_large_export_limit(client) -> None:
    assert _create(client, key="daily1", rows=1200).status_code == 201
    response = _create(client, key="daily2", rows=1200)
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "large_export_daily_limit"


def test_idempotent_replay_returns_same_export(client) -> None:
    first = _create(client, key="idem-same", rows=3)
    second = _create(client, key="idem-same", rows=3)
    assert first.status_code == second.status_code == 201
    assert first.json()["export_id"] == second.json()["export_id"]
    listed = client.get(BASE).json()["data"]
    assert len([row for row in listed if row["reason"] == "审计抽查"]) == 1


def test_idempotency_key_reuse_conflicts(client) -> None:
    assert _create(client, key="idem-diff", rows=3).status_code == 201
    response = _create(client, key="idem-diff", rows=4)
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "idempotency_key_reused"


# ─────────────────────────────────────────────────────── 审批（双人）与状态机
def test_approver_cannot_be_requester(savepoint_conn) -> None:
    row = export_service.create_request(
        savepoint_conn, requester="ops-admin", tenant_id="tenant-a", body=_body(rows=1200),
        now=FIXED_NOW, idempotency_key=idempotency_key("approve-svc"),
        trace_id="trace-a")
    with pytest.raises(errors.Forbidden):
        export_service.approve_request(
            savepoint_conn, str(row["export_id"]), approver="ops-admin",
            tenant_id="tenant-a", now=FIXED_NOW)
    approved = export_service.approve_request(
        savepoint_conn, str(row["export_id"]), approver="ops-approver",
        tenant_id="tenant-a", now=FIXED_NOW)
    assert approved["state"] == "approved" and approved["approver"] == "ops-approver"
    replay = export_service.approve_request(
        savepoint_conn, str(row["export_id"]), approver="ops-approver",
        tenant_id="tenant-a", now=FIXED_NOW)
    assert replay["state"] == "approved"                       # 同审批人幂等
    with pytest.raises(errors.Conflict):
        export_service.approve_request(
            savepoint_conn, str(row["export_id"]), approver="someone-else",
            tenant_id="tenant-a", now=FIXED_NOW)


def test_complete_produces_watermark_link_and_event(savepoint_conn, sink) -> None:
    row = _flow(savepoint_conn, rows=3, sink=sink, trace="trace-flow")
    assert row["state"] == "done" and row["watermark"].startswith("DJB-M14")
    events_rows = outbox_rows(savepoint_conn)
    assert [item["type"] for item in events_rows] == ["data.export.completed"]
    assert events_rows[0]["payload"]["rows"] == 3
    assert events_rows[0]["trace_id"] == "trace-flow"
    with build_client(savepoint_conn, audit_sink=sink) as test_client:
        response = test_client.get(f"{BASE}/{row['export_id']}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "done" and payload["rows"] == 3
    download = payload["download"]
    assert download["available"] is True and download["one_time"] is True
    assert download["ttl_s"] <= 15 * 60
    assert download["url"].startswith("https://admin.test/files/")


def test_link_ttl_is_clamped_to_fifteen_minutes(savepoint_conn) -> None:
    row = _flow(savepoint_conn, rows=1, key="ttl-60")
    with build_client(savepoint_conn, config={"data.export_link_ttl_min": 60}) as test_client:
        payload = test_client.get(f"{BASE}/{row['export_id']}").json()
    assert payload["download"]["ttl_s"] == 900
    row2 = _flow(savepoint_conn, rows=1, key="ttl-5")
    with build_client(savepoint_conn, config={"data.export_link_ttl_min": 5}) as test_client:
        payload2 = test_client.get(f"{BASE}/{row2['export_id']}").json()
    assert payload2["download"]["ttl_s"] == 300


def test_download_link_is_one_time(savepoint_conn, sink) -> None:
    row = _flow(savepoint_conn, rows=3, sink=sink, key="one-time")
    with build_client(savepoint_conn, audit_sink=sink) as test_client:
        first = test_client.get(f"{BASE}/{row['export_id']}").json()["download"]["url"]
        second = test_client.get(f"{BASE}/{row['export_id']}").json()["download"]["url"]
        token_first = parse_qs(urlparse(first).query)["token"][0]
        token_second = parse_qs(urlparse(second).query)["token"][0]
        assert token_first != token_second                      # 新链接顶掉旧链接
        with pytest.raises(errors.Conflict) as superseded:
            export_service.consume_link(savepoint_conn, token_first, secret=LINK_SECRET,
                                        now=FIXED_NOW, audit_sink=sink)
        assert superseded.value.reason == "link_superseded"
        consumed = export_service.consume_link(savepoint_conn, token_second,
                                               secret=LINK_SECRET, now=FIXED_NOW,
                                               audit_sink=sink)
        assert consumed["one_time"] is True and consumed["rows"] == 3
        with pytest.raises(errors.Conflict) as replay:
            export_service.consume_link(savepoint_conn, token_second,
                                        secret=LINK_SECRET, now=FIXED_NOW)
        assert replay.value.reason == "link_already_consumed"
        payload = test_client.get(f"{BASE}/{row['export_id']}").json()
    assert payload["download"] == {"available": False, "reason": "already_downloaded"}
    assert "data.export.link_consumed" in sink.actions()


def test_invalid_download_token_rejected(savepoint_conn) -> None:
    with pytest.raises(errors.Conflict) as excinfo:
        export_service.consume_link(savepoint_conn, "not-a-token", secret=LINK_SECRET,
                                    now=FIXED_NOW)
    assert excinfo.value.reason == "link_invalid"


def test_file_expires_after_seven_days(savepoint_conn) -> None:
    row = _flow(savepoint_conn, rows=2, key="expiry")
    export_id = str(row["export_id"])
    store.update_export(savepoint_conn, export_id,
                        expires_at=FIXED_NOW - timedelta(seconds=1))
    with build_client(savepoint_conn) as test_client:
        payload = test_client.get(f"{BASE}/{export_id}").json()
        listed = test_client.get(BASE).json()["data"]
    assert payload["state"] == "expired"
    assert payload["download"]["reason"] == "state_expired"
    assert listed[0]["state"] == "expired"
    assert store.get_export(savepoint_conn, export_id)["state"] == "expired"


def test_complete_over_limit_marks_failed(savepoint_conn) -> None:
    row = _flow(savepoint_conn, rows=1500, key="over-limit",
                config={"data.export_max_rows": 1000})
    assert row["state"] == "failed"
    assert row["failure_reason"] == "row_limit_exceeded"
    assert outbox_rows(savepoint_conn) == []


# ─────────────────────────────────────────────────────── 取消 / 查询
def test_cancel_only_before_execution(savepoint_conn, client) -> None:
    row = _create(client, key="cancel-a", rows=1).json()
    response = client.post(f"{BASE}/{row['export_id']}/cancel",
                           headers=write_headers("cancel-a2"))
    assert response.status_code == 200
    cancelled = response.json()
    # 1.2.6 裁决：state→failed + failure_reason=cancelled_by_requester + cancelled_at/by；
    # 不新增 cancelled 枚举值（ExportRequest.state 仍六值）；重复取消幂等。
    assert cancelled["state"] == "failed"
    assert cancelled["failure_reason"] == "cancelled_by_requester"
    assert cancelled["cancelled_by"] == "ops-admin"
    assert cancelled["cancelled_at"] is not None
    stored = store.get_export(savepoint_conn, row["export_id"])
    assert stored["state"] == "failed"
    assert stored["failure_reason"] == "cancelled_by_requester"
    assert stored["cancelled_at"] is not None and stored["cancelled_by"] == "ops-admin"
    replay = client.post(f"{BASE}/{row['export_id']}/cancel",
                         headers=write_headers("cancel-a3"))
    assert replay.status_code == 200                            # 幂等（不同幂等键也不重复生效）
    assert replay.json()["state"] == "failed"
    assert replay.json()["cancelled_at"] == cancelled["cancelled_at"]
    running = make_export(savepoint_conn, state="running")
    refused = client.post(f"{BASE}/{running['export_id']}/cancel",
                          headers=write_headers("cancel-running"))
    assert refused.status_code == 409
    assert refused.json()["error"]["reason"] == "cancel_not_allowed"
    done = make_export(savepoint_conn, state="done")
    assert client.post(f"{BASE}/{done['export_id']}/cancel",
                       headers=write_headers("cancel-done")).status_code == 409


def test_cancel_requires_step_up_and_write_scope(savepoint_conn) -> None:
    row = make_export(savepoint_conn, state="pending")
    with build_client(savepoint_conn, step_up=False) as test_client:
        response = test_client.post(f"{BASE}/{row['export_id']}/cancel",
                                    headers=write_headers("cancel-nostep"))
    assert response.status_code == 424
    with build_client(savepoint_conn, principal={"admin_id": "auditor",
                                                 "tenant_id": "tenant-a",
                                                 "roles": ["AUDIT"]}) as test_client:
        response = test_client.post(f"{BASE}/{row['export_id']}/cancel",
                                    headers=write_headers("cancel-readonly"))
    assert response.status_code == 403


def test_get_unknown_export_returns_404(client) -> None:
    assert client.get(f"{BASE}/{uuid.uuid4()}").status_code == 404
    assert client.get(f"{BASE}/not-a-uuid").status_code == 404
    response = client.get(f"{BASE}/{uuid.uuid4()}")
    assert response.json()["error"]["code"] == 40401


def test_list_pagination_and_filters(client, savepoint_conn) -> None:
    for index in range(3):
        _create(client, key=f"page-{index}", rows=1,
                object_name="usage" if index < 2 else "receipts")
    first_page = client.get(BASE, params={"limit": 2}).json()
    assert len(first_page["data"]) == 2
    assert first_page["page"]["has_more"] is True
    assert first_page["page"]["next_cursor"]
    second_page = client.get(BASE, params={"limit": 2,
                                           "cursor": first_page["page"]["next_cursor"]}).json()
    assert len(second_page["data"]) == 1
    assert second_page["page"]["has_more"] is False
    assert second_page["page"]["next_cursor"] is None
    ids_seen = {row["export_id"] for row in first_page["data"] + second_page["data"]}
    assert len(ids_seen) == 3
    receipts = client.get(BASE, params={"object": "receipts"}).json()["data"]
    assert len(receipts) == 1 and receipts[0]["scope"]["object"] == "receipts"
    pending = client.get(BASE, params={"state": "pending"}).json()["data"]
    assert len(pending) == 3


def test_list_rejects_invalid_filters(client) -> None:
    assert client.get(BASE, params={"state": "cancelled"}).status_code == 400
    assert client.get(BASE, params={"limit": 0}).status_code == 400
    assert client.get(BASE, params={"cursor": "%%%"}).status_code == 400


def test_response_echoes_request_id(client) -> None:
    response = client.get(BASE, headers={"X-Request-Id": "req-m14-1"})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == "req-m14-1"


def test_policy_helpers() -> None:
    assert policy.link_ttl_seconds(None) == 900
    assert policy.link_ttl_seconds(60) == 900
    assert policy.link_ttl_seconds(5) == 300
    assert policy.link_ttl_seconds("bad") == 900
    assert policy.resolve_export_max_rows(None) == 200000
    assert policy.resolve_export_max_rows(500) == 200000
    assert policy.resolve_export_max_rows(2000) == 2000
    assert policy.dual_review_required(1000, False) is False
    assert policy.dual_review_required(1001, False) is True
    assert policy.dual_review_required(10, True) is True
    token, expires_at, jti = policy.mint_download_token(
        str(uuid.uuid4()), now=FIXED_NOW, ttl_s=3600, secret=LINK_SECRET)
    assert jti and expires_at <= FIXED_NOW + timedelta(seconds=900)
    claims = policy.verify_download_token(token, secret=LINK_SECRET, now=FIXED_NOW)
    assert claims["jti"] == jti
    with pytest.raises(errors.Conflict):
        policy.verify_download_token(token, secret=b"other-secret", now=FIXED_NOW)
    with pytest.raises(errors.Conflict):
        policy.verify_download_token(token, secret=LINK_SECRET,
                                     now=FIXED_NOW + timedelta(hours=1))
