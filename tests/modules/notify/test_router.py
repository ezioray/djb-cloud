# SPDX-License-Identifier: Apache-2.0
"""HTTP 契约：七条操作 + 错误信封 + fail-closed 接线 + 账户隔离（spec 1.2.3）。"""
from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.notify import events, preferences, webhooks
from app.notify.router import create_router
from notifykit import NOW, TEST_WEBHOOK_SECRET, connect, count, scalar


def _client(*, factory=None, principal=None, now=NOW) -> TestClient:
    app = FastAPI()
    app.include_router(create_router(connection_factory=factory,
                                     principal_resolver=principal,
                                     now_provider=lambda: now))
    return TestClient(app)


def _principal(account_id) -> callable:
    return lambda request: {"account_id": str(account_id)}


def test_unauthenticated_when_resolver_not_wired():
    client = _client()
    response = client.get("/api/v1/user/notifications")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == 40101
    assert body["error"]["type"] == "authentication_error"
    assert body["error"]["request_id"]
    assert response.headers["X-Request-Id"]


def test_store_unavailable_when_factory_not_wired():
    client = _client(principal=_principal(uuid.uuid4()))
    response = client.get("/api/v1/user/notifications")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == 50001


def test_request_id_is_echoed(migrated):
    request_id = str(uuid.uuid4())
    client = _client(factory=_factory(migrated), principal=_principal(uuid.uuid4()))
    response = client.get("/api/v1/user/notifications", headers={"X-Request-Id": request_id})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == request_id


def _factory(schema: str):
    def factory():
        return connect(schema)

    return factory


#: 种子用不同类型：同类型同窗口会被 INV-03 合并成一条，测分页就少一条
_SEED_TYPES = ("payment.paid", "payout.paid", "refund.completed", "cop.earned",
               "por.published")


def _seed(migrated, account_id, count_=2):
    conn = connect(migrated)
    try:
        for index in range(count_):
            events.consume(conn, _event(account_id, index), now=NOW)
        conn.commit()
    finally:
        conn.close()
    return count_


def _event(account_id, index=0):
    from datetime import timedelta

    from notifykit import event

    return event(_SEED_TYPES[index % len(_SEED_TYPES)], account_id=account_id,
                 occurred_at=NOW + timedelta(minutes=index), order_no=f"ord-{index}")


def test_list_notifications_returns_page_and_unread(migrated):
    account = uuid.uuid4()
    _seed(migrated, account)
    client = _client(factory=_factory(migrated), principal=_principal(account))
    response = client.get("/api/v1/user/notifications", params={"limit": 1})
    assert response.status_code == 200
    body = response.json()
    assert body["unread"] == 2
    assert len(body["data"]) == 1
    assert body["page"]["has_more"] is True
    assert body["page"]["next_cursor"]

    second = client.get("/api/v1/user/notifications",
                        params={"limit": 1, "cursor": body["page"]["next_cursor"]})
    assert second.json()["page"]["has_more"] is False


def test_list_filters_and_validation(migrated):
    account = uuid.uuid4()
    _seed(migrated, account)
    client = _client(factory=_factory(migrated), principal=_principal(account))
    assert client.get("/api/v1/user/notifications",
                      params={"level": "P1"}).json()["data"]
    assert client.get("/api/v1/user/notifications",
                      params={"level": "P0"}).json()["data"] == []
    bad_level = client.get("/api/v1/user/notifications", params={"level": "P9"})
    assert bad_level.status_code == 400 and bad_level.json()["error"]["code"] == 40001
    bad_limit = client.get("/api/v1/user/notifications", params={"limit": 500})
    assert bad_limit.status_code == 400
    bad_cursor = client.get("/api/v1/user/notifications", params={"cursor": "junk"})
    assert bad_cursor.status_code == 400
    assert bad_cursor.json()["error"]["reason"] == "cursor_invalid"


def test_mark_read_is_idempotent_over_http(migrated):
    account = uuid.uuid4()
    _seed(migrated, account, 1)
    client = _client(factory=_factory(migrated), principal=_principal(account))
    listed = client.get("/api/v1/user/notifications").json()
    notification_id = listed["data"][0]["id"]

    first = client.post(f"/api/v1/user/notifications/{notification_id}/read")
    assert first.status_code == 200
    assert first.json()["marked"] == 1
    assert first.json()["unread"] == 0
    second = client.post(f"/api/v1/user/notifications/{notification_id}/read")
    assert second.json()["marked"] == 0
    assert second.json()["read_at"] == first.json()["read_at"]


def test_mark_all_read_over_http(migrated):
    account = uuid.uuid4()
    _seed(migrated, account, 3)
    client = _client(factory=_factory(migrated), principal=_principal(account))
    response = client.post("/api/v1/user/notifications/all/read")
    assert response.status_code == 200
    assert response.json()["notification_id"] is None
    assert response.json()["marked"] == 3
    assert response.json()["unread"] == 0


def test_mark_read_unknown_is_404(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    response = client.post(f"/api/v1/user/notifications/{uuid.uuid4()}/read")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401
    assert client.post("/api/v1/user/notifications/not-a-uuid/read").status_code == 404


def test_account_isolation_over_http(migrated):
    owner = uuid.uuid4()
    _seed(migrated, owner, 1)
    conn = connect(migrated)
    try:
        notification_id = str(scalar(
            conn, "SELECT id FROM notifications WHERE account_id = %s", (owner,)))
    finally:
        conn.close()
    stranger = _client(factory=_factory(migrated), principal=_principal(uuid.uuid4()))
    assert stranger.get("/api/v1/user/notifications").json()["data"] == []
    assert stranger.post(f"/api/v1/user/notifications/{notification_id}/read").status_code == 404


# ─────────────────────────────────────────────────── 偏好
def test_preferences_default_and_update(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    default = client.get("/api/v1/user/notifications/preferences")
    assert default.status_code == 200
    assert default.json() == {"email": True, "in_app": True, "webhook": False,
                              "quiet_hours": None, "digest": "realtime", "p0_opt_out": False}
    updated = client.put("/api/v1/user/notifications/preferences",
                         json={"email": False, "in_app": True, "webhook": True,
                               "digest": "weekly"})
    assert updated.status_code == 200
    assert updated.json()["digest"] == "weekly"
    assert client.get("/api/v1/user/notifications/preferences").json()["email"] is False


def test_p0_opt_out_is_rejected_over_http(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    client.put("/api/v1/user/notifications/preferences",
               json={"email": True, "in_app": True, "webhook": False})
    response = client.put("/api/v1/user/notifications/preferences",
                          json={"email": True, "in_app": True, "webhook": False,
                                "p0_opt_out": True})
    assert response.status_code == 409
    body = response.json()["error"]
    assert body["code"] == 40902 and body["type"] == "conflict_error"
    assert client.get("/api/v1/user/notifications/preferences").json()["p0_opt_out"] is False


@pytest.mark.parametrize("payload", [
    None,
    {},
    {"email": True},
    {"email": "yes", "in_app": True, "webhook": False},
    [1, 2],
])
def test_preferences_invalid_bodies_over_http(migrated, payload):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    if payload is None:
        response = client.put("/api/v1/user/notifications/preferences",
                              content=b"", headers={"Content-Type": "application/json"})
    elif isinstance(payload, list):
        response = client.put("/api/v1/user/notifications/preferences", json=payload)
    else:
        response = client.put("/api/v1/user/notifications/preferences", json=payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_idempotency_key_shape_is_validated(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    body = {"email": True, "in_app": True, "webhook": False}
    short = client.put("/api/v1/user/notifications/preferences", json=body,
                       headers={"X-DJB-Idempotency-Key": "too-short"})
    assert short.status_code == 400 and short.json()["error"]["code"] == 40001
    good = client.put("/api/v1/user/notifications/preferences", json=body,
                      headers={"X-DJB-Idempotency-Key": "idem-key-0123456789abcdef"})
    assert good.status_code == 200


def test_webhook_body_rejects_unknown_fields(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    response = client.post("/api/v1/user/webhooks",
                           json={"url": "https://hooks.example.com/cb",
                                 "events": ["task.completed"], "unknown": 1})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_invalid_json_body_is_400(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    response = client.put("/api/v1/user/notifications/preferences",
                          content=b"{not json", headers={"Content-Type": "application/json"})
    assert response.status_code == 400


# ─────────────────────────────────────────────────── Webhook
def test_webhook_create_returns_secret_once(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    response = client.post("/api/v1/user/webhooks",
                           json={"url": "https://hooks.example.com/cb",
                                 "events": ["payment.settled"],
                                 "description": "我的监控"})
    assert response.status_code == 201
    body = response.json()
    assert body["secret"] and body["url"] == "https://hooks.example.com/cb"
    assert body["status"] == "active"
    assert "secret_hash" not in body

    conn = connect(migrated)
    try:
        stored = scalar(conn, "SELECT secret_hash FROM webhook_subscriptions WHERE id = %s",
                        (uuid.UUID(body["id"]),))
    finally:
        conn.close()
    assert stored and stored != body["secret"] and len(stored) == 64

    listed = client.get("/api/v1/user/webhooks").json()
    assert listed["data"] and "secret" not in listed["data"][0]

    duplicate = client.post("/api/v1/user/webhooks",
                            json={"url": "https://hooks.example.com/cb",
                                  "events": ["payment.settled"]})
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["reason"] == "duplicate_subscription"


def test_webhook_ssrf_is_rejected_over_http(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    for url in ("https://127.0.0.1/cb", "http://example.com/cb",
                "https://169.254.169.254/latest/meta-data"):
        response = client.post("/api/v1/user/webhooks",
                               json={"url": url, "events": ["task.completed"]})
        assert response.status_code == 400, url
        assert response.json()["error"]["code"] == 40001


def test_webhook_idempotency_replay_is_conflict(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    headers = {"X-DJB-Idempotency-Key": "idem-key-abcdefghijklmnop"}
    body = {"url": "https://hooks.example.com/cb", "events": ["task.completed"]}
    assert client.post("/api/v1/user/webhooks", json=body, headers=headers).status_code == 201
    replay = client.post("/api/v1/user/webhooks", json=body, headers=headers)
    assert replay.status_code == 409
    assert replay.json()["error"]["reason"] == "idempotent_replay"


def test_webhook_delete_is_idempotent(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    created = client.post("/api/v1/user/webhooks",
                          json={"url": "https://hooks.example.com/cb",
                                "events": ["task.completed"]}).json()
    assert client.delete(f"/api/v1/user/webhooks/{created['id']}").status_code == 204
    assert client.delete(f"/api/v1/user/webhooks/{created['id']}").status_code == 204
    assert client.delete(f"/api/v1/user/webhooks/{uuid.uuid4()}").status_code == 204
    assert client.delete("/api/v1/user/webhooks/not-a-uuid").status_code == 404


def test_webhook_list_pagination(migrated):
    account = uuid.uuid4()
    client = _client(factory=_factory(migrated), principal=_principal(account))
    for index in range(3):
        client.post("/api/v1/user/webhooks",
                    json={"url": f"https://h{index}.example.com/cb",
                          "events": ["task.completed"]})
    page = client.get("/api/v1/user/webhooks", params={"limit": 2}).json()
    assert len(page["data"]) == 2 and page["page"]["has_more"] is True
    tail = client.get("/api/v1/user/webhooks",
                      params={"limit": 2, "cursor": page["page"]["next_cursor"]}).json()
    assert len(tail["data"]) == 1 and tail["page"]["has_more"] is False


def test_all_routes_are_under_spec_prefixes():
    client = _client()
    paths = set(client.app.openapi()["paths"])
    expected = {
        "/api/v1/user/notifications",
        "/api/v1/user/notifications/{id}/read",
        "/api/v1/user/notifications/preferences",
        "/api/v1/user/webhooks",
        "/api/v1/user/webhooks/{id}",
    }
    assert expected <= paths
