# SPDX-License-Identifier: AGPL-3.0-or-later
"""C15/M12a 节点通知队列：入队幂等、payload 白名单、拉取/游标、ack/read、过期、开关与鉴权。

不联网、不碰账本：所有 DB 操作在 ``migrated``（模块级隔离 schema）里，行用随机 id 隔离，
``conn`` 夹具非 autocommit → 每个用例结束回滚。
路由用例走 ``create_router`` 注入的假鉴权 + 连接工厂（与生产同款 ``with conn`` 提交口径）。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import psycopg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from app.notify import errors, facts, features, node_push
from app.notify.node_push_router import create_router
from app.notify.store import dict_cursor
from notifykit import NOW, connect, count, scalar

PUSH_ENV = node_push.PUSH_ENV


@pytest.fixture(autouse=True)
def _push_on(monkeypatch):
    """默认把 S2 激活开关打开（关闭场景由用例自己 delenv）。"""
    monkeypatch.setenv(PUSH_ENV, "1")


def _node() -> str:
    return f"n_{uuid.uuid4().hex[:8]}"


def _enqueue(conn, node_id: str, **kwargs):
    """固定时钟入队（``NOW``）；要测过期就显式传 ``expires_at`` / ``now``。"""
    params = {"severity": "P1", "category": "alert", "template_key": "node.alert.cpu_high",
              "payload": {"node_id": node_id, "reason_code": "cpu_high", "amount_minor": 0}}
    params.update(kwargs)
    params.setdefault("now", NOW)
    return node_push.enqueue(conn, node_id, params.pop("severity"), params.pop("category"),
                             params.pop("template_key"), params.pop("payload"), **params)


def _pull(conn, node_id: str, **kwargs):
    kwargs.setdefault("now", NOW)
    return node_push.pull(conn, node_id, **kwargs)


def _ack(conn, node_id: str, notification_id, **kwargs):
    kwargs.setdefault("now", NOW)
    return node_push.ack(conn, node_id, notification_id, **kwargs)


def _read(conn, node_id: str, notification_id, **kwargs):
    kwargs.setdefault("now", NOW)
    return node_push.read(conn, node_id, notification_id, **kwargs)


def _unread(conn, node_id: str, **kwargs):
    kwargs.setdefault("now", NOW)
    return node_push.unread_count(conn, node_id, **kwargs)


def _expire(conn, **kwargs):
    kwargs.setdefault("now", NOW)
    return node_push.expire_due(conn, **kwargs)


def _admin_list(conn, **kwargs):
    kwargs.setdefault("now", NOW)
    return node_push.list_for_admin(conn, **kwargs)


def _rows(conn, sql: str, params=()):
    with dict_cursor(conn) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def _events(conn, notification_id) -> list[str]:
    return sorted(row["event"] for row in _rows(
        conn, "SELECT event FROM node_notification_events WHERE notification_id = %s",
        (uuid.UUID(str(notification_id)),)))


def _state(conn, notification_id) -> str:
    return _rows(conn, "SELECT state FROM node_notifications WHERE id = %s",
                 (uuid.UUID(str(notification_id)),))[0]["state"]


# ─────────────────────────────────────────────────────── 开关
def test_switch_is_registered_with_three_fields_and_off_by_default(monkeypatch):
    switch = features.get(node_push.SWITCH)
    assert switch.name == "notify.node_push.enabled"
    assert switch.owner == "lead"
    assert switch.expire_at.isoformat() == "2026-12-31"
    assert switch.default is False
    assert "503" in switch.rollback_rule and "保留" in switch.rollback_rule
    monkeypatch.delenv(PUSH_ENV, raising=False)
    assert node_push.enabled() is False


def test_enabled_follows_the_feature_gate(monkeypatch):
    monkeypatch.delenv(PUSH_ENV, raising=False)
    monkeypatch.setattr(features, "enabled", lambda name: name == node_push.SWITCH)
    assert node_push.enabled() is True


def test_enqueue_is_rejected_when_the_switch_is_off(conn, monkeypatch):
    monkeypatch.delenv(PUSH_ENV, raising=False)
    with pytest.raises(errors.StoreUnavailable) as info:
        _enqueue(conn, _node())
    assert (info.value.status_code, info.value.code) == (503, "50001")
    assert info.value.reason == "node_push_disabled"


def test_pull_is_rejected_when_the_switch_is_off(conn, monkeypatch):
    node = _node()
    _enqueue(conn, node)
    monkeypatch.delenv(PUSH_ENV, raising=False)
    with pytest.raises(errors.StoreUnavailable):
        _pull(conn, node)


def test_ack_and_unread_stay_available_when_the_switch_is_off(conn, monkeypatch):
    node = _node()
    notification = _enqueue(conn, node)
    _pull(conn, node)
    monkeypatch.delenv(PUSH_ENV, raising=False)          # 回滚：停新投递、存量仍可确认
    assert _ack(conn, node, notification["id"])["accepted"] is True
    assert _unread(conn, node) == 1
    assert _admin_list(conn, node_id=node)["items"]


# ─────────────────────────────────────────────────────── 入队
def test_enqueue_creates_a_queued_notification_with_the_wire_shape(conn):
    node = _node()
    notification = _enqueue(conn, node, dedupe_key="dedupe-" + uuid.uuid4().hex)
    assert set(notification) >= {"id", "severity", "category", "template_key", "payload",
                                 "created_at", "expires_at", "read_at"}
    assert notification["severity"] == "P1" and notification["category"] == "alert"
    assert notification["state"] == "queued" and notification["expires_at"] is None
    assert _events(conn, notification["id"]) == ["queued"]


def test_enqueue_is_idempotent_by_dedupe_key(conn):
    node = _node()
    key = "dedupe-" + uuid.uuid4().hex
    first = _enqueue(conn, node, dedupe_key=key)
    second = _enqueue(conn, node, dedupe_key=key, category="system")
    assert second["id"] == first["id"]
    assert count(conn, "node_notifications", "node_id = %s", (node,)) == 1
    assert _events(conn, first["id"]) == ["queued"]      # 幂等不追加第二条 queued 事件


def test_enqueue_is_idempotent_by_source_event_id(conn):
    node = _node()
    event_id = str(uuid.uuid4())
    first = _enqueue(conn, node, source_event_id=event_id)
    second = _enqueue(conn, node, source_event_id=event_id)
    assert second["id"] == first["id"]
    assert count(conn, "node_notifications", "source_event_id = %s", (uuid.UUID(event_id),)) == 1


@pytest.mark.parametrize("key", ["email", "phone", "secret", "password", "token", "body",
                                 "content", "html", "text"])
def test_enqueue_rejects_sensitive_payload_keys(conn, key):
    node = _node()
    with pytest.raises(errors.InvalidArgument) as info:
        _enqueue(conn, node, payload={"reason_code": "x", key: "whatever"})
    assert info.value.code == "40001"


def test_enqueue_rejects_unregistered_payload_keys(conn):
    with pytest.raises(errors.InvalidArgument):
        _enqueue(conn, _node(), payload={"freeform_note": "hello"})


def test_enqueue_rejects_pii_looking_values(conn):
    with pytest.raises(errors.InvalidArgument):
        _enqueue(conn, _node(), payload={"reason_code": "ops@example.com"})
    with pytest.raises(errors.InvalidArgument):
        _enqueue(conn, _node(), payload={"reason_code": "13800138000"})


def test_p0_requires_an_expiry_within_seven_days(conn):
    node = _node()
    with pytest.raises(errors.InvalidArgument) as missing:
        _enqueue(conn, node, severity="P0")
    assert missing.value.details.get("field") == "expires_at"
    with pytest.raises(errors.InvalidArgument):
        _enqueue(conn, node, severity="P0", expires_at=NOW + timedelta(days=8))
    ok = _enqueue(conn, node, severity="P0", expires_at=NOW + timedelta(days=7))
    assert ok["severity"] == "P0" and ok["expires_at"] is not None


def test_expiry_must_be_in_the_future(conn):
    with pytest.raises(errors.InvalidArgument):
        _enqueue(conn, _node(), expires_at=NOW - timedelta(minutes=1))


@pytest.mark.parametrize("field,value", [("severity", "P9"), ("category", "unknown"),
                                         ("template_key", "Bad Key!")])
def test_enqueue_validates_enums_and_template_key(conn, field, value):
    kwargs = {field: value}
    with pytest.raises(errors.InvalidArgument):
        _enqueue(conn, _node(), **kwargs)


# ─────────────────────────────────────────────────────── 拉取
def test_pull_returns_items_and_marks_them_delivered(conn):
    node = _node()
    first = _enqueue(conn, node)
    second = _enqueue(conn, node, severity="P2", category="campaign",
                      template_key="node.campaign.notice", now=NOW + timedelta(seconds=1))
    page = _pull(conn, node)
    assert [item["id"] for item in page["items"]] == [first["id"], second["id"]]
    assert page["has_more"] is False and page["next_cursor"]
    assert _state(conn, first["id"]) == "delivered"
    assert count(conn, "node_notification_deliveries", "notification_id = %s",
                 (uuid.UUID(first["id"]),)) == 1
    assert _events(conn, first["id"]) == ["delivered", "queued"]
    row = _rows(conn, "SELECT delivered_at FROM node_notifications WHERE id = %s",
                (uuid.UUID(first["id"]),))[0]
    assert row["delivered_at"] is not None


def test_pull_is_scoped_to_the_node(conn):
    mine, other = _node(), _node()
    _enqueue(conn, mine)
    _enqueue(conn, other)
    page = _pull(conn, mine)
    assert len(page["items"]) == 1
    assert count(conn, "node_notifications", "node_id = %s AND state = 'queued'", (other,)) == 1


def test_pull_excludes_expired_and_expire_due_marks_them(conn):
    node = _node()
    _enqueue(conn, node, severity="P0", expires_at=NOW + timedelta(minutes=5))
    later = NOW + timedelta(minutes=10)
    assert _pull(conn, node, now=later)["items"] == []
    assert _expire(conn, now=later) == 1
    row = _rows(conn, "SELECT id, state FROM node_notifications WHERE node_id = %s", (node,))[0]
    assert row["state"] == "expired"
    assert _events(conn, row["id"]) == ["expired", "queued"]


def test_pull_filters_by_category(conn):
    node = _node()
    _enqueue(conn, node, category="alert")
    campaign = _enqueue(conn, node, category="campaign", template_key="node.campaign.notice")
    page = _pull(conn, node, category="campaign")
    assert [item["id"] for item in page["items"]] == [campaign["id"]]


def test_pull_paginates_with_a_keyset_cursor(conn):
    node = _node()
    created = [_enqueue(conn, node, now=NOW + timedelta(seconds=index)) for index in range(3)]
    first = _pull(conn, node, limit=2)
    assert len(first["items"]) == 2 and first["has_more"] is True
    second = _pull(conn, node, limit=2, since=first["next_cursor"])
    assert [item["id"] for item in second["items"]] == [created[2]["id"]]
    assert second["has_more"] is False


def test_pull_hides_read_notifications_unless_asked(conn):
    node = _node()
    first = _enqueue(conn, node)
    second = _enqueue(conn, node)
    _read(conn, node, first["id"])
    page = _pull(conn, node)
    assert [item["id"] for item in page["items"]] == [second["id"]]
    admin = _pull(conn, node, include_read=True)
    assert {item["id"] for item in admin["items"]} == {first["id"], second["id"]}


# ─────────────────────────────────────────────────────── ack / read
def test_ack_is_idempotent_and_records_one_event(conn):
    node = _node()
    notification = _enqueue(conn, node)
    first = _ack(conn, node, notification["id"])
    second = _ack(conn, node, notification["id"])
    assert first == second == {"accepted": True, "state": "delivered"}
    assert _events(conn, notification["id"]).count("acked") == 1


def test_read_marks_read_and_implies_ack(conn):
    node = _node()
    notification = _enqueue(conn, node)
    assert _read(conn, node, notification["id"]) == {"accepted": True, "state": "read"}
    events = _events(conn, notification["id"])
    assert events.count("acked") == 1 and events.count("read") == 1
    row = _rows(conn, "SELECT delivered_at, read_at FROM node_notifications WHERE id = %s",
                (uuid.UUID(notification["id"]),))[0]
    assert row["delivered_at"] is not None and row["read_at"] is not None
    again = _read(conn, node, notification["id"])       # 幂等：不再追加事件
    assert again == {"accepted": True, "state": "read"}
    assert _events(conn, notification["id"]).count("read") == 1


def test_ack_and_read_are_scoped_to_the_node(conn):
    owner, stranger = _node(), _node()
    notification = _enqueue(conn, owner)
    for call in (node_push.ack, node_push.read):
        with pytest.raises(errors.NotFound) as info:
            call(conn, stranger, notification["id"])
        assert (info.value.status_code, info.value.code) == (404, "40401")
        with pytest.raises(errors.NotFound):
            call(conn, owner, str(uuid.uuid4()))
        with pytest.raises(errors.NotFound):
            call(conn, owner, "not-a-uuid")


def test_ack_of_an_expired_notification_is_a_conflict(conn):
    node = _node()
    notification = _enqueue(conn, node, severity="P0",
                            expires_at=NOW + timedelta(minutes=5))
    _expire(conn, now=NOW + timedelta(minutes=10))
    with pytest.raises(errors.Conflict) as info:
        _ack(conn, node, notification["id"])
    assert (info.value.status_code, info.value.code) == (409, "40902")


def test_unread_count_counts_unread_and_unexpired(conn):
    node = _node()
    first = _enqueue(conn, node)
    _enqueue(conn, node)
    _enqueue(conn, node, severity="P0", expires_at=NOW + timedelta(minutes=5))
    assert _unread(conn, node) == 3
    _read(conn, node, first["id"])
    assert _unread(conn, node) == 2
    _expire(conn, now=NOW + timedelta(minutes=10))
    assert _unread(conn, node, now=NOW + timedelta(minutes=10)) == 1


# ─────────────────────────────────────────────────────── 管理面
def test_list_for_admin_reports_state_and_delivery_count(conn):
    node = _node()
    notification = _enqueue(conn, node)
    _pull(conn, node)
    page = _admin_list(conn, node_id=node)
    assert page["items"] and page["has_more"] is False
    item = page["items"][0]
    assert item["id"] == notification["id"] and item["state"] == "delivered"
    assert item["deliveries"] == 1 and item["node_id"] == node


def test_list_for_admin_filters_by_state(conn):
    node = _node()
    queued = _enqueue(conn, node)                                    # 较早：留给「未投递」
    delivered = _enqueue(conn, node, now=NOW + timedelta(seconds=1))  # 较晚：先被拉走
    _pull(conn, node, limit=1)                   # 只投递最早的一条
    pulled = _admin_list(conn, state="delivered")["items"]
    pending = _admin_list(conn, state="queued")["items"]
    assert [item["id"] for item in pulled] == [queued["id"]]      # 最早一条被拉走
    assert [item["id"] for item in pending] == [delivered["id"]]


# ─────────────────────────────────────────────────────── 账本 / DB 护栏
def test_node_push_never_touches_the_ledger(conn):
    before = scalar(conn, "SELECT count(*) FROM ledger_entry")
    node = _node()
    notification = _enqueue(conn, node)
    _pull(conn, node)
    _ack(conn, node, notification["id"])
    _read(conn, node, notification["id"])
    assert scalar(conn, "SELECT count(*) FROM ledger_entry") == before


def test_database_rejects_sensitive_payload_keys_even_bypassing_the_service(conn):
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.cursor() as cur:
            cur.execute("INSERT INTO node_notifications"
                        " (id, node_id, severity, category, template_key, payload)"
                        " VALUES (%s, %s, 'P1', 'alert', 'node.alert.cpu_high', %s)",
                        (uuid.uuid4(), _node(), Jsonb({"email": "ops@example.com"})))
    conn.rollback()


def test_database_enforces_p0_expiry_and_enum_values(conn):
    for values in (("P9", None), ("P0", None)):
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute("INSERT INTO node_notifications"
                            " (id, node_id, severity, category, template_key, expires_at)"
                            " VALUES (%s, %s, %s, 'alert', 'node.alert.cpu_high', %s)",
                            (uuid.uuid4(), _node(), values[0], values[1]))
        conn.rollback()


def test_columns_other_than_state_are_immutable(conn):
    notification = _enqueue(conn, _node())
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.cursor() as cur:
            cur.execute("UPDATE node_notifications SET template_key = 'other.key'"
                        " WHERE id = %s", (uuid.UUID(notification["id"]),))


def test_delete_within_retention_is_rejected(conn):
    notification = _enqueue(conn, _node())
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM node_notifications WHERE id = %s",
                        (uuid.UUID(notification["id"]),))


def test_delivery_rows_are_append_only(conn):
    node = _node()
    notification = _enqueue(conn, node)
    _pull(conn, node)
    delivery_id = _rows(conn, "SELECT id FROM node_notification_deliveries"
                              " WHERE notification_id = %s", (uuid.UUID(notification["id"]),))[0]["id"]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.cursor() as cur:
            cur.execute("UPDATE node_notification_deliveries SET status = 'failed'"
                        " WHERE id = %s", (delivery_id,))


def test_event_rows_are_append_only(conn):
    notification = _enqueue(conn, _node())
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.cursor() as cur:
            cur.execute("UPDATE node_notification_events SET event = 'read'"
                        " WHERE notification_id = %s", (uuid.UUID(notification["id"]),))


def test_truncate_is_rejected(migrated):
    connection = connect(migrated, autocommit=True)
    try:
        for table in ("node_notifications", "node_notification_deliveries",
                      "node_notification_events"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with connection.cursor() as cur:
                    cur.execute(f"TRUNCATE {table}")
    finally:
        connection.close()


# ─────────────────────────────────────────────────────── HTTP 路由
def _client(*, factory=None, node_auth=None, admin_auth=None, now=NOW) -> TestClient:
    app = FastAPI()
    app.include_router(create_router(connection_factory=factory, node_auth=node_auth,
                                     admin_auth=admin_auth, now_provider=lambda: now))
    return TestClient(app)


def test_router_is_fail_closed_without_auth_wiring():
    client = _client()
    for method, path in (("get", "/api/v1/node/notifications"),
                         ("post", f"/api/v1/node/notifications/{uuid.uuid4()}/ack"),
                         ("post", f"/api/v1/node/notifications/{uuid.uuid4()}/read"),
                         ("get", "/api/v1/node/notifications/unread_count"),
                         ("post", "/api/v1/admin/notifications/node"),
                         ("get", "/api/v1/admin/notifications/node")):
        kwargs = {"json": {}} if method == "post" else {}
        response = getattr(client, method)(path, **kwargs)
        assert response.status_code == 401, (method, path, response.text[:120])
        assert response.json()["error"]["code"] == 40101


def test_router_node_flow_pull_ack_read(connection_factory):
    node = _node()
    admin = _client(factory=connection_factory,
                    node_auth=lambda request: {"node_id": node},
                    admin_auth=lambda request: {"actor": "ops:test"})
    created = admin.post("/api/v1/admin/notifications/node", json={
        "node_id": node, "severity": "P1", "category": "earnings",
        "template_key": "node.earnings.settled",
        "payload": {"amount_minor": 2500, "currency": "USD", "reason_code": "settled"}})
    assert created.status_code == 201, created.text
    notification = created.json()
    assert notification["state"] == "queued" and notification["payload"]["amount_minor"] == 2500

    client = _client(factory=connection_factory, node_auth=lambda request: {"node_id": node},
                     admin_auth=lambda request: {"actor": "ops:test"})
    page = client.get("/api/v1/node/notifications", headers={"X-Request-Id": "rid-pull"})
    assert page.status_code == 200 and page.headers["X-Request-Id"] == "rid-pull"
    body = page.json()
    assert [item["id"] for item in body["items"]] == [notification["id"]]
    assert body["has_more"] is False and body["next_cursor"]

    assert client.get("/api/v1/node/notifications/unread_count").json() == {"unread": 1}
    acked = client.post(f"/api/v1/node/notifications/{notification['id']}/ack")
    assert acked.status_code == 200 and acked.json() == {"accepted": True, "state": "delivered"}
    read = client.post(f"/api/v1/node/notifications/{notification['id']}/read")
    assert read.json() == {"accepted": True, "state": "read"}
    assert client.get("/api/v1/node/notifications/unread_count").json() == {"unread": 0}


def test_router_rejects_cross_node_and_expired_actions(connection_factory):
    owner, stranger = _node(), _node()
    admin = _client(factory=connection_factory, node_auth=lambda request: {"node_id": owner},
                    admin_auth=lambda request: {"actor": "ops:test"})
    notification = admin.post("/api/v1/admin/notifications/node", json={
        "node_id": owner, "severity": "P1", "category": "alert",
        "template_key": "node.alert.cpu_high"}).json()
    other = _client(factory=connection_factory, node_auth=lambda request: {"node_id": stranger},
                    admin_auth=lambda request: {"actor": "ops:test"})
    response = other.post(f"/api/v1/node/notifications/{notification['id']}/ack")
    assert response.status_code == 404 and response.json()["error"]["code"] == 40401
    assert response.headers["X-Request-Id"]


def test_router_admin_list_and_validation(connection_factory):
    node = _node()
    client = _client(factory=connection_factory, node_auth=lambda request: {"node_id": node},
                     admin_auth=lambda request: {"actor": "ops:test"})
    assert client.post("/api/v1/admin/notifications/node", json={
        "node_id": node, "severity": "P2", "category": "maintenance",
        "template_key": "node.maintenance.window"}).status_code == 201
    listing = client.get(f"/api/v1/admin/notifications/node?node_id={node}")
    assert listing.status_code == 200 and listing.json()["items"][0]["node_id"] == node
    bad = client.post("/api/v1/admin/notifications/node",
                      json={"node_id": node, "severity": "P9", "category": "alert",
                            "template_key": "node.alert.cpu_high"})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == 40001


def test_router_returns_503_when_the_switch_is_off(connection_factory, monkeypatch):
    node = _node()
    client = _client(factory=connection_factory, node_auth=lambda request: {"node_id": node},
                     admin_auth=lambda request: {"actor": "ops:test"})
    monkeypatch.delenv(PUSH_ENV, raising=False)
    pulled = client.get("/api/v1/node/notifications")
    assert pulled.status_code == 503 and pulled.json()["error"]["code"] == 50001
    created = client.post("/api/v1/admin/notifications/node", json={
        "node_id": node, "severity": "P1", "category": "alert",
        "template_key": "node.alert.cpu_high"})
    assert created.status_code == 503 and created.json()["error"]["code"] == 50001
