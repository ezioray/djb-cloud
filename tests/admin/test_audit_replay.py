# SPDX-License-Identifier: Apache-2.0
"""操作回放：audit_log + outbox 合并时间线（只读、脱敏、游标分页）。"""
from __future__ import annotations

from datetime import timedelta

from admin_kit import (
    FIXED_NOW,
    apply_migrations,
    build_client,
    connect,
    create_schema,
    drop_schema,
    idempotency_key,
    insert_audit,
    m14_migration_files,
)
from app.data_gov import export as export_service

BASE = "/api/v1/admin/ops/audit-replay"


def _completed_export(connection, *, trace: str = "trace-m14", key: str = "replay") -> dict:
    row = export_service.create_request(
        connection, requester="ops-admin", tenant_id="tenant-a",
        body={"scope": {"object": "usage"}, "reason": "回放用例", "estimated_rows": 0},
        now=FIXED_NOW - timedelta(days=1), idempotency_key=idempotency_key(key),
        trace_id=trace)
    export_service.approve_request(connection, str(row["export_id"]),
                                   approver="ops-approver", tenant_id="tenant-a",
                                   now=FIXED_NOW - timedelta(days=1), trace_id=trace)
    export_service.start_request(connection, str(row["export_id"]),
                                 now=FIXED_NOW - timedelta(days=1), trace_id=trace)
    return export_service.complete_request(connection, str(row["export_id"]),
                                           row_count=3, now=FIXED_NOW, trace_id=trace)


def test_replay_requires_filter(client) -> None:
    response = client.get(BASE)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_replay_reads_audit_log(savepoint_conn, client) -> None:
    insert_audit(savepoint_conn, action="data.export.requested", actor="ops-admin",
                 target="exp-1", ts=FIXED_NOW, after={"object": "usage", "rows": 3})
    insert_audit(savepoint_conn, action="account.frozen", actor="risk", ts=FIXED_NOW)
    payload = client.get(BASE, params={"action": "data.export"}).json()
    assert payload["source"]["audit_log"] == "ok"
    assert payload["observed_at"]
    assert len(payload["data"]) == 1
    item = payload["data"][0]
    assert item["source"] == "audit" and item["action"] == "data.export.requested"
    assert item["owner_id"] == "ops-admin" and item["target"] == "exp-1"
    assert item["detail"] == {"object": "usage", "rows": 3}


def test_replay_owner_filter(savepoint_conn, client) -> None:
    insert_audit(savepoint_conn, action="data.export.requested", actor="ops-admin")
    insert_audit(savepoint_conn, action="data.export.requested", actor="someone-else")
    payload = client.get(BASE, params={"owner_id": "ops-admin"}).json()
    assert len(payload["data"]) == 1
    assert payload["data"][0]["owner_id"] == "ops-admin"


def test_replay_trace_filter_reads_outbox(savepoint_conn, client) -> None:
    _completed_export(savepoint_conn)
    payload = client.get(BASE, params={"trace_id": "trace-m14"}).json()
    events = [item for item in payload["data"] if item["source"] == "event"]
    assert events, payload
    event = events[0]
    assert event["action"] == "data.export.completed"
    assert event["trace_id"] == "trace-m14"
    assert event["payload"]["rows"] == 3
    assert event["state"] == "pending"


def test_replay_merges_same_timestamp_by_source(savepoint_conn, client) -> None:
    insert_audit(savepoint_conn, action="data.export.requested", actor="ops-admin",
                 ts=FIXED_NOW)
    _completed_export(savepoint_conn, trace="trace-merge", key="merge")
    payload = client.get(BASE, params={"action": "data.export"}).json()
    sources = [item["source"] for item in payload["data"]]
    assert sources == ["audit", "event"]                       # 同刻：审计在前（rank 0）


def test_replay_pagination(savepoint_conn, client) -> None:
    for index in range(3):
        insert_audit(savepoint_conn, action="data.export.requested", actor="ops-admin",
                     ts=FIXED_NOW + timedelta(minutes=index))
    first = client.get(BASE, params={"action": "data.export", "limit": 2}).json()
    assert len(first["data"]) == 2 and first["page"]["has_more"] is True
    second = client.get(BASE, params={"action": "data.export", "limit": 2,
                                      "cursor": first["page"]["next_cursor"]}).json()
    assert len(second["data"]) == 1 and second["page"]["has_more"] is False
    seen = [item["occurred_at"] for item in first["data"] + second["data"]]
    assert len(set(seen)) == 3


def test_replay_sanitises_sensitive_keys(savepoint_conn, client) -> None:
    insert_audit(savepoint_conn, action="data.export.requested", actor="ops-admin",
                 after={"secret": "abc", "api_key": "k", "email": "a@b",
                        "nested": {"token": "t", "ok": 1}, "impact_scope": "gateway"})
    payload = client.get(BASE, params={"action": "data.export"}).json()
    detail = payload["data"][0]["detail"]
    assert "secret" not in detail and "api_key" not in detail and "email" not in detail
    assert detail["nested"] == {"ok": 1}
    assert detail["impact_scope"] == "gateway"


def test_replay_rejects_invalid_cursor_and_action(client) -> None:
    assert client.get(BASE, params={"action": "data.export",
                                    "cursor": "%%%"}).status_code == 400
    assert client.get(BASE, params={"action": "bad action!"}).status_code == 400
    assert client.get(BASE, params={"trace_id": "x" * 200}).status_code == 400


def test_replay_degraded_without_audit_log(db, schema_prefix) -> None:
    name = f"{schema_prefix}_replaynoaudit"
    create_schema(name)
    try:
        apply_migrations(name, m14_migration_files())
        connection = connect(name, autocommit=False)
        try:
            with build_client(connection) as client:
                payload = client.get(BASE, params={"action": "data.export"}).json()
        finally:
            connection.close()
    finally:
        drop_schema(name)
    assert payload["data"] == []
    assert payload["source"] == {"audit_log": "unavailable", "outbox": "ok"}


def test_replay_permissions(readonly_client, nonadmin_client, unauth_client) -> None:
    assert readonly_client.get(BASE, params={"trace_id": "t"}).status_code == 200
    assert nonadmin_client.get(BASE, params={"trace_id": "t"}).status_code == 403
    assert unauth_client.get(BASE, params={"trace_id": "t"}).status_code == 401
