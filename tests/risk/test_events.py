# SPDX-License-Identifier: Apache-2.0
"""事件：02-events 信封 / payload 白名单（INV-01·INV-05）/ outbox 幂等 / 重试与 DLQ。"""
from __future__ import annotations

import uuid
import psycopg
import pytest

from app.risk import errors, events, facts
from riskkit import FIXED_NOW, outbox_events


def _event(event_type=facts.EVENT_ACTION_REQUESTED, payload=None, key=None):
    return events.build_event(
        event_type,
        aggregate_type="risk_case",
        aggregate_id=str(uuid.uuid4()),
        payload=payload or {"case_id": str(uuid.uuid4()), "subject_type": "account",
                            "subject_id": "sha256:" + "d" * 64, "action": "freeze",
                            "reason_code": "risk_case_freeze", "expires_at": None},
        occurred_at=FIXED_NOW,
        idempotency_key=key or f"idem-{uuid.uuid4().hex}",
        trace_id="trace-1")


# ───────────────────────────────────────────────────────────── payload 白名单
def test_payload_rejects_unknown_and_threshold_keys() -> None:
    with pytest.raises(errors.BadRequest) as excinfo:
        events.validate_payload(facts.EVENT_CASE_OPENED,
                                {"case_id": "c1", "threshold": 0.8})
    assert excinfo.value.code == 40001
    # 已登记键但名字像阈值 → 同样拒绝
    with pytest.raises(errors.BadRequest):
        events.validate_payload(facts.EVENT_LIMIT_HIT,
                                {"subject_id": "s", "limit_type": "qps", "value": 1,
                                 "window_s": 60, "weight": 0.3})
    # PII 形态值也拒绝
    with pytest.raises(errors.BadRequest):
        events.validate_payload(facts.EVENT_CASE_OPENED,
                                {"case_id": "c1", "subject_id": "user@example.com",
                                 "risk_type": "sybil", "severity": "P2"})


def test_envelope_has_all_required_fields() -> None:
    event = _event()
    for field in ("event_id", "type", "version", "occurred_at", "producer", "aggregate_type",
                  "aggregate_id", "trace_id", "idempotency_key", "payload"):
        assert field in event
    assert event["producer"] == "M11"
    assert event["version"] == 1
    assert uuid.UUID(event["event_id"])


# ───────────────────────────────────────────────────────────── outbox 幂等
def test_enqueue_is_idempotent_by_key(conn) -> None:
    key = f"risk_action:{uuid.uuid4()}:1"
    event = _event(key=key)
    first = events.enqueue(conn, event)
    second = events.enqueue(conn, event)
    assert first == second
    assert len([row for row in outbox_events(conn)
                if row["idempotency_key"] == key]) == 1


def test_outbox_retry_backoff_and_dead(conn) -> None:
    event = _event()
    events.enqueue(conn, event)
    for _ in range(7):
        assert events.mark_failed(conn, event["event_id"], "boom") == "retry"
    assert events.mark_failed(conn, event["event_id"], "boom") == "dead"
    row = [item for item in outbox_events(conn)
           if str(item["event_id"]) == event["event_id"]][0]
    assert row["status"] == "dead"
    assert row["attempts"] == events.MAX_ATTEMPTS


def test_mark_published(conn) -> None:
    event = _event()
    events.enqueue(conn, event)
    events.mark_published(conn, event["event_id"], at=FIXED_NOW)
    row = [item for item in outbox_events(conn)
           if str(item["event_id"]) == event["event_id"]][0]
    assert row["status"] == "published"


# ───────────────────────────────────────────────────────────── risk.limit.hit
def test_record_limit_hit_is_idempotent_by_source_event(conn) -> None:
    source = str(uuid.uuid4())
    first = events.record_limit_hit(
        conn, subject_hash="sha256:" + "e" * 64, limit_type="qps", value=10, window_s=60,
        occurred_at=FIXED_NOW, source_event_id=source, source_module="M03",
        payload={"request_id": "req-1"})
    second = events.record_limit_hit(
        conn, subject_hash="sha256:" + "e" * 64, limit_type="qps", value=10, window_s=60,
        occurred_at=FIXED_NOW, source_event_id=source, source_module="M03",
        payload={"request_id": "req-1"})
    assert first["created"] is True
    assert second["created"] is False
    assert second["event_id"] == first["event_id"]
    hits = [event for event in outbox_events(conn) if event["type"] == facts.EVENT_LIMIT_HIT]
    assert len(hits) == 1
    assert hits[0]["payload"] == {"subject_id": "sha256:" + "e" * 64, "limit_type": "qps",
                                  "value": 10, "window_s": 60}


def test_limit_hit_rejects_pii_payload(conn) -> None:
    with pytest.raises(errors.BadRequest):
        events.record_limit_hit(conn, subject_hash="sha256:" + "f" * 64, limit_type="qps",
                                value=1, window_s=60, occurred_at=FIXED_NOW,
                                payload={"email": "user@example.com"})


# ───────────────────────────────────────────────────────────── 只追加护栏
def test_risk_events_are_append_only(conn) -> None:
    signal = events.record_limit_hit(
        conn, subject_hash="sha256:" + "1" * 64, limit_type="qps", value=1, window_s=60,
        occurred_at=FIXED_NOW)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("DELETE FROM risk_events WHERE event_id = %s", (signal["event_id"],))


def test_outbox_envelope_is_immutable(conn) -> None:
    event = _event()
    events.enqueue(conn, event)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("UPDATE risk_outbox SET payload = '{\"threshold\": 1}'::jsonb"
                        " WHERE event_id = %s", (event["event_id"],))


def test_outbox_db_guard_rejects_threshold_payload(conn) -> None:
    """INV-01 库层兜底：payload 带 threshold / weight / blocklist 键直接拒写。"""
    import psycopg

    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction(), conn.cursor() as cur:
            cur.execute(
                "INSERT INTO risk_outbox (event_id, type, aggregate_type, aggregate_id,"
                " idempotency_key, payload, occurred_at) VALUES (%s, 'risk.case.opened',"
                " 'risk_case', 'c1', %s, %s::jsonb, now())",
                (str(uuid.uuid4()), f"idem-{uuid.uuid4().hex}",
                 '{"case_id": "c1", "threshold": 0.8}'))
