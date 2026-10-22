# SPDX-License-Identifier: Apache-2.0
"""config_outbox（1005）：三个事件的契约、幂等追加、只追加护栏（需要 DJB_DSN）。"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from psycopg.types.json import Jsonb

from app.config_center import outbox
from app.config_center.errors import ValidationFailed
from configkit import assert_db_error

NOW = datetime(2026, 10, 21, 2, 30, tzinfo=timezone.utc)


def published() -> outbox.OutboxEvent:
    return outbox.published_event(
        namespace="billing", key="billing.service_fee_bps", version=3, risk_level="P0",
        policy_version="323b64cf6e17", effective_at=NOW, request_id=str(uuid.uuid4()),
        trace_id="trace-pub-1", occurred_at=NOW)


def rolled_back() -> outbox.OutboxEvent:
    return outbox.rolled_back_event(
        namespace="billing", key="billing.service_fee_bps", version=4, rollback_to=2,
        reason_code="public_pool_below_floor", trace_id="trace-rb-1", occurred_at=NOW)


def drift() -> outbox.OutboxEvent:
    return outbox.drift_detected_event(
        namespace="billing", key="billing.service_fee_bps", expected=1500, actual=1400,
        detected_at=NOW, trace_id="trace-drift-1", occurred_at=NOW)


# ─────────────────────────────────────────────── 纯函数：契约校验
@pytest.mark.parametrize("factory", [published, rolled_back, drift])
def test_builders_produce_valid_events(factory):
    event = outbox.validate_event(factory())
    assert event.producer == "M10"
    assert event.aggregate_type == "config_key"
    assert event.type in outbox.EVENT_TYPES
    assert set(outbox.REQUIRED_PAYLOAD_KEYS[event.type]) <= set(event.payload)


def test_idempotency_keys_are_business_derived():
    assert published().idempotency_key == \
        "config.published:billing.service_fee_bps:global::3"
    assert rolled_back().idempotency_key == \
        "config.rolled_back:billing.service_fee_bps:global::4"
    assert drift().idempotency_key.startswith(
        "config.drift_detected:billing.service_fee_bps:global::")


def test_invalid_events_are_rejected():
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.deleted", aggregate_id="a.b", payload={}, idempotency_key="x" * 8,
            trace_id="t"))
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.published", aggregate_id="a.b", payload={}, idempotency_key="x" * 8,
            trace_id="t"))
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.published", aggregate_id="a.b",
            payload={"namespace": "billing"}, idempotency_key="x" * 8, trace_id="t"))
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.published", aggregate_id="", payload={}, idempotency_key="x" * 8,
            trace_id="t"))
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.published", aggregate_id="a.b", payload={}, idempotency_key="short",
            trace_id="t"))
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.published", aggregate_id="a.b", payload={}, idempotency_key="x" * 8,
            trace_id="t", version=0))
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.published", aggregate_id="a.b", payload={}, idempotency_key="x" * 8,
            trace_id="t", producer="M06"))
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.published", aggregate_id="a.b", payload={}, idempotency_key="x" * 8,
            trace_id="t", aggregate_type="journal_entry"))
    with pytest.raises(ValidationFailed):
        outbox.validate_event(outbox.OutboxEvent(
            type="config.published", aggregate_id="a.b", payload={}, idempotency_key="x" * 8,
            trace_id="t", occurred_at=datetime(2026, 10, 21, 2, 30)))     # 无时区


# ─────────────────────────────────────────────── DB：追加 / 幂等 / 只追加
def test_append_and_idempotent(conn):
    event = published()
    row = outbox.append_event(conn, event)
    assert row["type"] == "config.published"
    assert row["producer"] == "M10"
    assert row["published_at"] is None
    again = outbox.append_event(conn, event)
    assert again["event_id"] == row["event_id"]
    assert conn.execute("SELECT count(*) FROM config_outbox").fetchone()[0] == 1


def test_pending_and_mark_published(conn):
    first = outbox.append_event(conn, published())
    outbox.append_event(conn, rolled_back())
    pending = outbox.pending_events(conn)
    assert sorted(row["type"] for row in pending) == ["config.published", "config.rolled_back"]
    assert outbox.mark_published(conn, first["event_id"], published_at=NOW) == 1
    assert outbox.mark_published(conn, first["event_id"], published_at=NOW) == 0
    pending = outbox.pending_events(conn)
    assert [row["type"] for row in pending] == ["config.rolled_back"]
    assert outbox.pending_events(conn, limit=1)[0]["type"] == "config.rolled_back"
    with pytest.raises(ValidationFailed):
        outbox.pending_events(conn, limit=0)


def test_outbox_is_append_only(conn):
    row = outbox.append_event(conn, published())
    assert_db_error(conn, "only delivery fields", lambda c: c.execute(
        "UPDATE config_outbox SET payload = %s WHERE event_id = %s",
        (Jsonb({"x": 1}), row["event_id"])))
    assert_db_error(conn, "append-only", lambda c: c.execute(
        "DELETE FROM config_outbox WHERE event_id = %s", (row["event_id"],)))
    assert_db_error(conn, "TRUNCATE not allowed", lambda c: c.execute("TRUNCATE config_outbox"))
    # 已投递的不能改回去
    outbox.mark_published(conn, row["event_id"], published_at=NOW)
    assert_db_error(conn, "write-once", lambda c: c.execute(
        "UPDATE config_outbox SET published_at = NULL WHERE event_id = %s", (row["event_id"],)))


def test_payload_contract_is_enforced_by_db(conn):
    assert_db_error(conn, "config_outbox_payload_ck", lambda c: c.execute(
        """INSERT INTO config_outbox
             (type, aggregate_type, aggregate_id, trace_id, idempotency_key, payload)
           VALUES ('config.published', 'config_key', 'a.b', 't', %s, %s)""",
        (str(uuid.uuid4()), Jsonb({"key": "a.b"}))))
    # 未登记 type 会先撞 payload 白名单（payload CHECK 没有匹配分支）——两条约束都在库里
    assert_db_error(conn, "config_outbox_", lambda c: c.execute(
        """INSERT INTO config_outbox
             (type, aggregate_type, aggregate_id, trace_id, idempotency_key, payload)
           VALUES ('config.deleted', 'config_key', 'a.b', 't', %s, %s)""",
        (str(uuid.uuid4()), Jsonb({}))))


def test_drift_event_payload_keeps_raw_values(conn):
    row = outbox.append_event(conn, drift())
    assert row["payload"]["expected"] == 1500
    assert row["payload"]["actual"] == 1400
    assert json.loads(json.dumps(row["payload"]))["key"] == "billing.service_fee_bps"
