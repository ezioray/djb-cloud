# SPDX-License-Identifier: Apache-2.0
"""事件 / outbox / 请求日志的存储护栏（M03 §5、02-events §2、INV-M03-02、INV-M03-06）。"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest

from app.gateway import events, models, outbox, store
from gatewaykit import NOW


def _envelope(request_id: str | None = None, *, kind: str = "completed") -> dict:
    identifier = request_id or str(uuid.uuid4())
    if kind == "completed":
        return events.request_completed_event(request_id=identifier, model="m1", tokens_in=3,
                                              tokens_out=2, latency_ms=10, node_id="n_001",
                                              usage_source="actual", trace_id="t1",
                                              occurred_at=NOW)
    return events.request_failed_event(request_id=identifier, error_code=50901,
                                       upstream_error_class=None, attempts=1, trace_id="t1",
                                       occurred_at=NOW)


# ─────────────────────────────────────────────────────── 信封
def test_completed_envelope_has_twelve_fields():
    envelope = _envelope()
    assert set(envelope) == {"event_id", "type", "version", "occurred_at", "producer",
                             "aggregate_type", "aggregate_id", "correlation_id",
                             "causation_id", "trace_id", "idempotency_key", "payload"}
    assert envelope["type"] == "request.completed"
    assert envelope["producer"] == "M03" and envelope["version"] == 1
    assert uuid.UUID(envelope["event_id"]).version == 7
    assert envelope["occurred_at"] == "2026-10-23T04:00:00Z"


def test_failed_envelope_payload():
    envelope = _envelope(kind="failed")
    assert envelope["type"] == "request.failed"
    assert set(envelope["payload"]) == {"request_id", "error_code", "upstream_error_class",
                                        "attempts"}


def test_unregistered_event_type_is_rejected():
    with pytest.raises(ValueError):
        events.build_envelope(event_type="usage.recorded", aggregate_id="x", payload={},
                              trace_id="t1", occurred_at=NOW)


# ─────────────────────────────────────────────────────── outbox 写入与投递
def test_enqueue_is_idempotent_by_idempotency_key(conn):
    envelope = _envelope()
    outbox.enqueue(conn, envelope)
    outbox.enqueue(conn, envelope)
    count = conn.execute("SELECT count(*) FROM m03_outbox WHERE aggregate_id = %s",
                         (envelope["aggregate_id"],)).fetchone()[0]
    assert count == 1


def test_dispatch_without_publisher_keeps_rows_pending(conn):
    envelope = _envelope()
    outbox.enqueue(conn, envelope)
    result = outbox.dispatch_once(conn, now=NOW)
    assert result == {"published": 0, "failed": 0}
    row = conn.execute("SELECT published_at, attempts FROM m03_outbox WHERE event_id = %s",
                       (envelope["event_id"],)).fetchone()
    assert row[0] is None and row[1] == 0


def test_dispatch_publishes_and_marks(conn):
    envelope = _envelope()
    outbox.enqueue(conn, envelope)
    seen: list[tuple[str, dict]] = []
    outbox.set_publisher(lambda event_type, env: seen.append((event_type, env)))
    try:
        result = outbox.dispatch_once(conn, now=NOW)
    finally:
        outbox.set_publisher(None)
    assert result == {"published": 1, "failed": 0}
    assert seen[0][0] == "request.completed"
    row = conn.execute("SELECT published_at, attempts FROM m03_outbox WHERE event_id = %s",
                       (envelope["event_id"],)).fetchone()
    assert row[0] is not None and row[1] == 1


def test_dispatch_failure_backs_off(conn):
    envelope = _envelope()
    outbox.enqueue(conn, envelope)

    def boom(event_type, env):
        raise RuntimeError("channel down")

    outbox.set_publisher(boom)
    try:
        result = outbox.dispatch_once(conn, now=NOW)
    finally:
        outbox.set_publisher(None)
    assert result == {"published": 0, "failed": 1}
    attempts, next_at, last_error = conn.execute(
        "SELECT attempts, next_attempt_at, last_error FROM m03_outbox WHERE event_id = %s",
        (envelope["event_id"],)).fetchone()
    assert attempts == 1
    assert next_at > NOW
    assert "channel down" in last_error


# ─────────────────────────────────────────────────────── 护栏（只追加 / 状态机）
def test_api_request_log_rejects_update(conn):
    record = models.RequestRecord(request_id=str(uuid.uuid4()), status="completed",
                                  http_status=200)
    store.log_request(conn, record, now=NOW)
    with pytest.raises(Exception) as info:
        conn.execute("UPDATE api_request_log SET status = 'failed' WHERE request_id = %s",
                     (record.request_id,))
    assert "append-only" in str(info.value) or "42501" in str(info.value)


def test_api_request_log_rejects_deleting_fresh_rows(conn):
    record = models.RequestRecord(request_id=str(uuid.uuid4()), status="completed",
                                  http_status=200)
    store.log_request(conn, record, now=NOW)
    with pytest.raises(Exception) as info:
        conn.execute("DELETE FROM api_request_log WHERE request_id = %s", (record.request_id,))
    assert "retention" in str(info.value) or "42501" in str(info.value)


def test_api_request_log_rejects_truncate(conn):
    with pytest.raises(Exception) as info:
        conn.execute("TRUNCATE api_request_log")
    assert "TRUNCATE" in str(info.value) or "42501" in str(info.value)


def test_api_request_log_rejects_duplicate_request_id(conn):
    request_id = str(uuid.uuid4())
    first = models.RequestRecord(request_id=request_id, status="completed", http_status=200)
    assert store.log_request(conn, first, now=NOW) is True
    second = models.RequestRecord(request_id=request_id, status="failed", http_status=500)
    assert store.log_request(conn, second, now=NOW) is False        # 不报错、不产生第二行


def test_api_request_log_limits_metadata_columns(conn):
    record = models.RequestRecord(request_id=str(uuid.uuid4()), status="completed",
                                  http_status=200, model="m" * 200)
    with pytest.raises(Exception):
        store.log_request(conn, record, now=NOW)


def _batch_row(conn, **overrides) -> str:
    batch_id = str(uuid.uuid4())
    values = {"batch_id": batch_id, "account_id": str(uuid.uuid4()), "kind": "chat",
              "model": "m1", "status": "queued", "total_items": 2}
    values.update(overrides)
    conn.execute(
        """INSERT INTO batch_jobs (batch_id, account_id, kind, model, status, total_items,
                                  created_at, updated_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (values["batch_id"], values["account_id"], values["kind"], values["model"],
         values["status"], values["total_items"], NOW, NOW))
    return batch_id


def test_batch_state_machine_blocks_illegal_transition(conn):
    batch_id = _batch_row(conn)
    with pytest.raises(Exception) as info:
        conn.execute("UPDATE batch_jobs SET status = 'succeeded' WHERE batch_id = %s",
                     (batch_id,))
    assert "illegal transition" in str(info.value) or "42501" in str(info.value)


def test_batch_terminal_status_is_immutable(conn):
    batch_id = _batch_row(conn, status="succeeded")
    with pytest.raises(Exception) as info:
        conn.execute("UPDATE batch_jobs SET status = 'canceled' WHERE batch_id = %s",
                     (batch_id,))
    assert "terminal" in str(info.value) or "42501" in str(info.value)


def test_batch_cancel_is_idempotent_in_db(conn):
    """INV-M03-06：取消幂等——重复取消返回当前状态，不报错、不再改业务列。"""
    batch_id = _batch_row(conn)
    conn.execute("UPDATE batch_jobs SET status = 'canceled' WHERE batch_id = %s", (batch_id,))
    row = conn.execute("SELECT status, canceled_at FROM batch_jobs WHERE batch_id = %s",
                       (batch_id,)).fetchone()
    assert row[0] == "canceled" and row[1] is not None
    canceled_at = row[1]
    conn.execute("UPDATE batch_jobs SET status = 'canceled' WHERE batch_id = %s", (batch_id,))
    again = conn.execute("SELECT status, canceled_at FROM batch_jobs WHERE batch_id = %s",
                         (batch_id,)).fetchone()
    assert again[0] == "canceled" and again[1] == canceled_at


def test_outbox_envelope_is_immutable(conn):
    envelope = _envelope()
    outbox.enqueue(conn, envelope)
    with pytest.raises(Exception) as info:
        conn.execute("UPDATE m03_outbox SET payload = %s::jsonb WHERE event_id = %s",
                     (json.dumps({"tampered": True}), envelope["event_id"]))
    assert "immutable" in str(info.value) or "42501" in str(info.value)


def test_outbox_rejects_deleting_pending_rows(conn):
    envelope = _envelope()
    outbox.enqueue(conn, envelope)
    with pytest.raises(Exception) as info:
        conn.execute("DELETE FROM m03_outbox WHERE event_id = %s", (envelope["event_id"],))
    assert "retention" in str(info.value) or "42501" in str(info.value)


def test_outbox_allows_deleting_published_rows_after_retention(conn):
    envelope = _envelope()
    outbox.enqueue(conn, envelope)
    old = NOW - timedelta(days=31)
    store.mark_outbox_published(conn, event_id=envelope["event_id"], now=old)
    conn.execute("DELETE FROM m03_outbox WHERE event_id = %s", (envelope["event_id"],))
    assert conn.execute("SELECT count(*) FROM m03_outbox WHERE event_id = %s",
                        (envelope["event_id"],)).fetchone()[0] == 0


def test_batch_items_require_existing_batch(conn):
    with pytest.raises(Exception):
        conn.execute(
            """INSERT INTO batch_items (item_id, batch_id, seq, custom_id, status,
                                        created_at, updated_at)
               VALUES (%s, %s, 1, 'c1', 'queued', %s, %s)""",
            (str(uuid.uuid4()), str(uuid.uuid4()), NOW, NOW))


def test_batch_items_custom_id_is_unique_per_batch(conn):
    batch_id = _batch_row(conn)
    insert = ("""INSERT INTO batch_items (item_id, batch_id, seq, custom_id, status,
                                          created_at, updated_at)
                 VALUES (%s, %s, %s, %s, 'queued', %s, %s)""")
    conn.execute(insert, (str(uuid.uuid4()), batch_id, 1, "c1", NOW, NOW))
    with pytest.raises(Exception):
        conn.execute(insert, (str(uuid.uuid4()), batch_id, 2, "c1", NOW, NOW))
