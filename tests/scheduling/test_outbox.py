# SPDX-License-Identifier: AGPL-3.0-or-later
"""事件出站（CR-4 / 迁移 407）：至少一次、幂等、退避、DLQ（02-events §2）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.scheduling import events, facts, models, outbox


def _quote() -> models.Quote:
    from datetime import datetime, timezone

    moment = datetime(2026, 10, 23, tzinfo=timezone.utc)
    return models.Quote(id=uuid.uuid4(), node_id="n1", access="A1", model="m1", unit="token",
                        ask_price_minor=800, price_max_minor=1_000, currency="USD", ttl_s=60,
                        state="active", quote_version=1, created_at=moment,
                        expires_at=moment + timedelta(seconds=60))


def _pending_count(conn) -> int:
    return conn.execute("SELECT count(*) FROM scheduling_outbox").fetchone()[0]


# --------------------------------------------------------------------------- 写入
def test_append_writes_the_envelope(conn, now):
    quote = _quote()
    events.quote_created(conn, quote, trace_id="t", occurred_at=now)
    row = conn.execute(
        """SELECT type, version, producer, aggregate_type, aggregate_id, trace_id,
                  idempotency_key, payload, published_at, attempts, next_attempt_at
             FROM scheduling_outbox""").fetchone()
    assert row[0] == "quote.created"
    assert row[1] == facts.EVENT_VERSION
    assert row[2] == "M04"
    assert row[3] == "quote"
    assert row[4] == quote.quote_id
    assert row[5] == "t"
    assert row[6] == f"quote.created:{quote.quote_id}"
    assert set(row[7]) >= {"quote_id", "node_id", "model", "price_minor", "ttl_s"}
    assert row[8] is None                     # 未投递
    assert row[9] == 0
    assert row[10] == now                     # 立即可投（与事件时刻一致，可复算）


def test_append_is_idempotent_per_business_key(conn, now):
    quote = _quote()
    assert events.quote_created(conn, quote, trace_id="t", occurred_at=now)["type"] \
        == "quote.created"
    events.quote_created(conn, quote, trace_id="t", occurred_at=now)
    assert _pending_count(conn) == 1


def test_outbox_rejects_unknown_event_type(conn, now):
    """库层白名单兜底：M04 只能生产这 5 个事件。"""
    envelope = events.build_envelope(event_type="quote.created", aggregate_id="q1",
                                     payload={"quote_id": "q1", "node_id": "n", "model": "m",
                                              "price_minor": 1, "ttl_s": 1},
                                     trace_id="t", occurred_at=now)
    with pytest.raises(Exception):
        conn.execute(
            """INSERT INTO scheduling_outbox (event_id, type, aggregate_type, aggregate_id,
                                              trace_id, idempotency_key, payload)
               VALUES (%s, 'quote.updated', 'quote', 'q1', 't', 'k1', '{}'::jsonb)""",
            (uuid.uuid4(),))


def test_outbox_rejects_missing_payload_keys(conn, now):
    with pytest.raises(Exception):
        conn.execute(
            """INSERT INTO scheduling_outbox (event_id, type, aggregate_type, aggregate_id,
                                              trace_id, idempotency_key, payload)
               VALUES (%s, 'quote.created', 'quote', 'q1', 't', 'k-missing',
                       '{"quote_id":"q1"}'::jsonb)""", (uuid.uuid4(),))


def test_outbox_rejects_delete_and_immutable_updates(conn, now):
    events.quote_created(conn, _quote(), trace_id="t", occurred_at=now)
    with pytest.raises(Exception):
        conn.execute("DELETE FROM scheduling_outbox")
        conn.execute("UPDATE scheduling_outbox SET payload = '{}'::jsonb")
    conn.rollback()


# --------------------------------------------------------------------------- 派发
def test_dispatch_marks_published(conn, now):
    events.quote_created(conn, _quote(), trace_id="t", occurred_at=now)
    seen: list[tuple[str, dict]] = []
    result = outbox.dispatch(conn, now=now,
                            publisher=lambda event_type, envelope: seen.append(
                                (event_type, envelope)))
    assert result == {"sent": 1, "failed": 0}
    assert seen[0][0] == "quote.created"
    assert set(seen[0][1]) >= {"event_id", "type", "payload", "trace_id", "idempotency_key"}
    assert outbox.stats(conn) == {"pending": 0, "published": 1, "dead": 0}


def test_dispatch_retries_with_backoff(conn, now):
    events.quote_created(conn, _quote(), trace_id="t", occurred_at=now)

    def boom(_event_type, _envelope):
        raise RuntimeError("bus down")

    assert outbox.dispatch(conn, now=now, publisher=boom) == {"sent": 0, "failed": 1}
    row = conn.execute("SELECT attempts, next_attempt_at, last_error FROM scheduling_outbox"
                       ).fetchone()
    assert row[0] == 1
    assert row[1] == now + timedelta(seconds=outbox.BACKOFF_S[0])   # 1 s
    assert "bus down" in row[2]
    # 退避未到期 → 不重复投递
    assert outbox.pending(conn, now=now) == []
    assert len(outbox.pending(conn, now=now + timedelta(seconds=2))) == 1


def test_backoff_ladder_and_dead_letter(conn, now):
    assert [outbox.backoff_s(i) for i in range(5)] == [1, 5, 30, 300, 1_800]
    events.quote_created(conn, _quote(), trace_id="t", occurred_at=now)
    event_id = conn.execute("SELECT event_id FROM scheduling_outbox").fetchone()[0]
    moment = now
    for step in range(8):
        attempts = outbox.mark_failed(conn, event_id, f"fail-{step}", now=moment)
        assert attempts == min(step + 1, 8)
        moment = moment + timedelta(seconds=outbox.backoff_s(step))
    dead = outbox.dead_letters(conn)
    assert len(dead) == 1 and dead[0]["attempts"] == 8
    assert outbox.stats(conn)["dead"] == 1
    # 人工重放：attempts 归零、立即可投
    assert outbox.requeue(conn, event_id, now=now) is True
    assert outbox.pending(conn, now=now) != []
    assert outbox.dead_letters(conn) == []


def test_dispatch_respects_limit_and_order(conn, now):
    for _ in range(3):
        events.quote_created(conn, _quote(), trace_id="t", occurred_at=now)
    seen: list[str] = []
    result = outbox.dispatch(conn, limit=2, now=now,
                            publisher=lambda t, e: seen.append(e["aggregate_id"]))
    assert result == {"sent": 2, "failed": 0}
    assert len(seen) == 2
    assert outbox.stats(conn)["pending"] == 1


def test_default_publisher_is_structured_log(conn, now, caplog):
    events.quote_created(conn, _quote(), trace_id="t", occurred_at=now)
    with caplog.at_level("INFO", logger="djb.scheduling.outbox"):
        assert outbox.dispatch(conn, now=now) == {"sent": 1, "failed": 0}
    assert any(record.message == "scheduling.event.dispatched" for record in caplog.records)


def test_publisher_hook_is_resettable():
    outbox.set_publisher(lambda *args: None)
    assert outbox.current_publisher() is not None
    outbox.set_publisher(None)
    assert outbox.current_publisher() is None


def test_events_set_publisher_delegates_to_outbox():
    marker = lambda *args: None                       # noqa: E731
    events.set_publisher(marker)
    try:
        assert outbox.current_publisher() is marker
    finally:
        events.set_publisher(None)
