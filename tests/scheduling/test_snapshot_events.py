# SPDX-License-Identifier: AGPL-3.0-or-later
"""公开快照 / 事件生产（M04 §1「只发布输入」/ §4.1 snapshot / §4.2 / 02-events §1）。

两个门禁：

* 快照**只含输入**：不得出现 ρ/κ、权重、阈值、凭据；
* 事件**信封齐全**：12 个字段都在，5 个事件的必含业务键都在。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.scheduling import events, facts, models, snapshot
from app.scheduling.errors import InvalidArgument, NotFound


# --------------------------------------------------------------------------- 快照
@pytest.fixture
def book(factory, now):
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",))
    factory.quote("n_aaa", low=800, high=1_000)
    factory.node("n_bbb")
    factory.capacity("n_bbb", models=("m1",))
    factory.quote("n_bbb", access="B", low=900, high=None)
    return now


def test_latest_snapshot_lists_the_active_book(conn, book, now):
    payload = snapshot.build(conn, period="latest", now=now)
    assert payload["period"] == "latest"
    assert payload["quote_version"] == 2
    assert len(payload["quotes"]) == 2
    assert {item["access"] for item in payload["quotes"]} == {"A1", "B"}
    assert payload["summary"]["quote_count"] == 2


def test_snapshot_publishes_inputs_only(conn, book, now):
    """只发布输入：不得出现 ρ / κ / 权重 / 阈值 / 凭据（INV-12）。"""
    payload = snapshot.build(conn, period="latest", now=now)
    text = str(payload).lower()
    for forbidden in ("rho", "kappa", "cost_micro", "score", "weight", "secret", "token_cost",
                      "credential", "api_key"):
        assert forbidden not in text
    quote = payload["quotes"][0]
    assert set(quote) == {"quote_id", "node_id", "access", "model", "unit", "price_min",
                          "price_max", "quote_version", "expires_at"}
    assert quote["price_min"] == {"amount": "8.00", "unit": "token"}


def test_snapshot_is_deterministic(conn, book, now):
    first = snapshot.build(conn, period="latest", now=now)
    second = snapshot.build(conn, period="latest", now=now)
    assert first == second


def test_snapshot_model_filter(conn, book, now):
    payload = snapshot.build(conn, period="latest", now=now, model="m1")
    assert len(payload["quotes"]) == 2
    payload = snapshot.build(conn, period="latest", now=now, model="other")
    assert payload["quotes"] == []
    assert payload["summary"]["quote_count"] == 0


def test_snapshot_historical_period(conn, factory, now):
    """``YYYY-MM-DD``：该 UTC 日结束时的历史视图（对账 / 事后解释用）。"""
    factory.node("n_day")
    factory.capacity("n_day", models=("m_day",))
    factory.quote("n_day", model="m_day", ttl_s=86_400)      # 当天内一直有效
    payload = snapshot.build(conn, period=now.strftime("%Y-%m-%d"), now=now)
    assert [item["node_id"] for item in payload["quotes"]] == ["n_day"]
    assert payload["quote_version"] >= 1


def test_snapshot_rejects_future_and_unknown_periods(conn, book, now):
    with pytest.raises(InvalidArgument):
        snapshot.build(conn, period="2999-01-01", now=now)
    with pytest.raises(NotFound):
        snapshot.build(conn, period="yesterday", now=now)
    with pytest.raises(InvalidArgument):
        snapshot.build(conn, period="2026-13-45", now=now)


def test_snapshot_version_matches_the_book(conn, book, now):
    assert snapshot.version(conn, now=now) == 2


def test_snapshot_excludes_expired_quotes(conn, factory, now):
    factory.node("n_exp")
    factory.capacity("n_exp", models=("m2",))
    factory.quote("n_exp", model="m2", ttl_s=10)
    payload = snapshot.build(conn, period="latest", now=now + timedelta(seconds=30))
    assert all(item["model"] != "m2" for item in payload["quotes"])


# --------------------------------------------------------------------------- 事件信封
def test_envelope_has_all_twelve_fields(now):
    envelope = events.build_envelope(
        event_type="quote.created", aggregate_id="q-1",
        payload={"quote_id": "q-1", "node_id": "n1", "model": "m1", "price_minor": 800,
                 "ttl_s": 60}, trace_id="trace-1", occurred_at=now)
    assert set(envelope) == {"event_id", "type", "version", "occurred_at", "producer",
                             "aggregate_type", "aggregate_id", "correlation_id",
                             "causation_id", "trace_id", "idempotency_key", "payload"}
    assert envelope["producer"] == "M04"
    assert envelope["aggregate_type"] == "quote"
    assert envelope["version"] == 1
    assert envelope["occurred_at"] == now.isoformat()
    assert uuid.UUID(envelope["event_id"]).version == 7


@pytest.mark.parametrize("event_type,keys", list(facts.EVENT_PAYLOAD_KEYS.items()))
def test_every_event_requires_its_business_keys(event_type, keys):
    payload = {key: None for key in keys}
    events.validate_payload(event_type, payload)                  # 键全 → 通过
    for key in keys:
        broken = {item: None for item in keys if item != key}
        with pytest.raises(ValueError):
            events.validate_payload(event_type, broken)


def test_unknown_event_type_is_rejected():
    with pytest.raises(ValueError):
        events.validate_payload("quote.updated", {})


def test_envelope_rejects_overlong_identifiers(now):
    with pytest.raises(ValueError):
        events.build_envelope(event_type="quote.created", aggregate_id="x" * 200,
                              payload={"quote_id": "q", "node_id": "n", "model": "m",
                                       "price_minor": 1, "ttl_s": 1},
                              trace_id="trace-1", occurred_at=now)


def test_trace_id_defaults_to_event_id(now):
    envelope = events.build_envelope(
        event_type="quote.expired", aggregate_id="q-1",
        payload={"quote_id": "q-1", "node_id": "n1", "model": "m1", "price_minor": 800,
                 "ttl_s": 60}, trace_id="", occurred_at=now)
    assert envelope["trace_id"] == uuid.UUID(envelope["event_id"]).hex


# --------------------------------------------------------------------------- 5 个构造器
def _quote() -> models.Quote:
    return models.Quote(id=uuid.uuid4(), node_id="n1", access="A1", model="m1", unit="token",
                        ask_price_minor=800, price_max_minor=1_000, currency="USD", ttl_s=60,
                        state="active", quote_version=1,
                        created_at=__import__("datetime").datetime(2026, 10, 23,
                                                                  tzinfo=__import__("datetime").timezone.utc),
                        expires_at=__import__("datetime").datetime(2026, 10, 23, 0, 1,
                                                                  tzinfo=__import__("datetime").timezone.utc))


def _booking() -> models.Booking:
    moment = __import__("datetime").datetime(2026, 10, 23, tzinfo=__import__("datetime").timezone.utc)
    return models.Booking(id=uuid.uuid4(), quote_id=uuid.uuid4(), bid_id=None, node_id="n1",
                          tenant_id=uuid.uuid4(), request_id="req-1", price_minor=875,
                          strategy="mid", state="held", created_at=moment,
                          expires_at=moment + timedelta(seconds=60))


def test_quote_builders_write_the_declared_payloads(conn):
    """T4 起事件走 outbox（同一事务），payload 仍按 02-events §3 的键集合落库。"""
    first = _quote()
    second = _quote()
    events.quote_created(conn, first, trace_id="t")
    events.quote_expired(conn, second, trace_id="t")
    rows = conn.execute(
        "SELECT type, payload FROM scheduling_outbox ORDER BY created_at, type").fetchall()
    assert [row[0] for row in rows] == ["quote.created", "quote.expired"]
    for _type, payload in rows:
        assert set(payload) >= {"quote_id", "node_id", "model", "price_minor", "ttl_s"}


def test_booking_builders_write_the_declared_payloads(conn):
    events.booking_created(conn, _booking(), trace_id="t")
    events.booking_expired(conn, _booking(), trace_id="t")
    rows = conn.execute("SELECT type, payload FROM scheduling_outbox ORDER BY type").fetchall()
    assert [row[0] for row in rows] == ["booking.created", "booking.expired"]
    for _type, payload in rows:
        assert set(payload) >= {"booking_id", "node_id", "request_id", "expires_at"}


def test_routing_decided_payload_uses_decision_id_as_snapshot_id(conn):
    moment = __import__("datetime").datetime(2026, 10, 23, tzinfo=__import__("datetime").timezone.utc)
    decision = models.Decision(decision_id=uuid.uuid4(), trace_id="trace-1", attempt_no=1,
                               snapshot_ts=moment, quote_version=1,
                               policy_version="000000000000", request_digest="a" * 64,
                               chosen={"node_id": "n1", "upstream_id": "", "access": "A1",
                                       "model": "m1", "unit": "token"},
                               outcome="routed", reason_codes=["rep_missing"],
                               decided_at=moment)
    events.routing_decided(conn, decision, trace_id="trace-1")
    payload = conn.execute("SELECT payload FROM scheduling_outbox").fetchone()[0]
    assert payload["request_id"] == "trace-1"
    assert payload["node_id"] == "n1"
    assert payload["snapshot_id"] == str(decision.decision_id)
    assert payload["reason_codes"] == ["rep_missing"]


def test_emit_is_transactional_with_the_business_fact(conn):
    """02-events §2.1：事件与业务事实同一事务——业务回滚，事件也不能留下。"""
    events.quote_created(conn, _quote(), trace_id="t")
    assert conn.execute("SELECT count(*) FROM scheduling_outbox").fetchone()[0] == 1
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM scheduling_outbox").fetchone()[0] == 0


def test_event_idempotency_key_is_unique(conn):
    """同一事实重复入队只产生一条事件（生产侧按业务键去重）。"""
    quote = _quote()
    events.quote_created(conn, quote, trace_id="t")
    events.quote_created(conn, quote, trace_id="t")
    assert conn.execute("SELECT count(*) FROM scheduling_outbox").fetchone()[0] == 1
