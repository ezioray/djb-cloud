# SPDX-License-Identifier: AGPL-3.0-or-later
"""消费 M03/M04 事件：估算落库、失败不计费、成交价核对、配置发布（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid

import pytest

from app.metering import consumers, errors, facts, features, receipts, signing
from meterkit import (NOW, TEST_CONSUMER_KEY, TEST_PROVIDER_KEY, count, fetch_all,
                      receipt)


def _event(event_type: str, payload: dict, *, trace_id: str = "trace-consume") -> dict:
    return {"event_id": str(uuid.uuid4()), "type": event_type, "version": 1,
            "occurred_at": "2026-10-23T04:00:00Z", "producer": "M03",
            "trace_id": trace_id, "payload": payload}


def _completed_payload(*, request_id: str, account_id, node_id: str,
                       tokens_in: int = 1000, tokens_out: int = 500) -> dict:
    return {"request_id": request_id, "attempt_no": 1, "account_id": str(account_id),
            "node_id": node_id, "model": "m1", "access": "A1", "unit": "token",
            "tokens_in": tokens_in, "tokens_out": tokens_out}


def _enable_estimated(monkeypatch) -> None:
    """打开「无收据按网关计量落 estimated」开关（默认关闭）。"""
    real = features.enabled
    monkeypatch.setattr(features, "enabled",
                        lambda name: True if name == "metering.estimated_usage_from_gateway"
                        else real(name))


def _prices(in_micro: int = 800, out_micro: int = 1000):
    return lambda request_id, model, access: {"in_price_micro": in_micro,
                                              "out_price_micro": out_micro}


# ─────────────────────────────────────────────────────── request.completed
def test_completed_is_skipped_while_switch_is_off(migrated, conn, account):
    """默认关闭：缺收据不计量（保持「等收据到达再落库」的保守行为）。"""
    node_id = f"n_cons_{uuid.uuid4().hex[:8]}"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    event = _event("request.completed", _completed_payload(request_id="req_cons_off",
                                                           account_id=account, node_id=node_id))
    result = consumers.consume(conn, event, now=NOW, price_provider=_prices())
    assert result["action"] == "skipped" and result["reason"] == "switch_off"
    assert fetch_all(migrated, "SELECT count(*) FROM usage_records WHERE request_id = %s",
                     ("req_cons_off",))[0][0] == 0


def test_completed_records_estimated_usage_when_enabled(migrated, conn, account, monkeypatch):
    node_id = f"n_cons_{uuid.uuid4().hex[:8]}"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    _enable_estimated(monkeypatch)
    event = _event("request.completed", _completed_payload(request_id="req_cons_on",
                                                           account_id=account, node_id=node_id))
    result = consumers.consume(conn, event, now=NOW, price_provider=_prices())
    assert result["action"] == "recorded" and result["amount_minor"] == 130
    rows = fetch_all(migrated,
                     """SELECT usage_source, amount_minor, receipt_id, state, tokens_in,
                               tokens_out
                          FROM usage_records WHERE request_id = %s""", ("req_cons_on",))
    assert rows == [("estimated", 130, None, "recorded", 1000, 500)]
    outbox_rows = fetch_all(migrated,
                            "SELECT type, payload FROM metering_outbox WHERE aggregate_id = %s",
                            (result["usage_id"],))
    assert [row[0] for row in outbox_rows] == ["usage.recorded"]
    assert outbox_rows[0][1]["source"] == "estimated"


def test_completed_replay_is_idempotent(migrated, conn, account, monkeypatch):
    node_id = f"n_cons_{uuid.uuid4().hex[:8]}"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    _enable_estimated(monkeypatch)
    payload = _completed_payload(request_id="req_cons_idem", account_id=account,
                                 node_id=node_id)
    actions = [consumers.consume(conn, _event("request.completed", payload), now=NOW,
                                 price_provider=_prices())["action"] for _ in range(3)]
    assert actions == ["recorded", "exists", "exists"]
    assert fetch_all(migrated, "SELECT count(*) FROM usage_records WHERE request_id = %s",
                     ("req_cons_idem",))[0][0] == 1
    assert fetch_all(migrated, """SELECT count(*) FROM metering_outbox o
                                    JOIN usage_records u ON u.usage_id::text = o.aggregate_id
                                   WHERE u.request_id = %s""", ("req_cons_idem",))[0][0] == 1


def test_completed_defers_to_existing_receipt_usage(migrated, conn, account):
    """有收据时以收据为准（不落 estimated，不重复计量）。"""
    node_id = f"n_cons_{uuid.uuid4().hex[:8]}"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id, request_id="req_cons_receipt")
    outcome = receipts.accept_batch(conn, [body], node_id=node_id, trace_id="t",
                                    keys=signing.SignatureKeys(TEST_PROVIDER_KEY,
                                                               TEST_CONSUMER_KEY), now=NOW)
    assert outcome.accepted == (body["receipt_id"],)
    result = consumers.consume(conn, _event("request.completed",
                                            _completed_payload(request_id="req_cons_receipt",
                                                               account_id=account,
                                                               node_id=node_id)),
                               now=NOW, price_provider=_prices())
    assert result["action"] == "exists" and result["usage_source"] == "dual"
    assert fetch_all(migrated, "SELECT count(*) FROM usage_records WHERE request_id = %s",
                     ("req_cons_receipt",))[0][0] == 1


def test_completed_without_price_is_skipped(migrated, conn, account, monkeypatch):
    node_id = f"n_cons_{uuid.uuid4().hex[:8]}"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    _enable_estimated(monkeypatch)
    event = _event("request.completed", _completed_payload(request_id="req_cons_noprice",
                                                           account_id=account, node_id=node_id))
    result = consumers.consume(conn, event, now=NOW, price_provider=None)
    assert result["action"] == "skipped" and result["reason"] == "price_unavailable"


def test_completed_missing_required_field_raises(migrated, conn, monkeypatch):
    """开关打开后，缺必填字段必须显式失败（不静默落一条缺 model 的用量）。"""
    _enable_estimated(monkeypatch)
    payload = _completed_payload(request_id="req_cons_bad", account_id=uuid.uuid4(),
                                 node_id="n1")
    payload.pop("model")
    with pytest.raises(errors.InvalidArgument):
        consumers.consume(conn, _event("request.completed", payload), now=NOW,
                          price_provider=_prices())


# ─────────────────────────────────────────────────────── request.failed
def test_failed_request_writes_nothing(migrated, conn):
    before = count(migrated, "usage_records")
    result = consumers.consume(conn, _event("request.failed",
                                            {"request_id": "req_failed_1", "attempt_no": 1}))
    assert result["action"] == "noop"
    assert count(migrated, "usage_records") == before


def test_failed_after_estimated_flags_correction(migrated, conn, account, monkeypatch):
    node_id = f"n_cons_{uuid.uuid4().hex[:8]}"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    _enable_estimated(monkeypatch)
    recorded = consumers.consume(conn, _event("request.completed",
                                              _completed_payload(request_id="req_failed_2",
                                                                 account_id=account,
                                                                 node_id=node_id)),
                                 now=NOW, price_provider=_prices())
    assert recorded["action"] == "recorded"
    result = consumers.consume(conn, _event("request.failed",
                                            {"request_id": "req_failed_2", "attempt_no": 1}))
    assert result["action"] == "needs_correction"
    assert result["reason_code"] == "estimate_fix" and result["amount_minor"] == 130
    # 原值不动（append-only）：等 T4 追加校正
    rows = fetch_all(migrated, "SELECT amount_minor, state FROM usage_records "
                               "WHERE request_id = %s", ("req_failed_2",))
    assert rows == [(130, "recorded")]


def test_failed_replay_is_idempotent(migrated, conn):
    event = _event("request.failed", {"request_id": "req_failed_3"})
    results = [consumers.consume(conn, event)["action"] for _ in range(3)]
    assert results == ["noop", "noop", "noop"]


# ─────────────────────────────────────────────────────── booking.created
def test_booking_created_checks_price_without_writing(migrated, conn, account, monkeypatch):
    node_id = f"n_cons_{uuid.uuid4().hex[:8]}"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    _enable_estimated(monkeypatch)
    consumers.consume(conn, _event("request.completed",
                                   _completed_payload(request_id="req_booking_1",
                                                      account_id=account, node_id=node_id)),
                      now=NOW, price_provider=_prices())
    before = count(migrated, "usage_records")
    result = consumers.consume(conn, _event("booking.created",
                                            {"booking_id": "b-1", "request_id": "req_booking_1",
                                             "model": "m1", "access": "A1"}),
                               price_provider=_prices())
    assert result["action"] == "checked" and result["amount_minor"] == 130
    assert result["in_price_micro"] == 800 and result["out_price_micro"] == 1000
    assert count(migrated, "usage_records") == before          # 只读核对


def test_booking_created_without_usage_is_noop(migrated, conn):
    result = consumers.consume(conn, _event("booking.created", {"booking_id": "b-2",
                                                                "request_id": "req_unknown"}),
                               price_provider=_prices())
    assert result["action"] == "noop" and result["reason"] == "no_usage"


# ─────────────────────────────────────────────────────── config.published
def test_config_published_applies_and_ignores_stale_or_foreign():
    applied = consumers.consume(None, _event("config.published",
                                             {"namespace": "metering", "version": 5}))
    assert applied == {"action": "applied", "namespace": "metering", "version": 5}
    stale = consumers.consume(None, _event("config.published",
                                           {"namespace": "metering", "version": 4}),
                              current_version=5)
    assert stale["action"] == "ignored" and stale["reason"] == "stale_version"
    foreign = consumers.consume(None, _event("config.published",
                                             {"namespace": "routing", "version": 9}))
    assert foreign == {"action": "ignored", "namespace": "routing"}
    with pytest.raises(errors.InvalidArgument):
        consumers.consume(None, _event("config.published", {"namespace": "metering",
                                                            "version": 0}))


# ─────────────────────────────────────────────────────── 分发
def test_consume_ignores_unknown_event_type():
    result = consumers.consume(None, {"type": "usage.exploded", "payload": {}})
    assert result == {"action": "ignored", "type": "usage.exploded"}


def test_consumer_registry_covers_contract_events():
    assert set(consumers._CONSUMERS) == set(facts.CONSUMED_EVENTS)
