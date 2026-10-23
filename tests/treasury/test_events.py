# SPDX-License-Identifier: Apache-2.0
"""M08 事件生产：信封 / payload 白名单 / outbox 幂等 / 退避与 dead（02-events）。"""
from __future__ import annotations

import pytest

from app.treasury import clock, errors, events, facts

import m08kit

NOW = m08kit.FIXED_NOW


def test_validate_payload_whitelist_and_forbidden_keys():
    payload = events.validate_payload("payment.created", {
        "order_no": "PO-1", "amount_minor": 100, "method": "card", "currency": "USD"})
    assert payload["order_no"] == "PO-1"
    with pytest.raises(errors.BadRequest):
        events.validate_payload("payment.created", {"order_no": "PO-1", "extra": 1})
    with pytest.raises(errors.BadRequest):
        events.validate_payload("payment.created", {"order_no": "PO-1", "signature": "x"})
    with pytest.raises(errors.BadRequest):
        events.validate_payload("unknown.event", {})
    with pytest.raises(errors.BadRequest):
        events.validate_payload("payment.created", {"order_no": {"nested": 1}})
    with pytest.raises(errors.BadRequest):
        events.validate_payload("payment.created", {"order_no": "a" * 300})
    with pytest.raises(errors.BadRequest):
        events.validate_payload("payment.created", {"order_no": "user@example.com"})
    assert set(facts.PRODUCED_EVENTS) == set(facts.EVENT_PAYLOAD_FIELDS)


def test_build_event_envelope():
    event = events.build_event("payment.paid", aggregate_type="payment_order",
                               aggregate_id="order-1", payload={
                                   "order_no": "PO-1", "paid_at": clock.iso(NOW),
                                   "provider_ref": "txn-1", "amount_minor": 100},
                               occurred_at=NOW, idempotency_key="payment_order_paid:order-1")
    assert event["producer"] == "M08" and event["version"] == 1
    assert event["type"] == "payment.paid" and event["occurred_at"] == NOW
    assert len(event["event_id"]) == 36 and event["trace_id"]
    with pytest.raises(errors.BadRequest):
        events.build_event("payment.paid", aggregate_type="x", aggregate_id="1",
                           payload={}, occurred_at=NOW, idempotency_key="")


def test_outbox_idempotency_and_backoff(savepoint_conn):
    event = events.build_event("payment.created", aggregate_type="payment_order",
                               aggregate_id="order-2", payload={
                                   "order_no": "PO-2", "amount_minor": 100,
                                   "method": "card", "currency": "USD"},
                               occurred_at=NOW, idempotency_key="payment_order:order-2")
    first = events.enqueue(savepoint_conn, event)
    second = events.enqueue(savepoint_conn, {**event, "event_id": "00000000-0000-7000-8000-000000000001"})
    assert first == second
    pending = events.pending(savepoint_conn)
    assert len(pending) == 1
    event_id = pending[0]["event_id"]
    assert events.mark_failed(savepoint_conn, event_id, "boom") == "retry"
    # 手动把 next_attempt_at 拨到过去，再次失败累计到 dead
    for _ in range(events.MAX_ATTEMPTS - 1):
        savepoint_conn.execute("UPDATE m08_outbox SET next_attempt_at = now() - interval '1 s'"
                               " WHERE event_id = %s", (event_id,))
        outcome = events.mark_failed(savepoint_conn, event_id, "boom")
    assert outcome == "dead"
    row = events.published_events(savepoint_conn)[0]
    assert row["status"] == "dead" and row["attempts"] == events.MAX_ATTEMPTS
    with pytest.raises(errors.BadRequest):
        events.mark_failed(savepoint_conn, "00000000-0000-7000-8000-0000000000ff", "x")


def test_mark_published(savepoint_conn):
    event = events.build_event("payment.failed", aggregate_type="payment_order",
                               aggregate_id="order-3",
                               payload={"order_no": "PO-3", "error_code": "failed"},
                               occurred_at=NOW, idempotency_key="payment_order_failed:order-3")
    event_id = events.enqueue(savepoint_conn, event)
    events.mark_published(savepoint_conn, event_id, at=NOW)
    row = events.published_events(savepoint_conn)[0]
    assert row["status"] == "published" and row["published_at"] is not None


def test_domain_event_builders(savepoint_conn):
    order = m08kit.make_order(savepoint_conn, order_no="PO-EV-1")
    attempt = m08kit.make_attempt(savepoint_conn, order, provider_txn_id="txn-ev-1")
    events.payment_created(savepoint_conn, order)
    events.payment_paid(savepoint_conn, order, provider_ref="txn-ev-1", paid_at=NOW)
    events.payment_failed(savepoint_conn, order, error_code="failed", occurred_at=NOW)
    events.wallet_switched(savepoint_conn, pool_id="polygon:hot:CLIENT", from_wallet="w1",
                           to_wallet="w2", reason="manual", occurred_at=NOW)
    events.sweep_completed(savepoint_conn, batch_no="SW-1", from_wallet="w1", to_wallet="w2",
                           amount_minor=100, txid="0xtx", occurred_at=NOW, transfer_id="t1")
    intent = {"intent_id": "11111111-1111-7111-8111-111111111111", "kind": "PAYOUT",
              "expires_at": NOW, "correlation_id": "PB-1"}
    events.signing_requested(savepoint_conn, intent=intent, signing_request_id="s1")
    events.signing_signed(savepoint_conn, intent=intent, signing_request_id="s1",
                          signer_type="owner", signed_at=NOW)
    types = [item["type"] for item in m08kit.outbox_events(savepoint_conn)]
    assert types[:3] == ["payment.created", "payment.paid", "payment.failed"]
    assert {"wallet.switched", "sweep.completed", "signing.requested",
            "signing.signed"} <= set(types)


def test_payout_and_refund_event_builders(savepoint_conn):
    address = m08kit.make_payout_address(savepoint_conn)
    from app.treasury import models, payout
    batch = payout.create_payout_batch(
        savepoint_conn, models.PayoutBatchDraft(items=(
            models.PayoutItemDraft(payee_account_id="acct-1",
                                   payee_address=address["address"],
                                   gross_minor=5_000, fee_minor=0),),
            attestation_ref="att-1"), maker="fin", idempotency_key=None,
        config_provider=None, now=NOW)
    events.payout_paid(savepoint_conn, batch["batch"], txid="0xtx", settled_at=NOW)
    refund = {"refund_request_id": "22222222-2222-7222-8222-222222222222",
              "refund_no": "RF-1", "order_no": "PO-1", "amount_minor": 100,
              "reason_code": "unused"}
    events.refund_completed(savepoint_conn, refund, succeeded_at=NOW)
    types = [item["type"] for item in m08kit.outbox_events(savepoint_conn)]
    assert "payout.paid" in types and "refund.completed" in types
