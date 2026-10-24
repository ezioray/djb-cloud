# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08 ↔ M06 记账适配：E3 / E4 两步 / E5 两步（真实 M06 网关；只 propose）。"""
from __future__ import annotations

import pytest

from app.treasury import errors, ledger

import m08kit

NOW = m08kit.FIXED_NOW


def test_to_micro_and_balance_checks():
    assert ledger.to_micro(100) == 1_000_000
    assert ledger.subject_account("acct-1") == "acct:acct-1"
    assert ledger.platform_account("1120") == "coa:1120"
    request = ledger.e3_request(
        attempt={"provider_txn_id": "txn-1", "amount_minor": 100},
        order={"account_id": "acct-1", "order_no": "PO-1", "amount_minor": 100},
        policy_version="v", occurred_at=NOW)
    assert request.balanced() and request.total_debit_minor() == 1_000_000
    assert request.key() == ("payment_attempt", "txn-1", 1)
    with pytest.raises(errors.BadRequest):
        ledger.e3_request(attempt={"amount_minor": 100},
                          order={"account_id": "a", "order_no": "PO-1"},
                          policy_version="v", occurred_at=NOW)


def test_e4_requires_balanced_settlement():
    attempt = {"provider_txn_id": "txn-2", "amount_minor": 100}
    order = {"account_id": "acct-1", "order_no": "PO-2", "amount_minor": 100}
    steps = ledger.e4_requests(attempt=attempt, order=order, settled_minor=99, fee_minor=1,
                               policy_version="v", occurred_at=NOW)
    assert len(steps) == 2 and all(step.balanced() for step in steps)
    with pytest.raises(errors.BadRequest):
        ledger.e4_requests(attempt=attempt, order=order, settled_minor=99, fee_minor=0,
                           policy_version="v", occurred_at=NOW)
    with pytest.raises(errors.BadRequest):
        ledger.e4_requests(attempt={"amount_minor": 100}, order=order, settled_minor=1,
                           fee_minor=0, policy_version="v", occurred_at=NOW)


def test_e5_two_steps_client_and_platform_target():
    client_steps = ledger.e5_requests(
        trade={"trade_id": "trade-1", "amount_minor": 100, "fee_minor": 1},
        policy_version="v", occurred_at=NOW)
    assert len(client_steps) == 2 and all(step.balanced() for step in client_steps)
    assert "1102" in {line.coa_code for line in client_steps[0].lines}
    platform_steps = ledger.e5_requests(
        trade={"trade_id": "trade-2", "amount_minor": 100, "fee_minor": 1,
               "fund_class": "PLATFORM"}, policy_version="v", occurred_at=NOW)
    assert "1109" in {line.coa_code for line in platform_steps[0].lines}
    with pytest.raises(errors.BadRequest):
        ledger.e5_requests(trade={"amount_minor": 100, "fee_minor": 1},
                           policy_version="v", occurred_at=NOW)


def test_post_one_requires_poster_and_balance():
    request = ledger.e3_request(
        attempt={"provider_txn_id": "txn-3", "amount_minor": 100},
        order={"account_id": "acct-1", "order_no": "PO-3", "amount_minor": 100},
        policy_version="v", occurred_at=NOW)
    with pytest.raises(errors.LedgerUnavailable):
        ledger.post_one(None, None, request)
    recording = ledger.RecordingPoster()
    assert ledger.post_one(None, recording, request)["journal_id"] == "rec-1"
    unbalanced = ledger.PostingRequest(
        event_type="E3", unit_type="USD", source_type="payment_attempt", source_id="txn-x",
        event_seq=1, policy_version="v",
        lines=(ledger.LedgerLine("acct:a", "1120", "D", 100, "deposit"),),
        occurred_at=NOW)
    with pytest.raises(errors.BadRequest):
        ledger.post_one(None, recording, unbalanced)


def test_e3_e4_e5_post_to_real_ledger(savepoint_conn):
    adapter = m08kit.LedgerAdapter()
    e3 = ledger.e3_request(
        attempt={"provider_txn_id": "txn-real", "amount_minor": 100},
        order={"account_id": "acct-1", "order_no": "PO-REAL", "amount_minor": 100},
        policy_version="m08-pool-default", occurred_at=NOW)
    ledger.post_one(savepoint_conn, adapter, e3)
    e4 = ledger.e4_requests(
        attempt={"provider_txn_id": "txn-real", "amount_minor": 100},
        order={"account_id": "acct-1", "order_no": "PO-REAL", "amount_minor": 100},
        settled_minor=99, fee_minor=1, policy_version="m08-pool-default", occurred_at=NOW)
    assert len(ledger.post_many(savepoint_conn, adapter, e4)) == 2
    e5 = ledger.e5_requests(
        trade={"trade_id": "trade-real", "amount_minor": 100, "fee_minor": 1},
        policy_version="m08-pool-default", occurred_at=NOW)
    ledger.post_many(savepoint_conn, adapter, e5)
    with savepoint_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM journal_entry WHERE source_id IN"
                    " ('txn-real', 'trade-real')")
        assert int(cur.fetchone()[0]) == 5
        cur.execute("SELECT event_type, event_seq FROM journal_entry"
                    " WHERE source_id = 'txn-real' ORDER BY seq")
        assert cur.fetchall() == [("E3", 1), ("E4", 2), ("E4", 3)]
    ledger.post_one(savepoint_conn, adapter, e3)
    with savepoint_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM journal_entry WHERE source_id = 'txn-real'")
        assert int(cur.fetchone()[0]) == 3
