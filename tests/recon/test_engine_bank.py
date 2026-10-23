# SPDX-License-Identifier: Apache-2.0
"""scope=bank 三方对账：payout / refund ↔ E8/E11 ↔ 银行流水（§20.5.4）。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.recon import engine, errors, facts
from reconkit import (FIXED_NOW, fetch_exceptions, journal_line_fixture, post_journal,
                      recon_spec, seed_payout_item, seed_refund_request)

NET = 84_500_000               # 84.50 USD（micro）
FEE = 500_000                  # 0.50
GROSS = 85_000_000             # 85.00
TS = FIXED_NOW - timedelta(hours=2)
PAID_AT = FIXED_NOW - timedelta(hours=1)


def _run(conn, *, deps=None):
    return engine.run(conn, recon_spec("bank"), deps=deps, now=FIXED_NOW)


def _post_e8(conn, item_id: str, *, gross: int = GROSS, net: int = NET,
             fee: int = FEE, ts=TS) -> str:
    lines = [journal_line_fixture("2201", "D", gross, entry_type="payout"),
             journal_line_fixture("1102", "C", net, entry_type="payout",
                                  qty_minor=net, wallet_id="wallet-warm"),
             journal_line_fixture("5102", "C", fee, entry_type="payout")]
    return post_journal(conn, lines, event_type="E8", source_type="payout_item",
                        source_id=item_id, ts=ts, event_seq=2)


def _post_e11(conn, refund_id: str, *, amount: int = 50_000_000, gas: int = 200_000,
              ts=TS) -> str:
    total = amount + gas
    lines = [journal_line_fixture("2203", "D", amount, entry_type="refund"),
             journal_line_fixture("5102", "D", gas, entry_type="refund"),
             journal_line_fixture("1102", "C", total, entry_type="refund",
                                  qty_minor=total, wallet_id="wallet-warm")]
    return post_journal(conn, lines, event_type="E11", source_type="refund",
                        source_id=refund_id, ts=ts, event_seq=2)


def _bank_row(txid: str, amount_minor: int, *, posted_at=PAID_AT,
              currency: str = "USD") -> dict:
    return {"txid": txid, "amount": amount_minor, "currency": currency,
            "posted_at": posted_at}


def _payout(conn, **kwargs):
    params = {"net_minor": 8_450, "fee_minor": 50, "created_at": TS,
              "chain_tx_id": "0xtx-" + "ab" * 8}
    params.update(kwargs)
    return seed_payout_item(conn, **params)


def _kinds(conn, run_id: str) -> list[dict]:
    return fetch_exceptions(conn, run_id)


# ─────────────────────────────────────────────────────────────── 匹配
def test_matched_payout_with_journal_and_bank(conn) -> None:
    item = _payout(conn, chain_tx_id="0xtx-payout-1")
    _post_e8(conn, item["item_id"])
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("0xtx-payout-1", 8_450)]))[0]
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert run["book_minor"] == NET
    assert run["external_minor"] == NET
    assert run["rule_version"] == "m09-bank-r1"
    assert result["metrics"]["bank_statement_source"] == "provided"
    assert len(result["metrics"]["bank_statement_sha256"]) == 64
    assert result["metrics"]["batch_checked"] == 1
    assert _kinds(conn, str(run["run_id"])) == []


def test_matched_refund_with_journal_and_bank(conn) -> None:
    refund = seed_refund_request(conn, amount_minor=5_000, created_at=TS)
    _post_e11(conn, refund["refund_request_id"])
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row(refund["refund_request_id"], 5_000)]))[0]
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert run["book_minor"] == 50_000_000
    assert run["external_minor"] == 50_000_000
    assert _kinds(conn, str(run["run_id"])) == []


# ─────────────────────────────────────────────────────────────── 未匹配
def test_unmatched_payout_journal_and_bank(conn) -> None:
    no_journal = _payout(conn, chain_tx_id="0xtx-no-journal")
    with_journal = _payout(conn, chain_tx_id="0xtx-no-bank")
    _post_e8(conn, with_journal["item_id"])
    result = _run(conn)[0]
    exceptions = {item["ref_id"]: item for item in _kinds(conn, str(result["run"]["run_id"]))}
    assert exceptions[no_journal["item_id"]]["kind"] == "missing_in_ledger"
    assert exceptions[no_journal["item_id"]]["diff_minor"] == -NET
    assert exceptions[no_journal["item_id"]]["root_cause"] == "journal_and_bank_missing"
    assert exceptions[with_journal["item_id"]]["kind"] == "missing_external"
    assert exceptions[with_journal["item_id"]]["diff_minor"] == NET
    assert exceptions[with_journal["item_id"]]["root_cause"] == "bank_row_missing"


def test_unmatched_bank_row(conn) -> None:
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("bank-orphan", 12_345)]))[0]
    item = _kinds(conn, str(result["run"]["run_id"]))[0]
    assert item["kind"] == "missing_in_ledger"
    assert item["ref_type"] == "bank_row"
    assert item["diff_minor"] == -123_450_000
    assert item["root_cause"] == "unmatched_bank_row"


def test_journal_without_m08_fact(conn) -> None:
    _post_e8(conn, "ghost-item-id")
    result = _run(conn)[0]
    item = _kinds(conn, str(result["run"]["run_id"]))[0]
    assert item["kind"] == "missing_external"
    assert item["ref_type"] == "journal"
    assert item["diff_minor"] == NET
    assert item["root_cause"] == "journal_without_m08_fact"
    assert result["metrics"]["journal_unmapped"] == 1


# ─────────────────────────────────────────────────────────────── 金额差
def test_amount_mismatch_between_journal_and_bank(conn) -> None:
    item = _payout(conn, chain_tx_id="0xtx-underpaid")
    _post_e8(conn, item["item_id"])
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("0xtx-underpaid", 8_400)]))[0]
    exception = _kinds(conn, str(result["run"]["run_id"]))[0]
    assert exception["kind"] == "amount_mismatch"
    assert exception["diff_minor"] == 500_000              # 0.50 USD
    assert exception["root_cause"] == "underpaid"
    assert exception["severity"] == "P2"


def test_amount_mismatch_between_item_and_journal(conn) -> None:
    item = _payout(conn, chain_tx_id="0xtx-item-diff")
    _post_e8(conn, item["item_id"], gross=84_500_000, net=84_000_000, fee=FEE)
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("0xtx-item-diff", 8_400)]))[0]
    exception = _kinds(conn, str(result["run"]["run_id"]))[0]
    assert exception["kind"] == "amount_mismatch"
    assert exception["diff_minor"] == -500_000
    assert exception["root_cause"] == "m08_vs_journal"


def test_batch_totals_must_equal_items(conn) -> None:
    item = _payout(conn, chain_tx_id="0xtx-batch-diff", total_gross_minor=9_050,
                   total_fee_minor=50, total_net_minor=9_000)
    _post_e8(conn, item["item_id"])
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("0xtx-batch-diff", 8_450)]))[0]
    exception = _kinds(conn, str(result["run"]["run_id"]))[0]
    assert exception["kind"] == "amount_mismatch"
    assert exception["ref_type"] == "payout_batch"
    assert exception["ref_id"] == item["batch_no"]
    assert exception["root_cause"] == "batch_totals_mismatch"
    assert exception["diff_minor"] == 5_500_000            # 9000 − 8450 分
    assert result["metrics"]["batch_inconsistent"] == 1


# ─────────────────────────────────────────────────────────────── 状态差
def test_amount_mismatch_over_1000_usd_is_p0(conn) -> None:
    """验收 A2：银行差异 1,240 USD 判 P0、首响 15 分钟。"""
    item = _payout(conn, net_minor=124_000, fee_minor=0, chain_tx_id="0xtx-large")
    post_journal(
        conn,
        [journal_line_fixture("2201", "D", 1_240_000_000, entry_type="payout"),
         journal_line_fixture("1102", "C", 1_240_000_000, entry_type="payout",
                              qty_minor=1_240_000_000, wallet_id="wallet-warm")],
        event_type="E8", source_type="payout_item", source_id=item["item_id"], ts=TS,
        event_seq=2)
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("0xtx-large", 0)]))[0]
    exception = _kinds(conn, str(result["run"]["run_id"]))[0]
    assert exception["kind"] == "amount_mismatch"
    assert exception["diff_minor"] == 1_240_000_000           # 1,240.00 USD
    assert exception["severity"] == "P0"
    assert exception["sla_due"] == FIXED_NOW + timedelta(minutes=15)


def test_payout_item_not_sent_but_journal_posted(conn) -> None:
    item = _payout(conn, status="failed", chain_tx_id="0xtx-failed")
    _post_e8(conn, item["item_id"])
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("0xtx-failed", 8_450)]))[0]
    exception = _kinds(conn, str(result["run"]["run_id"]))[0]
    assert exception["kind"] == "missing_external"
    assert exception["diff_minor"] == NET
    assert exception["root_cause"] == "payout_item_not_sent"


# ─────────────────────────────────────────────────────────────── 重复 / 币种
def test_duplicate_bank_rows_are_structural_p0(conn) -> None:
    item = _payout(conn, chain_tx_id="0xtx-dup")
    _post_e8(conn, item["item_id"])
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("0xtx-dup", 8_450), _bank_row("0xtx-dup", 8_450)]))[0]
    exceptions = _kinds(conn, str(result["run"]["run_id"]))
    assert len(exceptions) == 1
    assert exceptions[0]["kind"] == "duplicate"
    assert exceptions[0]["severity"] == "P0"
    assert result["metrics"]["bank_duplicate_rows"] == 1


def test_unsupported_currency_row_is_flagged(conn) -> None:
    result = _run(conn, deps=engine.EngineDeps(
        bank_statement=[_bank_row("bank-eur", 100, currency="EUR")]))[0]
    exception = _kinds(conn, str(result["run"]["run_id"]))[0]
    assert exception["kind"] == "unidentified"
    assert exception["root_cause"] == "unsupported_currency"
    assert result["metrics"]["currency_skipped"] == 1


# ─────────────────────────────────────────────────────────────── 幂等 / 空数据
def test_bank_replay_is_idempotent(conn) -> None:
    item = _payout(conn, chain_tx_id="0xtx-idem")
    _post_e8(conn, item["item_id"])
    deps = engine.EngineDeps(bank_statement=[_bank_row("0xtx-idem", 8_450)])
    first = _run(conn, deps=deps)[0]
    second = _run(conn, deps=deps)[0]
    assert second["duplicate"] is True
    assert second["run"]["run_id"] == first["run"]["run_id"]
    assert _kinds(conn, str(first["run"]["run_id"])) == []


def test_empty_bank_period_reports_no_source(conn) -> None:
    result = _run(conn)[0]
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert run["book_minor"] == 0 and run["external_minor"] == 0
    assert result["metrics"]["bank_statement_source"] == "absent"
    assert result["metrics"]["payout_items"] == 0
    assert result["metrics"]["refunds"] == 0


def test_empty_provided_statement_marks_provided(conn) -> None:
    result = _run(conn, deps=engine.EngineDeps(bank_statement=[]))[0]
    assert result["metrics"]["bank_statement_source"] == "provided"
    assert result["metrics"]["bank_rows"] == 0
    assert result["run"]["status"] == facts.RUN_STATUS_MATCHED


def test_invalid_bank_fixture_is_rejected(conn) -> None:
    deps = engine.EngineDeps(bank_statement=[{"txid": "x", "currency": "USD",
                                              "posted_at": TS}])
    with pytest.raises(errors.BadRequest):
        _run(conn, deps=deps)

