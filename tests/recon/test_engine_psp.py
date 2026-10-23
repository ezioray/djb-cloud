# SPDX-License-Identifier: Apache-2.0
"""scope=psp 三方对账：payment_attempts ↔ E3/E4 + PSP 结算文件（§20.5.3）。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.recon import engine, errors, facts, threeway
from reconkit import (FIXED_NOW, fetch_exceptions, journal_line_fixture, post_journal,
                      recon_spec, seed_payment_attempt)

GROSS = 100_000_000            # 100.00 USD（micro）
NET = 98_500_000               # 98.50
FEE = 1_500_000                # 1.50
CENTS = 10_000                 # 100.00 USD（分）
TS = FIXED_NOW - timedelta(hours=2)


def _run(conn, *, deps=None, spec=None):
    return engine.run(conn, spec or recon_spec("psp"), deps=deps, now=FIXED_NOW)


def _post_e3(conn, txn: str, *, gross: int = GROSS, ts=TS, subject: str = "acct-subject") -> str:
    return post_journal(
        conn,
        [journal_line_fixture("1120", "D", gross, account_id=f"acct:{subject}",
                              entry_type="deposit"),
         journal_line_fixture("2101", "C", gross, account_id=f"acct:{subject}",
                              entry_type="deposit")],
        event_type="E3", source_type="payment_attempt", source_id=txn, ts=ts, event_seq=1)


def _post_e4(conn, txn: str, *, gross: int = GROSS, net: int = NET, fee: int = FEE,
             book_fee: int | None = None, ts=TS) -> None:
    book_fee = fee if book_fee is None else book_fee
    post_journal(
        conn,
        [journal_line_fixture("1121", "D", net, entry_type="deposit"),
         journal_line_fixture("1910", "D", fee, entry_type="adjust"),
         journal_line_fixture("1120", "C", gross, entry_type="deposit")],
        event_type="E4", source_type="payment_attempt", source_id=txn, ts=ts, event_seq=2)
    post_journal(
        conn,
        [journal_line_fixture("1121", "D", book_fee, entry_type="deposit"),
         journal_line_fixture("5103", "D", book_fee, entry_type="adjust"),
         journal_line_fixture("1109", "C", book_fee, entry_type="transfer"),
         journal_line_fixture("1910", "C", book_fee, entry_type="adjust")],
        event_type="E4", source_type="payment_attempt", source_id=txn, ts=ts, event_seq=3)


def _attempt(conn, txn: str, **kwargs):
    params = {"provider_txn_id": txn, "amount_minor": CENTS, "created_at": TS}
    params.update(kwargs)
    return seed_payment_attempt(conn, **params)


def _kinds(conn, run_id: str) -> dict[str, dict]:
    return {item["kind"]: item for item in fetch_exceptions(conn, run_id)}


# ─────────────────────────────────────────────────────────────── 匹配
def test_matched_attempt_with_settlement_file(conn) -> None:
    txn = "psp-txn-1"
    _attempt(conn, txn, settled_minor=9_850, settlement_fee_minor=150)
    _post_e3(conn, txn)
    _post_e4(conn, txn)
    deps = engine.EngineDeps(psp_settlement=[
        {"provider_txn_id": txn, "settled_minor": 9_850, "fee_minor": 150, "currency": "USD"}])

    result = _run(conn, deps=deps)[0]
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert run["diff_minor"] == 0
    assert run["book_minor"] == GROSS
    assert run["external_minor"] == GROSS
    assert run["rule_version"] == "m09-psp-r1"
    assert result["metrics"]["matched_txns"] == 1
    assert result["metrics"]["settlement_source"] == "provided"
    assert len(result["metrics"]["settlement_sha256"]) == 64
    assert fetch_exceptions(conn, str(run["run_id"])) == []


# ─────────────────────────────────────────────────────────────── 未匹配（双向）
def test_unmatched_both_directions(conn) -> None:
    _attempt(conn, "psp-only-external")                       # PSP 有、账本无
    _post_e3(conn, "psp-only-book", gross=50_000_000)         # 账本有、PSP 无
    result = _run(conn)[0]
    exceptions = {item["ref_id"]: item for item in
                  fetch_exceptions(conn, str(result["run"]["run_id"]))}
    missing_book = exceptions["psp-only-external"]
    assert missing_book["kind"] == "missing_in_ledger"
    assert missing_book["diff_minor"] == -GROSS
    assert missing_book["root_cause"] == "attempt_not_booked"
    missing_psp = exceptions["psp-only-book"]
    assert missing_psp["kind"] == "missing_external"
    assert missing_psp["diff_minor"] == 50_000_000
    assert missing_psp["root_cause"] == "journal_without_attempt"
    assert result["run"]["status"] == facts.RUN_STATUS_EXCEPTIONS_OPEN


# ─────────────────────────────────────────────────────────────── 金额差
def test_amount_mismatch_is_graded_by_amount(conn) -> None:
    txn = "psp-amount-diff"
    _attempt(conn, txn, settled_minor=9_850, settlement_fee_minor=150)
    _post_e3(conn, txn, gross=GROSS - 1_000_000)              # E3 少 1.00 USD
    _post_e4(conn, txn)
    result = _run(conn)[0]
    item = fetch_exceptions(conn, str(result["run"]["run_id"]))[0]
    assert item["kind"] == "amount_mismatch"
    assert item["diff_minor"] == -1_000_000                   # book − external
    assert item["root_cause"] == "e3_gross_mismatch"
    assert item["severity"] == "P2"                           # 1.00 USD < 100
    assert item["sla_due"] == FIXED_NOW + timedelta(days=1)


# ─────────────────────────────────────────────────────────────── 状态差
def test_failed_attempt_but_journal_posted(conn) -> None:
    txn = "psp-failed-but-booked"
    _attempt(conn, txn, status="failed")
    _post_e3(conn, txn)
    _post_e4(conn, txn)
    result = _run(conn)[0]
    item = fetch_exceptions(conn, str(result["run"]["run_id"]))[0]
    assert item["kind"] == "missing_external"
    assert item["diff_minor"] == GROSS
    assert item["root_cause"] == "attempt_not_succeeded"
    assert item["severity"] == "P1"                           # 100.00 USD


# ─────────────────────────────────────────────────────────────── 手续费容差
def test_fee_tolerance_and_fee_diff(conn) -> None:
    over = "psp-fee-over"
    within = "psp-fee-within"
    for txn in (over, within):
        _attempt(conn, txn, settled_minor=9_850, settlement_fee_minor=150)
        _post_e3(conn, txn)
    _post_e4(conn, over, book_fee=FEE + 500_000)              # 账本 2.00 vs 1.50
    _post_e4(conn, within, book_fee=FEE + 10_000)             # 账本 1.51 vs 1.50（容差内）

    result = _run(conn)[0]
    exceptions = fetch_exceptions(conn, str(result["run"]["run_id"]))
    assert len(exceptions) == 1
    assert exceptions[0]["kind"] == "fee_diff"
    assert exceptions[0]["ref_id"] == over
    assert exceptions[0]["diff_minor"] == 500_000
    assert exceptions[0]["root_cause"] == "fee_out_of_tolerance"
    # 容差内的一笔算 matched
    assert result["metrics"]["matched_txns"] == 1


# ─────────────────────────────────────────────────────────────── 结算文件差异
def test_settlement_file_amount_mismatch(conn) -> None:
    txn = "psp-settle-diff"
    _attempt(conn, txn, settled_minor=9_850, settlement_fee_minor=150)
    _post_e3(conn, txn)
    _post_e4(conn, txn)
    deps = engine.EngineDeps(psp_settlement=[
        {"provider_txn_id": txn, "settled_minor": 9_800, "fee_minor": 150, "currency": "USD"}])
    result = _run(conn, deps=deps)[0]
    item = fetch_exceptions(conn, str(result["run"]["run_id"]))[0]
    assert item["kind"] == "amount_mismatch"
    assert item["ref_type"] == "psp_settlement"
    assert item["diff_minor"] == 500_000                      # 0.50 USD
    assert item["root_cause"] == "settlement_file_mismatch"


def test_settlement_row_without_attempt(conn) -> None:
    deps = engine.EngineDeps(psp_settlement=[
        {"provider_txn_id": "psp-orphan", "settled_minor": 4_000, "fee_minor": 0,
         "currency": "USD"}])
    result = _run(conn, deps=deps)[0]
    item = fetch_exceptions(conn, str(result["run"]["run_id"]))[0]
    assert item["kind"] == "missing_in_ledger"
    assert item["diff_minor"] == -40_000_000                  # 40.00 USD
    assert item["root_cause"] == "settlement_without_attempt"


def test_duplicate_settlement_rows_are_structural_p0(conn) -> None:
    txn = "psp-dup-settle"
    _attempt(conn, txn, settled_minor=9_850, settlement_fee_minor=150)
    _post_e3(conn, txn)
    _post_e4(conn, txn)
    row = {"provider_txn_id": txn, "settled_minor": 9_850, "fee_minor": 150,
           "currency": "USD"}
    result = _run(conn, deps=engine.EngineDeps(psp_settlement=[row, dict(row)]))[0]
    exceptions = fetch_exceptions(conn, str(result["run"]["run_id"]))
    duplicate = [item for item in exceptions if item["kind"] == "duplicate"]
    assert len(duplicate) == 1
    assert duplicate[0]["severity"] == "P0"
    assert result["metrics"]["settlement_duplicate_rows"] == 1


# ─────────────────────────────────────────────────────────────── 幂等 / 空数据
def test_psp_replay_is_idempotent(conn) -> None:
    txn = "psp-idem"
    _attempt(conn, txn, settled_minor=9_850, settlement_fee_minor=150)
    _post_e3(conn, txn)
    _post_e4(conn, txn)
    deps = engine.EngineDeps(psp_settlement=[
        {"provider_txn_id": txn, "settled_minor": 9_850, "fee_minor": 150, "currency": "USD"}])
    first = _run(conn, deps=deps)[0]
    second = _run(conn, deps=deps)[0]
    assert second["duplicate"] is True
    assert second["run"]["run_id"] == first["run"]["run_id"]
    assert len(fetch_exceptions(conn, str(first["run"]["run_id"]))) == 0


def test_empty_psp_period_reports_no_source(conn) -> None:
    result = _run(conn)[0]
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert run["book_minor"] == 0 and run["external_minor"] == 0
    assert result["metrics"]["attempt_rows"] == 0
    assert result["metrics"]["journal_rows"] == 0
    assert result["metrics"]["settlement_source"] == "absent"


def test_invalid_settlement_fixture_is_rejected(conn) -> None:
    deps = engine.EngineDeps(psp_settlement=[{"provider_txn_id": "x"}])
    with pytest.raises(errors.BadRequest):
        _run(conn, deps=deps)


# ─────────────────────────────────────────────────────────────── 纯函数
def test_fee_tolerance_uses_max_of_bps_and_minimum() -> None:
    assert threeway._psp_fee_tolerance(100_000_000) == 100_000      # 0.10% × 100 USD
    assert threeway._psp_fee_tolerance(10_000_000) == 10_000        # 下限 0.01 USD
    assert threeway._psp_fee_tolerance(0) == 10_000


def test_fingerprint_is_stable_and_body_is_not_stored(conn) -> None:
    rows = threeway.parse_settlement_file([
        {"provider_txn_id": "a", "settled_minor": 100, "fee_minor": 1, "currency": "usd"}])
    assert rows[0].currency == "USD"
    first = threeway.settlement_fingerprint(rows)
    second = threeway.settlement_fingerprint(list(reversed(rows)))
    assert first == second and len(first) == 64
    with pytest.raises(errors.BadRequest):
        threeway.parse_settlement_file([{"provider_txn_id": "a", "settled_minor": -1,
                                         "fee_minor": 0, "currency": "USD"}])


def test_micro_normalisation_rejects_finer_scales() -> None:
    assert threeway._micro(100, 2) == 1_000_000
    assert threeway._micro(100, 6) == 100
    with pytest.raises(errors.BadRequest):
        threeway._micro(1, 7)

