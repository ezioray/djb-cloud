# SPDX-License-Identifier: Apache-2.0
"""scope=chain 三方对账：wallet.balance_minor ↔ journal_line(wallet_id, 1101/1102)。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.recon import engine, facts
from reconkit import (FIXED_NOW, fetch_exceptions, journal_line_fixture, post_journal,
                      recon_spec, seed_wallet)

TS = FIXED_NOW - timedelta(hours=2)


def _run(conn, *, spec=None):
    return engine.run(conn, spec or recon_spec("chain"), now=FIXED_NOW)


def _post_asset(conn, wallet_id: str | None, amount: int, *, coa: str = "1101",
                ts=TS) -> str:
    lines = [journal_line_fixture(coa, "D", amount, wallet_id=wallet_id, entry_type="deposit",
                                  qty_minor=amount),
             journal_line_fixture("2101", "C", amount, entry_type="deposit")]
    return post_journal(conn, lines, event_type="E2", source_type="chain_tx",
                        source_id=f"tx-{wallet_id or 'none'}", ts=ts)


def _seed_chain_tx(conn, *, to_address: str, amount_minor: int, detected_at=TS) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO chain_tx
                 (chain_id, tx_hash, log_index, block_number, block_hash, from_address,
                  to_address, asset_contract, qty_minor, amount_minor, required_confirmations,
                  policy_version, scanner_id, detected_at)
               VALUES ('polygon', %s, 0, 100, %s, %s, %s, %s, %s, %s, 64, 'm09-test',
                       'scanner-test', %s)""",
            ("aa" * 32, "bb" * 32, "0x" + "cd" * 20, to_address, "0x" + "ef" * 20,
             amount_minor, amount_minor, detected_at))


def test_matched_wallet_balance(conn) -> None:
    seed_wallet(conn, wallet_id="wallet-hot-1", balance_minor=5_000)     # 50.00 USD
    _post_asset(conn, "wallet-hot-1", 50_000_000)
    result = _run(conn)[0]
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert run["book_minor"] == 50_000_000
    assert run["external_minor"] == 50_000_000
    assert run["rule_version"] == "m09-chain-r1"
    assert result["metrics"]["wallets_checked"] == 1
    assert result["metrics"]["chains"] == ["polygon"]
    assert fetch_exceptions(conn, str(run["run_id"])) == []


def test_unmatched_both_directions(conn) -> None:
    seed_wallet(conn, wallet_id="wallet-unbooked", balance_minor=3_000)  # 外部有、账本无
    _post_asset(conn, "wallet-ghost", 10_000_000)                        # 账本有、钱包未知
    result = _run(conn)[0]
    exceptions = {item["ref_id"]: item for item in
                  fetch_exceptions(conn, str(result["run"]["run_id"]))}
    assert exceptions["wallet-unbooked"]["kind"] == "chain_balance_mismatch"
    assert exceptions["wallet-unbooked"]["diff_minor"] == -30_000_000
    assert exceptions["wallet-unbooked"]["root_cause"] == "balance_not_booked"
    assert exceptions["wallet-ghost"]["kind"] == "chain_balance_mismatch"
    assert exceptions["wallet-ghost"]["diff_minor"] == 10_000_000
    assert exceptions["wallet-ghost"]["root_cause"] == "wallet_unknown_in_m08"


def test_tolerance_is_zero_even_for_one_micro(conn) -> None:
    seed_wallet(conn, wallet_id="wallet-tol", balance_minor=5_000)       # 50,000,000 micro
    _post_asset(conn, "wallet-tol", 49_999_999)                          # 差 1 个最小单位
    result = _run(conn)[0]
    item = fetch_exceptions(conn, str(result["run"]["run_id"]))[0]
    assert item["kind"] == "chain_balance_mismatch"
    assert item["diff_minor"] == -1
    assert item["severity"] == "P0"                  # 地址余额不符 = 结构性（INV-02）
    assert item["sla_due"] == FIXED_NOW + timedelta(minutes=15)


def test_asset_line_without_wallet_id_is_structural_p0(conn) -> None:
    seed_wallet(conn, wallet_id="wallet-zero", balance_minor=0)
    _post_asset(conn, None, 10_000_000)
    result = _run(conn)[0]
    exceptions = fetch_exceptions(conn, str(result["run"]["run_id"]))
    assert len(exceptions) == 1
    item = exceptions[0]
    assert item["kind"] == "missing_wallet_ref"
    assert item["ref_type"] == "journal_line"
    assert item["diff_minor"] == 10_000_000
    assert item["severity"] == "P0"
    assert item["root_cause"] == "wallet_id_missing"
    assert result["metrics"]["null_wallet_lines"] == 1


def test_platform_wallets_are_out_of_scope(conn) -> None:
    seed_wallet(conn, wallet_id="wallet-platform", balance_minor=5_000, role="warm",
                fund_class="platform")
    result = _run(conn)[0]
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert result["metrics"]["wallets_checked"] == 0
    assert result["metrics"]["wallets_excluded_platform"] == 1
    assert fetch_exceptions(conn, str(run["run_id"])) == []


def test_chain_tx_is_used_as_evidence(conn) -> None:
    address = "0x" + "ab" * 20
    seed_wallet(conn, wallet_id="wallet-tx", balance_minor=5_000, address=address)
    _post_asset(conn, "wallet-tx", 49_000_000)
    _seed_chain_tx(conn, to_address=address, amount_minor=1_000_000)
    result = _run(conn)[0]
    item = fetch_exceptions(conn, str(result["run"]["run_id"]))[0]
    assert "chain_tx_rows:1" in (item["evidence_ref"] or "")
    assert result["metrics"]["chain_tx_rows"] == 1
    assert result["metrics"]["block_height_latest"] == 100


def test_subject_ref_filters_to_one_chain(conn) -> None:
    seed_wallet(conn, wallet_id="wallet-polygon", balance_minor=100, chain_id="polygon")
    seed_wallet(conn, wallet_id="wallet-ethereum", balance_minor=200, chain_id="ethereum",
                role="warm")
    _post_asset(conn, "wallet-polygon", 1_000_000)
    _post_asset(conn, "wallet-ethereum", 2_000_000)
    result = _run(conn, spec=recon_spec("chain", subject_ref="polygon"))[0]
    assert result["run"]["subject_ref"] == "polygon"
    assert result["metrics"]["wallets_checked"] == 1
    assert result["run"]["status"] == facts.RUN_STATUS_MATCHED


def test_chain_replay_is_idempotent(conn) -> None:
    seed_wallet(conn, wallet_id="wallet-idem", balance_minor=5_000)
    _post_asset(conn, "wallet-idem", 50_000_000)
    first = _run(conn)[0]
    second = _run(conn)[0]
    assert second["duplicate"] is True
    assert second["run"]["run_id"] == first["run"]["run_id"]
    assert fetch_exceptions(conn, str(first["run"]["run_id"])) == []


def test_empty_chain_period(conn) -> None:
    result = _run(conn)[0]
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert run["book_minor"] == 0 and run["external_minor"] == 0
    assert result["metrics"]["wallets_checked"] == 0
    assert result["metrics"]["null_wallet_lines"] == 0


def test_invalid_unit_scale_fails_closed(conn) -> None:
    """账本行 unit_scale > 6 无法整数归一：拒绝近似比较（400/40001）。"""
    seed_wallet(conn, wallet_id="wallet-scale", balance_minor=0)
    from app.recon import errors

    lines = [{"coa_code": "1101", "dc": "D", "amount_minor": 1, "account_id": "coa:1101",
              "qty_minor": 1, "entry_type": "deposit", "fund_class": "CLIENT",
              "unit_scale": 7, "wallet_id": "wallet-scale", "reverse_of": None},
             journal_line_fixture("2101", "C", 1, entry_type="deposit")]
    post_journal(conn, lines, event_type="E2", source_type="chain_tx", source_id="tx-scale",
                 ts=TS)
    with pytest.raises(errors.BadRequest):
        _run(conn)

