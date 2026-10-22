# SPDX-License-Identifier: Apache-2.0
"""试算平衡与科目余额验收（spec 1.2.1 TrialBalance / LedgerAccountPage；INV-04 / INV-05 / INV-12）。

口径：一切从分录聚合，`balance = Σ借 − Σ贷`（借方为正）；借贷平衡只在本 unit_type 内判定。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.ledger import trial
from app.ledger.constants import ALL_COA, COA_FUND_CLASS, COA_NAMES

from gatewaykit import e2_draft, e6_draft, post_ok
from ledgerkit import connect


def _seed(migrated: str):
    deposit = post_ok(migrated, e2_draft(amount_minor=100_000_000))          # 100.000000 USD
    consume = post_ok(migrated, e6_draft(amount_minor=30_000_000))           # 30.000000 USD
    cop = post_ok(migrated, e6_draft(amount_minor=5, unit_type="COP",        # 5 micro COP
                                     source_id="cop-1"))
    return deposit, consume, cop


# ─────────────────────────────────────────────────────── 金额格式
def test_decimal_str_is_exact_and_trimmed() -> None:
    assert trial.decimal_str(0) == "0"
    assert trial.decimal_str(1) == "0.000001"
    assert trial.decimal_str(1_000_000) == "1"
    assert trial.decimal_str(1_500_000) == "1.5"
    assert trial.decimal_str(123_456_789) == "123.456789"
    assert trial.decimal_str(-2_500_000) == "-2.5"


# ─────────────────────────────────────────────────────── 试算平衡
def test_trial_balance_is_balanced_and_covers_42_accounts(migrated: str) -> None:
    _seed(migrated)
    with connect(migrated) as c:
        report = trial.trial_balance(c, unit_type="USD")

    assert report["balanced"] is True
    assert report["unit_type"] == "USD"
    assert len(report["accounts"]) == 42
    assert {row["coa_code"] for row in report["accounts"]} == set(ALL_COA)
    assert report["totals"]["debit"] == report["totals"]["credit"]
    assert report["totals"]["debit"]["amount"] == report["totals"]["credit"]["amount"]
    assert report["entry_count"] == 2                     # USD 两张凭证（COP 那张不算）

    by_coa = {row["coa_code"]: row for row in report["accounts"]}
    assert by_coa["1101"]["debit"]["amount"] == "100"
    assert by_coa["2101"]["credit"]["amount"] == "100"    # E2 贷 2101
    assert by_coa["2101"]["debit"]["amount"] == "30"      # E6 借 2101
    assert by_coa["2101"]["balance"]["amount"] == "-70"   # 借正贷负
    assert by_coa["4101"]["balance"]["amount"] == "-30"
    assert by_coa["2901"]["balance"]["amount"] == "0"     # 无尾差
    assert report["tail_diff"]["amount"] == "0"
    # 每行都带 spec 要求的字段与展示名
    assert by_coa["1101"]["name"] == COA_NAMES["1101"]
    assert by_coa["1101"]["fund_class"] == COA_FUND_CLASS["1101"]


def test_trial_balance_keeps_units_separate(migrated: str) -> None:
    """INV-04：COP 与 USD 不互转，各自在自己的 unit_type 内平账。"""
    _seed(migrated)
    with connect(migrated) as c:
        usd = trial.trial_balance(c, unit_type="USD")
        cop = trial.trial_balance(c, unit_type="COP")
        other = trial.trial_balance(c, unit_type="FIAT_CNY")
    assert usd["balanced"] and cop["balanced"] and other["balanced"]
    assert cop["entry_count"] == 1
    assert cop["totals"]["debit"]["amount"] == "0.000005"
    assert other["entry_count"] == 0
    assert other["totals"]["debit"]["amount"] == "0"


def test_trial_balance_as_of_filters_by_ts(migrated: str) -> None:
    """as_of 只统计 ts ≤ as_of 的凭证（历史时点试算）。"""
    early = datetime.now(timezone.utc) - timedelta(days=2)
    post_ok(migrated, e2_draft(amount_minor=10_000_000, ts=early))
    post_ok(migrated, e6_draft(amount_minor=4_000_000))
    with connect(migrated) as c:
        at_early = trial.trial_balance(c, unit_type="USD", as_of=early + timedelta(hours=1))
        now = trial.trial_balance(c, unit_type="USD")
    assert at_early["entry_count"] == 1
    assert at_early["totals"]["debit"]["amount"] == "20"          # 只有 E2 四行里的借方合计
    assert now["entry_count"] == 2
    assert now["totals"]["debit"]["amount"] == "24"               # 20（E2 两行借）+ 4（E6 借 2101）


def test_unknown_unit_is_rejected(migrated: str) -> None:
    import pytest
    from app.ledger.errors import InvalidUnitType
    with connect(migrated) as c, pytest.raises(InvalidUnitType):
        trial.trial_balance(c, unit_type="BTC")


# ─────────────────────────────────────────────────────── 科目与余额
def test_accounts_overview_lists_42_with_balances(migrated: str) -> None:
    _seed(migrated)
    with connect(migrated) as c:
        page = trial.accounts_overview(c, unit_type="USD", limit=200)
    assert len(page["data"]) == 42
    assert page["page"]["has_more"] is False and page["page"]["next_cursor"] is None
    rows = {row["coa_code"]: row for row in page["data"]}
    assert rows["1101"]["balance"]["amount"] == "100"
    assert rows["2101"]["balance"]["amount"] == "-70"
    assert rows["4101"]["balance"]["amount"] == "-30"
    assert rows["1101"]["unit_type"] == "USD"
    assert "updated_at" in rows["1101"] and "updated_at" not in rows["6101"]   # 未发生额不给时间


def test_accounts_overview_paginates_by_cursor(migrated: str) -> None:
    with connect(migrated) as c:
        first = trial.accounts_overview(c, limit=10)
        assert len(first["data"]) == 10 and first["page"]["has_more"] is True
        cursor = first["page"]["next_cursor"]
        second = trial.accounts_overview(c, limit=10, cursor=cursor)
    assert len(second["data"]) == 10
    assert not ({row["coa_code"] for row in first["data"]} & {row["coa_code"] for row in second["data"]})
    assert second["data"][0]["coa_code"] > first["data"][-1]["coa_code"]


def test_accounts_overview_filters_fund_class(migrated: str) -> None:
    with connect(migrated) as c:
        client = trial.accounts_overview(c, fund_class="CLIENT", limit=200)
    assert client["data"] and all(row["fund_class"] == "CLIENT" for row in client["data"])
    expected = [coa for coa in ALL_COA if COA_FUND_CLASS[coa] == "CLIENT"]
    assert [row["coa_code"] for row in client["data"]] == sorted(expected, key=ALL_COA.index)
