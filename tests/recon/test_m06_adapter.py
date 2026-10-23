# SPDX-License-Identifier: Apache-2.0
"""M06 只读适配层：与 M06 公开 API 逐单位对拍（口径漂移立刻红）。

本文件**只读** M06 的代码与表：不写 journal_*，不 import 会改数据的东西。
"""
from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from app.recon import m06
from reconkit import FIXED_NOW, post_journal, simple_journal_lines, snapshot_balances, utc

#: M06 的整数最小单位是 **micro**（``journal_line.unit_scale`` 默认 6，见 600 迁移注释），
#: 与 M05 的「分」不同。M09 的 run 只在同一 scope 内聚合，从不跨 scope 相加；
#: 这条差异已写入证据「遗留」（跨 scope 汇总必须带单位/标度）。
MINOR_PER_UNIT = Decimal("0.000001")


def _minor(amount: dict) -> int:
    """spec Amount（十进制字符串）→ M06 整数最小单位（micro，不经过 float）。"""
    return int((Decimal(str(amount["amount"])) / MINOR_PER_UNIT).to_integral_value())


def test_trial_totals_match_m06_public_api(conn) -> None:
    from app.ledger import trial

    post_journal(conn, simple_journal_lines(123_456), ts=FIXED_NOW - timedelta(hours=3))
    post_journal(conn, simple_journal_lines(7_890), ts=FIXED_NOW - timedelta(hours=2))

    mine = m06.trial_totals(conn, unit_type="USD", as_of=FIXED_NOW)
    theirs = trial.trial_balance(conn, unit_type="USD", as_of=FIXED_NOW)
    assert mine["debit_minor"] == _minor(theirs["totals"]["debit"])
    assert mine["credit_minor"] == _minor(theirs["totals"]["credit"])
    assert mine["balanced"] == theirs["balanced"] is True
    assert mine["entry_count"] == theirs["entry_count"] == 2


def test_trial_totals_respect_cutoff(conn) -> None:
    post_journal(conn, simple_journal_lines(1_000), ts=FIXED_NOW - timedelta(hours=3))
    post_journal(conn, simple_journal_lines(9_000), ts=FIXED_NOW + timedelta(hours=1))
    mine = m06.trial_totals(conn, unit_type="USD", as_of=FIXED_NOW)
    assert mine["debit_minor"] == 1_000
    assert mine["entry_count"] == 1


def test_unit_types_as_of(conn) -> None:
    post_journal(conn, simple_journal_lines(1_000), unit_type="USD",
                 ts=FIXED_NOW - timedelta(hours=1))
    post_journal(conn, simple_journal_lines(1_000), unit_type="COP",
                 ts=FIXED_NOW - timedelta(hours=1))
    post_journal(conn, simple_journal_lines(1_000), unit_type="FIAT_CNY",
                 ts=FIXED_NOW + timedelta(hours=1))          # 截止之后 → 不算
    assert m06.unit_types_as_of(conn, FIXED_NOW) == ["COP", "USD"]


def test_balance_drift_as_of_matches_m06_balance_drift(conn) -> None:
    from app.ledger import balances

    post_journal(conn, simple_journal_lines(5_000), ts=FIXED_NOW - timedelta(hours=3))
    snapshot_balances(conn, created_at=FIXED_NOW - timedelta(hours=2))
    post_journal(conn, simple_journal_lines(500), ts=FIXED_NOW - timedelta(hours=1))

    mine = m06.balance_drift_as_of(conn, unit_type="USD", as_of=FIXED_NOW)
    theirs = balances.balance_drift(conn)
    # 键形状不同：M06 用 (account, unit, sub)，M09 的 as-of 版本按单位过滤 → (account, sub)
    assert {(account, "USD", sub) for account, sub in mine["mismatched"]} == \
        {(account, unit, sub) for account, unit, sub in theirs["mismatched"]}
    assert mine["diff"] == theirs["diff"]
    assert mine["amount_gap_minor"] == 1_000                 # 两键各 500
    assert mine["derived_keys"] == theirs["derived_keys"]


def test_balance_drift_is_zero_when_cache_is_current(conn) -> None:
    post_journal(conn, simple_journal_lines(5_000), ts=FIXED_NOW - timedelta(hours=3))
    snapshot_balances(conn, created_at=FIXED_NOW - timedelta(hours=2))
    drift = m06.balance_drift_as_of(conn, unit_type="USD", as_of=FIXED_NOW)
    assert drift == {
        "unit_type": "USD", "as_of": FIXED_NOW, "derived_keys": 2, "stored_keys": 2,
        "missing_in_store": [], "missing_in_ledger": [], "mismatched": [], "diff": 0,
        "amount_gap_minor": 0,
    }


def test_locked_coa_mapping_matches_m06_constants() -> None:
    from app.ledger.constants import SUB_ACCOUNT_BY_COA

    assert set(m06._LOCKED_COA) == {coa for coa, sub in SUB_ACCOUNT_BY_COA.items()
                                    if sub == "LOCKED"}


def test_drift_as_of_ignores_versions_after_cutoff(conn) -> None:
    post_journal(conn, simple_journal_lines(1_000), ts=utc(2026, 10, 22, 9))
    snapshot_balances(conn, as_of=utc(2026, 10, 22, 12), created_at=utc(2026, 10, 22, 12))
    post_journal(conn, simple_journal_lines(2_000), ts=utc(2026, 10, 23, 1))   # 不再 snapshot

    as_of_early = m06.balance_drift_as_of(conn, unit_type="USD", as_of=utc(2026, 10, 22, 12))
    assert as_of_early["diff"] == 0                          # 该时点缓存是最新的
    as_of_now = m06.balance_drift_as_of(conn, unit_type="USD", as_of=utc(2026, 10, 23, 12))
    assert as_of_now["mismatched"]                          # 缓存落后于分录
    assert as_of_now["stored_keys"] == 2
