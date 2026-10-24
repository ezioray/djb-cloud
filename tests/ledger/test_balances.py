# SPDX-License-Identifier: AGPL-3.0-or-later
"""余额派生验收（INV-10 / CR-L3）：版本化只追加、上一版本+1、借方为正、最新视图、并发无跳版。

验收来源：DEV-M06-T3 §交付 3 与 §验收「并发用例无余额跳版」「复算 diff=0」。
"""
from __future__ import annotations

import threading
import uuid

from app.ledger import (
    JournalDraft,
    JournalLine,
    apply_journal,
    balance_drift,
    check_negative_liabilities,
    deltas_for_journal,
    derive_balances,
    latest_balances,
    post_journal,
    sub_account_for,
    verify_ledger,
)
from app.ledger.balances import version_chain
from app.ledger.constants import DEFAULT_SUB_ACCOUNT, SUB_ACCOUNT_BY_COA

from ledger_gatewaykit import e2_draft, e6_draft, post_ok
from ledgerkit import connect, tx


# ─────────────────────────────────────────────────────── 写入与版本
def test_post_writes_balances_in_same_transaction(migrated: str) -> None:
    """落账即写余额（§6 事务边界）：E2 四行 → 4 个键、版本 1、借方为正。"""
    deposit = post_ok(migrated, e2_draft(amount_minor=100))

    with connect(migrated) as c:
        latest = latest_balances(c)
        derived = derive_balances(c)
    assert set(latest) == set(derived)
    assert {value["version"] for value in latest.values()} == {1}
    assert latest[("acct:user-2", "USD", "AVAILABLE")]["balance_minor"] == -100   # 2101 贷 → 负
    assert latest[("coa:1101", "USD", "AVAILABLE")]["balance_minor"] == 100       # 资产借 → 正
    assert latest[("coa:2990", "USD", "AVAILABLE")]["balance_minor"] == 100
    assert latest[("coa:1111", "USD", "AVAILABLE")]["balance_minor"] == -100
    assert all(value["journal_id"] == deposit.journal_id for value in latest.values())


def test_second_journal_accumulates_on_next_version(migrated: str) -> None:
    deposit = post_ok(migrated, e2_draft(amount_minor=100))
    consume = post_ok(migrated, e6_draft(amount_minor=30, user="user-2"))

    with connect(migrated) as c:
        chain = version_chain(c, ("acct:user-2", "USD", "AVAILABLE"))
        latest = latest_balances(c)
    assert [row["version"] for row in chain] == [1, 2]
    assert [row["balance_minor"] for row in chain] == [-100, -70]
    assert chain[0]["journal_id"] == deposit.journal_id
    assert chain[1]["journal_id"] == consume.journal_id
    assert latest[("acct:user-2", "USD", "AVAILABLE")]["balance_minor"] == -70


def test_apply_journal_is_idempotent(migrated: str) -> None:
    """同一凭证重复写余额不会重复累加（account_balances.journal_id 判据）。"""
    result = post_ok(migrated, e6_draft(amount_minor=25))
    with tx(migrated) as c:
        assert apply_journal(c, result.journal_id) == []          # 已写过 → 空操作
    with connect(migrated) as c:
        assert latest_balances(c)[("coa:4101", "USD", "AVAILABLE")]["balance_minor"] == -25


def test_deltas_fold_lines_per_key(migrated: str) -> None:
    result = post_ok(migrated, e2_draft(amount_minor=7))
    with connect(migrated) as c:
        deltas = deltas_for_journal(c, result.journal_id)
    assert deltas[("coa:1101", "USD", "AVAILABLE")] == 7
    assert deltas[("acct:user-2", "USD", "AVAILABLE")] == -7
    assert sum(deltas.values()) == 0                    # 单张凭证净额为 0（借贷平衡）


def test_sub_account_mapping(migrated: str) -> None:
    """2102（锁定服务预付款）落 LOCKED，其余落 AVAILABLE（§20.2.7 / §20.4.4 freeze）。"""
    assert sub_account_for("2102") == "LOCKED"
    assert sub_account_for("2101") == DEFAULT_SUB_ACCOUNT == "AVAILABLE"
    assert SUB_ACCOUNT_BY_COA == {"2102": "LOCKED"}

    post_ok(migrated, e2_draft(amount_minor=100, user="lock-user"))
    freeze = JournalDraft(
        event_type="E9", unit_type="USD", source_type="wallet_transfer",
        source_id=f"freeze-{uuid.uuid4().hex[:8]}", policy_version="v4.0-t3",
        lines=(JournalLine(account_id="acct:lock-user", coa_code="2101", dc="D",
                           amount_minor=40, entry_type="freeze"),
               JournalLine(account_id="acct:lock-user", coa_code="2102", dc="C",
                           amount_minor=40, entry_type="freeze")))
    post_ok(migrated, freeze)

    with connect(migrated) as c:
        latest = latest_balances(c)
    assert latest[("acct:lock-user", "USD", "AVAILABLE")]["balance_minor"] == -60   # 2101: -100+40
    assert latest[("acct:lock-user", "USD", "LOCKED")]["balance_minor"] == -40      # 2102: 贷 40


# ─────────────────────────────────────────────────────── 一致性 / 复算
def test_derived_matches_stored_and_ledger_verifies(migrated: str) -> None:
    post_ok(migrated, e2_draft(amount_minor=100))
    post_ok(migrated, e6_draft(amount_minor=30, user="user-2"))
    post_ok(migrated, e6_draft(amount_minor=5, source_id="usage-b"))

    with connect(migrated) as c:
        assert balance_drift(c)["diff"] == 0
        report = verify_ledger(c)
    assert report["diff"] == 0, report
    assert report["chain"]["diff"] == 0 and report["balances"]["diff"] == 0
    assert report["net_minor"] == 0


def test_drift_detects_tampered_snapshot(migrated: str) -> None:
    """人为插一条错误余额版本（只追加表只能"插错"，不能改）→ drift 必须报出来。"""
    post_ok(migrated, e6_draft(amount_minor=10))
    with tx(migrated) as c, c.cursor() as cur:
        cur.execute(
            """INSERT INTO account_balances (account_id, unit_type, sub_account, version,
                                             balance_minor, journal_id)
               VALUES ('coa:4101', 'USD', 'AVAILABLE', 2, -999, NULL)""")
    with connect(migrated) as c:
        drift = balance_drift(c)
        report = verify_ledger(c)
    assert drift["mismatched"] == [("coa:4101", "USD", "AVAILABLE")]
    assert drift["diff"] == 1 and report["diff"] >= 1


def test_empty_ledger_has_no_balances(migrated: str) -> None:
    with connect(migrated) as c:
        assert derive_balances(c) == {}
        assert latest_balances(c) == {}
        assert balance_drift(c)["diff"] == 0
        assert verify_ledger(c)["diff"] == 0


# ─────────────────────────────────────────────────────── I-4（负债不得为负）
def test_negative_liability_is_detected(migrated: str) -> None:
    """I-4 只看分录真值：E6 消耗超过预付款 → 2101 正常方向为负。"""
    post_ok(migrated, e6_draft(amount_minor=30))            # 无充值直接消耗
    with connect(migrated) as c:
        violations = check_negative_liabilities(c)
        scoped = check_negative_liabilities(c, account_ids=["acct:user-1"])
        unrelated = check_negative_liabilities(c, account_ids=["acct:nobody"])
    assert [(v["coa_code"], v["normal_balance_minor"]) for v in violations] == [("2101", -30)]
    assert scoped == violations and unrelated == []


def test_balanced_deposit_has_no_negative_liability(migrated: str) -> None:
    post_ok(migrated, e2_draft(amount_minor=50))
    with connect(migrated) as c:
        assert check_negative_liabilities(c) == []


# ─────────────────────────────────────────────────────── 并发：无跳版
def test_concurrent_posts_keep_versions_contiguous(migrated: str) -> None:
    """4 线程 × 2 张凭证并发落账：每个键的版本必须 1..N 连续（无跳版/无重版），并与分录重建一致。"""
    threads_n, per_thread = 4, 2
    user = "user-conc"
    barrier = threading.Barrier(threads_n)
    errors: list[BaseException] = []

    def run(index: int) -> None:
        try:
            barrier.wait(timeout=30)
            with tx(migrated) as c:
                for k in range(per_thread):
                    post_journal(c, e6_draft(amount_minor=100 + index * 10 + k, user=user,
                                             source_id=f"conc-{index}-{k}-{uuid.uuid4().hex[:6]}"))
        except BaseException as exc:           # noqa: BLE001 - 线程内异常带回主线程
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in threads), "并发线程未在超时内结束"
    assert errors == [], errors

    with connect(migrated) as c, c.cursor() as cur:
        cur.execute(
            """SELECT account_id, unit_type, sub_account, count(*), min(version), max(version),
                      count(DISTINCT version)
                 FROM account_balances GROUP BY 1,2,3""")
        rows = cur.fetchall()
        drift = balance_drift(c)
        report = verify_ledger(c)
    assert rows, "并发后应写入余额"
    for account_id, unit_type, sub_account, count, min_v, max_v, distinct_v in rows:
        assert (int(min_v), int(max_v)) == (1, int(count)), (account_id, count, min_v, max_v)
        assert int(distinct_v) == int(count), (account_id, distinct_v, count)     # 无跳版/无重版
    user_rows = [r for r in rows if r[0] == f"acct:{user}"]
    assert user_rows and int(user_rows[0][3]) == threads_n * per_thread
    assert drift["diff"] == 0 and report["diff"] == 0, (drift, report)
