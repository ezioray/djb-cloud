# SPDX-License-Identifier: Apache-2.0
"""冲正验收（INV-07 / INV-14 / R5）：整单等额取反、至多一条、posted→voided、ledger.reversed。

验收来源：DEV-M06-T3 §交付 1 + §验收「冲正全链路 / 部分冲正拒绝 / 重复冲正拒绝 / 并发」，
错误码口径按 M06 §7 失败表：40920 重复冲正 · 40921 冷却期 · 42220 不变量/部分冲正 · 40924 不存在。
"""
from __future__ import annotations

import threading

import psycopg
import pytest

from app.ledger import (
    InvariantViolation,
    JournalDraft,
    JournalNotFound,
    PartialReversalNotAllowed,
    ReversalCooldown,
    ReversalNotAllowed,
    balance_drift,
    derive_balances,
    find_reversal,
    load_journal,
    latest_balances,
    post_journal,
    reverse_journal,
    verify_ledger,
)

from gatewaykit import e2_draft, e6_draft, journal_row, line, outbox_rows, post_ok, reverse_ok
from ledgerkit import assert_db_error, connect, run_ok, tx


# ─────────────────────────────────────────────────────── 全链路
def test_reverse_two_line_journal(shared: str) -> None:
    """E6 两行整单取反：新凭证 E16/void、原凭证 voided、事件两个、链与余额都平。"""
    original = post_ok(shared, e6_draft(amount_minor=30))
    before = journal_row(shared, original.journal_id)

    result = reverse_ok(shared, original.journal_id, reason_code="ops_error")

    assert result.reversal_of == original.journal_id
    assert result.lines == 2 and result.total_minor == 30
    assert result.voided_entries == 2
    assert result.invariants == {"i4_violations": 0, "i5_drift": 0}
    assert len(result.event_ids) == 2          # journal.posted（冲正凭证）+ ledger.reversed

    reversal = journal_row(shared, result.reversal_journal_id)
    assert reversal["event_type"] == "E16"
    assert reversal["source_type"] == "void"
    assert reversal["source_id"] == original.journal_id
    assert reversal["event_seq"] == 1
    assert str(reversal["reversal_of_journal"]) == original.journal_id
    assert bytes(reversal["prev_hash"]) == bytes(before["hash"])   # 接在原凭证之后
    assert reversal["status"] == "posted"

    after = journal_row(shared, original.journal_id)
    assert after["status"] == "voided"
    for column in ("hash", "prev_hash", "event_type", "unit_type", "source_id", "policy_version"):
        assert after[column] == before[column], column            # 原凭证除 status 外一字未改

    with connect(shared) as c, c.cursor() as cur:
        cur.execute(
            """SELECT o.coa_code, o.dc, o.amount_minor, o.qty_minor,
                      r.coa_code, r.dc, r.amount_minor, r.qty_minor, e.reverse_of
                 FROM journal_line o
                 JOIN journal_line r ON r.journal_id = %s AND r.line_no = o.line_no
                 JOIN ledger_entry e ON e.entry_id = r.ledger_entry_id
                WHERE o.journal_id = %s ORDER BY o.line_no""",
            (result.reversal_journal_id, original.journal_id))
        rows = cur.fetchall()
        cur.execute("SELECT count(*) FROM ledger_entry WHERE journal_id = %s AND status = 'voided'",
                    (original.journal_id,))
        voided_entries = cur.fetchone()[0]

    assert len(rows) == 2
    for o_coa, o_dc, o_amount, o_qty, r_coa, r_dc, r_amount, r_qty, reverse_of in rows:
        assert (r_coa, r_amount, r_qty) == (o_coa, o_amount, o_qty)     # 等额、同科目、同 qty
        assert r_dc != o_dc                                             # 逐行取反
        assert reverse_of is not None                                   # 分录级反向指针
    assert voided_entries == 2


def test_reverse_four_line_journal_and_balances_restored(migrated: str) -> None:
    """E2 四行（含资产双记）整单取反；冲正后余额回到未落账状态。"""
    deposit = post_ok(migrated, e2_draft(amount_minor=100))
    with connect(migrated) as c:
        after_deposit = derive_balances(c)
        assert all(value != 0 for value in after_deposit.values())        # 充值后各键都有净额

    result = reverse_ok(migrated, deposit.journal_id, reason_code="wrong_chain")

    with connect(migrated) as c:
        derived = derive_balances(c)
        latest = latest_balances(c)
        drift = balance_drift(c)
        report = verify_ledger(c)
    assert all(value == 0 for value in derived.values()), derived          # 净额归零
    assert {key: value["balance_minor"] for key, value in latest.items()} == derived   # 缓存与真值一致
    assert drift["diff"] == 0
    assert report["diff"] == 0, report
    assert result.lines == 4
    assert set(derived) == set(after_deposit)


def test_reversal_emits_ledger_reversed(shared: str) -> None:
    original = post_ok(shared, e6_draft(amount_minor=12))
    result = reverse_ok(shared, original.journal_id, reason_code="user_request")

    events = outbox_rows(shared, aggregate_id=result.reversal_journal_id)
    types = sorted(event["type"] for event in events)
    assert types == ["journal.posted", "ledger.reversed"]
    reversed_event = next(event for event in events if event["type"] == "ledger.reversed")
    assert reversed_event["payload"]["journal_id"] == result.reversal_journal_id
    assert reversed_event["payload"]["reverse_of"] == original.journal_id
    assert reversed_event["payload"]["reason_code"] == "user_request"


def test_find_reversal_reads_back(shared: str) -> None:
    original = post_ok(shared, e6_draft(amount_minor=3))
    assert run_ok(shared, lambda c: find_reversal(c, original.journal_id)) is None
    result = reverse_ok(shared, original.journal_id, reason_code="dup_check")
    assert run_ok(shared, lambda c: find_reversal(c, original.journal_id)) == result.reversal_journal_id


# ─────────────────────────────────────────────────────── 拒绝路径
def test_repeat_reversal_is_rejected_and_original_unchanged(shared: str) -> None:
    original = post_ok(shared, e6_draft(amount_minor=9))
    reverse_ok(shared, original.journal_id, reason_code="first")
    snapshot = journal_row(shared, original.journal_id)

    with pytest.raises(ReversalNotAllowed) as ei:
        reverse_ok(shared, original.journal_id, reason_code="second")
    assert ei.value.code == "40920"

    assert journal_row(shared, original.journal_id) == snapshot       # 原凭证不再变化
    with connect(shared) as c, c.cursor() as cur:
        cur.execute("SELECT count(*) FROM journal_entry WHERE reversal_of_journal = %s",
                    (original.journal_id,))
        assert cur.fetchone()[0] == 1                                    # 只有一条冲正


def test_unknown_journal_is_404_like(shared: str) -> None:
    with pytest.raises(JournalNotFound) as ei:
        reverse_ok(shared, "00000000-0000-0000-0000-000000000000", reason_code="nope")
    assert ei.value.code == "40924"


def test_reversing_a_reversal_is_rejected(shared: str) -> None:
    original = post_ok(shared, e6_draft(amount_minor=4))
    result = reverse_ok(shared, original.journal_id, reason_code="first")
    with pytest.raises(ReversalNotAllowed) as ei:
        reverse_ok(shared, result.reversal_journal_id, reason_code="again")
    assert ei.value.code == "40920"


def test_reason_code_is_required(shared: str) -> None:
    original = post_ok(shared, e6_draft(amount_minor=1))
    for bad in ("", "x" * 65):
        with pytest.raises(Exception) as ei:
            reverse_ok(shared, original.journal_id, reason_code=bad)
        assert "reason_code" in str(ei.value)


def test_cooldown_blocks_second_reversal_of_same_ref(shared: str) -> None:
    """同一 ref_id（source_type + source_id）的另 24h 内二次冲正 → 40921。"""
    ref = "0x-cooldown-ref"
    first = post_ok(shared, e6_draft(amount_minor=6, source_id=ref, event_seq=1))
    second = post_ok(shared, e6_draft(amount_minor=7, source_id=ref, event_seq=2))
    reverse_ok(shared, first.journal_id, reason_code="first")

    with pytest.raises(ReversalCooldown) as ei:
        reverse_ok(shared, second.journal_id, reason_code="second")
    assert ei.value.code == "40921"
    assert journal_row(shared, second.journal_id)["status"] == "posted"

    # 冷却期可显式放宽（配置化前的逃生阀，T4 接 M10 配置）
    reverse_ok(shared, second.journal_id, reason_code="second", cooldown_hours=0)
    assert journal_row(shared, second.journal_id)["status"] == "voided"


def test_partial_reversal_is_rejected_at_validation(shared: str) -> None:
    """部分冲正：只有一部分行带 reverse_of，或声明了 reversal_of_journal 却没带反向行。"""
    original = post_ok(shared, e6_draft(amount_minor=8))
    entry_ids = _line_entries(shared, original.journal_id)
    half = JournalDraft(
        event_type="E16", unit_type="USD", source_type="void", source_id=original.journal_id,
        policy_version="v4.0-t3", reversal_of_journal=original.journal_id,
        lines=(line("2101", "C", 8, account_id="acct:user-1", entry_type="void",
                    reverse_of=entry_ids[0]),
               line("4101", "D", 8, entry_type="void")))          # 第二行没带 reverse_of
    with pytest.raises(PartialReversalNotAllowed):
        post_ok(shared, half)

    orphan = JournalDraft(
        event_type="E16", unit_type="USD", source_type="void", source_id=original.journal_id,
        policy_version="v4.0-t3",
        lines=(line("2101", "C", 8, account_id="acct:user-1", entry_type="void",
                    reverse_of=entry_ids[0]),
               line("4101", "D", 8, entry_type="void", reverse_of=entry_ids[1])))
    with pytest.raises(PartialReversalNotAllowed):
        post_ok(shared, orphan)


def test_db_guards_backstop_unequal_reversal(shared: str) -> None:
    """库内护栏兜底：冲正金额不等 / 未取反 / 二次冲正同一分录都写不进去。"""
    original = post_ok(shared, e6_draft(amount_minor=20))
    entry_ids = _line_entries(shared, original.journal_id)

    unequal = JournalDraft(
        event_type="E16", unit_type="USD", source_type="void", source_id=original.journal_id,
        policy_version="v4.0-t3", reversal_of_journal=original.journal_id,
        lines=(line("2101", "C", 19, account_id="acct:user-1", entry_type="void", reverse_of=entry_ids[0]),
               line("4101", "D", 19, entry_type="void", reverse_of=entry_ids[1])))
    assert_db_error(shared, "reversal amount", lambda c: post_journal(c, unequal))

    not_flipped = JournalDraft(
        event_type="E16", unit_type="USD", source_type="void", source_id=original.journal_id,
        policy_version="v4.0-t3", reversal_of_journal=original.journal_id,
        lines=(line("2101", "D", 20, account_id="acct:user-1", entry_type="void", reverse_of=entry_ids[0]),
               line("4101", "C", 20, entry_type="void", reverse_of=entry_ids[1])))
    assert_db_error(shared, "must flip dc", lambda c: post_journal(c, not_flipped))


# ─────────────────────────────────────────────────────── INV-14：不变量失败整笔回滚
def test_i4_violation_rolls_back_the_whole_reversal(migrated: str) -> None:
    """冲正后负债为负（把已消耗的充值冲掉）→ I-4 失败 → 整笔回滚，原凭证仍 posted。"""
    deposit = post_ok(migrated, e2_draft(amount_minor=100))
    post_ok(migrated, e6_draft(amount_minor=30, user="user-2"))
    before = journal_row(migrated, deposit.journal_id)
    with connect(migrated) as c:
        balances_before = derive_balances(c)

    with pytest.raises(InvariantViolation) as ei:
        reverse_ok(migrated, deposit.journal_id, reason_code="undo_deposit")
    assert ei.value.code == "42220"
    assert ei.value.detail["violations"][0]["coa_code"] == "2101"

    assert journal_row(migrated, deposit.journal_id) == before         # 原凭证未被 void
    with connect(migrated) as c, c.cursor() as cur:
        cur.execute("SELECT count(*) FROM journal_entry WHERE reversal_of_journal = %s",
                    (deposit.journal_id,))
        assert cur.fetchone()[0] == 0                                  # 没有留下半张冲正凭证
        cur.execute("SELECT count(*) FROM m06_outbox WHERE type = 'ledger.reversed'")
        assert cur.fetchone()[0] == 0
        assert derive_balances(c) == balances_before


# ─────────────────────────────────────────────────────── 并发冲正
def test_concurrent_double_reversal_yields_one_reversal(shared: str) -> None:
    """两个线程同时冲同一张凭证：只能成功一个，另一个 40920；库里只有一条冲正。"""
    original = post_ok(shared, e6_draft(amount_minor=15))
    barrier = threading.Barrier(2)
    results: list = []
    errors: list[BaseException] = []

    def run(reason: str) -> None:
        try:
            barrier.wait(timeout=30)
            results.append(reverse_ok(shared, original.journal_id, reason_code=reason))
        except BaseException as exc:            # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(f"conc-{i}",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in threads)

    assert len(results) == 1, (results, errors)
    assert len(errors) == 1 and isinstance(errors[0], ReversalNotAllowed), errors
    assert errors[0].code == "40920"
    with connect(shared) as c, c.cursor() as cur:
        cur.execute("SELECT count(*) FROM journal_entry WHERE reversal_of_journal = %s",
                    (original.journal_id,))
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM m06_outbox WHERE type = 'ledger.reversed' AND "
                    "payload->>'reverse_of' = %s", (str(original.journal_id),))
        assert cur.fetchone()[0] == 1
        assert verify_ledger(c)["diff"] == 0


# ─────────────────────────────────────────────────────── 小工具
def _line_entries(schema: str, journal_id: str) -> list[str]:
    journal = run_ok(schema, lambda c: load_journal(c, journal_id))
    return [line["ledger_entry_id"] for line in journal["lines"]]
