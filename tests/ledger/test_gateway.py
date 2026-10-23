# SPDX-License-Identifier: Apache-2.0
"""记账网关验收：E6 落账、借贷平衡、幂等重放、校验拒绝、同事务 outbox、并发链。

验收来源：DEV-M06-T2 §验收 1（T2 用例全绿 + 复算 diff=0）、§交付 1/4。
"""
from __future__ import annotations

import threading
import uuid

import psycopg
import pytest

from app.ledger import (
    FundClassMismatch,
    InvalidEntryType,
    InvalidEventType,
    InvalidSourceType,
    InvalidUnitType,
    JournalDraft,
    JournalValidationError,
    LineCountOutOfRange,
    MissingAssetQuantity,
    TransactionRequired,
    UnbalancedJournal,
    UnknownCoaCode,
    find_existing,
    load_journal,
    post_journal,
    verify_chain,
)
from app.ledger.constants import JOURNAL_MAX_LINES
from app.ledger.errors import LedgerError

from ledger_gatewaykit import count_by_source, e2_draft, e6_draft, journal_row, line, outbox_rows, post_ok, totals
from ledgerkit import assert_db_error, connect, run_ok, tx


# ─────────────────────────────────────────────────────── 1 落账主路径
def test_posts_e6_usage_settle(shared: str) -> None:
    """E6：借 2101 / 贷 4101 全额确认；凭证 + 分录 + 行 + outbox 同事务落库。"""
    draft = e6_draft(amount_minor=30_000_000)
    result = post_ok(shared, draft)

    assert result.idempotent is False
    assert len(result.hash) == 32
    assert result.total_debit_minor == 30_000_000
    assert result.line_count == 2
    assert len(result.event_ids) == 1

    row = journal_row(shared, result.journal_id)
    assert row["event_type"] == "E6"
    assert row["unit_type"] == "USD"
    assert row["source_type"] == "usage_settle"
    assert row["source_id"] == draft.source_id
    assert row["event_seq"] == 1
    assert row["status"] == "posted"
    assert row["prev_hash"] is None            # 该 schema 的第一张凭证 = 链首
    assert bytes(row["hash"]) == result.hash

    sums = totals(shared, result.journal_id)
    assert sums == {"debit": 30_000_000, "credit": 30_000_000, "lines": 2}   # Σ借 = Σ贷（INV-01）

    marks = count_by_source(shared, "usage_settle", draft.source_id)
    assert marks == {"journals": 1, "lines": 2, "entries": 2, "events": 1}

    events = outbox_rows(shared, aggregate_id=result.journal_id)
    assert [e["type"] for e in events] == ["journal.posted"]
    assert events[0]["payload"]["amount_minor"] == 30_000_000
    assert events[0]["payload"]["event_type"] == "E6"
    assert events[0]["payload"]["ref_id"] == draft.source_id
    assert events[0]["published_at"] is None

    with connect(shared) as c:
        assert verify_chain(c)["diff"] == 0


def test_e2_four_line_deposit_keeps_asset_qty(shared: str) -> None:
    """E2 四行：资产行双记 qty_minor（INV-11），借贷仍只看金额。"""
    result = post_ok(shared, e2_draft(amount_minor=123_000_000))
    with connect(shared) as c, c.cursor() as cur:
        cur.execute(
            """SELECT coa_code, dc, amount_minor, qty_minor FROM journal_line
                WHERE journal_id = %s ORDER BY line_no""", (result.journal_id,))
        rows = cur.fetchall()
    assert [(r[0], r[1]) for r in rows] == [("1101", "D"), ("2990", "D"), ("1111", "C"), ("2101", "C")]
    assert rows[0][2] == 123_000_000 and rows[0][3] == 123_000_000      # 1101 双记
    assert rows[1][3] is None                                          # 2990 无 qty 要求
    assert totals(shared, result.journal_id)["debit"] == 246_000_000
    assert totals(shared, result.journal_id)["credit"] == 246_000_000


# ─────────────────────────────────────────────────────── 2 幂等重放（INV-06）
def test_idempotent_replay_returns_existing_without_new_rows(shared: str) -> None:
    draft = e6_draft(amount_minor=1_000_000)
    first = post_ok(shared, draft)
    before = count_by_source(shared, "usage_settle", draft.source_id)

    second = post_ok(shared, draft)

    assert second.journal_id == first.journal_id
    assert second.seq == first.seq
    assert second.hash == first.hash
    assert second.idempotent is True
    assert second.event_ids == ()
    assert count_by_source(shared, "usage_settle", draft.source_id) == before


def test_same_source_different_event_seq_is_a_new_journal(shared: str) -> None:
    """E1/E2 用同一 tx_hash 的两个 event_seq：两张凭证，各自独立。"""
    tx_id = f"0x{uuid.uuid4().hex}"
    first = post_ok(shared, e6_draft(source_id=tx_id, event_seq=1))
    second = post_ok(shared, e6_draft(source_id=tx_id, event_seq=2))
    assert first.journal_id != second.journal_id
    assert count_by_source(shared, "usage_settle", tx_id)["journals"] == 2


def test_find_existing_is_read_only(shared: str) -> None:
    draft = e6_draft()
    assert run_ok(shared, lambda c: find_existing(c, draft)) is None
    posted = post_ok(shared, draft)
    found = run_ok(shared, lambda c: find_existing(c, draft))
    assert found is not None and found.journal_id == posted.journal_id and found.idempotent is True


# ─────────────────────────────────────────────────────── 3 校验拒绝（不写一行）
def _assert_rejected(shared: str, draft: JournalDraft, exc_type, match: str = "") -> None:
    with pytest.raises(exc_type) as ei:
        post_ok(shared, draft)
    if match:
        assert match in str(ei.value).lower(), str(ei.value)
    assert count_by_source(shared, draft.source_type, draft.source_id)["journals"] == 0


def test_unbalanced_is_rejected(shared: str) -> None:
    draft = e6_draft()
    bad = JournalDraft(**{**draft.__dict__,
                          "lines": (line("2101", "D", 100), line("4101", "C", 99))})
    _assert_rejected(shared, bad, UnbalancedJournal, "借贷不平")


def test_unknown_coa_is_rejected(shared: str) -> None:
    draft = e6_draft()
    bad = JournalDraft(**{**draft.__dict__,
                          "lines": (line("2101", "D", 100), line("9999", "C", 100))})
    _assert_rejected(shared, bad, UnknownCoaCode, "白名单")


def test_fund_class_must_pair_with_coa(shared: str) -> None:
    draft = e6_draft()
    bad = JournalDraft(**{**draft.__dict__, "lines": (
        line("2101", "D", 100), line("4101", "C", 100, fund_class="CLIENT"))})
    _assert_rejected(shared, bad, FundClassMismatch, "fund_class")


def test_fund_class_is_inferred_when_omitted(shared: str) -> None:
    """省略 fund_class 时按科目推导，落库值与推导一致（不靠调用方记忆）。"""
    result = post_ok(shared, e6_draft(amount_minor=500))
    with connect(shared) as c, c.cursor() as cur:
        cur.execute("SELECT DISTINCT fund_class FROM journal_line WHERE journal_id = %s",
                    (result.journal_id,))
        assert {row[0] for row in cur.fetchall()} == {"CLIENT", "FEE"}


@pytest.mark.parametrize("mutate,exc,match", [
    ({"unit_type": "BTC"}, InvalidUnitType, "unit_type"),
    ({"event_type": "E99"}, InvalidEventType, "event_type"),
    ({"event_type": "usage.settled"}, InvalidEventType, "event_type"),
    ({"source_type": "manual_adjust"}, InvalidSourceType, "source_type"),
])
def test_enum_whitelists_are_enforced(shared: str, mutate, exc, match) -> None:
    draft = e6_draft()
    _assert_rejected(shared, JournalDraft(**{**draft.__dict__, **mutate}), exc, match)


def test_unknown_entry_type_is_rejected(shared: str) -> None:
    draft = e6_draft()
    bad = JournalDraft(**{**draft.__dict__, "lines": (
        line("2101", "D", 100, entry_type="mystery"),
        line("4101", "C", 100, entry_type="consume"))})
    _assert_rejected(shared, bad, InvalidEntryType, "entry_type")


def test_line_count_limits(shared: str) -> None:
    draft = e6_draft()
    one_line = JournalDraft(**{**draft.__dict__, "lines": (line("2101", "D", 100),)})
    _assert_rejected(shared, one_line, LineCountOutOfRange, "行数")

    too_many = tuple(line("2101", "D", 1) for _ in range(JOURNAL_MAX_LINES)) + (line("4101", "C", JOURNAL_MAX_LINES),)
    over = JournalDraft(**{**draft.__dict__, "lines": too_many})
    _assert_rejected(shared, over, LineCountOutOfRange, "行数")


@pytest.mark.parametrize("amount", [0, -1, -100])
def test_amount_must_be_positive(shared: str, amount: int) -> None:
    draft = e6_draft()
    bad = JournalDraft(**{**draft.__dict__, "lines": (
        line("2101", "D", amount), line("4101", "C", amount))})
    _assert_rejected(shared, bad, JournalValidationError, "amount_minor")


def test_asset_line_requires_qty(shared: str) -> None:
    draft = e2_draft()
    bad = JournalDraft(**{**draft.__dict__, "lines": (
        line("1101", "D", 100), line("2990", "D", 100),
        line("1111", "C", 100), line("2101", "C", 100))})
    _assert_rejected(shared, bad, MissingAssetQuantity, "qty_minor")


def test_naive_timestamp_is_rejected(shared: str) -> None:
    from datetime import datetime
    draft = e6_draft(ts=datetime(2026, 10, 23, 3, 0, 0))       # 无时区
    _assert_rejected(shared, draft, JournalValidationError, "时区")


def test_rejected_draft_leaves_ledger_empty(migrated: str) -> None:
    """空库 + 非法凭证：一行都不写，复算与链校验都是 0。"""
    draft = e6_draft()
    bad = JournalDraft(**{**draft.__dict__, "lines": (line("2101", "D", 10), line("4101", "C", 9))})
    with pytest.raises(UnbalancedJournal):
        post_ok(migrated, bad)
    with connect(migrated) as c, c.cursor() as cur:
        cur.execute("SELECT (SELECT count(*) FROM journal_entry), (SELECT count(*) FROM journal_line),"
                    " (SELECT count(*) FROM ledger_entry), (SELECT count(*) FROM m06_outbox)")
        assert cur.fetchone() == (0, 0, 0, 0)
    with connect(migrated) as c:
        assert verify_chain(c)["diff"] == 0


# ─────────────────────────────────────────────────────── 4 事务与 outbox
def test_autocommit_connection_is_rejected(shared: str) -> None:
    conn = connect(shared, autocommit=True)
    try:
        with pytest.raises(TransactionRequired, match="显式事务"):
            post_journal(conn, e6_draft())
    finally:
        conn.close()


def test_outbox_and_journal_share_the_transaction(migrated: str) -> None:
    """冲正/失败回滚时 outbox 不能留下孤事件（§6 事务边界）。"""
    draft = e6_draft()
    with pytest.raises(RuntimeError, match="boom"):
        with tx(migrated) as c:
            result = post_journal(c, draft)          # 正常写入 + outbox
            assert result.event_ids, "outbox 应在同一事务内写入"
            raise RuntimeError("boom")               # 业务后续失败 → 整个事务回滚
    with connect(migrated) as c, c.cursor() as cur:
        cur.execute("SELECT (SELECT count(*) FROM journal_entry), (SELECT count(*) FROM m06_outbox)")
        assert cur.fetchone() == (0, 0)


def test_event_emission_can_be_disabled(shared: str) -> None:
    """内部重放/补录场景可不发事件（显式关闭，不静默）。"""
    draft = e6_draft()
    result = run_ok(shared, lambda c: post_journal(c, draft, emit_event=False))
    assert result.event_ids == ()
    assert outbox_rows(shared, aggregate_id=result.journal_id) == []


# ─────────────────────────────────────────────────────── 5 链与并发
def test_chain_links_sequential_journals(shared: str) -> None:
    first = post_ok(shared, e6_draft(amount_minor=10))
    second = post_ok(shared, e6_draft(amount_minor=20))
    row2 = journal_row(shared, second.journal_id)
    assert bytes(row2["prev_hash"]) == first.hash
    assert second.hash != first.hash
    with connect(shared) as c:
        report = verify_chain(c)
    assert report["diff"] == 0 and report["journals"] >= 2


def test_append_lock_blocks_second_writer(shared: str) -> None:
    """持锁事务提交前，另一个写入方必须被锁挡住（否则链会分叉）。"""
    holder = connect(shared, autocommit=False)
    try:
        post_journal(holder, e6_draft(amount_minor=1))
        with pytest.raises(psycopg.errors.LockNotAvailable):
            with connect(shared, autocommit=False) as other:
                with other.cursor() as cur:
                    cur.execute("SET LOCAL lock_timeout = '400ms'")
                post_journal(other, e6_draft(amount_minor=2))
        holder.commit()
    finally:
        holder.close()
    with connect(shared) as c:
        assert verify_chain(c)["diff"] == 0


def test_concurrent_posts_keep_chain_linear(migrated: str) -> None:
    """4 线程 × 2 张凭证并发落账：链仍线性、无断链、无重复 prev。"""
    threads_n, per_thread = 4, 2
    drafts = [
        [e6_draft(source_id=f"conc-{uuid.uuid4().hex[:8]}-{i}-{k}") for k in range(per_thread)]
        for i in range(threads_n)
    ]
    barrier = threading.Barrier(threads_n)
    errors: list[BaseException] = []

    def worker(batch: list[JournalDraft]) -> None:
        try:
            barrier.wait(timeout=30)
            with tx(migrated) as c:
                for draft in batch:
                    post_journal(c, draft)
        except BaseException as exc:            # noqa: BLE001 - 线程内异常带回主线程
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(batch,)) for batch in drafts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not any(t.is_alive() for t in threads), "并发线程未在超时内结束"
    assert errors == [], errors

    with connect(migrated) as c, c.cursor() as cur:
        report = verify_chain(c)
        cur.execute("SELECT count(*) FROM journal_entry")
        assert cur.fetchone()[0] == threads_n * per_thread
        # 链首的 prev 是 NULL，其余每条 prev 必须各不相同（相同即分叉）
        cur.execute("SELECT count(*) FILTER (WHERE prev_hash IS NULL),"
                    " count(DISTINCT prev_hash) FILTER (WHERE prev_hash IS NOT NULL)"
                    " FROM journal_entry")
        heads, distinct_prevs = cur.fetchone()
        assert heads == 1, heads
        assert distinct_prevs == threads_n * per_thread - 1, distinct_prevs
    assert report["diff"] == 0, report


def test_load_journal_returns_lines(shared: str) -> None:
    result = post_ok(shared, e2_draft(amount_minor=7))
    journal = run_ok(shared, lambda c: load_journal(c, result.journal_id))
    assert journal is not None
    assert journal["journal_id"] == result.journal_id
    assert [l["line_no"] for l in journal["lines"]] == [1, 2, 3, 4]
    assert journal["lines"][0]["coa_code"] == "1101"
    assert journal["hash"] == result.hash_hex
