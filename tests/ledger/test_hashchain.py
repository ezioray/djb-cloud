# SPDX-License-Identifier: Apache-2.0
"""哈希链验收：规范化确定性、链接、断链与篡改检测（INV-13 / BUG-0002 口径）。

做法上不赌并发竞态：断链与篡改都在**显式事务 + 回滚**里构造，断言检测得到后立刻撤销。
"""
from __future__ import annotations

import uuid

import pytest

from app.ledger import canonical_bytes, canonical_payload, journal_hash, verify_chain
from app.ledger.hashchain import GENESIS, hash_hex

from gatewaykit import e2_draft, e6_draft, journal_row, post_ok
from ledgerkit import connect, run_ok, tx


def _payload(amount: int = 100, **over) -> dict:
    fields = dict(unit_type="USD", event_type="E6", source_type="usage_settle",
                  source_id="hash-unit", event_seq=1, policy_version="v4.0-t2", fx_rate_id=1,
                  lines=[{"line_no": 1, "account_id": "a", "coa_code": "2101", "dc": "D",
                          "amount_minor": amount, "qty_minor": None, "unit_scale": 6,
                          "fund_class": "CLIENT"}])
    fields.update(over)
    return canonical_payload(**fields)


# ─────────────────────────────────────────────────────── 规范化
def test_canonical_bytes_are_stable_and_sorted() -> None:
    payload = _payload()
    assert canonical_bytes(payload) == canonical_bytes(dict(reversed(list(payload.items()))))
    text = canonical_bytes(payload).decode()
    assert '": ' not in text and '", "' not in text         # 无多余空格（separators=(',',':')）
    assert text.index('"event_type"') < text.index('"unit_type"')  # 键排序


def test_hash_is_content_addressed() -> None:
    prev = bytes(range(32))
    same_a = journal_hash(prev, _payload(100))
    same_b = journal_hash(bytes(range(32)), _payload(100))
    other_prev = journal_hash(bytes(range(1, 33)), _payload(100))
    other_amount = journal_hash(prev, _payload(101))
    assert same_a == same_b and len(same_a) == 32
    assert other_prev != same_a and other_amount != same_a


def test_genesis_label_is_used_for_chain_head() -> None:
    payload = _payload()
    assert journal_hash(None, payload) == journal_hash(None, payload)
    assert journal_hash(None, payload) != journal_hash(bytes(32), payload)
    assert GENESIS == "GENESIS"


@pytest.mark.parametrize("bad_prev", [b"short", bytes(31), bytes(33)])
def test_invalid_prev_hash_length_is_rejected(bad_prev: bytes) -> None:
    with pytest.raises(ValueError, match="prev_hash"):
        journal_hash(bad_prev, _payload())


def test_line_no_can_come_from_order_or_from_row() -> None:
    """写入时行号由网关按顺序给；读回校验时行自带 line_no —— 两种来源必须一致。"""
    line = {"account_id": "a", "coa_code": "2101", "dc": "D", "amount_minor": 1,
            "qty_minor": None, "unit_scale": 6, "fund_class": "CLIENT"}
    from_write = canonical_payload(unit_type="USD", event_type="E6", source_type="usage_settle",
                                   source_id="s", event_seq=1, policy_version="v",
                                   fx_rate_id=1, lines=[line])
    from_read = canonical_payload(unit_type="USD", event_type="E6", source_type="usage_settle",
                                  source_id="s", event_seq=1, policy_version="v",
                                  fx_rate_id=1, lines=[{**line, "line_no": 1}])
    assert from_write == from_read


# ─────────────────────────────────────────────────────── 链（真库）
def test_chain_of_three_journals_verifies(shared: str) -> None:
    first = post_ok(shared, e6_draft(amount_minor=11))
    second = post_ok(shared, e6_draft(amount_minor=22))
    third = post_ok(shared, e2_draft(amount_minor=33))

    row2, row3 = journal_row(shared, second.journal_id), journal_row(shared, third.journal_id)
    assert bytes(row2["prev_hash"]) == first.hash
    assert bytes(row3["prev_hash"]) == second.hash

    with connect(shared) as c:
        report = verify_chain(c)
    assert report["chain_bad"] == [] and report["hash_bad"] == [] and report["diff"] == 0


def _insert_raw_journal(cur, *, prev: bytes | None, digest: bytes, source_id: str) -> str:
    journal_id = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO journal_entry
             (journal_id, ts, event_type, unit_type, source_type, source_id, event_seq,
              policy_version, fx_rate_id, prev_hash, hash)
           VALUES (%s, now(), 'E6', 'USD', 'usage_settle', %s, 1, 'v4.0-t2', 1, %s, %s)""",
        (journal_id, source_id, prev, digest))
    return journal_id


def test_broken_link_is_detected(shared: str) -> None:
    """两条凭证共用同一个 prev（分叉形态）→ chain_bad 命中；回滚后干净。

    构造与用例顺序无关：先读当前链尾 L，插入 A(prev=L)，再插入 B(prev=L) ——
    此时链尾已是 A，B 的 prev 指不到 A，必然断链。
    """
    post_ok(shared, e6_draft(amount_minor=44))
    with tx(shared) as c:
        with c.cursor() as cur:
            cur.execute("SELECT hash FROM journal_entry ORDER BY seq DESC LIMIT 1")
            last = bytes(cur.fetchone()[0])
            _insert_raw_journal(cur, prev=last, digest=b"\x01" * 32,
                                source_id=f"fork-a-{uuid.uuid4().hex[:8]}")
            _insert_raw_journal(cur, prev=last, digest=b"\x02" * 32,
                                source_id=f"fork-b-{uuid.uuid4().hex[:8]}")
            report = verify_chain(c)
            assert report["chain_bad"], report                         # 断链被检出
            assert report["diff"] > 0
            c.rollback()
    with connect(shared) as c:
        assert verify_chain(c)["chain_bad"] == []


def test_tampered_hash_is_detected(shared: str) -> None:
    """hash 与内容不符（内容被改过 / 写错哈希）→ hash_bad 命中；回滚后干净。"""
    post_ok(shared, e6_draft(amount_minor=55))
    with tx(shared) as c:
        with c.cursor() as cur:
            cur.execute("SELECT hash FROM journal_entry ORDER BY seq DESC LIMIT 1")
            prev = bytes(cur.fetchone()[0])
            _insert_raw_journal(cur, prev=prev, digest=b"\xff" * 32,
                                source_id=f"tamper-{uuid.uuid4().hex[:8]}")
            report = verify_chain(c)
            assert report["hash_bad"], report
            assert report["chain_bad"] == []
            c.rollback()
    with connect(shared) as c:
        assert verify_chain(c)["hash_bad"] == []


def test_identical_content_on_same_prev_is_rejected_by_unique_hash(migrated: str) -> None:
    """同内容 + 同 prev 必得同一 hash（内容寻址）→ 唯一约束直接拦下（分叉护栏）。"""
    head = post_ok(migrated, e6_draft(amount_minor=66))
    row = journal_row(migrated, head.journal_id)
    with pytest.raises(Exception) as ei:
        with tx(migrated) as c:
            with c.cursor() as cur:
                _insert_raw_journal(cur, prev=row["prev_hash"], digest=bytes(row["hash"]),
                                    source_id=f"dup-{uuid.uuid4().hex[:8]}")
    assert "journal_entry_hash_uq" in str(ei.value)


def test_verify_chain_reports_counts(shared: str) -> None:
    before = run_ok(shared, lambda c: verify_chain(c)["journals"])
    post_ok(shared, e6_draft(amount_minor=77))
    after = run_ok(shared, lambda c: verify_chain(c))
    assert after["journals"] == before + 1
    assert after["diff"] == 0


def test_hash_hex_helper() -> None:
    assert hash_hex(None) is None
    assert hash_hex(b"\x00\xff") == "00ff"
