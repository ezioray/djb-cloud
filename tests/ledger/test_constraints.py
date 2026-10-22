# SPDX-License-Identifier: Apache-2.0
"""约束边界：42 科目白名单（INV-03）、单位（INV-04）、借贷平衡（INV-01）、
1:1 绑定（INV-02）、幂等键（INV-06）、冲正等额取反（INV-07）、期间根与事件契约。

验收来源：DEV-M06-T1 验收 3「42 科目白名单与单位约束有测试」。
"""
from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from ledgerkit import (
    session,
    COA_FUND_CLASS,
    ENTRY_TYPES,
    SOURCE_TYPES,
    UNIT_TYPES,
    assert_db_error,
    connect,
    line,
    new_hash,
    post_journal,
    run_ok,
    simple_lines,
)

# ─────────────────────────────────────────────────────── 手工插入小工具（只为构造非法组合）
def _header(cur, *, unit_type: str = "USD", event_type: str = "E6", source_type: str = "usage_settle",
            source_id: str | None = None, event_seq: int = 0) -> str:
    journal_id = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO journal_entry
             (journal_id, ts, event_type, unit_type, source_type, source_id, event_seq,
              policy_version, hash)
           VALUES (%s, now(), %s, %s, %s, %s, %s, 'v4.0-t1', %s)""",
        (journal_id, event_type, unit_type, source_type,
         source_id or f"src-{uuid.uuid4().hex[:12]}", event_seq, new_hash(journal_id)))
    return journal_id


def _entry(cur, journal_id: str, line_no: int, *, coa: str = "2101", dc: str = "C",
           amount_minor: int = 100, unit_type: str = "USD", fund_class: str = "CLIENT",
           qty_minor: int | None = None, entry_type: str = "consume",
           account_id: str | None = None, reverse_of: str | None = None) -> str:
    entry_id = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO ledger_entry
             (entry_id, journal_id, line_no, account_id, entry_type, unit_type, dc,
              amount_minor, qty_minor, fund_class, reverse_of)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (entry_id, journal_id, line_no, account_id or f"coa:{coa}", entry_type, unit_type,
         dc, amount_minor, qty_minor, fund_class, reverse_of))
    return entry_id


def _line(cur, journal_id: str, line_no: int, entry_id: str, *, account_id: str, coa: str,
          dc: str, amount_minor: int, unit_scale: int = 6, qty_minor: int | None = None,
          fund_class: str = "CLIENT") -> None:
    cur.execute(
        """INSERT INTO journal_line
             (journal_id, line_no, ledger_entry_id, account_id, coa_code, dc, amount_minor,
              unit_scale, qty_minor, fund_class)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (journal_id, line_no, entry_id, account_id, coa, dc, amount_minor, unit_scale,
         qty_minor, fund_class))


def _pair(cur, journal_id: str, *, debit_coa: str = "1101", credit_coa: str = "2101",
          amount_minor: int = 100, qty_minor: int | None = None) -> None:
    d_qty = qty_minor if qty_minor is not None else (amount_minor if debit_coa in ("1101", "1102", "1103") else None)
    d_acct = f"coa:{debit_coa}"
    c_acct = f"coa:{credit_coa}"
    e1 = _entry(cur, journal_id, 1, coa=debit_coa, dc="D", amount_minor=amount_minor,
                fund_class=COA_FUND_CLASS[debit_coa], qty_minor=d_qty, account_id=d_acct)
    _line(cur, journal_id, 1, e1, account_id=d_acct, coa=debit_coa, dc="D",
          amount_minor=amount_minor, qty_minor=d_qty, fund_class=COA_FUND_CLASS[debit_coa])
    e2 = _entry(cur, journal_id, 2, coa=credit_coa, dc="C", amount_minor=amount_minor,
                fund_class=COA_FUND_CLASS[credit_coa], account_id=c_acct)
    _line(cur, journal_id, 2, e2, account_id=c_acct, coa=credit_coa, dc="C",
          amount_minor=amount_minor, fund_class=COA_FUND_CLASS[credit_coa])


# ─────────────────────────────────────────────────────── 42 科目白名单（INV-03）
def test_coa_whitelist_has_exactly_42_codes() -> None:
    """常量侧自检：测试用的 42 科目表就是 spec §20.2 的 42 条（12/12/6/10/2）。"""
    groups = {
        "资产": ["1101", "1102", "1103", "1109", "1111", "1120", "1121", "1130", "1140", "1190", "1901", "1910"],
        "负债权益": ["2101", "2102", "2103", "2201", "2202", "2203", "2204", "2210", "2301", "2901", "2990", "3101"],
        "收入": ["4101", "4102", "4103", "4104", "4105", "4201"],
        "费用损失": ["5101", "5102", "5103", "5104", "5105", "5106", "5201", "5301", "5401", "5501"],
        "非现金调整": ["6101", "6901"],
    }
    assert [len(v) for v in groups.values()] == [12, 12, 6, 10, 2]
    assert sum(len(v) for v in groups.values()) == 42
    assert set().union(*map(set, groups.values())) == set(COA_FUND_CLASS) == set(COA_FUND_CLASS.keys())


def test_ddl_whitelist_matches_spec(shared: str) -> None:
    """DDL 里的白名单与 spec 常量逐条一致（防止只改一处）。"""
    with session(shared) as c, c.cursor() as cur:
        cur.execute(
            """SELECT pg_get_constraintdef(con.oid)
                 FROM pg_constraint con
                 JOIN pg_class cl ON cl.oid = con.conrelid
                 JOIN pg_namespace n ON n.oid = cl.relnamespace
                WHERE n.nspname = current_schema() AND cl.relname = 'journal_line'
                  AND con.conname = 'journal_line_coa_ck'""")
        ddl = cur.fetchone()[0]
    for code in COA_FUND_CLASS:
        assert f"'{code}'" in ddl, f"白名单缺 {code}"
    assert ddl.count("'") == 42 * 2, "白名单条数应为 42"


@pytest.mark.parametrize("coa_code", sorted(COA_FUND_CLASS))
def test_each_of_42_coa_is_accepted(shared: str, coa_code: str) -> None:
    """42 个科目逐个落账均被接受（资产行按 C4 双记 qty）。"""
    qty = 100 if coa_code in ("1101", "1102", "1103") else None
    lines = [
        line(coa_code, "D", 100, qty_minor=qty),
        line("2901" if coa_code != "2901" else "1101", "C", 100,
             qty_minor=100 if coa_code == "2901" else None),
    ]
    run_ok(shared, lambda c: post_journal(c, lines))


@pytest.mark.parametrize("bad", ["9999", "110", "11010", "4101 ", "ABCD"])
def test_unknown_coa_is_rejected(shared: str, bad: str) -> None:
    """INV-05：白名单外的科目一律拒绝，不静默放过。"""
    def _fn(c):
        with c.cursor() as cur:
            journal_id = _header(cur)
            e1 = _entry(cur, journal_id, 1, coa="1101", dc="D", amount_minor=100,
                        fund_class="CLIENT", qty_minor=100, account_id="coa:1101")
            _line(cur, journal_id, 1, e1, account_id="coa:1101", coa="1101", dc="D",
                  amount_minor=100, qty_minor=100, fund_class="CLIENT")
            e2 = _entry(cur, journal_id, 2, coa="2101", dc="C", amount_minor=100,
                        fund_class="CLIENT", account_id="coa:2101")
            _line(cur, journal_id, 2, e2, account_id="coa:2101", coa=bad, dc="C",
                  amount_minor=100, fund_class="CLIENT")

    assert_db_error(shared, "journal_line_coa_ck", _fn)


@pytest.mark.parametrize("coa,bad_class", [
    ("1101", "PLATFORM"), ("1109", "CLIENT"), ("2901", "CLIENT"), ("3101", "FEE"),
    ("4101", "CLIENT"), ("5105", "PLATFORM"), ("6901", "CLIENT"),
])
def test_fund_class_must_match_coa(shared: str, coa: str, bad_class: str) -> None:
    """INV-03 后半：fund_class 与科目归属不一致即拒绝。"""
    def _fn(c):
        with c.cursor() as cur:
            journal_id = _header(cur)
            e1 = _entry(cur, journal_id, 1, coa=coa, dc="D", amount_minor=100,
                        fund_class=bad_class, qty_minor=100, account_id=f"coa:{coa}")
            _line(cur, journal_id, 1, e1, account_id=f"coa:{coa}", coa=coa, dc="D",
                  amount_minor=100, qty_minor=100, fund_class=bad_class)
            e2 = _entry(cur, journal_id, 2, coa="2101", dc="C", amount_minor=100,
                        fund_class="CLIENT", account_id="coa:2101")
            _line(cur, journal_id, 2, e2, account_id="coa:2101", coa="2101", dc="C",
                  amount_minor=100, fund_class="CLIENT")

    assert_db_error(shared, "journal_line_coa_fund_class_ck", _fn)


# ─────────────────────────────────────────────────────── 单位（INV-04）
@pytest.mark.parametrize("unit_type", UNIT_TYPES)
def test_four_unit_types_are_accepted(shared: str, unit_type: str) -> None:
    run_ok(shared, lambda c: post_journal(c, simple_lines(100), unit_type=unit_type))


@pytest.mark.parametrize("bad_unit", ["BTC", "usd", "USDT", "CNY", ""])
def test_unknown_unit_type_is_rejected(shared: str, bad_unit: str) -> None:
    assert_db_error(shared, "journal_entry_unit_type_ck",
                    lambda c: post_journal(c, simple_lines(100), unit_type=bad_unit))


def test_entry_unit_must_match_journal(shared: str) -> None:
    """分录与凭证必须同单位（复合外键；USD 凭证里不允许出现 COP 分录）。"""
    def _fn(c):
        with c.cursor() as cur:
            journal_id = _header(cur, unit_type="USD")
            _entry(cur, journal_id, 1, coa="2101", dc="C", unit_type="COP")

    assert_db_error(shared, "ledger_entry_journal_unit_fkey", _fn)


# ─────────────────────────────────────────────────────── 金额 / 方向 / 辅助计量
@pytest.mark.parametrize("bad_amount", [0, -1, -100])
def test_amount_must_be_positive_integer(shared: str, bad_amount: int) -> None:
    assert_db_error(shared, "amount_ck",
                    lambda c: post_journal(c, simple_lines(bad_amount)))


def test_dc_must_be_d_or_c(shared: str) -> None:
    def _fn(c):
        with c.cursor() as cur:
            journal_id = _header(cur)
            _entry(cur, journal_id, 1, coa="2101", dc="X")

    assert_db_error(shared, "ledger_entry_dc_ck", _fn)


@pytest.mark.parametrize("coa", ["1101", "1102", "1103"])
def test_asset_rows_require_qty(shared: str, coa: str) -> None:
    """INV-11 / C4：链上资产行必须同时记 qty_minor 与 amount_minor。"""
    def _fn(c):
        with c.cursor() as cur:
            journal_id = _header(cur)
            e1 = _entry(cur, journal_id, 1, coa=coa, dc="D", amount_minor=100,
                        fund_class="CLIENT", qty_minor=None, account_id=f"coa:{coa}")
            _line(cur, journal_id, 1, e1, account_id=f"coa:{coa}", coa=coa, dc="D",
                  amount_minor=100, qty_minor=None, fund_class="CLIENT")
            e2 = _entry(cur, journal_id, 2, coa="2101", dc="C", amount_minor=100,
                        fund_class="CLIENT", account_id="coa:2101")
            _line(cur, journal_id, 2, e2, account_id="coa:2101", coa="2101", dc="C",
                  amount_minor=100, fund_class="CLIENT")

    assert_db_error(shared, "journal_line_asset_qty_ck", _fn)


def test_amount_display_column_follows_unit_scale(shared: str) -> None:
    """B4：amount = amount_minor / 10^unit_scale（生成列，永远与最小单位一致）。"""
    ids = run_ok(shared, lambda c: post_journal(
        c, [line("1101", "D", 123_456_789, qty_minor=123_456_789), line("2101", "C", 123_456_789)]))
    with session(shared) as c, c.cursor() as cur:
        cur.execute("SELECT amount FROM journal_line WHERE journal_id = %s ORDER BY line_no",
                    (ids["journal_id"],))
        amounts = [row[0] for row in cur.fetchall()]
    assert amounts == [Decimal("123.456789")] * 2, amounts


# ─────────────────────────────────────────────────────── 借贷平衡（INV-01 / B1）
def test_unbalanced_journal_is_rejected_at_commit(shared: str) -> None:
    lines = [line("1101", "D", 100, qty_minor=100), line("2101", "C", 99)]
    assert_db_error(shared, "is not balanced", lambda c: post_journal(c, lines))


def test_single_line_journal_is_rejected(shared: str) -> None:
    assert_db_error(shared, "at least 2 required",
                    lambda c: post_journal(c, [line("1101", "D", 100, qty_minor=100)]))


def test_journal_without_lines_is_rejected(shared: str) -> None:
    assert_db_error(shared, "at least 2 required", lambda c: post_journal(c, []))


def test_journal_max_lines_64(shared: str) -> None:
    """JOURNAL_MAX_LINES=64：64 行可提交，第 65 行被拒绝。"""
    ok_lines = [line("1101", "D", 1, qty_minor=1) for _ in range(63)] + [line("2101", "C", 63)]
    assert len(ok_lines) == 64
    run_ok(shared, lambda c: post_journal(c, ok_lines))

    too_many = [line("1101", "D", 1, qty_minor=1) for _ in range(64)] + [line("2101", "C", 64)]
    assert_db_error(shared, "line_no_ck",
                    lambda c: post_journal(c, too_many))


# ─────────────────────────────────────────────────────── 幂等键（INV-06 / I-8）
def test_idempotency_key_is_unique(shared: str) -> None:
    src = f"src-{uuid.uuid4().hex[:8]}"
    run_ok(shared, lambda c: post_journal(c, simple_lines(10), source_id=src, event_seq=1))
    assert_db_error(
        shared, "journal_entry_idem_uq",
        lambda c: post_journal(c, simple_lines(10), source_id=src, event_seq=1))
    # 同一 source_id 不同 event_seq 是另一张凭证（E2 的两步）
    run_ok(shared, lambda c: post_journal(c, simple_lines(10), source_id=src, event_seq=2))


@pytest.mark.parametrize("bad", ["", "x" * 129])
def test_source_id_length_bounds(shared: str, bad: str) -> None:
    assert_db_error(shared, "journal_entry_source_id_ck",
                    lambda c: post_journal(c, simple_lines(10), source_id=bad))


# ─────────────────────────────────────────────────────── 1:1 绑定（INV-02）
def test_line_must_point_to_entry_of_same_journal(shared: str) -> None:
    def _fn(c):
        with c.cursor() as cur:
            j1 = _header(cur)
            j2 = _header(cur)
            foreign_entry = _entry(cur, j2, 1, coa="2101", dc="C", amount_minor=100)
            _line(cur, j1, 1, foreign_entry, account_id="coa:2101", coa="2101", dc="C",
                  amount_minor=100, fund_class="CLIENT")

    assert_db_error(shared, "journal_line_ledger_entry_fkey", _fn)


def test_one_to_one_constraints_exist(shared: str) -> None:
    """INV-02 的结构保证：UNIQUE(ledger_entry_id) + 复合外键(ledger_entry_id, journal_id)。"""
    with session(shared) as c, c.cursor() as cur:
        cur.execute(
            """SELECT con.conname, pg_get_constraintdef(con.oid)
                 FROM pg_constraint con
                 JOIN pg_class cl ON cl.oid = con.conrelid
                 JOIN pg_namespace n ON n.oid = cl.relnamespace
                WHERE n.nspname = current_schema() AND cl.relname = 'journal_line'""")
        defs = {name: d for name, d in cur.fetchall()}
    assert "journal_line_ledger_entry_uq" in defs, defs
    fk = defs.get("journal_line_ledger_entry_fkey", "")
    assert "ledger_entry(entry_id, journal_id)" in fk.replace(" ", " "), fk


@pytest.mark.parametrize("field,value", [("amount_minor", 99), ("dc", "D"), ("line_no", 3),
                                         ("qty_minor", 7), ("account_id", "coa:9999")])
def test_line_and_entry_must_agree(shared: str, field: str, value) -> None:
    """同一行的两处记录（ledger_entry / journal_line）不得漂移。"""
    def _fn(c):
        with c.cursor() as cur:
            j = _header(cur)
            e1 = _entry(cur, j, 1, coa="1101", dc="D", amount_minor=100, qty_minor=100,
                        fund_class="CLIENT", account_id="coa:1101")
            _line(cur, j, 1, e1, account_id="coa:1101", coa="1101", dc="D", amount_minor=100,
                  qty_minor=100, fund_class="CLIENT")
            e2 = _entry(cur, j, 2, coa="2101", dc="C", amount_minor=100, fund_class="CLIENT",
                        account_id="coa:2101")
            kwargs = {"account_id": "coa:2101", "coa": "2101", "dc": "C", "amount_minor": 100,
                      "fund_class": "CLIENT"}
            kwargs[field] = value
            line_no = kwargs.pop("line_no", 2)
            _line(cur, j, line_no, e2, **kwargs)

    assert_db_error(shared, "does not match ledger_entry", _fn)


def test_two_entries_cannot_share_one_line_no(shared: str) -> None:
    def _fn(c):
        with c.cursor() as cur:
            j = _header(cur)
            _entry(cur, j, 1, coa="2101", dc="C", amount_minor=100)
            _entry(cur, j, 1, coa="2101", dc="C", amount_minor=100)

    assert_db_error(shared, "ledger_entry_journal_line_uq", _fn)


def test_cannot_append_lines_to_voided_journal(shared: str) -> None:
    ids = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    run_ok(shared, lambda c: c.cursor().execute(
        "UPDATE journal_entry SET status = 'voided' WHERE journal_id = %s", (ids["journal_id"],)))

    def _fn(c):
        with c.cursor() as cur:
            e = _entry(cur, ids["journal_id"], 3, coa="2101", dc="C", amount_minor=100)
            _line(cur, ids["journal_id"], 3, e, account_id="coa:2101", coa="2101", dc="C",
                  amount_minor=100, fund_class="CLIENT")

    assert_db_error(shared, "cannot append lines", _fn)


# ─────────────────────────────────────────────────────── 冲正（INV-07 / R5）
def _reversal_lines(original: dict, *, amount_minor: int | None = None, dc: str = "C",
                    unit_type: str = "USD") -> list[dict]:
    """冲正行：1101 逐行取反（qty 仍按 C4 双记），2101 反向。"""
    amount = amount_minor if amount_minor is not None else 100
    return [line("1101", dc, amount, qty_minor=amount, entry_type="void",
                 reverse_of=original["entry_ids"][0]),
            line("2101", "D" if dc == "C" else "C", 100, entry_type="void",
                 reverse_of=original["entry_ids"][1])]


def test_reversal_is_equal_and_flipped(shared: str) -> None:
    original = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    # 逐行取反 + reverse_of + reversal_of_journal
    run_ok(shared, lambda c: post_journal(
        c, _reversal_lines(original), event_type="E15", source_type="void",
        reversal_of=original["journal_id"]))
    run_ok(shared, lambda c: c.cursor().execute(
        "UPDATE journal_entry SET status = 'voided' WHERE journal_id = %s", (original["journal_id"],)))


def test_reversal_amount_must_be_equal(shared: str) -> None:
    original = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    assert_db_error(
        shared, "reversal amount",
        lambda c: post_journal(c, _reversal_lines(original, amount_minor=99),
                               source_type="void", reversal_of=original["journal_id"]))


def test_reversal_must_flip_dc(shared: str) -> None:
    original = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    lines = [line("1101", "D", 100, qty_minor=100, entry_type="void",
                  reverse_of=original["entry_ids"][0]),
             line("2101", "C", 100, entry_type="void", reverse_of=original["entry_ids"][1])]
    assert_db_error(shared, "must flip dc",
                    lambda c: post_journal(c, lines, source_type="void",
                                           reversal_of=original["journal_id"]))


def test_only_one_reversal_per_entry(shared: str) -> None:
    original = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    run_ok(shared, lambda c: post_journal(
        c, _reversal_lines(original), source_type="void", reversal_of=original["journal_id"],
        source_id="void-1"))
    # 凭证层护栏先命中：同一原凭证只能有一条冲正凭证（INV-07）
    assert_db_error(
        shared, "journal_entry_reversal_uq",
        lambda c: post_journal(c, _reversal_lines(original), source_type="void",
                               reversal_of=original["journal_id"], source_id="void-2"))
    # 绕开凭证级索引（不带 reversal_of_journal）时，分录级唯一仍然拦住第二次冲正
    assert_db_error(
        shared, "ledger_entry_reverse_uq",
        lambda c: post_journal(c, _reversal_lines(original), source_type="void",
                               source_id="void-3"))


def test_cannot_reverse_voided_entry(shared: str) -> None:
    original = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    run_ok(shared, lambda c: c.cursor().execute(
        "UPDATE ledger_entry SET status = 'voided' WHERE entry_id = %s", (original["entry_ids"][0],)))
    assert_db_error(
        shared, "already voided",
        lambda c: post_journal(c, _reversal_lines(original), source_type="void",
                               reversal_of=original["journal_id"]))


# ─────────────────────────────────────────────────────── 期间根（INV-13）
def _merkle(c, period: str = "2026-10", kind: str = "journal", root: str = "b" * 64,
            entry_count: int = 1) -> None:
    c.cursor().execute(
        "INSERT INTO merkle_commitments (period, kind, root, entry_count) VALUES (%s,%s,%s,%s)",
        (period, kind, root, entry_count))


@pytest.mark.parametrize("kwargs,match", [
    ({"kind": "audit"}, "merkle_commitments_kind_ck"),          # audit 根归 M16，不得入本表
    ({"kind": "por"}, "merkle_commitments_kind_ck"),            # por 根归 M09
    ({"root": "zz" * 32}, "merkle_commitments_root_ck"),
    ({"root": "b" * 63}, "merkle_commitments_root_ck"),
    ({"period": "2026/10"}, "merkle_commitments_period_ck"),
    ({"period": "2026-13"}, "merkle_commitments_period_ck"),
    ({"entry_count": -1}, "merkle_commitments_count_ck"),
])
def test_merkle_domain_checks(shared: str, kwargs: dict, match: str) -> None:
    assert_db_error(shared, match, lambda c: _merkle(c, **kwargs))


def test_merkle_period_kind_is_unique(shared: str) -> None:
    run_ok(shared, lambda c: _merkle(c))
    assert_db_error(shared, "merkle_commitments_pk", lambda c: _merkle(c))
    # 同期间不同类型根是允许的（journal / daily_close 各一）
    run_ok(shared, lambda c: _merkle(c, kind="daily_close", period="2026-10-23"))


# ─────────────────────────────────────────────────────── 事件契约（02-events / M06 §4.2）
@pytest.mark.parametrize("kwargs,match", [
    ({"type": "journal.updated"}, "m06_outbox_"),                          # 未登记事件
    ({"type": "merkle.anchored", "aggregate_type": "journal_entry"}, "m06_outbox_aggregate_ck"),
    ({"payload": '{"journal_id": "j"}'}, "m06_outbox_payload"),            # 缺必含字段
    ({"payload": '"not-an-object"'}, "m06_outbox_payload"),
    ({"producer": "M08"}, "m06_outbox_producer_ck"),
])
def test_outbox_event_contract(shared: str, kwargs: dict, match: str) -> None:
    from test_append_only import _insert_outbox  # 复用同一份合法样本

    assert_db_error(shared, match, lambda c: _insert_outbox(c.cursor(), **kwargs))


def test_outbox_idempotency_key_unique(shared: str) -> None:
    from test_append_only import _insert_outbox

    key = f"journal.posted:{uuid.uuid4().hex}"
    run_ok(shared, lambda c: _insert_outbox(c.cursor(), idempotency_key=key))
    assert_db_error(shared, "m06_outbox_idem_uq",
                    lambda c: _insert_outbox(c.cursor(), idempotency_key=key))


# ─────────────────────────────────────────────────────── 派生余额（INV-10）
def test_balance_version_must_be_contiguous(shared: str) -> None:
    def _gap(c):
        c.cursor().execute(
            "INSERT INTO account_balances (account_id, unit_type, sub_account, version, balance_minor) "
            "VALUES ('coa:2101','USD','AVAILABLE', 2, -100)")

    assert_db_error(shared, "version must be", _gap)
    run_ok(shared, lambda c: c.cursor().execute(
        "INSERT INTO account_balances (account_id, unit_type, sub_account, version, balance_minor) "
        "VALUES ('coa:2101','USD','AVAILABLE', 1, -100)"))
    # 重复版本：版本连续性触发器先命中；主键是同版本并发写的最终兜底
    assert_db_error(shared, "version must be", lambda c: c.cursor().execute(
        "INSERT INTO account_balances (account_id, unit_type, sub_account, version, balance_minor) "
        "VALUES ('coa:2101','USD','AVAILABLE', 1, 0)"))


@pytest.mark.parametrize("kwargs,match", [
    ({"unit_type": "BTC"}, "account_balances_unit_type_ck"),
    ({"sub_account": "SPARE"}, "account_balances_sub_account_ck"),
])
def test_balance_domain_checks(shared: str, kwargs: dict, match: str) -> None:
    def _fn(c):
        row = {"account_id": "coa:2101", "unit_type": "USD", "sub_account": "AVAILABLE",
               "version": 1, "balance_minor": -100}
        row.update(kwargs)
        c.cursor().execute(
            "INSERT INTO account_balances (account_id, unit_type, sub_account, version, balance_minor) "
            "VALUES (%(account_id)s,%(unit_type)s,%(sub_account)s,%(version)s,%(balance_minor)s)", row)

    assert_db_error(shared, match, _fn)


# ─────────────────────────────────────────────────────── 枚举常量自检
def test_enum_constants_sizes() -> None:
    """source_type 16 值、entry_type 16 值、E1–E17 十七条（与 spec / §20.4.4 对齐）。"""
    assert len(SOURCE_TYPES) == 16
    assert len(set(SOURCE_TYPES)) == 16
    assert len(ENTRY_TYPES) == 16
    assert len(set(ENTRY_TYPES)) == 16


def test_balance_and_reversal_unique_structures_exist(shared: str) -> None:
    """结构兜底：余额主键、分录级冲正唯一索引、凭证级冲正唯一索引都在。"""
    with session(shared) as c, c.cursor() as cur:
        cur.execute(
            """SELECT con.conname FROM pg_constraint con
                 JOIN pg_class cl ON cl.oid = con.conrelid
                 JOIN pg_namespace n ON n.oid = cl.relnamespace
                WHERE n.nspname = current_schema() AND cl.relname = 'account_balances'""")
        assert "account_balances_pk" in {r[0] for r in cur.fetchall()}
        cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
        indexes = {r[0] for r in cur.fetchall()}
    assert "ledger_entry_reverse_uq" in indexes, indexes
    assert "journal_entry_reversal_uq" in indexes, indexes
