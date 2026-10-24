# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-M06-T2 网关测试夹具：凭证构造器 + 只读断言工具。

约定：
  · 构造器只造"合法"凭证，非法组合由测试显式改写字段（见 test_gateway.py 的用例）；
  · 断言一律按业务键（source_id / journal_id）取数，不依赖库内总量 ——
    这样多数用例可以共享一个模块级 schema，跑得快，也不会互相踩。
"""
from __future__ import annotations

import uuid
from typing import Sequence

from app.ledger import JournalDraft, JournalLine, post_journal, reverse_journal

from ledgerkit import connect, run_ok  # noqa: F401  (复用 T1 的连接/事务夹具)


def line(coa_code: str, dc: str, amount_minor: int, *, account_id: str | None = None,
         qty_minor: int | None = None, entry_type: str = "consume", unit_scale: int = 6,
         wallet_id: str | None = None, fund_class: str | None = None,
         reverse_of: str | None = None) -> JournalLine:
    return JournalLine(
        account_id=account_id or (f"coa:{coa_code}" if coa_code != "2101" else "acct:user-1"),
        coa_code=coa_code, dc=dc, amount_minor=amount_minor, entry_type=entry_type,
        qty_minor=qty_minor, unit_scale=unit_scale, wallet_id=wallet_id, fund_class=fund_class,
        reverse_of=reverse_of)


def e6_draft(amount_minor: int = 30_000_000, *, source_id: str | None = None,
             event_seq: int = 1, user: str = "user-1", **over) -> JournalDraft:
    """E6 计量消耗：借 2101（用户预付款）/ 贷 4101（全额确认收入，毛额法）。"""
    fields = dict(
        event_type="E6", unit_type="USD", source_type="usage_settle",
        source_id=source_id or f"usage-{uuid.uuid4().hex[:10]}", event_seq=event_seq,
        policy_version="v4.0-t2",
        lines=(line("2101", "D", amount_minor, account_id=f"acct:{user}"),
               line("4101", "C", amount_minor)),
    )
    fields.update(over)
    return JournalDraft(**fields)


def e2_draft(amount_minor: int = 100_000_000, *, source_id: str | None = None,
             event_seq: int = 2, user: str = "user-2", **over) -> JournalDraft:
    """E2 USDT 收款确认入账（四行）：借 1101 + 借 2990 / 贷 1111 + 贷 2101。"""
    fields = dict(
        event_type="E2", unit_type="USD", source_type="chain_tx",
        source_id=source_id or f"0x{uuid.uuid4().hex}", event_seq=event_seq,
        policy_version="v4.0-t2",
        lines=(
            line("1101", "D", amount_minor, qty_minor=amount_minor, entry_type="deposit"),
            line("2990", "D", amount_minor, entry_type="deposit"),
            line("1111", "C", amount_minor, entry_type="deposit"),
            line("2101", "C", amount_minor, account_id=f"acct:{user}", entry_type="deposit"),
        ),
    )
    fields.update(over)
    return JournalDraft(**fields)


def post_ok(schema: str, draft: JournalDraft):
    """在独立事务里落账并提交（借贷平衡等 DEFERRABLE 约束在提交时校验）。"""
    return run_ok(schema, lambda c: post_journal(c, draft))


def reverse_ok(schema: str, journal_id: str, **over):
    """在独立事务里冲正并提交（冲正后不变量复算失败会整笔回滚）。"""
    return run_ok(schema, lambda c: reverse_journal(c, journal_id, **over))


def count_by_source(schema: str, source_type: str, source_id: str) -> dict:
    """按幂等键取该业务对象的落账痕迹（凭证 / 行 / 分录 / 事件）。"""
    with connect(schema) as c, c.cursor() as cur:
        cur.execute(
            """SELECT count(*) FROM journal_entry WHERE source_type = %s AND source_id = %s""",
            (source_type, source_id))
        journals = cur.fetchone()[0]
        cur.execute(
            """SELECT count(*) FROM journal_line l JOIN journal_entry j ON j.journal_id = l.journal_id
                WHERE j.source_type = %s AND j.source_id = %s""", (source_type, source_id))
        lines = cur.fetchone()[0]
        cur.execute(
            """SELECT count(*) FROM ledger_entry e JOIN journal_entry j ON j.journal_id = e.journal_id
                WHERE j.source_type = %s AND j.source_id = %s""", (source_type, source_id))
        entries = cur.fetchone()[0]
        cur.execute(
            """SELECT count(*) FROM m06_outbox o JOIN journal_entry j
                 ON o.payload->>'journal_id' = j.journal_id::text
                WHERE j.source_type = %s AND j.source_id = %s""", (source_type, source_id))
        events = cur.fetchone()[0]
    return {"journals": journals, "lines": lines, "entries": entries, "events": events}


def totals(schema: str, journal_id: str) -> dict:
    with connect(schema) as c, c.cursor() as cur:
        cur.execute(
            """SELECT COALESCE(sum(amount_minor) FILTER (WHERE dc = 'D'), 0),
                      COALESCE(sum(amount_minor) FILTER (WHERE dc = 'C'), 0), count(*)
                 FROM journal_line WHERE journal_id = %s""", (journal_id,))
        debit, credit, lines = cur.fetchone()
    return {"debit": int(debit), "credit": int(credit), "lines": lines}


def journal_row(schema: str, journal_id: str) -> dict:
    with connect(schema) as c, c.cursor() as cur:
        cur.execute(
            """SELECT journal_id, seq, ts, event_type, unit_type, source_type, source_id,
                      event_seq, policy_version, fx_rate_id, reversal_of_journal, status,
                      prev_hash, hash, merkle_period
                 FROM journal_entry WHERE journal_id = %s""", (journal_id,))
        row = cur.fetchone()
        columns = ("journal_id", "seq", "ts", "event_type", "unit_type", "source_type",
                   "source_id", "event_seq", "policy_version", "fx_rate_id",
                   "reversal_of_journal", "status", "prev_hash", "hash", "merkle_period")
    if row is None:
        raise AssertionError(f"journal {journal_id} 不存在")
    return dict(zip(columns, row))


def outbox_rows(schema: str, *, aggregate_id: str | None = None) -> list[dict]:
    sql = ("SELECT event_id, type, aggregate_type, aggregate_id, trace_id, idempotency_key, "
           "payload, published_at FROM m06_outbox")
    args: Sequence = ()
    if aggregate_id is not None:
        sql += " WHERE aggregate_id = %s"
        args = (aggregate_id,)
    with connect(schema) as c, c.cursor() as cur:
        cur.execute(sql + " ORDER BY created_at", args)
        columns = ("event_id", "type", "aggregate_type", "aggregate_id", "trace_id",
                   "idempotency_key", "payload", "published_at")
        return [dict(zip(columns, row)) for row in cur.fetchall()]
