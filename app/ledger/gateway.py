# SPDX-License-Identifier: Apache-2.0
"""记账网关：校验 → 落账 → 哈希链 → outbox，全部在调用方的**同一个事务**里。

落账顺序（与 600/601 迁移的约束逐条对应，顺序不能变）::

    1. journal_entry   凭证头（幂等键 + hash 链）
    2. ledger_entry    每行一条业务分录（1:1，journal_line 复合外键指过来）
    3. journal_line    每行一条会计行（coa_code / dc / amount_minor / fund_class）
    4. m06_outbox      journal.posted（与业务同事务；投递失败不回滚业务）

事务与并发：
  · 必须显式事务（autocommit 连接无法持有 ``pg_advisory_xact_lock``，直接报错不降级）；
  · 追加前先抢 ``LEDGER_APPEND_LOCK_ID``（与旧路径同一个 id，全库账本追加一个全序），
    再读 prev_hash → 计算 hash → 插入，避免并发读到同一 prev 造成链分叉（BUG-0002 口径）；
  · 余额由 T3 负责（本网关不写 account_balances，避免两处各算一次）。

幂等（INV-06 / I-8）：``(source_type, source_id, event_seq)`` 命中既有凭证时**不写任何行**，
返回既有 ``journal_id`` 且 ``idempotent=True``。业务载荷是否一致由调用方保证（重复请求
语义 = 同一业务事件）；若需要「同键不同载荷」的强拒绝，需要 605 迁移加指纹列，见证据 §风险。
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from . import balances as balances_mod
from . import hashchain, outbox
from .constants import LEDGER_APPEND_LOCK_ID
from .errors import TransactionRequired
from .validate import JournalDraft, NormalizedJournal, normalize


@dataclass(frozen=True)
class PostJournalResult:
    journal_id: str
    seq: int
    hash: bytes
    idempotent: bool = False
    event_ids: tuple[str, ...] = ()
    total_debit_minor: int = 0
    line_count: int = 0

    @property
    def hash_hex(self) -> str:
        return self.hash.hex()


def require_transaction(conn) -> None:
    """账本追加必须在显式事务里（否则 advisory 锁等于没加）。"""
    if getattr(conn, "autocommit", False):
        raise TransactionRequired(
            "post_journal 需要显式事务：autocommit 连接无法保持 pg_advisory_xact_lock，"
            "账本 hash 链不会被串行化")


def _acquire_append_lock(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (LEDGER_APPEND_LOCK_ID,))


def _prev_hash(conn) -> bytes | None:
    with conn.cursor() as cur:
        cur.execute("SELECT hash FROM journal_entry ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
    return None if row is None else bytes(row[0])


def find_existing(conn, draft: JournalDraft) -> PostJournalResult | None:
    """按幂等键找既有凭证（INV-06）。调用方负责先拿追加锁，保证读到的是最新状态。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT j.journal_id, j.seq, j.hash,
                      (SELECT count(*) FROM journal_line l WHERE l.journal_id = j.journal_id),
                      (SELECT COALESCE(sum(l.amount_minor), 0) FROM journal_line l
                        WHERE l.journal_id = j.journal_id AND l.dc = 'D')
                 FROM journal_entry j
                WHERE j.source_type = %s AND j.source_id = %s AND j.event_seq = %s""",
            draft.key())
        row = cur.fetchone()
    if row is None:
        return None
    journal_id, seq, digest, line_count, total_debit = row
    return PostJournalResult(journal_id=str(journal_id), seq=seq, hash=bytes(digest),
                             idempotent=True, event_ids=(), total_debit_minor=int(total_debit),
                             line_count=int(line_count))


def _insert_journal(cur, norm: NormalizedJournal, journal_id: uuid.UUID, digest: bytes,
                    prev_hash: bytes | None) -> int:
    draft = norm.draft
    cur.execute(
        """INSERT INTO journal_entry
             (journal_id, ts, event_type, unit_type, source_type, source_id, event_seq,
              policy_version, fx_rate_id, approval_chain, merkle_period, reversal_of_journal,
              prev_hash, hash)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)
           RETURNING seq""",
        (str(journal_id), norm.ts, draft.event_type, draft.unit_type, draft.source_type,
         draft.source_id, int(draft.event_seq), draft.policy_version, int(draft.fx_rate_id),
         None if draft.approval_chain is None else json.dumps(dict(draft.approval_chain),
                                                             ensure_ascii=False, sort_keys=True),
         draft.merkle_period, draft.reversal_of_journal, prev_hash, digest))
    return int(cur.fetchone()[0])


def _insert_lines(cur, norm: NormalizedJournal, journal_id: uuid.UUID) -> None:
    for line_no, line in enumerate(norm.lines, start=1):
        entry_id = uuid.uuid4()
        cur.execute(
            """INSERT INTO ledger_entry
                 (entry_id, journal_id, line_no, account_id, entry_type, unit_type, dc,
                  amount_minor, qty_minor, fund_class, reverse_of, ref_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (str(entry_id), str(journal_id), line_no, line.account_id, line.entry_type,
             norm.draft.unit_type, line.dc, line.amount_minor, line.qty_minor,
             line.fund_class, line.reverse_of, norm.ref_id))
        cur.execute(
            """INSERT INTO journal_line
                 (journal_id, line_no, ledger_entry_id, account_id, coa_code, dc, amount_minor,
                  unit_scale, qty_minor, fund_class, wallet_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (str(journal_id), line_no, str(entry_id), line.account_id, line.coa_code, line.dc,
             line.amount_minor, line.unit_scale, line.qty_minor, line.fund_class, line.wallet_id))


def post_journal(conn, draft: JournalDraft, *, emit_event: bool = True,
                 apply_balances: bool = True) -> PostJournalResult:
    """校验并落账一张凭证（调用方给事务；失败由调用方回滚）。

    ``apply_balances``：默认 True —— 凭证 + 行 + 分录 + **余额** + outbox 同一事务（§6 事务边界）。
    T3 起余额由 :mod:`app.ledger.balances` 按「上一版本 + 1」写入；关闭只用于特殊回放。
    """
    require_transaction(conn)
    _acquire_append_lock(conn)

    existing = find_existing(conn, draft)
    if existing is not None:
        return existing

    norm = normalize(draft)
    prev_hash = _prev_hash(conn)
    payload = hashchain.canonical_payload(
        unit_type=norm.draft.unit_type, event_type=norm.draft.event_type,
        source_type=norm.draft.source_type, source_id=norm.draft.source_id,
        event_seq=norm.draft.event_seq, policy_version=norm.draft.policy_version,
        fx_rate_id=norm.draft.fx_rate_id, lines=norm.lines)
    digest = hashchain.journal_hash(prev_hash, payload)

    journal_id = uuid.uuid4()
    with conn.cursor() as cur:
        seq = _insert_journal(cur, norm, journal_id, digest, prev_hash)
        _insert_lines(cur, norm, journal_id)

    if apply_balances:
        balances_mod.apply_journal(conn, str(journal_id))

    event_ids: tuple[str, ...] = ()
    if emit_event:
        event = outbox.journal_posted_event(
            journal_id=str(journal_id), event_type=norm.draft.event_type,
            amount_minor=norm.total_debit_minor, ref_id=norm.ref_id, trace_id=norm.trace_id,
            correlation_id=norm.draft.correlation_id, occurred_at=norm.ts)
        event_ids = (outbox.append_event(conn, event),)

    return PostJournalResult(journal_id=str(journal_id), seq=seq, hash=digest, idempotent=False,
                             event_ids=event_ids, total_debit_minor=norm.total_debit_minor,
                             line_count=len(norm.lines))


def load_journal(conn, journal_id: str) -> dict[str, Any] | None:
    """读回一张凭证（含行）；T3 冲正与 T4 管理面共用。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT journal_id, seq, ts, event_type, unit_type, source_type, source_id,
                      event_seq, policy_version, fx_rate_id, reversal_of_journal, status,
                      prev_hash, hash, merkle_period, created_at
                 FROM journal_entry WHERE journal_id = %s""", (journal_id,))
        row = cur.fetchone()
        if row is None:
            return None
        columns = ("journal_id", "seq", "ts", "event_type", "unit_type", "source_type",
                   "source_id", "event_seq", "policy_version", "fx_rate_id",
                   "reversal_of_journal", "status", "prev_hash", "hash", "merkle_period",
                   "created_at")
        journal = {key: value for key, value in zip(columns, row)}
        journal["journal_id"] = str(journal["journal_id"])
        journal["prev_hash"] = hashchain.hash_hex(journal["prev_hash"])
        journal["hash"] = hashchain.hash_hex(journal["hash"])
        cur.execute(
            """SELECT line_no, ledger_entry_id, account_id, coa_code, dc, amount_minor,
                      unit_scale, qty_minor, fund_class, wallet_id
                 FROM journal_line WHERE journal_id = %s ORDER BY line_no""", (journal_id,))
        line_columns = ("line_no", "ledger_entry_id", "account_id", "coa_code", "dc",
                        "amount_minor", "unit_scale", "qty_minor", "fund_class", "wallet_id")
        journal["lines"] = []
        for line_row in cur.fetchall():
            line = {key: value for key, value in zip(line_columns, line_row)}
            line["ledger_entry_id"] = str(line["ledger_entry_id"])
            journal["lines"].append(line)
    return journal
