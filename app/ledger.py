# SPDX-License-Identifier: Apache-2.0
"""账本核心：只追加 + hash 链 + 可复算（对应设计文档 §4.3）"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

GENESIS = "GENESIS"


def entry_hash(prev_hash: str | None, debit: str, credit: str, amount_micro: int, memo: str | None) -> str:
    payload = json.dumps(
        {"prev": prev_hash or GENESIS, "debit": debit, "credit": credit,
         "amount_micro": amount_micro, "memo": memo},
        ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class PostResult:
    seq: int
    hash: str


def post_entry(c, debit: str, credit: str, amount_micro: int, memo: str | None = None,
               receipt_id: str | None = None) -> PostResult:
    """写一条分录：链上接前一条；同时更新余额。只允许 INSERT。"""
    if amount_micro <= 0:
        raise ValueError("amount_micro must be > 0")
    with c.cursor() as cur:
        cur.execute("SELECT hash FROM ledger_entries ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        prev = row[0] if row else None
        h = entry_hash(prev, debit, credit, amount_micro, memo)
        cur.execute(
            """INSERT INTO ledger_entries (receipt_id, debit, credit, amount_micro, memo, prev_hash, hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING seq""",
            (receipt_id, debit, credit, amount_micro, memo, prev, h),
        )
        seq = cur.fetchone()[0]
        cur.execute("UPDATE accounts SET balance_micro = balance_micro - %s WHERE id = %s", (amount_micro, debit))
        cur.execute("UPDATE accounts SET balance_micro = balance_micro + %s WHERE id = %s", (amount_micro, credit))
    return PostResult(seq=seq, hash=h)


def recompute(c) -> dict:
    """重算 hash 链与余额，返回差异（必须为 0）。"""
    with c.cursor() as cur:
        cur.execute("SELECT seq, debit, credit, amount_micro, memo, prev_hash, hash FROM ledger_entries ORDER BY seq")
        rows = cur.fetchall()
        prev = None
        chain_bad = []
        total = {}
        for seq, debit, credit, amt, memo, prev_hash, h in rows:
            if entry_hash(prev, debit, credit, amt, memo) != h:
                chain_bad.append(seq)
            if (prev_hash or None) != prev:
                chain_bad.append(seq)
            prev = h
            total[debit] = total.get(debit, 0) - amt
            total[credit] = total.get(credit, 0) + amt
        cur.execute("SELECT id, balance_micro FROM accounts")
        stored = dict(cur.fetchall())
    balance_bad = {a: (stored.get(a), v) for a, v in total.items() if stored.get(a) != v}
    return {"entries": len(rows), "chain_bad": chain_bad, "balance_bad": balance_bad,
            "diff": len(chain_bad) + len(balance_bad)}
