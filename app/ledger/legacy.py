# SPDX-License-Identifier: Apache-2.0
"""M06 旧路径（001 的 ledger_entries + accounts 余额）：只追加 + hash 链 + 可复算。

**位置迁移说明（DEV-M06-T2）**：本文件的内容从 ``app/ledger.py``（integration@fd5325b）
逐字搬入，行为**冻结**，不新增语义：

  · ``post_entry`` / ``recompute`` / ``entry_hash`` / ``GENESIS`` / ``PostResult`` /
    ``LEDGER_APPEND_LOCK_ID`` 是存量调用方（``app/api.py``、``app/chain/polygon.py``、
    ``app/wallet_pool.py``、``scripts/*``、``tests/test_ledger*.py``）的公开符号；
  · 新账本（journal_entry / journal_line / ledger_entry 五表，600–604）的写入走
    :mod:`app.ledger.gateway`，两条路径目前并存（M06 §20.4 迁移期口径，旧表退役在 T4 之后）；
  · 两条路径共用同一个 ``LEDGER_APPEND_LOCK_ID``：同一库内账本追加保持一个全序，
    避免「各持一把锁、互相看不见」造成链分叉（BUG-0002 的口径继续有效）。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

GENESIS = "GENESIS"

# 账本追加的全局串行化 key（pg_advisory_xact_lock 的 key 空间按「每个数据库」划分，
# 同一库内同一个 bigint 就是同一把锁）：
#   · 本模块的 post_entry 与 app/chain/polygon.py::_append_entry 必须抢**同一把锁**，
#     否则两条写入路径互相看不见，hash 链仍可能分叉（BUG-0002）；
#   · polygon 侧的私有常量 ``_LEDGER_APPEND_LOCK`` 必须与本值相等，由
#     tests/test_ledger_concurrency.py 断言，防止两边各自漂移。
LEDGER_APPEND_LOCK_ID = 4_442_002


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


def _serialize_append(c) -> None:
    """在「读 prev_hash → INSERT」之前拿事务级 advisory lock，直到事务结束才释放。

    必须是显式事务：autocommit 连接会让 ``pg_advisory_xact_lock`` 在语句结束即释放，
    等于没加锁；这种情况直接报错，不做静默降级（否则等于把 BUG-0002 藏起来）。
    """
    if getattr(c, "autocommit", False):
        raise RuntimeError(
            "post_entry 需要显式事务：autocommit 连接无法保持 pg_advisory_xact_lock，"
            "账本 hash 链不会被串行化")
    with c.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (LEDGER_APPEND_LOCK_ID,))


def post_entry(c, debit: str, credit: str, amount_micro: int, memo: str | None = None,
               receipt_id: str | None = None) -> PostResult:
    """写一条分录：链上接前一条；同时更新余额。只允许 INSERT。

    并发安全：先拿 ``pg_advisory_xact_lock(LEDGER_APPEND_LOCK_ID)`` 再读 prev_hash，
    让「读前一条 hash → 插入」在同一把锁下串行，避免两个事务读到同一个 prev 造成链分叉。
    """
    if amount_micro <= 0:
        raise ValueError("amount_micro must be > 0")
    _serialize_append(c)
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
