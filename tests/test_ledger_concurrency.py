# SPDX-License-Identifier: AGPL-3.0-or-later
"""BUG-0002：`ledger.post_entry` 并发写入不得让 hash 链分叉。

修复口径：`post_entry` 在「读 prev_hash → INSERT」之前拿事务级
`pg_advisory_xact_lock(LEDGER_APPEND_LOCK_ID)`，与 `app/chain/polygon.py` 的追加路径
抢同一把锁。本文件验证：

1. N 线程并发 post_entry 后，`recompute` 的 `chain_bad=[]`、`diff=0`、余额守恒；
2. 锁 id 与 chain 路径一致（防两条写入路径各自漂移成两把锁）；
3. 锁真的互斥：持锁事务未提交时，第二个写入方会被 lock_timeout 挡住；
4. autocommit 连接被明确拒绝（否则 advisory 锁等于没加）；
5. 对照说明：把旧实现（无锁，读同一 prev 后插入）放进 savepoint 确定性复现，
   `recompute` 必然报 `chain_bad`；随后 ROLLBACK TO SAVEPOINT，不留脏数据。
   —— 不靠"故意让并发测试失败"当证据。

DB：`DJB_DSN` 指向开发库（127.0.0.1:5433）；无库则整文件 skip。
"""
import os
import threading
import uuid

import psycopg
import pytest
from psycopg import sql

os.environ.setdefault("DJB_DSN", "postgresql:///djb_dev")  # 真值从环境注入，测试文件不含凭据

from app import db  # noqa: E402
from app import ledger  # noqa: E402
from app.chain import polygon  # noqa: E402
from app.config import dsn  # noqa: E402
from app.ledger import post_entry, recompute  # noqa: E402

THREADS = 6
PER_THREAD = 3


# --------------------------------------------------------------------------- 工具
def _count(c, sql: str, args=()) -> int:
    with c.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchone()[0]


def _balances(c) -> dict:
    with c.cursor() as cur:
        cur.execute("SELECT id, balance_micro FROM accounts")
        return dict(cur.fetchall())


def _make_accounts(tag: str, n: int) -> list[str]:
    ids = [f"acct:conc-{tag}-{i}" for i in range(n)]
    with db.conn() as c, c.cursor() as cur:
        cur.executemany(
            "INSERT INTO accounts (id, kind) VALUES (%s, 'user') ON CONFLICT (id) DO NOTHING",
            [(i,) for i in ids])
    return ids


def _post_with_lock_timeout(debit: str, credit: str, amount: int, memo: str, timeout_ms: int = 400):
    """另一个连接：设 lock_timeout 后尝试追加（应被持锁方挡住）。"""
    # SET 不支持占位符参数，用 sql.Literal 拼（值来自本函数的 int，仍走类型化拼装）
    stmt = sql.SQL("SET LOCAL lock_timeout = {}").format(sql.Literal(f"{int(timeout_ms)}ms"))
    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute(stmt)
        return post_entry(c, debit, credit, amount, memo=memo)


# --------------------------------------------------------------------------- 1 并发不折链
def test_concurrent_post_entry_keeps_hash_chain_linear():
    tag = uuid.uuid4().hex[:8]
    accts = _make_accounts(tag, THREADS * 2)

    with db.conn() as c:
        entries_before = _count(c, "SELECT count(*) FROM ledger_entries")
        report_before = recompute(c)
        balances_before = _balances(c)
    assert report_before["diff"] == 0, report_before        # 迁移/改动前基线：diff=0

    barrier = threading.Barrier(THREADS)
    errors: list[BaseException] = []
    produced: dict[int, int] = {}

    def worker(i: int) -> None:
        debit, credit = accts[2 * i], accts[2 * i + 1]
        total = 0
        try:
            barrier.wait(timeout=30)                        # 尽量同时开抢，放大争用
            with db.conn() as c:
                for k in range(PER_THREAD):
                    amount = 1_000 + i * 10 + k
                    post_entry(c, debit, credit, amount, memo=f"conc-{tag}-{i}-{k}")
                    total += amount
        except BaseException as exc:                        # noqa: BLE001 - 线程内异常带回主线程断言
            errors.append(exc)
        produced[i] = total

    threads = [threading.Thread(target=worker, args=(i,), name=f"w{i}") for i in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not any(t.is_alive() for t in threads), "并发线程未在超时内结束"
    assert errors == [], errors

    with db.conn() as c:
        report_after = recompute(c)
        entries_after = _count(c, "SELECT count(*) FROM ledger_entries")
        balances_after = _balances(c)

    # hash 链必须线性、余额必须与分录一致
    assert report_after["chain_bad"] == []
    assert report_after["balance_bad"] == {}
    assert report_after["diff"] == 0, report_after
    assert entries_after - entries_before == THREADS * PER_THREAD
    assert report_after["entries"] == entries_after

    # 余额守恒：双分录记账下全库 Σbalance 恒为 0；每对账户净额与写入金额一致
    assert sum(balances_after.values()) == 0
    for i in range(THREADS):
        assert balances_after[accts[2 * i]] == -produced[i]
        assert balances_after[accts[2 * i + 1]] == produced[i]
    # 除本次涉及的账户外，其余账户余额未被并发写入破坏
    untouched = {k: v for k, v in balances_before.items() if k not in accts}
    assert {k: balances_after[k] for k in untouched} == untouched


# --------------------------------------------------------------------------- 2 同一把锁
def test_lock_id_is_shared_with_chain_ingest_path():
    assert ledger.LEDGER_APPEND_LOCK_ID == polygon._LEDGER_APPEND_LOCK == 4_442_002


# --------------------------------------------------------------------------- 3 锁真互斥
def test_append_lock_blocks_second_writer_until_commit():
    tag = uuid.uuid4().hex[:8]
    a, b = _make_accounts(tag, 2)

    with db.conn() as holder:
        post_entry(holder, a, b, 100, memo=f"hold-{tag}")   # 事务级锁持有到 commit
        with pytest.raises(psycopg.errors.LockNotAvailable):
            _post_with_lock_timeout(a, b, 200, f"blocked-{tag}")
        # 持锁方仍可继续追加（advisory 锁对同一事务可重入）
        post_entry(holder, a, b, 300, memo=f"hold2-{tag}")

    # 持锁事务提交后，被挡住的写入可以正常完成
    with db.conn() as c:
        post_entry(c, a, b, 200, memo=f"after-{tag}")
        report = recompute(c)
    assert report["chain_bad"] == [] and report["diff"] == 0


# --------------------------------------------------------------------------- 4 autocommit 必须被拒
def test_autocommit_connection_is_rejected_instead_of_locking_silently():
    with psycopg.connect(dsn(), autocommit=True) as c:
        with pytest.raises(RuntimeError, match="显式事务"):
            post_entry(c, "acct:conc-autocommit-a", "acct:conc-autocommit-b", 1, memo="autocommit")


# --------------------------------------------------------------------------- 5 对照：无锁会分叉
def test_control_unlocked_append_would_fork_and_recompute_catches_it():
    """确定性对照：旧实现（无锁）两次读到同一个 prev 再插入 → 链分叉。

    全程在 SAVEPOINT 内完成并回滚，不向共享开发库留下任何脏数据；
    这里只证明「recompute 能检出分叉」，不用并发竞态去赌。
    """
    tag = uuid.uuid4().hex[:8]
    a, b = _make_accounts(tag, 2)

    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT hash FROM ledger_entries ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
            prev = row[0] if row else None

            cur.execute("SAVEPOINT fork_demo")
            # 旧实现：两个"并发"写入都读到同一个 prev，各自算出自己的 hash
            for idx, amount in enumerate((111, 222), start=1):
                fork_hash = ledger.entry_hash(prev, a, b, amount, f"fork{idx}-{tag}")
                cur.execute(
                    """INSERT INTO ledger_entries (debit, credit, amount_micro, memo, prev_hash, hash)
                       VALUES (%s,%s,%s,%s,%s,%s)""",
                    (a, b, amount, f"fork{idx}-{tag}", prev, fork_hash))

            forked = recompute(c)
            assert forked["chain_bad"], "无锁重复 prev 必须被 recompute 检出（否则证据无效）"

            cur.execute("ROLLBACK TO SAVEPOINT fork_demo")
        clean = recompute(c)
        assert clean["chain_bad"] == []
        assert clean["diff"] == 0

    # 事务外再确认：没有任何残留行
    with db.conn() as c:
        assert _count(c, "SELECT count(*) FROM ledger_entries WHERE memo LIKE %s", (f"fork%{tag}",)) == 0
        assert recompute(c)["diff"] == 0
