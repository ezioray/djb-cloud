# SPDX-License-Identifier: AGPL-3.0-or-later
"""旧调用回归：``app.ledger`` 的旧符号与行为不得因拆包而改变。

覆盖 T2 任务卡第 2 条（app/ledger.py 兼容 shim）与验收「旧 tests/test_ledger.py、
tests/test_ledger_concurrency.py 通过」的同一批契约：
  · 旧符号可从 app.ledger（包）与 app/ledger.py（文件）两处拿到，且是同一份实现；
  · post_entry / recompute / entry_hash 行为不变（链 + 余额 + 只追加）；
  · app.api / app.chain.polygon / app.points / app.wallet_pool 仍能 import；
  · polygon 的私有锁常量与包常量仍然相等（BUG-0002 口径）。
"""
from __future__ import annotations

import importlib.util
import pathlib
import uuid

import pytest

import app.ledger as pkg
from app.ledger import legacy

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


# ─────────────────────────────────────────────────────── 符号面
def test_legacy_symbols_are_reexported_from_package() -> None:
    for name in ("GENESIS", "LEDGER_APPEND_LOCK_ID", "PostResult", "entry_hash", "post_entry", "recompute"):
        assert hasattr(pkg, name), f"app.ledger 缺旧符号 {name}"
    assert pkg.post_entry is legacy.post_entry
    assert pkg.recompute is legacy.recompute
    assert pkg.entry_hash is legacy.entry_hash
    assert pkg.PostResult is legacy.PostResult
    assert pkg.GENESIS == "GENESIS" == legacy.GENESIS
    assert pkg.LEDGER_APPEND_LOCK_ID == legacy.LEDGER_APPEND_LOCK_ID


def test_shim_file_exports_the_same_implementation() -> None:
    """按文件路径加载 app/ledger.py（同名包会遮蔽它，但 shim 本身必须可用）。"""
    path = REPO_ROOT / "app" / "ledger.py"
    assert path.exists(), "兼容 shim 文件被删了"
    spec = importlib.util.spec_from_file_location("app_ledger_shim_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.post_entry is legacy.post_entry
    assert module.recompute is legacy.recompute
    assert module.entry_hash is legacy.entry_hash
    assert module.LEDGER_APPEND_LOCK_ID == legacy.LEDGER_APPEND_LOCK_ID
    assert set(module.__all__) == {"GENESIS", "LEDGER_APPEND_LOCK_ID", "PostResult",
                                   "entry_hash", "post_entry", "recompute"}


def test_consumers_import_without_change() -> None:
    """旧调用方（API / 链上 / 积分 / 钱包池）仍可 import —— 拆包没有破调用面。"""
    import app.api          # noqa: F401
    import app.chain.polygon  # noqa: F401
    import app.points       # noqa: F401
    import app.wallet_pool  # noqa: F401


def test_append_lock_id_is_shared_with_chain_ingest() -> None:
    from app.chain import polygon
    assert pkg.LEDGER_APPEND_LOCK_ID == polygon._LEDGER_APPEND_LOCK == 4_442_002


# ─────────────────────────────────────────────────────── 旧路径行为
def test_legacy_post_entry_and_recompute_still_agree(migrated: str) -> None:
    from ledgerkit import connect, tx

    tag = uuid.uuid4().hex[:8]
    debit, credit = f"user:shim-{tag}", f"node:shim-{tag}"
    with tx(migrated) as c:
        with c.cursor() as cur:
            cur.execute("INSERT INTO accounts (id,kind) VALUES (%s,'user'),(%s,'node') "
                        "ON CONFLICT DO NOTHING", (debit, credit))
        first = pkg.post_entry(c, debit, credit, 1000, memo=f"shim-1-{tag}")
        second = pkg.post_entry(c, debit, credit, 2500, memo=f"shim-2-{tag}")

    assert isinstance(first, pkg.PostResult) and isinstance(second, pkg.PostResult)
    assert first.seq < second.seq and len(first.hash) == 64

    with connect(migrated) as c:
        report = pkg.recompute(c)
    assert report["chain_bad"] == [] and report["balance_bad"] == {}
    assert report["diff"] == 0, report


def test_legacy_entry_hash_is_unchanged() -> None:
    """哈希口径冻结：旧链的历史 hash 必须还能复算（改一行就会让历史对不上）。"""
    assert pkg.entry_hash(None, "a", "b", 1, "m") == legacy.entry_hash(None, "a", "b", 1, "m")
    assert len(pkg.entry_hash(None, "a", "b", 1, "m")) == 64
    assert pkg.entry_hash(None, "a", "b", 1, "m") != pkg.entry_hash(None, "a", "b", 2, "m")


def test_legacy_tables_stay_append_only(migrated: str) -> None:
    from ledgerkit import assert_db_error, tx

    tag = uuid.uuid4().hex[:8]
    with tx(migrated) as c:
        with c.cursor() as cur:
            cur.execute("INSERT INTO accounts (id,kind) VALUES (%s,'user'),(%s,'node') "
                        "ON CONFLICT DO NOTHING", (f"user:ro-{tag}", f"node:ro-{tag}"))
        pkg.post_entry(c, f"user:ro-{tag}", f"node:ro-{tag}", 7, memo=f"ro-{tag}")

    assert_db_error(migrated, "append-only",
                    lambda c: c.cursor().execute(
                        "UPDATE ledger_entries SET amount_micro = amount_micro + 1 WHERE memo = %s",
                        (f"ro-{tag}",)))


def test_legacy_rejects_autocommit(migrated: str) -> None:
    from ledgerkit import connect
    conn = connect(migrated, autocommit=True)
    try:
        with pytest.raises(RuntimeError, match="显式事务"):
            pkg.post_entry(conn, "a", "b", 1, memo="autocommit")
    finally:
        conn.close()
