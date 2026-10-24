# SPDX-License-Identifier: AGPL-3.0-or-later
"""Merkle 期间根验收（INV-13 / spec 1.2.1 MerkleCommitment）：根可复现、写入即发布、根不可改。

根算法：叶子 = 凭证 hash；内部节点 = sha256(0x01‖left‖right)；奇数节点上提；空期间有定义好的空根。
"""
from __future__ import annotations

import hashlib

import pytest

from app.ledger import merkle
from app.ledger.constants import MERKLE_KINDS_OWNED

from ledger_gatewaykit import e2_draft, e6_draft, outbox_rows, post_ok
from ledgerkit import connect

EMPTY_ROOT = hashlib.sha256(b"M06:MERKLE:EMPTY").hexdigest()


def _period(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H")


def _post_in_period(migrated: str, count: int = 2) -> str:
    """在同一小时桶里落 count 张凭证，返回该期间字符串。"""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    for index in range(count):
        post_ok(migrated, e6_draft(amount_minor=100 + index, ts=now,
                                   source_id=f"merkle-{now.isoformat()}-{index}"))
    return _period(now)


# ─────────────────────────────────────────────────────── 纯函数：根
def test_root_is_deterministic_and_order_sensitive() -> None:
    a, b, c = b"a" * 32, b"b" * 32, b"c" * 32
    assert merkle.merkle_root([a, b, c]) == merkle.merkle_root([a, b, c])
    assert merkle.merkle_root([a, b]) != merkle.merkle_root([b, a])
    assert len(merkle.merkle_root([a])) == 32


def test_odd_node_is_promoted_not_duplicated() -> None:
    """奇数节点上提（不复制自己）：[a,b,c] 与 [a,b,c,c] 必须不同根（防 CVE-2012-2459 式歧义）。"""
    a, b, c = b"a" * 32, b"b" * 32, b"c" * 32
    assert merkle.merkle_root([a, b, c]) != merkle.merkle_root([a, b, c, c])


def test_empty_period_has_defined_root() -> None:
    assert merkle.merkle_root([]).hex() == EMPTY_ROOT


@pytest.mark.parametrize("bad", ["2026/10", "2026-10-2", "26-10", "2026-10-23T1"])
def test_period_shape_is_enforced(bad: str) -> None:
    with pytest.raises(merkle.MerkleError):
        merkle.period_format(bad)


# ─────────────────────────────────────────────────────── 真库：计算 → 锚定 → 读回
def test_anchor_publishes_root_and_emits_event(migrated: str) -> None:
    period = _post_in_period(migrated, count=3)
    with connect(migrated) as c:
        computed = merkle.compute(c, kind="journal", period=period)
        assert computed["entry_count"] == 3
        result = merkle.anchor(c, kind="journal", period=period)
        record = merkle.get(c, kind="journal", period=period)
        events = outbox_rows(migrated, aggregate_id=f"journal:{period}")

    assert result["created"] is True and len(result["event_ids"]) == 1
    assert record["root"] == computed["root"] == result["root"]
    assert record["entry_count"] == 3
    assert record["reproducible"] is True
    assert record["verify_hint"].startswith("POST /api/v1/admin/ledger/recompute")
    assert [event["type"] for event in events] == ["merkle.anchored"]
    assert events[0]["payload"]["root"] == computed["root"]
    assert events[0]["payload"]["kind"] == "journal"


def test_anchor_is_idempotent_for_same_root(migrated: str) -> None:
    period = _post_in_period(migrated, count=1)
    with connect(migrated) as c:
        first = merkle.anchor(c, kind="daily_close", period=period[:10])
        second = merkle.anchor(c, kind="daily_close", period=period[:10])
    assert first["created"] is True and second["created"] is False
    assert first["root"] == second["root"] and second["event_ids"] == ()
    rows = outbox_rows(migrated, aggregate_id=f"daily_close:{period[:10]}")
    assert len(rows) == 1                                   # 事件也只发一次


def test_published_root_cannot_change(migrated: str) -> None:
    """发布后再落一张同期间凭证 → 重算根变化 → 锚定拒绝（40920），旧根不变。"""
    period = _post_in_period(migrated, count=1)
    with connect(migrated) as c:
        published = merkle.anchor(c, kind="journal", period=period)
    post_ok(migrated, e6_draft(amount_minor=7, ts=_parse(period), source_id="late-1"))
    with connect(migrated) as c:
        with pytest.raises(merkle.MerklePublishedImmutable) as ei:
            merkle.anchor(c, kind="journal", period=period)
        record = merkle.get(c, kind="journal", period=period)
    assert ei.value.code == "40920"
    assert record["root"] == published["root"]               # 发布后不可改
    assert record["reproducible"] is False                   # 重算不一致 → P0 信号
    assert record["recomputed_root"] != record["root"]


def test_kind_is_limited_to_m06_roots(migrated: str) -> None:
    with connect(migrated) as c:
        for kind in ("audit", "por"):
            with pytest.raises(merkle.MerkleError):
                merkle.compute(c, kind=kind, period="2026-10")
            with pytest.raises(merkle.MerkleError):
                merkle.get(c, kind=kind, period="2026-10")
    assert set(MERKLE_KINDS_OWNED) == {"journal", "daily_close"}


def test_missing_commitment_returns_none(migrated: str) -> None:
    with connect(migrated) as c:
        assert merkle.get(c, kind="journal", period="2000-01-01T00") is None
        assert merkle.verify_commitment(c, kind="journal", period="2000-01-01T00") is False


def test_empty_period_can_be_anchored(migrated: str) -> None:
    with connect(migrated) as c:
        result = merkle.anchor(c, kind="journal", period="2001-02-03T04")
        record = merkle.get(c, kind="journal", period="2001-02-03T04")
    assert result["entry_count"] == 0 and record["root"] == EMPTY_ROOT
    assert record["reproducible"] is True


def test_merkle_period_column_overrides_ts_bucket(migrated: str) -> None:
    """凭证可显式声明 merkle_period（T1 的列）：优先于按 ts 落桶。"""
    from ledger_gatewaykit import e6_draft as draft
    post_ok(migrated, draft(amount_minor=11, source_id="explicit-1", merkle_period="2030-05"))
    with connect(migrated) as c:
        by_column = merkle.compute(c, kind="journal", period="2030-05")
    assert by_column["entry_count"] == 1


def _parse(period: str):
    from datetime import datetime, timezone
    fmt = "%Y-%m-%dT%H" if len(period) == 13 else "%Y-%m-%d"
    return datetime.strptime(period, fmt).replace(tzinfo=timezone.utc)
