# SPDX-License-Identifier: AGPL-3.0-or-later
"""人工授予 / 扣回测试（§4.1 / CR-5 / §7）：双人复核、理由必填、404、幂等、扣回不透支。

step-up（424 / 42401）在路由层判定，见 ``test_router.py``；本文件测领域层。
"""
from __future__ import annotations

import pytest

from app import points
from app.reputation import cop, errors, grants
from repukit import NOW, count, seed_account_on


def _grant(conn, account, **overrides):
    payload = {"account_id": account, "kind": "grant", "units": 100, "reason": "运营补发",
               "actor": "admin:alice", "approved_by": "admin:bob", "now": NOW}
    payload.update(overrides)
    return grants.create(conn, **payload)


def test_grant_writes_ledger_and_voucher(conn):
    account = seed_account_on(conn)
    grant = _grant(conn, account)
    assert grant.kind == "grant" and grant.units == 100
    assert grant.approved_by == "admin:bob"
    assert cop.balance(conn, account, now=NOW).available == 100
    assert count(conn, "reward_grants", "account_id = %s", (account,)) == 1

    # 账本侧：一条 adjust 分录，approval 记录在 points_journal.approved_by
    with conn.cursor() as cur:
        cur.execute("""SELECT action, units, approved_by, actor, ref_id FROM points_journal
                        WHERE account_id = %s AND action = 'adjust'""", (account,))
        action, units, approved_by, actor, ref_id = cur.fetchone()
    assert (action, int(units), approved_by, actor) == ("adjust", 100, "admin:bob", "admin:alice")
    assert ref_id == str(grant.id)


def test_grant_rejects_self_approval(conn):
    account = seed_account_on(conn)
    with pytest.raises(errors.ReviewerConflict) as info:
        _grant(conn, account, approved_by="admin:alice")
    assert (info.value.status_code, info.value.code) == (409, "40919")
    assert info.value.reason == "approver_is_actor"


def test_grant_requires_approver(conn):
    account = seed_account_on(conn)
    with pytest.raises(errors.ReviewerConflict) as info:
        _grant(conn, account, approved_by=None)
    assert info.value.code == "40919"


def test_grant_requires_reason_and_valid_kind(conn):
    account = seed_account_on(conn)
    for bad in ({"reason": ""}, {"reason": "   "}, {"reason": None}, {"reason": "x" * 513}):
        with pytest.raises(errors.InvalidArgument) as info:
            _grant(conn, account, **bad)
        assert (info.value.status_code, info.value.code) == (400, "40001")
    with pytest.raises(errors.InvalidArgument):
        _grant(conn, account, kind="magic")
    for bad_units in (0, -1, "x", 10 ** 9):
        with pytest.raises(errors.InvalidArgument):
            _grant(conn, account, units=bad_units)


def test_grant_unknown_account_is_404(conn):
    with pytest.raises(errors.NotFound) as info:
        _grant(conn, "user:does-not-exist")
    assert (info.value.status_code, info.value.code) == (404, "40401")
    assert count(conn, "reward_grants") == 0


def test_grant_is_idempotent(conn):
    account = seed_account_on(conn)
    first = _grant(conn, account, request_id="idem-grant-1")
    again = _grant(conn, account, request_id="idem-grant-1")
    assert again.id == first.id
    assert count(conn, "reward_grants") == 1
    assert cop.balance(conn, account, now=NOW).available == 100


def test_grant_idempotency_conflict_on_different_payload(conn):
    account = seed_account_on(conn)
    _grant(conn, account, request_id="idem-grant-2", units=100)
    with pytest.raises(errors.Conflict) as info:
        _grant(conn, account, request_id="idem-grant-2", units=999)
    assert info.value.reason == "idempotency_conflict"


def test_clawback_cannot_overdraw(conn):
    """INV-01：扣回不得把可用量扣成负数（余额不足 → 402 / 40201）。"""
    account = seed_account_on(conn)
    _grant(conn, account, units=100)
    with pytest.raises(errors.InsufficientBalance) as info:
        _grant(conn, account, kind="clawback", units=150, reason="违规扣回")
    assert (info.value.status_code, info.value.code) == (402, "40201")
    assert cop.balance(conn, account, now=NOW).available == 100


def test_clawback_posts_negative_adjust(conn):
    account = seed_account_on(conn)
    _grant(conn, account, units=200)
    clawback = _grant(conn, account, kind="clawback", units=80, reason="违规扣回")
    assert clawback.kind == "clawback"
    assert cop.balance(conn, account, now=NOW).available == 120
    with conn.cursor() as cur:
        cur.execute("""SELECT units FROM points_journal
                        WHERE account_id = %s AND action = 'adjust' AND approved_by IS NOT NULL
                          AND ref_id = %s""", (account, str(clawback.id)))
        assert int(cur.fetchone()[0]) == 80
    # 复算口径：账本仍然平衡、无负余额
    assert points.recompute(conn)["diff"] == 0


def test_grants_emit_cop_events(conn):
    account = seed_account_on(conn)
    grant = _grant(conn, account, units=70)
    _grant(conn, account, kind="clawback", units=20, reason="扣回")
    with conn.cursor() as cur:
        cur.execute("""SELECT type, payload->>'source' FROM reputation_outbox
                        ORDER BY created_at""")
        rows = cur.fetchall()
    assert ("cop.earned", "reward") in rows
    assert ("cop.spent", "revoke") in rows
    # 事件 payload 只放事实（不含阈值 / PII）
    with conn.cursor() as cur:
        cur.execute("SELECT payload FROM reputation_outbox WHERE type = 'cop.earned' LIMIT 1")
        payload = cur.fetchone()[0]
    assert payload["ref_id"] == str(grant.id)
    assert set(payload) <= {"account_id", "amount", "source", "ref_id", "lock_until",
                            "journal_id"}


def test_list_grants(conn):
    account = seed_account_on(conn)
    _grant(conn, account, units=10)
    _grant(conn, account, units=20)
    rows = grants.list_grants(conn, account)
    assert len(rows) == 2
    assert {row.units for row in rows} == {10, 20}
