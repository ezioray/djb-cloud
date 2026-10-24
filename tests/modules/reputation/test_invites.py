# SPDX-License-Identifier: AGPL-3.0-or-later
"""单层邀请测试（INV-03 / INV-04 / §6.2）：一层、唯一、自邀、同簇、过期、状态机、概览。

任务卡验收 3：「邀请一层 + ``(inviter, invitee)`` 唯一」。
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.reputation import errors, invites
from repukit import NOW, count, seed_account_on


def _issue(conn, inviter, **kwargs):
    return invites.issue(conn, inviter, now=NOW, **kwargs)


def test_issue_and_list_pending(conn):
    inviter = seed_account_on(conn)
    invite = _issue(conn, inviter)
    assert invite.status == "sent" and invite.invitee_id is None
    assert len(invite.code) == invites.CODE_LENGTH

    overview = invites.list_overview(conn, inviter)
    assert overview.pending == 1 and overview.bound == 0
    assert overview.earned_units == 0
    assert overview.as_dict()["totals"] == {"bound": 0, "pending": 1, "earned_units": 0}
    assert overview.as_dict()["page"]["has_more"] is False


def test_issue_rejects_non_future_expiry(conn):
    inviter = seed_account_on(conn)
    with pytest.raises(errors.InvalidArgument):
        invites.issue(conn, inviter, expire_at=NOW - timedelta(days=1), now=NOW)


def test_bind_marks_bound_and_emits_event(conn):
    inviter = seed_account_on(conn)
    invitee = seed_account_on(conn)
    invite = _issue(conn, inviter)
    bound = invites.bind(conn, invite.code, invitee, now=NOW)
    assert bound.status == "bound" and bound.invitee_id == invitee
    assert bound.bound_at is not None

    overview = invites.list_overview(conn, inviter)
    assert overview.bound == 1 and overview.pending == 0
    assert invites.bound_invite_of(conn, invitee) is not None


def test_self_invite_is_rejected(conn):
    inviter = seed_account_on(conn)
    invite = _issue(conn, inviter)
    with pytest.raises(errors.ValidationFailed) as info:
        invites.bind(conn, invite.code, inviter, now=NOW)
    assert (info.value.status_code, info.value.code) == (422, "42240")
    assert info.value.reason == "self_invite"


def test_rebinding_is_conflict(conn):
    inviter = seed_account_on(conn)
    first, second = seed_account_on(conn), seed_account_on(conn)
    invite = _issue(conn, inviter)
    invites.bind(conn, invite.code, first, now=NOW)
    with pytest.raises(errors.InviteStateConflict) as info:
        invites.bind(conn, invite.code, second, now=NOW)
    assert (info.value.status_code, info.value.code) == (409, "40902")


def test_expired_invite_cannot_be_bound(conn):
    inviter = seed_account_on(conn)
    invitee = seed_account_on(conn)
    invite = invites.issue(conn, inviter, expire_at=NOW + timedelta(days=1), now=NOW)
    with pytest.raises(errors.InviteStateConflict) as info:
        invites.bind(conn, invite.code, invitee, now=NOW + timedelta(days=2))
    assert info.value.reason == "invite_expired"


def test_unknown_code_is_not_found(conn):
    with pytest.raises(errors.NotFound) as info:
        invites.bind(conn, "NOPE123456", seed_account_on(conn), now=NOW)
    assert (info.value.status_code, info.value.code) == (404, "40401")


def test_same_device_cluster_is_rejected(conn):
    inviter = seed_account_on(conn, device_cluster="dev-cluster-1")
    invitee = seed_account_on(conn, device_cluster="dev-cluster-1")
    invite = _issue(conn, inviter)
    with pytest.raises(errors.ValidationFailed) as info:
        invites.bind(conn, invite.code, invitee, now=NOW)
    assert info.value.reason == "same_device_cluster"


def test_same_payment_cluster_is_rejected(conn):
    inviter = seed_account_on(conn, payment_cluster="pm-cluster-1")
    invitee = seed_account_on(conn, payment_cluster="pm-cluster-1")
    invite = _issue(conn, inviter)
    with pytest.raises(errors.ValidationFailed) as info:
        invites.bind(conn, invite.code, invitee, now=NOW)
    assert info.value.reason == "same_payment_cluster"


def test_second_layer_inviter_is_rejected(conn):
    """INV-03：邀请人自己已经有上级 → 它不能再作为邀请人绑定新被邀请人。"""
    top = seed_account_on(conn)
    middle = seed_account_on(conn)
    leaf = seed_account_on(conn)
    first = _issue(conn, top)
    invites.bind(conn, first.code, middle, now=NOW)          # middle 成为被邀请人
    second = _issue(conn, middle)                            # middle 想再邀请别人
    with pytest.raises(errors.InviteStateConflict) as info:
        invites.bind(conn, second.code, leaf, now=NOW)
    assert (info.value.status_code, info.value.code) == (409, "40902")
    assert info.value.reason == "invite_layer"


def test_existing_inviter_cannot_become_invitee(conn):
    """INV-03 的另一半：已经邀请过别人的账户，不能再被绑成别人的被邀请人。"""
    inviter = seed_account_on(conn)
    other = seed_account_on(conn)
    former = seed_account_on(conn)
    _issue(conn, inviter)                                    # inviter 已是邀请人
    second = _issue(conn, other)
    with pytest.raises(errors.ValidationFailed) as info:
        invites.bind(conn, second.code, inviter, now=NOW)
    assert (info.value.status_code, info.value.code) == (422, "42240")
    assert info.value.reason == "invite_layer"
    assert count(conn, "invites", "status = 'bound'") == 0


def test_revoke_and_expire_jobs(conn):
    inviter = seed_account_on(conn)
    invitee = seed_account_on(conn)
    bound = invites.bind(conn, _issue(conn, inviter).code, invitee, now=NOW)
    revoked = invites.revoke(conn, bound.id)
    assert revoked.status == "revoked"
    with pytest.raises(errors.InviteStateConflict):
        invites.revoke(conn, bound.id)                        # 只能撤销 bound

    stale = invites.issue(conn, inviter, expire_at=NOW + timedelta(hours=1), now=NOW)
    expired = invites.expire_due(conn, now=NOW + timedelta(days=1))
    assert str(stale.id) in expired
    assert invites.expire_due(conn, now=NOW + timedelta(days=1)) == []   # 幂等


def test_overview_reports_earned_units_within_window(conn):
    """概览里的累计奖励来自 COP 台账 ``source=invite``（同一账本，不另记一份）。"""
    from app.reputation import cop

    inviter = seed_account_on(conn)
    invitee = seed_account_on(conn)
    invites.bind(conn, _issue(conn, inviter).code, invitee, now=NOW)
    cop.post_earn(conn, inviter, 250, source="invite", ref_id="usage-earn-1",
                  request_id="req-earn-1", now=NOW)
    overview = invites.list_overview(conn, inviter)
    assert overview.earned_units == 250
    assert overview.items[0].earned_units == 250


def test_overview_pagination(conn):
    inviter = seed_account_on(conn)
    for _ in range(3):
        _issue(conn, inviter)
    first = invites.list_overview(conn, inviter, limit=2)
    assert len(first.items) == 2 and first.next_cursor
    second = invites.list_overview(conn, inviter, limit=2, cursor=first.next_cursor)
    assert len(second.items) == 1 and second.next_cursor is None


def test_duplicate_code_is_rejected(conn):
    inviter = seed_account_on(conn)
    code = "FIXEDCODE01"
    _issue(conn, inviter, code=code)
    with pytest.raises(Exception) as info:                    # 唯一索引兜底（IntegrityError）
        _issue(conn, seed_account_on(conn), code=code)
    assert "unique" in str(info.value).lower() or "duplicate" in str(info.value).lower()
