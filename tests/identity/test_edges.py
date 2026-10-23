# SPDX-License-Identifier: Apache-2.0
"""边界与分支补充用例（DEV-M01-T1 验收 5：关键分支 100%）。

这里的每一条都对应 ``models.py`` / ``state.py`` 的一个具体分支：取值越界、对象不存在、
席位在「邀请 → 接受」之间被占满、存量 Key 无归属、epoch 与状态双闸门等。
目的不是凑覆盖率，而是把「**拒绝**路径」也钉死：拒绝必须是明确的错误码，而不是静默放过。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from psycopg.rows import dict_row

from app.identity import models, state

from identitykit import rows, scalar

CLEAN = {"locked_earnings": True, "open_disputes": True, "negative_balance": True,
         "open_tickets": True}


# --------------------------------------------------------------------------- 错误信封 / 值对象
def test_error_envelope_shape(f):
    account = f.normal()
    err = models.NotFound("账户不存在", account_id=str(account.id))
    payload = err.as_dict()
    assert payload["type"] == "NotFound" and payload["code"] == "40401"
    assert payload["message"] == "账户不存在" and payload["account_id"] == str(account.id)
    assert models.InvalidArgument("x").reason == "identity_error"


def test_value_object_helpers(f):
    account = f.normal()
    assert account.writable is True and account.is_closed is False
    frozen = f.freeze(account)
    assert frozen.writable is False

    binding = models.bind_role(f.conn, account_id=account.id, admin_role="VIEWER",
                               granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    assert binding.active_at(f.moment) is True
    models.revoke_role(f.conn, binding.id, reason="cleanup", now=f.moment)
    revoked = rows(f.conn, "SELECT expires_at FROM role_bindings WHERE id = %s", (binding.id,))[0]
    assert binding.active_at(f.moment) is True          # 值对象快照不变
    assert revoked["expires_at"] == f.moment + timedelta(days=models.ROLE_RECLAIM_DAYS)


def test_row_helper_accepts_dict_rows(f):
    f.user()
    with f.conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT id, mfa_state FROM users")
        data = models._rows(cur)
    assert data and set(data[0]) == {"id", "mfa_state"}


def test_text_field_length_guards(f):
    with pytest.raises(models.InvalidArgument) as exc:
        models.create_user(f.conn, email="a@b.c", display_name="x" * 65, now=f.moment)
    assert exc.value.code == "40001"
    account = f.normal()
    with pytest.raises(models.InvalidArgument):
        f.key(account, label="y" * 65)


# --------------------------------------------------------------------------- 不存在 / 不可写
def test_missing_objects_are_404(f):
    ghost = uuid.uuid4()
    with pytest.raises(models.NotFound):
        models.get_user(f.conn, ghost)
    with pytest.raises(models.NotFound):
        models.get_org(f.conn, ghost)
    with pytest.raises(models.NotFound):
        models.remove_member(f.conn, ghost, now=f.moment)
    with pytest.raises(models.NotFound):
        models.get_account(f.conn, ghost)
    with pytest.raises(models.NotFound):
        models.bump_session_epoch(f.conn, ghost)
    with pytest.raises(models.NotFound):
        models.get_api_key(f.conn, 999999)


def test_closed_org_is_read_only(f):
    org = f.org()
    f.conn.execute("UPDATE orgs SET state = 'closing' WHERE id = %s", (org.id,))
    with pytest.raises(models.AccountReadOnly) as exc:
        models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                              now=f.moment)
    assert exc.value.code == "40304"


def test_seat_taken_between_invite_and_accept(f):
    """邀请时不占席位（避免过期邀请泄漏），但接受时抢不到席位必须拒绝。"""
    org = f.org(seats_limit=2)
    accounts = [models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                                      now=f.moment) for _ in range(2)]
    _m1, token_a = models.invite_member(f.conn, org.id, accounts[0].id, "admin", now=f.moment)
    _m2, token_b = models.invite_member(f.conn, org.id, accounts[1].id, "operator",
                                        now=f.moment)
    models.accept_invite(f.conn, token_a, now=f.moment)
    f.conn.execute("UPDATE orgs SET seats = seats_limit WHERE id = %s", (org.id,))
    with pytest.raises(models.StateConflict) as exc:
        models.accept_invite(f.conn, token_b, now=f.moment)
    assert exc.value.reason == "seats_exceeded"


def test_removing_pending_invite_releases_nothing(f):
    org = f.org()
    account = models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                                    now=f.moment)
    member, _token = models.invite_member(f.conn, org.id, account.id, "billing", now=f.moment)
    assert models.get_org(f.conn, org.id).seats == 0
    removed = models.remove_member(f.conn, member.id, now=f.moment)
    assert removed.state == "removed" and removed.joined_at is None
    assert models.get_org(f.conn, org.id).seats == 0


def test_owner_transfer_rejects_same_approver(f):
    org = f.org()
    account = models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                                    now=f.moment)
    _m, token = models.invite_member(f.conn, org.id, account.id, "owner", now=f.moment)
    models.accept_invite(f.conn, token, now=f.moment)
    same = uuid.uuid4()
    with pytest.raises(models.StateConflict) as exc:
        models.transfer_org_owner(f.conn, org.id, account.id, requester_id=same,
                                  approver_id=same, second_factor=True,
                                  target_confirmed=True, now=f.moment)
    assert exc.value.reason == "dual_control_required"


# --------------------------------------------------------------------------- Key 边界
def test_key_quota_arguments_are_validated(f):
    account = f.normal()
    with pytest.raises(models.InvalidArgument) as exc:
        f.key(account, qps=0)
    assert exc.value.details["field"] == "qps"
    with pytest.raises(models.InvalidArgument) as exc:
        f.key(account, daily_usd_minor=0)
    assert exc.value.details["field"] == "daily_usd_minor"


def test_list_and_get_api_key_filters(f):
    a, b = f.normal(), f.normal()
    key_a, _ = f.key(a)
    f.key(b)
    models.revoke_api_key(f.conn, key_a.id, now=f.moment)
    assert models.get_api_key(f.conn, key_a.id, account_id=a.id).id == key_a.id
    assert models.list_api_keys(f.conn, a.id, tenant_id=a.tenant_id, now=f.moment) == []
    assert len(models.list_api_keys(f.conn, a.id, include_revoked=True, now=f.moment)) == 1
    assert len(models.list_api_keys(f.conn, a.id, tenant_id=a.tenant_id,
                                    include_revoked=True, now=f.moment)) == 1


def test_legacy_key_without_account_cannot_authenticate(f):
    plaintext = "legacy-plaintext-key"
    f.conn.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s, %s, %s)",
                   ("user:legacy", plaintext[:8], models.hash_secret(plaintext)))
    assert models.lookup_api_key(f.conn, plaintext).account_id is None
    with pytest.raises(models.ApiKeyInvalid) as exc:
        models.authenticate_api_key(f.conn, plaintext)
    assert exc.value.message == "Key 未绑定账户"


def test_closed_account_key_and_role_are_rejected(f):
    account = f.normal()
    key, plaintext = f.key(account)
    f.conn.execute("UPDATE user_accounts SET state = 'closed', closed_at = now()"
                   " WHERE id = %s", (account.id,))
    with pytest.raises(models.AccountClosed):
        models.bind_role(f.conn, account_id=account.id, admin_role="CS",
                         granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    with pytest.raises(models.AccountClosed):
        state.require_writable(f.conn, account.id)
    with pytest.raises(models.ApiKeyInvalid) as exc:      # 鉴权路径统一 40101
        models.authenticate_api_key(f.conn, plaintext)
    assert exc.value.message == "账户已注销"
    assert key.id is not None


def test_invite_to_missing_org_is_404(f):
    with pytest.raises(models.NotFound):
        models.invite_member(f.conn, uuid.uuid4(), uuid.uuid4(), "admin", now=f.moment)


# --------------------------------------------------------------------------- 会话边界
def test_session_epoch_mismatch_alone_invalidates(f):
    account = f.normal()
    session = f.session(account)
    models.bump_session_epoch(f.conn, account.id)               # 只加 epoch，不撤销会话
    with pytest.raises(models.SessionInvalid) as exc:
        models.validate_session(f.conn, session.id, now=f.moment)
    assert "epoch" in exc.value.message


def test_closed_account_with_live_session_is_rejected(f):
    account = f.normal()
    session = f.session(account)
    f.conn.execute("UPDATE user_accounts SET state = 'closed', closed_at = now()"
                   " WHERE id = %s", (account.id,))
    with pytest.raises(models.SessionInvalid) as exc:
        models.validate_session(f.conn, session.id, now=f.moment)
    assert exc.value.message == "账户已注销"


def test_reclaim_expired_roles_dedupes_accounts(f):
    account = f.normal()
    for role in ("CS", "VIEWER"):
        models.bind_role(f.conn, account_id=account.id, admin_role=role,
                         granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    later = f.moment + timedelta(days=models.ROLE_RECLAIM_DAYS + 1)
    assert models.reclaim_expired_roles(f.conn, now=later) == [account.id]
    assert scalar(f.conn, "SELECT count(*) FROM role_bindings WHERE revoked_at IS NULL") == 0


# --------------------------------------------------------------------------- 配额边界
def test_effective_quotas_without_key_or_node(f):
    assert models.effective_quotas(tenant={"qps": 4}) == {"qps": 4}
    assert models.effective_quotas(tenant={"qps": 4}, key=None, node=None) == {"qps": 4}
    assert models.effective_quotas(tenant={}, node={"qps": 2}) == {"qps": 2}


# --------------------------------------------------------------------------- 状态机边界
def test_finalize_requires_closing_state(f):
    account = f.normal()
    with pytest.raises(models.StateConflict) as exc:
        state.finalize_closing(f.conn, account.id, now=f.moment)
    assert exc.value.reason == "not_closing"
