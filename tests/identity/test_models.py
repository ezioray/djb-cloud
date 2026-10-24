# SPDX-License-Identifier: AGPL-3.0-or-later
"""模型 / Key / 会话 / 角色 / 配额 / 租户隔离（DEV-M01-T1 验收 3、4、5）。

覆盖要点：
- 邮箱 / 手机只存不可逆哈希，明文不可能过库层 CHECK；
- **Key 明文只出现一次**：库里只有 sha256 与前缀，日志里没有明文（INV-04）；
- 撤销幂等（A3）、轮换同事务失效旧钥、单账户 Key 上限、跨租户 404 / 40101（A6）；
- 会话：epoch 失效（A4）、滑动续期不越 12 h 绝对、撤销幂等；
- 角色：八角色白名单、双人复核、SVC 不得绑自然人、90 天到期回收、默认拒绝；
- 配额：min(租户, Key, 节点)、policy_version 快照、缺快照 40907；
- 租户隔离：跨租户读 / 写 / 复合外键在库层被拒；
- 架构门：不跨模块 import、不碰它模块基表、包内无密钥字面量。
"""
from __future__ import annotations

import ast
import logging
import pathlib
import re
import uuid
from datetime import timedelta

import psycopg
import pytest

from app.identity import models, state

from identitykit import all_events, rows, scalar

CLEAN = {"locked_earnings": True, "open_disputes": True, "negative_balance": True,
         "open_tickets": True}
NON_SVC_ROLES = tuple(r for r in models.ADMIN_ROLES if r != "SVC")


# --------------------------------------------------------------------------- users
def test_user_pii_is_hashed_never_stored(f):
    user = f.user(email="Alice@Example.com", phone="+8613800000000", display_name="Alice")
    assert user.email_hash == models.hash_pii("alice@example.com"), "哈希前需归一化"
    assert len(user.email_hash) == 64 and len(user.phone_hash) == 64
    assert models.find_user_by_email(f.conn, " ALICE@example.com ").id == user.id

    stored = rows(f.conn, "SELECT * FROM users WHERE id = %s", (user.id,))[0]
    blob = str(stored)
    assert "example.com" not in blob and "13800000000" not in blob


def test_duplicate_email_is_rejected(f):
    f.user(email="dup@example.com")
    with pytest.raises(models.StateConflict) as exc, f.conn.transaction():
        f.user(email="dup@example.com")
    assert exc.value.code == "40902"


def test_plaintext_email_cannot_pass_db_check(conn):
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("INSERT INTO users (id, email_hash) VALUES (%s, %s)",
                     (uuid.uuid4(), "alice@example.com"))


def test_pii_pepper_changes_hash(monkeypatch):
    plain = "alice@example.com"
    monkeypatch.delenv(models.PII_PEPPER_ENV, raising=False)
    bare = models.hash_pii(plain)
    assert len(bare) == 64
    monkeypatch.setenv(models.PII_PEPPER_ENV, "deployment-pepper-not-a-real-secret")
    peppered = models.hash_pii(plain)
    assert peppered != bare and len(peppered) == 64
    monkeypatch.delenv(models.PII_PEPPER_ENV, raising=False)
    assert models.hash_pii(plain) == bare


def test_service_account_without_contact_is_allowed(f):
    user = models.create_user(f.conn, now=f.moment)           # SVC：无邮箱 / 手机
    assert user.email_hash is None and user.phone_hash is None


def test_purge_user_pii_is_idempotent(f):
    user = f.user(email="purge@example.com", display_name="P")
    assert models.purge_user_pii(f.conn, user.id) == 1
    assert models.purge_user_pii(f.conn, user.id) == 0
    assert models.find_user_by_email(f.conn, "purge@example.com") is None


# --------------------------------------------------------------------------- accounts / orgs
def test_personal_account_tenant_is_itself(f):
    account = f.normal()
    assert account.tenant_id == account.id
    assert account.org_id is None
    assert [e["type"] for e in all_events(f.conn)] == ["account.created", "account.state.changed"]


def test_team_account_requires_org(f):
    user = f.user()
    with pytest.raises(models.InvalidArgument):
        models.create_account(f.conn, user_id=user.id, type="team", now=f.moment)
    org = f.org(type="team")
    account = models.create_account(f.conn, user_id=user.id, type="team", org_id=org.id,
                                    now=f.moment)
    assert account.tenant_id == org.id and account.org_id == org.id
    with pytest.raises(models.InvalidArgument):
        models.create_account(f.conn, user_id=user.id, type="personal", org_id=org.id,
                              now=f.moment)
    with pytest.raises(models.InvalidArgument):
        models.create_account(f.conn, user_id=user.id, type="team", org_id=org.id,
                              tenant_id=uuid.uuid4(), now=f.moment)


def test_cross_tenant_account_read_is_404(f):
    account = f.normal()
    with pytest.raises(models.NotFound) as exc:
        models.get_account(f.conn, account.id, tenant_id=uuid.uuid4())
    assert exc.value.status_code == 404 and exc.value.code == "40401"


def test_account_constraints_are_enforced(f):
    account = f.normal()
    with pytest.raises(psycopg.errors.CheckViolation), f.conn.transaction():   # 租户必须=id
        f.conn.execute("INSERT INTO user_accounts (id, user_id, type, state, tenant_id)"
                       " VALUES (%s, %s, 'personal', 'normal', %s)",
                       (uuid.uuid4(), account.user_id, uuid.uuid4()))
    with pytest.raises(psycopg.errors.CheckViolation), f.conn.transaction():   # 五态白名单
        f.conn.execute("INSERT INTO user_accounts (id, user_id, type, state, tenant_id)"
                       " VALUES (%s, %s, 'personal', 'sleeping', %s)",
                       (uuid.uuid4(), account.user_id, uuid.uuid4()))


def test_org_constraints_are_enforced(f):
    with pytest.raises(models.InvalidArgument):              # 席位上限：team ≤ 20
        models.create_org(f.conn, type="team", name="too-big", seats_limit=21, now=f.moment)
    with pytest.raises(models.InvalidArgument):
        models.create_org(f.conn, type="personal", name="nope", now=f.moment)
    org = f.org(type="enterprise", seats_limit=200)
    assert org.type == "enterprise" and org.seats == 0 and org.state == "active"


def test_list_accounts_filters(f):
    a = f.normal()
    b = f.account()
    assert {x.id for x in models.list_accounts(f.conn, state="normal")} == {a.id}
    assert {x.id for x in models.list_accounts(f.conn, tenant_id=b.tenant_id)} == {b.id}
    with pytest.raises(models.InvalidArgument):
        models.list_accounts(f.conn, state="sleeping")


def test_org_seat_limits_and_member_lifecycle(f):
    org = f.org(type="team", seats_limit=2)
    a = models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                              now=f.moment)
    b = models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                              now=f.moment)

    member_a, token_a = models.invite_member(f.conn, org.id, a.id, "owner", now=f.moment)
    stored = rows(f.conn, "SELECT invite_hash FROM org_members WHERE id = %s", (member_a.id,))[0]
    assert stored["invite_hash"] == models.hash_secret(token_a)
    assert token_a not in str(stored)
    models.accept_invite(f.conn, token_a, now=f.moment)
    assert models.get_org(f.conn, org.id).seats == 1
    with pytest.raises(models.InviteInvalid) as exc:          # 令牌一次性（INV-08）
        models.accept_invite(f.conn, token_a, now=f.moment)
    assert exc.value.code == "40905"

    _member_b, token_b = models.invite_member(f.conn, org.id, b.id, "billing", now=f.moment)
    models.accept_invite(f.conn, token_b, now=f.moment)
    assert models.get_org(f.conn, org.id).seats == 2

    with pytest.raises(models.StateConflict) as exc:          # 席位已满
        models.invite_member(f.conn, org.id, a.id, "billing", now=f.moment)
    assert exc.value.reason == "seats_exceeded"

    with pytest.raises(models.StateConflict) as exc:          # owner 不可直接移除（INV-05）
        models.remove_member(f.conn, member_a.id, now=f.moment)
    assert exc.value.reason == "owner_protected"

    members = {m.account_id: m for m in models.list_members(f.conn, org.id)}
    removed = models.remove_member(f.conn, members[b.id].id, now=f.moment)
    assert removed.state == "removed" and removed.removed_at is not None
    assert models.get_org(f.conn, org.id).seats == 1
    assert models.remove_member(f.conn, members[b.id].id, now=f.moment).state == "removed"


def test_expired_invite_is_rejected(f):
    org = f.org()
    account = models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                                    now=f.moment)
    _member, token = models.invite_member(f.conn, org.id, account.id, "operator", now=f.moment)
    with pytest.raises(models.InviteInvalid) as exc:
        models.accept_invite(f.conn, token, now=f.moment + timedelta(hours=73))
    assert exc.value.code == "40905"
    with pytest.raises(models.InviteInvalid):
        models.accept_invite(f.conn, "not-a-token", now=f.moment)


def test_member_must_belong_to_the_org_tenant(f):
    """成员账户必须属于该组织租户：库层复合外键兜底。"""
    org = f.org()
    outsider = f.normal()                                     # personal 账户，租户=自身
    with pytest.raises(psycopg.errors.ForeignKeyViolation), f.conn.transaction():
        models.invite_member(f.conn, org.id, outsider.id, "admin", now=f.moment)


def test_duplicate_member_is_rejected(f):
    org = f.org()
    account = models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                                    now=f.moment)
    models.invite_member(f.conn, org.id, account.id, "admin", now=f.moment)
    with pytest.raises(models.StateConflict) as exc, f.conn.transaction():
        models.invite_member(f.conn, org.id, account.id, "billing", now=f.moment)
    assert exc.value.reason == "member_exists"


def test_owner_transfer_requires_dual_control_and_cools_down(f):
    org = f.org()
    a = models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                              now=f.moment)
    b = models.create_account(f.conn, user_id=f.user().id, type="team", org_id=org.id,
                              now=f.moment)
    for account, role in ((a, "owner"), (b, "admin")):
        _m, token = models.invite_member(f.conn, org.id, account.id, role, now=f.moment)
        models.accept_invite(f.conn, token, now=f.moment)
    requester, approver = uuid.uuid4(), uuid.uuid4()

    with pytest.raises(models.StateConflict):
        models.transfer_org_owner(f.conn, org.id, b.id, requester_id=requester,
                                  approver_id=approver, second_factor=False,
                                  target_confirmed=True, now=f.moment)
    with pytest.raises(models.StateConflict):
        models.transfer_org_owner(f.conn, org.id, b.id, requester_id=requester,
                                  approver_id=approver, second_factor=True,
                                  target_confirmed=False, now=f.moment)
    with pytest.raises(models.StateConflict) as exc:
        models.transfer_org_owner(f.conn, org.id, a.id, requester_id=requester,
                                  approver_id=approver, second_factor=True,
                                  target_confirmed=True, now=f.moment)
    assert exc.value.reason == "not_a_member"                 # 目标已是 owner

    transferred = models.transfer_org_owner(f.conn, org.id, b.id, requester_id=requester,
                                            approver_id=approver, second_factor=True,
                                            target_confirmed=True, now=f.moment)
    assert transferred.owner_account_id == b.id
    assert {m.account_id: m.org_role for m in models.list_members(f.conn, org.id)} == \
        {a.id: "admin", b.id: "owner"}

    with pytest.raises(models.StateConflict) as exc:          # 24 h 冷却
        models.transfer_org_owner(f.conn, org.id, a.id, requester_id=requester,
                                  approver_id=approver, second_factor=True,
                                  target_confirmed=True, now=f.moment + timedelta(hours=1))
    assert exc.value.reason == "owner_transfer_cooling"


# --------------------------------------------------------------------------- api_keys
def test_api_key_plaintext_is_shown_once_and_never_stored(f, caplog):
    account = f.normal()
    with caplog.at_level(logging.DEBUG, logger="djb.identity"):
        key, plaintext = f.key(account, label="ci", qps=7, daily_usd_minor=5000)

    assert len(plaintext) >= 32, "256 bit 熵（M01 §6.2）"
    assert key.key_prefix == plaintext[: models.KEY_PREFIX_LEN]
    assert key.key_hash == models.hash_secret(plaintext) != plaintext
    assert key.qps == 7 and key.daily_usd_minor == 5000 and key.label == "ci"
    assert key.live and key.account_id == account.id and key.tenant_id == account.tenant_id

    stored = str(rows(f.conn, "SELECT * FROM api_keys WHERE id = %s", (key.id,))[0])
    assert plaintext not in stored and key.key_hash in stored

    assert caplog.records, "创建 Key 应留结构化日志"
    assert plaintext not in caplog.text
    for record in caplog.records:
        assert plaintext not in record.getMessage()
        assert plaintext not in str(record.args)

    listed = models.list_api_keys(f.conn, account.id)
    assert [k.key_prefix for k in listed] == [key.key_prefix]
    assert plaintext not in str(listed) and not hasattr(listed[0], "plaintext")


def test_api_key_lookup_and_authenticate(f):
    account = f.normal()
    _key, plaintext = f.key(account)
    assert models.authenticate_api_key(f.conn, plaintext).id == account.id
    with pytest.raises(models.ApiKeyInvalid) as exc:
        models.authenticate_api_key(f.conn, "wrong-key")
    assert exc.value.code == "40101"


def test_api_key_cannot_be_created_in_read_only_states(f):
    frozen = f.freeze(f.normal())
    with pytest.raises(models.AccountReadOnly) as exc:
        f.key(frozen)
    assert exc.value.code == "40304"

    closing = state.start_closing(f.conn, f.normal().id, checks=CLEAN, now=f.moment)
    with pytest.raises(models.AccountReadOnly):
        f.key(closing)


def test_api_key_limit(f):
    account = f.normal()
    for _ in range(models.KEY_MAX_PER_ACCOUNT):
        f.key(account)
    with pytest.raises(models.KeyLimitReached) as exc:
        f.key(account)
    assert exc.value.code == "40902"


def test_revoke_api_key_is_idempotent(f):
    """A3：同一 Key 撤销两次 → 第二次返回首次结果，不报 500。"""
    account = f.normal()
    key, plaintext = f.key(account)
    first = models.revoke_api_key(f.conn, key.id, reason="user_revoked", now=f.moment)
    second = models.revoke_api_key(f.conn, key.id, reason="user_revoked",
                                   now=f.moment + timedelta(seconds=5))
    assert first.revoked_at == second.revoked_at
    assert scalar(f.conn, "SELECT count(*) FROM identity_outbox"
                          " WHERE type = 'apikey.revoked'") == 1
    with pytest.raises(models.ApiKeyInvalid):
        models.lookup_api_key(f.conn, plaintext, now=f.moment)


def test_rotate_api_key_swaps_in_one_step(f):
    account = f.normal()
    old, old_plain = f.key(account)
    new, new_plain = models.rotate_api_key(f.conn, old.id, now=f.moment)

    assert new.id != old.id and new.rotated_from == old.id
    assert models.get_api_key(f.conn, old.id).revoked_reason == "rotated"
    with pytest.raises(models.ApiKeyInvalid):
        models.authenticate_api_key(f.conn, old_plain, now=f.moment)
    assert models.authenticate_api_key(f.conn, new_plain).id == account.id
    assert new_plain != old_plain
    types = [e["type"] for e in all_events(f.conn)]
    assert types.count("apikey.created") == 2 and types.count("apikey.revoked") == 1


def test_rotate_revoked_or_legacy_key_is_rejected(f):
    account = f.normal()
    key, _ = f.key(account)
    models.revoke_api_key(f.conn, key.id, now=f.moment)
    with pytest.raises(models.StateConflict) as exc:
        models.rotate_api_key(f.conn, key.id, now=f.moment)
    assert exc.value.code == "40902"

    f.conn.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s, %s, %s)",
                   ("user:legacy", "legacyab", "f" * 64))
    legacy_id = scalar(f.conn, "SELECT id FROM api_keys WHERE key_hash = %s", ("f" * 64,))
    with pytest.raises(models.StateConflict) as exc:
        models.rotate_api_key(f.conn, legacy_id, now=f.moment)
    assert exc.value.reason == "legacy_key"


def test_key_cross_tenant_access_is_404_or_401(f):
    a, b = f.normal(), f.normal()
    key, plaintext = f.key(a)
    with pytest.raises(models.NotFound):                      # A6：跨租户读 → 404
        models.get_api_key(f.conn, key.id, tenant_id=b.tenant_id)
    with pytest.raises(models.ApiKeyInvalid):                 # 跨租户鉴权 → 40101
        models.lookup_api_key(f.conn, plaintext, tenant_id=b.tenant_id)
    assert models.list_api_keys(f.conn, b.id) == []


def test_cross_tenant_key_ownership_is_rejected_by_db(f):
    a, b = f.normal(), f.normal()
    with pytest.raises(psycopg.errors.ForeignKeyViolation), f.conn.transaction():
        f.conn.execute(
            "INSERT INTO api_keys (user_id, key_prefix, key_hash, account_id, tenant_id)"
            " VALUES (%s, %s, %s, %s, %s)",
            ("user:x", "abcdefgh", "e" * 64, a.id, b.tenant_id))


def test_key_hash_shape_check_blocks_plaintext(f):
    account = f.normal()
    with pytest.raises(psycopg.errors.CheckViolation), f.conn.transaction():
        f.conn.execute(
            "INSERT INTO api_keys (user_id, key_prefix, key_hash, account_id, tenant_id)"
            " VALUES (%s, %s, %s, %s, %s)",
            ("user:x", "abcdefgh", "sk-plaintext-key", account.id, account.tenant_id))


# --------------------------------------------------------------------------- sessions
def test_session_epoch_invalidated_by_role_change(f):
    """A4：角色变更后用旧会话请求 → 40102。"""
    account = f.normal()
    session = f.session(account)
    assert models.validate_session(f.conn, session.id, now=f.moment).id == session.id

    models.bind_role(f.conn, account_id=account.id, admin_role="OPS",
                     granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    with pytest.raises(models.SessionInvalid) as exc:
        models.validate_session(f.conn, session.id, now=f.moment)
    assert exc.value.code == "40102"
    assert models.get_session(f.conn, session.id).revoked_at is not None


def test_session_ttl_and_sliding_window(f):
    account = f.normal()
    admin = f.session(account, kind="admin")
    user = f.session(account, kind="user")
    assert admin.expires_at == f.moment + timedelta(minutes=models.SESSION_SLIDE_MINUTES)
    assert user.expires_at == f.moment + timedelta(hours=models.ACCESS_TTL_HOURS)
    assert user.refresh_expires_at == f.moment + timedelta(days=models.REFRESH_TTL_DAYS)
    assert admin.refresh_expires_at is None

    touched = models.touch_session(f.conn, admin.id, now=f.moment + timedelta(minutes=20))
    assert touched.last_seen_at == f.moment + timedelta(minutes=20)
    assert touched.expires_at == f.moment + timedelta(minutes=50)

    # 持续滑动续期（每 20 分钟一次，始终在到期前）→ 到期时间被 12 h 绝对上限压住
    session = touched
    for step in range(2, 36):
        session = models.touch_session(f.conn, admin.id,
                                       now=f.moment + timedelta(minutes=20 * step))
    assert session.expires_at == f.moment + timedelta(hours=models.SESSION_ABSOLUTE_HOURS)


def test_expired_and_revoked_sessions_are_rejected(f):
    account = f.normal()
    session = f.session(account, kind="admin")
    with pytest.raises(models.SessionInvalid):
        models.validate_session(f.conn, session.id, now=f.moment + timedelta(hours=13))
    with pytest.raises(models.SessionInvalid):
        models.touch_session(f.conn, session.id, now=f.moment + timedelta(hours=13))

    fresh = f.session(account)
    revoked = models.revoke_session(f.conn, fresh.id, reason="logout", now=f.moment)
    assert models.revoke_session(f.conn, fresh.id, now=f.moment).revoked_at == revoked.revoked_at
    with pytest.raises(models.SessionInvalid):
        models.validate_session(f.conn, fresh.id, now=f.moment)
    assert scalar(f.conn, "SELECT count(*) FROM identity_outbox"
                          " WHERE type = 'session.revoked'") == 1


def test_revoke_live_sessions_counts(f):
    account = f.normal()
    f.session(account)
    f.session(account, kind="admin")
    assert models.revoke_live_sessions(f.conn, account.id, reason="offboard", now=f.moment) == 2
    assert models.revoke_live_sessions(f.conn, account.id, reason="offboard", now=f.moment) == 0


def test_session_creation_blocked_for_pending_and_closed(f):
    pending = f.account()
    with pytest.raises(models.InvalidArgument):
        f.session(pending)

    account = f.normal()
    state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)
    state.finalize_closing(f.conn, account.id, now=f.moment + timedelta(days=30))
    with pytest.raises(models.AccountClosed):
        f.session(account)


def test_session_tenant_isolation(f):
    a, b = f.normal(), f.normal()
    session = f.session(a)
    with pytest.raises(models.SessionInvalid):
        models.get_session(f.conn, session.id, tenant_id=b.tenant_id)


# --------------------------------------------------------------------------- roles
@pytest.mark.parametrize("role", NON_SVC_ROLES)
def test_roles_can_be_bound_with_90_day_ttl(f, role):
    account = f.normal()
    binding = models.bind_role(f.conn, account_id=account.id, admin_role=role,
                               granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    assert binding.admin_role == role
    assert binding.expires_at == f.moment + timedelta(days=models.ROLE_RECLAIM_DAYS)
    assert models.effective_roles(f.conn, account.id, now=f.moment) == [role]


def test_role_whitelist_is_exactly_eight(f):
    # 顺序按 contracts/facts.yaml「后台角色」原文（CR-4 起以机器源为准）
    assert models.ADMIN_ROLES == ("SUPER", "SVC", "OPS", "AUDIT", "RISK", "FIN", "CS", "VIEWER")
    assert set(models.ADMIN_ROLES) == {"SUPER", "SVC", "OPS", "AUDIT", "RISK", "FIN", "CS",
                                       "VIEWER"}


def test_unknown_role_and_scope_are_rejected(f):
    account = f.normal()
    with pytest.raises(models.InvalidArgument):
        models.bind_role(f.conn, account_id=account.id, admin_role="ROOT",
                         granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    with pytest.raises(models.InvalidArgument):
        models.bind_role(f.conn, account_id=account.id, admin_role="OPS", scope="global",
                         granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)


def test_role_requires_second_person(f):
    account = f.normal()
    same = uuid.uuid4()
    with pytest.raises(models.StateConflict) as exc:
        models.bind_role(f.conn, account_id=account.id, admin_role="FIN",
                         granted_by=same, approved_by=same, now=f.moment)
    assert exc.value.code == "40902"


def test_svc_role_rejects_human_account(f):
    account = f.normal()                                      # 有邮箱哈希
    with pytest.raises(models.StateConflict) as exc:
        models.bind_role(f.conn, account_id=account.id, admin_role="SVC",
                         granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    assert exc.value.code == "40902"


def test_svc_role_allowed_for_natural_free_account(f):
    svc_user = models.create_user(f.conn, now=f.moment)       # 无邮箱 / 手机
    svc = models.create_account(f.conn, user_id=svc_user.id, now=f.moment)
    state.verify(f.conn, svc.id, now=f.moment)
    binding = models.bind_role(f.conn, account_id=svc.id, admin_role="SVC",
                              granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    assert binding.admin_role == "SVC"


def test_svc_guard_trigger_blocks_direct_insert(f):
    account = f.normal()
    with pytest.raises(psycopg.errors.CheckViolation), f.conn.transaction():
        f.conn.execute(
            """INSERT INTO role_bindings
                   (id, account_id, tenant_id, admin_role, granted_by, approved_by, expires_at)
               VALUES (%s, %s, %s, 'SVC', %s, %s, now() + interval '90 days')""",
            (uuid.uuid4(), account.id, account.tenant_id, uuid.uuid4(), uuid.uuid4()))


def test_duplicate_live_role_is_rejected(f):
    account = f.normal()
    kwargs = dict(account_id=account.id, admin_role="OPS", granted_by=uuid.uuid4(),
                  approved_by=uuid.uuid4(), now=f.moment)
    models.bind_role(f.conn, **kwargs)
    with pytest.raises(models.StateConflict) as exc, f.conn.transaction():
        models.bind_role(f.conn, **kwargs)
    assert exc.value.reason == "role_already_bound"


def test_revoke_role_and_expiry_reclaim(f):
    account = f.normal()
    binding = models.bind_role(f.conn, account_id=account.id, admin_role="CS",
                               granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    revoked = models.revoke_role(f.conn, binding.id, reason="offboard", now=f.moment)
    assert revoked.revoked_at is not None
    assert models.revoke_role(f.conn, binding.id, now=f.moment).revoked_at == revoked.revoked_at
    assert models.effective_roles(f.conn, account.id, now=f.moment) == []

    again = models.bind_role(f.conn, account_id=account.id, admin_role="CS",
                             granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    later = f.moment + timedelta(days=models.ROLE_RECLAIM_DAYS + 1)
    assert models.effective_roles(f.conn, account.id, now=later) == []
    assert models.reclaim_expired_roles(f.conn, now=later) == [account.id]
    assert models.reclaim_expired_roles(f.conn, now=later) == []
    assert rows(f.conn, "SELECT revoked_reason FROM role_bindings WHERE id = %s",
                (again.id,))[0]["revoked_reason"] == "expired"


def test_default_deny_without_binding(f):
    account = f.normal()
    assert models.effective_roles(f.conn, account.id, now=f.moment) == []


def test_revoke_unknown_role_is_404(f):
    with pytest.raises(models.NotFound):
        models.revoke_role(f.conn, uuid.uuid4(), now=f.moment)


# --------------------------------------------------------------------------- quotas
def test_quota_min_across_three_layers(f):
    """INV-07：生效配额 = min(租户, Key, 节点能力)。"""
    account = f.normal()
    key, _ = f.key(account)
    models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=5,
                     policy_version="v4.0", now=f.moment)
    models.set_quota(f.conn, tenant_id=account.tenant_id, kind="daily_usd_minor", value=10000,
                     policy_version="v4.0", now=f.moment)
    models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=3,
                     policy_version="v4.0", key_id=key.id, now=f.moment)

    snapshot = models.quota_snapshot(f.conn, account.tenant_id, key_id=key.id,
                                     node_caps={"qps": 10, "concurrency": 4})
    assert snapshot["policy_version"] == "v4.0"
    assert snapshot["effective"] == {"concurrency": 4, "daily_usd_minor": 10000, "qps": 3}
    assert {q["kind"] for q in snapshot["quotas"]} == {"qps", "daily_usd_minor"}
    assert models.effective_quotas(tenant={"qps": 5}, key={"qps": 8})["qps"] == 5
    assert models.effective_quotas(tenant={"qps": 5})["qps"] == 5


def test_quota_upsert_is_idempotent(f):
    account = f.normal()
    first = models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=5,
                             policy_version="v4.0", now=f.moment)
    second = models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=9,
                              policy_version="v4.1", now=f.moment)
    assert first.id == second.id and second.value == 9
    assert scalar(f.conn, "SELECT count(*) FROM tenant_quotas") == 1


def test_quota_snapshot_missing_or_conflicting_version(f):
    account = f.normal()
    f.conn.execute("DELETE FROM tenant_quotas WHERE tenant_id = %s", (account.tenant_id,))
    with pytest.raises(models.QuotaSnapshotMissing) as exc:
        models.quota_snapshot(f.conn, account.tenant_id)
    assert exc.value.code == "40907"

    key, _ = f.key(account)
    models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=5,
                     policy_version="v4.0", now=f.moment)
    models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=2,
                     policy_version="v9.9", key_id=key.id, now=f.moment)
    with pytest.raises(models.QuotaSnapshotMissing) as exc:
        models.quota_snapshot(f.conn, account.tenant_id, key_id=key.id)
    assert exc.value.details["versions"] == ["v4.0", "v9.9"]


def test_quota_validation(f):
    account = f.normal()
    with pytest.raises(models.InvalidArgument):
        models.set_quota(f.conn, tenant_id=account.tenant_id, kind="tokens", value=1,
                         policy_version="v4.0", now=f.moment)
    with pytest.raises(models.InvalidArgument):
        models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=-1,
                         policy_version="v4.0", now=f.moment)
    with pytest.raises(models.InvalidArgument):
        models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=True,
                         policy_version="v4.0", now=f.moment)
    with pytest.raises(models.InvalidArgument):
        models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=1,
                         policy_version="  ", now=f.moment)
    with pytest.raises(psycopg.errors.CheckViolation), f.conn.transaction():
        f.conn.execute("INSERT INTO tenant_quotas (id, tenant_id, kind, value, policy_version)"
                       " VALUES (%s, %s, 'qps', 1, '')", (uuid.uuid4(), account.tenant_id))


def test_key_quota_is_tenant_isolated(f):
    a, b = f.normal(), f.normal()
    key_a, _ = f.key(a)
    with pytest.raises(models.NotFound):                      # 跨租户写 Key 级配额 → 404
        models.set_quota(f.conn, tenant_id=b.tenant_id, kind="qps", value=1,
                         policy_version="v4.0", key_id=key_a.id, now=f.moment)
    with pytest.raises(psycopg.errors.ForeignKeyViolation), f.conn.transaction():  # 库层兜底
        f.conn.execute("INSERT INTO tenant_quotas (id, tenant_id, key_id, kind, value,"
                       " policy_version) VALUES (%s, %s, %s, 'qps', 1, 'v4.0')",
                       (uuid.uuid4(), b.tenant_id, key_a.id))


def test_legacy_key_cannot_hold_quota(f):
    f.conn.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s, %s, %s)",
                   ("user:legacy", "legacyab", "9" * 64))
    legacy_id = scalar(f.conn, "SELECT id FROM api_keys WHERE key_hash = %s", ("9" * 64,))
    account = f.normal()
    with pytest.raises(models.StateConflict) as exc:
        models.set_quota(f.conn, tenant_id=account.tenant_id, kind="qps", value=1,
                         policy_version="v4.0", key_id=legacy_id, now=f.moment)
    assert exc.value.reason == "legacy_key"


def test_registration_seeds_tenant_quota(f):
    account = f.account(policy_version="v4.2")
    assert models.quota_snapshot(f.conn, account.tenant_id)["effective"] == {
        "qps": models.DEFAULT_QPS}
    unseeded = f.account(policy_version=None)
    with pytest.raises(models.QuotaSnapshotMissing):
        models.quota_snapshot(f.conn, unseeded.tenant_id)


# --------------------------------------------------------------------------- outbox
def test_outbox_dedupes_by_idempotency_key(f):
    account = f.normal()
    assert models.emit_event(f.conn, "account.created", aggregate_type="account",
                             aggregate_id=account.id, payload={"k": 1},
                             idempotency_key="fixed-key", now=f.moment) is True
    assert models.emit_event(f.conn, "account.created", aggregate_type="account",
                             aggregate_id=account.id, payload={"k": 1},
                             idempotency_key="fixed-key", now=f.moment) is False
    assert scalar(f.conn, "SELECT count(*) FROM identity_outbox"
                          " WHERE idempotency_key = 'fixed-key'") == 1


def test_outbox_publish_marks_pending(f):
    account = f.normal()
    assert models.pending_events(f.conn, limit=10)
    f.conn.execute("UPDATE identity_outbox SET published_at = now()")
    assert models.pending_events(f.conn, limit=10) == []
    assert account is not None


# --------------------------------------------------------------------------- 架构门（验收 4）
def _package_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[2] / "app" / "identity"


def test_identity_imports_no_other_app_module():
    """只允许标准库与 psycopg；不 import 其它 app.* 业务模块（00-conventions §1.2）。"""
    offenders: list[str] = []
    for path in sorted(_package_dir().glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            for name in names:
                root = name.split(".")[0]
                if root != "app":
                    continue
                # 只放行基础设施（app.db / app.config）；业务模块与 app.api 一律禁止
                if name.startswith("app.identity") or name in ("app.db", "app.config"):
                    continue
                offenders.append(f"{path.name}: import {name}")
    assert offenders == [], offenders


def test_identity_sql_does_not_touch_other_module_tables():
    """不读写 M06 / M10 / M02 等基表（跨模块只走 API 或视图）。"""
    forbidden = ("ledger_entry", "ledger_entries", "journal_entry", "journal_line",
                 "account_balances", "merkle_commitments", "config_items", "config_versions",
                 "config_snapshots", "nodes", "node_policies", "usage_records", "receipts")
    hits: list[str] = []
    for path in sorted(_package_dir().glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for table in forbidden:
            if re.search(rf"\b{table}\b", text):
                hits.append(f"{path.name}: {table}")
    assert hits == [], hits


def test_no_plaintext_secret_literals_in_package():
    """包内不得出现 Key / 密码形态的字面量（secret-scan 口径）。"""
    pattern = re.compile(r"(?:password|passwd|secret|token)\s*=\s*['\"][^'\"]{8,}['\"]", re.I)
    hits = [f"{p.name}: {m.group(0)[:40]}" for p in sorted(_package_dir().glob("*.py"))
            for m in [pattern.search(p.read_text(encoding="utf-8"))] if m]
    assert hits == [], hits
