# SPDX-License-Identifier: AGPL-3.0-or-later
"""T2 登录 / 刷新 / 登出 / 会话时效（tasks-11 验收）。

覆盖：
- 登录成功：令牌形状、``security: []``、账户视图脱敏、库里只有哈希、日志无明文；
- 凭据错误统一 **40110**（不区分账号不存在 / 口令错误）、失败 5 次锁定 15 分钟（429/42901）；
- 刷新即轮换：新令牌对、旧 refresh 重放 → 401 40103、旧 access 仍可用到自然过期；
- 登出：``all_devices`` 写 epoch（旧令牌 40102）、重复登出幂等；
- 会话时效：admin 30 min 滑动 / 15 min 空闲 / 12 h 绝对；user 访问令牌 2 h；空闲回收 job；
- 错误信封与 ``X-Request-Id`` 回显；未接通道（短信 / 外部 OAuth）403 40303。
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta

import pytest

from app.identity import models, tokens

from identitykit import bearer, error_of, rows, scalar

PASSWORD = "S3cret!"


def _login(api, identifier: str, *, secret: str = PASSWORD, method: str = "password",
           **extra) -> dict:
    response = api.post("/api/v1/auth/login",
                        json={"method": method, "identifier": identifier, "secret": secret,
                              **extra})
    return response


# --------------------------------------------------------------------------- 登录成功
def test_login_success_issues_tokens_and_profile(api, f, caplog):
    user, account = f.login_ready()
    with caplog.at_level(logging.DEBUG, logger="djb.identity"):
        response = _login(api, "login1@example.com")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"tokens", "account", "mfa_required"}
    assert body["mfa_required"] is False

    auth = body["tokens"]
    assert auth["token_type"] == "Bearer"
    assert auth["expires_in"] == 2 * 3600, "访问令牌 ≤2 h（M01 §1）"
    assert auth["access_token"] and auth["refresh_token"]
    assert auth["access_token"] != auth["refresh_token"]
    assert auth["session_id"] and auth["refresh_expires_at"]

    profile = body["account"]
    assert profile["account_id"] == str(account.id)
    assert profile["tenant_id"] == str(account.tenant_id)
    assert profile["state"] == "normal"
    assert profile["roles"] == []
    assert "balance" not in profile, "余额归 M06，M01 不读其基表"
    assert "example.com" not in str(profile), "账户视图不得回传邮箱原文"

    # 库里只有哈希
    stored = rows(f.conn, "SELECT access_hash, refresh_hash FROM sessions WHERE id = %s",
                  (auth["session_id"],))[0]
    assert stored["access_hash"] == hashlib.sha256(auth["access_token"].encode()).hexdigest()
    assert stored["refresh_hash"] == hashlib.sha256(auth["refresh_token"].encode()).hexdigest()
    dump = str(rows(f.conn, "SELECT * FROM sessions"))
    assert auth["access_token"] not in dump and auth["refresh_token"] not in dump
    assert auth["access_token"] not in caplog.text
    assert auth["refresh_token"] not in caplog.text

    # 登录成功后清空失败计数并记录 last_login
    auth_row = models.get_user_auth(f.conn, user.id)
    assert auth_row.failed_login_count == 0 and auth_row.last_login_at is not None


def test_login_accepts_phone_identifier(api, f):
    user, _account = f.login_ready()
    f.conn.execute("UPDATE users SET phone_hash = %s WHERE id = %s",
                   (models.hash_pii("+8613800000007"), user.id))
    response = _login(api, "+8613800000007")
    assert response.status_code == 200
    assert response.json()["account"]["state"] == "normal"


def test_login_request_id_is_echoed(api, f):
    f.login_ready()
    response = api.post("/api/v1/auth/login",
                        headers={"X-Request-Id": "req-abc-123"},
                        json={"method": "password", "identifier": "login1@example.com",
                              "secret": PASSWORD})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == "req-abc-123"


# --------------------------------------------------------------------------- 凭据错误
def test_wrong_password_and_unknown_account_look_identical(api, f):
    f.login_ready()
    wrong = _login(api, "login1@example.com", secret="nope")
    unknown = _login(api, "ghost@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert error_of(wrong)["code"] == error_of(unknown)["code"] == 40110
    assert error_of(wrong)["message"] == error_of(unknown)["message"]
    assert error_of(wrong)["type"] == "authentication_error"
    assert error_of(wrong)["request_id"]


def test_login_lockout_after_five_failures(api, f, timeline):
    f.login_ready()
    for _ in range(5):
        assert _login(api, "login1@example.com", secret="bad").status_code == 401

    throttled = _login(api, "login1@example.com")
    assert throttled.status_code == 429
    err = error_of(throttled)
    assert err["code"] == 42901 and err["type"] == "rate_limit_error"
    assert int(throttled.headers["Retry-After"]) > 0

    # 锁定期内即使口令正确也拒绝
    assert _login(api, "login1@example.com").status_code == 429

    timeline.advance(minutes=16)
    assert _login(api, "login1@example.com").status_code == 200
    assert models.get_user_auth(f.conn, models.find_user_by_identifier(
        f.conn, "login1@example.com").id).failed_login_count == 0


def test_closed_account_cannot_login(api, f):
    _user, account = f.login_ready()
    f.conn.execute("UPDATE user_accounts SET state = 'closed', closed_at = now()"
                   " WHERE id = %s", (account.id,))
    response = _login(api, "login1@example.com")
    assert response.status_code == 409
    assert error_of(response)["code"] == 40903


@pytest.mark.parametrize("method,extra", [("sms_code", {}), ("oauth", {"provider": "github"})])
def test_unavailable_login_methods_return_403(api, f, method, extra):
    f.login_ready()
    response = _login(api, "login1@example.com", method=method, **extra)
    assert response.status_code == 403
    assert error_of(response)["code"] == 40303


@pytest.mark.parametrize("payload", [
    {},
    {"method": "password"},
    {"identifier": "x@example.com"},
    {"method": "pin", "identifier": "x@example.com"},
    {"method": "password", "identifier": "x@example.com", "secret": 123},
])
def test_bad_login_body_is_400(api, f, payload):
    f.login_ready()
    response = api.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 400
    assert error_of(response)["code"] == 40001


def test_malformed_json_is_400(api, f):
    f.login_ready()
    response = api.post("/api/v1/auth/login", content=b"{not json",
                        headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert error_of(response)["reason"] == "malformed_json"


# --------------------------------------------------------------------------- 刷新轮换
def test_refresh_rotates_and_detects_replay(api, f):
    f.login_ready()
    first = _login(api, "login1@example.com").json()["tokens"]

    response = api.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert response.status_code == 200
    second = response.json()
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]
    assert second["session_id"] != first["session_id"], "轮换出新会话，旧会话只保留 access"
    assert second["expires_in"] == 2 * 3600

    # 旧 refresh 重放 → 40103
    replay = api.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401
    assert error_of(replay)["code"] == 40103

    # 旧 access 仍可用到自然过期（未被轮换连坐）
    profile = api.get("/api/v1/user/profile", headers=bearer(first["access_token"]))
    assert profile.status_code == 200
    # 新 access 也可用
    assert api.get("/api/v1/user/profile",
                   headers=bearer(second["access_token"])).status_code == 200


def test_refresh_inherits_absolute_expiry(api, f, timeline):
    f.login_ready()
    first = _login(api, "login1@example.com").json()["tokens"]
    absolute = scalar(f.conn, "SELECT absolute_expires_at FROM sessions WHERE id = %s",
                      (first["session_id"],))

    timeline.advance(hours=1)
    second = api.post("/api/v1/auth/refresh",
                      json={"refresh_token": first["refresh_token"]}).json()
    new_absolute = scalar(f.conn, "SELECT absolute_expires_at FROM sessions WHERE id = %s",
                          (second["session_id"],))
    assert new_absolute == absolute, "刷新不延长绝对过期时间"


def test_refresh_rejects_unknown_expired_and_revoked(api, f, timeline):
    f.login_ready()
    assert api.post("/api/v1/auth/refresh",
                    json={"refresh_token": "nope"}).status_code == 401

    first = _login(api, "login1@example.com").json()["tokens"]
    timeline.advance(days=31)
    expired = api.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert expired.status_code == 401
    assert error_of(expired)["code"] == 40102


def test_refresh_requires_token(api, f):
    f.login_ready()
    response = api.post("/api/v1/auth/refresh", json={})
    assert response.status_code == 400
    assert error_of(response)["code"] == 40001


# --------------------------------------------------------------------------- 登出
def test_logout_revokes_current_session_idempotently(api, f):
    f.login_ready()
    auth = _login(api, "login1@example.com").json()["tokens"]
    response = api.post("/api/v1/auth/logout", headers=bearer(auth["access_token"]), json={})
    assert response.status_code == 200
    body = response.json()
    assert body["revoked_sessions"] == 1 and body["revoked_at"]

    replay = api.post("/api/v1/auth/logout", headers=bearer(auth["access_token"]), json={})
    assert replay.status_code == 200
    assert replay.json()["revoked_sessions"] == 0
    assert datetime.fromisoformat(replay.json()["revoked_at"]) == \
        datetime.fromisoformat(body["revoked_at"])

    assert api.get("/api/v1/user/profile",
                   headers=bearer(auth["access_token"])).status_code == 401


def test_logout_all_devices_bumps_epoch(api, f):
    _user, account = f.login_ready()
    a = _login(api, "login1@example.com").json()["tokens"]
    b = _login(api, "login1@example.com").json()["tokens"]

    response = api.post("/api/v1/auth/logout", headers=bearer(a["access_token"]),
                        json={"all_devices": True})
    assert response.status_code == 200
    assert response.json()["revoked_sessions"] == 2
    assert models.get_account(f.conn, account.id).session_epoch == 1
    for token in (a["access_token"], b["access_token"]):
        assert api.get("/api/v1/user/profile", headers=bearer(token)).status_code == 401


def test_logout_requires_bearer(api, f):
    f.login_ready()
    assert api.post("/api/v1/auth/logout", json={}).status_code == 401


# --------------------------------------------------------------------------- 会话时效
def test_user_access_token_expires_after_two_hours(api, f, timeline):
    f.login_ready()
    auth = _login(api, "login1@example.com").json()["tokens"]
    timeline.advance(hours=1, minutes=59)
    assert api.get("/api/v1/user/profile", headers=bearer(auth["access_token"])).status_code == 200
    timeline.advance(minutes=2)
    expired = api.get("/api/v1/user/profile", headers=bearer(auth["access_token"]))
    assert expired.status_code == 401
    assert error_of(expired)["code"] == 40102


def test_admin_session_slides_forwards(f, timeline):
    _user, account = f.login_ready()
    session, access, _ = tokens._issue_session(
        f.conn, account=account, kind="admin", moment=timeline.moment, mfa=True,
        access_ttl=timedelta(minutes=30),
        absolute=timeline.moment + timedelta(hours=12))
    assert session.idle_expires_at == timeline.moment + timedelta(
        minutes=models.SESSION_IDLE_MINUTES)

    timeline.advance(minutes=10)                     # 10 < 15 min 空闲窗口
    ctx = tokens.authenticate(f.conn, access, now=timeline.moment)
    assert ctx.session.expires_at == timeline.moment + timedelta(
        minutes=models.SESSION_SLIDE_MINUTES)
    assert ctx.step_up_active is False


def test_admin_session_idle_timeout(f, timeline):
    _user, account = f.login_ready()
    session, access, _ = tokens._issue_session(
        f.conn, account=account, kind="admin", moment=timeline.moment, mfa=True,
        access_ttl=timedelta(minutes=30),
        absolute=timeline.moment + timedelta(hours=12))
    timeline.advance(minutes=models.SESSION_IDLE_MINUTES + 1)
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.authenticate(f.conn, access, now=timeline.moment)
    assert exc.value.reason == "idle_timeout"
    assert models.get_session(f.conn, session.id).revoked_at is not None


def test_admin_session_absolute_cap_is_twelve_hours(f, timeline):
    _user, account = f.login_ready()
    session, access, _ = tokens._issue_session(
        f.conn, account=account, kind="admin", moment=timeline.moment, mfa=True,
        access_ttl=timedelta(hours=1),
        absolute=timeline.moment + timedelta(days=2))
    assert session.absolute_expires_at == timeline.moment + timedelta(hours=12), \
        "后台会话 12 h 绝对上限（03-facts §8）"


def test_expire_idle_job_revokes_due_sessions(f, timeline):
    _user, account = f.login_ready()
    session, _access, _ = tokens._issue_session(
        f.conn, account=account, kind="admin", moment=timeline.moment, mfa=True,
        access_ttl=timedelta(minutes=30),
        absolute=timeline.moment + timedelta(hours=12))
    assert tokens.expire_idle(f.conn, now=timeline.moment) == 0
    timeline.advance(minutes=models.SESSION_IDLE_MINUTES + 1)
    assert tokens.expire_idle(f.conn, now=timeline.moment) == 1
    assert tokens.expire_idle(f.conn, now=timeline.moment) == 0          # 可重放
    assert models.get_session(f.conn, session.id).revoked_at is not None


def test_role_change_invalidates_live_session(f, timeline):
    """A4：角色变更后 epoch 不符 → 40102。"""
    _user, account = f.login_ready()
    session, access, _ = tokens._issue_session(
        f.conn, account=account, kind="user", moment=timeline.moment, mfa=False,
        access_ttl=timedelta(hours=2),
        absolute=timeline.moment + timedelta(days=30),
        refresh_ttl=timedelta(days=30))
    assert tokens.authenticate(f.conn, access, now=timeline.moment).account.id == account.id
    models.bind_role(f.conn, account_id=account.id, admin_role="OPS",
                     granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=timeline.moment)
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.authenticate(f.conn, access, now=timeline.moment)
    assert exc.value.reason == "revoked" or exc.value.reason == "epoch_mismatch"
    assert models.get_session(f.conn, session.id).revoked_at is not None
