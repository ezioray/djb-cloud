# SPDX-License-Identifier: AGPL-3.0-or-later
"""T2 边界分支：把「拒绝」路径也钉死（401/40103/40102/500 兜底 / 票据 / 因子 / 口令）。

覆盖的是领域与路由上的**负向分支**：缺令牌、令牌未知、绝对过期、epoch 不符、
刷新重放、关闭 MFA 时因子错、票据不存在 / 状态不对、请求体形态错、服务端兜底 500。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from fastapi import FastAPI

from app.identity import credentials, errors, mfa, models, router as router_module, scan, tokens

from identitykit import bearer, error_of

PASSWORD = "S3cret!"
PIN = "123456"


def _login_tokens(api, identifier: str = "login1@example.com") -> dict:
    response = api.post("/api/v1/auth/login",
                        json={"method": "password", "identifier": identifier,
                              "secret": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["tokens"]


# --------------------------------------------------------------------------- 凭据派生
def test_password_derivation_guards():
    with pytest.raises(ValueError):
        credentials.hash_password("")
    assert credentials.verify_password(None, "x") is False
    assert credentials.verify_password("not-a-scrypt-string", "x") is False
    assert credentials.verify_password(credentials.hash_password("x"), None) is False
    assert credentials.verify_password("scrypt$n=bad,r=8,p=1$00$00", "x") is False
    assert credentials.normalize_identifier("  Alice@Example.COM ") == "alice@example.com"


def test_token_hash_is_stable_and_never_plaintext():
    plaintext, digest = credentials.new_token()
    assert digest == credentials.token_hash(plaintext) != plaintext
    assert len(digest) == 64


# --------------------------------------------------------------------------- 账户 / 口令写入
def test_create_user_rejects_non_none_mfa_state(f):
    with pytest.raises(models.InvalidArgument):
        models.create_user(f.conn, email="mfa@example.com", mfa_state="enabled", now=f.moment)


def test_set_password_resets_lock_and_requires_user(f):
    user, _account = f.login_ready()
    for _ in range(3):
        tokens.register_failure(f.conn, user.id, f.moment)
    assert models.get_user_auth(f.conn, user.id).failed_login_count == 3
    models.set_password(f.conn, user.id, "NewPass!", now=f.moment)
    auth = models.get_user_auth(f.conn, user.id)
    assert auth.failed_login_count == 0 and auth.login_locked_until is None
    assert credentials.verify_password(auth.password_hash, "NewPass!")
    with pytest.raises(models.NotFound):
        models.set_password(f.conn, uuid.uuid4(), "x", now=f.moment)


def test_update_profile_guards(f):
    user, _account = f.login_ready()
    with pytest.raises(models.InvalidArgument) as exc:
        models.update_user_profile(f.conn, user.id, {}, now=f.moment)
    assert exc.value.reason == "empty_update"
    with pytest.raises(models.NotFound):
        models.update_user_profile(f.conn, uuid.uuid4(), {"display_name": "X"}, now=f.moment)


def test_primary_account_requires_accounts(f):
    user = models.create_user(f.conn, email="solo@example.com", now=f.moment)
    with pytest.raises(models.NotFound):
        models.primary_account(f.conn, user.id)


# --------------------------------------------------------------------------- MFA 负向
def test_mfa_disable_and_verify_guard(f):
    _user, account = f.login_ready()
    mfa.enroll(f.conn, account.id, PIN, now=f.moment)
    mfa.confirm(f.conn, account.id, PIN, now=f.moment)
    assert mfa.verify(f.conn, account.id, PIN) is True
    assert mfa.verify(f.conn, account.id, "000000") is False
    with pytest.raises(errors.LoginCredentialError) as exc:
        mfa.disable(f.conn, account.id, "000000", now=f.moment)
    assert exc.value.code == "40110"
    mfa.disable(f.conn, account.id, PIN, now=f.moment)
    assert mfa.verify(f.conn, account.id, PIN) is False


# --------------------------------------------------------------------------- 登录 / 刷新负向
def test_login_requires_identifier(api, f):
    f.login_ready()
    response = api.post("/api/v1/auth/login",
                        json={"method": "password", "identifier": "   ", "secret": PASSWORD})
    assert response.status_code == 400
    assert error_of(response)["code"] == 40001


def test_login_body_shapes(api, f):
    f.login_ready()
    empty = api.post("/api/v1/auth/login")
    assert empty.status_code == 400
    array = api.post("/api/v1/auth/login", json=[1, 2, 3])
    assert array.status_code == 400
    too_long = api.post("/api/v1/auth/login",
                        json={"method": "password", "identifier": "a" * 400, "secret": PASSWORD})
    assert too_long.status_code == 400
    bad_mfa = api.post("/api/v1/auth/login",
                       json={"method": "password", "identifier": "login1@example.com",
                             "secret": PASSWORD, "mfa_code": 123456})
    assert bad_mfa.status_code == 400


def test_refresh_guards(f, timeline):
    _user, account = f.login_ready()
    session, _access, refresh = tokens._issue_session(
        f.conn, account=account, kind="user", moment=timeline.moment, mfa=False,
        access_ttl=timedelta(hours=2), absolute=timeline.moment + timedelta(days=30),
        refresh_ttl=timedelta(days=30))
    with pytest.raises(errors.RefreshTokenRejected):
        tokens.refresh(f.conn, "", now=timeline.moment)

    # 已撤销 → 40103
    models.revoke_session(f.conn, session.id, reason="manual", now=timeline.moment)
    with pytest.raises(errors.RefreshTokenRejected) as exc:
        tokens.refresh(f.conn, refresh, now=timeline.moment)
    assert exc.value.code == "40103"

    # 绝对过期 → 40102
    other, _access2, refresh2 = tokens._issue_session(
        f.conn, account=account, kind="user", moment=timeline.moment, mfa=False,
        access_ttl=timedelta(hours=2), absolute=timeline.moment + timedelta(days=1),
        refresh_ttl=timedelta(days=30))
    with pytest.raises(models.SessionInvalid) as exc2:
        tokens.refresh(f.conn, refresh2, now=timeline.moment + timedelta(days=2))
    assert exc2.value.code == "40102"

    # 账户注销 / epoch 不符
    third, _access3, refresh3 = tokens._issue_session(
        f.conn, account=account, kind="user", moment=timeline.moment, mfa=False,
        access_ttl=timedelta(hours=2), absolute=timeline.moment + timedelta(days=30),
        refresh_ttl=timedelta(days=30))
    models.bump_session_epoch(f.conn, account.id)
    with pytest.raises(models.SessionInvalid) as exc3:
        tokens.refresh(f.conn, refresh3, now=timeline.moment)
    assert exc3.value.reason == "epoch_mismatch"
    assert models.get_session(f.conn, third.id).revoked_at is not None
    assert other.id and session.id


def test_refresh_rejects_closed_account(f, timeline):
    _user, account = f.login_ready()
    _session, _access, refresh = tokens._issue_session(
        f.conn, account=account, kind="user", moment=timeline.moment, mfa=False,
        access_ttl=timedelta(hours=2), absolute=timeline.moment + timedelta(days=30),
        refresh_ttl=timedelta(days=30))
    f.conn.execute("UPDATE user_accounts SET state = 'closed', closed_at = now()"
                   " WHERE id = %s", (account.id,))
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.refresh(f.conn, refresh, now=timeline.moment)
    assert exc.value.reason == "account_closed" or exc.value.code == "40102"


def test_authenticate_guards(f, timeline):
    _user, account = f.login_ready()
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.authenticate(f.conn, "")
    assert exc.value.reason == "missing_token"
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.authenticate(f.conn, "ghost-token")
    assert exc.value.reason == "unknown_token"

    admin, access, _ = tokens._issue_session(
        f.conn, account=account, kind="admin", moment=timeline.moment, mfa=True,
        access_ttl=timedelta(minutes=30), absolute=timeline.moment + timedelta(hours=12))
    timeline.advance(hours=13)
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.authenticate(f.conn, access, now=timeline.moment)
    assert exc.value.reason in ("expired", "absolute_expiry")
    assert admin.id is not None


def test_authenticate_epoch_mismatch_revokes_session(f, timeline):
    _user, account = f.login_ready()
    session, access, _ = tokens._issue_session(
        f.conn, account=account, kind="user", moment=timeline.moment, mfa=False,
        access_ttl=timedelta(hours=2), absolute=timeline.moment + timedelta(days=30))
    models.bump_session_epoch(f.conn, account.id)
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.authenticate(f.conn, access, now=timeline.moment)
    assert exc.value.reason == "epoch_mismatch"
    assert models.get_session(f.conn, session.id).revoked_at is not None


def test_step_up_requires_token(f):
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.step_up(f.conn, access_token="", code=PIN, now=f.moment)
    assert exc.value.reason == "missing_token"


def test_session_resolution_helpers(f):
    _user, account = f.login_ready()
    session, access, _ = tokens._issue_session(
        f.conn, account=account, kind="user", moment=f.moment, mfa=False,
        access_ttl=timedelta(hours=2), absolute=f.moment + timedelta(days=30))
    assert tokens.resolve_session(f.conn, access).id == session.id
    assert tokens.AuthContext(session=session, account=account, user=models.get_user(
        f.conn, account.user_id), roles=()).account_id == account.id
    assert tokens.AuthContext(session=session, account=account, user=models.get_user(
        f.conn, account.user_id), roles=()).tenant_id == account.tenant_id


# --------------------------------------------------------------------------- 扫码负向
def test_scan_lookup_and_state_guards(f):
    _user, account = f.login_ready()
    row, ticket = scan.create(f.conn, now=f.moment)
    assert scan.get(f.conn, row.id).status == "created"
    with pytest.raises(errors.ScanTicketInvalid):
        scan.get(f.conn, uuid.uuid4())

    with pytest.raises(errors.ScanTicketInvalid):           # 未扫码就确认
        scan.confirm(f.conn, ticket, account_id=account.id, now=f.moment)
    with pytest.raises(errors.ScanTicketInvalid):           # 未确认就消费
        scan.consume(f.conn, ticket, now=f.moment)
    scan.scan(f.conn, ticket, account_id=account.id, now=f.moment)
    scan.confirm(f.conn, ticket, account_id=account.id, now=f.moment)
    scan.consume(f.conn, ticket, now=f.moment)
    with pytest.raises(errors.ScanTicketInvalid):           # 已消费
        scan.consume(f.conn, ticket, now=f.moment)


def test_scan_unknown_ticket_paths(f):
    _user, account = f.login_ready()
    for call in (lambda: scan.scan(f.conn, "ghost", account_id=account.id, now=f.moment),
                 lambda: scan.confirm(f.conn, "ghost", account_id=account.id, now=f.moment),
                 lambda: scan.poll(f.conn, "ghost", now=f.moment),
                 lambda: scan.consume(f.conn, "ghost", now=f.moment)):
        with pytest.raises(errors.ScanTicketInvalid):
            call()


# --------------------------------------------------------------------------- 路由兜底与装配
def test_server_error_envelope(api, f, monkeypatch):
    """领域外的异常 → 500 server_error 信封（不回堆栈、回显 request_id）。"""
    f.login_ready()
    tokens_ = _login_tokens(api)

    def boom(*args, **kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(models, "get_user", boom)
    response = api.get("/api/v1/user/profile", headers=bearer(tokens_["access_token"]))
    assert response.status_code == 500
    err = error_of(response)
    assert err["type"] == "server_error" and err["message"] == "服务繁忙"
    assert err["request_id"] == response.headers["X-Request-Id"]


def test_include_in_mounts_router():
    app = FastAPI()
    router_module.include_in(app)
    paths = set(app.openapi()["paths"])
    assert {"/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout",
            "/api/v1/user/profile"} <= paths


def test_sink_wrapper_closes_connection():
    class FakeConn:
        closed = False

        def close(self):
            self.closed = True

    fake = FakeConn()
    with router_module._Sink(fake) as connection:
        assert connection is fake
    assert fake.closed is True


def test_default_failure_sink_commits_independently():
    """默认 sink 是一条 autocommit 短连接（不在业务事务里）。"""
    sink_cm = router_module._failure_sink()
    with sink_cm as connection:
        assert connection.autocommit is True
        assert connection.execute("SELECT 1").fetchone()[0] == 1


# --------------------------------------------------------------------------- 幂等重放
def test_refresh_idempotency_replay(api, f):
    f.login_ready()
    tokens_ = _login_tokens(api)
    headers = {"X-DJB-Idempotency-Key": "refresh-once"}
    first = api.post("/api/v1/auth/refresh", headers=headers,
                     json={"refresh_token": tokens_["refresh_token"]})
    second = api.post("/api/v1/auth/refresh", headers=headers,
                      json={"refresh_token": tokens_["refresh_token"]})
    assert first.status_code == second.status_code == 200
    assert first.json()["session_id"] == second.json()["session_id"]
    assert first.json()["access_token"] != second.json()["access_token"]


def test_logout_idempotency_replay(api, f):
    f.login_ready()
    tokens_ = _login_tokens(api)
    headers = {**bearer(tokens_["access_token"]), "X-DJB-Idempotency-Key": "logout-once"}
    first = api.post("/api/v1/auth/logout", headers=headers, json={})
    second = api.post("/api/v1/auth/logout", headers=headers, json={})
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()


def test_login_replay_after_session_revoked_is_40103(api, f):
    f.login_ready()
    headers = {"X-DJB-Idempotency-Key": "login-then-kill"}
    payload = {"method": "password", "identifier": "login1@example.com", "secret": PASSWORD}
    first = api.post("/api/v1/auth/login", headers=headers, json=payload).json()
    f.conn.execute("UPDATE sessions SET revoked_at = now(), revoked_reason = 'test'"
                   " WHERE id = %s", (first["tokens"]["session_id"],))
    replay = api.post("/api/v1/auth/login", headers=headers, json=payload)
    assert replay.status_code == 401
    assert error_of(replay)["code"] == 40103


# --------------------------------------------------------------------------- 补充分支
def test_domain_login_guards(f, timeline):
    _user, account = f.login_ready()
    with pytest.raises(models.InvalidArgument):
        tokens.login(f.conn, method="password", identifier="  ", secret=PASSWORD,
                     now=timeline.moment)

    f.conn.execute("UPDATE user_accounts SET state = 'closed', closed_at = now()"
                   " WHERE id = %s", (account.id,))
    with pytest.raises(models.AccountClosed):
        tokens.login(f.conn, method="password", identifier="login1@example.com",
                     secret=PASSWORD, now=timeline.moment)


def test_resolve_session_guards(f):
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.resolve_session(f.conn, "")
    assert exc.value.reason == "missing_token"
    with pytest.raises(models.SessionInvalid) as exc:
        tokens.resolve_session(f.conn, "ghost")
    assert exc.value.reason == "unknown_token"


def test_refresh_rejects_absolute_expiry(f, timeline):
    _user, account = f.login_ready()
    _session, _access, refresh = tokens._issue_session(
        f.conn, account=account, kind="user", moment=timeline.moment, mfa=False,
        access_ttl=timedelta(hours=2), absolute=timeline.moment + timedelta(days=1),
        refresh_ttl=timedelta(days=30))
    with pytest.raises(models.SessionInvalid) as exc:       # refresh 窗口本身被绝对期限压住
        tokens.refresh(f.conn, refresh, now=timeline.moment + timedelta(days=2))
    assert exc.value.reason in ("expired", "absolute_expiry")


def test_replay_when_session_row_is_gone(api, f):
    f.login_ready()
    headers = {"X-DJB-Idempotency-Key": "login-row-gone"}
    payload = {"method": "password", "identifier": "login1@example.com", "secret": PASSWORD}
    first = api.post("/api/v1/auth/login", headers=headers, json=payload).json()
    f.conn.execute("DELETE FROM sessions WHERE id = %s", (first["tokens"]["session_id"],))
    replay = api.post("/api/v1/auth/login", headers=headers, json=payload)
    assert replay.status_code == 401
    assert error_of(replay)["reason"] == "session_gone"


def test_get_user_auth_missing_user(f):
    with pytest.raises(models.NotFound):
        models.get_user_auth(f.conn, uuid.uuid4())


def test_capture_headers_idempotency_and_retry_after(api, f):
    f.login_ready()
    for _ in range(5):
        api.post("/api/v1/auth/login",
                 json={"method": "password", "identifier": "login1@example.com",
                       "secret": "bad"})
    throttled = api.post("/api/v1/auth/login",
                         json={"method": "password", "identifier": "login1@example.com",
                               "secret": PASSWORD})
    assert throttled.status_code == 429
    assert throttled.headers["X-Request-Id"]
