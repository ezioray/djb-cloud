# SPDX-License-Identifier: Apache-2.0
"""MFA 与扫码中间态（tasks-11 验收：MFA / 扫码中间态 / 不存明文）。

覆盖：
- ``mfa_state`` 迁移：none → pending → enabled → none，非法迁移与非法因子 400；
- 因子只存 scrypt 派生串 + salt（库里没有明文 PIN，日志也没有）；
- 登录分支：未启用 → 正常发令牌；已启用缺码 → ``mfa_required=true`` + **短期令牌**，
  该令牌不能访问业务端点；码错 → 40110（与口令错误同码）；码对 → 正式令牌；
- step-up：5 分钟窗口、``require_step_up`` 放行/拒绝、未启用 MFA 时 40902；
- 扫码：created → scanned → confirmed → consumed 全链路、抢票 40905、120 s 过期、
  票据只存哈希、明文不入日志、轮询走 /auth/login 复用端点。
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

import pytest

from app.identity import credentials, mfa, models, scan, tokens

from conftest import bearer, error_of, rows, scalar

PASSWORD = "S3cret!"
PIN = "123456"


def _auth(api, f, *, mfa_code: str | None = None):
    payload = {"method": "password", "identifier": "login1@example.com", "secret": PASSWORD}
    if mfa_code is not None:
        payload["mfa_code"] = mfa_code
    return api.post("/api/v1/auth/login", json=payload)


def _enable_mfa(f, account, *, pin: str = PIN):
    mfa.enroll(f.conn, account.id, pin, now=f.moment)
    mfa.confirm(f.conn, account.id, pin, now=f.moment)


# --------------------------------------------------------------------------- 因子生命周期
def test_mfa_state_machine(f):
    _user, account = f.login_ready()
    assert mfa.status(f.conn, account.id)["mfa_state"] == "none"

    mfa.enroll(f.conn, account.id, PIN, now=f.moment)
    assert mfa.status(f.conn, account.id)["mfa_state"] == "pending"
    enabled_at = mfa.confirm(f.conn, account.id, PIN, now=f.moment)
    status = mfa.status(f.conn, account.id)
    assert status["mfa_state"] == "enabled"
    assert datetime.fromisoformat(status["mfa_enabled_at"]) == enabled_at

    with pytest.raises(models.StateConflict):                 # 已启用不可重复登记
        mfa.enroll(f.conn, account.id, PIN, now=f.moment)

    mfa.disable(f.conn, account.id, PIN, now=f.moment)
    auth = models.get_user_auth(f.conn, _user.id)
    assert auth.mfa_state == "none" and auth.mfa_secret_hash is None and auth.mfa_salt is None


def test_mfa_factor_is_hashed_only(f, caplog):
    user, account = f.login_ready()
    with caplog.at_level(logging.DEBUG, logger="djb.identity"):
        mfa.enroll(f.conn, account.id, PIN, now=f.moment)
    auth = models.get_user_auth(f.conn, user.id)
    assert auth.mfa_secret_hash and auth.mfa_secret_hash.startswith("scrypt$")
    assert auth.mfa_secret_hash != PIN and PIN not in auth.mfa_secret_hash
    dump = str(rows(f.conn, "SELECT * FROM users WHERE id = %s", (user.id,))[0])
    assert PIN not in dump, "因子明文不得入库"
    assert PIN not in caplog.text


def test_mfa_guards(f):
    _user, account = f.login_ready()
    with pytest.raises(models.InvalidArgument):               # 非 6 位数字
        mfa.enroll(f.conn, account.id, "12ab56", now=f.moment)
    with pytest.raises(models.InvalidArgument):
        mfa.enroll(f.conn, account.id, "12345", now=f.moment)
    with pytest.raises(Exception) as exc:                     # 未登记就确认
        mfa.confirm(f.conn, account.id, PIN, now=f.moment)
    assert getattr(exc.value, "reason", "") in ("mfa_not_enrolled", "mfa_not_enabled")

    mfa.enroll(f.conn, account.id, PIN, now=f.moment)
    with pytest.raises(Exception) as exc:
        mfa.confirm(f.conn, account.id, "000000", now=f.moment)
    assert getattr(exc.value, "code", None) == "40110"

    mfa.disable(f.conn, account.id, PIN, now=f.moment)
    with pytest.raises(Exception) as exc:
        mfa.disable(f.conn, account.id, PIN, now=f.moment)
    assert getattr(exc.value, "reason", "") == "mfa_not_enabled"


def test_mfa_enroll_requires_writable_account(f):
    _user, personal = f.login_ready()
    frozen = f.freeze(personal)
    with pytest.raises(models.AccountReadOnly):
        mfa.enroll(f.conn, frozen.id, PIN, now=f.moment)


# --------------------------------------------------------------------------- 登录分支
def test_login_requires_mfa_when_enabled(api, f):
    _user, account = f.login_ready()
    _enable_mfa(f, account)

    response = _auth(api, f)
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    short = body["tokens"]
    assert short["expires_in"] == 5 * 60, "MFA 未完成只发短期令牌（M01 §1）"
    assert "refresh_token" not in short or short["refresh_token"] is None

    # 短期令牌不能访问业务端点
    profile = api.get("/api/v1/user/profile", headers=bearer(short["access_token"]))
    assert profile.status_code == 401
    assert error_of(profile)["code"] == 40102
    assert error_of(profile)["reason"] == "mfa_pending"


def test_login_with_wrong_mfa_code_is_40110(api, f):
    _user, account = f.login_ready()
    _enable_mfa(f, account)
    response = _auth(api, f, mfa_code="000000")
    assert response.status_code == 401
    assert error_of(response)["code"] == 40110


def test_login_with_mfa_code_issues_full_session(api, f):
    _user, account = f.login_ready()
    _enable_mfa(f, account)
    response = _auth(api, f, mfa_code=PIN)
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is False
    assert body["tokens"]["expires_in"] == 2 * 3600
    assert body["tokens"]["refresh_token"]
    assert api.get("/api/v1/user/profile",
                   headers=bearer(body["tokens"]["access_token"])).status_code == 200


def test_pending_mfa_still_logs_in_without_code(api, f):
    """pending（已登记未确认）不拦截登录，只有 enabled 才要求第二因子。"""
    _user, account = f.login_ready()
    mfa.enroll(f.conn, account.id, PIN, now=f.moment)
    body = _auth(api, f).json()
    assert body["mfa_required"] is False
    assert body["tokens"]["refresh_token"]


# --------------------------------------------------------------------------- step-up
def test_step_up_window_and_gate(f, timeline):
    _user, account = f.login_ready()
    _enable_mfa(f, account)
    session, access, _ = tokens._issue_session(
        f.conn, account=account, kind="user", moment=timeline.moment, mfa=True,
        access_ttl=timedelta(hours=2), absolute=timeline.moment + timedelta(days=30))

    ctx = tokens.authenticate(f.conn, access, now=timeline.moment)
    with pytest.raises(Exception) as exc:                     # 未 step-up → 424/42401
        tokens.require_step_up(ctx, now=timeline.moment)
    assert exc.value.code == "42401"

    grant = tokens.step_up(f.conn, access_token=access, code=PIN, now=timeline.moment)
    assert grant.expires_at == timeline.moment + timedelta(minutes=models.STEP_UP_MINUTES)
    elevated = tokens.authenticate(f.conn, access, now=timeline.moment)
    assert elevated.step_up_active is True
    assert tokens.require_step_up(elevated, now=timeline.moment).account.id == account.id
    assert tokens.authenticate(f.conn, grant.access_token,
                               now=timeline.moment).session.kind == "step_up"

    timeline.advance(minutes=models.STEP_UP_MINUTES + 1)
    with pytest.raises(Exception) as exc:
        tokens.require_step_up(elevated, now=timeline.moment)
    assert exc.value.code == "42401"
    with pytest.raises(models.SessionInvalid):
        tokens.authenticate(f.conn, grant.access_token, now=timeline.moment)


def test_step_up_requires_mfa_and_valid_code(f):
    _user, account = f.login_ready()
    session, access, _ = tokens._issue_session(
        f.conn, account=account, kind="user", moment=f.moment, mfa=False,
        access_ttl=timedelta(hours=2), absolute=f.moment + timedelta(days=30))
    with pytest.raises(Exception) as exc:                     # 未启用 MFA
        tokens.step_up(f.conn, access_token=access, code=PIN, now=f.moment)
    assert exc.value.code == "40902"

    _enable_mfa(f, account)
    with pytest.raises(Exception) as exc:                     # 码错 → 40110
        tokens.step_up(f.conn, access_token=access, code="000000", now=f.moment)
    assert exc.value.code == "40110"


# --------------------------------------------------------------------------- 扫码
def _scan_login(api, ticket: str):
    return api.post("/api/v1/auth/login",
                    json={"method": "oauth", "provider": "qr", "identifier": ticket})


def test_scan_flow_end_to_end(api, f, caplog):
    _user, account = f.login_ready()
    with caplog.at_level(logging.DEBUG, logger="djb.identity"):
        ticket_row, ticket = scan.create(f.conn, now=f.moment)

    # 只存哈希
    stored = rows(f.conn, "SELECT ticket_hash FROM identity_scan_tickets WHERE id = %s",
                  (ticket_row.id,))[0]
    assert stored["ticket_hash"] == credentials.token_hash(ticket)
    assert ticket not in str(stored) and ticket not in caplog.text

    pending = _scan_login(api, ticket)
    assert pending.status_code == 202
    assert pending.json()["status"] == "pending"          # 对外枚举：created → pending
    assert pending.json()["scan"]["retry_after_s"] >= 1

    scan.scan(f.conn, ticket, account_id=account.id, now=f.moment)
    assert _scan_login(api, ticket).json()["status"] == "scanned"

    scan.confirm(f.conn, ticket, account_id=account.id, now=f.moment)
    done = _scan_login(api, ticket)
    assert done.status_code == 200
    body = done.json()
    assert body["mfa_required"] is False
    assert body["tokens"]["refresh_token"]
    assert body["account"]["account_id"] == str(account.id)
    assert api.get("/api/v1/user/profile",
                   headers=bearer(body["tokens"]["access_token"])).status_code == 200

    # 一次性：再换 → 40905
    again = _scan_login(api, ticket)
    assert again.status_code == 409
    assert error_of(again)["code"] == 40905


def test_scan_ticket_expires_after_120_seconds(api, f, timeline):
    _user, account = f.login_ready()
    _row, ticket = scan.create(f.conn, now=timeline.moment)
    scan.scan(f.conn, ticket, account_id=account.id, now=timeline.moment)
    timeline.advance(seconds=models.SCAN_TICKET_TTL_SECONDS + 1)

    assert scan.poll(f.conn, ticket, now=timeline.moment).status == "expired"
    response = _scan_login(api, ticket)
    assert response.status_code == 409
    assert error_of(response)["code"] == 40905


def test_scan_confirm_must_match_scanner(f):
    _user_a, account_a = f.login_ready()
    _user_b, account_b = f.login_ready()
    _row, ticket = scan.create(f.conn, now=f.moment)
    scan.scan(f.conn, ticket, account_id=account_a.id, now=f.moment)
    with pytest.raises(Exception) as exc:
        scan.confirm(f.conn, ticket, account_id=account_b.id, now=f.moment)
    assert exc.value.code == "40905"


def test_scan_unknown_and_double_scan(f):
    _user, account = f.login_ready()
    with pytest.raises(Exception) as exc:
        scan.poll(f.conn, "no-such-ticket", now=f.moment)
    assert exc.value.code == "40905"

    _row, ticket = scan.create(f.conn, now=f.moment)
    scan.scan(f.conn, ticket, account_id=account.id, now=f.moment)
    with pytest.raises(Exception) as exc:
        scan.scan(f.conn, ticket, account_id=account.id, now=f.moment)
    assert exc.value.code == "40905"


def test_scan_for_mfa_enabled_account_is_rejected(api, f):
    _user, account = f.login_ready()
    _enable_mfa(f, account)
    _row, ticket = scan.create(f.conn, now=f.moment)
    scan.scan(f.conn, ticket, account_id=account.id, now=f.moment)
    scan.confirm(f.conn, ticket, account_id=account.id, now=f.moment)
    response = _scan_login(api, ticket)
    assert response.status_code == 401
    assert error_of(response)["code"] == 40110
