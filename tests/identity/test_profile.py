# SPDX-License-Identifier: Apache-2.0
"""账户视图与幂等（tasks-11：/user/profile GET/PATCH + X-DJB-Idempotency-Key）。

覆盖：
- 认证闸门：无 Bearer / 错 Bearer → 401 40102；
- GET：脱敏视图（无邮箱 / 无 balance）、角色来自 role_bindings、closed 账户拒绝；
- PATCH：只允许 display_name / locale；身份字段与未知字段 → 400；取值校验；
- 只读态（frozen / closing）禁止改档案 → 403 40304；
- 幂等：同键同载荷回放首次响应（不重复落库）、同键不同载荷 → 409 40919；
  登录接口的幂等重放**不产生第二个会话**。
"""
from __future__ import annotations

import pytest

from app.identity import models, state

from conftest import bearer, error_of, rows, scalar

PASSWORD = "S3cret!"


def _login(api, identifier: str = "login1@example.com") -> dict:
    response = api.post("/api/v1/auth/login",
                        json={"method": "password", "identifier": identifier,
                              "secret": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["tokens"]


# --------------------------------------------------------------------------- GET
def test_profile_requires_bearer(api, f):
    f.login_ready()
    response = api.get("/api/v1/user/profile")
    assert response.status_code == 401
    err = error_of(response)
    assert err["code"] == 40102 and err["type"] == "authentication_error"

    bad = api.get("/api/v1/user/profile", headers=bearer("not-a-token"))
    assert bad.status_code == 401


def test_profile_view_is_redacted(api, f):
    user, account = f.login_ready()
    models.update_user_profile(f.conn, user.id, {"display_name": "小明"}, now=f.moment)
    import uuid

    models.bind_role(f.conn, account_id=account.id, admin_role="CS",
                     granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    tokens = _login(api)
    # 角色变更会 epoch++，因此重新登录拿新会话
    tokens = _login(api)

    response = api.get("/api/v1/user/profile", headers=bearer(tokens["access_token"]))
    assert response.status_code == 200
    body = response.json()
    assert body["account_id"] == str(account.id)
    assert body["tenant_id"] == str(account.tenant_id)
    assert body["display_name"] == "小明"
    assert body["locale"] == "zh-CN"
    assert body["state"] == "normal"
    assert body["roles"] == ["CS"]
    assert body["mfa_state"] == "none"
    assert "balance" not in body
    assert "example.com" not in str(body)


def test_profile_closed_account_is_rejected(api, f):
    _user, account = f.login_ready()
    tokens = _login(api)
    f.conn.execute("UPDATE user_accounts SET state = 'closed', closed_at = now()"
                   " WHERE id = %s", (account.id,))
    response = api.get("/api/v1/user/profile", headers=bearer(tokens["access_token"]))
    assert response.status_code == 401
    assert error_of(response)["reason"] == "account_closed"


# --------------------------------------------------------------------------- PATCH
def test_patch_profile_updates_display_fields(api, f):
    user, _account = f.login_ready()
    tokens = _login(api)
    response = api.patch("/api/v1/user/profile", headers=bearer(tokens["access_token"]),
                         json={"display_name": "Ezio", "locale": "en-US"})
    assert response.status_code == 200
    body = response.json()
    assert body["display_name"] == "Ezio" and body["locale"] == "en-US"
    assert models.get_user(f.conn, user.id).display_name == "Ezio"


@pytest.mark.parametrize("payload,reason", [
    ({"state": "normal"}, "immutable_field"),
    ({"account_id": "x"}, "immutable_field"),
    ({"tenant_id": "x"}, "immutable_field"),
    ({"email": "a@b.c"}, "immutable_field"),
    ({}, "empty_update"),
])
def test_patch_profile_rejects_immutable_or_empty(api, f, payload, reason):
    f.login_ready()
    tokens = _login(api)
    response = api.patch("/api/v1/user/profile", headers=bearer(tokens["access_token"]),
                         json=payload)
    assert response.status_code == 400
    err = error_of(response)
    assert err["code"] == 40001 and err["reason"] == reason


@pytest.mark.parametrize("payload", [
    {"display_name": ""},
    {"display_name": "x" * 65},
    {"locale": "中文"},
    {"locale": "zh_CN_extra_long_value"},
])
def test_patch_profile_value_validation(api, f, payload):
    f.login_ready()
    tokens = _login(api)
    response = api.patch("/api/v1/user/profile", headers=bearer(tokens["access_token"]),
                         json=payload)
    assert response.status_code == 400
    assert error_of(response)["code"] == 40001


@pytest.mark.parametrize("state_kind", ["frozen", "closing"])
def test_patch_profile_blocked_on_read_only_states(api, f, state_kind):
    _user, account = f.login_ready()
    tokens = _login(api)
    if state_kind == "frozen":
        f.freeze(account)
    else:
        state.start_closing(f.conn, account.id,
                            checks={"locked_earnings": True, "open_disputes": True,
                                    "negative_balance": True, "open_tickets": True},
                            now=f.moment)
    # 冻结 / 注销会 epoch++ 撤销旧会话（M01 §6.3），frozen / closing 仍可登录（只读）
    tokens = _login(api)
    response = api.patch("/api/v1/user/profile", headers=bearer(tokens["access_token"]),
                         json={"display_name": "Nope"})
    assert response.status_code == 403
    assert error_of(response)["code"] == 40304


# --------------------------------------------------------------------------- 幂等
def test_patch_profile_idempotent_replay(api, f):
    f.login_ready()
    tokens = _login(api)
    headers = {**bearer(tokens["access_token"]), "X-DJB-Idempotency-Key": "patch-1"}
    payload = {"display_name": "Once"}

    first = api.patch("/api/v1/user/profile", headers=headers, json=payload)
    second = api.patch("/api/v1/user/profile", headers=headers, json=payload)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert scalar(f.conn, "SELECT count(*) FROM identity_idempotency") == 1


def test_idempotency_conflict_on_different_payload(api, f):
    f.login_ready()
    tokens = _login(api)
    headers = {**bearer(tokens["access_token"]), "X-DJB-Idempotency-Key": "patch-2"}
    api.patch("/api/v1/user/profile", headers=headers, json={"display_name": "A"})
    response = api.patch("/api/v1/user/profile", headers=headers, json={"display_name": "B"})
    assert response.status_code == 409
    err = error_of(response)
    assert err["code"] == 40919 and err["reason"] == "idempotency_conflict"


def test_login_idempotency_does_not_create_second_session(api, f):
    f.login_ready()
    headers = {"X-DJB-Idempotency-Key": "login-once"}
    payload = {"method": "password", "identifier": "login1@example.com", "secret": PASSWORD}

    first = api.post("/api/v1/auth/login", headers=headers, json=payload)
    second = api.post("/api/v1/auth/login", headers=headers, json=payload)
    assert first.status_code == second.status_code == 200
    assert first.json()["tokens"]["session_id"] == second.json()["tokens"]["session_id"]
    assert first.json()["tokens"]["access_token"] != second.json()["tokens"]["access_token"], \
        "重放要重绑新令牌，但不能新建会话"
    assert scalar(f.conn, "SELECT count(*) FROM sessions") == 1

    # 重绑后的令牌可用，旧令牌仍有效（同一会话，只重绑哈希）
    assert api.get("/api/v1/user/profile", headers=bearer(
        second.json()["tokens"]["access_token"])).status_code == 200


def test_idempotency_key_is_per_scope(api, f):
    f.login_ready()
    tokens = _login(api)
    headers = {**bearer(tokens["access_token"]), "X-DJB-Idempotency-Key": "shared-key"}
    assert api.patch("/api/v1/user/profile", headers=headers,
                     json={"display_name": "X"}).status_code == 200
    assert api.post("/api/v1/auth/logout", headers=headers, json={}).status_code == 200
    assert scalar(f.conn, "SELECT count(*) FROM identity_idempotency") == 2


def test_idempotency_rows_carry_no_tokens(api, f):
    f.login_ready()
    api.post("/api/v1/auth/login", headers={"X-DJB-Idempotency-Key": "k-no-secret"},
             json={"method": "password", "identifier": "login1@example.com",
                   "secret": PASSWORD})
    stored = rows(f.conn, "SELECT response FROM identity_idempotency WHERE idem_key = 'k-no-secret'")
    assert stored and set(stored[0]["response"]) == {"kind", "session_id"}, \
        "幂等表只存会话指针，不存令牌明文"
