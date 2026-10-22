# SPDX-License-Identifier: Apache-2.0
"""T3 · API Key 生命周期 + 网关鉴权（tasks-15 验收）。

覆盖：
- 4 个端点：创建（201，明文一次）/ 列表（游标分页、只回前缀）/ 撤销（幂等、立即失效）/ 轮换（重叠期）；
- 安全：库里只有 sha256 + 8 位前缀，明文不入库不入日志；跨租户一律 404；撤销后鉴权 401；
- 网关鉴权 ``verify_api_key``：哈希 / 失效时刻 / Key 级过期 / 重叠期 / 账户状态 / 配额快照（INV-07）；
- CR-3：T3 **没有**给 api_keys 加 NOT NULL（T4 统一切换），用测试钉住。
"""
from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest

from app.identity import api_keys, errors, models, tokens

from conftest import bearer, error_of, rows, scalar

PASSWORD = "S3cret!"


def _tokens(api, identifier: str = "login1@example.com") -> dict:
    response = api.post("/api/v1/auth/login",
                        json={"method": "password", "identifier": identifier,
                              "secret": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()["tokens"]


def _create(api, token: str, *, name: str = "ci-key", **extra):
    return api.post("/api/v1/user/api-keys", headers=bearer(token),
                    json={"name": name, **extra})


# --------------------------------------------------------------------------- 创建
def test_create_key_returns_plaintext_once(api, f, caplog):
    f.login_ready()
    token = _tokens(api)["access_token"]
    response = _create(api, token, name="ci-key", scopes=["chat:read"])
    assert response.status_code == 201

    body = response.json()
    plaintext = body["key"]
    assert set(body) >= {"key_id", "key", "prefix", "created_at"}
    assert body["name"] == "ci-key"
    assert body["scopes"] == ["chat:read"]
    assert body["prefix"] == plaintext[: models.KEY_PREFIX_LEN]

    stored = rows(f.conn, "SELECT * FROM api_keys WHERE id = %s", (int(body["key_id"]),))[0]
    assert stored["key_hash"] == hashlib.sha256(plaintext.encode()).hexdigest()
    assert stored["key_prefix"] == body["prefix"]
    assert stored["scopes"] == ["chat:read"]
    assert plaintext not in str(stored), "明文不得入库"
    assert plaintext not in caplog.text

    # 列表只回前缀
    listed = api.get("/api/v1/user/api-keys", headers=bearer(token)).json()
    assert listed["data"][0]["prefix"] == body["prefix"]
    assert "key" not in listed["data"][0] and "key_hash" not in str(listed)


def test_create_key_requires_auth_and_writable_account(api, f):
    f.login_ready()
    assert api.post("/api/v1/user/api-keys", json={"name": "x"}).status_code == 401

    token = _tokens(api)["access_token"]
    _user, account = f.login_ready()          # 第二个账户（用于冻结场景）
    f.freeze(account)
    frozen_tokens = _tokens(api, "login2@example.com")     # 冻结撤销旧会话，重新登录（只读可登录）
    response = _create(api, frozen_tokens["access_token"])
    assert response.status_code == 403
    assert error_of(response)["code"] == 40304
    assert _create(api, token).status_code == 201           # 第一个账户不受影响


@pytest.mark.parametrize("payload,fragment", [
    ({}, "name"),
    ({"name": ""}, "name"),
    ({"name": "x" * 65}, "name"),
    ({"name": "k", "scopes": "chat"}, "scopes"),
    ({"name": "k", "scopes": [""]}, "scopes"),
    ({"name": "k", "scopes": [f"s{i}" for i in range(17)]}, "scopes"),
    ({"name": "k", "expires_at": "not-a-date"}, "expires_at"),
    ({"name": "k", "expires_at": "2020-01-01T00:00:00Z"}, "expires_at"),
])
def test_create_key_validation(api, f, payload, fragment):
    f.login_ready()
    token = _tokens(api)["access_token"]
    response = api.post("/api/v1/user/api-keys", headers=bearer(token), json=payload)
    assert response.status_code == 400, response.text
    err = error_of(response)
    assert err["code"] == 40001 and err.get("field") == fragment


def test_create_key_limit_is_429(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    for index in range(models.KEY_MAX_PER_ACCOUNT):
        assert _create(api, token, name=f"k{index}").status_code == 201
    response = _create(api, token, name="overflow")
    assert response.status_code == 429
    err = error_of(response)
    assert err["code"] == 42901 and err["reason"] == "key_limit_reached"
    assert response.headers["X-Request-Id"]


# --------------------------------------------------------------------------- 列表
def test_list_pagination_and_include_revoked(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = [_create(api, token, name=f"page-{i}").json() for i in range(3)]

    first = api.get("/api/v1/user/api-keys?limit=2", headers=bearer(token)).json()
    assert len(first["data"]) == 2 and first["page"]["has_more"] is True
    assert first["page"]["next_cursor"]

    second = api.get(f"/api/v1/user/api-keys?limit=2&cursor={first['page']['next_cursor']}",
                     headers=bearer(token)).json()
    assert len(second["data"]) == 1 and second["page"]["has_more"] is False
    assert second["page"]["next_cursor"] is None
    seen = {item["key_id"] for item in first["data"] + second["data"]}
    assert seen == {item["key_id"] for item in created}

    # 撤销后默认不返回，include_revoked=true 可查（保留 24 个月）
    api.delete(f"/api/v1/user/api-keys/{created[0]['key_id']}", headers=bearer(token))
    live = api.get("/api/v1/user/api-keys", headers=bearer(token)).json()
    assert created[0]["key_id"] not in {item["key_id"] for item in live["data"]}
    all_keys = api.get("/api/v1/user/api-keys?include_revoked=true",
                       headers=bearer(token)).json()
    assert created[0]["key_id"] in {item["key_id"] for item in all_keys["data"]}


@pytest.mark.parametrize("query,fragment", [
    ("limit=0", "limit"),
    ("limit=201", "limit"),
    ("cursor=not-a-cursor", "cursor"),
    ("cursor=%%%", "cursor"),
])
def test_list_query_validation(api, f, query, fragment):
    f.login_ready()
    token = _tokens(api)["access_token"]
    response = api.get(f"/api/v1/user/api-keys?{query}", headers=bearer(token))
    assert response.status_code == 400
    assert error_of(response).get("field") == fragment


def test_list_is_tenant_and_account_scoped(api, f):
    f.login_ready()
    f.login_ready()
    token_a = _tokens(api, "login1@example.com")["access_token"]
    token_b = _tokens(api, "login2@example.com")["access_token"]
    key_a = _create(api, token_a, name="a").json()

    listed_b = api.get("/api/v1/user/api-keys", headers=bearer(token_b)).json()
    assert listed_b["data"] == []
    assert api.delete(f"/api/v1/user/api-keys/{key_a['key_id']}",
                      headers=bearer(token_b)).status_code == 404
    assert api.post(f"/api/v1/user/api-keys/{key_a['key_id']}/rotate",
                    headers=bearer(token_b), json={}).status_code == 404


# --------------------------------------------------------------------------- 撤销
def test_revoke_is_idempotent_and_immediate(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()
    plaintext = created["key"]

    first = api.delete(f"/api/v1/user/api-keys/{created['key_id']}", headers=bearer(token))
    assert first.status_code == 200
    assert first.json()["revoked_at"]

    # 立即失效：网关鉴权 40101
    with pytest.raises(models.ApiKeyInvalid) as exc:
        api_keys.verify_api_key(f.conn, plaintext, now=f.moment)
    assert exc.value.code == "40101"

    # 幂等：第二次返回首次结果，不再发事件
    second = api.delete(f"/api/v1/user/api-keys/{created['key_id']}", headers=bearer(token))
    assert second.status_code == 200
    assert second.json()["revoked_at"] == first.json()["revoked_at"]
    assert scalar(f.conn, "SELECT count(*) FROM identity_outbox"
                          " WHERE type = 'apikey.revoked'") == 1

    assert api.delete("/api/v1/user/api-keys/999999",
                      headers=bearer(token)).status_code == 404


# --------------------------------------------------------------------------- 轮换
def test_rotate_without_overlap_kills_old_key(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token, name="old", scopes=["chat:read"]).json()

    response = api.post(f"/api/v1/user/api-keys/{created['key_id']}/rotate",
                        headers=bearer(token), json={})
    assert response.status_code == 201
    rotated = response.json()
    assert rotated["key"] != created["key"] and rotated["key_id"] != created["key_id"]

    with pytest.raises(models.ApiKeyInvalid):
        api_keys.verify_api_key(f.conn, created["key"], now=f.moment)
    ctx = api_keys.verify_api_key(f.conn, rotated["key"], now=f.moment, require_quota=False)
    assert ctx.api_key_id == int(rotated["key_id"])

    old_row = models.get_api_key(f.conn, int(created["key_id"]))
    new_row = models.get_api_key(f.conn, int(rotated["key_id"]))
    assert old_row.revoked_reason == "rotated" and old_row.revoked_at <= f.moment
    assert new_row.rotated_from == old_row.id
    assert new_row.scopes == ["chat:read"], "轮换默认继承 scopes"


def test_rotate_with_overlap_only_allows_verification(api, f, timeline):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()

    response = api.post(f"/api/v1/user/api-keys/{created['key_id']}/rotate",
                        headers=bearer(token), json={"overlap_seconds": 3600})
    assert response.status_code == 201
    new_key = response.json()

    # 重叠期内：旧钥仍可验签（M03 放行在途请求），但新注册类动作必须被拒（INV-10）
    ctx = api_keys.verify_api_key(f.conn, created["key"], now=timeline.moment,
                                  allow_overlap=True, require_quota=False)
    assert ctx.key_overlap is True and ctx.api_key_id == int(created["key_id"])
    with pytest.raises(errors.KeyOverlapForbidden) as exc:
        api_keys.verify_api_key(f.conn, created["key"], now=timeline.moment,
                                allow_overlap=False, require_quota=False)
    assert exc.value.code == "40902"
    assert api_keys.verify_api_key(f.conn, new_key["key"], now=timeline.moment,
                                   require_quota=False).key_overlap is False

    # 重叠期到点后旧钥彻底失效
    timeline.advance(seconds=3601)
    with pytest.raises(models.ApiKeyInvalid):
        api_keys.verify_api_key(f.conn, created["key"], now=timeline.moment)


@pytest.mark.parametrize("overlap", [-1, 86401, "3600", 1.5])
def test_rotate_overlap_validation(api, f, overlap):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()
    response = api.post(f"/api/v1/user/api-keys/{created['key_id']}/rotate",
                        headers=bearer(token), json={"overlap_seconds": overlap})
    assert response.status_code == 400
    assert error_of(response)["code"] == 40001


def test_rotate_guards(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()

    assert api.post("/api/v1/user/api-keys/999999/rotate",
                    headers=bearer(token), json={}).status_code == 404
    assert api.post("/api/v1/user/api-keys/not-a-number/rotate",
                    headers=bearer(token), json={}).status_code == 400

    api.delete(f"/api/v1/user/api-keys/{created['key_id']}", headers=bearer(token))
    again = api.post(f"/api/v1/user/api-keys/{created['key_id']}/rotate",
                     headers=bearer(token), json={})
    assert again.status_code == 409
    assert error_of(again)["code"] == 40902


def test_rotate_on_frozen_account_is_forbidden(api, f):
    _user, account = f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()
    f.freeze(account)
    token = _tokens(api)["access_token"]        # 冻结撤销旧会话，重新登录（frozen 只读可登录）
    response = api.post(f"/api/v1/user/api-keys/{created['key_id']}/rotate",
                        headers=bearer(token), json={})
    assert response.status_code == 403
    assert error_of(response)["code"] == 40304
    # 旧钥未被误撤销（同事务回滚）
    assert models.get_api_key(f.conn, int(created["key_id"])).revoked_at is None


# --------------------------------------------------------------------------- 网关鉴权
def test_verify_api_key_returns_context_with_quota(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()

    ctx = api_keys.verify_api_key(f.conn, created["key"], now=f.moment)
    assert ctx.via == "api_key" and ctx.api_key_id == int(created["key_id"])
    assert ctx.api_key_prefix == created["prefix"]
    assert ctx.account.state == "normal" and ctx.key_overlap is False
    assert ctx.quotas["policy_version"] == "v4.0"
    assert ctx.quotas["effective"] == {"qps": models.DEFAULT_QPS}
    assert models.get_api_key(f.conn, int(created["key_id"])).last_used_at == f.moment


def test_verify_api_key_rejections(api, f, timeline):
    _user, account = f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token, expires_at="2026-10-30T00:00:00Z").json()

    with pytest.raises(models.ApiKeyInvalid) as exc:
        api_keys.verify_api_key(f.conn, "not-a-key", now=f.moment)
    assert exc.value.code == "40101"

    # Key 级过期
    timeline.advance(days=30)
    assert models.get_api_key(f.conn, int(created["key_id"])).expires_at is not None
    with pytest.raises(models.ApiKeyInvalid):
        api_keys.verify_api_key(f.conn, created["key"], now=timeline.moment)


def test_verify_api_key_account_state_gates(api, f):
    _user, account = f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()

    f.freeze(account)
    with pytest.raises(models.AccountReadOnly) as exc:
        api_keys.verify_api_key(f.conn, created["key"], now=f.moment, require_writable=True)
    assert exc.value.code == "40304"
    # 只读请求（require_writable=False）仍可验签
    assert api_keys.verify_api_key(f.conn, created["key"], now=f.moment,
                                   require_writable=False,
                                   require_quota=False).account.state == "frozen"

    f.conn.execute(
        """UPDATE user_accounts
              SET state = 'closed', closed_at = now(), frozen_until = NULL,
                  frozen_reason = NULL, frozen_by = NULL, frozen_approval = NULL
            WHERE id = %s""", (account.id,))
    with pytest.raises(models.AccountClosed) as exc:
        api_keys.verify_api_key(f.conn, created["key"], now=f.moment)
    assert exc.value.code == "40903"


def test_verify_api_key_requires_quota_snapshot(api, f):
    _user, account = f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()
    f.conn.execute("DELETE FROM tenant_quotas WHERE tenant_id = %s", (account.tenant_id,))
    with pytest.raises(models.QuotaSnapshotMissing) as exc:
        api_keys.verify_api_key(f.conn, created["key"], now=f.moment)
    assert exc.value.code == "40907"
    # 只要验签不要求计费快照，仍然放行
    assert api_keys.verify_api_key(f.conn, created["key"], now=f.moment,
                                   require_quota=False).account.id == account.id


def test_verify_rejects_legacy_key_without_owner(api, f):
    f.conn.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s, %s, %s)",
                   ("user:legacy", "legacyab", models.hash_secret("legacy-raw")))
    with pytest.raises(models.ApiKeyInvalid):
        api_keys.verify_api_key(f.conn, "legacy-raw", now=f.moment)


# --------------------------------------------------------------------------- 幂等（明文不可重放）
def test_create_idempotency_never_replays_plaintext(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    headers = {**bearer(token), "X-DJB-Idempotency-Key": "key-once"}
    first = api.post("/api/v1/user/api-keys", headers=headers, json={"name": "once"})
    second = api.post("/api/v1/user/api-keys", headers=headers, json={"name": "once"})
    assert first.status_code == 201
    assert second.status_code == 409
    err = error_of(second)
    assert err["code"] == 40919 and err["reason"] == "plaintext_not_replayable"
    assert err["key_id"] == first.json()["key_id"]
    # 只建了一枚 Key，且幂等表里没有明文
    assert scalar(f.conn, "SELECT count(*) FROM api_keys WHERE account_id IS NOT NULL") == 1
    stored = rows(f.conn, "SELECT response FROM identity_idempotency"
                          " WHERE idem_key = 'key-once'")[0]["response"]
    assert set(stored) == {"kind", "key_id"}


def test_revoke_idempotency_replays_summary(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()
    headers = {**bearer(token), "X-DJB-Idempotency-Key": "revoke-once"}
    first = api.delete(f"/api/v1/user/api-keys/{created['key_id']}", headers=headers)
    second = api.delete(f"/api/v1/user/api-keys/{created['key_id']}", headers=headers)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()


# --------------------------------------------------------------------------- CR-3 守卫
def test_no_not_null_on_api_keys_owner_columns_yet(conn):
    """CR-3：T3 只给方案不加约束；T4 才统一切换（NOT VALID → VALIDATE）。"""
    columns = rows(conn, """SELECT column_name, is_nullable FROM information_schema.columns
                             WHERE table_schema = current_schema() AND table_name = 'api_keys'
                               AND column_name IN ('account_id', 'tenant_id')
                             ORDER BY 1""")
    assert [c["is_nullable"] for c in columns] == ["YES", "YES"], columns


def test_cr3_observation_query_works(conn):
    """T3 交付的观测 SQL：切换前用它看还有多少存量行没有账户归属。"""
    conn.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s, %s, %s)",
                 ("user:legacy", "legacyab", "1" * 64))
    missing = scalar(conn, "SELECT count(*) FROM api_keys WHERE account_id IS NULL"
                           " OR tenant_id IS NULL")
    assert missing == 1


# --------------------------------------------------------------------------- 分支补充
def test_create_name_validation_direct(f):
    """领域层也守住 name（路由层已拦一次，领域层不依赖调用方）。"""
    _user, account = f.login_ready()
    with pytest.raises(models.InvalidArgument) as exc:
        api_keys.create(f.conn, account_id=account.id, name="", now=f.moment)
    assert exc.value.details["field"] == "name"
    with pytest.raises(models.InvalidArgument):
        api_keys.create(f.conn, account_id=account.id, name="x" * 65, now=f.moment)
    with pytest.raises(models.InvalidArgument):
        api_keys.create(f.conn, account_id=account.id, name=123, now=f.moment)
    with pytest.raises(models.InvalidArgument):
        api_keys.create(f.conn, account_id=account.id, name=None, now=f.moment)


@pytest.mark.parametrize("cursor", ["not-a-cursor", "%%%", "zzz", "k:",
                                    api_keys.encode_cursor(0)])
def test_decode_cursor_rejects_malformed(cursor):
    with pytest.raises(models.InvalidArgument) as exc:
        api_keys.decode_cursor(cursor)
    assert exc.value.details["field"] == "cursor"


def test_list_page_without_tenant_filter(api, f):
    _user, account = f.login_ready()
    f.key(account, label="direct")
    page = api_keys.list_page(f.conn, account_id=account.id, now=f.moment)
    assert [k.label for k in page.items] == ["direct"]
    assert page.has_more is False and page.next_cursor is None and page.cursor is None


def test_verify_without_touch_leaves_last_used(api, f):
    _user, account = f.login_ready()
    _key, plaintext = f.key(account)
    api_keys.verify_api_key(f.conn, plaintext, now=f.moment, touch=False, require_quota=False)
    key = models.get_api_key(f.conn, models.lookup_api_key(f.conn, plaintext,
                                                           now=f.moment).id)
    assert key.last_used_at is None


@pytest.mark.parametrize("expires_at", [123, {"at": "x"}, "2026-10-30T00:00:00"])
def test_create_expires_at_parsing(api, f, expires_at):
    f.login_ready()
    token = _tokens(api)["access_token"]
    response = api.post("/api/v1/user/api-keys", headers=bearer(token),
                        json={"name": "k", "expires_at": expires_at})
    assert response.status_code == 400
    assert error_of(response)["code"] == 40001


@pytest.mark.parametrize("raw_id", ["0", "-3", "abc"])
def test_path_id_validation(api, f, raw_id):
    f.login_ready()
    token = _tokens(api)["access_token"]
    response = api.delete(f"/api/v1/user/api-keys/{raw_id}", headers=bearer(token))
    assert response.status_code == 400
    assert error_of(response).get("field") == "id"


def test_rotate_accepts_new_name(api, f):
    """spec ApiKeyRotateRequest = {name?, overlap_seconds?}（不含 expires_at）。"""
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token, name="old").json()
    response = api.post(f"/api/v1/user/api-keys/{created['key_id']}/rotate",
                        headers=bearer(token),
                        json={"name": "renamed", "overlap_seconds": 0})
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "renamed"
    assert models.get_api_key(f.conn, int(body["key_id"])).label == "renamed"


def test_rotate_idempotency_never_replays_plaintext(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()
    headers = {**bearer(token), "X-DJB-Idempotency-Key": "rotate-once"}
    first = api.post(f"/api/v1/user/api-keys/{created['key_id']}/rotate",
                     headers=headers, json={})
    second = api.post(f"/api/v1/user/api-keys/{created['key_id']}/rotate",
                      headers=headers, json={})
    assert first.status_code == 201 and second.status_code == 409
    assert error_of(second)["reason"] == "plaintext_not_replayable"
    assert scalar(f.conn, "SELECT count(*) FROM api_keys WHERE account_id IS NOT NULL") == 2


def test_scope_dedupe_and_naive_expiry_direct(f):
    _user, account = f.login_ready()
    key, _ = models.create_api_key(f.conn, account_id=account.id, label="scoped",
                                   scopes=["a", "a", "b"], now=f.moment)
    assert key.scopes == ["a", "b"]
    with pytest.raises(models.InvalidArgument) as exc:
        models.create_api_key(f.conn, account_id=account.id, label="naive",
                              expires_at=(f.moment + timedelta(days=1)).replace(tzinfo=None),
                              now=f.moment)
    assert exc.value.details["field"] == "expires_at"


def test_rotate_expired_key_is_rejected(api, f):
    _user, account = f.login_ready()
    key, _ = models.create_api_key(f.conn, account_id=account.id, label="short",
                                   expires_at=f.moment + timedelta(days=1), now=f.moment)
    later = f.moment + timedelta(days=2)
    with pytest.raises(models.ApiKeyInvalid) as exc:
        models.rotate_api_key(f.conn, key.id, now=later)
    assert exc.value.code == "40101"


def test_step_up_requires_session_not_api_key(api, f):
    f.login_ready()
    token = _tokens(api)["access_token"]
    created = _create(api, token).json()
    ctx = api_keys.verify_api_key(f.conn, created["key"], now=f.moment, require_quota=False)
    assert ctx.via == "api_key" and ctx.session is None
    with pytest.raises(errors.StepUpRequired) as exc:
        tokens.require_step_up(ctx, now=f.moment)
    assert exc.value.code == "42401"
