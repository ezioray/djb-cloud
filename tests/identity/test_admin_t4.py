# SPDX-License-Identifier: Apache-2.0
"""T4 · 管理面：冻结 / 解冻 / 角色 SoD / 租户配额（tasks-17 验收）。

覆盖：
- adminBearer + 后台角色 + step-up：无令牌 401、无角色 403/40303、缺 step-up 424/42401、
  step-up 凭据不属于本人 424；
- 冻结：`frozen_until` 必填且 ≤180 天（400/40001）、非 normal 账户 409、未知账户 404；
  冻结后会话失效（epoch++）并落 `account.state.changed`；
- 解冻：解冻人 ≠ 冻结人（409/40902）、重复解冻 409；
- 角色：八角色白名单、SoD（second_approver ≠ 操作人）、epoch++、SVC 不得绑自然人、
  frozen 账户禁止授予但允许回收；
- 配额：升需复核（409/40902）、降立即生效、policy_version 每次变更生成、
  历史只追加（UPDATE/DELETE 被触发器拒绝）、min(租户,Key,节点) 口径、未知租户 404；
- 幂等：同键同载荷回放首次响应；越权与非管理员一律拒绝。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import psycopg
import pytest

from app.identity import admin, clock, errors, mfa, models, state, tokens

from identitykit import bearer, error_of, rows, scalar

PASSWORD = "S3cret!"
PIN = "123456"
STEP_UP = "X-Admin-Step-Up"


def _make_admin(api, f, *, email: str = "admin@example.com", role: str = "SUPER"):
    """建一个可用的后台操作员：normal 账户 + MFA + 后台角色 + step-up 令牌。"""
    user = models.create_user(f.conn, email=email, password=PASSWORD, now=f.moment)
    account = models.create_account(f.conn, user_id=user.id, policy_version="v4.0",
                                    now=f.moment)
    state.verify(f.conn, account.id, now=f.moment)
    mfa.enroll(f.conn, account.id, PIN, now=f.moment)
    mfa.confirm(f.conn, account.id, PIN, now=f.moment)
    models.bind_role(f.conn, account_id=account.id, admin_role=role,
                     granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    login = api.post("/api/v1/auth/login",
                     json={"method": "password", "identifier": email, "secret": PASSWORD,
                           "mfa_code": PIN})
    assert login.status_code == 200, login.text
    session = login.json()["tokens"]
    grant = tokens.step_up(f.conn, access_token=session["access_token"], code=PIN,
                           now=clock.utcnow())
    headers = {**bearer(session["access_token"]), STEP_UP: grant.access_token}
    return account, session, grant, headers


def _target(f, email: str = "target@example.com"):
    user = models.create_user(f.conn, email=email, password=PASSWORD, now=f.moment)
    account = models.create_account(f.conn, user_id=user.id, policy_version="v4.0",
                                    now=f.moment)
    state.verify(f.conn, account.id, now=f.moment)
    return account


# --------------------------------------------------------------------------- 身份闸门
def test_admin_requires_role_and_step_up(api, f, timeline):
    _admin_acc, session, grant, headers = _make_admin(api, f)
    target = _target(f)
    body = {"reason": "risk_case_1", "frozen_until": "2026-11-01T00:00:00Z"}

    # 无令牌
    assert api.post(f"/api/v1/admin/accounts/{target.id}/freeze", json=body).status_code == 401

    # 有会话但无后台角色 → 403 / 40303
    plain = api.post("/api/v1/auth/login",
                     json={"method": "password", "identifier": "target@example.com",
                           "secret": PASSWORD}).json()["tokens"]
    no_role = api.post(f"/api/v1/admin/accounts/{target.id}/freeze",
                       headers=bearer(plain["access_token"]), json=body)
    assert no_role.status_code == 403
    assert error_of(no_role)["code"] == 40303

    # 有角色但缺 step-up → 424 / 42401（用**全新会话**：_make_admin 的会话已带 step-up 窗口）
    fresh = api.post("/api/v1/auth/login",
                     json={"method": "password", "identifier": "admin@example.com",
                           "secret": PASSWORD, "mfa_code": PIN}).json()["tokens"]
    no_step = api.post(f"/api/v1/admin/accounts/{target.id}/freeze",
                       headers=bearer(fresh["access_token"]), json=body)
    assert no_step.status_code == 424
    assert error_of(no_step)["code"] == 42401

    # step-up 凭据不属于本人 → 424
    other = api.post("/api/v1/auth/login",
                     json={"method": "password", "identifier": "target@example.com",
                           "secret": PASSWORD}).json()["tokens"]
    wrong = api.post(f"/api/v1/admin/accounts/{target.id}/freeze",
                     headers={**bearer(session["access_token"]), STEP_UP: other["access_token"]},
                     json=body)
    assert wrong.status_code == 424

    # step-up 头可省略：同一会话 5 分钟内刚做过 step-up 也放行
    ok = api.post(f"/api/v1/admin/accounts/{target.id}/freeze",
                  headers=bearer(session["access_token"]), json=body)
    assert ok.status_code == 200, ok.text


# --------------------------------------------------------------------------- 冻结 / 解冻
def test_freeze_and_unfreeze_flow(api, f, timeline):
    admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    target_session = api.post("/api/v1/auth/login",
                              json={"method": "password", "identifier": "target@example.com",
                                    "secret": PASSWORD}).json()["tokens"]

    response = api.post(f"/api/v1/admin/accounts/{target.id}/freeze", headers=headers,
                        json={"reason": "chargeback_case_42",
                              "frozen_until": (f.moment + timedelta(days=30)).isoformat(),
                              "evidence_ref": "TICKET-42"})
    assert response.status_code == 200, response.text
    ack = response.json()
    assert ack["account_id"] == str(target.id) and ack["state"] == "frozen"
    assert ack["frozen_until"] and ack["changed_at"]

    row = models.get_account(f.conn, target.id)
    assert row.state == "frozen" and row.frozen_by == admin_acc.id
    assert row.frozen_approval[0]["evidence_ref"] == "TICKET-42"
    # 冻结撤销旧会话（M01 §6.3）
    assert api.get("/api/v1/user/profile",
                   headers=bearer(target_session["access_token"])).status_code == 401
    assert scalar(f.conn, "SELECT count(*) FROM identity_outbox"
                          " WHERE type = 'account.state.changed'"
                          " AND payload->>'to' = 'frozen'") == 1

    # 原冻结人自己解冻 → 409 / 40902
    self_unfreeze = api.post(f"/api/v1/admin/accounts/{target.id}/unfreeze", headers=headers,
                             json={"reason": "appeal_approved"})
    assert self_unfreeze.status_code == 409
    assert error_of(self_unfreeze)["code"] == 40902

    # 另一个操作员解冻 → 200
    _other, _s2, _g2, other_headers = _make_admin(api, f, email="admin2@example.com",
                                                  role="RISK")
    unfreeze = api.post(f"/api/v1/admin/accounts/{target.id}/unfreeze",
                        headers=other_headers, json={"reason": "appeal_approved",
                                                     "evidence_ref": "TICKET-43"})
    assert unfreeze.status_code == 200, unfreeze.text
    assert unfreeze.json()["state"] == "normal"
    assert models.get_account(f.conn, target.id).frozen_until is None

    # 重复解冻 → 409（已不是 frozen）
    again = api.post(f"/api/v1/admin/accounts/{target.id}/unfreeze", headers=other_headers,
                     json={"reason": "again"})
    assert again.status_code == 409


@pytest.mark.parametrize("payload,fragment", [
    ({"frozen_until": "2026-11-01T00:00:00Z"}, "reason"),
    ({"reason": "", "frozen_until": "2026-11-01T00:00:00Z"}, "reason"),
    ({"reason": "x"}, "frozen_until"),
    ({"reason": "x", "frozen_until": "2026-05-01T00:00:00Z"}, "frozen_until"),
    ({"reason": "x", "frozen_until": "2027-12-31T00:00:00Z"}, "frozen_until"),
    ({"reason": "x", "frozen_until": "not-a-date"}, "frozen_until"),
    ({"reason": "x", "frozen_until": "2026-11-01T00:00:00"}, "frozen_until"),
])
def test_freeze_validation(api, f, payload, fragment):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    response = api.post(f"/api/v1/admin/accounts/{target.id}/freeze", headers=headers,
                        json=payload)
    assert response.status_code == 400, response.text
    err = error_of(response)
    assert err["code"] == 40001 and err.get("field") == fragment


def test_freeze_boundary_180_days_allowed(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    response = api.post(f"/api/v1/admin/accounts/{target.id}/freeze", headers=headers,
                        json={"reason": "max_window",
                              "frozen_until": (f.moment + timedelta(days=180)).isoformat()})
    assert response.status_code == 200
    assert models.get_account(f.conn, target.id).frozen_until == f.moment + timedelta(days=180)


def test_freeze_unknown_or_illegal_target(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    ghost = uuid.uuid4()
    response = api.post(f"/api/v1/admin/accounts/{ghost}/freeze", headers=headers,
                        json={"reason": "x", "frozen_until": "2026-11-01T00:00:00Z"})
    assert response.status_code == 404 and error_of(response)["code"] == 40401

    assert api.post("/api/v1/admin/accounts/not-a-uuid/freeze", headers=headers,
                    json={"reason": "x", "frozen_until": "2026-11-01T00:00:00Z"}
                    ).status_code == 400

    pending_user = models.create_user(f.conn, email="pending@example.com", now=f.moment)
    pending = models.create_account(f.conn, user_id=pending_user.id, now=f.moment)
    response = api.post(f"/api/v1/admin/accounts/{pending.id}/freeze", headers=headers,
                        json={"reason": "x", "frozen_until": "2026-11-01T00:00:00Z"})
    assert response.status_code == 409


# --------------------------------------------------------------------------- 角色
def test_roles_grant_and_revoke_with_sod(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    approver = str(uuid.uuid4())
    epoch_before = models.get_account(f.conn, target.id).session_epoch

    grant = api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                     json={"grant": ["OPS", "VIEWER"], "reason": "harness_duty",
                           "second_approver": approver})
    assert grant.status_code == 200, grant.text
    body = grant.json()
    assert body["account_id"] == str(target.id)
    assert sorted(body["roles"]) == ["OPS", "VIEWER"]
    assert body["session_epoch"] >= epoch_before + 1
    assert body["session_epoch"] == models.get_account(f.conn, target.id).session_epoch
    assert set(admin.roles_view(f.conn, target.id, now=timeline.moment)["roles"]) == {"OPS",
                                                                                     "VIEWER"}

    # SoD：复核人 == 操作人 → 409
    same = api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                    json={"grant": ["FIN"], "reason": "x",
                          "second_approver": str(_admin_acc.id)})
    assert same.status_code == 409 and error_of(same)["code"] == 40902

    # 缺复核人 / 非法角色 / 空变更
    assert api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                    json={"grant": ["FIN"], "reason": "x"}).status_code == 400
    assert api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                    json={"grant": ["ROOT"], "reason": "x",
                          "second_approver": approver}).status_code == 400
    assert api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                    json={"reason": "x", "second_approver": approver}).status_code == 400

    revoke = api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                      json={"revoke": ["VIEWER"], "reason": "offboard",
                            "second_approver": approver})
    assert revoke.status_code == 200
    assert revoke.json()["roles"] == ["OPS"]


def test_roles_svc_guard_and_frozen_target(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    approver = str(uuid.uuid4())

    svc = api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                   json={"grant": ["SVC"], "reason": "service_account",
                         "second_approver": approver})
    assert svc.status_code == 409           # SVC 不得绑自然人（有邮箱哈希）
    assert error_of(svc)["code"] == 40902

    # 冻结账户：禁止授予（403/40304），但允许回收
    models.bind_role(f.conn, account_id=target.id, admin_role="CS",
                     granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    f.freeze(target)
    denied = api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                      json={"grant": ["OPS"], "reason": "x", "second_approver": approver})
    assert denied.status_code == 403 and error_of(denied)["code"] == 40304
    revoked = api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                       json={"revoke": ["CS"], "reason": "compromised",
                             "second_approver": approver})
    assert revoked.status_code == 200 and revoked.json()["roles"] == []


def test_roles_unknown_account(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    response = api.post(f"/api/v1/admin/accounts/{uuid.uuid4()}/roles", headers=headers,
                        json={"grant": ["OPS"], "reason": "x",
                              "second_approver": str(uuid.uuid4())})
    assert response.status_code == 404


# --------------------------------------------------------------------------- 配额
def test_quota_raise_requires_approval_and_versions(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)                      # 注册时种了 qps=3, v4.0

    # 升配额缺复核 → 409/40902
    denied = api.post(f"/api/v1/admin/tenants/{target.tenant_id}/quotas", headers=headers,
                      json={"quotas": [{"kind": "qps", "value": 10}], "reason": "growth"})
    assert denied.status_code == 409
    assert error_of(denied)["reason"] == "quota_increase_requires_approval"

    approver = str(uuid.uuid4())
    raised = api.post(f"/api/v1/admin/tenants/{target.tenant_id}/quotas", headers=headers,
                      json={"quotas": [{"kind": "qps", "value": 10},
                                       {"kind": "daily_spend", "value": 50000}],
                            "reason": "growth", "second_approver": approver})
    assert raised.status_code == 200, raised.text
    ack = raised.json()
    assert ack["tenant_id"] == str(target.tenant_id)
    assert ack["policy_version"] and ack["effective_at"]
    kinds = {item["kind"]: item["value"] for item in ack["quotas"]}
    assert kinds["qps"] == 10
    assert kinds["daily_usd_minor"] == 50000, "spec 的 daily_spend 归一到 daily_usd_minor"

    snapshot = models.quota_snapshot(f.conn, target.tenant_id)
    assert snapshot["policy_version"] == ack["policy_version"]
    assert snapshot["effective"]["qps"] == 10

    # 历史只追加：同一 kind 两条（3 → 10）
    history = rows(f.conn, "SELECT kind, value, previous_value, policy_version, actor_id, reason"
                           " FROM tenant_quota_history ORDER BY created_at, kind")
    qps_rows = [r for r in history if r["kind"] == "qps"]
    assert [r["value"] for r in qps_rows] == [10]
    assert qps_rows[0]["previous_value"] == 3
    assert qps_rows[0]["actor_id"] == _admin_acc.id and qps_rows[0]["reason"] == "growth"
    # 预期报错必须走 savepoint：否则会把外层测试事务打挂，后续请求全部 InFailedSqlTransaction
    with pytest.raises(psycopg.errors.RaiseException), f.conn.transaction():
        f.conn.execute("UPDATE tenant_quota_history SET value = 0")

    # 降配额：无需复核，立即生效，并生成新版本
    lowered = api.post(f"/api/v1/admin/tenants/{target.tenant_id}/quotas", headers=headers,
                       json={"quotas": [{"kind": "qps", "value": 2}], "reason": "cost_cut"})
    assert lowered.status_code == 200
    assert lowered.json()["policy_version"] != ack["policy_version"]
    assert models.quota_snapshot(f.conn, target.tenant_id)["effective"]["qps"] == 2


def test_quota_validation_and_scope(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    bad = [
        {"reason": "x"},
        {"quotas": [], "reason": "x"},
        {"quotas": [{"kind": "tokens", "value": 1}], "reason": "x", "second_approver": str(uuid.uuid4())},
        {"quotas": [{"kind": "qps", "value": -1}], "reason": "x", "second_approver": str(uuid.uuid4())},
        {"quotas": [{"kind": "qps", "value": "10"}], "reason": "x", "second_approver": str(uuid.uuid4())},
    ]
    for payload in bad:
        response = api.post(f"/api/v1/admin/tenants/{target.tenant_id}/quotas",
                            headers=headers, json=payload)
        assert response.status_code == 400, payload
        assert error_of(response)["code"] == 40001

    same_person = api.post(f"/api/v1/admin/tenants/{target.tenant_id}/quotas", headers=headers,
                           json={"quotas": [{"kind": "qps", "value": 9}], "reason": "x",
                                 "second_approver": str(_admin_acc.id)})
    assert same_person.status_code == 409
    assert error_of(same_person)["reason"] == "dual_control_required"

    ghost = api.post(f"/api/v1/admin/tenants/{uuid.uuid4()}/quotas", headers=headers,
                     json={"quotas": [{"kind": "qps", "value": 1}], "reason": "x",
                           "second_approver": str(uuid.uuid4())})
    assert ghost.status_code == 404 and error_of(ghost)["code"] == 40401

    # 跨租户的 Key 级配额 → 404（Key 不属于该租户）
    other = _target(f, email="other@example.com")
    key, _plain = models.create_api_key(f.conn, account_id=other.id, label="k", now=f.moment)
    cross = api.post(f"/api/v1/admin/tenants/{target.tenant_id}/quotas", headers=headers,
                     json={"quotas": [{"kind": "qps", "value": 5, "key_id": str(key.id)}],
                           "reason": "x", "second_approver": str(uuid.uuid4())})
    assert cross.status_code == 404


def test_quota_key_level_entry_and_view(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    key, _plain = models.create_api_key(f.conn, account_id=target.id, label="k", now=f.moment)

    response = api.post(f"/api/v1/admin/tenants/{target.tenant_id}/quotas", headers=headers,
                        json={"quotas": [{"kind": "qps", "value": 4, "key_id": str(key.id)}],
                              "reason": "per_key", "second_approver": str(uuid.uuid4())})
    assert response.status_code == 200, response.text
    view = admin.quotas_view(f.conn, target.tenant_id, key_id=key.id)
    assert {q["kind"] for q in view["quotas"]} == {"qps"}
    assert view["policy_version"] == response.json()["policy_version"]


# --------------------------------------------------------------------------- 幂等
def test_admin_idempotent_replay(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    headers = {**headers, "X-DJB-Idempotency-Key": "freeze-once"}
    payload = {"reason": "case_1", "frozen_until": "2026-11-01T00:00:00Z"}
    first = api.post(f"/api/v1/admin/accounts/{target.id}/freeze", headers=headers,
                     json=payload)
    second = api.post(f"/api/v1/admin/accounts/{target.id}/freeze", headers=headers,
                      json=payload)
    assert first.status_code == 200 and second.status_code == 200
    assert first.json() == second.json()
    assert scalar(f.conn, "SELECT count(*) FROM identity_outbox"
                          " WHERE type = 'account.state.changed'"
                          " AND payload->>'to' = 'frozen'") == 1


# --------------------------------------------------------------------------- 入参校验补充
@pytest.mark.parametrize("payload,fragment", [
    ({"reason": "x", "frozen_until": "2026-11-01T00:00:00Z", "evidence_ref": ""}, "evidence_ref"),
    ({"reason": "x", "frozen_until": "2026-11-01T00:00:00Z",
      "evidence_ref": "T" * 200}, "evidence_ref"),
    ({"reason": "x" * 600, "frozen_until": "2026-11-01T00:00:00Z"}, "reason"),
])
def test_freeze_payload_extra_validation(api, f, timeline, payload, fragment):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    response = api.post(f"/api/v1/admin/accounts/{target.id}/freeze", headers=headers,
                        json=payload)
    assert response.status_code == 400
    assert error_of(response).get("field") == fragment


def test_admin_empty_body_is_400(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    response = api.post(f"/api/v1/admin/accounts/{target.id}/freeze", headers=headers, json={})
    assert response.status_code == 400
    assert error_of(response)["reason"] == "empty_body"


@pytest.mark.parametrize("payload,fragment", [
    ({"grant": "OPS", "reason": "x", "second_approver": "00000000-0000-0000-0000-000000000001"},
     "grant"),
    ({"grant": ["OPS"], "reason": "x", "second_approver": "not-a-uuid"}, "second_approver"),
    ({"grant": ["OPS"], "reason": "x", "second_approver": "00000000-0000-0000-0000-000000000001",
      "scope": ""}, "scope"),
])
def test_roles_payload_validation(api, f, timeline, payload, fragment):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    response = api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
                        json=payload)
    assert response.status_code == 400
    assert error_of(response).get("field") == fragment


@pytest.mark.parametrize("quotas", [
    "qps",
    [{"kind": "qps"}],
    [{"value": 3}],
    ["qps=3"],
    [{"kind": "qps", "value": 3, "key_id": "not-int"}],
])
def test_quota_entry_validation(api, f, timeline, quotas):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    response = api.post(f"/api/v1/admin/tenants/{target.tenant_id}/quotas", headers=headers,
                        json={"quotas": quotas, "reason": "x",
                              "second_approver": str(uuid.uuid4())})
    assert response.status_code == 400
    assert error_of(response)["code"] == 40001


def test_roles_view_and_quotas_view_read_side(api, f, timeline):
    _admin_acc, _session, _grant, headers = _make_admin(api, f)
    target = _target(f)
    approver = str(uuid.uuid4())
    api.post(f"/api/v1/admin/accounts/{target.id}/roles", headers=headers,
             json={"grant": ["AUDIT"], "reason": "read_side", "second_approver": approver})
    view = admin.roles_view(f.conn, target.id, now=timeline.moment)
    assert view["roles"] == ["AUDIT"] and view["account_id"] == str(target.id)

    quotas = admin.quotas_view(f.conn, target.tenant_id)
    assert quotas["tenant_id"] == str(target.tenant_id)
    assert {q["kind"] for q in quotas["quotas"]} == {"qps"}
    assert quotas["policy_version"] == "v4.0"          # 注册时种下的版本


def test_roles_view_unknown_account(f):
    with pytest.raises(models.NotFound):
        admin.roles_view(f.conn, uuid.uuid4(), now=f.moment)
    with pytest.raises(models.InvalidArgument):
        admin.roles_view(f.conn, "not-a-uuid", now=f.moment)
