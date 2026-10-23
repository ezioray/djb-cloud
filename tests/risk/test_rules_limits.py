# SPDX-License-Identifier: Apache-2.0
"""规则元数据（rules ×2）与限额（limits ×2）：版本只加不改 / 48005 / 幂等 / 租户隔离 / 视图口径。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from riskkit import ADMIN_PRINCIPAL, OTHER_TENANT_PRINCIPAL, READONLY_PRINCIPAL, build_client
from riskkit import FIXED_NOW

STEP_UP = {"X-Admin-Step-Up": "step-up-token-123"}


def _rule_body(**overrides):
    body = {"rule_key": "self_trade.ratio", "severity": "P2", "action_class": "observe",
            "config_ref": "risk.case.auto_action"}
    body.update(overrides)
    return body


# ───────────────────────────────────────────────────────────── 规则
def test_create_rule_returns_metadata_only(client) -> None:
    response = client.post("/api/v1/admin/risk/rules", json=_rule_body(),
                           headers=STEP_UP)
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["rule_key"] == "self_trade.ratio"
    assert payload["version"] == 1
    assert payload["severity"] == "P2"
    assert payload["action_class"] == "observe"
    assert payload["config_ref"] == "risk.case.auto_action"
    # INV-01：规则响应只有元数据，不含阈值 / 权重 / 名单
    assert set(payload) <= {
        "rule_key", "version", "enabled", "severity", "action_class", "config_ref",
        "created_at"}
    assert payload["enabled"] is True


def test_same_rule_replays_and_change_bumps_version(client) -> None:
    first = client.post("/api/v1/admin/risk/rules", json=_rule_body(), headers=STEP_UP)
    assert first.status_code == 201
    same = client.post("/api/v1/admin/risk/rules", json=_rule_body(), headers=STEP_UP)
    assert same.status_code == 201
    assert same.json()["version"] == 1                       # 完全相同 → 不新增版本
    changed = client.post("/api/v1/admin/risk/rules", json=_rule_body(severity="P0"),
                          headers=STEP_UP)
    assert changed.status_code == 201
    assert changed.json()["version"] == 2                    # 版本只加不改

    listing = client.get("/api/v1/admin/risk/rules")
    assert listing.status_code == 200
    keys = [(row["rule_key"], row["version"]) for row in listing.json()["data"]]
    assert ("self_trade.ratio", 2) in keys and ("self_trade.ratio", 1) in keys


def test_expected_version_conflict_returns_48005(client) -> None:
    client.post("/api/v1/admin/risk/rules", json=_rule_body(), headers=STEP_UP)
    response = client.post("/api/v1/admin/risk/rules",
                           json=_rule_body(severity="P1", expected_version=9), headers=STEP_UP)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 48005
    assert "threshold" not in response.text.lower()


def test_rule_idempotency_key_replay_and_reuse(client) -> None:
    key = "idem-" + uuid.uuid4().hex
    headers = {**STEP_UP, "X-DJB-Idempotency-Key": key}
    first = client.post("/api/v1/admin/risk/rules", json=_rule_body(), headers=headers)
    assert first.status_code == 201
    replay = client.post("/api/v1/admin/risk/rules", json=_rule_body(), headers=headers)
    assert replay.status_code == 201
    assert replay.json()["version"] == first.json()["version"]
    reused = client.post("/api/v1/admin/risk/rules", json=_rule_body(severity="P3"),
                         headers=headers)
    assert reused.status_code == 409
    assert reused.json()["error"]["code"] == 40919


def test_rule_config_ref_must_be_risk_namespace(client) -> None:
    response = client.post("/api/v1/admin/risk/rules",
                           json=_rule_body(config_ref="pricing.foo"), headers=STEP_UP)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_rule_requires_step_up(client) -> None:
    response = client.post("/api/v1/admin/risk/rules", json=_rule_body())
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401


def test_rule_write_requires_scope(savepoint_conn) -> None:
    with build_client(savepoint_conn, admin=READONLY_PRINCIPAL) as readonly:
        assert readonly.get("/api/v1/admin/risk/rules").status_code == 200
        response = readonly.post("/api/v1/admin/risk/rules", json=_rule_body(),
                                 headers=STEP_UP)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 40301


def test_list_rules_enabled_filter_and_pagination(client) -> None:
    for index in range(3):
        client.post("/api/v1/admin/risk/rules",
                    json=_rule_body(rule_key=f"rule.{index}", enabled=index % 2 == 0),
                    headers=STEP_UP)
    enabled = client.get("/api/v1/admin/risk/rules", params={"enabled": "true"})
    assert enabled.status_code == 200
    assert all(row["enabled"] for row in enabled.json()["data"])
    page = client.get("/api/v1/admin/risk/rules", params={"limit": 2})
    assert page.status_code == 200
    assert len(page.json()["data"]) == 2
    assert page.json()["page"]["has_more"] is True
    next_cursor = page.json()["page"]["next_cursor"]
    page2 = client.get("/api/v1/admin/risk/rules",
                       params={"limit": 2, "cursor": next_cursor})
    assert page2.status_code == 200
    first_ids = {(row["rule_key"], row["version"]) for row in page.json()["data"]}
    second_ids = {(row["rule_key"], row["version"]) for row in page2.json()["data"]}
    assert first_ids.isdisjoint(second_ids)


# ───────────────────────────────────────────────────────────── 限额
def _limit_body(**overrides):
    body = {"subject_type": "account", "subject_id": "acct-0001", "limit_type": "qps",
            "value": 50, "window_s": 60}
    body.update(overrides)
    return body


def test_set_and_adjust_limit(client) -> None:
    created = client.post("/api/v1/admin/risk/limits", json=_limit_body(), headers=STEP_UP)
    assert created.status_code == 201, created.text
    assert created.json()["revision"] == 1
    assert created.json()["value"] == 50
    adjusted = client.post("/api/v1/admin/risk/limits",
                           json=_limit_body(value=20, expected_version=1), headers=STEP_UP)
    assert adjusted.status_code == 201
    assert adjusted.json()["revision"] == 2
    assert adjusted.json()["value"] == 20


def test_limit_expected_version_conflict(client) -> None:
    client.post("/api/v1/admin/risk/limits", json=_limit_body(), headers=STEP_UP)
    response = client.post("/api/v1/admin/risk/limits",
                           json=_limit_body(value=10, expected_version=7), headers=STEP_UP)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 48005


def test_limit_validation(client) -> None:
    for overrides in ({"subject_type": "unknown"}, {"value": -1},
                      {"value": "many"}, {"window_s": -5}):
        response = client.post("/api/v1/admin/risk/limits",
                               json=_limit_body(**overrides), headers=STEP_UP)
        assert response.status_code == 400, overrides
        assert response.json()["error"]["code"] == 40001


def test_limit_listing_uses_active_view_and_tenant_scope(client) -> None:
    tomorrow = (FIXED_NOW + timedelta(days=1)).isoformat()
    yesterday = (FIXED_NOW - timedelta(days=1)).isoformat()
    assert client.post("/api/v1/admin/risk/limits",
                       json=_limit_body(limit_type="qps", expires_at=tomorrow),
                       headers=STEP_UP).status_code == 201
    assert client.post("/api/v1/admin/risk/limits",
                       json=_limit_body(limit_type="daily_quota", expires_at=yesterday),
                       headers=STEP_UP).status_code == 201
    listing = client.get("/api/v1/admin/risk/limits")
    assert listing.status_code == 200
    types = {row["limit_type"] for row in listing.json()["data"]}
    assert "qps" in types and "daily_quota" not in types      # 过期即回收（视图口径）


def test_limit_tenant_isolation(savepoint_conn) -> None:
    with build_client(savepoint_conn, admin=ADMIN_PRINCIPAL) as tenant_a:
        created = tenant_a.post("/api/v1/admin/risk/limits", json=_limit_body(),
                                headers=STEP_UP)
        assert created.status_code == 201
    with build_client(savepoint_conn, admin=OTHER_TENANT_PRINCIPAL) as tenant_b:
        listing = tenant_b.get("/api/v1/admin/risk/limits")
        assert listing.status_code == 200
        assert listing.json()["data"] == []
        # 同主体同类型在另一租户可独立设置
        created_b = tenant_b.post("/api/v1/admin/risk/limits", json=_limit_body(),
                                  headers=STEP_UP)
        assert created_b.status_code == 201


def test_limit_subject_id_rejects_plaintext_pii(client) -> None:
    response = client.get("/api/v1/admin/risk/limits",
                          params={"subject_id": "user@example.com"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_limit_requires_step_up(client) -> None:
    response = client.post("/api/v1/admin/risk/limits", json=_limit_body())
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401


# ───────────────────────────────────────────────────────────── 未接线 fail-closed
@pytest.mark.parametrize("method,path", [
    ("get", "/api/v1/admin/risk/rules"),
    ("get", "/api/v1/admin/risk/limits"),
    ("get", "/api/v1/admin/risk/cases"),
    ("get", "/api/v1/admin/risk/cases/00000000-0000-0000-0000-000000000000"),
])
def test_unauth_get_is_401(unauth_client, method: str, path: str) -> None:
    response = getattr(unauth_client, method)(path)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == 40101


@pytest.mark.parametrize("path,body", [
    ("/api/v1/admin/risk/rules", _rule_body()),
    ("/api/v1/admin/risk/limits", _limit_body()),
    ("/api/v1/admin/risk/appeals", {"case_id": "x", "reason": "y"}),
])
def test_unauth_post_is_401(unauth_client, path: str, body: dict) -> None:
    response = unauth_client.post(path, json=body, headers=STEP_UP)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == 40101


def test_limit_query_for_unknown_subject_is_404(client) -> None:
    response = client.get("/api/v1/admin/risk/limits",
                          params={"subject_type": "account", "subject_id": "acct-unknown"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401
