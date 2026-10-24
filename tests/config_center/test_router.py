# SPDX-License-Identifier: AGPL-3.0-or-later
"""管理面 router（T4）：11 条端点 / operationId 对齐 spec 1.2.1 / 错误信封 / 生效链路。

用 TestClient + 独立 schema（模块级，避免污染共享 schema）；``now_provider`` 固定在
周三 10:30（UTC+8）窗口内，所有时间相关行为可复现。
"""
from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import psycopg
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config_center import audit, drift, registry, router
from configkit import apply_migrations, connect, create_schema, dsn, drop_schema

NOW = datetime(2026, 10, 21, 2, 30, tzinfo=timezone.utc)          # 周三 10:30 CST
PROPOSER = {"X-Admin-Actor": "u1", "X-Admin-Roles": "FIN", "X-Admin-Step-Up": "step-pub-1"}
APPROVER = {"X-Admin-Actor": "u2", "X-Admin-Roles": "FIN", "X-Admin-Step-Up": "step-app-1"}
OPS = {"X-Admin-Actor": "ops1", "X-Admin-Roles": "OPS", "X-Admin-Step-Up": "step-ops-1"}


@pytest.fixture(scope="module")
def router_schema(db, schema_prefix):
    name = f"{schema_prefix}_router_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture(scope="module")
def audit_sink():
    return audit.InMemoryAuditSink()


@pytest.fixture(scope="module")
def client(router_schema, audit_sink):
    @contextmanager
    def factory():
        conn = psycopg.connect(dsn(), autocommit=False,
                               options=f"-c search_path={router_schema}")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    app = FastAPI()
    app.include_router(router.create_router(
        connection_factory=factory, now_provider=lambda: NOW, audit_sink=audit_sink))
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def draft_payload(value, *, value_type="integer", reason="router 测试草稿"):
    return {"value": value, "value_type": value_type, "reason": reason}


# ─────────────────────────────────────────────── 契约：operationId / 认证
def test_operation_ids_match_spec_1_2_1(client):
    api = client.get("/openapi.json").json()
    operations = {op["operationId"] for path in api["paths"].values()
                  for method, op in path.items()
                  if method in ("get", "post", "put", "delete", "patch")}
    assert operations == {
        "listConfigItems", "listConfigDrifts", "listConfigNamespaces", "getConfigItem",
        "getConfigDiff", "getConfigImpact", "createConfigDraft", "publishConfigItem",
        "approveConfigPublish", "rollbackConfigItem", "killSwitchConfigItem",
        "promoteConfigPublish", "listConfigAudit",
    }


def test_requires_actor(client):
    response = client.get("/api/v1/admin/config/items")
    assert response.status_code == 401
    assert response.json()["error"]["type"] == "authentication_error"


# ─────────────────────────────────────────────── 读：items / namespaces / get / diff
def test_items_namespaces_and_get(client):
    created = client.post("/api/v1/admin/config/content.wordlist_version",
                          json=draft_payload("v2026.10", value_type="string"), headers=PROPOSER)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["key"] == "content.wordlist_version" and body["state"] == "draft"

    items = client.get("/api/v1/admin/config/items", headers=PROPOSER,
                       params={"prefix": "content.", "limit": 10})
    assert items.status_code == 200
    payload = items.json()
    assert payload["data"] and all(row["key"].startswith("content.") for row in payload["data"])
    assert payload["page"]["has_more"] is False

    namespaces = client.get("/api/v1/admin/config/namespaces", headers=PROPOSER)
    assert namespaces.status_code == 200
    data = namespaces.json()["data"]
    assert len(data) == 12                                  # 十域 + config + points
    assert {row["namespace"] for row in data} >= {"billing", "treasury", "config", "points"}

    got = client.get("/api/v1/admin/config/content.wordlist_version", headers=PROPOSER)
    assert got.status_code == 200 and got.json()["value"] == "v2026.10"

    missing = client.get("/api/v1/admin/config/not.registered", headers=PROPOSER)
    assert missing.status_code == 404 and missing.json()["error"]["code"] == 47006
    missing_version = client.get("/api/v1/admin/config/content.wordlist_version",
                                 headers=PROPOSER, params={"version": 99})
    assert missing_version.status_code == 404


def test_diff_and_impact(client):
    client.post("/api/v1/admin/config/billing.service_fee_bps",
                json=draft_payload(1500), headers=PROPOSER)
    client.post("/api/v1/admin/config/billing.service_fee_bps",
                json=draft_payload(1600), headers=PROPOSER)
    diff = client.get("/api/v1/admin/config/billing.service_fee_bps/diff", headers=PROPOSER,
                      params={"from_version": 1, "to_version": 2})
    assert diff.status_code == 200, diff.text
    body = diff.json()
    assert body["from_version"] == 1 and body["to_version"] == 2
    assert body["changes"] == [{"path": "", "before": 1500, "after": 1600, "masked": False}]
    assert body["digest_before"] != body["digest_after"]

    impact = client.get("/api/v1/admin/config/billing.service_fee_bps/impact", headers=PROPOSER)
    assert impact.status_code == 200
    assert impact.json()["risk_level"] == "P0"
    assert impact.json()["consumers"] == ["scheduler", "settlement", "provider-console"]


# ─────────────────────────────────────────────── 写：草稿校验 / 幂等
def test_draft_validation_and_idempotency(client):
    bad_extra = client.post("/api/v1/admin/config/billing.service_fee_bps",
                            json={**draft_payload(1500), "extra": 1}, headers=PROPOSER)
    assert bad_extra.status_code == 400 and bad_extra.json()["error"]["code"] == 47001
    missing_type = client.post("/api/v1/admin/config/billing.service_fee_bps",
                               json={"value": 1500, "reason": "缺 value_type"}, headers=PROPOSER)
    assert missing_type.status_code == 400
    bad_type = client.post("/api/v1/admin/config/billing.service_fee_bps",
                           json=draft_payload("1500"), headers=PROPOSER)
    assert bad_type.status_code == 400
    forbidden = client.post("/api/v1/admin/config/risk.rule_version",
                            json=draft_payload("v1", value_type="string"), headers=PROPOSER)
    assert forbidden.status_code == 403 and forbidden.json()["error"]["code"] == 47004

    headers = {**PROPOSER, "X-DJB-Idempotency-Key": "idem-router-0000000001"}
    first = client.post("/api/v1/admin/config/pool.reserved_default",
                        json=draft_payload(30), headers=headers)
    second = client.post("/api/v1/admin/config/pool.reserved_default",
                         json=draft_payload(30), headers=headers)
    assert first.status_code == second.status_code == 201
    assert first.json()["version"] == second.json()["version"]


def test_sensitive_values_are_masked(client):
    created = client.post("/api/v1/admin/config/treasury.deposit_address_ref",
                          json={"secret_ref": {"scheme": "kms", "path": "alias/treasury-signing",
                                               "inject": "sdk", "version": "v1"},
                                "value_type": "json", "reason": "初始化地址引用"},
                          headers=PROPOSER)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["masked"] is True
    assert body.get("value") is None
    assert body["secret_ref"] == "kms://alias/treasury-signing"


# ─────────────────────────────────────────────── 发布 → 复核 → 生效（S1 同步）
def test_publish_approve_activates(client):
    draft = client.post("/api/v1/admin/config/pool.reserved_default",
                        json=draft_payload(35), headers=OPS)
    assert draft.status_code == 201, draft.text
    version = draft.json()["version"]
    published = client.post("/api/v1/admin/config/pool.reserved_default/publish",
                            json={"version": version, "reason": "预留池 30→35"}, headers=OPS)
    assert published.status_code == 202, published.text
    ack = published.json()
    assert ack["state"] == "pending_approval" and ack["approvals_required"] == 1
    assert ack["version"] == version

    approved = client.post(f"/api/v1/admin/config/publish-requests/{ack['request_id']}/approve",
                           json={"decision": "approve", "reason": "复核通过"}, headers=APPROVER)
    assert approved.status_code == 200, approved.text
    assert approved.json()["state"] == "active"

    got = client.get("/api/v1/admin/config/pool.reserved_default", headers=PROPOSER)
    assert got.json()["state"] == "active"
    assert got.json()["value"] == 35


def test_publish_without_step_up_returns_424(client):
    draft = client.post("/api/v1/admin/config/billing.service_fee_bps",
                        json=draft_payload(1500), headers=PROPOSER)
    version = draft.json()["version"]
    response = client.post(
        "/api/v1/admin/config/billing.service_fee_bps/publish",
        json={"version": version, "reason": "缺 step-up"},
        headers={"X-Admin-Actor": "u1", "X-Admin-Roles": "FIN"})
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401


def test_self_approval_returns_403(client):
    draft = client.post("/api/v1/admin/config/treasury.hot_wallet_cap",
                        json=draft_payload("9000.00", value_type="string"), headers=PROPOSER)
    version = draft.json()["version"]
    published = client.post("/api/v1/admin/config/treasury.hot_wallet_cap/publish",
                            json={"version": version, "reason": "调整热钱包上限"}, headers=PROPOSER)
    assert published.status_code == 202, published.text
    request_id = published.json()["request_id"]
    response = client.post(f"/api/v1/admin/config/publish-requests/{request_id}/approve",
                           json={"decision": "approve", "reason": "自批自核"}, headers=PROPOSER)
    assert response.status_code == 403 and response.json()["error"]["code"] == 47002


# ─────────────────────────────────────────────── P2：发布即生效 → 回滚
def test_p2_rollback_flow(client):
    first = client.post("/api/v1/admin/config/notify.report.daily_send_at",
                        json=draft_payload("02:00", value_type="string"), headers=OPS)
    assert first.status_code == 201
    v1 = first.json()["version"]
    published = client.post("/api/v1/admin/config/notify.report.daily_send_at/publish",
                            json={"version": v1, "reason": "调整日报时刻"}, headers=OPS)
    assert published.status_code == 202 and published.json()["state"] == "active"  # P2 单人即生效

    second = client.post("/api/v1/admin/config/notify.report.daily_send_at",
                         json=draft_payload("03:00", value_type="string"), headers=OPS)
    v2 = second.json()["version"]
    published2 = client.post("/api/v1/admin/config/notify.report.daily_send_at/publish",
                             json={"version": v2, "reason": "再次调整"}, headers=OPS)
    assert published2.json()["state"] == "active"

    rolled = client.post("/api/v1/admin/config/notify.report.daily_send_at/rollback",
                         json={"target_version": v1, "reason": "回滚到 02:00"}, headers=OPS)
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["state"] == "active"
    got = client.get("/api/v1/admin/config/notify.report.daily_send_at", headers=OPS)
    assert got.json()["value"] == "02:00"
    assert got.json()["version"] > v2


# ─────────────────────────────────────────────── kill switch
def test_kill_switch_endpoint(client):
    draft = client.post("/api/v1/admin/config/billing.service_fee_bps",
                        json=draft_payload(1500), headers=PROPOSER)
    version = draft.json()["version"]
    published = client.post("/api/v1/admin/config/billing.service_fee_bps/publish",
                            json={"version": version, "reason": "费率对齐基线"}, headers=PROPOSER)
    request_id = published.json()["request_id"]
    approved = client.post(f"/api/v1/admin/config/publish-requests/{request_id}/approve",
                           json={"decision": "approve", "reason": "复核通过"},
                           headers=APPROVER)
    assert approved.status_code == 200 and approved.json()["state"] == "active"

    killed = client.post("/api/v1/admin/config/billing.service_fee_bps/kill-switch",
                         json={"value": 1400, "ttl_seconds": 600, "reason": "事故止损",
                               "tighten_only": True}, headers=PROPOSER)
    assert killed.status_code == 200, killed.text
    body = killed.json()
    assert body["state"] == "active" and body["emergency"] is True
    assert body["expires_at"] is not None
    got = client.get("/api/v1/admin/config/billing.service_fee_bps", headers=PROPOSER)
    assert got.json()["value"] == 1400

    widened = client.post("/api/v1/admin/config/billing.service_fee_bps/kill-switch",
                          json={"value": 1600, "ttl_seconds": 60, "reason": "借开关放宽"},
                          headers=PROPOSER)
    assert widened.status_code == 403 and widened.json()["error"]["code"] == 47004


# ─────────────────────────────────────────────── S2：灰度推进 / M16 审计只读
def test_promote_requires_gray_switch(client):
    draft = client.post("/api/v1/admin/config/treasury.platform_share_bps",
                        json=draft_payload(1500), headers=PROPOSER)
    version = draft.json()["version"]
    published = client.post("/api/v1/admin/config/treasury.platform_share_bps/publish",
                            json={"version": version, "reason": "灰度推进测试"}, headers=PROPOSER)
    request_id = published.json()["request_id"]
    client.post(f"/api/v1/admin/config/publish-requests/{request_id}/approve",
                json={"decision": "approve", "reason": "复核通过"}, headers=APPROVER)
    promoted = client.post(f"/api/v1/admin/config/publish-requests/{request_id}/promote",
                           json={"target_stage": "next_bucket"}, headers=PROPOSER)
    assert promoted.status_code == 409
    assert promoted.json()["error"]["code"] == 47007


def test_audit_endpoint_lists_injected_sink(client, audit_sink):
    response = client.get("/api/v1/admin/config/billing.service_fee_bps/audit",
                          headers=PROPOSER, params={"limit": 20})
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "m16-injected"
    assert body["data"] and all(row["key"] == "billing.service_fee_bps" for row in body["data"])
    assert any(row["action"] == "config.published" for row in body["data"])
    # 审计事件来自真实动作，且不含明文敏感值
    assert all("value" not in row for row in body["data"])


# ─────────────────────────────────────────────── 漂移清单
def test_drifts_endpoint(client, router_schema):
    with connect(router_schema) as conn:
        drift.scan_effective_vs_running(
            conn, {"pool.reserved_default": 9}, now=NOW)
    response = client.get("/api/v1/admin/config/drifts", headers=PROPOSER)
    assert response.status_code == 200
    data = response.json()["data"]
    assert any(row["key"] == "pool.reserved_default" and row["running_version"] == 9
               for row in data)
