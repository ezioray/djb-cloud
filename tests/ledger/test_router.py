# SPDX-License-Identifier: Apache-2.0
"""管理面 6 端点验收（spec 1.2.1）：operationId 契约、响应必填字段、错误码、step-up / 权限拒绝。

路由器不改 app/api.py：本测试用独立 FastAPI 实例挂载 ``app.ledger.router.router``，
与 lead 合并时的接线方式一致（``app.include_router(ledger_router)``）。
"""
from __future__ import annotations

import os
import time

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.ledger import merkle
from app.ledger.constants import RECOMPUTE_LOCK_ID
from app.ledger.router import OPERATIONS, router
from app.ledger.trial import decimal_str

from ledger_gatewaykit import e6_draft, post_ok
from ledgerkit import apply_migrations, connect, create_schema, drop_schema

STEP_UP = {"X-Admin-Step-Up": str(int(time.time())), "X-Admin-Roles": "fin",
           "X-Admin-Actor": "ops-1"}


def _spec_or_none() -> dict | None:
    """spec 1.2.1（CI 拉取）；本地没有就返回 None —— 端点用例照跑，只跳过纯契约比对。"""
    path = os.environ.get("DJB_SPEC_FILE") or os.path.join("spec", "openapi.yaml")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _spec() -> dict:
    spec = _spec_or_none()
    if spec is None:
        pytest.skip("spec 缺失（CI 会拉 spec 1.2.1）；纯契约比对用例在有 spec 时校验")
    return spec


# 内置最小契约（不依赖 spec 文件也要校验的必填字段，来自 spec 1.2.1 的 required）
MIN_REQUIRED = {
    "trial-balance": {"as_of", "unit_type", "balanced", "totals", "accounts"},
    "accounts": {"data", "page"},
    "merkle": {"period", "kind", "root", "entry_count", "published_at"},
    "recompute": {"job_id", "state", "requested_at"},
    "journal": {"journal_id", "ts", "state", "lines"},
    "reversal": {"reversal_id", "journal_id", "state", "created_at"},
}


def _assert_min_required(payload: dict, kind: str) -> None:
    assert MIN_REQUIRED[kind] <= set(payload), (kind, sorted(set(payload)))


def _resolve(spec: dict, node: dict) -> dict:
    if "$ref" in node:
        return spec["components"]["schemas"][node["$ref"].split("/")[-1]]
    return node


def _required_fields(spec: dict, path: str, method: str, status: str) -> set[str]:
    node = spec["paths"][path][method]["responses"][status]["content"]["application/json"]["schema"]
    return set(_resolve(spec, node).get("required", []))


@pytest.fixture(scope="module")
def api():
    """模块级隔离 schema + 独立 FastAPI 实例（与 lead 合并时的接线方式一致）。

    ``app.db.conn()`` 不带 options，所以这里用 PGOPTIONS 把 search_path 重定向到测试 schema ——
    与 CI 的 public schema 互不打扰，模块结束即 DROP。
    """
    name = f"m06_t4_api_{os.getpid()}_{int(time.time() * 1000) % 100000}"
    create_schema(name)
    apply_migrations(name)
    os.environ["PGOPTIONS"] = f"-c search_path={name} -c synchronous_commit=off"
    app = FastAPI()
    app.include_router(router)
    try:
        yield TestClient(app), name
    finally:
        os.environ.pop("PGOPTIONS", None)
        drop_schema(name)


def _seed_journal(schema_name: str, **over) -> str:
    return post_ok(schema_name, e6_draft(amount_minor=30_000_000, **over)).journal_id


# ─────────────────────────────────────────────────────── 契约：operationId / 路径 / 必填字段
def test_operations_match_spec() -> None:
    spec = _spec()
    for operation_id, meta in OPERATIONS.items():
        node = spec["paths"][meta["path"]][meta["method"].lower()]
        assert node.get("operationId") == operation_id, (operation_id, node.get("operationId"))


def test_router_registers_exactly_the_six_operations() -> None:
    spec = _spec()
    ours = {(meta["method"].lower(), meta["path"]) for meta in OPERATIONS.values()}
    assert len(ours) == 6
    for method, path in ours:
        assert path in spec["paths"] and method in spec["paths"][path]
    declared_ledger = {
        (method, path) for path, item in spec["paths"].items()
        if path.startswith("/api/v1/admin/ledger/")
        for method in item if method in ("get", "post")
    }
    assert ours <= declared_ledger


# ─────────────────────────────────────────────────────── 正常路径
def test_trial_balance_endpoint(api) -> None:
    client, schema_name = api
    _seed_journal(schema_name)
    resp = client.get("/api/v1/admin/ledger/trial-balance", headers=STEP_UP)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    _assert_min_required(payload, "trial-balance")
    spec = _spec_or_none()
    if spec:
        assert _required_fields(spec, "/api/v1/admin/ledger/trial-balance", "get", "200") <= set(payload)
    assert payload["balanced"] is True
    assert len(payload["accounts"]) == 42
    assert resp.headers["X-Request-Id"]


def test_accounts_endpoint_paginates(api) -> None:
    client, _ = api
    resp = client.get("/api/v1/admin/ledger/accounts",
                      params={"limit": 10, "fund_class": "CLIENT", "unit_type": "USD"},
                      headers=STEP_UP)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    _assert_min_required(payload, "accounts")
    spec = _spec_or_none()
    if spec:
        assert _required_fields(spec, "/api/v1/admin/ledger/accounts", "get", "200") <= set(payload)
    assert payload["page"]["has_more"] is True and payload["page"]["next_cursor"]
    assert all(row["fund_class"] == "CLIENT" for row in payload["data"])


def test_merkle_endpoint_404_then_200(api) -> None:
    client, schema_name = api
    resp = client.get("/api/v1/admin/ledger/merkle/2000-01-01T00", headers=STEP_UP)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == 40924

    with connect(schema_name) as c:
        merkle.anchor(c, kind="journal", period="2000-01-01T00")
    resp = client.get("/api/v1/admin/ledger/merkle/2000-01-01T00", headers=STEP_UP)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    _assert_min_required(payload, "merkle")
    spec = _spec_or_none()
    if spec:
        assert _required_fields(spec, "/api/v1/admin/ledger/merkle/{period}", "get", "200") <= set(payload)
    assert payload["kind"] == "journal" and payload["reproducible"] is True


def test_recompute_endpoint_is_read_only_and_clean(api) -> None:
    client, _ = api
    before_headers = STEP_UP | {"X-Request-Id": "req-recompute-1"}
    resp = client.post("/api/v1/admin/ledger/recompute", json={"dry_run": True},
                       headers=before_headers)
    assert resp.status_code == 202, resp.text
    payload = resp.json()
    _assert_min_required(payload, "recompute")
    spec = _spec_or_none()
    if spec:
        assert _required_fields(spec, "/api/v1/admin/ledger/recompute", "post", "202") <= set(payload)
    assert payload["state"] == "succeeded" and payload["verified"] is True
    assert payload["diff_count"] == 0
    assert payload["report"]["chain"]["diff"] == 0
    assert resp.headers["X-Request-Id"] == "req-recompute-1"


def test_journal_endpoint(api) -> None:
    client, schema_name = api
    journal_id = _seed_journal(schema_name, source_id="router-journal-1")
    resp = client.get(f"/api/v1/admin/ledger/journals/{journal_id}", headers=STEP_UP)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    _assert_min_required(payload, "journal")
    spec = _spec_or_none()
    if spec:
        assert _required_fields(spec, "/api/v1/admin/ledger/journals/{id}", "get", "200") <= set(payload)
    assert payload["journal_id"] == journal_id and payload["state"] == "posted"
    assert len(payload["lines"]) == 2
    assert {line["dc"] for line in payload["lines"]} == {"debit", "credit"}
    assert payload["lines"][0]["amount"]["amount"] == decimal_str(30_000_000)


def test_journal_not_found(api) -> None:
    client, _ = api
    resp = client.get("/api/v1/admin/ledger/journals/00000000-0000-0000-0000-000000000000",
                      headers=STEP_UP)
    assert resp.status_code == 404
    error = resp.json()["error"]
    assert error["code"] == 40924 and error["type"] == "not_found_error"
    assert error["request_id"] == resp.headers["X-Request-Id"]


def test_reversal_endpoint_posts_and_rejects_repeat(api) -> None:
    client, schema_name = api
    journal_id = _seed_journal(schema_name, source_id="router-reversal-1")
    body = {"journal_id": journal_id, "reason": "ops_error", "second_approver": "fin-auditor"}
    resp = client.post("/api/v1/admin/ledger/reversals", json=body, headers=STEP_UP)
    assert resp.status_code == 201, resp.text
    payload = resp.json()
    _assert_min_required(payload, "reversal")
    spec = _spec_or_none()
    if spec:
        assert _required_fields(spec, "/api/v1/admin/ledger/reversals", "post", "201") <= set(payload)
    assert payload["journal_id"] == journal_id and payload["state"] == "posted"
    assert payload["reversal_id"] != journal_id

    repeat = client.post("/api/v1/admin/ledger/reversals", json=body, headers=STEP_UP)
    assert repeat.status_code == 409
    assert repeat.json()["error"]["code"] == 40921          # spec 1.2.1：原凭证已冲正


# ─────────────────────────────────────────────────────── step-up / 权限拒绝
@pytest.mark.parametrize("method,path,body", [
    ("get", "/api/v1/admin/ledger/trial-balance", None),
    ("get", "/api/v1/admin/ledger/accounts", None),
    ("get", "/api/v1/admin/ledger/merkle/2026-10", None),
    ("post", "/api/v1/admin/ledger/recompute", {"dry_run": True}),
    ("get", "/api/v1/admin/ledger/journals/x", None),
    ("post", "/api/v1/admin/ledger/reversals", {"journal_id": "x", "reason": "r",
                                                "second_approver": "y"}),
])
def test_missing_step_up_is_424(api, method: str, path: str, body) -> None:
    client, _ = api
    kwargs = {"headers": {"X-Admin-Roles": "fin"}}
    resp = getattr(client, method)(path, json=body, **kwargs) if body is not None \
        else getattr(client, method)(path, **kwargs)
    assert resp.status_code == 424, resp.text
    error = resp.json()["error"]
    assert error["code"] == 42401 and error["type"] == "authentication_error"


def test_stale_step_up_is_rejected(api) -> None:
    client, _ = api
    stale = {"X-Admin-Step-Up": str(int(time.time()) - 3600), "X-Admin-Roles": "fin"}
    resp = client.get("/api/v1/admin/ledger/trial-balance", headers=stale)
    assert resp.status_code == 424 and resp.json()["error"]["code"] == 42401


def test_viewer_cannot_write_but_can_read(api) -> None:
    client, schema_name = api
    viewer = {"X-Admin-Step-Up": str(int(time.time())), "X-Admin-Roles": "viewer"}
    assert client.get("/api/v1/admin/ledger/trial-balance", headers=viewer).status_code == 200
    journal_id = _seed_journal(schema_name, source_id="router-viewer-1")
    resp = client.post("/api/v1/admin/ledger/reversals",
                       json={"journal_id": journal_id, "reason": "x", "second_approver": "a"},
                       headers=viewer)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == 40301 and resp.json()["error"]["type"] == "permission_error"
    assert client.post("/api/v1/admin/ledger/recompute", json={}, headers=viewer).status_code == 403


# ─────────────────────────────────────────────────────── 参数与冲突
def test_reversal_requires_fields(api) -> None:
    client, _ = api
    resp = client.post("/api/v1/admin/ledger/reversals", json={"journal_id": "x"}, headers=STEP_UP)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == 40013


def test_reversal_rejects_self_approval(api) -> None:
    client, schema_name = api
    journal_id = _seed_journal(schema_name, source_id="router-sod-1")
    resp = client.post("/api/v1/admin/ledger/reversals",
                       json={"journal_id": journal_id, "reason": "x", "second_approver": "ops-1"},
                       headers=STEP_UP)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == 40902


def test_reversal_unknown_journal_is_404(api) -> None:
    client, _ = api
    resp = client.post("/api/v1/admin/ledger/reversals",
                       json={"journal_id": "00000000-0000-0000-0000-000000000000",
                             "reason": "x", "second_approver": "fin-auditor"},
                       headers=STEP_UP)
    assert resp.status_code == 404 and resp.json()["error"]["code"] == 40924


def test_recompute_rejects_bad_scope_and_busy_lock(api) -> None:
    client, schema_name = api
    bad = client.post("/api/v1/admin/ledger/recompute", json={"scope": "nope"}, headers=STEP_UP)
    assert bad.status_code == 400 and bad.json()["error"]["code"] == 40013

    with connect(schema_name) as c, c.cursor() as cur:
        cur.execute("SELECT pg_advisory_lock(%s)", (RECOMPUTE_LOCK_ID,))
        try:
            busy = client.post("/api/v1/admin/ledger/recompute", json={"dry_run": True},
                               headers=STEP_UP)
        finally:
            cur.execute("SELECT pg_advisory_unlock(%s)", (RECOMPUTE_LOCK_ID,))
    assert busy.status_code == 409
    assert busy.json()["error"]["code"] == 40920


def test_trial_balance_rejects_bad_as_of(api) -> None:
    client, _ = api
    resp = client.get("/api/v1/admin/ledger/trial-balance", params={"as_of": "not-a-time"},
                      headers=STEP_UP)
    assert resp.status_code == 400 and resp.json()["error"]["code"] == 40013


def test_merkle_rejects_other_kinds(api) -> None:
    client, _ = api
    resp = client.get("/api/v1/admin/ledger/merkle/2026-10",
                      params={"kind": "audit"}, headers=STEP_UP)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == 42222
