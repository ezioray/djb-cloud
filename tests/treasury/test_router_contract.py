# SPDX-License-Identifier: Apache-2.0
"""M08 路由契约：spec 1.2.5 M08 段 21 操作逐字对齐 + 鉴权 fail-closed + 错误信封。"""
from __future__ import annotations

import pathlib

import pytest
import yaml

from app.treasury.router import create_router

import m08kit
from conftest import READONLY_PRINCIPAL, build_client

_REPO = pathlib.Path(__file__).resolve().parents[2]
# 契约 1.2.5 先在 workspace（spec 在主仓，尚未合入 integration 的 worktree）；两处都找
SPEC_CANDIDATES = (_REPO / "spec" / "openapi.yaml", _REPO.parents[1] / "spec" / "openapi.yaml")
SPEC = next((item for item in SPEC_CANDIDATES if item.exists()), SPEC_CANDIDATES[0])
if not SPEC.exists():                                   # pragma: no cover - 环境缺契约
    pytest.skip("缺 spec/openapi.yaml（契约未注入）", allow_module_level=True)
M08_PREFIXES = ("/api/v1/pay/", "/api/v1/provider/payout", "/api/v1/admin/treasury/")
M08_SKIP = ("/recon",)


def _spec_operations() -> set[tuple[str, str, str]]:
    spec = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    operations: set[tuple[str, str, str]] = set()
    for path, ops in (spec.get("paths") or {}).items():
        if not path.startswith(M08_PREFIXES) or any(skip in path for skip in M08_SKIP):
            continue
        for method, op in ops.items():
            if method not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                continue
            operations.add((op["operationId"], method, path))
    return operations


def _impl_operations() -> set[tuple[str, str, str]]:
    router = create_router(connection_factory=lambda: None)
    operations: set[tuple[str, str, str]] = set()
    for route in router.routes:
        for method in sorted(route.methods or []):
            if method in ("HEAD", "OPTIONS"):
                continue
            operations.add((route.operation_id, method.lower(), route.path))
    return operations


def test_route_vs_spec_diff_is_empty():
    wanted = _spec_operations()
    implemented = _impl_operations()
    assert len(wanted) == 21, wanted
    assert implemented == wanted
    assert implemented - wanted == set() and wanted - implemented == set()


def test_unauth_is_fail_closed(unauth_client):
    assert unauth_client.post("/api/v1/pay/orders", json={
        "amount_minor": 100, "currency": "USD", "method": "card"}).status_code == 401
    assert unauth_client.get("/api/v1/pay/orders/PO-1").status_code == 401
    assert unauth_client.get("/api/v1/provider/payouts").status_code == 401
    assert unauth_client.get("/api/v1/admin/treasury/pools").status_code == 401
    assert unauth_client.post("/api/v1/admin/treasury/switch", json={
        "pool_id": "polygon:hot:CLIENT", "reason": "x"}).status_code == 401
    # 回调不做用户鉴权（独立验签端点）
    assert unauth_client.post("/api/v1/pay/webhooks/mock", content=b"{}").status_code in (
        200, 400, 404, 409, 500)


def test_scope_enforcement_and_step_up(savepoint_conn):
    with build_client(savepoint_conn, admin=READONLY_PRINCIPAL) as client:
        assert client.get("/api/v1/admin/treasury/pools").status_code == 200
        assert client.post("/api/v1/admin/treasury/switch", json={
            "pool_id": "polygon:hot:CLIENT", "reason": "x"}).status_code == 403
        assert client.post("/api/v1/admin/treasury/pools", json={
            "chain": "polygon", "role": "warm",
            "fund_class": "CLIENT"}).status_code == 403
    with build_client(savepoint_conn, step_up=False) as client:
        assert client.post("/api/v1/admin/treasury/switch", json={
            "pool_id": "polygon:hot:CLIENT", "reason": "x"}).status_code == 424
        assert client.post("/api/v1/admin/treasury/pools", json={
            "chain": "polygon", "role": "warm", "fund_class": "CLIENT"}).status_code == 424


def test_error_envelope_shape(client):
    response = client.get("/api/v1/pay/orders/PO-NOT-EXIST")
    assert response.status_code == 404
    body = response.json()["error"]
    assert set(body) >= {"type", "code", "message", "request_id"}
    assert isinstance(body["code"], int)
    assert response.headers.get("X-Request-Id")


def test_body_limits_and_unknown_fields(client):
    huge = b"{" + b"a" * (facts_limit() + 10) + b"}"
    response = client.post("/api/v1/pay/orders", content=huge,
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert client.post("/api/v1/pay/orders", json={
        "amount_minor": 100, "currency": "USD", "method": "card", "x": 1}).status_code == 400


def facts_limit() -> int:
    from app.treasury import facts

    return facts.MAX_BODY_BYTES
