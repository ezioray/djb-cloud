# SPDX-License-Identifier: AGPL-3.0-or-later
"""契约门禁：十条端点 / operationId / 与冻结 spec 1.2.5 逐字一致 / 错误码已登记。

路由差集必须为 0（Lead 合并前跑 route-vs-spec）：本测试从 ROOT/spec/openapi.yaml 反查；
ROOT spec 不存在（如单独 checkout 模块）时跳过该条，其余断言照跑。
"""
from __future__ import annotations

import pathlib
import uuid

import pytest

from admin_kit import FIXED_NOW, build_client, idempotency_key, write_headers
from app.data_gov import errors as m14_errors

EXPECTED: dict[tuple[str, str], str] = {
    ("/api/v1/admin/data/export-requests", "GET"): "listAdminDataExportRequests",
    ("/api/v1/admin/data/export-requests", "POST"): "createAdminDataExportRequest",
    ("/api/v1/admin/data/export-requests/{export_id}", "GET"): "getAdminDataExportRequest",
    ("/api/v1/admin/data/export-requests/{export_id}/cancel", "POST"):
        "cancelAdminDataExportRequest",
    ("/api/v1/admin/data/retention-jobs", "POST"): "createRetentionJob",
    ("/api/v1/admin/data/retention-jobs", "GET"): "listRetentionJobs",
    ("/api/v1/admin/ops/health", "GET"): "getOpsHealth",
    ("/api/v1/admin/ops/changes", "GET"): "listOpsChanges",
    ("/api/v1/admin/ops/batch-ops", "POST"): "executeOpsBatch",
    ("/api/v1/admin/ops/audit-replay", "GET"): "replayOpsAudit",
}

WRITE_ENDPOINTS = {(path, method) for (path, method) in EXPECTED
                   if method == "POST"}


def _routes() -> dict[tuple[str, str], str]:
    from app.data_gov.router import create_router

    # 直接读 APIRouter.routes：当前 FastAPI 的 include_router 是惰性挂载（_IncludedRouter），
    # app.routes 里看不到子路由；真正的 path / operationId 以 router.routes 为准。
    router = create_router(connection_factory=lambda: None, link_secret=b"x")
    routes: dict[tuple[str, str], str] = {}
    for route in router.routes:
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", "")
        if not (path.startswith("/api/v1/admin/data")
                or path.startswith("/api/v1/admin/ops")):
            continue
        for method in methods:
            if method in ("HEAD", "OPTIONS"):
                continue
            routes[(path, method)] = getattr(route, "operation_id", "")
    return routes


def _url(path: str) -> str:
    return path.replace("{export_id}", str(uuid.uuid4()))


def test_exactly_ten_operations_with_frozen_ids() -> None:
    assert _routes() == EXPECTED


def test_routes_match_frozen_spec() -> None:
    root = pathlib.Path(__file__).resolve().parents[4]
    spec_path = root / "spec" / "openapi.yaml"
    if not spec_path.exists():
        pytest.skip("ROOT/spec/openapi.yaml 不存在（单独 checkout 模块）")
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    frozen: dict[tuple[str, str], str] = {}
    for path, item in (document.get("paths") or {}).items():
        if not (path.startswith("/api/v1/admin/data")
                or path.startswith("/api/v1/admin/ops")):
            continue
        for method, operation in item.items():
            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE") and isinstance(
                    operation, dict):
                frozen[(path, method.upper())] = operation.get("operationId", "")
    if not frozen:
        pytest.skip("冻结 spec 尚未包含 M14 端点（CR-2 未合并）")
    assert frozen == EXPECTED
    assert _routes() == frozen


def test_unauthenticated_requests_are_401(unauth_client) -> None:
    for path, method in EXPECTED:
        response = (unauth_client.get(_url(path)) if method == "GET"
                    else unauth_client.post(_url(path), json={},
                                            headers=write_headers("u401")))
        assert response.status_code == 401, (path, method, response.text)
        error = response.json()["error"]
        assert error["code"] == 40101 and error["type"] == "authentication_error"
        assert {"type", "code", "message", "request_id"} <= set(error)


def test_non_admin_requests_are_403(nonadmin_client) -> None:
    for path, method in EXPECTED:
        response = (nonadmin_client.get(_url(path)) if method == "GET"
                    else nonadmin_client.post(_url(path), json={},
                                              headers=write_headers("n403")))
        assert response.status_code == 403, (path, method, response.text)
        assert response.json()["error"]["code"] == 40301


def test_readonly_cannot_write(readonly_client) -> None:
    for path, method in WRITE_ENDPOINTS:
        response = readonly_client.post(_url(path), json={},
                                        headers=write_headers("ro403"))
        assert response.status_code == 403, (path, response.text)


def test_write_endpoints_require_step_up(no_stepup_client) -> None:
    for path, method in WRITE_ENDPOINTS:
        headers = {"X-DJB-Idempotency-Key": idempotency_key("nostep")}
        response = no_stepup_client.post(_url(path), json={}, headers=headers)
        assert response.status_code == 424, (path, response.text)
        assert response.json()["error"]["code"] == 42401


def test_write_endpoints_require_idempotency(client) -> None:
    for path, method in WRITE_ENDPOINTS:
        response = client.post(_url(path), json={},
                               headers={"X-Admin-Step-Up": "step-up-token"})
        assert response.status_code == 400, (path, response.text)
        assert response.json()["error"]["code"] == 40001


def test_error_codes_are_registered() -> None:
    classes = [value for value in vars(m14_errors).values()
               if isinstance(value, type) and issubclass(value, m14_errors.M14Error)
               and value is not m14_errors.M14Error]
    codes = {cls.code for cls in classes}
    assert codes == set(m14_errors.REGISTERED_CODES)
    assert {40001, 40101, 40301, 40401, 40901, 42401, 49001} <= codes


def test_error_status_mapping_follows_lead_ruling() -> None:
    assert m14_errors.BadRequest.status_code == 400
    assert m14_errors.Unauthorized.status_code == 401
    assert m14_errors.Forbidden.status_code == 403
    assert m14_errors.NotFound.status_code == 404
    assert m14_errors.Conflict.status_code == 409
    assert m14_errors.StepUpRequired.status_code == 424
    assert m14_errors.ExportTooLarge.status_code == 400        # Lead 裁决：不用 413
    assert m14_errors.ServerError.status_code == 500


def test_error_envelope_shape(client) -> None:
    not_found = client.get("/api/v1/admin/data/export-requests/"
                           f"{uuid.uuid4()}")
    assert not_found.status_code == 404
    body = not_found.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == 40401
    assert not_found.headers["X-Request-Id"]
    bad = client.post("/api/v1/admin/data/export-requests", json={},
                      headers={"X-Admin-Step-Up": "x"})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == 40001


def test_admin_facade_exposes_same_router() -> None:
    from app.admin.data_gov import create_router as facade_router
    from app.data_gov.router import create_router as canonical_router

    assert facade_router is canonical_router
    assert callable(facade_router)


def test_list_envelope_has_page(savepoint_conn, client) -> None:
    response = client.get("/api/v1/admin/data/export-requests")
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {"data", "page"}
    assert payload["page"]["has_more"] is False
    assert payload["page"]["next_cursor"] is None
    assert response.headers["X-Request-Id"]
