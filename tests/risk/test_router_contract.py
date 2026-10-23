# SPDX-License-Identifier: Apache-2.0
"""契约测试：9 条操作 ⊆ spec 1.2.4、错误信封、request_id、错误码登记、无阈值泄漏。"""
from __future__ import annotations

import os
import pathlib
import uuid

import pytest
import yaml

from conftest import ADMIN_PRINCIPAL, build_client
from riskkit import FIXED_NOW, make_case

STEP_UP = {"X-Admin-Step-Up": "step-up-token-123"}


def _resolve_spec() -> pathlib.Path:
    """spec 不在模块工作树里（只读引用）：优先 $DJB_SPEC_FILE，其次 ROOT/spec。"""
    here = pathlib.Path(__file__).resolve()
    candidates = []
    if os.environ.get("DJB_SPEC_FILE"):
        candidates.append(pathlib.Path(os.environ["DJB_SPEC_FILE"]))
    candidates.append(here.parents[4] / "spec" / "openapi.yaml")
    candidates.append(here.parents[2] / "spec" / "openapi.yaml")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]


SPEC_PATH = _resolve_spec()

HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def _spec() -> dict:
    if not SPEC_PATH.exists():
        pytest.skip(f"spec 缺失（{SPEC_PATH}）")
    return yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))


def _spec_risk_ops() -> dict[tuple[str, str], dict]:
    spec = _spec()
    return {(method, path): item[method]
            for path, item in spec["paths"].items()
            if path.startswith("/api/v1/admin/risk")
            for method in item if method in HTTP_METHODS}


def _implemented_risk_ops() -> dict[tuple[str, str], dict]:
    """直接读路由工厂的 APIRouter（FastAPI 0.149 的 include_router 是嵌套路由）。"""
    from app.risk.router import create_router

    router = create_router(connection_factory=lambda: None)
    implemented = {}
    for route in router.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/v1/admin/risk"):
            continue
        for method in (getattr(route, "methods", set()) or set()) - {"HEAD", "OPTIONS"}:
            implemented[(method.lower(), path)] = route
    return implemented


def test_nine_operations_match_spec_exactly() -> None:
    spec_ops = _spec_risk_ops()
    implemented = _implemented_risk_ops()
    assert len(spec_ops) == 9, sorted(spec_ops)
    assert set(implemented) == set(spec_ops), {
        "missing": sorted(set(spec_ops) - set(implemented)),
        "extra": sorted(set(implemented) - set(spec_ops)),
    }
    # operationId 与 spec 对齐（合并期 / 文档生成可对得上）
    for (method, path), item in spec_ops.items():
        assert implemented[(method, path)].operation_id == item["operationId"]


def test_error_envelope_shape_and_request_id(client) -> None:
    response = client.post("/api/v1/admin/risk/rules", json={"severity": "P9"},
                           headers={**STEP_UP, "X-Request-Id": "rid-123"})
    assert response.status_code == 400
    assert response.headers["X-Request-Id"] == "rid-123"
    error = response.json()["error"]
    assert set(error) >= {"type", "code", "message", "request_id"}
    assert isinstance(error["code"], int)
    assert error["request_id"] == "rid-123"
    assert error["type"] == "invalid_request_error"


def test_success_responses_echo_request_id(client) -> None:
    response = client.get("/api/v1/admin/risk/rules", headers={"X-Request-Id": "rid-ok"})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == "rid-ok"


@pytest.mark.parametrize("code,status", [
    (40001, 400), (40101, 401), (40301, 403), (40401, 404), (40919, 409), (42401, 424),
    (48002, 409), (48003, 409), (48004, 400), (48005, 409), (48006, 403),
])
def test_registered_error_codes_have_expected_status(code: int, status: int) -> None:
    from app.risk import errors

    mapping = {cls.code: cls.status_code for cls in _error_classes()}
    assert mapping[code] == status


def _error_classes():
    from app.risk import errors

    return [value for value in vars(errors).values()
            if isinstance(value, type) and issubclass(value, errors.RiskError)
            and value is not errors.RiskError]


def test_spec_1_2_4_registers_48xxx_codes() -> None:
    raw = SPEC_PATH.read_text(encoding="utf-8") if SPEC_PATH.exists() else ""
    for code in ("48001", "48002", "48003", "48004", "48005", "48006"):
        assert code in raw, f"spec 未登记 {code}"
    assert "42401" in raw and "40919" in raw


def test_rule_and_case_responses_have_no_threshold_fields(client, savepoint_conn) -> None:
    rule = client.post("/api/v1/admin/risk/rules",
                       json={"rule_key": "key_leak.rate", "severity": "P1",
                             "action_class": "manual_review", "config_ref": "risk.limit.qps"},
                       headers=STEP_UP)
    case = make_case(savepoint_conn, status="opened")
    detail = client.get(f"/api/v1/admin/risk/cases/{case['case_id']}")
    bodies = [rule.json(), detail.json()]
    forbidden = ("threshold", "weight", "blocklist", "blacklist", "allowlist", "score_weight",
                 "rule_score")
    for body in bodies:
        text = str(body).lower()
        for token in forbidden:
            assert token not in text, f"响应出现敏感字段：{token}"


def test_unknown_route_is_not_implemented(client) -> None:
    response = client.get("/api/v1/admin/risk/unknown")
    assert response.status_code == 404
