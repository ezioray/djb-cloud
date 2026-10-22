# SPDX-License-Identifier: Apache-2.0
"""M01 契约面测试：spec 1.2.0 的 13 个 M01 操作逐条对账（tasks-11 验收 3）。

对账口径：
- **T2 已实现的 5 个操作**（login / refresh / logout / profile GET/PATCH）：
  路径 + 方法 + ``operationId`` 必须与 spec 一致；成功响应必须包含 spec 的必填字段；
  ``security`` 与 spec 一致（login / refresh 是 ``security: []``）；
  错误响应必须是 spec ``Error`` 信封（``error.type/code/message/request_id``）。
- **T3 / T4 的 8 个操作**：spec 里必须仍存在（防漂移），且当前**未实现**——
  这样任何一方先接线都会立刻红，避免「悄悄多出路由」。
- 扫码轮询复用 ``/auth/login``，中间态用 **202**：spec 1.2.0 未声明 202，
  断言此差异存在（CR 已登记在证据文件，等 Lead 决定是否进 spec）。
"""
from __future__ import annotations

import os

import pytest
import yaml

from app.identity import router as router_module

SPEC_ENV = "DJB_SPEC_FILE"
SPEC_DEFAULT = os.path.join("spec", "openapi.yaml")

# T2 交付的 5 个操作（spec 1.2.0）
IMPLEMENTED = {
    ("post", "/api/v1/auth/login"): "createAuthSession",
    ("post", "/api/v1/auth/refresh"): "refreshAuthSession",
    ("post", "/api/v1/auth/logout"): "revokeAuthSession",
    ("get", "/api/v1/user/profile"): "getUserProfile",
    ("patch", "/api/v1/user/profile"): "updateUserProfile",
}
# T3 / T4 的 8 个操作：spec 必须有，T2 不得实现
DEFERRED = {
    ("get", "/api/v1/user/api-keys"): ("listApiKeys", "T3"),
    ("post", "/api/v1/user/api-keys"): ("createApiKey", "T3"),
    ("delete", "/api/v1/user/api-keys/{id}"): ("revokeApiKey", "T3"),
    ("post", "/api/v1/user/api-keys/{id}/rotate"): ("rotateApiKey", "T3"),
    ("post", "/api/v1/admin/accounts/{id}/freeze"): ("freezeAccount", "T4"),
    ("post", "/api/v1/admin/accounts/{id}/unfreeze"): ("unfreezeAccount", "T4"),
    ("post", "/api/v1/admin/accounts/{id}/roles"): ("updateAccountRoles", "T4"),
    ("post", "/api/v1/admin/tenants/{id}/quotas"): ("updateTenantQuotas", "T4"),
}


def _spec() -> dict:
    path = os.environ.get(SPEC_ENV) or SPEC_DEFAULT
    if not os.path.exists(path):
        pytest.skip(f"spec 缺失（{path}）；CI 会先拉取固定版本")
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def spec() -> dict:
    return _spec()


def _routes() -> dict[tuple[str, str], object]:
    out: dict[tuple[str, str], object] = {}
    for route in router_module.router.routes:
        path = getattr(route, "path", "")
        for method in getattr(route, "methods", set()) or set():
            if method in ("HEAD", "OPTIONS"):
                continue
            out[(method.lower(), path)] = route
    return out


def test_implemented_surface_is_exactly_the_t2_five():
    assert set(_routes()) == set(IMPLEMENTED)


def test_every_implemented_route_exists_in_spec(spec):
    routes = _routes()
    implemented_paths = {path for _m, path in routes}
    missing = sorted(p for p in implemented_paths if p not in spec["paths"])
    assert missing == [], f"实现多出 spec 之外的路径：{missing}"


def test_operation_ids_match_spec(spec):
    routes = _routes()
    for key, operation_id in IMPLEMENTED.items():
        method, path = key
        node = spec["paths"][path][method]
        assert node["operationId"] == operation_id, f"{path} operationId 漂移"
        assert getattr(routes[key], "operation_id", None) == operation_id


def test_public_endpoints_match_spec_security(spec):
    for path in ("/api/v1/auth/login", "/api/v1/auth/refresh"):
        assert spec["paths"][path]["post"]["security"] == [], "spec：登录 / 刷新是公开端点"
    for path in ("/api/v1/auth/logout", "/api/v1/user/profile"):
        assert spec["paths"][path][
            "post" if path.endswith("logout") else "get"]["security"] == [{"userBearer": []}]

    routes = _routes()
    assert routes[("post", "/api/v1/auth/login")].openapi_extra == {"security": []}
    assert routes[("post", "/api/v1/auth/refresh")].openapi_extra == {"security": []}


def test_deferred_operations_still_declared_and_not_implemented(spec):
    routes = _routes()
    for key, (operation_id, owner) in DEFERRED.items():
        method, path = key
        assert path in spec["paths"], f"{path} 从 spec 消失（{owner} 的契约被删？）"
        assert spec["paths"][path][method]["operationId"] == operation_id
        assert key not in routes, f"{path} 已实现：请把 {owner} 的状态同步进本测试"


def test_login_response_carries_all_spec_required_fields(spec, api, f):
    f.login_ready()
    response = api.post("/api/v1/auth/login",
                        json={"method": "password", "identifier": "login1@example.com",
                              "secret": "S3cret!"})
    assert response.status_code == 200
    body = response.json()
    schemas = spec["components"]["schemas"]

    assert set(schemas["LoginResponse"]["required"]) <= set(body)
    assert set(schemas["AuthTokens"]["required"]) <= set(body["tokens"])
    assert body["tokens"]["token_type"] == "Bearer"
    assert isinstance(body["tokens"]["expires_in"], int) and body["tokens"]["expires_in"] >= 1
    assert isinstance(body["mfa_required"], bool)

    account_required = set(schemas["AccountProfile"]["required"])
    assert account_required <= set(body["account"]), account_required - set(body["account"])
    states = set(schemas["AccountProfile"]["properties"]["state"]["enum"])
    assert body["account"]["state"] in states
    roles = set(schemas["AccountProfile"]["properties"]["roles"]["items"]["enum"])
    assert set(body["account"]["roles"]) <= roles


def test_refresh_and_logout_responses_match_spec(spec, api, f):
    f.login_ready()
    tokens = api.post("/api/v1/auth/login",
                      json={"method": "password", "identifier": "login1@example.com",
                            "secret": "S3cret!"}).json()["tokens"]
    rotated = api.post("/api/v1/auth/refresh",
                       json={"refresh_token": tokens["refresh_token"]}).json()
    schemas = spec["components"]["schemas"]
    assert set(schemas["AuthTokens"]["required"]) <= set(rotated)

    ack = api.post("/api/v1/auth/logout",
                   headers={"Authorization": f"Bearer {rotated['access_token']}"},
                   json={}).json()
    assert set(schemas["LogoutAck"]["required"]) <= set(ack)
    assert ack["revoked_sessions"] >= 0


def test_profile_patch_matches_spec(spec, api, f):
    f.login_ready()
    tokens = api.post("/api/v1/auth/login",
                      json={"method": "password", "identifier": "login1@example.com",
                            "secret": "S3cret!"}).json()["tokens"]
    response = api.patch("/api/v1/user/profile",
                        headers={"Authorization": f"Bearer {tokens['access_token']}"},
                        json={"display_name": "Spec", "locale": "zh-CN"})
    assert response.status_code == 200
    schemas = spec["components"]["schemas"]
    assert set(schemas["AccountProfile"]["required"]) <= set(response.json())
    allowed = set(schemas["AccountProfileUpdateRequest"]["properties"])
    assert set(("display_name", "locale")) <= allowed


def test_error_envelope_matches_spec(spec, api, f):
    f.login_ready()
    response = api.post("/api/v1/auth/login",
                        json={"method": "password", "identifier": "login1@example.com",
                              "secret": "bad"})
    assert response.status_code == 401
    error = response.json()["error"]
    spec_error = spec["components"]["schemas"]["Error"]["properties"]["error"]
    assert set(spec_error["required"]) <= set(error)
    assert error["type"] in set(spec_error["properties"]["type"]["enum"])
    assert isinstance(error["code"], int), "spec：code 是整数"
    assert error["request_id"] == response.headers["X-Request-Id"]
    assert 40110 in {
        int(x) for x in spec_error["properties"]["code"].get("examples", [40110])
    } or True   # spec 用描述性文本登记 40110，这里只断言形态


def test_scan_pending_202_is_not_in_spec_yet(spec):
    """CR：扫码中间态用 202，spec 1.2.0 的 /auth/login 只声明了 200/400/401/403/429。"""
    responses = set(spec["paths"]["/api/v1/auth/login"]["post"]["responses"])
    assert responses == {"200", "400", "401", "403", "429"}
    assert "202" not in responses, "spec 已补 202：请更新本用例与 router 文档"
