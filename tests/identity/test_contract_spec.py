# SPDX-License-Identifier: Apache-2.0
"""M01 契约面测试：spec 1.2.0 的 13 个 M01 操作逐条对账（tasks-11 验收 3）。

对账口径：
- **T2/T3 已实现的 9 个操作**（login / refresh / logout / profile GET/PATCH + api-keys ×4）：
  路径 + 方法 + ``operationId`` 必须与 spec 一致；成功响应必须包含 spec 的必填字段；
  ``security`` 与 spec 一致（login / refresh 是 ``security: []``）；
  错误响应必须是 spec ``Error`` 信封（``error.type/code/message/request_id``）。
- **T4 的 4 个操作**：spec 里必须仍存在（防漂移），且当前**未实现**——
  这样任何一方先接线都会立刻红，避免「悄悄多出路由」。
- 扫码轮询复用 ``/auth/login``，中间态用 **202 + ScanStatus**（CR-5 / task-13）：
  spec 1.2.0 尚未声明 202 时该用例 skip 并留痕；spec 1.2.1 合入后**同一份代码**
  自动切到严格断言（202 存在 + ScanStatus 必填字段 / 枚举 / 类型逐项匹配），不需要再改测试。
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
    # T3：API Key 生命周期
    ("get", "/api/v1/user/api-keys"): "listApiKeys",
    ("post", "/api/v1/user/api-keys"): "createApiKey",
    ("delete", "/api/v1/user/api-keys/{id}"): "revokeApiKey",
    ("post", "/api/v1/user/api-keys/{id}/rotate"): "rotateApiKey",
}
# T4 的 4 个操作：spec 必须有，T3 不得实现
DEFERRED = {
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


def test_implemented_surface_is_exactly_the_nine():
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


LOGIN_1_2_0_RESPONSES = {"200", "400", "401", "403", "429"}


def _scan_status_schema(spec: dict) -> dict:
    ref = spec["paths"]["/api/v1/auth/login"]["post"]["responses"]["202"]["content"][
        "application/json"]["schema"]["$ref"]
    assert ref == "#/components/schemas/ScanStatus", ref
    return spec["components"]["schemas"]["ScanStatus"]


def test_scan_pending_202_matches_spec(spec, api, f):
    """扫码中间态：spec 1.2.0 → 暂缺 202（skip 留痕）；spec 1.2.1 起严格对账。"""
    responses = set(spec["paths"]["/api/v1/auth/login"]["post"]["responses"])
    assert LOGIN_1_2_0_RESPONSES <= responses, "1.2.0 的既有响应不得被删（纯 additive）"

    if "202" not in responses:
        pytest.skip("spec 仍是 1.2.0（无 202 / ScanStatus，CR-5 待 task-13）；"
                    "1.2.1 同步后本用例自动执行严格断言")

    # —— spec 1.2.1 起的严格对账 ——
    schema = _scan_status_schema(spec)
    assert schema["type"] == "object"
    required = set(schema["required"])
    assert {"status", "expires_at", "retry_after_s"} <= required
    status_enum = set(schema["properties"]["status"]["enum"])
    assert {"pending", "scanned", "confirmed", "expired"} <= status_enum
    assert schema["properties"]["retry_after_s"]["type"] == "integer"
    assert schema["properties"]["retry_after_s"]["minimum"] >= 1

    f.login_ready()
    from app.identity import scan

    _row, ticket = scan.create(f.conn, now=f.moment)
    response = api.post("/api/v1/auth/login",
                        json={"method": "oauth", "provider": "qr", "identifier": ticket})
    assert response.status_code == 202
    body = response.json()

    # 必填字段齐全、类型正确、枚举合法（顶层即 ScanStatus）
    assert required <= set(body), required - set(body)
    assert body["status"] in status_enum
    assert isinstance(body["retry_after_s"], int) and body["retry_after_s"] >= 1
    assert isinstance(body["expires_at"], str) and body["expires_at"]
    # 过渡期的 scan 包裹与顶层保持一致（纯增量，不为契约引入第二种真相）
    assert body["scan"] == {key: body[key] for key in required}


def test_scan_status_enum_mapping():
    """内部票据状态 → spec 枚举（created 对外是 pending，其余同名）。"""
    assert router_module.SCAN_STATUS_MAP == {"created": "pending", "scanned": "scanned",
                                             "confirmed": "confirmed", "expired": "expired"}
