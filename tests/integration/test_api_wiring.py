# SPDX-License-Identifier: Apache-2.0
"""app/api.py 接线回归：W1 模块路由必须真的挂在生产 app 上（不是只存在于各自测试里）。

背景（2026-10-23 Lead 合并窗口）：
- M02 / M04 / M05 / M10 的 router 之前只在各自测试里被挂载，`app/api.py` 未 include；
- 本测试钉住接线结果，并钉住「未认证时返回 spec Error 信封（数字码）」，
  防止回归成 404 或 `code=0`。

不依赖数据库：所有断言都在鉴权 / 参数校验阶段返回。
"""
from __future__ import annotations

import os

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

os.environ.setdefault("DJB_PRICING_FILE", os.path.join(os.path.dirname(__file__), "..", "..", "config", "pricing.dev.json"))

from fastapi.testclient import TestClient  # noqa: E402

from app.api import app  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)

# 代表端点（每个模块至少一条），来源：各模块 router + spec 1.2.1
WIRED = {
    "supply": ("POST", "/api/v1/node/pair"),
    "scheduling": ("POST", "/api/v1/schedule/route"),
    "metering": ("GET", "/api/v1/user/usage/summary"),
    "config_center": ("GET", "/api/v1/admin/config/items"),
}


@pytest.mark.parametrize("module,spec", sorted(WIRED.items()))
def test_module_route_is_wired(module: str, spec: tuple[str, str]) -> None:
    """模块端点必须存在（未接鉴权时返回 4xx，而不是 404 Not Found）。"""
    method, path = spec
    response = client.request(method, path, json={})
    assert response.status_code != 404, f"{module} 未接线：{method} {path}"
    assert response.status_code != 405, f"{module} 方法不对：{method} {path}"


@pytest.mark.parametrize("module,spec", sorted(WIRED.items()))
def test_unauthenticated_returns_spec_error_envelope(module: str, spec: tuple[str, str]) -> None:
    """未认证必须是 spec Error 信封，且 code 是**已登记数字码**（不是 0 / 缺失）。"""
    method, path = spec
    response = client.request(method, path, json={})
    body = response.json()
    assert "error" in body, f"{module} 错误信封不符合 spec：{body!r}"
    err = body["error"]
    for field in ("type", "code", "message", "request_id"):
        assert field in err, f"{module} 缺 error.{field}"
    assert isinstance(err["code"], int) and err["code"] > 0, f"{module} code 未登记：{err['code']}"


def test_legacy_duplicate_summary_removed() -> None:
    """M05 的 usage summary 是唯一实现；api.py 里的旧 stub 不得回归（响应形状不符 spec）。"""
    # 判据：未认证时返回 Error 信封；旧 stub 会在无 DB 时 500 或返回 consumer/amount_micro
    response = client.get("/api/v1/user/usage/summary")
    body = response.json()
    assert "error" in body, body
    assert "consumer" not in body and "amount_micro" not in body


# ── M16 审计链接线（spec 1.2.2）─────────────────────────────────────────────

def test_healthz_matches_health_status_schema():
    """GET /healthz 必须是 HealthStatus（status/version/checked_at），不是 legacy {"ok": true}。"""
    response = client.get("/healthz")
    body = response.json()
    assert response.status_code in (200, 500, 503), body
    if response.status_code == 200:
        for field in ("status", "version", "checked_at"):
            assert field in body, body
        assert body["status"] in ("ok", "degraded")
        assert "ok" not in body or body.get("ok") is not True  # legacy 字段不应回归


def test_internal_audit_requires_service_token():
    """内部审计端点默认 fail-closed：无令牌 → 401 + 40101，绝不 404。"""
    for method, path in (("POST", "/internal/ops/audit/entries"), ("POST", "/internal/ops/audit/verify")):
        response = client.request(method, path, json={})
        assert response.status_code == 401, (path, response.status_code, response.text[:200])
        err = response.json()["error"]
        assert err["code"] == 40101
        assert err["type"] == "authentication_error"


def test_internal_audit_rejects_wrong_token(monkeypatch):
    """令牌不匹配 → 401（不得因为配置了环境变量就放行）。"""
    monkeypatch.setenv("DJB_INTERNAL_SERVICE_TOKEN", "expected-token-not-real")
    response = client.post("/internal/ops/audit/entries", json={},
                           headers={"X-DJB-Service-Token": "wrong-token-not-real"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == 40101


# ── M09 对账接线（spec 1.2.3）──────────────────────────────────────────────

def test_recon_admin_endpoints_require_admin_actor():
    """管理面未带主体 → 401 + 40101（不是 404，也不是放行）。"""
    for path in ("/api/v1/admin/treasury/recon/runs", "/api/v1/admin/reports/exceptions?period=2026-10"):
        response = client.get(path)
        assert response.status_code == 401, (path, response.status_code, response.text[:160])
        assert response.json()["error"]["code"] == 40101


def test_recon_validate_requires_service_token():
    """出款前校验走服务令牌：缺失 → 401 + 40101。"""
    response = client.get("/api/v1/admin/treasury/recon/attestations/none/validate")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == 40101


def test_recon_routes_are_wired():
    """八条 recon + 两条报表都必须在生产 app 上（未带主体时也不得 404）。"""
    paths = [
        ("GET", "/api/v1/admin/treasury/recon/runs"),
        ("GET", "/api/v1/admin/treasury/recon/runs/x"),
        ("POST", "/api/v1/admin/treasury/recon/runs/x/sign-off"),
        ("GET", "/api/v1/admin/treasury/recon/exceptions"),
        ("POST", "/api/v1/admin/treasury/recon/exceptions/x/resolve"),
        ("POST", "/api/v1/admin/treasury/recon/attestations"),
        ("GET", "/api/v1/admin/treasury/recon/attestations/x"),
        ("GET", "/api/v1/admin/reports/recon-daily?period=2026-10"),
    ]
    for method, path in paths:
        response = client.request(method, path, json={})
        assert response.status_code != 404, (method, path, response.status_code)


# ── M12 通知接线（spec 1.2.3）──────────────────────────────────────────────

def test_notify_user_endpoints_require_bearer():
    """站内信/Webhook 未带 Bearer → 401 + 40101（不是 404，也不放行）。"""
    for path in ("/api/v1/user/notifications",
                 "/api/v1/user/notifications/preferences",
                 "/api/v1/user/webhooks"):
        response = client.get(path)
        assert response.status_code == 401, (path, response.status_code, response.text[:160])
        assert response.json()["error"]["code"] == 40101


def test_notify_rejects_unknown_bearer():
    """无效 Bearer → 401/40101（走 api_keys 查询但不得放行）。"""
    response = client.get("/api/v1/user/notifications",
                          headers={"Authorization": "Bearer not-a-real-key"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == 40101


def test_notify_routes_are_wired():
    paths = [
        ("GET", "/api/v1/user/notifications"),
        ("POST", "/api/v1/user/notifications/all/read"),
        ("GET", "/api/v1/user/notifications/preferences"),
        ("PUT", "/api/v1/user/notifications/preferences"),
        ("GET", "/api/v1/user/webhooks"),
        ("POST", "/api/v1/user/webhooks"),
        ("DELETE", "/api/v1/user/webhooks/x"),
    ]
    for method, path in paths:
        response = client.request(method, path, json={})
        assert response.status_code != 404, (method, path, response.status_code)


# ── M07 信誉与 COP 接线（spec 1.2.4）────────────────────────────────────────

def test_reputation_user_endpoints_require_bearer():
    for path in ("/api/v1/user/reputation", "/api/v1/user/cop",
                 "/api/v1/user/cop/ledger", "/api/v1/user/cop/invites"):
        response = client.get(path)
        assert response.status_code == 401, (path, response.status_code, response.text[:160])
        assert response.json()["error"]["code"] == 40101


def test_reputation_grant_requires_step_up():
    """管理主体齐备但缺 step-up → 424 + 42401。"""
    response = client.post("/api/v1/admin/reputation/grants", json={},
                           headers={"X-Admin-Actor": "u1", "X-Admin-Roles": "ADMIN"})
    assert response.status_code == 424, response.text[:200]
    assert response.json()["error"]["code"] == 42401


def test_reputation_routes_are_wired():
    paths = [
        ("GET", "/api/v1/user/reputation"),
        ("GET", "/api/v1/user/reputation/events"),
        ("GET", "/api/v1/user/cop"),
        ("GET", "/api/v1/user/cop/ledger"),
        ("POST", "/api/v1/user/cop/redemptions"),
        ("GET", "/api/v1/user/cop/redemptions/x"),
        ("POST", "/api/v1/user/cop/transfers"),
        ("GET", "/api/v1/user/cop/invites"),
        ("GET", "/api/v1/admin/reputation/scores"),
        ("POST", "/api/v1/admin/reputation/grants"),
    ]
    for method, path in paths:
        response = client.request(method, path, json={})
        assert response.status_code != 404, (method, path, response.status_code)


# ── M11 风控接线（spec 1.2.4）──────────────────────────────────────────────

def test_risk_endpoints_require_admin():
    for path in ("/api/v1/admin/risk/rules", "/api/v1/admin/risk/cases",
                 "/api/v1/admin/risk/limits?subject_type=account&subject_id=x"):
        response = client.get(path)
        assert response.status_code == 401, (path, response.status_code, response.text[:160])
        assert response.json()["error"]["code"] == 40101


def test_risk_routes_are_wired():
    paths = [
        ("GET", "/api/v1/admin/risk/rules"),
        ("POST", "/api/v1/admin/risk/rules"),
        ("GET", "/api/v1/admin/risk/limits"),
        ("POST", "/api/v1/admin/risk/limits"),
        ("GET", "/api/v1/admin/risk/cases"),
        ("GET", "/api/v1/admin/risk/cases/x"),
        ("POST", "/api/v1/admin/risk/cases/x/decisions"),
        ("POST", "/api/v1/admin/risk/appeals"),
        ("POST", "/api/v1/admin/risk/appeals/x/decide"),
    ]
    for method, path in paths:
        response = client.request(method, path, json={})
        assert response.status_code != 404, (method, path, response.status_code)
