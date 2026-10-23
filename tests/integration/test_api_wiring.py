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
