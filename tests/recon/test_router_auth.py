# SPDX-License-Identifier: AGPL-3.0-or-later
"""鉴权 fail-closed / 请求标识回显 / 未注册路径 / 错误信封形状。"""
from __future__ import annotations

import uuid

import pytest

PATHS = [
    ("get", "/api/v1/admin/treasury/recon/runs"),
    ("get", "/api/v1/admin/treasury/recon/runs/00000000-0000-7000-8000-000000000000"),
    ("get", "/api/v1/admin/treasury/recon/exceptions"),
    ("get", "/api/v1/admin/treasury/recon/attestations/00000000-0000-7000-8000-000000000001"),
    ("get", "/api/v1/admin/treasury/recon/attestations/"
            "00000000-0000-7000-8000-000000000001/validate"),
    ("get", "/api/v1/admin/reports/recon-daily?period=2026-10"),
    ("get", "/api/v1/admin/reports/exceptions?period=2026-10"),
    ("post", "/api/v1/admin/treasury/recon/runs/00000000-0000-7000-8000-000000000000/sign-off"),
]


@pytest.mark.parametrize("method,path", PATHS)
def test_every_endpoint_is_fail_closed_without_auth(unauth_client, method: str, path: str) -> None:
    kwargs = {"headers": {"X-Admin-Step-Up": "ok"}}
    if method == "post":
        kwargs["json"] = {}
    response = getattr(unauth_client, method)(path, **kwargs)
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == 40101
    assert error["type"] == "authentication_error"
    assert error["request_id"] == response.headers["X-Request-Id"]


def test_request_id_is_echoed_or_generated(client) -> None:
    supplied = str(uuid.uuid4())
    response = client.get("/api/v1/admin/treasury/recon/runs",
                          headers={"X-Request-Id": supplied})
    assert response.headers["X-Request-Id"] == supplied

    generated = client.get("/api/v1/admin/treasury/recon/runs")
    assert uuid.UUID(generated.headers["X-Request-Id"]).version == 4


def test_unknown_path_is_404(client) -> None:
    assert client.get("/api/v1/admin/treasury/recon/unknown").status_code == 404


def test_error_envelope_shape(client) -> None:
    response = client.get("/api/v1/admin/treasury/recon/runs/00000000-0000-7000-8000-00000000dead")
    error = response.json()["error"]
    assert set(error) >= {"type", "code", "message", "request_id"}
    assert isinstance(error["code"], int)
    assert error["type"] in {
        "invalid_request_error", "authentication_error", "permission_error", "rate_limit_error",
        "not_found_error", "conflict_error", "protocol_error", "server_error", "upstream_error"}


def test_scope_guard_on_read_endpoints(savepoint_conn) -> None:
    from reconkit import build_client

    no_scope = {"admin_id": "admin-x", "tenant_id": None, "scopes": ["other.read"]}
    with build_client(savepoint_conn, admin=no_scope) as client:
        response = client.get("/api/v1/admin/treasury/recon/runs")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 47010

    wildcard = {"admin_id": "admin-y", "tenant_id": None, "scopes": ["*"]}
    with build_client(savepoint_conn, admin=wildcard) as client:
        assert client.get("/api/v1/admin/treasury/recon/runs").status_code == 200

    comma = {"admin_id": "admin-z", "tenant_id": None, "scopes": "recon.read,recon.write"}
    with build_client(savepoint_conn, admin=comma) as client:
        assert client.get("/api/v1/admin/treasury/recon/runs").status_code == 200
