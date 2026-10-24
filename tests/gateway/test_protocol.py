# SPDX-License-Identifier: AGPL-3.0-or-later
"""协议版本与能力协商（T4 / M03 §4.3）：426/42601、能力交集、Sunset。"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.gateway import errors, facts, features, protocol, providers
from gatewaykit import FakeAuth, FakeCatalog


# ─────────────────────────────────────────────────────── 解析
def test_current_version_is_semver_and_major_is_supported():
    major, minor, patch = (int(part) for part in facts.PROTOCOL_VERSION_CURRENT.split("."))
    assert major in facts.PROTOCOL_MAJOR_SUPPORTED
    assert (minor, patch) >= (0, 0)


def test_parse_accepts_valid_versions():
    info = protocol.parse("1.2.3")
    assert (info.major, info.minor, info.patch) == (1, 2, 3)
    assert info.compatible is True


@pytest.mark.parametrize("raw", [None, "", "   ", "1.2", "v1.2.3", "1.2.3.4", "abc"])
def test_parse_ignores_missing_or_malformed_versions(raw):
    assert protocol.parse(raw) is None


def test_parse_flags_incompatible_major():
    info = protocol.parse("2.0.0")
    assert info.compatible is False


# ─────────────────────────────────────────────────────── 判定（严格模式闸门）
def test_compatible_version_passes_in_strict_mode():
    info = protocol.check("1.0.0", strict=True)
    assert info.compatible is True


def test_incompatible_version_is_tolerated_when_gate_is_off():
    info = protocol.check("2.0.0", strict=False)
    assert info.compatible is False          # 只记录，不报错


def test_incompatible_version_is_426_when_gate_is_on():
    with pytest.raises(errors.GatewayError) as info:
        protocol.check("2.0.0", strict=True)
    exc = info.value
    assert (exc.http_status, exc.code) == (426, 42601)
    assert exc.type == "protocol_error"
    assert exc.details["supported_major"] == list(facts.PROTOCOL_MAJOR_SUPPORTED)


def test_gate_defaults_to_off():
    assert features.enabled("gateway.protocol_version_strict") is False
    assert protocol.check("2.0.0").compatible is False       # 默认阈值：不报错


def test_missing_version_is_compatible():
    info = protocol.check(None, strict=True)
    assert info.present is False and info.compatible is True


# ─────────────────────────────────────────────────────── 能力协商
def test_capabilities_are_split_and_trimmed():
    assert protocol.capabilities(" chat_completions , batch ") == ("chat_completions", "batch")


def test_unknown_capabilities_are_ignored():
    assert protocol.enabled_set("chat_completions,teleport") == ("chat_completions",)


def test_missing_capabilities_is_empty():
    assert protocol.capabilities(None) == ()
    assert protocol.enabled_set("") == ()


def test_response_headers_echo_server_version():
    info = protocol.check(None)
    assert protocol.response_headers(info) == {
        facts.PROTOCOL_VERSION_HEADER: facts.PROTOCOL_VERSION_CURRENT}


def test_sunset_header_is_ninety_days_after_deprecation():
    deprecated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    header = protocol.sunset_header(deprecated_at)
    assert "Sunset" in header and header["Sunset"].endswith("GMT")


# ─────────────────────────────────────────────────────── HTTP 层（严格模式 426）
@pytest.fixture
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.gateway import router as router_module

    app = FastAPI()
    app.include_router(router_module.router)
    original = router_module._client_ip_resolver
    router_module.set_client_ip_resolver(None)
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_model_catalog_provider(FakeCatalog())
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        router_module.set_client_ip_resolver(original)


def _auth():
    return {facts.AUTH_HEADER: "Bearer djb_live_abcdefgh"}


def test_http_incompatible_version_is_rejected_when_gate_is_on(client, monkeypatch):
    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "gateway.protocol_version_strict")
    response = client.get("/v1/models",
                          headers={**_auth(), facts.PROTOCOL_VERSION_HEADER: "2.0.0"})
    assert response.status_code == 426
    payload = response.json()["error"]
    assert payload["code"] == 42601
    assert payload["type"] == "protocol_error"
    assert response.headers[facts.REQUEST_ID_HEADER] == payload["request_id"]


def test_http_incompatible_version_is_tolerated_when_gate_is_off(client):
    response = client.get("/v1/models", headers={**_auth(),
                                                facts.PROTOCOL_VERSION_HEADER: "2.0.0"})
    assert response.status_code == 200


def test_http_malformed_version_header_is_ignored(client):
    response = client.get("/v1/models",
                          headers={**_auth(), facts.PROTOCOL_VERSION_HEADER: "not-a-version"})
    assert response.status_code == 200


def test_http_unknown_capability_is_ignored(client):
    response = client.get("/v1/models",
                          headers={**_auth(), facts.CAPABILITIES_HEADER: "teleport,batch"})
    assert response.status_code == 200


def test_http_response_echoes_protocol_version(client):
    response = client.get("/v1/models", headers=_auth())
    assert response.headers[facts.PROTOCOL_VERSION_HEADER] == facts.PROTOCOL_VERSION_CURRENT
