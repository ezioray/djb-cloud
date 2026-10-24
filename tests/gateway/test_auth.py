# SPDX-License-Identifier: AGPL-3.0-or-later
"""鉴权编排（M03 §6.1 第 2 步 / §4.4 / INV-M03-05）。不需要 DB。"""
from __future__ import annotations

import uuid

import pytest

from app.gateway import auth, errors, models, providers
from gatewaykit import FakeAuth, NOW, principal_dict


# ─────────────────────────────────────────────────────── Bearer 解析
def test_extract_bearer_accepts_bearer_scheme_case_insensitively():
    assert auth.extract_bearer("Bearer djb_live_abcdefgh") == "djb_live_abcdefgh"
    assert auth.extract_bearer("bearer djb_live_abcdefgh") == "djb_live_abcdefgh"


@pytest.mark.parametrize("header", [None, "", "   ", "Basic abcdefgh", "Bearer", "Bearer   "])
def test_missing_or_malformed_authorization_is_40101(header):
    with pytest.raises(errors.GatewayError) as info:
        auth.extract_bearer(header)
    assert (info.value.http_status, info.value.code) == (401, 40101)


@pytest.mark.parametrize("token", ["short", "x" * 513])
def test_abnormal_key_length_is_rejected_without_hints(token):
    with pytest.raises(errors.GatewayError) as info:
        auth.extract_bearer(f"Bearer {token}")
    assert info.value.code == 40101
    assert token not in info.value.message            # 不回显 Key


# ─────────────────────────────────────────────────────── IP 白名单
def test_empty_allowlist_does_not_restrict():
    principal = models.coerce_principal(principal_dict())
    auth.assert_ip_allowed(principal, "203.0.113.9")


def test_exact_ip_and_cidr_allowlist():
    principal = models.coerce_principal(principal_dict(ip_allowlist=["203.0.113.9",
                                                                   "10.0.0.0/8"]))
    auth.assert_ip_allowed(principal, "203.0.113.9")
    auth.assert_ip_allowed(principal, "10.1.2.3")


def test_ip_outside_allowlist_is_403_with_policy_blocked():
    principal = models.coerce_principal(principal_dict(ip_allowlist=["10.0.0.0/8"]))
    with pytest.raises(errors.GatewayError) as info:
        auth.assert_ip_allowed(principal, "203.0.113.9")
    assert (info.value.http_status, info.value.code) == (403, 40102)
    assert info.value.reason == "policy_blocked"


def test_unknown_client_ip_with_allowlist_is_denied():
    principal = models.coerce_principal(principal_dict(ip_allowlist=["10.0.0.0/8"]))
    with pytest.raises(errors.GatewayError):
        auth.assert_ip_allowed(principal, None)


def test_ip_allowed_helper_handles_garbage():
    assert models.ip_allowed("not-an-ip", ["10.0.0.0/8"]) is False
    assert models.ip_allowed("10.1.1.1", ["garbage", "10.0.0.0/8"]) is True


# ─────────────────────────────────────────────────────── 账户状态
def test_normal_account_is_writable():
    auth.assert_writable(models.coerce_principal(principal_dict(state="normal")))


@pytest.mark.parametrize("state", ["frozen", "closing"])
def test_read_only_states_map_to_40304(state):
    principal = models.coerce_principal(principal_dict(state=state))
    with pytest.raises(errors.GatewayError) as info:
        auth.assert_writable(principal)
    assert (info.value.http_status, info.value.code) == (403, 40304)
    assert info.value.reason == "account_restricted"


def test_pending_account_maps_to_40001():
    principal = models.coerce_principal(principal_dict(state="pending_verify"))
    with pytest.raises(errors.GatewayError) as info:
        auth.assert_writable(principal)
    assert (info.value.http_status, info.value.code) == (400, 40001)


# ─────────────────────────────────────────────────────── 注入 provider
def test_provider_not_wired_is_fail_closed_503():
    providers.reset_providers()
    with pytest.raises(errors.GatewayError) as info:
        auth.authenticate_request("Bearer djb_live_abcdefgh", now=NOW, client_ip=None,
                                  trace_id="t1")
    assert (info.value.http_status, info.value.code) == (503, 45001)
    assert info.value.retry_after_s


def test_translate_identity_error_keeps_the_registered_code():
    auth_provider = FakeAuth()
    providers.set_auth_provider(auth_provider)
    with pytest.raises(errors.GatewayError) as info:
        auth.authenticate_request("Bearer revoked_key_abcdefgh", now=NOW, client_ip=None,
                                  trace_id="t1")
    assert (info.value.http_status, info.value.code) == (401, 40101)


def test_provider_returning_none_is_fail_closed():
    providers.set_auth_provider(lambda *a, **k: None)
    with pytest.raises(errors.GatewayError) as info:
        auth.authenticate_request("Bearer djb_live_abcdefgh", now=NOW, client_ip=None,
                                  trace_id="t1")
    assert info.value.http_status == 503


def test_provider_result_is_coerced_into_principal():
    account_id, tenant_id = uuid.uuid4(), uuid.uuid4()
    providers.set_auth_provider(FakeAuth(account_id=account_id, tenant_id=tenant_id,
                                         api_key_id=42, qps=5))
    principal = auth.authenticate_request("Bearer djb_live_abcdefgh", now=NOW,
                                          client_ip="10.1.1.1", trace_id="t9")
    assert isinstance(principal, models.Principal)
    assert principal.account_id == str(account_id)
    assert principal.api_key_id == 42
    assert principal.quotas["effective"]["qps"] == 5


def test_coerce_principal_rejects_incomplete_subject():
    with pytest.raises(ValueError):
        models.coerce_principal({"api_key_id": 1})
