# SPDX-License-Identifier: AGPL-3.0-or-later
"""凭据与隐私原语（INV-03 / INV-04 / INV-10）：指纹再哈希、密钥形态、疑似凭据扫描。"""
from __future__ import annotations

import pytest

from app.supply import facts, security
from app.supply.errors import CredentialFieldRejected, InvalidArgument


# --------------------------------------------------------------------------- 指纹（INV-03）
def test_fingerprint_is_rehashed_and_stable():
    raw = "fp-machine-0001-abcdef"
    digest = security.hash_fingerprint(raw)
    assert len(digest) == 64
    assert digest == security.hash_fingerprint(f"  {raw}  ")
    assert raw not in digest


def test_normalize_fingerprint_accepts_hex_and_base64ish():
    assert security.normalize_fingerprint("a" * 64) == "a" * 64
    assert security.normalize_fingerprint(" sha256:ABC-123/xyz=+/_ ") == "sha256:ABC-123/xyz=+/_"


@pytest.mark.parametrize("value", [None, "", "   ", "short", "x" * 300, "has space inside"])
def test_normalize_fingerprint_rejects_bad_values(value):
    with pytest.raises(InvalidArgument) as excinfo:
        security.normalize_fingerprint(value)
    assert excinfo.value.code == "40001"
    assert excinfo.value.details["field"] == "hardware_fingerprint"


# --------------------------------------------------------------------------- 密钥（INV-10）
def test_new_client_key_shape():
    plaintext, prefix, digest = security.new_client_key()
    assert len(plaintext) >= 32
    assert prefix == plaintext[:facts.KEY_PREFIX_LEN]
    assert len(prefix) == facts.KEY_PREFIX_LEN
    assert digest == security.hash_secret(plaintext)
    assert len(digest) == 64


def test_client_keys_are_unique():
    keys = {security.new_client_key()[0] for _ in range(20)}
    assert len(keys) == 20


def test_key_matches_is_constant_time_comparison():
    plaintext, _prefix, digest = security.new_client_key()
    assert security.key_matches(plaintext, digest) is True
    assert security.key_matches(plaintext + "x", digest) is False
    assert security.key_matches("", digest) is False
    assert security.key_matches(plaintext, None) is False


def test_binding_code_shape():
    code, digest = security.new_binding_code()
    assert len(code) >= 24
    assert digest == security.hash_secret(code)
    assert len(digest) == 64


# --------------------------------------------------------------------------- 疑似凭据（INV-04）
@pytest.mark.parametrize("field", ["api_key", "apikey", "secret", "token", "password",
                                   "openai_api_key", "secret_key", "credential"])
def test_suspect_fields_catch_credential_names(field):
    body = {field: "s" * facts.SECRET_VALUE_MIN_LEN}
    assert security.suspect_fields(body) == (field,)


def test_suspect_fields_look_into_nested_objects_and_arrays():
    body = {"upstream": {"api_key": "k" * 40},
            "models": [{"token": "t" * 20}]}
    found = security.suspect_fields(body)
    assert "upstream.api_key" in found
    assert "models[0].token" in found


def test_credential_handle_is_allowlisted():
    body = {"credential_handle": "c" * 64}
    assert security.suspect_fields(body) == ()


def test_short_values_are_not_credentials():
    assert security.suspect_fields({"api_key": "short"}) == ()
    assert security.suspect_fields({"token": "x" * 15}) == ()


def test_non_string_values_are_ignored():
    assert security.suspect_fields({"api_key": 12345678901234567890}) == ()
    assert security.suspect_fields({"api_key": {"nested": "v" * 30}}) == ()


def test_non_mapping_bodies_are_safe():
    assert security.suspect_fields(None) == ()
    assert security.suspect_fields([]) == ()                        # type: ignore[arg-type]


def test_scan_credentials_reports_fields_but_never_values():
    raw = "sk-very-secret-value-0123456789"
    with pytest.raises(CredentialFieldRejected) as excinfo:
        security.scan_credentials({"provider": {"api_key": raw}})
    err = excinfo.value
    assert err.code == "40001"
    assert err.status_code == 400
    assert err.details["fields"] == ["provider.api_key"]
    assert raw not in str(err)
    assert raw not in str(err.details)


def test_scan_credentials_passes_clean_bodies():
    security.scan_credentials({"platform": "linux", "credential_handle": "keychain:djb"})
    security.scan_credentials({})
    security.scan_credentials(None)
