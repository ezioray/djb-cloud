# SPDX-License-Identifier: AGPL-3.0-or-later
"""HMAC-SHA256 签名：可验签 / 篡改必拒 / 缺密钥 fail-closed / 不回显密钥。"""
from __future__ import annotations

import hashlib
import hmac
import logging

import pytest

from app.model_sync import facts, signing
from app.model_sync.errors import FeatureUnavailable

from kit import TEST_SIGNING_KEY

HASH = "a" * 64


def _use_key(monkeypatch, key: str | None = TEST_SIGNING_KEY):
    if key is None:
        monkeypatch.delenv(facts.SIGNING_KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(facts.SIGNING_KEY_ENV, key)


def test_sign_and_verify_roundtrip(monkeypatch):
    _use_key(monkeypatch)
    signature = signing.sign(HASH)
    assert signature.startswith("hmac-sha256:")
    assert len(signature) == len("hmac-sha256:") + 64
    assert signing.verify(HASH, signature) is True
    assert signing.key_configured() is True
    # M18b 口径：HMAC-SHA256(key, payload_hash 的 ASCII 字节) → hex
    expected = hmac.new(TEST_SIGNING_KEY.encode("ascii"), HASH.encode("ascii"),
                        hashlib.sha256).hexdigest()
    assert signature == "hmac-sha256:" + expected


def test_verify_rejects_tampering_and_wrong_key(monkeypatch):
    _use_key(monkeypatch)
    signature = signing.sign(HASH)
    assert signing.verify("b" * 64, signature) is False           # 篡改 payload_hash
    assert signing.verify(HASH, signature[:-1] + "0") is False    # 篡改签名
    assert signing.verify(HASH, "md5:whatever") is False          # 算法前缀不对
    assert signing.verify(HASH, "") is False
    assert signing.verify(HASH, signing.signature_of(HASH, key=b"another-key")) is False


def test_missing_key_fails_closed(monkeypatch):
    _use_key(monkeypatch, None)
    assert signing.key_configured() is False
    with pytest.raises(FeatureUnavailable) as excinfo:
        signing.sign(HASH)
    assert (excinfo.value.status_code, excinfo.value.code) == (503, 50001)
    assert excinfo.value.reason == "signing_key_missing"
    assert signing.verify(HASH, "hmac-sha256:" + "0" * 64) is False


def test_short_key_is_treated_as_missing(monkeypatch):
    _use_key(monkeypatch, "too-short")
    assert signing.key_configured() is False
    with pytest.raises(FeatureUnavailable):
        signing.sign(HASH)


def test_key_material_never_appears_in_errors_or_logs(monkeypatch, caplog):
    _use_key(monkeypatch)
    with caplog.at_level(logging.DEBUG):
        signature = signing.sign(HASH)
    assert TEST_SIGNING_KEY not in signature
    _use_key(monkeypatch, None)
    with pytest.raises(FeatureUnavailable) as excinfo:
        signing.sign(HASH)
    assert TEST_SIGNING_KEY not in str(excinfo.value)
    assert TEST_SIGNING_KEY not in caplog.text
