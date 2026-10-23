# SPDX-License-Identifier: Apache-2.0
"""双签规范串与 HMAC-SHA256 验签（M05 §8.2 / CR-2 / INV-01）。不需要 DB。"""
from __future__ import annotations

import hashlib
import hmac

import pytest

from app.metering import errors, facts, signing
from meterkit import TEST_CONSUMER_KEY, TEST_PROVIDER_KEY

FIELDS = {
    "receipt_id": "rcpt_001",
    "task_id": "task_001",
    "access": "A1",
    "usage_amount": "1500",
    "usage_unit": "token",
    "price_amount": "1.25",
}
KEYS = signing.SignatureKeys(TEST_PROVIDER_KEY, TEST_CONSUMER_KEY)


# ─────────────────────────────────────────────────────── 规范串（6 字段 / 固定顺序 / 原样字符串）
def test_canonical_string_uses_fixed_field_order():
    text = signing.canonical_string(FIELDS)
    assert text == "\n".join(FIELDS[name] for name in facts.CANONICAL_FIELDS)
    assert facts.CANONICAL_FIELDS == ("receipt_id", "task_id", "access", "usage_amount",
                                      "usage_unit", "price_amount")


def test_canonical_string_keeps_original_strings():
    """``"1000"`` 与 ``"1000.0"`` 是**不同**的规范串（不复用 NUMERIC 回读值）。"""
    a = signing.canonical_string({**FIELDS, "usage_amount": "1000"})
    b = signing.canonical_string({**FIELDS, "usage_amount": "1000.0"})
    assert a != b
    assert signing.digest(KEYS.provider, a) != signing.digest(KEYS.provider, b)


def test_canonical_string_rejects_missing_field():
    broken = dict(FIELDS)
    broken.pop("task_id")
    with pytest.raises(errors.InvalidArgument) as exc:
        signing.canonical_string(broken)
    assert exc.value.details["field"] == "task_id"


def test_canonical_string_rejects_newline_injection():
    with pytest.raises(errors.InvalidArgument):
        signing.canonical_string({**FIELDS, "receipt_id": "a\nb"})


def test_canonical_string_rejects_non_string_field():
    with pytest.raises(errors.InvalidArgument):
        signing.canonical_string({**FIELDS, "usage_unit": b"token"})


def test_canonical_string_accepts_int_as_original_text():
    assert signing.canonical_string({**FIELDS, "usage_amount": 1500}) == \
        signing.canonical_string(FIELDS)


# ─────────────────────────────────────────────────────── 摘要
def test_digest_is_prefixed_hmac_sha256_lowercase_hex():
    digest = signing.digest(KEYS.provider, "payload")
    assert digest.startswith("hmac-sha256:")
    body = digest.split(":", 1)[1]
    assert len(body) == facts.SIG_HEX_LEN
    assert body == body.lower()


def test_digest_matches_independent_hmac_implementation():
    """与标准库独立算一遍对比（验证算法钉死为 HMAC-SHA256，不是自创摘要）。"""
    payload = signing.canonical_string(FIELDS)
    expected = hmac.new(TEST_PROVIDER_KEY, payload.encode(), hashlib.sha256).hexdigest()
    assert signing.digest(KEYS.provider, payload) == f"hmac-sha256:{expected}"


def test_two_sides_produce_different_digests():
    payload = signing.canonical_string(FIELDS)
    assert signing.digest(KEYS.provider, payload) != signing.digest(KEYS.consumer, payload)


# ─────────────────────────────────────────────────────── 验签
def _signed(**overrides):
    return {**FIELDS, **signing.sign(FIELDS, KEYS), **overrides}


def test_verify_pair_accepts_both_signatures():
    body = _signed()
    check = signing.verify_pair(FIELDS, sig_provider=body["sig_provider"],
                                sig_consumer=body["sig_consumer"], keys=KEYS)
    assert check.ok and check.reason is None and check.side is None


def test_verify_pair_rejects_missing_provider_signature():
    check = signing.verify_pair(FIELDS, sig_provider="", sig_consumer=_signed()["sig_consumer"],
                                keys=KEYS)
    assert not check.ok and check.reason == "missing_provider_signature"
    assert check.side == "provider"
    assert check.as_detail()["signature_side"] == "provider"


def test_verify_pair_rejects_missing_consumer_signature():
    """验收场景①的前半：缺 ``sig_consumer`` → 46001（整批其余仍可 accepted）。"""
    check = signing.verify_pair(FIELDS, sig_provider=_signed()["sig_provider"],
                                sig_consumer=None, keys=KEYS)
    assert not check.ok and check.reason == "missing_consumer_signature"


@pytest.mark.parametrize("bad", ["bad", "hmac-sha256:xyz", "sha256:" + "0" * 64,
                                 "hmac-sha256:" + "0" * 63, "hmac-sha256:" + "A" * 64])
def test_verify_pair_rejects_malformed_signatures(bad):
    check = signing.verify_pair(FIELDS, sig_provider=bad, sig_consumer=_signed()["sig_consumer"],
                                keys=KEYS)
    assert not check.ok and check.reason == "malformed_provider_signature"


def test_verify_pair_detects_cross_signed_sides():
    """把需方签名塞进供方位（单方伪造两侧）必须被发现。"""
    body = _signed()
    check = signing.verify_pair(FIELDS, sig_provider=body["sig_consumer"],
                                sig_consumer=body["sig_consumer"], keys=KEYS)
    assert not check.ok and check.reason == "provider_signature_mismatch"


def test_verify_pair_detects_tampered_amount():
    """伪造金额（改了 price_amount 但沿用旧签名）必须被发现。"""
    body = _signed()
    tampered = {**FIELDS, "price_amount": "0.01"}
    check = signing.verify_pair(tampered, sig_provider=body["sig_provider"],
                                sig_consumer=body["sig_consumer"], keys=KEYS)
    assert not check.ok and check.reason == "provider_signature_mismatch"


def test_verify_pair_detects_wrong_consumer_key():
    other = signing.SignatureKeys(TEST_PROVIDER_KEY, b"another-consumer-key-0123456789abcdef")
    body = {**FIELDS, **signing.sign(FIELDS, other)}
    check = signing.verify_pair(FIELDS, sig_provider=body["sig_provider"],
                                sig_consumer=body["sig_consumer"], keys=KEYS)
    assert not check.ok and check.reason == "consumer_signature_mismatch"
    assert check.side == "consumer"


# ─────────────────────────────────────────────────────── 密钥注入（fail-closed）
def test_resolve_keys_uses_injected_provider():
    keys = signing.resolve_keys(lambda: {"provider": "p" * 32, "consumer": "c" * 32})
    assert keys.provider == b"p" * 32 and keys.consumer == b"c" * 32


def test_resolve_keys_without_provider_or_env_is_fail_closed(monkeypatch):
    monkeypatch.delenv(signing.ENV_PROVIDER_KEY, raising=False)
    monkeypatch.delenv(signing.ENV_CONSUMER_KEY, raising=False)
    monkeypatch.setattr(signing, "_keys_provider", None, raising=False)
    with pytest.raises(errors.KeysUnavailable) as exc:
        signing.resolve_keys()
    assert exc.value.code == "50001"
    assert "密钥" in exc.value.message


def test_resolve_keys_reads_env_secret_references(monkeypatch):
    monkeypatch.setenv(signing.ENV_PROVIDER_KEY, "p" * 32)
    monkeypatch.setenv(signing.ENV_CONSUMER_KEY, "c" * 32)
    monkeypatch.setattr(signing, "_keys_provider", None, raising=False)
    keys = signing.resolve_keys()
    assert (keys.provider, keys.consumer) == (b"p" * 32, b"c" * 32)


def test_resolve_keys_rejects_identical_keys():
    """INV-01：两侧密钥必须不同，否则单方即可伪造双签。"""
    with pytest.raises(errors.KeysUnavailable):
        signing.resolve_keys(lambda: {"provider": "same" * 8, "consumer": "same" * 8})


def test_resolve_keys_rejects_short_keys():
    with pytest.raises(errors.KeysUnavailable):
        signing.resolve_keys(lambda: {"provider": "short", "consumer": "also-short"})


def test_resolve_keys_rejects_empty_values():
    with pytest.raises(errors.KeysUnavailable):
        signing.resolve_keys(lambda: {"provider": "", "consumer": ""})


# ─────────────────────────────────────────────────────── signature_ref（事件用短指纹）
def test_signature_ref_is_short_fingerprint_not_full_signature():
    body = _signed()
    ref = signing.signature_ref(body["sig_provider"], body["sig_consumer"])
    assert ref.startswith("hmac-sha256:")
    assert len(ref.split(":", 1)[1]) == facts.SIGNATURE_REF_LEN
    assert body["sig_provider"] not in ref and body["sig_consumer"] not in ref
