# SPDX-License-Identifier: Apache-2.0
"""Webhook 签名（INV-05）：签名串、头部、±300 s 窗口、伪造拒绝。"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import pytest

from app.notify import facts, signing

SECRET = "m12-signing-fixture-secret"
NOW = datetime(2026, 10, 23, 4, 0, tzinfo=timezone.utc)


def _expected(secret: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body,
                      hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_signature_string_matches_spec():
    body = b'{"notification_id":"abc"}'
    stamp = int(NOW.timestamp())
    assert signing.build_signature(SECRET, stamp, body) == _expected(SECRET, stamp, body)
    # 规格：sha256=HMAC_SHA256(secret, timestamp + "." + body)
    assert signing.build_signature(SECRET, stamp, body).startswith("sha256=")


def test_str_and_bytes_body_are_equivalent():
    text = '{"a":1}'
    assert signing.build_signature(SECRET, 1, text) == signing.build_signature(
        SECRET, 1, text.encode("utf-8"))
    assert signing.body_bytes(bytearray(b"x")) == b"x"
    with pytest.raises(TypeError):
        signing.body_bytes(123)


def test_sign_headers_include_all_three_headers():
    body = b'{"x":1}'
    headers = signing.sign_headers(SECRET, "notification.delivered", body, now=NOW)
    assert headers[signing.SIGNATURE_HEADER] == signing.build_signature(
        SECRET, int(NOW.timestamp()), body)
    assert headers[signing.TIMESTAMP_HEADER] == str(int(NOW.timestamp()))
    assert headers[signing.EVENT_HEADER] == "notification.delivered"
    # 显式 timestamp 覆盖 now
    explicit = signing.sign_headers(SECRET, "e", body, timestamp=123, now=NOW)
    assert explicit[signing.TIMESTAMP_HEADER] == "123"


def test_headers_of_is_case_insensitive():
    headers = policy = {"x-djb-signature": "sha256=a", "X-DJB-TIMESTAMP": "1",
                        "x-djb-event": "e"}
    assert signing.headers_of(policy) == ("sha256=a", "1", "e")
    assert signing.headers_of({}) == (None, None, None)


def test_verify_accepts_valid_signature():
    body = b'{"x":1}'
    stamp = int(NOW.timestamp())
    signature = signing.build_signature(SECRET, stamp, body)
    result = signing.verify_signature(SECRET, stamp, body, signature, now=NOW)
    assert result.ok is True and result.reason == "ok"
    assert bool(result) is True


def test_verify_rejects_wrong_secret():
    body = b'{"x":1}'
    stamp = int(NOW.timestamp())
    signature = signing.build_signature("other-secret", stamp, body)
    result = signing.verify_signature(SECRET, stamp, body, signature, now=NOW)
    assert result.ok is False and result.reason == "signature_mismatch"


def test_verify_rejects_tampered_body():
    stamp = int(NOW.timestamp())
    signature = signing.build_signature(SECRET, stamp, b'{"x":1}')
    assert signing.verify_signature(SECRET, stamp, b'{"x":2}', signature,
                                    now=NOW).reason == "signature_mismatch"


def test_verify_timestamp_window_is_300s():
    body = b"{}"
    stamp = int(NOW.timestamp())
    signature = signing.build_signature(SECRET, stamp, body)
    assert signing.verify_signature(SECRET, stamp, body, signature, now=NOW).ok
    # 边界：正好 300 s 允许，301 s 拒绝（两侧都测）
    at_edge = NOW + timedelta(seconds=facts.SIGNATURE_WINDOW_S)
    assert signing.verify_signature(SECRET, stamp, body, signature, now=at_edge).ok
    beyond = NOW + timedelta(seconds=facts.SIGNATURE_WINDOW_S + 1)
    assert signing.verify_signature(SECRET, stamp, body, signature,
                                    now=beyond).reason == "timestamp_out_of_window"
    before = NOW - timedelta(seconds=facts.SIGNATURE_WINDOW_S + 1)
    assert signing.verify_signature(SECRET, stamp, body, signature,
                                    now=before).reason == "timestamp_out_of_window"


@pytest.mark.parametrize("signature,reason", [
    ("", "malformed_signature"),
    ("deadbeef", "malformed_signature"),
    ("md5=abcdef", "unsupported_alg"),
])
def test_verify_rejects_malformed_signatures(signature, reason):
    assert signing.verify_signature(SECRET, int(NOW.timestamp()), b"{}", signature,
                                    now=NOW).reason == reason


def test_verify_rejects_bad_timestamp():
    assert signing.verify_signature(SECRET, "abc", b"{}", "sha256=aa",
                                    now=NOW).reason == "timestamp_invalid"


def test_verify_with_naive_now_uses_utc():
    """naive 时间按 UTC 解释（不跟随机器的本地时区）。"""
    body = b"{}"
    stamp = int(NOW.timestamp())
    signature = signing.build_signature(SECRET, stamp, body)
    naive_now = NOW.replace(tzinfo=None)                 # naive = UTC，不是本机时区
    assert signing.verify_signature(SECRET, stamp, body, signature, now=naive_now).ok


def test_secret_generation_and_hash():
    first = signing.new_secret()
    second = signing.new_secret()
    assert first != second
    assert len(first) >= 40
    assert signing.hash_secret(first) == hashlib.sha256(first.encode()).hexdigest()
    assert len(signing.hash_secret(first)) == 64
    with pytest.raises(ValueError):
        signing.hash_secret("")
    with pytest.raises(ValueError):
        signing.build_signature("", 1, b"{}")
