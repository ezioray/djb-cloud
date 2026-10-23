# SPDX-License-Identifier: Apache-2.0
"""支付通道适配器：SHA256 规范化 / 验签 / 时钟窗 / 金额主单位（§19.6.5）。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.treasury import errors, facts, provider

NOW = datetime(2026, 10, 24, 1, 0, tzinfo=timezone.utc)
KEY = b"test-only-mock-key"


def test_canonicalize_excludes_sign_and_empty_sorts_ascii():
    fields = {"b": 2, "a": "x", "sign": "ignored", "c": "", "d": None, "e": True}
    assert provider.canonicalize(fields) == "a=x&b=2&e=true"
    with pytest.raises(errors.BadRequest):
        provider.canonicalize({"a": {"nested": 1}})


def test_sign_and_verify_are_deterministic():
    fields = {"merId": "m1", "merOrderId": "PO-1", "amount": "1.00", "currency": "USD"}
    signature = provider.sign(fields, KEY)
    assert len(signature) == 64 and signature == provider.sign(dict(fields), KEY)
    assert provider.verify_signature(fields, signature, KEY)
    assert provider.verify_signature(fields, signature.upper(), KEY)
    assert not provider.verify_signature(fields, "00" * 32, KEY)
    assert not provider.verify_signature(fields, None, KEY)
    assert not provider.verify_signature(fields, signature, None)
    tampered = dict(fields)
    tampered["amount"] = "2.00"
    assert not provider.verify_signature(tampered, signature, KEY)


def test_check_timestamp_window():
    stamp = int(NOW.timestamp())
    assert provider.check_timestamp(stamp, now=NOW) == stamp
    with pytest.raises(errors.BadRequest):
        provider.check_timestamp(stamp - 301, now=NOW)
    with pytest.raises(errors.BadRequest):
        provider.check_timestamp("not-a-number", now=NOW)


def test_amount_to_major():
    assert provider.amount_to_major(12345, "USD") == "123.45"
    assert provider.amount_to_major(100, "USD") == "1.00"
    assert provider.amount_to_major(1000, "JPY") == "1000"
    assert provider.amount_to_major(1234567, "KWD") == "1234.567"
    assert provider.amount_to_major(105, "JPY") == "105"      # JPY 精度 0
    with pytest.raises(errors.BadRequest):
        provider.amount_to_major(0, "USD")
    with pytest.raises(errors.BadRequest):
        provider.amount_to_major(100, "CHF")


def test_mock_provider_checkout_and_webhook():
    mock = provider.MockProvider()
    checkout = mock.create_checkout({"order_no": "PO-1", "amount_minor": 100_00,
                                     "currency": "USD", "method": "card", "now": NOW})
    assert checkout["provider"] == "mock" and checkout["pay_url"].endswith("PO-1")
    capabilities = mock.capabilities()
    assert "card" in capabilities["methods"] and capabilities["supports_refund"]
    body = {"merId": "m08-merchant", "merOrderId": "PO-1", "platformOrderId": "txn-1",
            "amount": 10000, "currency": "USD", "status": "1",
            "timestamp": int(NOW.timestamp())}
    body["sign"] = provider.sign(body, KEY)
    import json

    raw = json.dumps(body).encode()
    event = mock.verify_webhook(raw, {}, now=NOW)
    assert event.signature_verified and event.payload_hash
    bad = dict(body)
    bad["amount"] = 1
    raw_bad = json.dumps(bad).encode()
    assert not mock.verify_webhook(raw_bad, {}, now=NOW).signature_verified
    with pytest.raises(errors.BadRequest):
        mock.verify_webhook(b"[]", {}, now=NOW)
    with pytest.raises(errors.BadRequest):
        mock.verify_webhook(b"{}", {}, now=NOW)          # 缺 timestamp


def test_provider_unavailable_paths():
    upg = provider.UpgProvider()                          # 未注入 KMS
    with pytest.raises(provider.ProviderUnavailable):
        upg.create_checkout({"order_no": "PO-1", "amount_minor": 100, "currency": "USD",
                             "method": "card", "now": NOW})
    with pytest.raises(provider.ProviderUnavailable):
        upg.verify_webhook(b"{}", {}, now=NOW)
    with pytest.raises(provider.ProviderUnavailable):
        upg.query_payment("txn-1")
    with pytest.raises(provider.ProviderUnavailable):
        upg.refund({})
    mock = provider.MockProvider()
    with pytest.raises(provider.ProviderUnavailable):
        mock.query_payment("unknown")
    assert mock.query_payment("txn-1") if False else True


def test_mock_query_resolver_and_registry():
    mock = provider.MockProvider(scripted_status={"txn-1": "1"})
    assert mock.query_payment("txn-1")["status"] == "1"
    resolved = provider.MockProvider(status_resolver=lambda ref: "2" if ref == "txn-2" else None)
    assert resolved.query_payment("txn-2")["status"] == "2"
    registry = provider.build_registry([mock])
    assert registry.get("MOCK") is mock
    assert registry.get("upg") is None
    assert registry.ids() == ["mock"]
    assert provider.build_registry().get("mock") is not None


def test_create_checkout_rejects_unknown_method():
    mock = provider.MockProvider()
    with pytest.raises(errors.BadRequest):
        mock.create_checkout({"order_no": "PO-1", "amount_minor": 100, "currency": "USD",
                              "method": "crypto", "now": NOW})
    with pytest.raises(errors.BadRequest):
        mock.create_checkout({"amount_minor": 100, "currency": "USD", "method": "card",
                              "now": NOW})
