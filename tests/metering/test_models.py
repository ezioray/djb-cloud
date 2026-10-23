# SPDX-License-Identifier: Apache-2.0
"""收据解析 / UUIDv7 / 时间窗口 / 分页游标（纯函数，不需要 DB）。"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.metering import errors, facts, models, usage
from meterkit import NOW, receipt


# ─────────────────────────────────────────────────────── UUIDv7
def test_uuid7_is_version_7_and_rfc4122_variant():
    value = models.uuid7(NOW)
    assert value.version == 7
    assert value.variant == uuid.RFC_4122


def test_uuid7_is_time_ordered():
    early = models.uuid7(NOW)
    later = models.uuid7(NOW + timedelta(seconds=1))
    assert str(early) < str(later)


# ─────────────────────────────────────────────────────── parse_receipt：两种写法
def test_parse_receipt_accepts_spec_nested_shape():
    draft = models.parse_receipt(receipt(account_id=uuid.uuid4()), now=NOW)
    assert draft.receipt_id.startswith("rcpt_")
    assert draft.access == "A1"
    assert draft.usage_amount == "1500" and draft.usage_unit == "token"
    assert draft.price_amount == "1.25" and draft.price_minor == 125
    assert draft.usage_qty == 1500 and draft.tokens_in == 1000 and draft.tokens_out == 500
    assert draft.usage_source == "dual"
    assert draft.attempt_no == 1
    assert draft.reported_at == NOW


def test_parse_receipt_accepts_flat_8_2_shape():
    draft = models.parse_receipt(receipt(shape="flat", account_id=uuid.uuid4()), now=NOW)
    assert draft.price_minor == 125
    assert draft.canonical_fields()["price_amount"] == "1.25"


def test_parse_receipt_keeps_original_amount_strings():
    draft = models.parse_receipt(
        receipt(usage_amount="1500.0", price_amount="001.25", account_id=uuid.uuid4()), now=NOW)
    assert draft.usage_amount == "1500.0"                 # 原样（参与签名）
    assert draft.price_amount == "001.25"
    assert draft.price_minor == 125                       # 解析成整数分


@pytest.mark.parametrize("unit,amount,expected", [
    ("USD", "1.25", 125), ("usd", "1.25", 125),      # 主单位（美元）
    ("usd_minor", "125", 125),                        # 整数分直传
])
def test_parse_receipt_price_unit_accepts_usd_forms(unit, amount, expected):
    draft = models.parse_receipt(receipt(price_unit=unit, price_amount=amount,
                                         account_id=uuid.uuid4()), now=NOW)
    assert draft.price_minor == expected


def test_parse_receipt_rejects_non_usd_price_unit():
    with pytest.raises(errors.UnsupportedCurrency) as exc:
        models.parse_receipt(receipt(price_unit="EUR", account_id=uuid.uuid4()), now=NOW)
    assert exc.value.reason == "unsupported_currency"


def test_parse_receipt_rejects_price_precision():
    with pytest.raises(errors.AmountPrecisionRejected) as exc:
        models.parse_receipt(receipt(price_amount="1.255", account_id=uuid.uuid4()), now=NOW)
    assert exc.value.code == "40001"


@pytest.mark.parametrize("field", ["receipt_id", "task_id", "access", "request_id", "model"])
def test_parse_receipt_requires_mandatory_fields(field):
    body = receipt(account_id=uuid.uuid4())
    body.pop(field)
    with pytest.raises(errors.InvalidArgument) as exc:
        models.parse_receipt(body, now=NOW)
    assert exc.value.code == "40001"


def test_parse_receipt_rejects_unknown_access():
    with pytest.raises(errors.InvalidArgument):
        models.parse_receipt(receipt(access="Z9", account_id=uuid.uuid4()), now=NOW)


def test_parse_receipt_rejects_token_sum_mismatch():
    with pytest.raises(errors.InvalidArgument) as exc:
        models.parse_receipt(receipt(usage_amount="999", account_id=uuid.uuid4()), now=NOW)
    assert exc.value.details["field"] == "usage.amount"


def test_parse_receipt_allows_request_unit_without_tokens():
    draft = models.parse_receipt(receipt(usage_unit="request", usage_amount="1", tokens_in=0,
                                        tokens_out=0, account_id=uuid.uuid4()), now=NOW)
    assert draft.usage_qty == 1 and draft.usage_unit == "request"


@pytest.mark.parametrize("source", ["client_reported", "server_measured", "dual", "estimated"])
def test_parse_receipt_accepts_usage_sources(source):
    draft = models.parse_receipt(receipt(usage_source=source, account_id=uuid.uuid4()), now=NOW)
    assert draft.usage_source == source


def test_parse_receipt_rejects_unknown_usage_source():
    with pytest.raises(errors.InvalidArgument):
        models.parse_receipt(receipt(usage_source="guessed", account_id=uuid.uuid4()), now=NOW)


def test_parse_receipt_clamps_future_reported_at():
    """未来时间按服务端 now 截断（时间比较只用服务端时间）。"""
    future = NOW + timedelta(hours=5)
    draft = models.parse_receipt(receipt(reported_at=future, account_id=uuid.uuid4()), now=NOW)
    assert draft.reported_at == NOW


def test_parse_receipt_rejects_malformed_reported_at():
    body = receipt(account_id=uuid.uuid4())
    body["reported_at"] = "yesterday-ish"
    with pytest.raises(errors.InvalidArgument):
        models.parse_receipt(body, now=NOW)


def test_parse_receipt_requires_account_uuid_shape():
    body = receipt()
    body["account_id"] = "not-a-uuid"
    with pytest.raises(errors.InvalidArgument):
        models.parse_receipt(body, now=NOW)


def test_parse_receipt_rejects_attempt_no_zero():
    with pytest.raises(errors.InvalidArgument):
        models.parse_receipt(receipt(attempt_no=0, account_id=uuid.uuid4()), now=NOW)


def test_parse_receipt_rejects_non_mapping():
    with pytest.raises(errors.InvalidArgument):
        models.parse_receipt(["not", "a", "dict"], now=NOW)


def test_parse_receipt_rejects_float_amount():
    body = receipt(account_id=uuid.uuid4())
    body["usage"] = {"amount": 1500.0, "unit": "token"}
    with pytest.raises(errors.InvalidArgument):
        models.parse_receipt(body, now=NOW)


# ─────────────────────────────────────────────────────── 时间工具
def test_parse_moment_accepts_date_and_rfc3339():
    assert models.parse_moment("2026-10-23", field="from") == \
        datetime(2026, 10, 23, tzinfo=timezone.utc)
    assert models.parse_moment("2026-10-23", field="to", end_of_day=True).hour == 23
    assert models.parse_moment("2026-10-23T04:00:00Z", field="from") == NOW


def test_parse_moment_rejects_garbage():
    with pytest.raises(errors.InvalidArgument):
        models.parse_moment("2026-13-45", field="from")


def test_iso_formats_utc_with_z():
    assert models.iso(NOW) == "2026-10-23T04:00:00Z"
    assert models.iso(None) is None


# ─────────────────────────────────────────────────────── 游标
def test_cursor_roundtrip():
    usage_id = str(uuid.uuid4())
    cursor = usage.encode_cursor(NOW, usage_id)
    moment, decoded_id = usage.decode_cursor(cursor)
    assert moment == NOW and decoded_id == usage_id


@pytest.mark.parametrize("bad", ["", "!!!", "bm90LWEtY3Vyc29y", "x" * (facts.MAX_CURSOR_LEN + 1)])
def test_cursor_rejects_invalid_values(bad):
    with pytest.raises(errors.InvalidArgument):
        usage.decode_cursor(bad)


# ─────────────────────────────────────────────────────── 结论 / 行的形状
def test_batch_outcome_response_shape():
    verdict = models.ReceiptVerdict(receipt_id="r1", state="rejected", code=46001,
                                    reason="provider_signature_mismatch", message="签名不符")
    outcome = models.BatchOutcome(accepted=("r0",), rejected=(verdict,),
                                  duplicates=("r9",))
    body = outcome.as_response()
    assert body["accepted"] == ["r0"] and body["duplicates"] == ["r9"]
    assert body["rejected"][0]["code"] == 46001
    assert body["rejected"][0]["reason"] == "provider_signature_mismatch"


def test_usage_row_amount_is_amount_object():
    row = models.UsageRow(usage_id="u1", request_id="r1", attempt_no=1, account_id="a1",
                          node_id="n1", model="m1", access="A1", tokens_in=1, tokens_out=2,
                          amount_minor=125, usage_source="dual", state="recorded",
                          receipt_id="rc1", correction_id=None, recorded_at=NOW)
    payload = row.as_dict()
    assert payload["amount"] == {"amount": "1.25", "unit": "USD"}
    assert payload["recorded_at"] == "2026-10-23T04:00:00Z"
