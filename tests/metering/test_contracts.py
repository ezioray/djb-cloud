# SPDX-License-Identifier: AGPL-3.0-or-later
"""事件信封 / 特性开关 / 配置快照（02-events §1 §3 / M05 §8.1 / 硬约束第 4 条）。不需要 DB。"""
from __future__ import annotations

import uuid
from datetime import date, timedelta

import pytest

from app.metering import config_source, errors, events, facts, features, models
from meterkit import NOW, receipt


# ─────────────────────────────────────────────────────── 事件信封
def _draft(**kwargs):
    return models.parse_receipt(receipt(account_id=uuid.uuid4(), **kwargs), now=NOW)


def test_build_envelope_has_all_twelve_fields():
    envelope = events.usage_recorded_event(usage_id="u1", account_id="a1", request_id="r1",
                                           amount_minor=125, source="dual", trace_id="t1",
                                           occurred_at=NOW)
    assert set(envelope) == {"event_id", "type", "version", "occurred_at", "producer",
                             "aggregate_type", "aggregate_id", "correlation_id", "causation_id",
                             "trace_id", "idempotency_key", "payload"}
    assert envelope["type"] == "usage.recorded"
    assert envelope["producer"] == "M05" and envelope["version"] == 1
    assert envelope["aggregate_type"] == "usage_record"
    assert uuid.UUID(envelope["event_id"]).version == 7
    assert envelope["occurred_at"] == "2026-10-23T04:00:00Z"
    assert envelope["idempotency_key"] == "usage.recorded:u1"


def test_receipt_signed_event_payload_has_contract_keys_only():
    draft = _draft()
    envelope = events.receipt_signed_event(draft=draft, usage_id="u1",
                                           signature_ref="hmac-sha256:abc", trace_id="t1",
                                           occurred_at=NOW)
    assert set(envelope["payload"]) == set(facts.EVENT_PAYLOAD_KEYS["receipt.signed"])
    assert envelope["aggregate_id"] == draft.receipt_id
    assert envelope["idempotency_key"] == f"receipt.signed:{draft.receipt_id}"


def test_usage_recorded_payload_carries_amount_minor_and_no_text():
    envelope = events.usage_recorded_event(usage_id="u1", account_id="a1", request_id="r1",
                                           amount_minor=125, source="dual", trace_id="t1",
                                           occurred_at=NOW)
    payload = envelope["payload"]
    assert payload["amount_minor"] == 125 and isinstance(payload["amount_minor"], int)
    assert payload["currency"] == "USD"
    for forbidden in ("prompt", "response", "content", "messages", "api_key", "secret"):
        assert forbidden not in payload


def test_usage_settled_idempotency_key_includes_correction():
    envelope = events.usage_settled_event(usage_id="u1", final_amount_minor=100,
                                          correction_id="c1", trace_id="t1", occurred_at=NOW)
    assert envelope["idempotency_key"] == "usage.settled:u1:c1"
    other = events.usage_settled_event(usage_id="u1", final_amount_minor=100,
                                       correction_id=None, trace_id="t1", occurred_at=NOW)
    assert other["idempotency_key"] == "usage.settled:u1:final"


def test_validate_payload_rejects_unknown_event_type():
    with pytest.raises(ValueError):
        events.validate_payload("usage.exploded", {"usage_id": "u1"})


def test_validate_payload_rejects_missing_required_key():
    with pytest.raises(ValueError):
        events.validate_payload("usage.recorded", {"usage_id": "u1"})


def test_build_envelope_rejects_overlong_trace():
    with pytest.raises(ValueError):
        events.usage_recorded_event(usage_id="u1", account_id="a1", request_id="r1",
                                    amount_minor=1, source="dual",
                                    trace_id="x" * (facts.MAX_TRACE_LEN + 1), occurred_at=NOW)


def test_event_types_are_registered_in_facts():
    assert set(facts.EVENT_TYPES) == {"receipt.signed", "usage.recorded", "usage.settled"}
    for event_type in facts.EVENT_TYPES:
        assert event_type in facts.EVENT_AGGREGATE_TYPE
        assert facts.EVENT_PAYLOAD_KEYS[event_type]


# ─────────────────────────────────────────────────────── 特性开关（三字段 + 默认关闭）
def test_every_switch_has_three_fields_and_defaults_off():
    for switch in features.switches():
        payload = switch.as_dict()
        assert payload["owner"].strip()
        assert payload["rollback_rule"].strip()
        assert payload["default"] is False
        assert isinstance(switch.expire_at, date)
        assert switch.expire_at > date(2026, 10, 23)


def test_switches_have_no_write_surface():
    assert features.WRITE_SURFACE == ()
    for switch in features.switches():
        assert features.enabled(switch.name) is False


def test_unknown_switch_lookup_raises():
    with pytest.raises(KeyError):
        features.get("metering.not_registered")


@pytest.mark.parametrize("kwargs", [
    {"name": "bad-name", "owner": "x", "expire_at": date(2027, 1, 1), "rollback_rule": "关掉即可"},
    {"name": "metering.x", "owner": "", "expire_at": date(2027, 1, 1), "rollback_rule": "关掉即可"},
    {"name": "metering.x", "owner": "x", "expire_at": "2027-01-01", "rollback_rule": "关掉即可"},
    {"name": "metering.x", "owner": "x", "expire_at": date(2027, 1, 1), "rollback_rule": "短"},
    {"name": "metering.x", "owner": "x", "expire_at": date(2027, 1, 1), "rollback_rule": "关掉即可",
     "default": True},
])
def test_switch_definition_requires_owner_expire_and_rollback(kwargs):
    with pytest.raises(ValueError):
        features.FeatureSwitch(**kwargs)


# ─────────────────────────────────────────────────────── 配置（§8.1 默认值 + 范围）
def test_config_defaults_match_section_8_1():
    snapshot = config_source.snapshot()
    assert snapshot.overbill_tolerance_pct == 1.0
    assert snapshot.correction_dual_threshold_usd == 50
    assert snapshot.estimated_alert_pct == 5
    assert snapshot.receipt_late_h == 24
    assert snapshot.source == "default"
    assert config_source.receipt_late_hours() == 24


def test_config_provider_overrides_values():
    provider = lambda namespace: {"metering.receipt_late_h": 48,  # noqa: E731
                                  "metering.overbill_tolerance_pct": "2.5"}
    snapshot = config_source.snapshot(provider)
    assert snapshot.receipt_late_h == 48
    assert snapshot.overbill_tolerance_pct == 2.5
    assert snapshot.source == "config_center"


def test_config_provider_values_are_clamped_to_declared_ranges():
    provider = lambda namespace: {"metering.receipt_late_h": 10_000,  # noqa: E731
                                  "metering.estimated_alert_pct": -5}
    snapshot = config_source.snapshot(provider)
    assert snapshot.receipt_late_h == facts.CONFIG_RANGES["metering.receipt_late_h"][1]
    assert snapshot.estimated_alert_pct == facts.CONFIG_RANGES["metering.estimated_alert_pct"][0]


@pytest.mark.parametrize("bad", ["not-a-number", None, True, {"x": 1}])
def test_config_provider_invalid_values_fall_back_to_defaults(bad):
    snapshot = config_source.snapshot(lambda namespace: {"metering.receipt_late_h": bad})
    assert snapshot.receipt_late_h == facts.CONFIG_DEFAULTS["metering.receipt_late_h"]


def test_config_provider_failure_is_not_fatal():
    def boom(namespace):
        raise RuntimeError("config center down")

    snapshot = config_source.snapshot(boom)
    assert snapshot.receipt_late_h == 24 and snapshot.source == "default"


def test_config_provider_accepts_short_keys():
    snapshot = config_source.snapshot(lambda namespace: {"receipt_late_h": 12})
    assert snapshot.receipt_late_h == 12


def test_config_set_provider_is_used_by_default_snapshot():
    config_source.set_config_provider(lambda namespace: {"metering.receipt_late_h": 6})
    try:
        assert config_source.snapshot().receipt_late_h == 6
    finally:
        config_source.set_config_provider(None)
    assert config_source.snapshot().receipt_late_h == 24


# ─────────────────────────────────────────────────────── 常量表自检
def test_facts_enums_match_spec():
    assert facts.ACCESS_MODES == ("A1", "A2", "B")
    assert facts.USAGE_STATES == ("recorded", "settled", "corrected")
    assert facts.CORRECTION_REASONS == ("overbill", "underbill", "estimate_fix", "dispute")
    assert facts.BILL_STATES == ("imported", "reconciled")
    assert facts.BATCH_MAX == 500 and facts.BATCH_MIN == 1
    assert facts.DEFAULT_PAGE_SIZE == 50 and facts.MAX_PAGE_SIZE == 200
    assert facts.RETENTION_YEARS == 5
    assert facts.CURRENCY == "USD"


def test_facts_tables_match_ownership():
    assert facts.TABLES == ("usage_records", "metering_receipts", "usage_corrections",
                            "upstream_bills", "loss_pool_entries", "metering_outbox")
    assert facts.NODE_SNAPSHOT_VIEW == "v_supply_node_snapshot"


def test_error_codes_are_registered_segment_values():
    assert errors.SignatureMismatch.status_code == 422
    assert errors.SignatureMismatch.code == "46001"
    assert errors.BatchTooLarge.status_code == 413
    assert errors.BatchTooLarge.code == "40013"
    assert errors.AuthUnavailable.status_code == 401
    assert errors.NotFound.code == "40401"
    assert errors.KeysUnavailable.code == "50001"
    assert errors.error_type_for(422) == "invalid_request_error"
    assert errors.error_type_for(500) == "server_error"
    assert errors.error_type_for(999) == "server_error"


def test_metering_error_dict_has_envelope_fields():
    exc = errors.InvalidArgument("bad", field="x")
    payload = exc.as_dict()
    assert payload["code"] == 40001 and payload["reason"] == "invalid_argument"
    assert payload["field"] == "x"


def test_retention_window_constant_is_five_years():
    assert timedelta(days=365 * facts.RETENTION_YEARS).days == 1825


# ─────────────────────────────────────────────────────── 契约 fixtures（只读校验）
FIXTURES_DIR = __import__("pathlib").Path(__file__).resolve().parents[2] / "contracts" / "fixtures" / "M05"


def _fixtures() -> list[dict]:
    import json

    return [json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(FIXTURES_DIR.glob("*.json"))]


ALLOWED_HTTP = {200, 201, 202, 400, 401, 403, 404, 409, 413, 422, 424, 429, 500}


def test_m05_fixtures_exist_and_match_schema():
    """``contracts/fixtures/M05/*.json`` 必须符合 ``_schema.json``（只校验结构，不改他人文件）。"""
    payloads = _fixtures()
    assert payloads, "缺 contracts/fixtures/M05/*.json"
    cases = {item["case"] for item in payloads}
    assert {"success", "error", "boundary"} <= cases
    for item in payloads:
        assert set(item) == {"module", "case", "description", "input", "expect"}
        assert item["module"] == "M05"
        assert isinstance(item["input"], dict) and isinstance(item["expect"], dict)
        assert item["description"].strip()
        http = item["expect"].get("http")
        if http is not None:
            assert http in ALLOWED_HTTP, (item["case"], http)


def test_fixtures_cover_m05_contract_surface():
    """T5：fixtures 覆盖 收据 / 明细分页 / 校正复核 / 账单容差 / outbox 五个面。"""
    descriptions = " ".join(item["description"] for item in _fixtures())
    for keyword in ("双签", "明细", "校正", "账单", "outbox"):
        assert keyword in descriptions, keyword
    receipt_fixtures = [item for item in _fixtures() if "receipt" in str(item["input"])]
    assert receipt_fixtures, "缺收据类 fixture"
    assert all(item["expect"].get("http") != 201 for item in receipt_fixtures
               if item["case"] in {"success", "boundary"}), \
        "spec 的 POST /node/receipts 成功响应是 200（不是 201）"


def test_bad_signature_fixture_code_is_tracked_against_spec_46001():
    """已知偏差登记：``error_bad_signature.json`` 里的 ``42220`` 属 M06 段，与 spec 1.2.0 和
    00-conventions §5 钉死的 ``46001`` 不一致（fixtures 归契约席维护，本席位只读）。

    本用例锁住「要么已改为 46001、要么仍是待裁决的历史值」——不允许出现第三种码。
    """
    payload = next(item for item in _fixtures() if item["case"] == "error")
    code = str(payload["expect"].get("error"))
    assert code in {"46001", "42220"}, code
    # 实现侧唯一口径：验签失败必须是 46001 / HTTP 422
    assert errors.SignatureMismatch.code == "46001"
    assert errors.SignatureMismatch.status_code == 422
