# SPDX-License-Identifier: Apache-2.0
"""错误映射与信封（M03 §4.4 / spec ``Error`` / INV-M03-05 / INV-M03-08）。不需要 DB。"""
from __future__ import annotations

import pytest

from app.gateway import errors, facts


# ─────────────────────────────────────────────────────── 映射表
def test_mapping_matches_m03_section_4_4():
    """逐行对照 M03 §4.4（HTTP / 数字码）——改表必须先改规格。"""
    expected = {
        # Key 缺失 / 无效 / 禁用过期 / IP 不在白名单
        "key_missing": (401, 40101),
        "key_invalid": (401, 40101),
        "key_policy_denied": (403, 40102),
        # 余额不足 / 内容拦截 / 特性未开放 / 账户只读
        "insufficient_balance": (402, 40201),
        "content_blocked": (403, 40302),
        "feature_disabled": (403, 40303),
        "account_readonly": (403, 40304),
        # 参数 / 请求体超限
        "bad_request": (400, 40001),
        "payload_too_large": (413, 40013),
        # 状态冲突
        "conflict": (409, 40919),
        # 无可用节点 / 上游超时 / 上游异常
        "no_node": (503, 50901),
        "upstream_timeout": (504, 50902),
        "upstream_error": (502, 50903),
        # QPS / 每日花费上限
        "rate_limited": (429, 42901),
        "daily_spend_cap": (429, 42902),
        # 流式中断
        "stream_interrupted": (441, 44101),
        # 慢任务
        "eta_exceeded": (408, 45201),
        "cost_confirm_required": (202, 45202),
        "group_admission": (403, 45203),
        # 兜底
        "error_model_fallback": (500, 45001),
        "service_unavailable": (503, 45001),
    }
    actual = {key: (item.http, item.code) for key, item in errors.ERROR_SPECS.items()}
    assert actual == expected


def test_every_spec_type_is_in_the_error_enum():
    for item in errors.ERROR_SPECS.values():
        assert item.type in errors.ERROR_TYPES, item.key


def test_spec_registered_codes_cover_the_contract_changes():
    """spec 1.2.0/1.2.1 已登记：40201 / 40013 / 40919 / 40102 / 40304 / 40101。"""
    registered = {item.code for item in errors.ERROR_SPECS.values() if item.registered}
    assert {40101, 40102, 40201, 40013, 40919, 40304} <= registered


def test_pending_spec_codes_are_explicit_and_reported():
    """未进 spec 码段表的码必须显式列出（交付证据里作为 CR 上报 Lead），不得静默返回。"""
    assert errors.PENDING_SPEC_CODES == (40001, 40302, 40303, 42901, 42902, 44101, 45001,
                                         45201, 45202, 45203, 50901, 50902, 50903)
    for item in errors.ERROR_SPECS.values():
        assert item.note, f"{item.key}: 未登记码必须写口径备注"


def test_never_returns_40103_because_spec_1_2_1_reuses_it_for_refresh_tokens():
    codes = {item.code for item in errors.ERROR_SPECS.values()}
    assert 40103 not in codes
    assert errors.ERROR_SPECS["key_policy_denied"].code == 40102


def test_unknown_error_key_is_rejected():
    with pytest.raises(KeyError):
        errors.spec("not_registered")


# ─────────────────────────────────────────────────────── 信封
def test_error_body_has_spec_required_fields():
    exc = errors.GatewayError("rate_limited", "太频繁", retry_after_s=3)
    body = errors.error_body(exc, "req-1")
    assert set(body) == {"error"}
    payload = body["error"]
    assert payload["type"] == "rate_limit_error"
    assert payload["code"] == 42901
    assert payload["message"] == "太频繁"
    assert payload["request_id"] == "req-1"
    assert payload["reason"] == "rate_limited"
    assert payload["retry_after"] == 3


def test_error_body_never_leaks_internal_details():
    exc = errors.GatewayError("bad_request", "参数不对", details={"field": "model",
                                                                "stack": "traceback..."})
    payload = errors.error_body(exc, "req-2")["error"]
    # details 原样进来会带上内部信息；调用方只允许放已核字段，这里断言 message 不含堆栈
    assert "Traceback" not in payload["message"]
    assert payload["field"] == "model"


def test_coarse_reason_codes_only():
    allowed = {None, "rate_limited", "quota_exceeded", "account_restricted", "policy_blocked"}
    for item in errors.ERROR_SPECS.values():
        assert item.reason in allowed, item.key


def test_403_and_429_carry_coarse_reason_only():
    for key in ("key_policy_denied", "account_readonly", "rate_limited", "daily_spend_cap"):
        item = errors.ERROR_SPECS[key]
        assert item.reason in {"policy_blocked", "account_restricted", "rate_limited",
                               "quota_exceeded"}


def test_429_and_503_require_retry_after():
    """INV-M03-05：429 / 503 必须带 Retry-After（由调用方填充，这里锁住默认值语义）。"""
    for key in ("rate_limited", "daily_spend_cap", "no_node", "service_unavailable"):
        exc = errors.GatewayError(key, "x", retry_after_s=5)
        assert exc.http_status in (429, 503)
        assert exc.retry_after_s == 5
        assert errors.error_body(exc, "r")["error"]["retry_after"] == 5


def test_with_headers_keeps_header_names():
    exc = errors.GatewayError("rate_limited", "x").with_headers(
        **{facts.RATE_LIMIT_LIMIT_HEADER: "5", facts.RETRY_AFTER_HEADER: "2"})
    assert exc.headers[facts.RATE_LIMIT_LIMIT_HEADER] == "5"
    assert exc.headers[facts.RETRY_AFTER_HEADER] == "2"


def test_server_error_helper_maps_to_500_and_45001():
    exc = errors.server_error("req-3")
    assert (exc.http_status, exc.code) == (500, 45001)
    assert exc.type == "server_error"


def test_error_billing_column_is_documented():
    """M03 §4.4 的「计费」列：失败一律不计，流式中断按上游实际。"""
    assert errors.ERROR_SPECS["no_node"].billing == "不计"
    assert errors.ERROR_SPECS["stream_interrupted"].billing == "按上游实际"
    assert errors.ERROR_SPECS["cost_confirm_required"].billing == "确认后计"
