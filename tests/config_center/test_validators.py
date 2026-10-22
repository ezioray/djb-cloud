# SPDX-License-Identifier: Apache-2.0
"""校验器测试：类型 / 范围 / 枚举 / 跨字段 / 危险键 / 密钥形态 / expire_at / 升级审批。

对应 M10 §9 验收场景 1–2 与 §3 不变量中与校验相关的部分：
INV-03（自批自核的输入约束）、INV-04（冷却由 facts 提供）、INV-05（密钥形态）、INV-06（危险键）。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.config_center import registry, validators
from app.config_center.errors import (
    CooldownActive,
    CrossFieldViolation,
    DangerousKeyForbidden,
    GrayPlanInvalid,
    IdempotencyConflict,
    KeyLocked,
    OutsidePublishWindow,
    RangeViolation,
    SecretShapeForbidden,
    SelfApprovalForbidden,
    StepUpRequired,
    TypeMismatch,
    UnitViolation,
    UnknownKey,
    ValidationFailed,
    VersionNotFound,
)

NOW = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)
FUTURE = NOW + timedelta(days=30)
PAST = NOW - timedelta(days=1)


# ─────────────────────────────────────────────── 正常值
@pytest.mark.parametrize("key,value", [
    ("billing.service_fee_bps", 1500),
    ("billing.gas_fee_mode", "EXTERNAL"),
    ("billing.gas_fee_bearer", "PAYER"),
    ("pool.reserved_default", 30),
    ("treasury.hot_wallet_cap", "10000.00"),
    ("config.gray_steps", [1, 5, 25, 100]),
    ("config.publish_window", {"start": "10:00", "end": "17:00", "timezone": "+08:00",
                               "weekdays": [1, 2, 3, 4, 5]}),
    ("points.redeem_rate_bps", 10000),
])
def test_validate_value_happy(key, value):
    result = validators.validate_value(key, value, now=NOW)
    assert result.key.key == key
    assert result.value == value
    assert result.requires_escalation is False


def test_validate_value_unknown_key_and_type():
    with pytest.raises(UnknownKey) as excinfo:
        validators.validate_value("billing.unknown_key", 1)
    assert excinfo.value.code == 47001

    with pytest.raises(TypeMismatch):
        validators.validate_value("billing.service_fee_bps", "1500")
    with pytest.raises(TypeMismatch):
        validators.validate_value("billing.gas_fee_mode", 1)
    with pytest.raises((TypeMismatch, UnitViolation)):
        validators.validate_value("billing.service_fee_bps", 15.0)


def test_validate_value_range_and_enum():
    with pytest.raises(RangeViolation):
        validators.validate_value("billing.service_fee_bps", 15000)
    with pytest.raises(RangeViolation):
        validators.validate_value("billing.gas_fee_mode", "internal")
    with pytest.raises(RangeViolation):
        validators.validate_value("routing.policy_version", "ABC")   # pattern 不匹配


# ─────────────────────────────────────────────── 升级审批（不拒绝，但走 P0）
def test_escalate_above_threshold():
    assert validators.validate_value("billing.service_fee_bps", 3000).requires_escalation is False
    result = validators.validate_value("billing.service_fee_bps", 3001)
    assert result.requires_escalation is True
    assert "强制升级阈值" in result.escalation_reasons[0]


def test_max_delta_escalates_without_rejecting():
    ok = validators.validate_value("pool.reserved_default", 35, current=30)
    assert ok.requires_escalation is False
    over = validators.validate_value("pool.reserved_default", 45, current=30)
    assert over.requires_escalation is True
    assert "x-djb-max-delta" in over.escalation_reasons[0]


def test_tighten_only_rejects_loosening():
    # billing.fee_cap_pct 是公开承诺上限（只允许收紧）
    assert validators.validate_value("billing.fee_cap_pct", 15, current=20).value == 15
    with pytest.raises(ValidationFailed) as excinfo:
        validators.validate_value("billing.fee_cap_pct", 20, current=18)
    assert excinfo.value.code == 47001
    assert "只允许收紧" in str(excinfo.value)


# ─────────────────────────────────────────────── expire_at（x-djb-expire-required）
def test_expire_required_switch_must_carry_expire_at():
    with pytest.raises(ValidationFailed) as excinfo:
        validators.validate_value("flag.slow_task_enabled", True, now=NOW)
    assert "expire_at" in str(excinfo.value)

    ok = validators.validate_value("flag.slow_task_enabled", True, expire_at=FUTURE, now=NOW)
    assert ok.value is True

    with pytest.raises(ValidationFailed):
        validators.validate_value("flag.slow_task_enabled", True, expire_at=PAST, now=NOW)
    with pytest.raises(ValidationFailed):
        validators.validate_value("flag.slow_task_enabled", True, expire_at="2027-01-01T00:00:00",
                                  now=NOW)                       # 无时区
    with pytest.raises(ValidationFailed):
        validators.validate_value("flag.slow_task_enabled", True, expire_at="not-a-time", now=NOW)


# ─────────────────────────────────────────────── INV-05 密钥形态
@pytest.mark.parametrize("value", [
    "-----BEGIN RSA PRIVATE KEY-----",
    "AKIAABCDEFGHIJKLMNOP",
    "sk_live_abcdefghijklmnopqrst",
    "0x" + "a" * 64,
    "a" * 64,
    "password=hunter2",
    "abandon ability able about above absent absorb abstract absurd abuse access accident",
])
def test_secret_shapes_are_rejected(value):
    with pytest.raises(SecretShapeForbidden) as excinfo:
        validators.assert_not_secret(value)
    assert excinfo.value.code == 47001


def test_secret_shape_rejected_through_validate_value():
    with pytest.raises(SecretShapeForbidden):
        validators.validate_value("content.wordlist_version", "AKIAABCDEFGHIJKLMNOP")
    with pytest.raises(SecretShapeForbidden):
        validators.validate_value("config.gray_steps", ["AKIAABCDEFGHIJKLMNOP", 100])


def test_normal_values_are_not_flagged_as_secret():
    for value in ("v2026.10", "INTERNAL", "2026-10-23", "wordlist-g6"):
        validators.validate_value("content.wordlist_version", value)


def test_secret_ref_structure():
    ref = {"scheme": "kms", "path": "alias/treasury-signing", "inject": "sdk", "version": "v3"}
    result = validators.validate_value("treasury.deposit_address_ref", ref)
    assert result.value == ref

    bad_refs = [
        {**ref, "extra": 1},                                  # 多字段
        {k: v for k, v in ref.items() if k != "path"},        # 缺字段
        {**ref, "scheme": "plain"},                          # scheme 非法
        {**ref, "inject": "http"},                           # inject 非法
        {**ref, "path": "has space"},                        # path 含空白
        {**ref, "version": ""},                              # version 空
    ]
    for bad in bad_refs:
        with pytest.raises(ValidationFailed):
            validators.validate_value("treasury.deposit_address_ref", bad)

    with pytest.raises(TypeMismatch):
        validators.validate_value("treasury.deposit_address_ref", "kms://alias/x")


# ─────────────────────────────────────────────── INV-06 危险键
def test_check_writable_blocks_blacklist_dangerous_and_generated():
    with pytest.raises(DangerousKeyForbidden) as excinfo:
        validators.check_writable("ops.audit_enabled")
    assert excinfo.value.code == 47004

    for key in ("risk.rule_version", "routing.policy_version", "treasury.gas_fee_mode"):
        with pytest.raises(DangerousKeyForbidden) as excinfo:
            validators.check_writable(key)
        assert excinfo.value.code == 47004

    with pytest.raises(UnknownKey):
        validators.check_writable("billing.not_registered")
    assert validators.check_writable("billing.service_fee_bps").key == "billing.service_fee_bps"


def test_check_publishable():
    assert validators.check_publishable("billing.service_fee_bps").publishable is True
    with pytest.raises(DangerousKeyForbidden):
        validators.check_publishable("risk.rule_version")
    with pytest.raises(ValidationFailed) as excinfo:
        validators.check_publishable("quota.per_user_daily_requests")
    assert excinfo.value.code == 47001


# ─────────────────────────────────────────────── 跨字段（§21.3.3）
def test_cross_field_share_sum():
    validators.validate_group({"treasury.platform_share_bps": 1600,
                               "treasury.provider_share_bps": 8400})
    with pytest.raises(CrossFieldViolation) as excinfo:
        validators.validate_group({"treasury.platform_share_bps": 1600,
                                   "treasury.provider_share_bps": 8300})
    assert "必须 = 10000" in str(excinfo.value)


def test_cross_field_gas_bearer_dependency():
    with pytest.raises(CrossFieldViolation):
        validators.validate_group({"billing.gas_fee_mode": "EXTERNAL"})
    assert validators.validate_group({"billing.gas_fee_mode": "EXTERNAL",
                                      "billing.gas_fee_bearer": "PAYER"})
    with pytest.raises(CrossFieldViolation):
        validators.validate_group({"billing.gas_fee_mode": "INTERNAL",
                                   "billing.gas_fee_bearer": "PAYER"})


def test_cross_field_fee_cap_commitment():
    validators.validate_group({"billing.service_fee_bps": 2000, "billing.fee_cap_pct": 20})
    with pytest.raises(CrossFieldViolation) as excinfo:
        validators.validate_group({"billing.service_fee_bps": 2500, "billing.fee_cap_pct": 20})
    assert "承诺上限" in str(excinfo.value)


@pytest.mark.parametrize("steps", [[1, 5, 25, 90], [5, 5, 25, 100], [100, 5], [-1, 100]])
def test_cross_field_gray_steps(steps):
    with pytest.raises(CrossFieldViolation):
        validators.validate_group({"config.gray_steps": steps})


def test_cross_field_publish_window_workdays_only():
    validators.validate_group({"config.publish_window": {
        "start": "10:00", "end": "17:00", "timezone": "+08:00", "weekdays": [1, 2, 3, 4, 5]}})
    with pytest.raises(CrossFieldViolation):
        validators.validate_group({"config.publish_window": {
            "start": "10:00", "end": "17:00", "timezone": "+08:00", "weekdays": [1, 6]}})


def test_cross_field_transfer_caps():
    validators.validate_group({"points.transfer_per_tx_cap": 1000,
                               "points.transfer_daily_out_cap": 10000})
    with pytest.raises(CrossFieldViolation):
        validators.validate_group({"points.transfer_per_tx_cap": 20000,
                                   "points.transfer_daily_out_cap": 10000})


def test_group_merges_effective_values():
    """只改 platform 时，也要能和已有 provider 求和。"""
    effective = {"treasury.provider_share_bps": 8500}
    validators.validate_group({"treasury.platform_share_bps": 1500}, effective=effective)
    with pytest.raises(CrossFieldViolation):
        validators.validate_group({"treasury.platform_share_bps": 1600}, effective=effective)


def test_group_rejects_empty_and_unknown():
    with pytest.raises(ValidationFailed):
        validators.validate_group({})
    with pytest.raises(UnknownKey):
        validators.validate_group({"nope.key": 1})


def test_group_carries_expire_at_to_each_key():
    with pytest.raises(ValidationFailed):
        validators.validate_group({"flag.slow_task_enabled": True}, now=NOW)
    results = validators.validate_group({"flag.slow_task_enabled": True},
                                        expire_at=FUTURE, now=NOW)
    assert results["flag.slow_task_enabled"].value is True


def test_cross_field_rules_cover_expected_keys():
    names = {rule.name for rule in validators.cross_field_rules()}
    assert names == {"treasury_share_sum", "gas_bearer_required", "fee_cap_commitment",
                     "gray_steps_shape", "publish_window_shape", "transfer_caps"}
    for rule in validators.cross_field_rules():
        for key in rule.keys:
            assert registry.load().get(key) is not None, f"规则 {rule.name} 引用未注册键 {key}"


# ─────────────────────────────────────────────── 错误码表（47xxx 已登记）
@pytest.mark.parametrize("exc,code,http", [
    (ValidationFailed, 47001, 400),
    (SelfApprovalForbidden, 47002, 403),
    (KeyLocked, 47003, 409),
    (DangerousKeyForbidden, 47004, 403),
    (CooldownActive, 47005, 409),
    (VersionNotFound, 47006, 404),
    (GrayPlanInvalid, 47007, 400),
    (OutsidePublishWindow, 47008, 409),
    (StepUpRequired, 47009, 403),
    (IdempotencyConflict, 40919, 409),
])
def test_error_codes_are_registered(exc, code, http):
    error = exc("测试")
    assert error.code == code
    assert error.http_status == http
    payload = error.as_dict()
    assert payload["code"] == code and payload["http"] == http


def test_step_up_has_transitional_and_spec_shapes():
    error = StepUpRequired("缺 step-up")
    assert (error.code, error.http_status) == (47009, 403)          # CR-3 过渡口径
    assert (error.spec_code, error.spec_http_status) == (42401, 424)  # spec 1.2.0 目标口径


def test_unknown_error_code_is_rejected_at_construction():
    class NotRegistered(Exception):
        code = 47999

    from app.config_center.errors import ConfigCenterError
    class Bad(ConfigCenterError):
        code = 47999

    with pytest.raises(AssertionError):
        Bad("x")
