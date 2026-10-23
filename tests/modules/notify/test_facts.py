# SPDX-License-Identifier: Apache-2.0
"""M12 纯函数单测：常量 / 合并窗口 / 渠道 / payload 零 PII（INV-03 / INV-07 / INV-09）。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.notify import facts, features


def test_constants_match_spec_enums():
    assert facts.LEVELS == ("P0", "P1", "P2")
    assert facts.CHANNELS == ("in_app", "email", "webhook")
    assert facts.CHANNEL_ORDER == ("in_app", "email", "webhook")
    assert facts.NOTIFICATION_STATUSES == ("queued", "sending", "delivered", "partial",
                                           "failed", "dead")
    assert facts.ATTEMPT_STATUSES == ("success", "retryable", "permanent")
    assert facts.WEBHOOK_EVENTS[-1] == "security.alert"
    assert facts.SIGNATURE_WINDOW_S == 300
    assert facts.MAX_ATTEMPTS_PER_CHANNEL == 3
    assert facts.WEBHOOK_RETRY_DELAYS_S == (1, 10, 60)


@pytest.mark.parametrize("created_at,window,expected", [
    (datetime(2026, 10, 23, 4, 0, tzinfo=timezone.utc), 3600, 1792728000 // 3600),
    (datetime(2026, 10, 23, 4, 59, 59, tzinfo=timezone.utc), 3600, 1792728000 // 3600),
    (datetime(2026, 10, 23, 5, 0, tzinfo=timezone.utc), 3600, 1792728000 // 3600 + 1),
])
def test_dedupe_bucket_is_floor_of_window(created_at, window, expected):
    assert facts.dedupe_bucket(created_at, window) == expected


def test_dedupe_bucket_rejects_bad_window():
    with pytest.raises(ValueError):
        facts.dedupe_bucket(datetime.now(timezone.utc), 0)


def test_channels_require_in_app_and_known_values():
    assert facts.validate_channels(["webhook", "in_app"]) == ("in_app", "webhook")
    with pytest.raises(ValueError):
        facts.validate_channels(["email"])                   # INV-02：站内必留
    with pytest.raises(ValueError):
        facts.validate_channels(["sms"])
    with pytest.raises(ValueError):
        facts.validate_channels("in_app")


def test_validate_events_accepts_spec_enum_only():
    assert facts.validate_events(["payment.settled", "task.completed"]) == (
        "payment.settled", "task.completed")
    with pytest.raises(ValueError):
        facts.validate_events([])
    with pytest.raises(ValueError):
        facts.validate_events(["batch.completed"])            # CR-5：以 spec 枚举为准
    with pytest.raises(ValueError):
        facts.validate_events("payment.settled")


def test_validate_level_digest_and_hhmm():
    assert facts.validate_level("P0") == "P0"
    with pytest.raises(ValueError):
        facts.validate_level("p0")
    assert facts.validate_digest("weekly") == "weekly"
    with pytest.raises(ValueError):
        facts.validate_digest("hourly")
    assert facts.normalize_hhmm("23:59") == "23:59"
    for bad in ("24:00", "9:00", "0900", "12:60"):
        with pytest.raises(ValueError):
            facts.normalize_hhmm(bad)


def test_payload_accepts_ids_amounts_and_reason_codes():
    cleaned = facts.validate_payload({
        "notification_id": "0b7c2f5e-1d2a-4c3b-8e9f-0123456789ab",
        "amount_minor": 12345, "currency": "USD",
        "occurred_at": datetime(2026, 10, 23, 4, 0, tzinfo=timezone.utc),
        "reason_code": "insufficient_balance", "count": 3, "status": "ok",
    })
    assert cleaned["amount_minor"] == 12345
    assert cleaned["occurred_at"].startswith("2026-10-23T04:00:00")


@pytest.mark.parametrize("payload", [
    {"email": "someone@example.com"},                       # PII 键
    {"phone": "+8613800138000"},                            # PII 键
    {"body": "hello"},                                      # 正文键
    {"secret": "x"},                                        # 凭据
    {"unknown_field": 1},                                   # 未登记键
    {"order_no": "a@b.com"},                                # 值像邮箱
    {"order_no": "13800138000"},                            # 值像手机号
    {"order_no": "x" * 200},                                # 疑似正文
    {"order_no": {"nested": 1}},                            # 嵌套对象
    {"Order No": 1},                                        # 键形态非法
])
def test_payload_rejects_pii_and_free_text(payload):
    with pytest.raises(ValueError):
        facts.validate_payload(payload)


def test_payload_customer_scope_rejects_internal_fields():
    with pytest.raises(ValueError):
        facts.validate_payload({"action": "freeze"}, scope=facts.SCOPE_CUSTOMER)
    # 内部模板允许（INV-09：内部可含处置动作，但仍不能有 PII）
    assert facts.validate_payload({"action": "freeze"}, scope=facts.SCOPE_INTERNAL) == {
        "action": "freeze"}
    with pytest.raises(ValueError):
        facts.validate_payload(None, scope="public")


def test_payload_lists_and_none():
    assert facts.validate_payload({"channels": ["in_app", "email"]}) == {
        "channels": ["in_app", "email"]}
    assert facts.validate_payload(None) == {}


def test_email_phone_detectors():
    assert facts.looks_like_email("a@b.co")
    assert not facts.looks_like_email("not-an-email")
    assert facts.looks_like_phone("+8613800138000")
    assert facts.looks_like_phone("13800138000")
    assert not facts.looks_like_phone("20261023")           # 8 位流水号不算手机号


def test_feature_switches_have_three_fields_and_are_off():
    assert features.WRITE_SURFACE == ()
    for switch in features.FEATURE_SWITCHES:
        assert switch.owner and switch.expire_at and switch.rollback_rule
        assert switch.default is False
        assert features.enabled(switch.name) is False
    with pytest.raises(KeyError):
        features.get("notify.not_registered")


def test_feature_switch_validation_rejects_incomplete_registration():
    with pytest.raises(ValueError):
        features.FeatureSwitch(name="notify.x", owner="", expire_at=datetime.now().date(),
                               rollback_rule="rollback ok")
    with pytest.raises(ValueError):
        features.FeatureSwitch(name="notify.x", owner="seat",
                               expire_at=datetime.now().date(), rollback_rule="short")
    with pytest.raises(ValueError):
        features.FeatureSwitch(name="notify.x", owner="seat",
                               expire_at=datetime.now().date(),
                               rollback_rule="rollback is clear", default=True)
    with pytest.raises(ValueError):
        features.FeatureSwitch(name="badname", owner="seat",
                               expire_at=datetime.now().date(),
                               rollback_rule="rollback is clear")


def test_config_defaults_and_validation():
    from app.notify import config_source

    cfg = config_source.snapshot()
    assert cfg.merge_window_s == 3600
    assert cfg.webhook_retry_delays_s == (1, 10, 60)
    assert cfg.as_dict()["notify.digest_default"] == "realtime"
    config_source.validate_config(cfg)
    with pytest.raises(ValueError):
        config_source.validate_config(config_source.NotifyConfig(merge_window_s=10))
    with pytest.raises(ValueError):
        config_source.validate_config(config_source.NotifyConfig(webhook_timeout_s=1))
    with pytest.raises(ValueError):
        config_source.validate_config(
            config_source.NotifyConfig(webhook_retry_delays_s=(10, 1, 60)))
    with pytest.raises(ValueError):
        config_source.validate_config(config_source.NotifyConfig(email_retry_count=9))


def test_config_provider_merges_partial_values():
    from app.notify import config_source

    config_source.set_provider(lambda: {"notify.merge_window_s": 120,
                                        "notify.webhook_retry_delays_s": [2, 20, 120],
                                        "notify.digest_default": "daily"})
    try:
        cfg = config_source.snapshot()
        assert cfg.merge_window_s == 120
        assert cfg.webhook_retry_delays_s == (2, 20, 120)
        assert cfg.digest_default == "daily"
        assert cfg.webhook_timeout_s == 10                    # 未提供的键回落默认
    finally:
        config_source.set_provider(None)
    assert config_source.snapshot().merge_window_s == 3600


def test_clock_helpers_normalize_naive_datetimes():
    from app.notify import clock

    naive = datetime(2026, 10, 23, 4, 0)
    assert clock.isoformat(naive) == "2026-10-23T04:00:00+00:00"
    assert clock.to_utc(naive).tzinfo is timezone.utc
    assert clock.from_epoch_s(1792728000).year == 2026
    assert clock.isoformat(None) is None
    # 合并窗口按 UTC 计算：带 +08:00 的时间也要先归一
    assert facts.dedupe_bucket(naive + timedelta(hours=1), 3600) == facts.dedupe_bucket(
        datetime(2026, 10, 23, 5, 0, tzinfo=timezone.utc), 3600)
