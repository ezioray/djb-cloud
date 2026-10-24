# SPDX-License-Identifier: AGPL-3.0-or-later
"""要点常量 / 错误码 / 特性开关 / 配置来源（M04 §8 / §4.1 / 00-conventions §1.5）。

这些用例不碰 DB：它们守的是「常量只有一个来源」和「开关三字段 + 默认关闭」两类硬约束。
"""
from __future__ import annotations

from datetime import date

import pytest

from app.scheduling import config_source, errors, facts, features


# --------------------------------------------------------------------------- facts
def test_enums_match_the_contract():
    assert facts.ACCESS_TYPES == ("A1", "A2", "B")            # M04 §5 / spec QuoteRequest
    assert facts.TIERS == ("realtime", "batch")               # spec RouteRequest.kind
    assert facts.OUTCOMES == ("routed", "fallback", "queued", "rejected")
    assert facts.PRICE_STRATEGIES == ("mid", "floor", "ceiling")
    assert facts.QUOTE_STATES == ("active", "consumed", "expired")
    assert facts.BOOKING_STATES == ("held", "consumed", "expired")
    assert facts.BID_STATES == ("active", "expired")


def test_elimination_codes_are_f1_to_f5():
    assert tuple(sorted(facts.ELIMINATION_CODES)) == ("F1", "F2", "F3", "F4", "F5")
    assert all(value and value.islower() for value in facts.ELIMINATION_CODES.values())


def test_config_keys_cover_m04_section_8_1():
    """M04 §8.1 的九个键必须全部登记（键名与规格逐字一致）。"""
    expected = {
        "routing.candidate_freshness_s", "routing.quotebook_refresh_s",
        "routing.max_tenant_share_pct", "routing.preempt_budget_per_h",
        "routing.latency_lambda", "routing.tie_break_epsilon_bps",
        "billing.service_fee_bps", "billing.price_strategy", "routing.policy_version",
    }
    assert set(facts.CONFIG_KEYS.values()) == expected


def test_module_constants_follow_section_8_2():
    assert facts.RHO_MIN_MILLI == 500 and facts.RHO_MAX_MILLI == 1_200       # ρ 0.50–1.20
    assert facts.KAPPA_MIN_MILLI == 1_000 and facts.KAPPA_MAX_MILLI == 3_000  # κ 1.00–3.00
    assert facts.DECISION_LATENCY_P99_MS == {"token": 20, "task": 2_000, "fabric": 10_000}
    assert facts.PREEMPT_BUDGET_PER_H == 6
    assert facts.PREEMPT_GRACEFUL_S == 30
    assert facts.TIE_EPSILON_DEFAULT_BPS == 300
    assert facts.BOOKING_TTL_S == 60
    assert facts.QUEUE_WATERMARK_PCT == (70, 85, 95)
    assert facts.GINI_MAX_MILLI == 350
    assert facts.DECISION_RETENTION_MONTHS == 12
    assert facts.QUOTE_RETENTION_DAYS == 90


def test_latency_lambda_per_channel_matches_product():
    """product §4.7.3：λ_realtime = 1.0 · λ_batch = 2.5 · λ_fabric = 4.0（分/ms 当量）。"""
    assert facts.LATENCY_LAMBDA_MICRO == {"realtime": 1_000_000, "batch": 2_500_000,
                                          "fabric": 4_000_000}


def test_events_are_the_five_registered_ones():
    assert set(facts.EVENT_TYPES) == {"quote.created", "quote.expired", "booking.created",
                                      "booking.expired", "routing.decided"}
    for event_type, keys in facts.EVENT_PAYLOAD_KEYS.items():
        assert event_type in facts.EVENT_TYPES
        assert keys, event_type


def test_reject_actions_are_exactly_three():
    """INV-06：最终拒绝必须带三个可选动作。"""
    assert len(facts.REJECT_ACTIONS) == 3
    assert all(set(item) == {"action", "hint"} for item in facts.REJECT_ACTIONS)


# --------------------------------------------------------------------------- errors
@pytest.mark.parametrize("exc_type,code,status", [
    (errors.InvalidArgument, 40001, 400),
    (errors.AuthUnavailable, 40101, 401),
    (errors.Forbidden, 40303, 403),
    (errors.NotFound, 40401, 404),
    (errors.ReplayBusy, 40901, 409),
    (errors.StateConflict, 40902, 409),
    (errors.IdempotencyConflict, 40919, 409),
    (errors.RateLimited, 42901, 429),
    (errors.SpendCapExceeded, 42902, 429),
    (errors.NoRoute, 45001, 503),
    (errors.DecisionLogUnavailable, 50001, 503),
])
def test_error_codes_are_registered(exc_type, code, status):
    """每个码都能追到 M04 §4.1 / 04-api-contracts 码段（未登记不得返回）。"""
    exc = exc_type("x")
    assert int(exc.code) == code
    assert exc.status_code == status
    assert exc.as_dict()["code"] == code
    assert exc.as_dict()["type"] == exc_type.__name__


def test_error_type_mapping_matches_spec_enum():
    assert errors.error_type_for(400) == "invalid_request_error"
    assert errors.error_type_for(401) == "authentication_error"
    assert errors.error_type_for(403) == "permission_error"
    assert errors.error_type_for(404) == "not_found_error"
    assert errors.error_type_for(409) == "conflict_error"
    assert errors.error_type_for(429) == "rate_limit_error"
    assert errors.error_type_for(503) == "service_unavailable"
    assert errors.error_type_for(599) == "server_error"


def test_no_route_carries_reason_and_three_actions():
    exc = errors.NoRoute("无可用节点", reason="no_route",
                         reason_codes=["no_candidates"], actions=list(facts.REJECT_ACTIONS))
    payload = exc.as_dict()
    assert payload["reason_codes"] == ["no_candidates"]
    assert len(payload["actions"]) == 3


# --------------------------------------------------------------------------- features
def test_every_switch_has_three_fields_and_defaults_off():
    assert features.FEATURE_SWITCHES, "至少要登记一个开关"
    for switch in features.switches():
        assert switch.owner.strip()
        assert isinstance(switch.expire_at, date) and switch.expire_at > date(2026, 10, 23)
        assert len(switch.rollback_rule.strip()) >= 8
        assert switch.default is False
        assert features.enabled(switch.name) is False


def test_no_write_surface_for_switches():
    assert features.WRITE_SURFACE == ()


def test_unknown_switch_is_rejected():
    with pytest.raises(KeyError):
        features.get("scheduling.not_registered")


@pytest.mark.parametrize("kwargs,error", [
    ({"name": "badname"}, ValueError),                        # 缺命名空间
    ({"name": "scheduling.x", "owner": " "}, ValueError),      # owner 空
    ({"name": "scheduling.x", "expire_at": "2027-01-01"}, ValueError),   # 非 date
    ({"name": "scheduling.x", "rollback_rule": "短"}, ValueError),        # 回滚规则太短
    ({"name": "scheduling.x", "default": True}, ValueError),             # 默认必须是关闭
])
def test_switch_validation_rejects_bad_declarations(kwargs, error):
    base = {"name": "scheduling.ok", "owner": "scheduler-seat",
            "expire_at": date(2027, 6, 30), "rollback_rule": "关闭后回到旧口径，无需迁移"}
    base.update(kwargs)
    with pytest.raises(error):
        features.FeatureSwitch(**base)


def test_switch_serialisation_keeps_three_fields():
    payload = features.get("scheduling.p4_preemption").as_dict()
    assert set(payload) >= {"name", "owner", "expire_at", "rollback_rule", "default"}
    assert payload["default"] is False


# --------------------------------------------------------------------------- config
def test_config_defaults_follow_section_8_1():
    values = config_source.resolve({})
    assert values["routing.candidate_freshness_s"] == 45
    assert values["routing.quotebook_refresh_s"] == 60
    assert values["routing.max_tenant_share_pct"] == 25
    assert values["routing.preempt_budget_per_h"] == 6
    assert values["routing.tie_break_epsilon_bps"] == 300
    assert values["routing.latency_lambda"] == 1_000           # 1.0 以 milli 存
    assert values["billing.price_strategy"] == "mid"
    assert values["routing.policy_version"] == facts.DEFAULT_POLICY_VERSION


def test_config_out_of_range_is_clamped():
    values = config_source.resolve({"routing.candidate_freshness_s": 999,
                                    "routing.max_tenant_share_pct": 1,
                                    "routing.tie_break_epsilon_bps": -5})
    assert values["routing.candidate_freshness_s"] == 120        # 上限
    assert values["routing.max_tenant_share_pct"] == 5           # 下限
    assert values["routing.tie_break_epsilon_bps"] == 0          # 下限


def test_config_rejects_bad_types_and_enums():
    values = config_source.resolve({"routing.candidate_freshness_s": "abc",
                                    "billing.price_strategy": "auction",
                                    "routing.policy_version": "not-hex"})
    assert values["routing.candidate_freshness_s"] == 45         # 回落默认
    assert values["billing.price_strategy"] == "mid"
    assert values["routing.policy_version"] == facts.DEFAULT_POLICY_VERSION


def test_config_provider_is_injected_and_resettable():
    calls: list[object] = []

    def provider(conn, context):
        calls.append(context)
        return {"routing.candidate_freshness_s": 30, "routing.policy_version": "abcdefabcdef"}

    config_source.set_provider(provider)
    try:
        values = config_source.resolve(config_source.raw(None, "tenant-x"))
        assert values["routing.candidate_freshness_s"] == 30
        assert values["routing.policy_version"] == "abcdefabcdef"
        assert calls == ["tenant-x"]
    finally:
        config_source.set_provider(None)
    assert config_source.current_provider() is None
    assert config_source.resolve(config_source.raw(None))["routing.candidate_freshness_s"] == 45


def test_config_provider_failure_falls_back_to_defaults():
    """provider 抛异常 / 返回非 mapping 时不能把请求打挂（防御性兜底）。"""
    config_source.set_provider(lambda conn, ctx: (_ for _ in ()).throw(RuntimeError("boom")))
    try:
        assert config_source.resolve(config_source.raw(None))["routing.quotebook_refresh_s"] == 60
    finally:
        config_source.set_provider(None)

    config_source.set_provider(lambda conn, ctx: ["not", "a", "mapping"])
    try:
        assert config_source.resolve(config_source.raw(None))["routing.quotebook_refresh_s"] == 60
    finally:
        config_source.set_provider(None)


def test_config_accessors_read_the_right_keys():
    values = config_source.resolve({})
    assert config_source.candidate_freshness_s(values) == 45
    assert config_source.quotebook_refresh_s(values) == 60
    assert config_source.max_tenant_share_pct(values) == 25
    assert config_source.preempt_budget_per_h(values) == 6
    assert config_source.tie_break_epsilon_bps(values) == 300
    assert config_source.latency_lambda_milli(values) == 1_000
    assert config_source.price_strategy(values) == "mid"
    assert config_source.policy_version(values) == facts.DEFAULT_POLICY_VERSION
