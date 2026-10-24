# SPDX-License-Identifier: AGPL-3.0-or-later
"""十域注册表测试：十域全覆盖、键契约自洽、默认值来自 facts、危险键与黑名单、schema 扩展关键字。"""
from __future__ import annotations

import pytest

from app.config_center import facts, registry, units
from app.config_center.errors import UnknownKey, ValidationFailed
from app.config_center.registry import AUX_NAMESPACES, DOMAINS, MISSING, ConfigKey, Registry

REG = registry.load()


# ─────────────────────────────────────────────── 十域
def test_exactly_ten_domains_with_unique_namespaces():
    assert len(REG.domains) == 10
    codes = [domain.code for domain in REG.domains]
    assert codes == ["flag", "billing", "risk", "quota_pool", "routing",
                     "notify", "content", "treasury", "partner", "exp"]
    namespaces = [ns for domain in REG.domains for ns in domain.namespaces]
    assert len(namespaces) == len(set(namespaces))
    assert set(REG.namespaces()) == set(namespaces) | {"config", "points"}


def test_every_domain_has_at_least_one_key():
    for domain in REG.domains:
        assert REG.by_domain(domain.code), f"配置域 {domain.code} 没有注册键"
    assert len(AUX_NAMESPACES) == 2
    assert REG.by_domain("config") and REG.by_domain("points")


def test_stats_snapshot():
    stats = REG.stats()
    assert stats["domains"] == 10
    assert stats["keys"] == 36
    assert stats["by_risk"] == {"P0": 22, "P1": 10, "P2": 4}
    assert stats["publishable"] == 26
    assert stats["dangerous"] == 3
    assert stats["sensitive"] == 3
    assert sum(stats["per_domain"].values()) + sum(stats["per_aux"].values()) == stats["keys"]


def test_key_contract_self_consistency():
    for item in REG.keys:
        assert registry.KEY_PATTERN.match(item.key)
        assert item.namespace == item.key.split(".", 1)[0]
        assert item.risk in registry.RISK_LEVELS
        assert item.value_type in units.VALUE_TYPES
        assert item.value_type in units.UNIT_VALUE_TYPES[item.unit]
        assert item.owner and item.owner.isupper()
        assert set(item.allow_scope) <= set(registry.SCOPES)
        assert item.schema_ref == f"{item.key}@v1"
        assert item.default_source.split(":", 1)[0] in ("facts", "spec", "policy", "unset")


# ─────────────────────────────────────────────── 默认值：来自 facts，不硬编码
def test_defaults_equal_facts_values():
    assert REG.require("billing.service_fee_bps").default == facts.platform_fee_default_bps()
    assert REG.require("billing.slow_task_discount_pct").default == \
        facts.slow_task_discount_pcts()[0]
    assert REG.require("billing.channel_fee_bps").default == facts.gas_defaults()["channel_fee_bps"]
    assert REG.require("billing.gas_fee_mode").default == facts.gas_defaults()["mode"]
    assert REG.require("billing.gas_fee_bearer").default == facts.gas_defaults()["bearer"]
    assert REG.require("billing.gas_fee_scope").default == facts.gas_defaults()["scope"]
    assert REG.require("pool.reserved_default").default == facts.reserved_pool()["default"]
    assert REG.require("treasury.platform_share_bps").default == facts.share_defaults_bps()[0]
    assert REG.require("treasury.provider_share_bps").default == facts.share_defaults_bps()[1]
    assert REG.require("treasury.hot_wallet_cap").default == f"{facts.wallet_cap_usd():.2f}"
    assert REG.require("billing.fee_cap_pct").default == facts.fee_cap_pct()          # R-3
    assert REG.require("notify.report.daily_send_at").default == facts.report_daily_send_at()  # R-2

    points = facts.points_defaults()
    assert REG.require("points.transfer_enabled").default == points["transfer_enabled"]
    assert REG.require("points.transfer_per_tx_cap").default == points["transfer_per_tx_cap"]
    assert REG.require("points.transfer_daily_out_cap").default == points["transfer_daily_out_cap"]
    assert REG.require("points.transfer_daily_in_cap").default == points["transfer_daily_in_cap"]
    assert REG.require("points.transfer_lock_days").default == points["transfer_lock_days"]
    assert REG.require("points.redeem_rate_bps").default == points["redeem_rate_bps"]

    cooldowns = facts.cooldowns()
    assert REG.require("config.p0_cooldown_h").default == cooldowns["P0"] // 3600
    assert REG.require("config.p1_cooldown_min").default == cooldowns["P1"] // 60
    assert REG.require("config.p0_rollback_mode").default == facts.p0_rollback_modes()[0]
    assert REG.require("config.publish_window").default == facts.publish_window().as_default()
    assert list(REG.require("config.gray_steps").default) == list(facts.gray_steps())


def test_missing_defaults_are_documented_and_unpublishable():
    missing = [item for item in REG.keys if item.default is MISSING]
    assert {item.key for item in missing} == {
        "risk.rule_version", "quota.per_user_daily_requests", "routing.policy_version",
        "content.wordlist_version", "content.compliance_terms",
        "treasury.deposit_address_ref", "treasury.gas_fee_mode",
        "partner.channel_rate_bps", "exp.route_weight_variant", "exp.ui_copy_variant",
    }
    for item in missing:
        assert item.default_source.startswith("unset:")
        assert item.publishable is False


def test_switch_keys_default_off_and_require_expiry():
    for name in ("flag.slow_task_enabled", "flag.invite_cop_enabled",
                 "partner.whitelist_enabled", "points.transfer_enabled"):
        item = REG.require(name)
        assert item.default is False
        assert item.default_source == "policy:switch-default-off" or name.startswith("points.")
    for name in ("flag.slow_task_enabled", "flag.invite_cop_enabled",
                 "partner.whitelist_enabled", "exp.route_weight_variant", "exp.ui_copy_variant"):
        assert REG.require(name).expire_required is True


def test_registry_follows_facts_changes(monkeypatch, tmp_path):
    """把 facts 里的冷却改成 12h，注册表默认值必须跟着变（证明没有硬编码）。"""
    text = facts.DEFAULT_FACTS_PATH.read_text(encoding="utf-8").replace(
        "value: P0 24h / P1 60min / P2 无", "value: P0 12h / P1 30min / P2 无")
    path = tmp_path / "facts.yaml"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv("DJB_FACTS_FILE", str(path))
    facts._load_cached.cache_clear()
    registry._load_cached.cache_clear()
    try:
        reg = registry.load()
        assert reg.require("config.p0_cooldown_h").default == 12
        assert reg.require("config.p1_cooldown_min").default == 30
    finally:
        registry._load_cached.cache_clear()
        facts._load_cached.cache_clear()


# ─────────────────────────────────────────────── 危险键
def test_dangerous_keys_are_read_only_and_documented():
    dangerous = {item.key: item for item in REG.dangerous_keys()}
    assert set(dangerous) == {"risk.rule_version", "routing.policy_version", "treasury.gas_fee_mode"}
    assert dangerous["risk.rule_version"].sensitive is True
    assert dangerous["routing.policy_version"].generated is True
    assert dangerous["treasury.gas_fee_mode"].legacy_alias_of == "billing.gas_fee_mode"


@pytest.mark.parametrize("key,fragment", [
    ("audit.audit_enabled", "审计"),
    ("ledger.merkle_disabled", "审计与账本行为"),
    ("identity.mfa_required", "MFA"),
    ("ops.skip_approval", "双人复核"),
    ("treasury.private_key", "密钥与凭据"),
    ("gateway.image_tag", "代码加载路径"),
    ("slo.p95_ms", "对外承诺"),
])
def test_forbidden_key_blacklist(key, fragment):
    reason = registry.forbidden_reason(key)
    assert reason is not None and fragment in reason


@pytest.mark.parametrize("key", [
    "billing.service_fee_bps", "ledger.close_cutoff_utc", "ledger.merkle_interval_h",
    "pool.reserved_default", "content.compliance_terms", "config.p0_rollback_mode",
])
def test_forbidden_key_blacklist_does_not_overmatch(key):
    assert registry.forbidden_reason(key) is None


# ─────────────────────────────────────────────── schema 与扩展关键字
def test_schema_body_has_2020_12_and_eight_x_djb_keywords():
    item = REG.require("billing.service_fee_bps")
    body = item.schema_body()
    assert body["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert body["$id"] == "billing.service_fee_bps@v1"
    assert body["type"] == "integer"
    assert body["minimum"] == facts.platform_fee_range_bps()[0]
    assert body["maximum"] == facts.platform_fee_range_bps()[1]
    assert body["x-djb-unit"] == "bps"
    assert body["x-djb-consumers"] == ["scheduler", "settlement", "provider-console"]
    assert body["x-djb-public"] is True
    assert body["default"] == facts.platform_fee_default_bps()
    assert body["x-djb-escalate-above"] == facts.platform_fee_range_bps()[2]
    for keyword in ("x-djb-unit", "x-djb-consumers", "x-djb-tighten-only", "x-djb-kill-switch",
                    "x-djb-secret-ref", "x-djb-public", "x-djb-expire-required"):
        assert keyword in body, keyword


def test_schema_max_delta_and_private_domains():
    pool = REG.require("pool.reserved_default")
    assert pool.schema_body()["x-djb-max-delta"] == {"abs": 10, "unit": "pp"}
    assert REG.require("treasury.platform_share_bps").schema_body()["x-djb-public"] is False
    assert REG.require("risk.rule_version").schema_body()["x-djb-public"] is False
    assert REG.require("treasury.deposit_address_ref").schema_body()["x-djb-secret-ref"] is True
    assert REG.require("config.publish_window").schema_body()["type"] == ["object", "array"]


def test_metadata_for_db_roundtrip():
    meta = REG.require("config.gray_steps").as_metadata()
    assert meta["namespace"] == "config"
    assert meta["default_value"] == list(facts.gray_steps())
    assert meta["allow_scope"] == ["global"]
    missing_meta = REG.require("risk.rule_version").as_metadata()
    assert missing_meta["default_value"] is None
    assert missing_meta["default_source"].startswith("unset:")


# ─────────────────────────────────────────────── 查询与失败路径
def test_require_and_domain_lookup():
    assert REG.require("billing.gas_fee_mode").domain == "billing"
    assert REG.domain_of("config.p0_cooldown_h").namespace == "config"
    assert REG.domain_of("points.transfer_enabled").namespace == "points"
    with pytest.raises(UnknownKey) as excinfo:
        REG.require("billing.not_registered")
    assert excinfo.value.code == 47001
    with pytest.raises(UnknownKey):
        REG.domain_of("unknown.key")
    assert "billing.gas_fee_mode" in REG
    assert "nope" not in REG
    assert len(list(iter(REG))) == len(REG)


def _one_key(base: str = "billing.gas_fee_mode", **overrides) -> ConfigKey:
    base = REG.require(base)
    fields = {field: getattr(base, field) for field in base.__dataclass_fields__}
    fields.update(overrides)
    return ConfigKey(**fields)


@pytest.mark.parametrize("mutate,expected", [
    (lambda: Registry(domains=DOMAINS[:9], aux=AUX_NAMESPACES, keys=()),
     "配置域必须是十域"),
    (lambda: Registry(domains=DOMAINS[:9] + (DOMAINS[0],), aux=AUX_NAMESPACES, keys=()),
     "配置域 code 重复"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(), _one_key())), "key 重复注册"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(unit="furlongs"),)), "单位未登记"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(value_type="json"),)), "不匹配"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(key="Audit.Bad"),)), "key 形态非法"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(key="audit.audit_enabled"),)), "危险键黑名单"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(base="pool.reserved_default", default=60),)), "大于上限"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(base="billing.service_fee_bps", minimum=2000, maximum=3000),)),
     "小于下限"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(default=MISSING, default_source="facts:假的"),)), "unset"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(tighten_only=True, direction="none"),)), "direction"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(legacy_alias_of="billing.nope"),)), "legacy_alias_of"),
    (lambda: Registry(domains=DOMAINS, aux=AUX_NAMESPACES,
                      keys=(_one_key(risk="P9"),)), "风险级非法"),
])
def test_registry_build_validation_rejects_bad_contracts(mutate, expected):
    with pytest.raises(ValidationFailed) as excinfo:
        registry._validate(mutate())
    assert expected in str(excinfo.value)


def test_partial_registry_validation_catches_missing_domain_coverage():
    keys = tuple(item for item in REG.keys if item.domain != "exp")
    with pytest.raises(ValidationFailed) as excinfo:
        registry._validate(Registry(domains=DOMAINS, aux=AUX_NAMESPACES, keys=keys))
    assert "十域全覆盖" in str(excinfo.value)
