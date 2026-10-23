# SPDX-License-Identifier: Apache-2.0
"""M08 纯策略测试：状态机 / 池深度 / cap / 归集 / 出款 / 退款 / 签名 / 白名单（INV-01…INV-14）。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.treasury import errors, facts, policy

NOW = datetime(2026, 10, 24, 1, 0, tzinfo=timezone.utc)


# ───────────────────────────────────────────── fund_class / pool 键（Lead 裁决）
def test_fund_class_canonical_and_storage_mapping():
    assert policy.canonical_fund_class("CLIENT") == "CLIENT"
    assert policy.canonical_fund_class("client") == "CLIENT"
    assert policy.canonical_fund_class("customer") == "CLIENT"
    assert policy.canonical_fund_class("platform") == "PLATFORM"
    with pytest.raises(errors.BadRequest):
        policy.canonical_fund_class("hot")
    assert policy.legacy_fund_class("CLIENT") == "customer"
    assert policy.pool_key("polygon", "hot", "CLIENT") == "polygon:hot:CLIENT"
    assert policy.storage_pool_key("polygon:hot:CLIENT") == "polygon:hot:customer"
    assert policy.canonical_pool_id("polygon:warm:platform") == "polygon:warm:PLATFORM"
    assert policy.canonical_pool_id("broken") == "broken"


def test_pool_key_validation():
    assert policy.split_pool_key("polygon:hot:CLIENT") == ("polygon", "hot", "CLIENT")
    assert policy.split_pool_key("polygon:hot:customer") == ("polygon", "hot", "CLIENT")
    with pytest.raises(errors.BadRequest):
        policy.split_pool_key("polygon:hot")
    with pytest.raises(errors.ChainUnsupported):
        policy.split_pool_key("tron:hot:CLIENT")
    with pytest.raises(errors.BadRequest):
        policy.split_pool_key("polygon:cold:CLIENT")
    with pytest.raises(errors.BadRequest):
        policy.split_pool_key("polygon:hot:PLATFORM")      # 平台热池不建（K5）


# ───────────────────────────────────────────── 订单（INV-07 / INV-08）
def test_order_state_machine_and_terminal():
    assert policy.order_transition("created", "pending") == "pending"
    assert policy.order_transition("pending", "paid") == "paid"
    assert policy.order_transition("paid", "credited") == "credited"
    assert policy.order_is_terminal("credited")
    assert not policy.order_is_terminal("pending")
    for bad in (("created", "credited"), ("credited", "paid"), ("failed", "pending")):
        with pytest.raises(errors.Conflict):
            policy.order_transition(*bad)
    with pytest.raises(errors.Conflict):
        policy.order_transition("unknown", "paid")
    assert policy.can_cancel_order("created") and policy.can_cancel_order("pending")
    assert not policy.can_cancel_order("paid")


def test_amount_and_currency_validation():
    assert policy.validate_amount(1234) == 1234
    for bad in (0, -1, True, 1.5, "100", None):
        with pytest.raises(errors.BadRequest):
            policy.validate_amount(bad)
    assert policy.validate_currency("usd") == "USD"
    for bad in ("US", "USDD", "12A", "CHF", None):
        with pytest.raises(errors.BadRequest):
            policy.validate_currency(bad)


def test_provider_status_and_callback_checks():
    assert policy.provider_status("1") == "succeeded"
    assert policy.provider_status(0) == "pending"
    assert policy.provider_status("6") == "closed"
    with pytest.raises(errors.BadRequest):
        policy.provider_status("99")
    policy.check_callback_amount(order_status="created", order_amount_minor=100,
                                 paid_minor=100, credited_minor=0)
    policy.check_callback_amount(order_status="pending", order_amount_minor=100,
                                 paid_minor=100, credited_minor=0)
    with pytest.raises(errors.AmountMismatch):
        policy.check_callback_amount(order_status="pending", order_amount_minor=100,
                                     paid_minor=99, credited_minor=0)
    with pytest.raises(errors.Conflict):
        policy.check_callback_amount(order_status="failed", order_amount_minor=100,
                                     paid_minor=100, credited_minor=0)
    assert policy.is_duplicate_callback(100, 100)
    assert not policy.is_duplicate_callback(0, 100)


# ───────────────────────────────────────────── 钱包与池（INV-01…INV-06）
def test_wallet_transitions_and_switch_state():
    assert policy.wallet_transition("provisioning", "active") == "active"
    assert policy.wallet_transition("active", "draining") == "draining"
    assert policy.wallet_transition("frozen", "retired") == "retired"
    assert policy.wallet_transition("active", "frozen") == "frozen"
    with pytest.raises(errors.Conflict):
        policy.wallet_transition("retired", "active")
    with pytest.raises(errors.Conflict):
        policy.wallet_transition("bogus", "active")
    assert policy.switch_transition("standby", "in_service") == "in_service"
    assert policy.switch_transition("in_service", "switching_out") == "switching_out"
    with pytest.raises(errors.Conflict):
        policy.switch_transition("draining", "in_service")
    with pytest.raises(errors.Conflict):
        policy.switch_transition("bogus", "in_service")


def test_ready_depth_and_selection():
    ready = {"wallet_id": "w1", "status": "active", "gas_ok": True, "cap_minor": 1000,
             "balance_minor": 100, "switch_state": "in_service", "activated_at": NOW}
    no_gas = {"wallet_id": "w2", "status": "active", "gas_ok": False, "cap_minor": 1000,
              "balance_minor": 0, "switch_state": "standby", "activated_at": NOW}
    provisioning = {"wallet_id": "w3", "status": "provisioning", "gas_ok": False,
                    "balance_minor": 0}
    assert policy.wallet_ready(ready) and not policy.wallet_ready(no_gas)
    assert policy.depth([ready, no_gas, provisioning]) == {
        "depth_ready": 1, "depth_available": 2, "in_service": 1}
    assert policy.select_switch_wallet([ready, no_gas])["wallet_id"] == "w1"
    assert policy.select_switch_wallet([no_gas]) is None


def test_cap_plan_invariants():
    cap = policy.cap_plan(pool_cap_minor=facts.POOL_CAP_MINOR, in_service_count=8)
    assert cap * 8 <= facts.POOL_CAP_MINOR
    assert cap >= facts.WALLET_CAP_FLOOR_MINOR
    assert policy.cap_plan(pool_cap_minor=200_000, in_service_count=2) == 100_000
    assert policy.cap_plan(pool_cap_minor=facts.POOL_CAP_MINOR, in_service_count=1,
                           forecast_5d_minor=500_000) == 500_000
    with pytest.raises(errors.Conflict):
        policy.cap_plan(pool_cap_minor=100_000, in_service_count=2)


def test_forecast_capacity_and_provision_trigger():
    assert policy.forecast_daily([], 14) == 0
    assert policy.forecast_daily([100, 200, 300], 2) == 250
    assert policy.forecast_daily([100, 200], 0) == 150
    assert policy.target_capacity(1000) == 1000 * 7 * 2
    assert policy.should_provision(depth_available=2, min_spare=3, projected_utilization_pct=0)
    assert not policy.should_provision(depth_available=3, min_spare=3,
                                       projected_utilization_pct=10)
    assert policy.should_provision(depth_available=3, min_spare=3,
                                   projected_utilization_pct=61)
    assert not policy.should_provision(depth_available=0, min_spare=3,
                                       projected_utilization_pct=0, auto_expand=False)
    assert policy.next_max_active(8) == 12
    assert policy.next_max_active(18) == 20
    assert policy.next_max_active(3) == 7


def test_switch_and_pool_empty_plan():
    assert policy.switch_needed(balance_minor=70, cap_minor=100)
    assert not policy.switch_needed(balance_minor=69, cap_minor=100)
    assert policy.switch_needed(balance_minor=1, cap_minor=0)
    plan = policy.pool_empty_plan(wallets=[
        {"wallet_id": "a", "status": "active", "balance_minor": 500},
        {"wallet_id": "b", "status": "active", "balance_minor": 100},
    ])
    assert plan["stop_collection"] is False and plan["expand_required"] is True
    assert plan["spread_to"] == ["b", "a"]


def test_sweep_amount_rules():
    assert policy.sweep_amount(balance_minor=90, cap_minor=100, gas_ok=True) == 0
    assert policy.sweep_amount(balance_minor=150, cap_minor=100, gas_ok=True) == 50
    assert policy.sweep_amount(balance_minor=90, cap_minor=100, gas_ok=True,
                               dust_minor=1) == 89
    assert policy.sweep_amount(balance_minor=50, cap_minor=100, gas_ok=True) == 0
    assert policy.sweep_amount(balance_minor=90, cap_minor=100, gas_ok=False) == 0
    assert policy.sweep_amount(balance_minor=90, cap_minor=100, gas_ok=True,
                               gas_reserve_pol=9) == 0


def test_retire_four_steps():
    assert policy.retire_step(status="active", step="drain", balance_minor=0, in_flight=0,
                              last_switched_at=None, now=NOW) == "draining"
    with pytest.raises(errors.Conflict):
        policy.retire_step(status="active", step="retire", balance_minor=0, in_flight=0,
                           last_switched_at=None, now=NOW)
    with pytest.raises(errors.BadRequest):
        policy.retire_step(status="active", step="bogus", balance_minor=0, in_flight=0,
                           last_switched_at=None, now=NOW)
    with pytest.raises(errors.Conflict):
        policy.retire_step(status="draining", step="zero", balance_minor=5, in_flight=0,
                           last_switched_at=NOW - timedelta(days=2), now=NOW)
    with pytest.raises(errors.Conflict):
        policy.retire_step(status="draining", step="zero", balance_minor=0, in_flight=1,
                           last_switched_at=NOW - timedelta(days=2), now=NOW)
    with pytest.raises(errors.Conflict):
        policy.retire_step(status="draining", step="zero", balance_minor=0, in_flight=0,
                           last_switched_at=NOW - timedelta(hours=1), now=NOW)
    assert policy.retire_step(status="draining", step="zero", balance_minor=0, in_flight=0,
                              last_switched_at=NOW - timedelta(days=2), now=NOW) == "zero"
    assert policy.retire_step(status="frozen", step="retire", balance_minor=0, in_flight=0,
                              last_switched_at=None, now=NOW) == "retired"
    assert policy.retire_required_attestation("retire")
    assert not policy.retire_required_attestation("drain")


def test_descriptors_and_merkle():
    descriptors = policy.descriptors_for_batch(
        pool_id="polygon:hot:CLIENT", wallet_ids=["w1", "w2"],
        addresses=["0x" + "a" * 40, "0x" + "b" * 40], signer_set_ref="signers:test")
    assert len(descriptors) == 2 and descriptors[0]["address"].startswith("0x")
    assert policy.descriptor_merkle_root(descriptors) == policy.descriptor_merkle_root(
        list(reversed(descriptors)))
    assert len(policy.descriptor_merkle_root([])) == 64
    with pytest.raises(errors.BadRequest):
        policy.descriptors_for_batch(pool_id="polygon:hot:CLIENT", wallet_ids=["w1"],
                                     addresses=[], signer_set_ref="s")
    policy.assert_no_transfer_instructions({"pool_id": "polygon:hot:CLIENT"})
    with pytest.raises(errors.BadRequest):
        policy.assert_no_transfer_instructions({"to_address": "0xabc"})


# ───────────────────────────────────────────── 出款 / 签名 / gas（INV-10 / INV-14）
def test_payout_classification_and_totals():
    carried = policy.classify_payout_item(gross_minor=5, fee_minor=8)
    assert carried["status"] == "carried" and carried["net_minor"] == 0
    tiny = policy.classify_payout_item(gross_minor=1_000, fee_minor=0)
    assert tiny["status"] == "carried"
    normal = policy.classify_payout_item(gross_minor=5_000, fee_minor=100)
    assert normal == {"status": "pending", "gross_minor": 5_000, "fee_minor": 100,
                      "net_minor": 4_900}
    with pytest.raises(errors.BadRequest):
        policy.classify_payout_item(gross_minor=-1, fee_minor=0)
    totals = policy.payout_totals([normal, carried])
    assert totals == {"total_gross_minor": 5_000, "total_fee_minor": 100,
                      "total_net_minor": 4_900, "item_count": 1}
    assert policy.items_hash([normal]) == policy.items_hash([normal])
    assert policy.items_hash([]) == policy.items_hash([])
    assert policy.payout_min_item(1_000) and not policy.payout_min_item(999)
    assert policy.large_payout_delayed(600, 1000)
    assert not policy.large_payout_delayed(500, 1000)
    assert not policy.large_payout_delayed(10**9, None)


def test_payout_transitions_sod_attestation_window():
    assert policy.payout_transition("draft", "prepared") == "prepared"
    assert policy.payout_transition("checked", "signed") == "signed"
    assert policy.payout_transition("broadcast", "settled") == "settled"
    with pytest.raises(errors.Conflict):
        policy.payout_transition("draft", "settled")
    with pytest.raises(errors.Conflict):
        policy.payout_transition("bogus", "draft")
    with pytest.raises(errors.Conflict):
        policy.ensure_separation("maker", "maker")
    policy.ensure_separation("maker", "checker")
    with pytest.raises(errors.AttestationMissing):
        policy.ensure_attestation(attestation_ref=None, valid=True)
    with pytest.raises(errors.AttestationMissing):
        policy.ensure_attestation(attestation_ref="att-1", valid=False)
    policy.ensure_attestation(attestation_ref="att-1", valid=True)
    assert policy.approval_window_open(checked_at=NOW - timedelta(minutes=5), now=NOW)
    assert not policy.approval_window_open(checked_at=NOW - timedelta(minutes=31), now=NOW)
    assert not policy.approval_window_open(checked_at=None, now=NOW)


def test_intent_ttl_and_gas():
    assert policy.intent_ttl_seconds("PAYOUT") == facts.SIGNING_TTL_S
    assert policy.intent_ttl_seconds("WALLET_PROVISION") == facts.WALLET_PROVISION_SIGNING_TTL_S
    expires = policy.intent_expires_at("PAYOUT", NOW)
    assert (expires - NOW).total_seconds() == facts.SIGNING_TTL_S
    policy.check_intent_alive("PAYOUT", NOW, expires, NOW + timedelta(minutes=5))
    with pytest.raises(errors.Conflict):
        policy.check_intent_alive("PAYOUT", NOW, expires, NOW + timedelta(minutes=31))
    with pytest.raises(errors.Conflict):
        policy.check_intent_alive("PAYOUT", NOW, expires + timedelta(minutes=5), NOW)
    assert policy.normalize_gas_mode("internal") == "INTERNAL"
    assert policy.normalize_gas_mode("EXTERNAL", "PAYER") == "EXTERNAL_PAYER"
    assert policy.normalize_gas_mode("EXTERNAL", "PLATFORM") == "EXTERNAL_PLATFORM"
    assert policy.normalize_gas_mode("unknown", None) == "INTERNAL"


class _Cfg:
    gas_mode = "EXTERNAL_PLATFORM"
    gas_bearer = "PLATFORM"
    policy_version = "m08-pool-v1"


def test_gas_snapshot_is_batch_frozen():
    snapshot = policy.gas_snapshot(_Cfg())
    assert snapshot == {"gas_mode": "EXTERNAL_PLATFORM", "gas_bearer": "PLATFORM",
                        "policy_version": "m08-pool-v1"}
    _Cfg.gas_mode = "INTERNAL"
    assert snapshot["gas_mode"] == "EXTERNAL_PLATFORM"


# ───────────────────────────────────────────── 签名六事件（INV-10）
def test_signing_stage_order_and_complete():
    assert [policy.event_stage(name) for name in facts.SIGNING_EVENTS] == list(range(6))
    with pytest.raises(errors.BadRequest):
        policy.event_stage("bogus")
    policy.ensure_stage_order(None, "requested")
    with pytest.raises(errors.Conflict):
        policy.ensure_stage_order(None, "signed")
    policy.ensure_stage_order("requested", "presented")
    with pytest.raises(errors.Conflict):
        policy.ensure_stage_order("verified", "signed")
    complete = [
        {"event": "signed", "signer_type": "owner"},
        {"event": "verified", "signer_type": "company"},
        {"event": "co_signed", "signer_type": "reviewer"},
    ]
    assert policy.signing_complete(complete)
    assert not policy.signing_complete(complete[:2])
    assert not policy.signing_complete(complete[1:])
    assert policy.signing_transition("pending", "signed") == "signed"
    with pytest.raises(errors.Conflict):
        policy.signing_transition("signed", "pending")


# ───────────────────────────────────────────── 退款（INV-12）
def test_refund_window_route_and_amounts():
    deadline = policy.refund_deadline(NOW)
    assert (deadline - NOW).days == facts.REFUND_WINDOW_DAYS
    policy.check_refund_window(deadline, NOW)
    with pytest.raises(errors.Conflict):
        policy.check_refund_window(deadline, deadline + timedelta(seconds=1))
    policy.check_original_route("psp:mock:txn-1", "PSP:mock:txn-1")
    with pytest.raises(errors.Conflict):
        policy.check_original_route("psp:mock:txn-1", "psp:mock:txn-2")
    with pytest.raises(errors.BadRequest):
        policy.check_original_route("", "psp:mock:txn-1")
    assert policy.remaining_refundable(paid_minor=1000, refunded_minor=200,
                                       consumed_minor=100) == 700
    assert policy.remaining_refundable(paid_minor=100, refunded_minor=200,
                                       consumed_minor=0) == 0
    assert policy.refund_transition("requested", "approved") == "approved"
    with pytest.raises(errors.Conflict):
        policy.refund_transition("succeeded", "failed")
    with pytest.raises(errors.Conflict):
        policy.refund_transition("bogus", "approved")
    assert policy.approval_cooldown_ready(NOW - timedelta(hours=1), NOW)
    assert not policy.approval_cooldown_ready(NOW + timedelta(hours=1), NOW)
    with pytest.raises(errors.Conflict):
        policy.ensure_dual_control("acct-1", "acct-1")
    policy.ensure_dual_control("acct-1", "fin-officer")


# ───────────────────────────────────────────── 白名单（INV-13）
def test_address_whitelist_rules():
    cooldown = policy.address_cooldown_until(NOW)
    assert (cooldown - NOW).total_seconds() == facts.ADDRESS_COOLDOWN_H * 3600
    policy.check_first_transfer(10_000)
    with pytest.raises(errors.PayeeNotEligible):
        policy.check_first_transfer(10_001)
    with pytest.raises(errors.Conflict):
        policy.check_address_change_allowed(changed_at=NOW - timedelta(hours=1),
                                            next_payout_at=None, now=NOW)
    with pytest.raises(errors.Conflict):
        policy.check_address_change_allowed(changed_at=NOW - timedelta(days=2),
                                            next_payout_at=NOW + timedelta(days=3), now=NOW)
    policy.check_address_change_allowed(changed_at=NOW - timedelta(days=2),
                                        next_payout_at=NOW + timedelta(days=30), now=NOW)
    good = {"status": "whitelisted", "cooldown_until": NOW - timedelta(days=1),
            "risk_level": "low"}
    assert policy.address_eligible(good, now=NOW) == (True, None)
    assert policy.address_eligible({"status": "pending"}, now=NOW) == (
        False, "address_not_whitelisted")
    assert policy.address_eligible({"status": "whitelisted", "cooldown_until": NOW +
                                    timedelta(hours=1)}, now=NOW)[1] == "address_cooldown"
    assert policy.address_eligible({"status": "whitelisted",
                                    "cooldown_until": NOW - timedelta(days=1),
                                    "risk_level": "high"}, now=NOW)[1] == \
        "address_risk_rejected"
    policy.check_payee_eligible(good, now=NOW)
    with pytest.raises(errors.PayeeNotEligible):
        policy.check_payee_eligible(None, now=NOW)
    with pytest.raises(errors.AddressRiskRejected):
        policy.check_payee_eligible({"status": "whitelisted",
                                     "cooldown_until": NOW - timedelta(days=1),
                                     "risk_level": "high"}, now=NOW)


def test_utilization_pct():
    assert policy.utilization_pct(balance_minor=70, cap_minor=100) == 70
    assert policy.utilization_pct(balance_minor=1, cap_minor=0) == 100
