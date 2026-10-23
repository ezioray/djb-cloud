# SPDX-License-Identifier: Apache-2.0
"""审计策略（纯函数）：高危判定 / 高危字段 / 审批链非自批 —— append 与 verify 共用同一份。"""
from __future__ import annotations

import pytest

from app.audit import errors, facts, policy


def entry(**overrides):
    base = {
        "seq": 1,
        "entry_id": "018f4d0e-0000-7000-8000-000000000001",
        "ts": "2026-10-23T08:00:00.000000Z",
        "actor": "infra-seat",
        "actor_type": "agent",
        "role": "INFRA",
        "action": "read.report",
        "target": "nas/guard",
        "before": None,
        "after": None,
        "reason_code": None,
        "ticket": None,
        "evidence": None,
        "approval_chain": [],
        "status": "recorded",
        "alg": "hmac-sha256",
        "prev_hash": "GENESIS",
        "hash": "a" * 64,
    }
    base.update(overrides)
    return base


HIGH_RISK_ENTRY = entry(
    action="authorize.window", target="REL-0001", reason_code="R-OK", ticket="REL-0001",
    before={"window": "closed"}, after={"window": "open"}, status="approved",
    approval_chain=[{"actor": "lead", "decision": "propose"},
                    {"actor": "release-manager", "decision": "approve"}],
)


# --------------------------------------------------------------------------- 高危判定
@pytest.mark.parametrize("action", [
    "authorize.window", "release.image", "reverse.journal", "freeze.account",
    "migrate.schema", "settle.period", "export.data", "grant.role", "rollback.deploy",
    "revoke.key", "retire.node", "fee.update", "routefn.switch", "unfreeze.account",
    "window.authorize",
])
def test_action_prefixes_are_high_risk(action):
    assert policy.action_is_high_risk(action)


@pytest.mark.parametrize("action", ["read.report", "config.published", "user.login", "approve",
                                    "audit.list", "execute.release", ""])
def test_ordinary_actions_are_not_high_risk(action):
    """``execute.release`` 不在 policy.mjs 的高危前缀里：它由"复核类动作"规则管（必须有审批链）。"""
    assert not policy.action_is_high_risk(action)


def test_execute_release_needs_approval_chain_but_not_high_risk_fields():
    plain = entry(action="execute.release")
    assert policy.high_risk_gaps(plain) == []
    assert any("approval_chain" in problem for problem in policy.approval_problems(plain))
    with_reason = entry(action="execute.release", reason_code="R-OK")
    assert policy.is_high_risk(with_reason)          # 带 reason_code = 高危（更严方向）


def test_is_high_risk_via_reason_code_chain_or_status():
    assert policy.is_high_risk(entry(reason_code="R-USER-REQ"))
    assert policy.is_high_risk(entry(approval_chain=[{"actor": "a", "decision": "propose"}]))
    assert policy.is_high_risk(entry(status="pending_approval"))
    assert policy.is_high_risk(entry(status="approved"))
    assert not policy.is_high_risk(entry())


# --------------------------------------------------------------------------- 高危字段
def test_high_risk_entry_with_all_fields_has_no_gaps():
    assert policy.high_risk_gaps(HIGH_RISK_ENTRY) == []


@pytest.mark.parametrize("field", ["reason_code", "ticket", "before", "after"])
def test_missing_high_risk_field_is_reported(field):
    broken = dict(HIGH_RISK_ENTRY)
    broken[field] = None
    gaps = policy.high_risk_gaps(broken)
    assert gaps and field in gaps[0]


def test_before_after_must_be_objects():
    broken = dict(HIGH_RISK_ENTRY, before="closed")
    gaps = policy.high_risk_gaps(broken)
    assert any("JSON 对象" in gap for gap in gaps)


def test_placeholder_true_counts_as_missing():
    broken = dict(HIGH_RISK_ENTRY, ticket="true")
    assert policy.high_risk_gaps(broken)


# --------------------------------------------------------------------------- 审批链
def test_approval_chain_of_two_different_people_is_clean():
    assert policy.approval_problems(HIGH_RISK_ENTRY) == []


def test_self_approval_is_rejected():
    same = dict(HIGH_RISK_ENTRY, approval_chain=[
        {"actor": "lead", "decision": "propose"},
        {"actor": "lead", "decision": "approve"},
    ])
    problems = policy.approval_problems(same)
    assert any("自批自核" in problem for problem in problems)


def test_single_person_chain_is_rejected():
    single = dict(HIGH_RISK_ENTRY, approval_chain=[{"actor": "lead", "decision": "approve"}])
    assert any("至少两人" in problem for problem in policy.approval_problems(single))


def test_approve_and_execute_same_person_is_rejected():
    same = dict(HIGH_RISK_ENTRY, approval_chain=[
        {"actor": "lead", "decision": "propose"},
        {"actor": "release-manager", "decision": "approve"},
        {"actor": "release-manager", "decision": "execute"},
    ])
    assert any("复核与执行同人" in problem for problem in policy.approval_problems(same))


def test_approval_action_requires_chain_with_propose_and_approve():
    no_chain = entry(action="execute.release")
    assert any("approval_chain" in problem for problem in policy.approval_problems(no_chain))

    only_approve = entry(action="execute.release", approval_chain=[
        {"actor": "lead", "decision": "approve"},
        {"actor": "release-manager", "decision": "execute"},
    ])
    problems = policy.approval_problems(only_approve)
    assert any("缺 propose" in problem for problem in problems)


def test_malformed_chain_items_are_reported():
    broken = entry(approval_chain=["not-an-object", {"decision": "approve"},
                                   {"actor": "x", "decision": "maybe"}])
    problems = policy.approval_problems(broken)
    assert len(problems) >= 3
    assert any("必须是对象" in problem for problem in problems)
    assert any("缺 actor" in problem for problem in problems)
    assert any("decision 非法" in problem for problem in problems)


def test_chain_not_a_list_is_reported():
    assert policy.approval_problems(entry(approval_chain="nope"))


# --------------------------------------------------------------------------- 信封字段
def test_base_gaps_clean_entry_passes():
    assert policy.base_gaps(entry()) == []


@pytest.mark.parametrize("field", ["actor", "actor_type", "role", "action", "target",
                                   "status", "alg", "prev_hash", "hash"])
def test_base_gaps_reports_missing_field(field):
    broken = dict(entry())
    broken[field] = ""
    assert policy.base_gaps(broken)


def test_base_gaps_reports_bad_enums_and_shapes():
    assert policy.base_gaps(entry(actor_type="robot"))
    assert policy.base_gaps(entry(status="done"))
    assert policy.base_gaps(entry(hash="not-a-hash"))
    assert policy.base_gaps(entry(prev_hash="nope"))
    assert policy.base_gaps(entry(seq=None))
    assert policy.base_gaps(entry(ts=None))
    assert policy.base_gaps(entry(entry_id=None))


def test_entry_problems_aggregates_everything():
    broken = dict(HIGH_RISK_ENTRY, ticket=None, hash="bad")
    problems = policy.entry_problems(broken)
    assert any("hash" in problem for problem in problems)
    assert any("ticket" in problem for problem in problems)


# --------------------------------------------------------------------------- 写入前校验
def test_validate_new_entry_rejects_missing_high_risk_fields():
    with pytest.raises(errors.InvalidArgument) as excinfo:
        policy.validate_new_entry(dict(HIGH_RISK_ENTRY, ticket=None))
    assert excinfo.value.code == "40001"
    assert excinfo.value.reason == "high_risk_fields_missing"


def test_validate_new_entry_rejects_self_approval_with_conflict():
    same = dict(HIGH_RISK_ENTRY, approval_chain=[
        {"actor": "lead", "decision": "propose"},
        {"actor": "lead", "decision": "approve"},
    ])
    with pytest.raises(errors.Conflict) as excinfo:
        policy.validate_new_entry(same)
    assert excinfo.value.status_code == 409
    assert excinfo.value.reason == "approval_chain_invalid"


def test_validate_new_entry_accepts_low_risk_and_high_risk():
    policy.validate_new_entry(entry())
    policy.validate_new_entry(dict(HIGH_RISK_ENTRY, seq=None, entry_id=None, ts=None,
                                   alg=facts.ALG, prev_hash=facts.GENESIS, hash=None))
