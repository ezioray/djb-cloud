# SPDX-License-Identifier: Apache-2.0
"""状态机（M02 §3）：权威层四态机 + 派生层在线判定。纯函数，无需 DB。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.supply import facts, state
from app.supply.errors import InvalidArgument, NodeStateForbidden

NOW = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- 枚举
def test_states_are_exactly_the_spec_enum():
    assert facts.NODE_STATES == ("pending", "active", "frozen", "retired")


def test_presence_is_derived_not_a_state():
    assert set(facts.PRESENCE_STATES) == {"online", "stale", "offline"}
    assert not set(facts.PRESENCE_STATES) & set(facts.NODE_STATES)


# --------------------------------------------------------------------------- 迁移表
@pytest.mark.parametrize("src,dst,expected", [
    ("pending", "active", True),
    ("pending", "frozen", False),
    ("pending", "retired", False),
    ("pending", "pending", False),
    ("active", "frozen", True),
    ("active", "retired", True),
    ("active", "pending", False),
    ("frozen", "active", True),
    ("frozen", "retired", True),
    ("frozen", "pending", False),
    ("retired", "active", False),
    ("retired", "frozen", False),
    ("retired", "pending", False),
])
def test_transition_matrix(src, dst, expected):
    assert state.can_transition(src, dst) is expected


def test_legal_targets_are_stable_and_ordered():
    assert state.legal_targets("pending") == ("active",)
    assert state.legal_targets("active") == ("frozen", "retired")
    assert state.legal_targets("frozen") == ("active", "retired")
    assert state.legal_targets("retired") == ()


def test_retired_is_irreversible():
    assert state.is_retired("retired") is True
    assert state.TRANSITIONS["retired"] == frozenset()
    for target in facts.NODE_STATES:
        assert state.can_transition("retired", target) is False


def test_unknown_state_is_not_a_transition():
    assert state.can_transition("ghost", "active") is False
    assert state.legal_targets("ghost") == ()


# --------------------------------------------------------------------------- 拒绝语义
def test_illegal_transition_raises_40305_with_context():
    with pytest.raises(NodeStateForbidden) as excinfo:
        state.require_transition("pending", "retired")
    err = excinfo.value
    assert err.code == "40305"
    assert err.status_code == 403
    assert err.details["state"] == "pending"
    assert err.details["allowed"] == ("active",)


def test_require_transition_rejects_unknown_state_as_40001():
    with pytest.raises(InvalidArgument):
        state.require_transition("ghost", "active")


def test_legal_transition_passes_silently():
    assert state.require_transition("pending", "active") is None


@pytest.mark.parametrize("node_state,expected", [
    ("pending", "await_review"),
    ("active", "heartbeat"),
    ("frozen", "read_only"),
    ("retired", "none"),
])
def test_allowed_actions_follow_the_state_table(node_state, expected):
    assert expected in state.allowed_actions(node_state)


def test_require_active_rejects_every_non_active_state_inv02():
    assert state.require_active("active", action="heartbeat") is None
    for node_state in ("pending", "frozen", "retired"):
        with pytest.raises(NodeStateForbidden) as excinfo:
            state.require_active(node_state, action="heartbeat")
        assert excinfo.value.code == "40305"
        assert excinfo.value.details["state"] == node_state
        assert "allowed_actions" in excinfo.value.details


def test_require_state_reports_required_state():
    with pytest.raises(NodeStateForbidden) as excinfo:
        state.require_state("pending", "active", action="bind")
    assert excinfo.value.details["required"] == "active"


# --------------------------------------------------------------------------- 派生层
def test_never_seen_is_never():
    assert state.derive_presence(None, NOW) == "never"
    assert state.derive_online(None, NOW) == "offline"


@pytest.mark.parametrize("age_seconds,expected", [
    (0, "online"),
    (facts.STALE_AFTER_S, "online"),                        # ≤ stale_after 仍算 online
    (facts.STALE_AFTER_S + 1, "stale"),
    (facts.OFFLINE_AFTER_CYCLES * facts.HEARTBEAT_INTERVAL_S, "stale"),   # ≤ 3 周期仍 stale
    (facts.OFFLINE_AFTER_CYCLES * facts.HEARTBEAT_INTERVAL_S + 1, "offline"),
])
def test_presence_thresholds(age_seconds, expected):
    seen = NOW - timedelta(seconds=age_seconds)
    assert state.derive_presence(seen, NOW) == expected
    assert state.derive_online(seen, NOW) == expected


def test_presence_uses_config_overrides():
    seen = NOW - timedelta(seconds=20)
    assert state.derive_presence(seen, NOW, heartbeat_interval_s=10,
                                 stale_after_s=15) == "stale"
    assert state.derive_presence(seen, NOW, heartbeat_interval_s=10,
                                 stale_after_s=30) == "online"


def test_presence_rejects_non_positive_thresholds():
    with pytest.raises(InvalidArgument):
        state.derive_presence(NOW, NOW, heartbeat_interval_s=0)
    with pytest.raises(InvalidArgument):
        state.derive_presence(NOW, NOW, stale_after_s=-1)


@pytest.mark.parametrize("node_state,last_seen_age,expected", [
    ("active", 0, True),
    ("active", facts.STALE_AFTER_S, True),
    ("active", facts.OFFLINE_AFTER_CYCLES * facts.HEARTBEAT_INTERVAL_S + 1, False),
    ("active", None, False),
    ("pending", 0, False),
    ("frozen", 0, False),
    ("retired", 0, False),
])
def test_routable_requires_active_and_online(node_state, last_seen_age, expected):
    seen = None if last_seen_age is None else NOW - timedelta(seconds=last_seen_age)
    assert state.routable(node_state, seen, NOW) is expected


def test_transitions_table_is_immutable_by_convention():
    """TRANSITIONS 只读：值必须是 frozenset（防止运行期被就地修改）。"""
    for targets in state.TRANSITIONS.values():
        assert isinstance(targets, frozenset)
