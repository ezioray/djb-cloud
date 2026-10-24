# SPDX-License-Identifier: AGPL-3.0-or-later
"""心跳（M02 §6.2 / INV-02 / §7 限流 / CR-5 runtime_state）。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.supply import facts, features, heartbeat, models
from app.supply.errors import (
    HeartbeatTooFast,
    InvalidArgument,
    NodeStateForbidden,
    ProtocolIncompatible,
)


def _entry(**overrides):
    entry = {"kind": "token_relay", "access": "A1", "model": "gpt-4o-mini",
             "max_qps": 4, "unit": "req"}
    entry.update(overrides)
    return entry


def _seed_verified_for(conn, node, entries, moment):
    """C9b 夹具：心跳公告只认「已验证且新鲜」的上游——按公告条目补种一条 verified 上游。

    本文件守的是心跳机制（限流 / seq / 事件 / 响应形状），不是门控本身；
    门控的正负例在 ``test_capacity_gate.py``。种上游用**同一事务连接**，随用例回滚。
    """
    from supplykit import seed_verified_upstream

    for entry in entries or ():
        if not isinstance(entry, dict) or entry.get("kind") not in facts.CAPACITY_KINDS:
            continue                                  # 未知 kind 本来就会被 normalize 丢掉
        seed_verified_upstream(conn, node.id, access=entry["access"],
                               models=(entry["model"],), verified_at=moment)


def _pulse(conn, node, moment, **overrides):
    _seed_verified_for(conn, node, overrides.get("capacity_entries"), moment)
    params = {"protocol_version": "1.0.0", "policy_version": node.policy_version,
              "now": moment, "trace_id": "trace-hb"}
    params.update(overrides)
    return heartbeat.pulse(conn, node=node, **params)


def _capacity_events(conn, node_id):
    with conn.cursor() as cur:
        cur.execute("SELECT payload FROM supply_outbox WHERE aggregate_id = %s "
                    "AND type = 'capacity.announced' ORDER BY occurred_at", (node_id,))
        return [row["payload"] for row in models._rows(cur)]


# --------------------------------------------------------------------------- 状态与协议
@pytest.mark.parametrize("state", ["pending", "frozen", "retired"])
def test_heartbeat_requires_active(conn, factory, state):
    node = factory.register().node
    if state != "pending":
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE nodes SET state = %s, retired_at = CASE WHEN %s = 'retired' "
                "THEN now() END WHERE id = %s", (state, state, node.id))
        node = models.get_node(conn, node.id)
    with pytest.raises(NodeStateForbidden) as excinfo:
        _pulse(conn, node, factory.moment)
    assert excinfo.value.code == "40305"
    assert excinfo.value.details["state"] == state


def test_heartbeat_rejects_incompatible_protocol(conn, factory):
    node = factory.active_node()[0]
    with pytest.raises(ProtocolIncompatible) as excinfo:
        _pulse(conn, node, factory.moment, protocol_version="2.0.0")
    assert excinfo.value.code == "42601"


def test_heartbeat_validates_load_shape(conn, factory):
    node = factory.active_node()[0]
    with pytest.raises(InvalidArgument) as excinfo:
        _pulse(conn, node, factory.moment, load={"inflight": -1})
    assert excinfo.value.details["field"] == "load.inflight"
    with pytest.raises(InvalidArgument):
        _pulse(conn, node, factory.moment + timedelta(seconds=30), load=[1, 2])


# --------------------------------------------------------------------------- 限流
def test_heartbeat_is_rate_limited_to_five_seconds(conn, factory):
    node = factory.active_node()[0]
    _pulse(conn, node, factory.moment)
    with pytest.raises(HeartbeatTooFast) as excinfo:
        _pulse(conn, models.get_node(conn, node.id), factory.moment + timedelta(seconds=3))
    assert excinfo.value.code == "42901"
    assert excinfo.value.status_code == 429
    assert excinfo.value.details["retry_after_s"] == 2

    _pulse(conn, models.get_node(conn, node.id), factory.moment + timedelta(seconds=5))


# --------------------------------------------------------------------------- 公告
def test_heartbeat_records_announcement_and_event(conn, factory):
    node = factory.active_node()[0]
    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)])

    assert result.accepted is True
    assert result.announcement is not None and result.announcement.seq == 1
    assert result.next_heartbeat_seconds == facts.HEARTBEAT_INTERVAL_S
    assert result.policy_updated is False

    events = _capacity_events(conn, node.id)
    assert len(events) == 1
    assert events[0]["models"] == ["gpt-4o-mini"]
    assert events[0]["expires_at"].endswith("Z") or "T" in events[0]["expires_at"]

    refreshed = models.get_node(conn, node.id)
    assert refreshed.last_seen_at == factory.moment
    assert refreshed.heartbeat_seq == 1


def test_heartbeat_without_capacity_records_nothing(conn, factory):
    node = factory.active_node()[0]
    result = _pulse(conn, node, factory.moment)
    assert result.announcement is None
    assert result.accepted is False
    assert _capacity_events(conn, node.id) == []


def test_zero_capacity_is_announced_but_not_accepted(conn, factory):
    node = factory.active_node()[0]
    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=0)])
    assert result.accepted is False
    assert result.announcement is not None            # 公告照落（历史）
    assert _capacity_events(conn, node.id) == []      # 但不发「有效公告」事件


def test_heartbeat_ignores_unknown_capacity_kind(conn, factory):
    node = factory.active_node()[0]
    result = _pulse(conn, node, factory.moment,
                    capacity_entries=[_entry(kind="quantum"), _entry(max_qps=2)])
    assert result.ignored_kinds == ("quantum",)
    assert result.accepted is True


def test_heartbeat_seq_increments_across_heartbeats(conn, factory):
    node = factory.active_node()[0]
    first = _pulse(conn, node, factory.moment, capacity_entries=[_entry()])
    second = _pulse(conn, models.get_node(conn, node.id),
                    factory.moment + timedelta(seconds=30), capacity_entries=[_entry()])
    assert (first.announcement.seq, second.announcement.seq) == (1, 2)


# --------------------------------------------------------------------------- policy_updated
def test_policy_updated_when_client_version_differs(conn, factory):
    node = factory.active_node()[0]
    result = _pulse(conn, node, factory.moment, policy_version="0")
    assert result.policy_updated is False            # 与节点当前一致
    stale = _pulse(conn, models.get_node(conn, node.id),
                   factory.moment + timedelta(seconds=30), policy_version="999")
    assert stale.policy_updated is True


# --------------------------------------------------------------------------- runtime_state（CR-5）
def test_runtime_state_ignored_while_switch_is_off(conn, factory):
    node = factory.active_node()[0]
    assert features.enabled(heartbeat.RUNTIME_STATE_SWITCH) is False
    result = _pulse(conn, node, factory.moment, runtime_state="yield_paused")
    assert result.runtime_state is None
    assert models.get_node(conn, node.id).runtime_state is None


def test_runtime_state_recorded_when_switch_is_on(conn, factory, monkeypatch):
    monkeypatch.setattr(features, "enabled", lambda name: name == heartbeat.RUNTIME_STATE_SWITCH)
    node = factory.active_node()[0]
    result = _pulse(conn, node, factory.moment, runtime_state=" Yield_Paused ")
    assert result.runtime_state == "yield_paused"
    assert models.get_node(conn, node.id).runtime_state == "yield_paused"

    unknown = _pulse(conn, models.get_node(conn, node.id),
                     factory.moment + timedelta(seconds=30), runtime_state="teleporting")
    assert unknown.runtime_state is None             # 未知值忽略不报错
    assert models.get_node(conn, node.id).runtime_state == "yield_paused"


# --------------------------------------------------------------------------- 负载回显
def test_payload_shape(conn, factory):
    node = factory.active_node()[0]
    payload = heartbeat.heartbeat_payload(
        _pulse(conn, node, factory.moment, capacity_entries=[_entry()]))
    assert set(payload) >= {"server_time", "protocol_version", "policy_version",
                            "next_heartbeat_seconds", "policy_updated"}
    assert payload["announcement"]["accepted"] is True
    assert payload["server_time"].endswith("Z")
    assert heartbeat.heartbeat_payload(_pulse(
        conn, models.get_node(conn, node.id), factory.moment + timedelta(seconds=30)
    )).get("announcement") is None
