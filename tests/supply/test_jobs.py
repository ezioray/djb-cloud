# SPDX-License-Identifier: AGPL-3.0-or-later
"""内部 job（M02 §4.3 / §7）：心跳超时 → 派生 offline + 事件（每段离线只发一次）。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.supply import facts, jobs, models


def _heartbeat_at(conn, node_id, moment):
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET last_seen_at = %s, offline_announced_at = NULL "
                    "WHERE id = %s", (moment, node_id))


def _offline_events(conn, node_id):
    with conn.cursor() as cur:
        cur.execute("SELECT payload FROM supply_outbox WHERE aggregate_id = %s "
                    "AND type = 'node.state.changed' "
                    "AND payload->>'reason' = 'timeout' ORDER BY occurred_at", (node_id,))
        return [row["payload"] for row in models._rows(cur)]


def test_scan_announces_offline_once(conn, factory):
    node = factory.active_node()[0]
    _heartbeat_at(conn, node.id, factory.moment)
    later = factory.moment + timedelta(
        seconds=facts.OFFLINE_AFTER_CYCLES * facts.HEARTBEAT_INTERVAL_S + 1)

    first = jobs.scan_offline(conn, now=later)
    assert node.id in first["announced"]
    assert first["offline_after_seconds"] == 90
    assert len(_offline_events(conn, node.id)) == 1
    assert models.get_node(conn, node.id).offline_announced_at == later
    # 生命周期状态不变（离线是派生视图）
    assert models.get_node(conn, node.id).state == "active"

    second = jobs.scan_offline(conn, now=later + timedelta(seconds=60))
    assert second["announced"] == []
    assert len(_offline_events(conn, node.id)) == 1


def test_scan_skips_fresh_heartbeats(conn, factory):
    node = factory.active_node()[0]
    _heartbeat_at(conn, node.id, factory.moment)
    result = jobs.scan_offline(conn, now=factory.moment + timedelta(seconds=30))
    assert result["announced"] == []


def test_scan_skips_nodes_never_seen_and_non_active(conn, factory):
    pending = factory.register().node
    frozen = factory.active_node()[0]
    _heartbeat_at(conn, frozen.id, factory.moment)
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET state = 'frozen' WHERE id = %s", (frozen.id,))
    later = factory.moment + timedelta(seconds=600)
    result = jobs.scan_offline(conn, now=later)
    assert pending.id not in result["announced"]
    assert frozen.id not in result["announced"]


def test_next_heartbeat_clears_offline_marker(conn, factory):
    from app.supply import heartbeat

    node = factory.active_node()[0]
    _heartbeat_at(conn, node.id, factory.moment)
    later = factory.moment + timedelta(seconds=600)
    jobs.scan_offline(conn, now=later)
    assert models.get_node(conn, node.id).offline_announced_at == later

    heartbeat.pulse(conn, node=models.get_node(conn, node.id), protocol_version="1.0.0",
                    policy_version="0", now=later + timedelta(seconds=1))
    assert models.get_node(conn, node.id).offline_announced_at is None


def test_scan_rejects_bad_interval(conn):
    with pytest.raises(ValueError):
        jobs.scan_offline(conn, now=None, heartbeat_interval_s=0)


def test_presence_of_wraps_derive_presence(conn, factory):
    node = factory.active_node()[0]
    _heartbeat_at(conn, node.id, factory.moment)
    fresh = models.get_node(conn, node.id)
    assert jobs.presence_of(fresh, factory.moment) == "online"
    assert jobs.presence_of(fresh, factory.moment + timedelta(seconds=60)) == "stale"
    assert jobs.presence_of(fresh, factory.moment + timedelta(seconds=120)) == "offline"

    pending = factory.register().node
    assert jobs.presence_of(pending, factory.moment) == "never"
