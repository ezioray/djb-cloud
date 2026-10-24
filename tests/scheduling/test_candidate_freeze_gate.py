# SPDX-License-Identifier: AGPL-3.0-or-later
"""候选集冻结门控（C14）：M17 active hold 的 (node, model) 不进候选。"""
from __future__ import annotations

import uuid

from schedulingkit import seed_capacity, seed_node, seed_quote

from app.scheduling import candidates


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _route(tenant):
    return candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                 trace_id="trace-freeze")


def _seed_market(schema, tenant, node_id, now):
    seed_node(schema, node_id, tenant_id=tenant, last_seen_at=now)
    seed_capacity(schema, node_id, models=("m1",), announced_at=now)
    seed_quote(schema, node_id, now=now)


def _insert_hold(conn, node_id, model, *, level="I2", state="active"):
    ratio = {"I0": 0, "I1": 5000, "I2": 8000, "I3": 10000, "I4": 10000}[level]
    base = 1000
    frozen = base * ratio // 10000
    conn.execute(
        """INSERT INTO supplier_integrity_holds
               (id, node_id, model, level, ratio_bp, base_amount_micro, frozen_amount_micro,
                state, reason, evidence_ref, created_at, expires_at, version)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'test', 'evt-1',
                   now(), CASE WHEN %s = 'I1' THEN now() + interval '7 days' ELSE NULL END, 1)""",
        (str(uuid.uuid4()), node_id, model, level, ratio, base, frozen, state, level))


def test_active_hold_excludes_candidate(conn, now, tenant, migrated):
    node_id = _uid("n_frozen")
    _seed_market(migrated, tenant, node_id, now)
    _insert_hold(conn, node_id, "m1")

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id not in [item.node_id for item in snapshot.candidates]
    assert [item for item in snapshot.eliminated if item["node_id"] == node_id] == []


def test_expired_hold_does_not_exclude_candidate(conn, now, tenant, migrated):
    node_id = _uid("n_released")
    _seed_market(migrated, tenant, node_id, now)
    _insert_hold(conn, node_id, "m1", state="expired")

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id in [item.node_id for item in snapshot.candidates]
