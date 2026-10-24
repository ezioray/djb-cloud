# SPDX-License-Identifier: AGPL-3.0-or-later
"""候选集证明门控（C12）：DJB_ATTEST=1 时只放行 L3+ 且未过期的 (node, model)。"""
from __future__ import annotations

import uuid

from schedulingkit import seed_capacity, seed_node, seed_quote

from app.scheduling import candidates


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _route(tenant):
    return candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                 trace_id="trace-attest")


def _seed_market(schema, tenant, node_id, now):
    seed_node(schema, node_id, tenant_id=tenant, last_seen_at=now)
    seed_capacity(schema, node_id, models=("m1",), announced_at=now)
    seed_quote(schema, node_id, now=now)


def _insert_attestation(conn, node_id, model, *, level="L3"):
    conn.execute(
        """INSERT INTO model_attestations
               (id, node_id, model, level, state, source, tokenizer_version, evidence_ref,
                verified_at, expires_at, created_at)
           VALUES (%s, %s, %s, %s, 'active', 'server_challenge', 'gateway.heuristic.v1',
                   'evt-1', now(), now() + interval '7 days', now())""",
        (str(uuid.uuid4()), node_id, model, level))


def test_without_attestation_candidate_excluded(conn, now, tenant, migrated, monkeypatch):
    monkeypatch.setenv("DJB_ATTEST", "1")
    node_id = _uid("n_noattest")
    _seed_market(migrated, tenant, node_id, now)

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id not in [item.node_id for item in snapshot.candidates]


def test_l3_attestation_candidate_included(conn, now, tenant, migrated, monkeypatch):
    monkeypatch.setenv("DJB_ATTEST", "1")
    node_id = _uid("n_attest")
    _seed_market(migrated, tenant, node_id, now)
    _insert_attestation(conn, node_id, "m1")

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id in [item.node_id for item in snapshot.candidates]
