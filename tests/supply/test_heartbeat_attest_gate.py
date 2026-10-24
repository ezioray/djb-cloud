# SPDX-License-Identifier: AGPL-3.0-or-later
"""心跳证明门控（C12）：DJB_ATTEST=1 时未达 L3 的模型公告 max_qps 置 0。"""
from __future__ import annotations

import uuid

from app.supply import heartbeat, models
from supplykit import seed_verified_upstream


def _entry(**overrides):
    entry = {"kind": "token_relay", "access": "A1", "model": "gpt-4o-mini",
             "max_qps": 4, "unit": "req"}
    entry.update(overrides)
    return entry


def _insert_attestation(conn, node_id, model, *, level="L3"):
    conn.execute(
        """INSERT INTO model_attestations
               (id, node_id, model, level, state, source, tokenizer_version, evidence_ref,
                verified_at, expires_at, created_at)
           VALUES (%s, %s, %s, %s, 'active', 'server_challenge', 'gateway.heuristic.v1',
                   'evt-1', now(), now() + interval '7 days', now())""",
        (str(uuid.uuid4()), node_id, model, level))


def _pulse(conn, node, moment):
    seed_verified_upstream(conn, node.id, access="A1", models=("gpt-4o-mini",),
                           verified_at=moment)
    return heartbeat.pulse(
        conn, node=node, protocol_version="1.0.0", policy_version=node.policy_version,
        capacity_entries=[_entry(max_qps=4)], now=moment, trace_id="trace-hb-attest")


def test_heartbeat_gates_unattested_model(conn, factory, monkeypatch):
    monkeypatch.setenv("DJB_ATTEST", "1")
    node = factory.active_node()[0]
    result = _pulse(conn, node, factory.moment)

    assert result.gated_count >= 1
    with conn.cursor() as cur:
        cur.execute("""SELECT capabilities FROM capacity_announcements
                        WHERE node_id = %s ORDER BY seq DESC LIMIT 1""", (node.id,))
        capabilities = models._rows(cur)[0]["capabilities"]
    assert capabilities[0]["max_qps"] == 0


def test_heartbeat_keeps_l3_attested_model(conn, factory, monkeypatch):
    monkeypatch.setenv("DJB_ATTEST", "1")
    node = factory.active_node()[0]
    _insert_attestation(conn, node.id, "gpt-4o-mini")
    result = _pulse(conn, node, factory.moment)

    assert result.accepted is True
    with conn.cursor() as cur:
        cur.execute("""SELECT capabilities FROM capacity_announcements
                        WHERE node_id = %s ORDER BY seq DESC LIMIT 1""", (node.id,))
        capabilities = models._rows(cur)[0]["capabilities"]
    assert capabilities[0]["max_qps"] == 4
