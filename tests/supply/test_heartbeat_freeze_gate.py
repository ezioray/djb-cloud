# SPDX-License-Identifier: AGPL-3.0-or-later
"""心跳冻结门控（C14）：M17 active hold 的模型公告 max_qps 置 0。"""
from __future__ import annotations

import uuid

from app.supply import heartbeat, models


def _entry(**overrides):
    entry = {"kind": "token_relay", "access": "A1", "model": "gpt-4o-mini",
             "max_qps": 4, "unit": "req"}
    entry.update(overrides)
    return entry


def _insert_hold(conn, node_id, model):
    conn.execute(
        """INSERT INTO supplier_integrity_holds
               (id, node_id, model, level, ratio_bp, base_amount_micro, frozen_amount_micro,
                state, reason, evidence_ref, created_at, version)
           VALUES (%s, %s, %s, 'I3', 10000, 1000, 1000, 'active', 'test', 'evt-1',
                   now(), 1)""",
        (str(uuid.uuid4()), node_id, model))


def test_heartbeat_gates_frozen_model(conn, factory):
    node = factory.active_node()[0]
    _insert_hold(conn, node.id, "gpt-4o-mini")
    from supplykit import seed_verified_upstream

    seed_verified_upstream(conn, node.id, access="A1", models=("gpt-4o-mini",),
                           verified_at=factory.moment)

    result = heartbeat.pulse(
        conn, node=node, protocol_version="1.0.0", policy_version=node.policy_version,
        capacity_entries=[_entry(max_qps=4)], now=factory.moment, trace_id="trace-hb-freeze")

    assert result.accepted is False          # 全部被置 0：公告受理但无正容量
    assert result.gated_count >= 1
    with conn.cursor() as cur:
        cur.execute("""SELECT capabilities FROM capacity_announcements
                        WHERE node_id = %s ORDER BY seq DESC LIMIT 1""", (node.id,))
        capabilities = models._rows(cur)[0]["capabilities"]
    assert capabilities[0]["max_qps"] == 0
