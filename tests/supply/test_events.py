# SPDX-License-Identifier: Apache-2.0
"""事件生产（02-events §1 信封 / §3 业务键 / M02 §4.2）：4 个事件 + outbox 契约。"""
from __future__ import annotations

from datetime import timedelta

import pytest
import psycopg

from app.supply import facts


def _outbox(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT event_id, type, version, occurred_at, producer, aggregate_type, "
                    "aggregate_id, correlation_id, causation_id, trace_id, idempotency_key, "
                    "payload, published_at FROM supply_outbox ORDER BY occurred_at, type")
        from app.supply import models

        return models._rows(cur)


def test_unregistered_event_type_is_refused(conn):
    from app.supply import events

    with pytest.raises(ValueError):
        events.emit(conn, type="node.invented", aggregate_id="n_x", payload={},
                    trace_id="trace")


def test_node_registered_is_single_fact_per_node(conn, factory):
    """``node.registered`` 的幂等键是业务键：同一节点只允许一条（02-events §1）。"""
    from app.supply import events

    node = factory.register().node
    # pytest.raises 必须在 transaction() 之外：否则 psycopg 看不到异常，事务留在 aborted 态
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.transaction():
            events.node_registered(conn, node_id=node.id, account_id=None,
                                   protocols=["1.0.0"], region=None, trace_id="trace")


def test_four_event_payloads_carry_the_contract_keys(conn, factory):
    from app.supply import events

    node = factory.active_node()[0]
    occurred = factory.moment
    events.node_state_changed(conn, node_id=node.id, from_state="active", to_state="frozen",
                              reason="risk", trace_id="trace-1", occurred_at=occurred)
    events.node_upstream_changed(conn, node_id=node.id, upstream_type="A1",
                                 state="verified", trace_id="trace-2", occurred_at=occurred)
    events.capacity_announced(conn, node_id=node.id, models=["gpt-4o-mini"], gpu="rtx4070",
                              ram=64, expires_at=occurred + timedelta(seconds=60),
                              trace_id="trace-3", announced_at=occurred)

    rows = _outbox(conn)
    by_type = {row["type"]: row for row in rows}
    assert {"node.registered", "node.state.changed", "node.upstream.changed",
            "capacity.announced"} <= set(by_type)

    assert by_type["node.registered"]["payload"]["protocols"] == ["1.0.0"]
    assert set(by_type["node.state.changed"]["payload"]) == {"node_id", "from", "to", "reason"}
    assert set(by_type["node.upstream.changed"]["payload"]) == {
        "node_id", "upstream_type", "state"}
    capacity = by_type["capacity.announced"]["payload"]
    assert set(capacity) == {"node_id", "models", "gpu", "ram", "expires_at"}
    assert capacity["ram"] == 64


def test_envelope_fields_follow_the_contract(conn, factory):
    node = factory.register().node
    row = _outbox(conn)[0]
    assert row["producer"] == facts.EVENT_PRODUCER == "M02"
    assert row["aggregate_type"] == facts.EVENT_AGGREGATE_TYPE == "node"
    assert row["aggregate_id"] == node.id
    assert row["version"] == 1
    assert row["trace_id"] == "trace-test"
    assert row["published_at"] is None                    # 待投递
    assert row["idempotency_key"].startswith("node.registered:")
    assert str(row["event_id"]) != ""


def test_event_trace_id_is_mandatory_and_bounded(conn, factory):
    from app.supply import events

    node = factory.register().node
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            events.node_state_changed(conn, node_id=node.id, from_state="pending",
                                      to_state="pending", reason="x", trace_id="x" * 200)


def test_payload_never_contains_fingerprint_or_key(conn, factory):
    result = factory.register(hardware_fingerprint="fp-event-secret-0001")
    plaintext = result.client_key
    with conn.cursor() as cur:
        cur.execute("SELECT payload::text AS p FROM supply_outbox")
        from app.supply import models

        payloads = [row["p"] for row in models._rows(cur)]
    blob = "".join(payloads)
    assert "fp-event-secret" not in blob
    assert plaintext not in blob
