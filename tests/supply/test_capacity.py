# SPDX-License-Identifier: Apache-2.0
"""容量公告（M02 §3 / §6.2 / INV-07 / §8.2）：校验、seq 单调、过期与 0 容量过滤、快照视图。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from supplykit import session

from app.supply import capacity, facts, models
from app.supply.errors import InvalidArgument, NodeNotFound


def _entry(**overrides):
    entry = {"kind": "token_relay", "access": "A1", "model": "gpt-4o-mini",
             "max_qps": 8, "unit": "req", "ask_price": "0.0012", "gpu": "rtx4070",
             "ram_gb": 32}
    entry.update(overrides)
    return entry


# --------------------------------------------------------------------------- 校验
def test_normalize_accepts_full_entry():
    valid, ignored = capacity.normalize([_entry()])
    assert ignored == ()
    assert valid[0]["kind"] == "token_relay"
    assert valid[0]["max_qps"] == 8.0
    assert valid[0]["ask_price"] == "0.0012"
    assert valid[0]["ram_gb"] == 32.0


def test_unknown_kind_is_ignored_not_rejected():
    valid, ignored = capacity.normalize([_entry(kind="quantum_v9"), _entry()])
    assert len(valid) == 1
    assert ignored == ("quantum_v9",)


def test_duplicate_kind_model_keeps_last():
    valid, _ = capacity.normalize([_entry(max_qps=1), _entry(max_qps=9)])
    assert len(valid) == 1
    assert valid[0]["max_qps"] == 9.0


@pytest.mark.parametrize("overrides,field", [
    ({"kind": ""}, "capacity[0].kind"),
    ({"access": "Z9"}, "capacity[0].access"),
    ({"model": ""}, "capacity[0].model"),
    ({"unit": ""}, "capacity[0].unit"),
    ({"max_qps": -1}, "capacity[0].max_qps"),
    ({"max_qps": "8"}, "capacity[0].max_qps"),
    ({"max_qps": True}, "capacity[0].max_qps"),
    ({"ask_price": "cheap"}, "capacity[0].ask_price"),
    ({"ram_gb": -1}, "capacity[0].ram_gb"),
])
def test_normalize_rejects_bad_entries(overrides, field):
    with pytest.raises(InvalidArgument) as excinfo:
        capacity.normalize([_entry(**overrides)])
    assert excinfo.value.details["field"] == field


def test_normalize_rejects_missing_required_key():
    entry = _entry()
    entry.pop("model")
    with pytest.raises(InvalidArgument) as excinfo:
        capacity.normalize([entry])
    assert excinfo.value.details["field"] == "capacity[0].model"


def test_normalize_rejects_too_many_entries():
    entries = [_entry(model=f"m{i}") for i in range(facts.MAX_CAPABILITIES_PER_ANNOUNCEMENT + 1)]
    with pytest.raises(InvalidArgument) as excinfo:
        capacity.normalize(entries)
    assert excinfo.value.details["field"] == "capacity"


def test_normalize_rejects_non_array_and_non_object():
    with pytest.raises(InvalidArgument):
        capacity.normalize("nope")
    with pytest.raises(InvalidArgument):
        capacity.normalize(["nope"])


def test_normalize_none_is_empty():
    assert capacity.normalize(None) == ([], ())


# --------------------------------------------------------------------------- 落库与时序
def test_record_allocates_monotonic_seq(conn, factory):
    node = factory.active_node()[0]
    first = capacity.record(conn, node_id=node.id, entries=[_entry()], ttl_seconds=60,
                            now=factory.moment)
    second = capacity.record(conn, node_id=node.id, entries=[_entry()], ttl_seconds=60,
                             now=factory.moment)
    assert (first.seq, second.seq) == (1, 2)
    assert second.expires_at == factory.moment + timedelta(seconds=60)
    assert capacity.latest(conn, node.id).seq == 2
    assert models.get_node(conn, node.id).heartbeat_seq == 2


def test_zero_capacity_is_accepted_but_not_routable(conn, factory):
    node = factory.active_node()[0]
    announcement = capacity.record(conn, node_id=node.id,
                                   entries=[_entry(max_qps=0)], ttl_seconds=60,
                                   now=factory.moment)
    assert announcement.accepted is False
    assert capacity.snapshot(conn) == []          # 0 容量不进候选集（fixture 口径）


def test_next_seq_unknown_node(conn):
    with pytest.raises(NodeNotFound):
        capacity.next_seq(conn, "n_missing")


def test_snapshot_keeps_latest_seq_per_kind_model(conn, factory):
    node = factory.active_node()[0]
    capacity.record(conn, node_id=node.id,
                    entries=[_entry(max_qps=1), _entry(kind="gpu", model="gpt-4o", max_qps=2)],
                    ttl_seconds=60, now=factory.moment)
    capacity.record(conn, node_id=node.id, entries=[_entry(max_qps=7)], ttl_seconds=60,
                    now=factory.moment)

    rows = capacity.snapshot(conn)
    by_key = {(row["kind"], row["model"]): row for row in rows}
    assert by_key[("token_relay", "gpt-4o-mini")]["max_qps"] == 7     # 最新 seq 生效
    assert by_key[("gpu", "gpt-4o")]["max_qps"] == 2                  # 其它 kind 保留
    assert all(row["node_id"] == node.id for row in rows)


def test_expired_announcement_leaves_candidates_but_keeps_history(conn, factory):
    """INV-07：``now > expires_at`` 不进候选集，但历史行仍在（只追加）。"""
    from psycopg.types.json import Jsonb

    node = factory.active_node()[0]
    with conn.cursor() as cur:            # 直接插一条「已过期」的公告（视图用库内 now() 过滤）
        cur.execute(
            """INSERT INTO capacity_announcements
                   (node_id, seq, announced_at, expires_at, capabilities)
               VALUES (%s, 1, now() - interval '10 min', now() - interval '5 min', %s)""",
            (node.id, Jsonb([_entry()])))
    assert capacity.snapshot(conn) == []
    assert capacity.latest(conn, node.id) is not None     # 历史仍在


def test_frozen_node_drops_out_of_candidates(conn, factory):
    node = factory.active_node()[0]
    capacity.record(conn, node_id=node.id, entries=[_entry()], ttl_seconds=600,
                    now=factory.moment)
    assert len(capacity.snapshot(conn)) == 1
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET state = 'frozen' WHERE id = %s", (node.id,))
    assert capacity.snapshot(conn) == []           # INV-02：非 active 不进候选集
