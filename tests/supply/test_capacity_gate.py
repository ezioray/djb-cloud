# SPDX-License-Identifier: AGPL-3.0-or-later
"""容量公告门控（C9b「容量只认已验证上游」）。

口径（服务端不再相信客户端公告）：

* 公告条目来自 ``(access, model)`` 的上游必须 ``state='verified'``、
  ``verified_at >= now - facts.PROBE_FRESH_S``（默认 900 s）**且**该模型在上游 ``models`` 里；
* 不满足 → 该条目 ``max_qps`` 置 0，**条目与 seq 保留**（审计要能看出「报了多少 / 认了多少」），
  公告照落、响应 schema 不变，被置 0 的条数进 ``HeartbeatResult.gated_count``；
* 容量校验 / 归一化口径不变（``capacity.normalize`` 仍是唯一校验点）；
* ``max_qps=0`` 的既有语义不变：允许公告，但不接单、不发 ``capacity.announced``。
"""
from __future__ import annotations

import logging
from datetime import timedelta

import pytest

from supplykit import seed_verified_upstream

from app.supply import capacity, facts, heartbeat, models


def _entry(**overrides):
    entry = {"kind": "token_relay", "access": "A1", "model": "gpt-4o-mini",
             "max_qps": 6, "unit": "req"}
    entry.update(overrides)
    return entry


def _pulse(conn, node, moment, **overrides):
    params = {"protocol_version": "1.0.0", "policy_version": node.policy_version,
              "now": moment, "trace_id": "trace-gate"}
    params.update(overrides)
    return heartbeat.pulse(conn, node=node, **params)


def _capacity_events(conn, node_id):
    with conn.cursor() as cur:
        cur.execute("SELECT payload FROM supply_outbox WHERE aggregate_id = %s "
                    "AND type = 'capacity.announced' ORDER BY occurred_at", (node_id,))
        return [row["payload"] for row in models._rows(cur)]


def _capabilities(conn, node_id):
    with conn.cursor() as cur:
        cur.execute("SELECT capabilities FROM capacity_announcements WHERE node_id = %s "
                    "ORDER BY seq DESC LIMIT 1", (node_id,))
        return models._one(cur)["capabilities"]


# --------------------------------------------------------------------------- 正例
def test_verified_and_fresh_keeps_max_qps(conn, factory):
    node = factory.active_node()[0]
    seed_verified_upstream(conn, node.id, access="A1", models=("gpt-4o-mini",),
                           verified_at=factory.moment)

    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)])

    assert result.gated_count == 0
    assert result.accepted is True
    assert result.announcement is not None and result.announcement.seq == 1
    assert _capabilities(conn, node.id)[0]["max_qps"] == 6
    assert len(_capacity_events(conn, node.id)) == 1


def test_freshness_boundary_is_inclusive(conn, factory):
    """``verified_at == now - PROBE_FRESH_S`` 仍算新鲜（>= 而不是 >）。"""
    node = factory.active_node()[0]
    seed_verified_upstream(
        conn, node.id, models=("gpt-4o-mini",),
        verified_at=factory.moment - timedelta(seconds=facts.PROBE_FRESH_S))

    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=3)])
    assert result.gated_count == 0
    assert result.accepted is True


# --------------------------------------------------------------------------- 负例
def test_undeclared_upstream_is_gated(conn, factory):
    node = factory.active_node()[0]                       # 一个上游都没申报

    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)])

    assert result.gated_count == 1
    assert result.accepted is False
    assert result.announcement is not None               # 公告照落（seq 仍分配）
    assert _capabilities(conn, node.id) == [
        {"kind": "token_relay", "access": "A1", "model": "gpt-4o-mini",
         "max_qps": 0.0, "unit": "req", "ask_price": None, "resource_level": None,
         "gpu": None, "ram_gb": None}]
    assert _capacity_events(conn, node.id) == []          # 0 容量不发「有效公告」事件


@pytest.mark.parametrize("state", ["declared", "probing", "rejected"])
def test_unverified_upstream_states_are_gated(conn, factory, state):
    node = factory.active_node()[0]
    seed_verified_upstream(conn, node.id, models=("gpt-4o-mini",), state=state)

    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)])
    assert result.gated_count == 1
    assert result.accepted is False


def test_verified_but_stale_upstream_is_gated(conn, factory):
    node = factory.active_node()[0]
    seed_verified_upstream(
        conn, node.id, models=("gpt-4o-mini",),
        verified_at=factory.moment - timedelta(seconds=facts.PROBE_FRESH_S + 1))

    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)])
    assert result.gated_count == 1
    assert result.accepted is False


def test_verified_upstream_without_the_model_is_gated(conn, factory):
    node = factory.active_node()[0]
    seed_verified_upstream(conn, node.id, models=("gpt-4o",), verified_at=factory.moment)

    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)])
    assert result.gated_count == 1
    assert result.accepted is False


def test_gated_count_counts_only_gated_entries(conn, factory):
    """同批两条：一条有 verified 上游、一条没有 → 只置 0 后者，seq/条目都保留。"""
    node = factory.active_node()[0]
    seed_verified_upstream(conn, node.id, access="A1", models=("gpt-4o-mini",),
                           verified_at=factory.moment)

    result = _pulse(conn, node, factory.moment, capacity_entries=[
        _entry(max_qps=6),
        _entry(access="A2", model="gpt-4o", max_qps=9),
    ])

    assert result.gated_count == 1
    assert result.accepted is True                        # A1 仍有容量
    caps = {item["access"]: item for item in _capabilities(conn, node.id)}
    assert caps["A1"]["max_qps"] == 6
    assert caps["A2"]["max_qps"] == 0
    # 事件反映**公告内容**（被门控的条目也在公告里，只是 max_qps=0），不删条目；
    # M04 不从事件推断可用性，读 v_supply_capacity_latest（0 容量已被视图过滤）。
    events = _capacity_events(conn, node.id)
    assert len(events) == 1
    assert events[0]["models"] == ["gpt-4o", "gpt-4o-mini"]


def test_all_gated_announcements_keep_seq_and_history(conn, factory):
    """全被门控也不删公告、不回退 seq：第二拍 seq=2，`latest` 仍能看到 0 容量。"""
    node = factory.active_node()[0]
    first = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)])
    second = _pulse(conn, models.get_node(conn, node.id),
                    factory.moment + timedelta(seconds=30), capacity_entries=[_entry()])

    assert (first.announcement.seq, second.announcement.seq) == (1, 2)
    assert (first.gated_count, second.gated_count) == (1, 1)
    latest = capacity.latest(conn, node.id)
    assert latest is not None and latest.seq == 2
    assert latest.capabilities[0]["max_qps"] == 0
    assert capacity.snapshot(conn) == []                  # 0 容量不进 M04 候选视图
    assert models.get_node(conn, node.id).heartbeat_seq == 2


def test_zero_capacity_with_verified_upstream_keeps_existing_semantics(conn, factory):
    """``max_qps=0`` 本来就「可公告、不接单、不发事件」——门控不改变这条语义。"""
    node = factory.active_node()[0]
    seed_verified_upstream(conn, node.id, models=("gpt-4o-mini",), verified_at=factory.moment)

    result = _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=0)])
    assert result.gated_count == 0                         # 不是门控置 0 的
    assert result.accepted is False
    assert result.announcement is not None
    assert _capacity_events(conn, node.id) == []


# --------------------------------------------------------------------------- 留痕与口径
def test_gate_agrees_with_the_m04_readonly_view(conn, factory):
    """心跳门控（基表）与 ``v_supply_upstream_verified``（209 视图）口径必须一致。"""
    node = factory.active_node()[0]
    seed_verified_upstream(conn, node.id, access="A1", models=("gpt-4o-mini", "m-x"),
                           verified_at=factory.moment)
    seed_verified_upstream(conn, node.id, access="B", models=("gpt-4o-mini",), state="declared")

    with conn.cursor() as cur:
        cur.execute("SELECT access_type, model FROM v_supply_upstream_verified "
                    "WHERE node_id = %s ORDER BY access_type, model", (node.id,))
        view_pairs = {(row["access_type"], row["model"]) for row in models._rows(cur)}

    assert view_pairs == {("A1", "gpt-4o-mini"), ("A1", "m-x")}


def test_gate_logs_counts_only(conn, factory, caplog):
    """日志只记计数：不带模型名 / 端点（排障靠表与公告快照）。"""
    node = factory.active_node()[0]
    with caplog.at_level(logging.INFO, logger="djb.supply.heartbeat"):
        _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)])

    gated = [record for record in caplog.records if record.msg == "supply.capacity.gated"]
    assert len(gated) == 1
    assert gated[0].event == "capacity.gated"
    assert (gated[0].entries, gated[0].gated) == (1, 1)
    assert "gpt-4o-mini" not in gated[0].getMessage()


def test_response_payload_is_unchanged(conn, factory):
    """响应 schema 不变：``gated_count`` 是内部字段，不进 payload。"""
    node = factory.active_node()[0]
    payload = heartbeat.heartbeat_payload(
        _pulse(conn, node, factory.moment, capacity_entries=[_entry(max_qps=6)]))
    assert "gated_count" not in payload
    assert set(payload["announcement"]) == {"announcement_id", "seq", "announced_at",
                                            "expires_at", "accepted", "capabilities"}
