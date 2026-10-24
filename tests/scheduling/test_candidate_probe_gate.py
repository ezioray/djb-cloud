# SPDX-License-Identifier: AGPL-3.0-or-later
"""候选集上游验证门控（C9b「调度只认已验证上游」）。

口径：``_view_rows`` 的 SQL 多一个 ``v_supply_upstream_verified`` join——
候选必须命中同 ``(node_id, access, model)`` 且 ``verified_at >= now - probe_freshness_s``
的已验证上游。未命中的节点**根本不进候选集**（SQL 层过滤，不产生额外淘汰码），
``probe_freshness_s=None`` 仅用于兼容测试（默认 900 s，见 ``facts.CANDIDATE_PROBE_FRESH_S``）。

夹具约定：``migrated`` 是**模块级** schema（同模块用例共享），所以每个用例用自己的
唯一节点 id，断言只针对自己的节点——不假设库是干净的。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from schedulingkit import seed_capacity, seed_node, seed_quote, seed_upstream

from app.scheduling import candidates, facts


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _route(tenant):
    return candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                 trace_id="trace-gate")


def _seed_market(schema, tenant, node_id, now, **capacity_kwargs):
    seed_node(schema, node_id, tenant_id=tenant, last_seen_at=now)
    seed_capacity(schema, node_id, models=("m1",), announced_at=now, **capacity_kwargs)
    seed_quote(schema, node_id, now=now)


def _ids(snapshot) -> list[str]:
    return [item.node_id for item in snapshot.candidates]


def _drops(snapshot, node_id) -> list[dict]:
    return [item for item in snapshot.eliminated if item["node_id"] == node_id]


# --------------------------------------------------------------------------- 正例
def test_verified_and_fresh_enters_candidates(conn, now, tenant, migrated):
    node_id = _uid("n_ok")
    _seed_market(migrated, tenant, node_id, now)

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert _ids(snapshot).count(node_id) == 1
    mine = next(item for item in snapshot.candidates if item.node_id == node_id)
    assert mine.max_qps == 20


def test_multiple_verified_upstreams_do_not_multiply_candidates(conn, now, tenant, migrated):
    """同 (node, access, model) 两条 verified 上游（换端点重复申报）只出一条候选。"""
    node_id = _uid("n_dup")
    _seed_market(migrated, tenant, node_id, now)
    seed_upstream(migrated, node_id, access="A1", models=("m1",),
                  base_url="http://127.0.0.1:9/a1/dup")

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert _ids(snapshot).count(node_id) == 1
    assert _drops(snapshot, node_id) == []


# --------------------------------------------------------------------------- 负例
def test_unverified_upstream_never_enters_candidates(conn, now, tenant, migrated):
    node_id = _uid("n_declared")
    _seed_market(migrated, tenant, node_id, now, verified=False)   # 只申报未验证

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id not in _ids(snapshot)
    assert _drops(snapshot, node_id) == []                  # 门控在 SQL 层，不是 F 码


def test_stale_verification_never_enters_candidates(conn, now, tenant, migrated):
    node_id = _uid("n_stale")
    _seed_market(migrated, tenant, node_id, now, verified=True,
                 verified_at=now - timedelta(seconds=facts.CANDIDATE_PROBE_FRESH_S + 60))

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id not in _ids(snapshot)


def test_verification_boundary_is_inclusive(conn, now, tenant, migrated):
    node_id = _uid("n_edge")
    _seed_market(migrated, tenant, node_id, now, verified=True,
                 verified_at=now - timedelta(seconds=facts.CANDIDATE_PROBE_FRESH_S))

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id in _ids(snapshot)


def test_model_outside_upstream_models_never_enters_candidates(conn, now, tenant, migrated):
    """上游 verified 但只申报了 m2，公告的 m1 不算数。"""
    node_id = _uid("n_model")
    _seed_market(migrated, tenant, node_id, now, verified=False)
    seed_upstream(migrated, node_id, access="A1", models=("m2",))

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id not in _ids(snapshot)


# --------------------------------------------------------------------------- 兼容开关
def test_probe_freshness_none_disables_the_gate_for_compat(conn, now, tenant, migrated):
    """``probe_freshness_s=None`` = 不过滤（仅为兼容既有用例；生产默认 900 s）。"""
    node_id = _uid("n_compat")
    _seed_market(migrated, tenant, node_id, now, verified=False)

    gated = candidates.collect(conn, _route(tenant), now=now)
    compat = candidates.collect(conn, _route(tenant), now=now, probe_freshness_s=None)

    assert node_id not in _ids(gated)
    assert node_id in _ids(compat)


def test_default_probe_freshness_is_900s():
    assert facts.CANDIDATE_PROBE_FRESH_S == 900
    assert facts.UPSTREAM_VERIFIED_VIEW == "v_supply_upstream_verified"


# --------------------------------------------------------------------------- 与其它 P1 逻辑共存
def test_gate_and_heartbeat_freshness_coexist(conn, now, tenant, migrated):
    """门控不替换 F2：已验证上游在，但心跳过期 → 仍然 F2 淘汰（有淘汰码）。"""
    node_id = _uid("n_offline")
    seed_node(migrated, node_id, tenant_id=tenant,
              last_seen_at=now - timedelta(seconds=facts.CANDIDATE_FRESHNESS_S + 30))
    seed_capacity(migrated, node_id, models=("m1",), announced_at=now)
    seed_quote(migrated, node_id, now=now)

    snapshot = candidates.collect(conn, _route(tenant), now=now)

    assert node_id not in _ids(snapshot)
    assert [item["reason_code"] for item in _drops(snapshot, node_id)] == ["F2"]
