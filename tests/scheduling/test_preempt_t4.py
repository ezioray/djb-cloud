# SPDX-License-Identifier: Apache-2.0
"""T4 抢占执行与预算（INV-09 / INV-10 / §4.7.3 P4）。

两个新能力：
* 预算从**决策日志**数（日志只追加 → 可复算，不建第二套计数表）；
* 抢占成立时真的把请求落到「被让路那个节点的位置」（不再是只排队）。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.scheduling import candidates, decisions, facts, models, pipeline, preempt, quota


def _victim(node_id: str, *, request_id: str = "req-batch-1", age: int = 5) -> dict:
    return {"node_id": node_id, "request_id": request_id, "tier": "batch",
            "checkpoint_age_s": age, "started_at": "2026-10-23T00:00:00"}


def _routed_decision(now, *, node_id: str, preempt_plan=None) -> models.Decision:
    digest = uuid.uuid4().hex + uuid.uuid4().hex          # 每条一行，避免撞四元锚点
    return models.Decision(
        decision_id=decisions.decision_id(now, 1, "000000000000", digest),
        trace_id=f"trace-{uuid.uuid4().hex[:8]}", attempt_no=1, snapshot_ts=now,
        quote_version=1, policy_version="000000000000", request_digest=digest,
        chosen={"node_id": node_id, "upstream_id": "", "access": "A1", "model": "m1",
                "unit": "token"},
        tie_break="cost", outcome="routed", price_minor=800,
        preempt_plan=preempt_plan or [], decided_at=now)


# --------------------------------------------------------------------------- INV-10 预算
def test_used_budget_counts_from_the_decision_log(conn, now):
    """日志里 preempt_plan 出现该节点的次数 = 该节点本小时的抢占次数。"""
    assert preempt.used_budget(conn, node_id="n1", now=now) == 0
    decisions.record(conn, _routed_decision(now, node_id="n1",
                                            preempt_plan=[{"node_id": "n1"}]))
    decisions.record(conn, _routed_decision(now, node_id="n1",
                                            preempt_plan=[{"node_id": "n1"}]))
    decisions.record(conn, _routed_decision(now, node_id="n2",
                                            preempt_plan=[{"node_id": "n2"}]))
    assert preempt.used_budget(conn, node_id="n1", now=now) == 2
    assert preempt.used_budget(conn, node_id="n2", now=now) == 1
    # 窗口外的不算
    later = now + timedelta(hours=2)
    assert preempt.used_budget(conn, node_id="n1", now=later) == 0


def test_budget_map_filters_exhausted_nodes():
    outcome = preempt.evaluate(tier="realtime", preempt_enabled=True,
                               victims=[_victim("n1")],
                               budget_limit=6, budget_map={"n1": 6})
    assert outcome.outcome == "rejected"
    assert outcome.reason_codes == ("preempt_budget_exhausted",)


# --------------------------------------------------------------------------- 抢占真的落地
def test_preemption_routes_to_the_victims_node(conn, now, tenant, factory):
    """P3 因配额挡住全部候选时：开关打开 + 有合法让路对象 → 直接路由到该节点。"""
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",), max_qps=10)
    factory.quote("n_aaa", low=800, high=1_000)

    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-preempt")
    ctx = pipeline.RouteContext(policy={}, quota_snapshot={"remaining": 0},
                                victims=(_victim("n_aaa"),), preempt_enabled=True)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)

    assert decision.outcome == "routed"
    assert decision.chosen_node_id == "n_aaa"
    assert decision.preempt_plan and decision.preempt_plan[0]["request_id"] == "req-batch-1"
    assert decision.eta_seconds == facts.PREEMPT_GRACEFUL_S
    assert decision.price_minor == 900                   # mid(800, 1000)，价格仍按 INV-02
    # 决策落库 + 成交锁一样都不少（P5 同事务）
    assert conn.execute("SELECT count(*) FROM bookings").fetchone()[0] == 1


def test_preemption_switch_off_keeps_the_request_out(conn, now, tenant, factory):
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",), max_qps=10)
    factory.quote("n_aaa", low=800, high=1_000)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    ctx = pipeline.RouteContext(policy={}, quota_snapshot={"remaining": 0},
                                victims=(_victim("n_aaa"),), preempt_enabled=False)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "rejected"
    assert decision.preempt_plan == []
    assert "preempt_disabled" in decision.reason_codes


def test_preemption_requires_a_checkpoint(conn, now, tenant, factory):
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",), max_qps=10)
    factory.quote("n_aaa", low=800, high=1_000)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    ctx = pipeline.RouteContext(policy={}, quota_snapshot={"remaining": 0},
                                victims=(_victim("n_aaa", age=600),),   # 检查点太旧
                                preempt_enabled=True)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "rejected"
    assert decision.preempt_plan == []


def test_execute_fills_the_budget_from_the_log(conn, now, tenant, factory, monkeypatch):
    """execute 会按候选节点回填本小时已用预算（超过上限 → 不再抢占）。"""
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",), max_qps=10)
    factory.quote("n_aaa", low=800, high=1_000)
    for _ in range(facts.PREEMPT_BUDGET_PER_H):
        decisions.record(conn, _routed_decision(now, node_id="n_aaa",
                                                preempt_plan=[{"node_id": "n_aaa"}]))

    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    ctx = pipeline.RouteContext(policy={}, quota_snapshot={"remaining": 0},
                                victims=(_victim("n_aaa"),), preempt_enabled=True)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "rejected"
    assert "preempt_budget_exhausted" in decision.reason_codes


def test_queue_eta_is_always_given_for_batch(conn, now, tenant, factory):
    """§4.7.3 P4：无合法对象 → 排队（**必给 ETA**）。"""
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",), max_qps=10)
    factory.quote("n_aaa", low=800, high=1_000)
    route = candidates.RouteInput(model="m1", kind="batch", tenant_id=tenant, trace_id="t",
                                  max_price_minor=1)
    ctx = pipeline.RouteContext(policy={}, checkpoint_age_s=5)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "queued"
    assert decision.eta_seconds and decision.eta_seconds > 0


def test_backpressure_rejects_batch_at_95_percent(conn, now, tenant):
    route = candidates.RouteInput(model="m1", kind="batch", tenant_id=tenant, trace_id="t")
    ctx = pipeline.RouteContext(policy={}, checkpoint_age_s=5, queue_level_pct=96)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "rejected"
    assert "queue_full" in decision.reason_codes


def test_realtime_is_still_served_at_95_percent(conn, now, tenant, factory):
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",), max_qps=10)
    factory.quote("n_aaa", low=800, high=1_000)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    ctx = pipeline.RouteContext(policy={}, queue_level_pct=96)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "routed"
