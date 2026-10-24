# SPDX-License-Identifier: AGPL-3.0-or-later
"""复算回放（M04 §6 流程 3 / INV-03 / 验收 ⑤「同锚点重跑 1,000 次一致率 100%」）。

三条：**重算能复现 chosen/tie_break/fallback_used**、**差异能被抓出来**、**并发 1**。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.scheduling import candidates, decisions, models, pipeline, replay
from app.scheduling.errors import InvalidArgument, NotFound, ReplayBusy


@pytest.fixture
def routed(conn, now, tenant, factory):
    """跑一条真实决策，返回 (decision, route)。"""
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",))
    factory.node("n_bbb")
    factory.capacity("n_bbb", models=("m1",))
    factory.quote("n_aaa", low=800, high=1_000)
    factory.quote("n_bbb", low=900, high=None)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-replay")
    decision, _ = pipeline.execute(conn, route, now=now)
    assert decision.outcome == "routed"
    return decision, route


# --------------------------------------------------------------------------- 重算
def test_recompute_reproduces_the_decision(routed):
    decision, _route = routed
    recomputed = replay.recompute(decision)
    assert recomputed["chosen"] == decision.chosen_node_id
    assert recomputed["tie_break"] == decision.tie_break
    assert recomputed["fallback_used"] == decision.fallback_used
    comparison = replay.compare(decision, recomputed)
    assert comparison["consistent"] is True
    assert comparison["diffs"] == {}


def test_thousand_replays_are_identical(routed):
    """验收 ⑤：同锚点重跑 1,000 次，一致率 100%。"""
    decision, _route = routed
    results = set()
    for _ in range(1_000):
        recomputed = replay.recompute(decision)
        results.add((recomputed["chosen"], recomputed["tie_break"]))
    assert results == {(decision.chosen_node_id, decision.tie_break)}


def test_cost_breakdown_is_reproducible(routed):
    """成本分项也必须逐项一致（否则就是打分实现漂移，不是复算口径问题）。"""
    decision, _route = routed
    recomputed = replay.recompute(decision)
    assert recomputed["recorded_costs"]
    for node_id, cost in recomputed["recorded_costs"].items():
        assert recomputed["costs"][node_id] == cost


def test_recompute_detects_a_tampered_choice(routed):
    decision, _route = routed
    decision.chosen = {"node_id": "n_other", "upstream_id": "", "access": "A1",
                       "model": "m1", "unit": "token"}
    comparison = replay.compare(decision, replay.recompute(decision))
    assert comparison["consistent"] is False
    assert "chosen" in comparison["diffs"]
    assert comparison["diffs"]["chosen"]["recorded"] == "n_other"


def test_recompute_detects_a_tampered_cost(routed):
    decision, _route = routed
    decision.score_breakdown[0]["cost_micro"] += 1
    comparison = replay.compare(decision, replay.recompute(decision))
    assert comparison["consistent"] is False
    assert "cost_micro" in comparison["diffs"]


def test_recompute_flags_fallback_drift(routed):
    decision, _route = routed
    decision.fallback_used = not decision.fallback_used
    comparison = replay.compare(decision, replay.recompute(decision))
    assert "fallback_used" in comparison["diffs"]


def test_policy_drift_is_reported_but_not_counted_as_inconsistency(routed):
    decision, _route = routed
    decision.fallback_used = not decision.fallback_used
    comparison = replay.compare(decision, replay.recompute(decision), policy_drift=True)
    assert comparison["consistent"] is True
    assert comparison["policy_drift"] is True


def test_non_routed_decisions_are_skipped_but_counted(conn, now, tenant):
    route = candidates.RouteInput(model="missing", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-rejected")
    pipeline.execute(conn, route, now=now)
    report = replay.run(conn, from_ts=now - timedelta(minutes=1), to_ts=now + timedelta(minutes=1))
    assert report["total"] == 1
    assert report["consistent"] == 1
    assert report["diffs"] == []


def test_recompute_uses_recorded_lambda(routed):
    """重算取日志里记录的 λ，而不是当前配置（否则策略一改，历史决策全成假差异）。"""
    decision, _route = routed
    recorded_lambda = decision.score_breakdown[0]["lambda_micro"]
    recomputed = replay.recompute(decision, policy={"routing.latency_lambda": 9.0})
    assert recomputed["scores"][0].lambda_micro == recorded_lambda


def test_recompute_handles_empty_candidates(conn, now, tenant):
    """拒绝类决策（无候选）也要能复算（不炸）。"""
    route = candidates.RouteInput(model="missing", kind="realtime", tenant_id=tenant,
                                  trace_id="t-empty")
    decision, _ = pipeline.execute(conn, route, now=now)
    assert decision.candidates == []
    recomputed = replay.recompute(decision)
    assert recomputed["candidates"] == 0
    assert recomputed["chosen"] is None
    assert replay.compare(decision, recomputed)["consistent"] is True


# --------------------------------------------------------------------------- 作业 / 报告
def test_run_validates_the_window(conn, now):
    with pytest.raises(InvalidArgument):
        replay.run(conn, from_ts=now, to_ts=now)
    with pytest.raises(InvalidArgument):
        replay.run(conn, from_ts=now - timedelta(minutes=1), to_ts=now, limit=0)
    with pytest.raises(InvalidArgument):
        replay.run(conn, from_ts=now - timedelta(minutes=1), to_ts=now,
                   limit=replay.MAX_DECISIONS_PER_JOB + 1)


def test_run_reports_differences(conn, now, routed):
    """日志里的 chosen 与输入快照算出来的不一致 → 必须报出来（差异 ≠ 0 即 P0 候选）。"""
    decision, _route = routed
    tampered = models.Decision(
        decision_id=decisions.decision_id(now, decision.quote_version,
                                          decision.policy_version, "f" * 64),
        trace_id="trace-tampered", attempt_no=1, snapshot_ts=now,
        quote_version=decision.quote_version, policy_version=decision.policy_version,
        request_digest="f" * 64, candidates=decision.candidates,
        score_breakdown=decision.score_breakdown,
        chosen={"node_id": "n_bbb", "upstream_id": "", "access": "A1", "model": "m1",
                "unit": "token"},        # 输入里 n_aaa 更便宜 → 重算必定选 n_aaa
        tie_break="cost", outcome="routed", price_minor=1_000, decided_at=now)
    decisions.record(conn, tampered)

    report = replay.run(conn, from_ts=now - timedelta(minutes=1), to_ts=now + timedelta(minutes=1))
    assert report["total"] == 2
    assert report["inconsistent"] == 1
    assert report["diffs"][0]["diffs"]["chosen"] == {"recorded": "n_bbb",
                                                     "recomputed": "n_aaa"}


def test_start_creates_a_job_and_runs_it(conn, now, routed):
    store = replay.InMemoryJobStore()
    job = replay.start(conn, from_ts=now - timedelta(minutes=1), to_ts=now + timedelta(minutes=1),
                       now=now, store=store)
    assert job.state == "succeeded"
    assert job.decisions_total >= 1
    assert job.consistent == job.decisions_total
    assert store.get(job.job_id) is job
    payload = job.as_dict()
    assert set(payload) >= {"job_id", "state", "requested_at", "decisions_total"}


def test_job_store_is_injectable_and_resettable():
    """空 store 是 falsy（``__len__``），所以注入逻辑必须显式判 None。"""
    custom = replay.InMemoryJobStore()
    replay.set_store(custom)
    try:
        assert replay.current_store() is custom
    finally:
        replay.set_store(None)
    assert isinstance(replay.current_store(), replay.InMemoryJobStore)


def test_get_job_unknown_is_404():
    with pytest.raises(NotFound):
        replay.get_job(str(uuid.uuid4()), store=replay.InMemoryJobStore())


def test_replay_is_exclusive(migrated, conn, now, routed):
    """spec ReplayRequest：同一时刻只允许 1 个复算作业（409 + 40901）。"""
    from schedulingkit import connect

    replay.acquire(conn)                       # 当前事务持有锁
    second = connect(migrated, autocommit=False)
    try:
        with pytest.raises(ReplayBusy) as excinfo:
            replay.acquire(second)
        assert int(excinfo.value.code) == 40901
        assert excinfo.value.status_code == 409
    finally:
        second.rollback()
        second.close()
    conn.rollback()
    replay.acquire(conn)                       # 释放后可再抢


def test_replay_never_writes(routed, conn):
    """复算只读：跑一遍不改任何决策行。"""
    decision, _route = routed
    before = conn.execute("SELECT count(*), sum(price_minor) FROM routing_decisions").fetchone()
    replay.recompute(decision)
    replay.run(conn, from_ts=decision.decided_at - timedelta(minutes=1),
               to_ts=decision.decided_at + timedelta(minutes=1))
    after = conn.execute("SELECT count(*), sum(price_minor) FROM routing_decisions").fetchone()
    assert before == after
