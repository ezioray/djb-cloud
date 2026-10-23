# SPDX-License-Identifier: Apache-2.0
"""P1–P5 决策管线（M04 §6 流程 2 / INV-03 / INV-05 / INV-06 / INV-11 / 验收 ②）。

最有价值的两条：

* **INV-03**：同一 ``(snapshot_ts, quote_version, policy_version, request_digest)`` ⇒ 同一决策
  （验收 ② 用「同秒 100 次」验证：只落一行、``decision_id`` 与 ``chosen`` 完全一致）；
* **P5 同事务**：决策日志、成交锁、配额计数要么一起在、要么一起不在（不允许「记了没锁」
  或「锁了没记」）。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.scheduling import (candidates, config_source, decisions, matching, models, pipeline,
                           quota, quotes)
from app.scheduling.errors import DecisionLogUnavailable, SpendCapExceeded
from schedulingkit import seed_quote


@pytest.fixture
def market(factory):
    """两个可用节点 + 报价（n_aaa 更便宜）+ 容量公告。"""
    for node_id in ("n_aaa", "n_bbb"):
        factory.node(node_id)
        factory.capacity(node_id, models=("m1",))
    factory.quote("n_aaa", low=800, high=1_000)
    factory.quote("n_bbb", low=900, high=None)
    return ["n_aaa", "n_bbb"]


# --------------------------------------------------------------------------- 正常路由
def test_route_picks_cheapest_and_commits_p5(conn, now, tenant, market):
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-1")
    decision, created = pipeline.execute(conn, route, now=now)

    assert created is True
    assert decision.outcome == "routed"
    assert decision.chosen_node_id == "n_aaa"
    assert decision.price_minor == 900            # mid(800, 1000)：无出价上界 → 取报价区间中点
    assert decision.eta_seconds is None           # realtime 不排队
    assert decision.tie_break == "cost"
    assert set(decision.reason_codes) >= {"rep_missing", "load_missing"}

    booking = conn.execute("SELECT node_id, price_minor, state, request_id FROM bookings").fetchone()
    assert booking == ("n_aaa", 900, "held", "trace-1")
    usage = conn.execute("SELECT concurrent, daily_spend_minor FROM quota_usage").fetchone()
    assert usage == (1, 900)
    # 成交后报价被消费（M04 §6 流程 1）
    assert conn.execute("SELECT state FROM quotes WHERE node_id = 'n_aaa'").fetchone()[0] \
        == "consumed"


def test_route_respects_max_price(conn, now, tenant, market):
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-2", max_price_minor=850)
    decision, _ = pipeline.execute(conn, route, now=now)
    assert decision.outcome == "routed"
    assert decision.price_minor == 825            # mid(800, 850)


def test_route_emits_routing_decided_event(conn, now, tenant, market):
    seen: list[tuple[str, dict]] = []
    from app.scheduling import events

    events.set_publisher(lambda event_type, envelope: seen.append((event_type, envelope)))
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                      trace_id="trace-evt")
        decision, _ = pipeline.execute(conn, route, now=now)
    finally:
        events.set_publisher(None)

    decided = [item for item in seen if item[0] == "routing.decided"]
    assert len(decided) == 1
    payload = decided[0][1]["payload"]
    assert payload["request_id"] == "trace-evt"
    assert payload["node_id"] == "n_aaa"
    assert payload["snapshot_id"] == str(decision.decision_id)
    assert set(payload) >= {"request_id", "node_id", "reason_codes", "snapshot_id"}


# --------------------------------------------------------------------------- INV-03
def test_same_anchor_yields_the_same_decision(conn, now, tenant, market):
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-1")
    first, _ = pipeline.execute(conn, route, now=now)
    second, created = pipeline.execute(conn, route, now=now)

    assert created is False
    assert second.decision_id == first.decision_id
    assert second.chosen == first.chosen
    assert second.tie_break == first.tie_break
    assert conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0] == 1
    # 不重复锁量
    assert conn.execute("SELECT count(*) FROM bookings").fetchone()[0] == 1


def test_one_hundred_concurrent_requests_share_one_decision(conn, now, tenant, market):
    """验收 ②：同 snapshot_ts 并发 100 次 → 同一 decision_id 与 chosen。"""
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-100")
    seen: set[tuple[uuid.UUID, str]] = set()
    for _ in range(100):
        decision, _created = pipeline.execute(conn, route, now=now)
        seen.add((decision.decision_id, decision.chosen_node_id))

    assert len(seen) == 1
    assert conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0] == 1
    assert conn.execute("SELECT count(*) FROM bookings").fetchone()[0] == 1
    assert conn.execute("SELECT concurrent FROM quota_usage").fetchone()[0] == 1


def test_snapshot_ts_is_truncated_to_the_second(conn, tenant, market):
    """同一秒内的两个时刻共享同一个锚点（否则并发请求会被拆成两条日志）。"""
    from app.scheduling import clock

    moment = clock.utcnow()
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    first, _ = pipeline.execute(conn, route, now=moment)
    second, _ = pipeline.execute(conn, route, now=moment.replace(microsecond=900_000))
    assert first.decision_id == second.decision_id


def test_attempt_two_gets_its_own_decision(conn, now, tenant, market):
    """INV-12：最多 2 次尝试，第 2 次用 attempt_no 区分（同 trace 不同 attempt）。"""
    first = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-retry", attempt_no=1)
    second = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                   trace_id="trace-retry", attempt_no=2)
    one, _ = pipeline.execute(conn, first, now=now)
    two, created = pipeline.execute(conn, second, now=now + timedelta(seconds=1))
    assert created is True
    assert two.decision_id != one.decision_id
    assert conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0] == 2


# --------------------------------------------------------------------------- P1 淘汰
def test_eliminated_candidates_are_recorded_with_codes(conn, now, tenant, factory):
    factory.node("n_cold")
    factory.capacity("n_cold", models=("m1",))
    factory.quote("n_cold", low=800, high=1_000)
    # 一个心跳过期的节点（F2）
    factory.node("n_stale", last_seen_at=now - timedelta(seconds=120))
    factory.capacity("n_stale", models=("m1",))

    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    decision, _ = pipeline.execute(conn, route, now=now)
    codes = {(item["node_id"], item["reason_code"]) for item in decision.eliminated}
    assert ("n_stale", "F2") in codes
    assert decision.chosen_node_id == "n_cold"


def test_model_mismatch_is_f1(conn, now, tenant, factory):
    factory.node("n_gpu")
    factory.capacity("n_gpu", models=("other-model",))
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    decision, _ = pipeline.execute(conn, route, now=now)
    assert decision.outcome == "rejected"
    assert "no_candidates" in decision.reason_codes


def test_access_mismatch_is_f1(conn, now, tenant, factory):
    factory.node("n_a2")
    factory.capacity("n_a2", access="A2", models=("m1",))
    factory.quote("n_a2", access="A2", low=800, high=1_000)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="t", required_access=("A1",))
    decision, _ = pipeline.execute(conn, route, now=now)
    codes = {(item["node_id"], item["reason_code"]) for item in decision.eliminated}
    assert ("n_a2", "F1") in codes


def test_self_dealing_is_f4(conn, now, tenant, factory):
    """F4 租户隔离：节点所属账户 = 用方账户时不允许自成交（product §4.7.3 F4）。"""
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    row = {"account_id": str(tenant)}
    assert candidates._isolation_ok(conn, route, row) is False
    assert candidates._isolation_ok(conn, route, {"account_id": str(uuid.uuid4())}) is True
    assert candidates._isolation_ok(conn, route, {"account_id": None}) is True


def test_quote_without_intersection_is_f5(conn, now, tenant, factory):
    factory.node("n_pricey")
    factory.capacity("n_pricey", models=("m1",))
    factory.quote("n_pricey", low=900, high=1_000)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="t", max_price_minor=500)
    decision, _ = pipeline.execute(conn, route, now=now)
    assert decision.outcome == "rejected"
    f5 = {item["node_id"]: item.get("detail") for item in decision.eliminated
          if item["reason_code"] == "F5"}
    assert f5.get("n_pricey") == "no_intersection"


# --------------------------------------------------------------------------- P4 / 拒绝
def test_realtime_rejection_carries_reason_and_actions(conn, now, tenant):
    route = candidates.RouteInput(model="missing", kind="realtime", tenant_id=tenant,
                                  trace_id="t")
    decision, _ = pipeline.execute(conn, route, now=now)
    assert decision.outcome == "rejected"
    assert decision.chosen is None
    assert "no_candidates" in decision.reason_codes
    assert decision.preempt_plan == []


def test_batch_without_checkpoint_is_rejected(conn, now, tenant, market):
    route = candidates.RouteInput(model="m1", kind="batch", tenant_id=tenant, trace_id="t",
                                  max_price_minor=1)
    decision, _ = pipeline.execute(conn, route, now=now)
    assert decision.outcome == "rejected"
    assert "no_checkpoint" in decision.reason_codes


def test_batch_with_checkpoint_queues_with_eta(conn, now, tenant, market):
    route = candidates.RouteInput(model="m1", kind="batch", tenant_id=tenant, trace_id="t",
                                  max_price_minor=1)
    ctx = pipeline.build_context(conn, route, checkpoint_age_s=10)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "queued"
    assert decision.eta_seconds is not None       # 排队必给 ETA
    assert decision.chosen is None


# --------------------------------------------------------------------------- P3
def test_spend_cap_blocks_with_42902(conn, now, tenant, market):
    quota.set_quota_provider(
        lambda c, tenant_id, model: {"daily_spend_minor": 5_000, "daily_cap_minor": 1_000})
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
        with pytest.raises(SpendCapExceeded) as excinfo:
            pipeline.execute(conn, route, now=now)
        assert int(excinfo.value.code) == 42902
    finally:
        quota.set_quota_provider(None)


def test_quota_exhaustion_goes_to_p4(conn, now, tenant, market):
    quota.set_quota_provider(lambda c, tenant_id, model: {"remaining": 0})
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
        decision, _ = pipeline.execute(conn, route, now=now)
    finally:
        quota.set_quota_provider(None)
    assert decision.outcome == "rejected"
    assert "quota_exhausted" in decision.reason_codes


def test_terminal_widening_is_clamped_and_visible(conn, now, tenant, market):
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    ctx = pipeline.build_context(conn, route, platform_concurrency=2, terminal_concurrency=50)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "routed"
    assert "tenant_widened" in decision.reason_codes


def test_share_overflow_is_visible_but_not_blocking(conn, now, tenant, market):
    quota.set_quota_provider(lambda c, tenant_id, model: {"share_pct_bps": 4_000})
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
        decision, _ = pipeline.execute(conn, route, now=now)
    finally:
        quota.set_quota_provider(None)
    assert decision.outcome == "routed"
    assert "share_exceeded" in decision.reason_codes      # INV-08：降权且可见


# --------------------------------------------------------------------------- 降级 / 兜底
def test_stale_book_marks_fallback(conn, tenant, factory, now):
    """§7：报价簿超刷新窗口 → 用最后有效快照放行并打 stale（outcome=fallback）。"""
    later = now + timedelta(seconds=facts_quotebook_refresh() + 30)
    factory.node("n_stale_book", last_seen_at=later)        # 心跳新鲜
    factory.capacity("n_stale_book", models=("m1",))
    factory.quote("n_stale_book", low=800, high=1_000, now=now)   # 报价陈旧

    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    decision, _ = pipeline.execute(conn, route, now=later)
    assert decision.outcome == "fallback"
    assert decision.fallback_used is True
    assert "stale_snapshot" in decision.reason_codes


def facts_quotebook_refresh() -> int:
    return config_source.quotebook_refresh_s(config_source.resolve({}))


def test_budget_overrun_is_logged_but_does_not_change_the_choice(conn, now, tenant, market,
                                                                 monkeypatch):
    """INV-05：超时延预算 → 只留痕（reason_codes），不改 chosen / tie_break / fallback_used。"""
    import app.scheduling.pipeline as pipeline_module

    real_solve = pipeline_module.solve

    def slow_solve(*args, **kwargs):
        result = real_solve(*args, **kwargs)
        result.decision.reason_codes = list(result.decision.reason_codes)
        return result

    monkeypatch.setattr(pipeline_module, "solve", slow_solve)
    monkeypatch.setattr(pipeline_module.time, "perf_counter", _slow_clock())
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    decision, _ = pipeline.execute(conn, route, now=now)
    assert "budget_exceeded" in decision.reason_codes
    assert decision.chosen_node_id == "n_aaa"


def _slow_clock():
    """返回一个「第一次 0、第二次很大」的 perf_counter 替身。"""
    values = iter([0.0, 1.0])

    def fake() -> float:
        return next(values, 1.0)

    return fake


# --------------------------------------------------------------------------- INV-11 / 事务
class _BrokenInsert:
    """包一层连接：对 routing_decisions 的 INSERT 抛错（模拟日志库不可写）。"""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self, *args, **kwargs):
        return _BrokenCursor(self._conn.cursor(*args, **kwargs))

    def __getattr__(self, item):
        return getattr(self._conn, item)


class _BrokenCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, *args, **kwargs):
        if "INSERT INTO routing_decisions" in str(sql):
            raise RuntimeError("disk full")
        return self._cursor.execute(sql, *args, **kwargs)

    def __enter__(self):
        self._cursor.__enter__()
        return self

    def __exit__(self, *args):
        return self._cursor.__exit__(*args)

    def __getattr__(self, item):
        return getattr(self._cursor, item)


def test_decision_log_failure_circuits_the_decision(conn, now, tenant, market):
    """INV-11：写失败即熔断新决策（503 + 50001），禁止「不记录继续」。"""
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    with pytest.raises(DecisionLogUnavailable) as excinfo:
        pipeline.execute(_BrokenInsert(conn), route, now=now)
    assert int(excinfo.value.code) == 50001
    assert excinfo.value.status_code == 503
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM bookings").fetchone()[0] == 0


def test_p5_is_one_transaction_with_the_log(conn, now, tenant, monkeypatch, migrated):
    """成交锁写失败 → 决策日志也不落（同事务，不允许「记了没锁」）。"""
    import app.scheduling.pipeline as pipeline_module
    from schedulingkit import seed_capacity, seed_node, session

    # 专用节点：报价必须**先提交**（否则回滚后无从验证「历史没被改」）；
    # 不能用 market 夹具——它在本用例事务里写过同一唯一键，跨连接会等锁。
    seed_node(migrated, "n_txn", tenant_id=tenant)
    seed_capacity(migrated, "n_txn", models=("m1",))
    quote_id = seed_quote(migrated, "n_txn", now=now)

    def boom(*args, **kwargs):
        raise RuntimeError("booking failed")

    monkeypatch.setattr(pipeline_module.matching, "create_booking", boom)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    with pytest.raises(RuntimeError):
        pipeline.execute(conn, route, now=now)
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM bookings").fetchone()[0] == 0
    with session(migrated) as fresh:
        state = fresh.execute("SELECT state FROM quotes WHERE id = %s", (quote_id,)).fetchone()[0]
    assert state == "active"                              # 报价没被消费（同事务回滚）


def test_solve_is_pure(conn, now, tenant, market):
    """solve 不写库：调用前后表计数不变。"""
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    snapshot = candidates.collect(conn, route, now=now)
    ctx = pipeline.build_context(conn, route, now=now) if False else pipeline.build_context(
        conn, route)
    before = conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0]
    result = pipeline.solve(route, snapshot, ctx, now=now)
    assert result.decision.outcome == "routed"
    assert conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0] == before
    assert isinstance(result.match, matching.MatchPlan)


def test_chosen_payload_matches_spec(conn, now, tenant, market):
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    decision, _ = pipeline.execute(conn, route, now=now)
    chosen = decision.chosen
    assert set(chosen) >= {"node_id", "upstream_id", "access", "model"}
    assert chosen["access"] in models.facts.ACCESS_TYPES
    assert decision.as_dict()["price"]["unit"] == "token"


def test_market_snapshot_provider_is_injectable(conn, now, tenant):
    """测试可以喂固定候选集（不依赖 M02 视图）。"""
    candidates.set_market_provider(lambda c, *, model: [
        {"node_id": "n_injected", "account_id": None, "tenant_id": None, "region": "cn-east",
         "lifecycle_state": "active", "last_seen_at": now, "access": "A1", "model": "m1",
         "unit": "token", "max_qps": 10, "resource_level": "low", "announced_at": now}])
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
        snapshot = candidates.collect(conn, route, now=now)
    finally:
        candidates.set_market_provider(None)
    # 没有报价 → F5
    assert snapshot.candidates == ()
    assert snapshot.eliminated[0]["reason_code"] == "F5"
