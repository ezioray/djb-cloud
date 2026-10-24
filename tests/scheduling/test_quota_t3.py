# SPDX-License-Identifier: AGPL-3.0-or-later
"""T3 配额记账：占比（自有计数）/ 降权槽位 / 软停 / 等待 / 三窗口（M04 §4.7.3 P3 / INV-08）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.scheduling import candidates, facts, pipeline, quota


def test_share_bps_and_cap_slots():
    assert quota.share_bps(25, 100) == 2_500
    assert quota.share_bps(0, 0) == 0
    assert quota.share_bps(1, 3) == 3_333
    assert quota.share_cap_slots(100, 25) == 25
    assert quota.share_cap_slots(3, 25) == 1               # 至少 1 个槽位（防饿死）
    assert quota.share_cap_slots(None, 25) is None


def test_observed_share_reads_own_counters(conn, now, tenant, other_tenant):
    quota.reserve(conn, tenant_id=tenant, model="m1", now=now, units=3)
    quota.reserve(conn, tenant_id=other_tenant, model="m1", now=now, units=1)
    share, mine = quota.observed_share(conn, tenant_id=tenant, model="m1", now=now)
    assert (share, mine) == (7_500, 3)
    assert quota.model_concurrency(conn, model="m1", now=now) == {str(tenant): 3,
                                                                 str(other_tenant): 1}


def test_refresh_share_persists(conn, now, tenant, other_tenant):
    quota.reserve(conn, tenant_id=tenant, model="m1", now=now, units=1)
    quota.reserve(conn, tenant_id=other_tenant, model="m1", now=now, units=3)
    assert quota.refresh_share(conn, tenant_id=tenant, model="m1", now=now) == 2_500
    row = conn.execute("SELECT share_pct_bps, share_updated_at FROM quota_usage "
                       "WHERE tenant_id = %s", (tenant,)).fetchone()
    assert row == (2_500, now)


def test_pipeline_records_share_and_releases_wait(conn, now, tenant, factory):
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",))
    factory.quote("n_aaa", low=800, high=1_000)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    decision, _ = pipeline.execute(conn, route, now=now)
    assert decision.outcome == "routed"
    row = conn.execute("SELECT concurrent, share_pct_bps, wait_started_at FROM quota_usage"
                       " WHERE tenant_id = %s", (tenant,)).fetchone()
    assert row[0] == 1
    assert row[1] == 10_000              # 唯一租户 → 100%
    assert row[2] is None                # 成功之后不留等待起点


def test_pipeline_notes_rejection_and_freezes_when_switch_on(conn, now, tenant, factory):
    """§4.7.3 P3：约束全违反 + 开关打开 → 冻结该租户 60 s。"""
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",))
    factory.quote("n_aaa", low=800, high=1_000)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    # 裸上下文 = 手工给 P3 的配额快照（provider 不参与），便于钉死「配额触顶」这一条路径
    ctx = pipeline.RouteContext(policy={}, quota_snapshot={"remaining": 0},
                                soft_stop_enabled=True)
    decision, _ = pipeline.execute(conn, route, now=now, context=ctx)
    assert decision.outcome == "rejected"
    assert "quota_exhausted" in decision.reason_codes
    frozen = quota.frozen_until(conn, tenant_id=tenant, model="m1", now=now)
    assert frozen == now + timedelta(seconds=facts.QUOTA_FREEZE_S)
    assert quota.is_frozen(conn, tenant_id=tenant, model="m1", now=now) is True


def test_pipeline_only_notes_rejection_when_switch_off(conn, now, tenant, factory):
    factory.node("n_aaa")
    factory.capacity("n_aaa", models=("m1",))
    factory.quote("n_aaa", low=800, high=1_000)
    route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant, trace_id="t")
    ctx = pipeline.RouteContext(policy={}, quota_snapshot={"remaining": 0})   # 开关默认关闭
    pipeline.execute(conn, route, now=now, context=ctx)
    assert quota.frozen_until(conn, tenant_id=tenant, model="m1", now=now) is None
    row = conn.execute("SELECT wait_started_at FROM quota_usage WHERE tenant_id = %s "
                       "AND model = 'm1'", (tenant,)).fetchone()
    assert row[0] == now                  # 只记等待起点


def test_freeze_expires_and_blocks_while_active(conn, now, tenant):
    quota.freeze(conn, tenant_id=tenant, model="m1", now=now, seconds=60)
    assert quota.is_frozen(conn, tenant_id=tenant, model="m1", now=now) is True
    later = now + timedelta(seconds=61)
    assert quota.is_frozen(conn, tenant_id=tenant, model="m1", now=later) is False
    assert quota.frozen_until(conn, tenant_id=tenant, model="m1", now=later) is None


def test_decide_blocks_while_frozen():
    verdict = quota.decide(snapshot=None, node_max_qps=10, platform_concurrency=None,
                           terminal_concurrency=None, limit_pct=25, frozen=True)
    assert verdict.allowed is False
    assert "quota_frozen" in verdict.reason_codes
    assert verdict.frozen is True


def test_decide_downsizes_over_share_tenant():
    """INV-08 降权：超 25% 时把该租户的可用槽位夹到 total×25%。"""
    verdict = quota.decide(snapshot=None, node_max_qps=100, platform_concurrency=None,
                           terminal_concurrency=None, limit_pct=25,
                           observed_share_bps=5_000, total_slots=100)
    assert verdict.share_exceeded is True
    assert verdict.share_cap == 25
    assert verdict.effective_concurrency == 25
    assert verdict.allowed is True                    # 降权而不是淘汰


def test_decide_takes_the_worse_of_observed_and_provider_share():
    verdict = quota.decide(snapshot={"share_pct_bps": 4_000}, node_max_qps=100,
                           platform_concurrency=None, terminal_concurrency=None,
                           limit_pct=25, observed_share_bps=1_000, total_slots=100)
    assert verdict.share_pct_bps == 4_000
    assert verdict.share_exceeded is True


def test_note_rejection_keeps_the_first_timestamp(conn, now, tenant):
    quota.note_rejection(conn, tenant_id=tenant, model="m1", now=now)
    quota.note_rejection(conn, tenant_id=tenant, model="m1", now=now + timedelta(minutes=5))
    row = conn.execute("SELECT wait_started_at FROM quota_usage WHERE tenant_id = %s",
                       (tenant,)).fetchone()
    assert row[0] == now
    quota.clear_wait(conn, tenant_id=tenant, model="m1", now=now)
    row = conn.execute("SELECT wait_started_at FROM quota_usage WHERE tenant_id = %s",
                       (tenant,)).fetchone()
    assert row[0] is None


def test_windows_reports_day_week_month(conn, now, tenant):
    quota.reserve(conn, tenant_id=tenant, model="m1", now=now, units=2, kind="day")
    quota.reserve(conn, tenant_id=tenant, model="m1", now=now, units=5, kind="week")
    report = quota.windows(conn, tenant_id=tenant, model="m1", now=now)
    assert set(report) == {"day", "week", "month"}
    assert report["day"]["concurrent"] == 2
    assert report["week"]["concurrent"] == 5
    assert report["month"] is None


def test_fairness_columns_are_writable_and_guarded(conn, now, tenant):
    """409 只加列：软停/等待列可写；但维度列仍不可改（405 的守卫继续生效）。"""
    quota.freeze(conn, tenant_id=tenant, model="m1", now=now, reason="quota_exhausted")
    row = conn.execute("SELECT frozen_reason FROM quota_usage WHERE tenant_id = %s",
                       (tenant,)).fetchone()
    assert row[0] == "quota_exhausted"
    with pytest.raises(Exception):
        conn.execute("UPDATE quota_usage SET frozen_until = NULL, frozen_reason = NULL "
                     "WHERE tenant_id = %s", (tenant,))
        conn.execute("UPDATE quota_usage SET tenant_id = %s", (uuid.uuid4(),))
    conn.rollback()
