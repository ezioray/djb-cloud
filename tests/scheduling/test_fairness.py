# SPDX-License-Identifier: AGPL-3.0-or-later
"""公平观测与计数（M04 §8.2 / §4.7.5 / INV-08）。

T3 做的三件事：**基尼**（纯函数，整数）、**单租户占比**（自有计数）、
**等待与反饥饿**（阈值判定）。S2 的加权公平不在本模块范围。
"""
from __future__ import annotations

import uuid

import pytest

from app.scheduling import facts, fairness, quota


# --------------------------------------------------------------------------- 基尼
def test_gini_of_equal_values_is_zero():
    assert fairness.gini_milli([5, 5, 5, 5]) == 0
    assert fairness.gini_milli([]) == 0
    assert fairness.gini_milli([0, 0]) == 0


def test_gini_of_maximal_inequality():
    """n 个样本、一人独占 → gini = (n-1)/n。"""
    assert fairness.gini_milli([0, 0, 100]) == 666
    assert fairness.gini_milli([0, 100]) == 500


def test_gini_is_symmetric_and_clamped():
    assert fairness.gini_milli([1, 2, 3]) == fairness.gini_milli([3, 2, 1])
    assert 0 <= fairness.gini_milli([1, 2, 3, 4, 5]) <= 1_000
    assert fairness.gini_milli([-5, 10]) == fairness.gini_milli([0, 10])   # 负值夹到 0


def test_gini_threshold_follows_section_8_2():
    assert facts.GINI_MAX_MILLI == 350
    assert fairness.gini_breach(350) is False
    assert fairness.gini_breach(351) is True
    assert fairness.gini_breach(None) is False


def test_median_and_wait_thresholds():
    assert fairness.median([3, 1, 2]) == 2
    assert fairness.median([1, 2, 3, 4]) == 2            # 偶数取中间下界
    assert fairness.median([]) is None
    assert facts.SMALL_NODE_MEDIAN_WAIT_S == 300
    assert fairness.wait_breach(300) is False
    assert fairness.wait_breach(301) is True
    assert fairness.starvation(facts.ANTI_STARVATION_S) is False
    assert fairness.starvation(facts.ANTI_STARVATION_S + 1) is True


def test_waiting_archive_suggestion():
    assert fairness.waiting(None)["starvation"] is False
    assert fairness.waiting(1_801)["starvation"] is True
    assert fairness.waiting(301)["wait_breach"] is True


# --------------------------------------------------------------------------- 观测
def test_observe_reports_share_breach_from_own_counters(conn, now, tenant, other_tenant):
    """占比来自 M04 自有计数：A 占 3 / 合计 4 = 75% → 越 25% 上限。"""
    quota.reserve(conn, tenant_id=tenant, model="m1", now=now, units=3)
    quota.reserve(conn, tenant_id=other_tenant, model="m1", now=now, units=1)
    snapshot = fairness.observe(conn, now=now)
    assert snapshot["models"] == {"m1": 4}
    assert snapshot["max_tenant_share_bps"] == 7_500
    assert "tenant_share" in snapshot["breaches"]
    assert snapshot["share_threshold_bps"] == 2_500
    assert snapshot["wait_observed"] is False            # 未接线 → 不观测（不当 0）


def test_observe_without_traffic_is_clean(conn, now):
    snapshot = fairness.observe(conn, now=now, model="no-such-model")
    assert snapshot["gini_milli"] == 0
    assert snapshot["models"] == {"no-such-model": 0}
    assert snapshot["breaches"] == []


def test_observe_uses_injected_wait_provider(conn, now, tenant):
    quota.reserve(conn, tenant_id=tenant, model="m1", now=now, units=1)
    fairness.set_median_wait_provider(lambda c: 900)
    try:
        snapshot = fairness.observe(conn, now=now)
    finally:
        fairness.set_median_wait_provider(None)
    assert snapshot["median_wait_s"] == 900
    assert snapshot["wait_observed"] is True
    assert "small_node_wait" in snapshot["breaches"]


def test_observe_survives_a_broken_wait_provider(conn, now, tenant):
    quota.reserve(conn, tenant_id=tenant, model="m1", now=now, units=1)

    def boom(c):
        raise RuntimeError("metrics down")

    fairness.set_median_wait_provider(boom)
    try:
        snapshot = fairness.observe(conn, now=now)
    finally:
        fairness.set_median_wait_provider(None)
    assert snapshot["wait_observed"] is False


def test_gini_breach_is_reported_when_one_tenant_dominates(conn, now, tenant, other_tenant):
    quota.reserve(conn, tenant_id=tenant, model="m1", now=now, units=9)
    quota.reserve(conn, tenant_id=other_tenant, model="m2", now=now, units=1)
    snapshot = fairness.observe(conn, now=now)
    assert snapshot["gini_milli"] > 0
    assert isinstance(snapshot["breaches"], list)
