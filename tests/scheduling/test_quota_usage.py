# SPDX-License-Identifier: AGPL-3.0-or-later
"""配额计数落库（M04 §5 quota_usage / §6 流程 2 P5 / INV-07 / INV-08）。

计数是**可增可减但不可消失**的：``+1`` 由 P5 在决策事务内做，``-1`` 由消费方释放；
维度列（tenant / model / window / window_start）不可变，避免计数被「挪」到别人头上。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.scheduling import quota


@pytest.fixture
def counted(conn, now, tenant):
    return conn, tenant, "m1", now


def test_reserve_creates_then_increments(counted):
    conn, tenant, model, now = counted
    try:
        assert quota.reserve(conn, tenant_id=tenant, model=model, now=now, spend_minor=800) == 1
        assert quota.reserve(conn, tenant_id=tenant, model=model, now=now, spend_minor=200) == 2
        row = quota.usage(conn, tenant_id=tenant, model=model, now=now)
        assert row == {"concurrent": 2, "daily_spend_minor": 1_000, "share_pct_bps": 0}
    finally:
        conn.rollback()


def test_release_floors_at_zero(counted):
    conn, tenant, model, now = counted
    try:
        quota.reserve(conn, tenant_id=tenant, model=model, now=now, units=2)
        assert quota.release(conn, tenant_id=tenant, model=model, now=now, units=1) == 1
        assert quota.release(conn, tenant_id=tenant, model=model, now=now, units=5) == 0
        assert quota.usage(conn, tenant_id=tenant, model=model, now=now)["concurrent"] == 0
    finally:
        conn.rollback()


def test_usage_is_scoped_per_window(counted):
    conn, tenant, model, now = counted
    try:
        quota.reserve(conn, tenant_id=tenant, model=model, now=now, units=1, kind="day")
        assert quota.usage(conn, tenant_id=tenant, model=model, now=now, kind="day")
        assert quota.usage(conn, tenant_id=tenant, model=model, now=now, kind="week") is None
    finally:
        conn.rollback()


def test_share_is_recorded_in_bps(counted):
    conn, tenant, model, now = counted
    try:
        quota.reserve(conn, tenant_id=tenant, model=model, now=now, share_pct_bps=2_500)
        assert quota.usage(conn, tenant_id=tenant, model=model, now=now)["share_pct_bps"] == 2_500
    finally:
        conn.rollback()


def test_quota_usage_dimension_cannot_be_moved(counted):
    """维度列不可变：改 tenant / model / window 只能新建行（库层守卫）。"""
    conn, tenant, model, now = counted
    quota.reserve(conn, tenant_id=tenant, model=model, now=now, units=1)
    with pytest.raises(Exception):
        conn.execute("UPDATE quota_usage SET model = 'other'")
    conn.rollback()


def test_quota_usage_rows_cannot_be_deleted(counted):
    conn, tenant, model, now = counted
    quota.reserve(conn, tenant_id=tenant, model=model, now=now, units=1)
    with pytest.raises(Exception):
        conn.execute("DELETE FROM quota_usage")
    conn.rollback()


def test_snapshot_provider_is_optional_and_defensive():
    quota.set_quota_provider(None)
    try:
        assert quota.snapshot(None, uuid.uuid4(), "m1") == {}
    finally:
        quota.set_quota_provider(None)

    quota.set_quota_provider(lambda c, tenant, model: {"remaining": 3})
    try:
        assert quota.snapshot(None, uuid.uuid4(), "m1") == {"remaining": 3}
    finally:
        quota.set_quota_provider(None)

    def boom(c, tenant, model):
        raise RuntimeError("identity down")

    quota.set_quota_provider(boom)
    try:
        assert quota.snapshot(None, uuid.uuid4(), "m1") == {}     # provider 挂了不当机
    finally:
        quota.set_quota_provider(None)


def test_evaluate_wraps_snapshot_and_decide(conn, now, tenant):
    quota.set_quota_provider(lambda c, tenant_id, model: {"remaining": 1})
    try:
        verdict = quota.evaluate(conn, tenant_id=tenant, model="m1", node_max_qps=10,
                                 platform_concurrency=20, terminal_concurrency=None,
                                 limit_pct=25)
        assert verdict.allowed is True and verdict.remaining == 1
        blocked = quota.evaluate(conn, tenant_id=tenant, model="m1", node_max_qps=10,
                                 platform_concurrency=20, terminal_concurrency=None,
                                 limit_pct=25, required_units=2)
        assert blocked.allowed is False
    finally:
        quota.set_quota_provider(None)


