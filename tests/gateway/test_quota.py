# SPDX-License-Identifier: Apache-2.0
"""配额口径 ``min(租户, Key, 节点)`` + 每日花费上限（M03 §1 / §4.4 的 42902）。不需要 DB。"""
from __future__ import annotations

import uuid

import pytest

from app.gateway import errors, models, quota
from gatewaykit import principal_dict


# ─────────────────────────────────────────────────────── min 语义
def test_resolve_takes_minimum_per_kind():
    merged = quota.resolve({"qps": 10, "daily_usd_minor": 5_000},
                           {"qps": 4}, {"qps": 8, "concurrency": 2})
    assert merged == {"qps": 4, "daily_usd_minor": 5_000, "concurrency": 2}


def test_resolve_ignores_missing_layers():
    assert quota.resolve({"qps": 7}) == {"qps": 7}
    assert quota.resolve(None, {}, {"qps": 3}) == {"qps": 3}
    assert quota.resolve() == {}


def test_resolve_accepts_row_lists():
    rows = [{"kind": "qps", "value": 9}, {"kind": "qps", "value": "6"}]
    assert quota.resolve(rows) == {"qps": 6}


def test_resolve_matches_m01_effective_semantics():
    """与 M01 ``effective_quotas`` 同语义（缺档位视为无上限、按 kind 取 min）。"""
    from app.gateway import models as gateway_models       # 只用本模块；对照在文档里

    tenant = {"qps": 20, "daily_usd_minor": 10_000}
    key = {"qps": 8}
    node = {"qps": 12, "concurrency": 4}
    merged = quota.resolve(tenant, key, node)
    assert merged["qps"] == min(8, 12, 20)
    assert merged["daily_usd_minor"] == 10_000
    assert merged["concurrency"] == 4
    assert gateway_models  # 保持 import 有用（避免误报未使用）


def test_effective_qps_helper():
    assert quota.effective_qps(None, 5, 9) == 5
    assert quota.effective_qps(None, None) is None
    assert quota.effective_qps() is None


# ─────────────────────────────────────────────────────── 快照解析
def _principal(qps=None, cap=None, spend=None):
    return models.coerce_principal(
        principal_dict(account_id=uuid.uuid4(), tenant_id=uuid.uuid4(),
                       qps=qps, daily_cap_minor=cap, daily_spend_minor=spend))


def test_from_snapshot_uses_effective_block():
    state = quota.from_snapshot(_principal(qps=6, cap=1_000).quotas)
    assert state.qps == 6
    assert state.daily_cap_minor == 1_000
    assert state.policy_version == "pv-1"


def test_from_snapshot_computes_min_from_rows_when_effective_missing():
    snapshot = {"policy_version": "pv-9",
                "quotas": [{"key_id": None, "kind": "qps", "value": 12},
                           {"key_id": None, "kind": "daily_usd_minor", "value": 5_000},
                           {"key_id": 3, "kind": "qps", "value": 4}]}
    state = quota.from_snapshot(snapshot)
    assert state.qps == 4
    assert state.daily_cap_minor == 5_000
    assert state.policy_version == "pv-9"


def test_from_snapshot_merges_node_caps():
    snapshot = {"effective": {"qps": 10}, "node_caps": {"qps": 3}}
    assert quota.from_snapshot(snapshot).qps == 3


def test_from_snapshot_empty():
    state = quota.from_snapshot(None)
    assert state.qps is None and state.daily_cap_minor is None
    assert state.daily_spend_minor is None


# ─────────────────────────────────────────────────────── 每日花费上限
def test_daily_cap_not_hit():
    quota.assert_daily_cap(quota.from_snapshot(_principal(cap=10_000, spend=9_999).quotas))


def test_daily_cap_reached_raises_42902():
    state = quota.from_snapshot(_principal(cap=10_000, spend=10_000).quotas)
    with pytest.raises(errors.GatewayError) as info:
        quota.assert_daily_cap(state)
    exc = info.value
    assert (exc.http_status, exc.code) == (429, 42902)
    assert exc.reason == "quota_exceeded"
    assert exc.retry_after_s and exc.retry_after_s > 0
    assert exc.details == {"limit": 10_000, "spend": 10_000}


def test_no_cap_or_no_spend_means_no_limit():
    quota.assert_daily_cap(quota.from_snapshot(_principal(spend=10 ** 9).quotas))
    quota.assert_daily_cap(quota.from_snapshot(_principal(cap=1).quotas))


def test_scope_keys_builds_tenant_and_key_scopes():
    principal = _principal(qps=5)
    spans = quota.scope_keys(principal)
    assert [scope for scope, _ in spans] == [f"tenant:{principal.tenant_id}",
                                             f"key:{principal.api_key_id}"]
    assert quota.scope_keys(principal, include_key=False) == [
        (f"tenant:{principal.tenant_id}", None)]


def test_quota_kinds_align_with_m01():
    assert quota.QUOTA_KINDS == ("qps", "daily_usd_minor", "concurrency")
