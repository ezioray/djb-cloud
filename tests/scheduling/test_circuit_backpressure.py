# SPDX-License-Identifier: AGPL-3.0-or-later
"""熔断与背压（M04 §7 失败矩阵 / §8.2 水位与熔断参数）。

熔断：κ ≥2.50 持续 60 s 或失败率 >30% → 停接新 + 熔断 10 min；
背压：水位 70/85/95 → 提示 / 收紧 / 只保实时。
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.scheduling import backpressure, candidates, circuit, facts, pipeline


# --------------------------------------------------------------------------- 背压
def test_watermarks_follow_section_8_2():
    assert facts.QUEUE_WATERMARK_PCT == (70, 85, 95)
    assert backpressure.level_name(None) == "ok"
    assert backpressure.level_name(69) == "ok"
    assert backpressure.level_name(70) == "notice"
    assert backpressure.level_name(84) == "notice"
    assert backpressure.level_name(85) == "tight"
    assert backpressure.level_name(94) == "tight"
    assert backpressure.level_name(95) == "realtime_only"
    assert backpressure.level_name(150) == "realtime_only"   # 夹到 100


def test_backpressure_actions_are_explicit():
    notice = backpressure.classify(70)
    assert notice.actions == ("broadcast_demand_signal",)
    tight = backpressure.classify(90)
    assert "queue_batch_with_eta" in tight.actions
    full = backpressure.classify(96)
    assert "reject_batch" in full.actions
    assert full.allows("realtime") is True
    assert full.allows("batch") is False


# --------------------------------------------------------------------------- 熔断
def test_should_trip_on_sustained_kappa():
    assert circuit.should_trip(kappa_milli=2_500, kappa_sustained_s=60).open is True
    assert circuit.should_trip(kappa_milli=2_500, kappa_sustained_s=59).open is False
    assert circuit.should_trip(kappa_milli=2_499, kappa_sustained_s=600).open is False


def test_should_trip_on_failure_rate():
    trip = circuit.should_trip(fail_rate_bps=3_001)
    assert trip.open is True and trip.reason == "fail_rate"
    assert circuit.should_trip(fail_rate_bps=3_000).open is False
    assert circuit.should_trip().open is False


def test_evaluate_honours_the_cooldown(now):
    state = {"opened_until": now + timedelta(minutes=5)}
    trip = circuit.evaluate(state, now=now)
    assert trip.open is True and trip.reason == "cooldown"
    assert circuit.evaluate(state, now=now + timedelta(minutes=6)).open is False


def test_evaluate_sets_a_ten_minute_window(now):
    trip = circuit.evaluate({"kappa_milli": 2_600, "kappa_sustained_s": 61}, now=now)
    assert trip.open is True and trip.reason == "kappa"
    assert trip.until == now + timedelta(seconds=facts.CIRCUIT_OPEN_S)


def test_provider_is_optional(conn):
    circuit.set_provider(None)
    assert circuit.is_open(conn, "n1").open is False

    circuit.set_provider(lambda c, node_id: {"fail_rate_bps": 9_000})
    try:
        assert circuit.is_open(conn, "n1").open is True
    finally:
        circuit.set_provider(None)


def test_provider_failure_does_not_trip(conn):
    def boom(c, node_id):
        raise RuntimeError("metrics down")

    circuit.set_provider(boom)
    try:
        assert circuit.is_open(conn, "n1").open is False
    finally:
        circuit.set_provider(None)


def test_open_circuit_eliminates_the_node_in_p1(conn, now, tenant, factory):
    """熔断中的节点不进候选集（F3，detail=circuit_open）。"""
    factory.node("n_hot")
    factory.capacity("n_hot", models=("m1",))
    factory.quote("n_hot", low=800, high=1_000)
    circuit.set_provider(lambda c, node_id: {"fail_rate_bps": 5_000})
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                      trace_id="t")
        snapshot = candidates.collect(conn, route, now=now)
    finally:
        circuit.set_provider(None)
    assert snapshot.candidates == ()
    dropped = [item for item in snapshot.eliminated if item["node_id"] == "n_hot"]
    assert dropped and dropped[0]["reason_code"] == "F3"
    assert dropped[0]["detail"] == "circuit_open"


def test_recovered_node_returns_to_the_pool(conn, now, tenant, factory):
    factory.node("n_cool")
    factory.capacity("n_cool", models=("m1",))
    factory.quote("n_cool", low=800, high=1_000)
    circuit.set_provider(lambda c, node_id: {"fail_rate_bps": 100, "kappa_milli": 1_100})
    try:
        route = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                      trace_id="t")
        snapshot = candidates.collect(conn, route, now=now)
    finally:
        circuit.set_provider(None)
    assert [item.node_id for item in snapshot.candidates] == ["n_cool"]
