# SPDX-License-Identifier: Apache-2.0
"""配置来源（M02 §8.1）：provider 注入、缺省兜底、越界夹取。纯函数 + 无 DB。"""
from __future__ import annotations

import pytest

from app.supply import config_source, facts


@pytest.fixture(autouse=True)
def _reset_provider():
    config_source.set_provider(None)
    yield
    config_source.set_provider(None)


def test_defaults_match_spec_81_without_provider():
    values = config_source.load(None)
    assert values[facts.CONFIG_KEYS["heartbeat_interval_s"]] == 30
    assert values[facts.CONFIG_KEYS["stale_after_s"]] == 45
    assert values[facts.CONFIG_KEYS["announcement_ttl_s"]] == 60
    assert values[facts.CONFIG_KEYS["max_nodes_per_account"]] == 100
    assert values[facts.CONFIG_KEYS["review_sla_h"]] == 24


def test_provider_values_win():
    config_source.set_provider(lambda c, node: {
        facts.CONFIG_KEYS["heartbeat_interval_s"]: 20,
        facts.CONFIG_KEYS["stale_after_s"]: 30,
    })
    values = config_source.load(None)
    assert config_source.heartbeat_interval_s(values) == 20
    assert config_source.stale_after_s(values) == 30
    # 未提供的键仍取 §8.1 默认
    assert config_source.announcement_ttl_s(values) == 60


@pytest.mark.parametrize("raw,expected", [(5, 10), (999, 120), (60, 60)])
def test_out_of_range_is_clamped(raw, expected):
    config_source.set_provider(
        lambda c, node: {facts.CONFIG_KEYS["heartbeat_interval_s"]: raw})
    assert config_source.heartbeat_interval_s(config_source.load(None)) == expected


@pytest.mark.parametrize("raw", ["not-a-number", None, [1, 2]])
def test_non_int_falls_back_to_default(raw):
    config_source.set_provider(
        lambda c, node: {facts.CONFIG_KEYS["stale_after_s"]: raw})
    assert config_source.stale_after_s(config_source.load(None)) == 45


def test_non_mapping_provider_result_is_ignored():
    config_source.set_provider(lambda c, node: ["not", "a", "mapping"])   # type: ignore[arg-type]
    assert config_source.raw(None) == {}
    assert config_source.load(None)[facts.CONFIG_KEYS["review_sla_h"]] == 24


def test_provider_receives_node_context():
    seen = {}

    def provider(conn, node):                                  # noqa: ARG001
        seen["node"] = node
        return {}

    config_source.set_provider(provider)
    config_source.load(None, node="node-object")
    assert seen["node"] == "node-object"


def test_reset_provider_restores_defaults():
    config_source.set_provider(lambda c, node: {facts.CONFIG_KEYS["review_sla_h"]: 1})
    assert config_source.review_sla_h(config_source.load(None)) == 1
    config_source.set_provider(None)
    assert config_source.review_sla_h(config_source.load(None)) == 24
    assert config_source.current_provider() is None


def test_ranges_cover_exactly_the_five_spec_keys():
    assert set(config_source.RANGES) == set(facts.CONFIG_KEYS.values())
    for key, (default, low, high) in config_source.RANGES.items():
        assert low <= default <= high, key
