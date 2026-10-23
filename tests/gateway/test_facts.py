# SPDX-License-Identifier: Apache-2.0
"""常量与配置键（M03 §8.1 / §8.2、03-facts §10、00-conventions §1.5）。不需要 DB。"""
from __future__ import annotations

import pathlib
import re

import yaml

from app.gateway import config_source, facts, features

ROOT = pathlib.Path(__file__).resolve().parents[2]


# ─────────────────────────────────────────────────────── §8.2 本模块常量
def test_section_8_2_constants_match_the_module_spec():
    assert facts.RETRY_MAX_ATTEMPTS == 2
    assert facts.IDEMPOTENCY_TTL_S == 86_400
    assert facts.FINGERPRINT_WINDOW_S == 300
    assert facts.STREAM_DEDUP_WINDOW_S == 60
    assert facts.BATCH_RESULT_TTL_DAYS == 7
    assert facts.BATCH_RESULT_URL_TTL_S == 900
    assert facts.MESSAGES_MAX_ITEMS == 256
    assert facts.MESSAGE_CONTENT_MAX_BYTES == 1_048_576
    assert facts.REQUEST_ID_HEADER == "X-Request-Id"
    assert facts.BATCH_COST_CONFIRM_USD == 10
    assert facts.DEPRECATION_NOTICE_DAYS == 90
    assert facts.REQUEST_LOG_RETENTION_DAYS == 7


def test_result_url_ttl_is_within_the_fifteen_minute_bound():
    """INV-M03-09：结果签名 URL ≤15 分钟。"""
    assert 0 < facts.BATCH_RESULT_URL_TTL_S <= 15 * 60


def test_fingerprint_windows_are_shorter_than_idempotency_ttl():
    assert facts.FINGERPRINT_WINDOW_S < facts.IDEMPOTENCY_TTL_S
    assert facts.STREAM_DEDUP_WINDOW_S < facts.FINGERPRINT_WINDOW_S


# ─────────────────────────────────────────────────────── 枚举（M03 §5）
def test_enums_match_the_spec_vocabulary():
    assert facts.SERVICE_TIERS == ("realtime", "batch")
    assert facts.REQUEST_STATUSES == ("completed", "failed", "interrupted")
    assert facts.USAGE_SOURCES == ("estimated", "actual")
    assert facts.BATCH_STATUSES == ("queued", "running", "succeeded", "failed", "canceled")
    assert facts.BATCH_TERMINAL_STATUSES == ("succeeded", "failed", "canceled")
    assert set(facts.MESSAGE_ROLES) == {"system", "user", "assistant", "tool"}
    assert "content_filter" in facts.FINISH_REASONS and "stop" in facts.FINISH_REASONS


def test_terminal_batch_statuses_are_a_subset_of_all_statuses():
    assert set(facts.BATCH_TERMINAL_STATUSES) <= set(facts.BATCH_STATUSES)


# ─────────────────────────────────────────────────────── 事件（02-events §3）
def test_event_types_and_payload_keys_match_the_event_contract():
    assert facts.EVENT_TYPES == ("request.completed", "request.failed")
    assert facts.EVENT_PRODUCER == "M03"
    assert facts.EVENT_PAYLOAD_KEYS["request.completed"] == (
        "request_id", "model", "tokens_in", "tokens_out", "latency_ms", "node_id",
        "usage_source")
    assert facts.EVENT_PAYLOAD_KEYS["request.failed"] == (
        "request_id", "error_code", "upstream_error_class", "attempts")
    # 02-events §1：payload 不放正文；这两组键都是元数据
    assert not any(key in {"content", "prompt", "response", "messages"}
                   for keys in facts.EVENT_PAYLOAD_KEYS.values() for key in keys)


# ─────────────────────────────────────────────────────── 配置键（§8.1，Owner=M10）
def test_config_keys_are_namespaced_and_registered():
    assert facts.CONFIG_KEYS == {"rate_limit_qps": "gateway.rate_limit_qps",
                                 "stream_timeout_s": "gateway.stream_timeout_s"}
    for key in facts.CONFIG_KEYS.values():
        assert key.startswith("gateway.")
        assert key in facts.CONFIG_KEY_RANGES


def test_config_source_without_provider_returns_none_not_invented_defaults():
    """M03 §8.1：默认 = M10 基线；模块**不内置**业务默认值。"""
    config_source.set_provider(None)
    assert config_source.rate_limit_qps() is None
    assert config_source.stream_timeout_s() is None
    assert config_source.raw() == {}


def test_config_source_reads_provider_values():
    config_source.set_provider(lambda: {"gateway.rate_limit_qps": 20,
                                        "gateway.stream_timeout_s": 60})
    assert config_source.snapshot() == {"rate_limit_qps": 20, "stream_timeout_s": 60}


def test_config_source_clamps_out_of_range_and_ignores_garbage():
    config_source.set_provider(lambda: {"gateway.rate_limit_qps": 10 ** 9,
                                        "gateway.stream_timeout_s": "abc"})
    snapshot = config_source.snapshot()
    assert snapshot["rate_limit_qps"] == facts.CONFIG_KEY_RANGES["gateway.rate_limit_qps"][1]
    assert snapshot["stream_timeout_s"] is None


def test_config_source_survives_broken_provider():
    def boom():
        raise RuntimeError("M10 不可用")

    config_source.set_provider(boom)
    assert config_source.snapshot() == {"rate_limit_qps": None, "stream_timeout_s": None}


# ─────────────────────────────────────────────────────── SLO（03-facts §10）
def test_slo_constants_match_contracts_facts_yaml():
    """03-facts §10 只允许一个来源：这里把它与机器源对账，防止两处漂移。"""
    source = yaml.safe_load((ROOT / "contracts" / "facts.yaml").read_text(encoding="utf-8"))
    section = next(item for item in source["sections"] if item["id"] == 10)
    row = next(item for item in section["facts"] if item["key"] == "首字节")
    value = row["value"]
    first_byte = re.search(r"P95\s*≤\s*([0-9.]+)s", value)
    overhead = re.search(r"网关额外\s*≤\s*([0-9.]+)\s*ms", value)
    assert first_byte and overhead, value
    assert int(round(float(first_byte.group(1)) * 1000)) == facts.SLO_FIRST_BYTE_P95_MS
    assert int(round(float(overhead.group(1)))) == facts.SLO_GATEWAY_OVERHEAD_MS


def test_slo_owner_is_m03_and_m16():
    source = yaml.safe_load((ROOT / "contracts" / "facts.yaml").read_text(encoding="utf-8"))
    section = next(item for item in source["sections"] if item["id"] == 10)
    assert section["owner"] == "M03 / M16"


# ─────────────────────────────────────────────────────── 特性开关（硬约束第 4 条）
def test_every_feature_switch_has_three_fields_and_defaults_off():
    for switch in features.switches():
        assert switch.owner.strip()
        assert switch.expire_at is not None
        assert len(switch.rollback_rule.strip()) >= 8
        assert switch.default is False
        assert features.enabled(switch.name) is False


def test_feature_switches_have_no_write_surface():
    assert features.WRITE_SURFACE == ()
    assert not any(name in dir(features) for name in ("set", "enable", "toggle", "write"))


def test_unknown_feature_switch_is_rejected():
    import pytest

    with pytest.raises(KeyError):
        features.get("gateway.not_registered")
