# SPDX-License-Identifier: AGPL-3.0-or-later
"""注册表 / payload / 差异（纯函数，不碰 DB）：只元数据、可复算、wire 形状逐字对齐。"""
from __future__ import annotations

import hashlib
import json

import pytest

from app.model_sync import facts, registry
from app.model_sync.errors import BadRequest


def test_builtin_catalog_is_metadata_only():
    """内置 6 条：只有元数据 + 占位指纹，不含任何凭据 / 厂商权重。"""
    assert len(registry.BUILTIN_MODELS) == 6
    vendors = {item["vendor"] for item in registry.BUILTIN_MODELS}
    assert {"openai", "anthropic", "deepseek"} <= vendors
    for item in registry.BUILTIN_MODELS:
        assert item["tokenizer_hash"] == registry.tokenizer_hash_of(
            item["tokenizer_family"], item["tokenizer_version"])
        assert len(item["tokenizer_hash"]) == 64
        assert item["context_window"] > 0
        text = json.dumps(item, ensure_ascii=False).lower()
        for forbidden in ("api_key", "secret", "password", "bearer", "sk-"):
            assert forbidden not in text, forbidden


def test_canonical_json_is_stable_and_sorted():
    left = {"b": 1, "a": {"y": 2, "x": 1}}
    right = {"a": {"x": 1, "y": 2}, "b": 1}
    assert registry.canonical_json(left) == registry.canonical_json(right)
    assert registry.canonical_json(left) == b'{"a":{"x":1,"y":2},"b":1}'


EXPIRES = "2026-10-26T00:00:00.000Z"


def _payload(models=None, *, version=1):
    return registry.build_payload(models or registry.BUILTIN_MODELS, version=version,
                                  expires_at=EXPIRES)


def test_payload_hash_matches_the_m18b_canonical_recipe():
    """payload = **恰好** {version, expires_at, models}；8 字段 models；sha256(canonical JSON)。"""
    payload = _payload(version=7)
    assert set(payload) == {"version", "expires_at", "models"}
    assert payload["version"] == 7 and payload["expires_at"] == EXPIRES
    for item in payload["models"]:
        assert list(item) == ["vendor", "canonical", "aliases", "context_window",
                              "tokenizer_family", "tokenizer_version", "tokenizer_hash",
                              "effective_at"]
        assert item["canonical"]

    # 客户端同款复算：只取这三个键 + 8 字段，json.dumps(sort_keys, 紧凑, 非 ASCII 不转义)
    rebuilt = {"version": payload["version"], "expires_at": payload["expires_at"],
               "models": [{key: item[key] for key in (
                   "vendor", "canonical", "aliases", "context_window", "tokenizer_family",
                   "tokenizer_version", "tokenizer_hash", "effective_at")}
                   for item in payload["models"]]}
    text = json.dumps(rebuilt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert registry.payload_hash_of(payload) == expected
    # 多一个键就不是同一份 hash（客户端会判不一致）
    polluted = dict(payload, extra=1)
    assert registry.payload_hash_of(polluted) != expected
    # 逐字节可复算：同一输入两次一致
    assert registry.payload_hash_of(_payload(version=7)) == expected


def test_build_payload_normalizes_order_and_shape():
    payload = _payload(reversed(registry.BUILTIN_MODELS))
    keys = [(item["vendor"], item["canonical"], item["effective_at"])
            for item in payload["models"]]
    assert keys == sorted(keys)
    assert set(payload["models"][0]) == {
        "vendor", "canonical", "aliases", "context_window", "tokenizer_family",
        "tokenizer_version", "tokenizer_hash", "effective_at"}
    assert payload["models"][0]["effective_at"].endswith("Z")


def _good_entry(**overrides):
    entry = dict(registry.BUILTIN_MODELS[0])
    entry.update(overrides)
    return entry


@pytest.mark.parametrize("overrides,field", [
    ({"tokenizer_hash": "deadbeef"}, "models[0].tokenizer_hash"),
    ({"context_window": 0}, "models[0].context_window"),
    ({"state": "deleted"}, "models[0].state"),
    ({"source": "rumour"}, "models[0].source"),
    ({"aliases": [""]}, "models[0].aliases[0]"),
    ({"effective_at": "yesterday"}, "models[0].effective_at"),
])
def test_normalize_rejects_bad_entries(overrides, field):
    with pytest.raises(BadRequest) as excinfo:
        registry.normalize_models([_good_entry(**overrides)])
    assert excinfo.value.details["field"] == field


def test_normalize_rejects_duplicate_keys_and_empty_list():
    entry = _good_entry()
    with pytest.raises(BadRequest):
        registry.normalize_models([entry, dict(entry)])
    with pytest.raises(BadRequest):
        registry.normalize_models([])


def test_diff_models_reports_added_removed_changed():
    before = [dict(registry.BUILTIN_MODELS[0]), dict(registry.BUILTIN_MODELS[1])]
    after = [dict(registry.BUILTIN_MODELS[0], context_window=256_000),
             dict(registry.BUILTIN_MODELS[2])]
    diff = registry.diff_models(before, after)
    assert diff["added"] == ["anthropic/claude-3-5-sonnet"]
    assert diff["removed"] == ["openai/gpt-4o"]
    assert diff["changed"] == ["openai/gpt-4o-mini"]


def test_catalog_payload_fallback_and_not_modified():
    fallback = registry.catalog_payload(None, since=None)
    assert fallback == {"version": 0, "payload_hash": None, "signature": None,
                        "expires_at": None, "not_modified": True, "models": []}

    payload = _payload(version=7)
    bundle = {"version": 7, "payload_hash": "0" * 64, "signature": "hmac-sha256:" + "1" * 64,
              "expires_at": None, "payload": payload}
    fresh = registry.catalog_payload(bundle, since=3)
    assert fresh["version"] == 7 and fresh["not_modified"] is False
    assert len(fresh["models"]) == 6
    assert registry.catalog_payload(bundle, since=7)["not_modified"] is True
    assert registry.catalog_payload(bundle, since=7)["models"] == []
    assert registry.catalog_payload(bundle, since=99)["not_modified"] is True
