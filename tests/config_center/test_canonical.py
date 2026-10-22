# SPDX-License-Identifier: Apache-2.0
"""规范化 JSON 与摘要（INV-01 / INV-08）：同内容同 digest、可复算、不接受非 JSON 类型。"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.config_center import canonical


def test_canonical_json_is_stable_and_sorted():
    assert canonical.canonical_json({"b": 1, "a": [2, {"d": 3, "c": 4}]}) == \
        '{"a":[2,{"c":4,"d":3}],"b":1}'
    # 键顺序不同 → 同一文本
    assert canonical.canonical_json({"a": 1, "b": 2}) == canonical.canonical_json({"b": 2, "a": 1})
    # 紧凑无空格 + 中文不转义
    assert canonical.canonical_json({"k": "配置"}) == '{"k":"配置"}'


@pytest.mark.parametrize("value", [Decimal("1.5"), datetime.now(timezone.utc), {1, 2}, b"raw"])
def test_canonical_json_rejects_non_json_types(value):
    with pytest.raises(TypeError):
        canonical.canonical_json({"v": value})


def test_canonical_json_rejects_nan():
    with pytest.raises(TypeError):
        canonical.canonical_json({"v": float("nan")})


def test_version_digest_is_deterministic_and_content_addressed():
    digest = canonical.version_digest(key="billing.gas_fee_mode", value="INTERNAL",
                                      schema_ref="billing.gas_fee_mode@v1", unit="enum")
    assert digest == canonical.version_digest(key="billing.gas_fee_mode", value="INTERNAL",
                                              schema_ref="billing.gas_fee_mode@v1", unit="enum")
    assert len(digest) == 64 and digest == digest.lower()
    int(digest, 16)                                    # 合法十六进制

    # 改 key / value / unit / schema_ref 任何一个，digest 必须变（内容寻址）
    assert digest != canonical.version_digest(key="billing.gas_fee_mode", value="EXTERNAL",
                                              schema_ref="billing.gas_fee_mode@v1", unit="enum")
    assert digest != canonical.version_digest(key="billing.gas_fee_bearer", value="INTERNAL",
                                              schema_ref="billing.gas_fee_mode@v1", unit="enum")
    assert digest != canonical.version_digest(key="billing.gas_fee_mode", value="INTERNAL",
                                              schema_ref="billing.gas_fee_mode@v1", unit="text")
    assert digest != canonical.version_digest(key="billing.gas_fee_mode", value="INTERNAL",
                                              schema_ref="billing.gas_fee_mode@v2", unit="enum")


def test_version_digest_requires_text_fields():
    with pytest.raises(TypeError):
        canonical.version_digest(key="", value=1, schema_ref="a@v1", unit="count")
    with pytest.raises(TypeError):
        canonical.version_digest(key="a.b", value=1, schema_ref=None, unit="count")


def test_request_digest_changes_with_scope():
    base = dict(key="pool.reserved_default", value=30)
    assert (canonical.request_digest(**base, scope="global", scope_id="")
            != canonical.request_digest(**base, scope="tenant", scope_id="t1"))


def _entry(key: str, version: int, digest_char: str = "a") -> dict:
    return {"key": key, "scope": "global", "scope_id": "", "version": version,
            "content_digest": digest_char * 64}


def test_snapshot_digest_is_order_independent_and_stable():
    a = _entry("billing.gas_fee_mode", 2)
    b = _entry("pool.reserved_default", 7, "b")
    assert canonical.snapshot_digest([a, b]) == canonical.snapshot_digest([b, a])
    assert canonical.snapshot_digest([a, b]) != canonical.snapshot_digest([a])
    # 额外字段（value_type 等）不参与 digest：加字段不等于换 policy_version
    a_extra = dict(a, value_type="string")
    assert canonical.snapshot_digest([a_extra, b]) == canonical.snapshot_digest([a, b])


def test_snapshot_digest_rejects_bad_input():
    with pytest.raises(ValueError):
        canonical.snapshot_digest([])
    with pytest.raises(TypeError):
        canonical.snapshot_digest([{"key": "a.b"}])
    with pytest.raises(TypeError):
        canonical.snapshot_digest([_entry("a.b", 1, "x")])       # digest 长度不对
    with pytest.raises(ValueError):
        canonical.snapshot_digest([_entry("a.b", 1), _entry("a.b", 2)])   # 重复 key


def test_policy_version_is_first_12_chars():
    digest = canonical.snapshot_digest([_entry("a.b", 1)])
    assert canonical.policy_version(digest) == digest[:12]
    assert len(canonical.policy_version(digest)) == 12
    with pytest.raises(ValueError):
        canonical.policy_version("short")
    with pytest.raises(ValueError):
        canonical.policy_version(None)
