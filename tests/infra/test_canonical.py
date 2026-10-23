# SPDX-License-Identifier: Apache-2.0
"""链哈希与 canonical JSON（纯函数；**算式钉死**，换实现必须红）。

钉住的三件事：
1. canonical JSON 的形状（键排序 / 紧凑 / UTF-8 直出 / 拒绝 NaN）；
2. ``hmac(key, prev_hash + LF + canonical_json(entry))`` 的**已知向量**（literal hex）；
3. 任一字段 / prev_hash / 密钥变化都必须改变哈希（篡改必报的前提）。
"""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from app.audit import canonical, facts
from app.audit import errors
from infrakit import OTHER_KEY, TEST_KEY

#: 已知向量：固定条目 + 固定测试密钥（密钥由非敏感标签派生，见 infrakit.TEST_KEY）
GOLDEN_ENTRY = {
    "seq": 1,
    "entry_id": "018f4d0e-0000-7000-8000-000000000001",
    "ts": "2026-10-23T08:00:00.000000Z",
    "actor": "infra-seat",
    "actor_type": "agent",
    "role": "INFRA",
    "action": "authorize.window",
    "target": "网关@1.4.2",                        # 含中文：钉住 ensure_ascii=False（UTF-8 直出）
    "before": {"window": "closed"},
    "after": {"window": "open"},
    "reason_code": "R-OK",
    "ticket": "REL-0001",
    "evidence": "ops/audit/reports/REL-0001.txt",
    "approval_chain": [
        {"actor": "lead", "decision": "propose"},
        {"actor": "release-manager", "decision": "approve"},
    ],
    "status": "approved",
    "alg": "hmac-sha256",
    "prev_hash": "GENESIS",
}

#: 金标准哈希（2026-10-23 由独立实现算出并写死；换算法 / 换键 / 改字段都会变红）
GOLDEN_HASH = "b58ba020fddcd69c252200d7f54b74170983366f88e67517da68294543717888"


def test_canonical_json_sorts_keys_and_is_compact():
    text = canonical.canonical_json({"b": 1, "a": {"y": 2, "x": 1}})
    assert text == '{"a":{"x":1,"y":2},"b":1}'
    assert " " not in text and "\n" not in text


def test_canonical_json_keeps_utf8_unscaped():
    assert canonical.canonical_json({"target": "网关"}) == '{"target":"网关"}'
    assert "\\u" not in canonical.canonical_json({"target": "网关"})


def test_canonical_json_rejects_nan_and_infinity():
    with pytest.raises(ValueError):
        canonical.canonical_json({"x": float("nan")})
    with pytest.raises(ValueError):
        canonical.canonical_json({"x": float("inf")})


def test_entry_payload_covers_exactly_the_audited_fields():
    payload = canonical.entry_payload(GOLDEN_ENTRY)
    assert set(payload) == set(facts.ENTRY_FIELDS)
    assert "hash" not in payload
    assert len(payload) == 17


def test_entry_payload_normalises_timestamp_and_ids():
    from datetime import datetime, timezone

    payload = canonical.entry_payload({
        **GOLDEN_ENTRY,
        "ts": datetime(2026, 10, 23, 8, 0, 0, tzinfo=timezone.utc),
        "entry_id": "018f4d0e-0000-7000-8000-000000000001",
    })
    assert payload["ts"] == "2026-10-23T08:00:00.000000Z"
    assert isinstance(payload["entry_id"], str)
    # 同一个时刻的两种写法必须归一到同一字符串（否则 append / verify 会假警报）
    assert canonical.canonical_ts("2026-10-23T16:00:00+08:00") == "2026-10-23T08:00:00.000000Z"


def test_chain_message_is_prev_hash_lf_canonical():
    payload = canonical.entry_payload(GOLDEN_ENTRY)
    message = canonical.chain_message("GENESIS", canonical.canonical_json(payload))
    assert message == b"GENESIS\n" + canonical.canonical_json(payload).encode("utf-8")


def test_golden_hash_vector_is_pinned():
    """已知向量：literal hex 钉死（换实现 / 改分隔符 / 改排序都必须红）。"""
    assert canonical.compute_hash(TEST_KEY, "GENESIS", GOLDEN_ENTRY) == GOLDEN_HASH


def test_golden_hash_matches_independent_recomputation():
    """用 stdlib 独立复算一遍（不经过被测函数），证明算式就是文档里那一条。"""
    payload = {field: GOLDEN_ENTRY[field] for field in facts.ENTRY_FIELDS}
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False)
    message = f"GENESIS\n{canonical_json}".encode("utf-8")
    expected = hmac.new(TEST_KEY, message, hashlib.sha256).hexdigest()
    assert expected == GOLDEN_HASH
    assert canonical.compute_hash(TEST_KEY, "GENESIS", GOLDEN_ENTRY) == expected


@pytest.mark.parametrize("field,value", [
    ("actor", "someone-else"),
    ("role", "REL"),
    ("action", "execute.release"),
    ("target", "网关@1.4.3"),
    ("before", {"window": "open"}),
    ("after", {"window": "closed"}),
    ("reason_code", "R-INCIDENT"),
    ("ticket", "REL-0002"),
    ("evidence", "ops/audit/reports/x.txt"),
    ("status", "recorded"),
    ("seq", 2),
    ("entry_id", "018f4d0e-0000-7000-8000-000000000002"),
    ("ts", "2026-10-23T08:00:01.000000Z"),
    ("approval_chain", [{"actor": "lead", "decision": "approve"}]),
])
def test_any_field_change_changes_the_hash(field, value):
    tampered = dict(GOLDEN_ENTRY)
    tampered[field] = value
    assert canonical.compute_hash(TEST_KEY, "GENESIS", tampered) != GOLDEN_HASH


def test_prev_hash_and_key_change_the_hash():
    assert canonical.compute_hash(TEST_KEY, "0" * 64, GOLDEN_ENTRY) != GOLDEN_HASH
    assert canonical.compute_hash(OTHER_KEY, "GENESIS", GOLDEN_ENTRY) != GOLDEN_HASH


def test_matches_detects_tampering():
    entry = {**GOLDEN_ENTRY, "hash": GOLDEN_HASH}
    assert canonical.matches(TEST_KEY, entry)
    tampered = {**entry, "target": "网关@9.9.9"}
    assert not canonical.matches(TEST_KEY, tampered)
    assert not canonical.matches(OTHER_KEY, entry)


def test_compute_hash_rejects_unsupported_payload_shape():
    with pytest.raises(ValueError):
        canonical.compute_hash(TEST_KEY, "GENESIS", {**GOLDEN_ENTRY, "before": {"x": float("nan")}})


def test_canonical_ts_falls_back_to_raw_text_when_unparseable():
    assert canonical.canonical_ts("not-a-timestamp") == "not-a-timestamp"
    assert canonical.canonical_ts(None) is None
    assert canonical.canonical_ts(123) == 123


def test_error_codes_are_registered():
    """错误码只在 00-conventions §5 段内（M16 段：40001 / 40101 / 40301 / 40901 / 42301 / 5xx）。"""
    assert errors.InvalidArgument("x").code == "40001"
    assert errors.Unauthorized("x").code == "40101"
    assert errors.Forbidden("x").code == "40301"
    assert errors.Conflict("x").code == "40901"
    assert errors.ChainLocked("x").code == "42301"
    assert errors.ChainLocked("x").status_code == 423
    assert errors.ServiceUnavailable("x").status_code == 503
    assert errors.error_type_for(423) == "locked_error"
    assert errors.error_type_for(409) == "conflict_error"
    assert errors.error_type_for(418) == "server_error"
