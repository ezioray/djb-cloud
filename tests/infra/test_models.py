# SPDX-License-Identifier: AGPL-3.0-or-later
"""请求解析（纯函数）：形态 / 枚举 / 长度 / 审批链结构 / 幂等指纹。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.audit import errors, facts, models

NOW = datetime(2026, 10, 23, 8, 0, 0, tzinfo=timezone.utc)

BODY = {"actor": "infra-seat", "actor_type": "agent", "role": "INFRA",
        "action": "read.report", "target": "nas/guard"}


def test_draft_defaults():
    draft = models.draft_from_request(BODY, now=NOW)
    assert draft["status"] == facts.DEFAULT_STATUS
    assert draft["alg"] == facts.ALG
    assert draft["approval_chain"] == []
    assert draft["before"] is None and draft["after"] is None
    assert draft["reason_code"] is None and draft["ticket"] is None


def test_draft_rejects_non_object_body():
    with pytest.raises(errors.InvalidArgument) as excinfo:
        models.draft_from_request(["not", "an", "object"], now=NOW)
    assert excinfo.value.reason == "malformed_json"


@pytest.mark.parametrize("field", ["actor", "actor_type", "role", "action", "target"])
def test_draft_requires_every_mandatory_field(field):
    body = dict(BODY)
    body.pop(field)
    with pytest.raises(errors.InvalidArgument) as excinfo:
        models.draft_from_request(body, now=NOW)
    assert field in excinfo.value.message


@pytest.mark.parametrize("field,value", [("actor", 123), ("actor", ""),
                                         ("actor", "x" * 300), ("target", " "),
                                         ("role", "y" * 80), ("action", "z" * 80)])
def test_draft_rejects_bad_text_fields(field, value):
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, **{field: value}), now=NOW)


def test_draft_rejects_unknown_enums():
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, actor_type="robot"), now=NOW)
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, status="done"), now=NOW)
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, alg="sha256"), now=NOW)


def test_draft_requires_before_after_to_be_objects():
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, before=["a"]), now=NOW)
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, after="closed"), now=NOW)


def test_draft_rejects_non_string_evidence():
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, evidence=["a", "b"]), now=NOW)


def test_draft_accepts_optional_fields():
    draft = models.draft_from_request(
        dict(BODY, before={"a": 1}, after={"a": 2}, reason_code="R-OK", ticket="REL-0001",
             evidence="ops/audit/reports/x.txt", status="approved",
             approval_chain=[{"actor": "lead", "decision": "propose", "role": "LEAD",
                              "at": "2026-10-23T08:00:00Z"},
                             {"actor": "release-manager", "decision": "approve"}]),
        now=NOW)
    assert draft["before"] == {"a": 1}
    assert draft["approval_chain"][0] == {"actor": "lead", "decision": "propose", "role": "LEAD",
                                          "at": "2026-10-23T08:00:00Z"}


@pytest.mark.parametrize("chain", [
    "not-a-list",
    ["not-an-object"],
    [{"decision": "approve"}],
    [{"actor": "lead", "decision": "maybe"}],
    [{"actor": "lead", "decision": "approve", "role": 5}],
    [{"actor": "lead", "decision": "approve", "at": 5}],
])
def test_approval_chain_structure_is_validated(chain):
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, approval_chain=chain), now=NOW)


def test_approval_chain_length_is_capped():
    chain = [{"actor": f"person-{index}", "decision": "approve"}
             for index in range(facts.MAX_CHAIN_ITEMS + 1)]
    with pytest.raises(errors.InvalidArgument):
        models.draft_from_request(dict(BODY, approval_chain=chain), now=NOW)


def test_parse_period():
    assert models.parse_period(None, default_day="2026-10-23") == "2026-10-23"
    assert models.parse_period("  ", default_day="2026-10-23") == "2026-10-23"
    assert models.parse_period("2026-10-20", default_day="2026-10-23") == "2026-10-20"
    for bad in ("2026-13-01", "2026-1-1", 20261020, "2026-10-23T00:00:00Z"):
        with pytest.raises(errors.InvalidArgument):
            models.parse_period(bad, default_day="2026-10-23")


def test_fingerprint_is_stable_within_window_and_changes_across_windows():
    first = models.fingerprint_request(BODY, now=NOW)
    same_window = models.fingerprint_request(BODY, now=NOW + timedelta(seconds=30))
    next_window = models.fingerprint_request(
        BODY, now=NOW + timedelta(seconds=facts.FINGERPRINT_WINDOW_S + 1))
    assert first == same_window
    assert first != next_window
    assert first.startswith("fp:") and len(first) <= facts.MAX_IDEMPOTENCY_LEN
    assert models.fingerprint_request(dict(BODY, target="other"), now=NOW) != first


def test_request_core_ignores_chain_fields():
    draft = models.draft_from_request(BODY, now=NOW)
    core = models.request_core(dict(draft, seq=7, hash="a" * 64, prev_hash="GENESIS"))
    assert "seq" not in core and "hash" not in core and "prev_hash" not in core
    assert core["actor"] == "infra-seat"


def test_uuid7_is_time_ordered_and_versioned():
    first = models.uuid7(NOW)
    later = models.uuid7(NOW + timedelta(milliseconds=2))
    assert str(first)[14] == "7"
    assert int(str(first).replace("-", "")[16], 16) in range(8, 12)   # 变体位 10xx
    assert str(first) < str(later)


def test_utc_from_epoch():
    assert models.utc_from_epoch(NOW.timestamp()) == NOW
