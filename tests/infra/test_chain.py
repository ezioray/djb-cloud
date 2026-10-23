# SPDX-License-Identifier: Apache-2.0
"""链校验内核（纯函数）：篡改必报 / 断链定位 / 算法降级 / 字段完整 / 自批 / pending 超时。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.audit import canonical, chain, facts
from infrakit import OTHER_KEY, TEST_KEY

NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)


def make_entry(seq: int, prev_hash: str, *, key: bytes = TEST_KEY, **overrides) -> dict:
    entry = {
        "seq": seq,
        "entry_id": f"018f4d0e-0000-7000-8000-0000000000{seq:02d}",
        "ts": (NOW - timedelta(minutes=seq)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "actor": "infra-seat",
        "actor_type": "agent",
        "role": "INFRA",
        "action": "read.report",
        "target": "nas/guard",
        "before": None,
        "after": None,
        "reason_code": None,
        "ticket": None,
        "evidence": None,
        "approval_chain": [],
        "status": "recorded",
        "alg": facts.ALG,
        "prev_hash": prev_hash,
    }
    entry.update(overrides)
    entry["hash"] = canonical.compute_hash(key, prev_hash, entry)
    return entry


def make_chain(count: int = 3, *, key: bytes = TEST_KEY, **overrides) -> list[dict]:
    entries: list[dict] = []
    prev = facts.GENESIS
    for seq in range(1, count + 1):
        item = make_entry(seq, prev, key=key, **overrides)
        entries.append(item)
        prev = item["hash"]
    return entries


def test_clean_chain_passes():
    report = chain.verify_entries(make_chain(3), key=TEST_KEY, now=NOW)
    assert report.ok, report.all_problems()
    assert report.entries == 3
    assert report.broken_seq is None
    assert report.expired_pending == 0


def test_tampered_content_is_reported_with_broken_seq():
    entries = make_chain(3)
    entries[1]["target"] = "tampered"
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert not report.ok
    assert report.broken_seq == 2
    assert any("哈希不匹配" in problem for problem in report.problems)


def test_tampered_prev_hash_breaks_the_link():
    entries = make_chain(3)
    entries[2]["prev_hash"] = "0" * 64
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert not report.ok
    assert report.broken_seq == 3
    assert any("prev_hash 断链" in problem for problem in report.problems)


def test_first_entry_must_point_to_genesis():
    entries = make_chain(2)
    entries[0]["prev_hash"] = "f" * 64
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert report.broken_seq == 1
    assert any("GENESIS" in problem or "prev_hash" in problem for problem in report.problems)


def test_algorithm_downgrade_is_reported():
    entries = make_chain(2)
    entries[1]["alg"] = "sha256"
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert not report.ok
    assert report.broken_seq == 2
    assert any("算法不一致" in problem for problem in report.problems)


def test_wrong_key_reports_hash_mismatch():
    entries = make_chain(2)
    report = chain.verify_entries(entries, key=OTHER_KEY, now=NOW)
    assert not report.ok
    assert report.broken_seq == 1


def test_missing_key_fails_closed_without_raising():
    report = chain.verify_entries(make_chain(2), key=None, now=NOW)
    assert not report.key_available
    assert not report.ok
    assert any("密钥不可用" in problem for problem in report.problems)
    assert report.broken_seq is None                 # 密钥问题不是"断链位置"


def test_expected_alg_mismatch_is_reported():
    report = chain.verify_entries(make_chain(1), key=TEST_KEY, expected_alg="sha256", now=NOW)
    assert not report.ok


def test_high_risk_entry_without_required_fields_is_a_gap():
    entries = make_chain(1, action="authorize.window", reason_code=None)
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert not report.ok
    assert any("reason_code" in gap for gap in report.field_gaps)


def test_high_risk_entry_with_complete_fields_passes():
    entries = make_chain(
        1, action="authorize.window", target="REL-0001", reason_code="R-OK", ticket="REL-0001",
        before={"window": "closed"}, after={"window": "open"}, status="approved",
        approval_chain=[{"actor": "lead", "decision": "propose"},
                        {"actor": "release-manager", "decision": "approve"}])
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert report.ok, report.all_problems()


def test_self_approval_is_reported():
    entries = make_chain(
        1, action="authorize.window", reason_code="R-OK", ticket="REL-0001",
        before={"a": 1}, after={"a": 2}, status="approved",
        approval_chain=[{"actor": "lead", "decision": "propose"},
                        {"actor": "lead", "decision": "approve"}])
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert not report.ok
    assert any("自批自核" in problem for problem in report.approval_problems)


def test_pending_approval_past_deadline_is_reported():
    entries = make_chain(
        1, action="authorize.window", reason_code="R-OK", ticket="REL-0001",
        before={"a": 1}, after={"a": 2}, status="pending_approval",
        approval_chain=[{"actor": "lead", "decision": "propose"},
                        {"actor": "release-manager", "decision": "approve"}])
    late = NOW + timedelta(hours=5)
    report = chain.verify_entries(entries, key=TEST_KEY, now=late)
    assert report.expired_pending == 1
    assert any("超时" in problem for problem in report.problems)
    assert not report.ok


def test_pending_approval_within_window_is_ok():
    entries = make_chain(
        1, action="authorize.window", reason_code="R-OK", ticket="REL-0001",
        before={"a": 1}, after={"a": 2}, status="pending_approval",
        approval_chain=[{"actor": "lead", "decision": "propose"},
                        {"actor": "release-manager", "decision": "approve"}])
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW + timedelta(hours=1))
    assert report.expired_pending == 0
    assert report.ok, report.all_problems()


def test_unparseable_timestamp_is_a_gap():
    entries = make_chain(1)
    entries[0]["ts"] = "yesterday"
    # ts 参与哈希，改了要重算，否则先报哈希不匹配（这里专门测"时间不可解析"这一条）
    entries[0]["hash"] = canonical.compute_hash(TEST_KEY, facts.GENESIS, entries[0])
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert any("ts 不可解析" in gap for gap in report.field_gaps)


def test_unserialisable_payload_is_reported_not_raised():
    entries = make_chain(1)
    entries[0]["before"] = {"x": float("nan")}
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW)
    assert not report.ok
    assert any("无法重算" in problem for problem in report.problems)


def test_custom_pending_timeout_is_honoured():
    entries = make_chain(
        1, action="authorize.window", reason_code="R-OK", ticket="REL-0001",
        before={"a": 1}, after={"a": 2}, status="pending_approval",
        approval_chain=[{"actor": "lead", "decision": "propose"},
                        {"actor": "release-manager", "decision": "approve"}])
    report = chain.verify_entries(entries, key=TEST_KEY, now=NOW + timedelta(hours=2),
                                  pending_timeout=timedelta(hours=1))
    assert report.expired_pending == 1


def test_report_all_problems_is_flat_list_of_strings():
    entries = make_chain(2)
    entries[0]["action"] = "authorize.window"
    report = chain.verify_entries(entries, key=None, now=NOW)
    problems = report.all_problems()
    assert problems and all(isinstance(item, str) for item in problems)


@pytest.mark.parametrize("count", [0, 1, 5])
def test_chain_lengths(count):
    report = chain.verify_entries(make_chain(count), key=TEST_KEY, now=NOW)
    assert report.entries == count
    assert report.ok
