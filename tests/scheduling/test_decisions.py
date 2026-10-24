# SPDX-License-Identifier: AGPL-3.0-or-later
"""决策日志（M04 §3 / §5 / INV-03 / INV-11 / CR-3 归档口径）。

这一组守的是「日志能不能当真凭据」：四元锚点唯一、只追加、写失败即熔断、
12 个月归档口径可算、下钻与窗口查询只读。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.scheduling import clock, decisions, models
from app.scheduling.errors import NotFound


_DEFAULT = object()


def _decision(now, *, snapshot_ts=None, quote_version=1, policy_version="000000000000",
              digest="a" * 64, trace_id="trace-1", attempt_no=1, outcome="routed",
              chosen=_DEFAULT, price_minor=875, fallback_used=False, reason_codes=None,
              candidates=None, eliminated=None, score_breakdown=None):
    return models.Decision(
        decision_id=decisions.decision_id(snapshot_ts or now, quote_version, policy_version,
                                          digest),
        trace_id=trace_id, attempt_no=attempt_no, snapshot_ts=snapshot_ts or now,
        quote_version=quote_version, policy_version=policy_version, request_digest=digest,
        candidates=candidates or [], eliminated=eliminated or [],
        score_breakdown=score_breakdown or [],
        chosen=(chosen if chosen is not _DEFAULT else (
            {"node_id": "n1", "upstream_id": "", "access": "A1", "model": "m1",
             "unit": "token"} if outcome in ("routed", "fallback") else None)),
        tie_break="cost", outcome=outcome, price_minor=price_minor,
        fallback_used=fallback_used, reason_codes=reason_codes or [], decided_at=now)


# --------------------------------------------------------------------------- 锚点
def test_decision_id_is_a_pure_function_of_the_four_anchors(now):
    first = decisions.decision_id(now, 3, "abcdefabcdef", "a" * 64)
    second = decisions.decision_id(now, 3, "abcdefabcdef", "a" * 64)
    assert first == second
    assert first.version == 5                                  # UUIDv5（确定性派生）

    assert first != decisions.decision_id(now, 4, "abcdefabcdef", "a" * 64)
    assert first != decisions.decision_id(now, 3, "000000000000", "a" * 64)
    assert first != decisions.decision_id(now, 3, "abcdefabcdef", "b" * 64)
    assert first != decisions.decision_id(now + timedelta(seconds=1), 3,
                                          "abcdefabcdef", "a" * 64)


def test_request_digest_excludes_trace_and_attempt(now, tenant):
    from app.scheduling import candidates

    base = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                 trace_id="trace-1")
    other = candidates.RouteInput(model="m1", kind="realtime", tenant_id=tenant,
                                  trace_id="trace-2", attempt_no=2)
    assert decisions.request_digest(base) == decisions.request_digest(other)
    assert len(decisions.request_digest(base)) == 64

    different = candidates.RouteInput(model="m2", kind="realtime", tenant_id=tenant,
                                      trace_id="trace-1")
    assert decisions.request_digest(base) != decisions.request_digest(different)


def test_request_digest_accepts_plain_mapping():
    assert decisions.request_digest({"model": "m1"}) == decisions.request_digest({"model": "m1"})


# --------------------------------------------------------------------------- 写入 / 幂等
def test_record_inserts_once_per_anchor(conn, now, tenant):
    record = _decision(now)
    stored, created = decisions.record(conn, record)
    assert created is True
    assert stored.decision_id == record.decision_id

    again, created_again = decisions.record(conn, record)
    assert created_again is False
    assert again.decision_id == record.decision_id
    assert conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0] == 1


def test_record_keeps_the_first_decision_for_the_same_anchor(conn, now, tenant):
    first = _decision(now, price_minor=875)
    decisions.record(conn, first)
    # 同锚点但内容不同（模拟重放 / 竞态）→ 读回第一条，不覆盖
    second = _decision(now, price_minor=999, chosen={"node_id": "n2", "upstream_id": "",
                                                     "access": "A1", "model": "m1",
                                                     "unit": "token"})
    stored, created = decisions.record(conn, second)
    assert created is False
    assert stored.price_minor == 875
    assert stored.chosen_node_id == "n1"


def test_trace_attempt_uniqueness(conn, now):
    decisions.record(conn, _decision(now, digest="a" * 64))
    # 同 trace + 同 attempt，但锚点不同（不同 digest）→ 违反 (trace_id, attempt_no) 唯一
    with pytest.raises(Exception):
        decisions.record(conn, _decision(now, digest="b" * 64))


def test_attempt_no_must_be_one_or_two(conn, now):
    with pytest.raises(Exception):
        decisions.record(conn, _decision(now, attempt_no=3))
    conn.rollback()                                    # DB 报错后事务已中止，先复位
    stored, _ = decisions.record(conn, _decision(now, attempt_no=2, trace_id="trace-2"))
    assert stored.attempt_no == 2


# --------------------------------------------------------------------------- 只追加
def test_decision_log_rejects_update(conn, now):
    stored, _ = decisions.record(conn, _decision(now))
    with pytest.raises(Exception):
        conn.execute("UPDATE routing_decisions SET price_minor = 1 WHERE decision_id = %s",
                     (stored.decision_id,))


def test_decision_log_rejects_delete_without_archive_flag(conn, now):
    stored, _ = decisions.record(conn, _decision(now))
    with pytest.raises(Exception):
        conn.execute("DELETE FROM routing_decisions WHERE decision_id = %s",
                     (stored.decision_id,))


def test_decision_log_allows_archive_delete_with_flag(conn, now):
    """12 个月归档：只有显式 ``SET LOCAL m04.archive = 'on'`` 的作业能删（CR-3）。"""
    stored, _ = decisions.record(conn, _decision(now))
    with pytest.raises(Exception):
        with conn.transaction():
            conn.execute("SET LOCAL m04.archive = 'on'")
            conn.execute("DELETE FROM routing_decisions WHERE decision_id = %s",
                         (stored.decision_id,))
            raise RuntimeError("rollback")
    conn.execute("SET LOCAL m04.archive = 'on'")
    conn.execute("DELETE FROM routing_decisions WHERE decision_id = %s", (stored.decision_id,))
    assert conn.execute("SELECT count(*) FROM routing_decisions").fetchone()[0] == 0


# --------------------------------------------------------------------------- 约束
def test_chosen_required_only_for_routed_outcomes(conn, now):
    with pytest.raises(Exception):
        decisions.record(conn, _decision(now, outcome="routed", chosen=None, price_minor=1))
    conn.rollback()
    # rejected 不能带 chosen（不制造假落点）
    with pytest.raises(Exception):
        decisions.record(conn, _decision(now, outcome="rejected",
                                        chosen={"node_id": "n1", "upstream_id": "",
                                                "access": "A1", "model": "m1",
                                                "unit": "token"}))


def test_outcome_enum_is_enforced(conn, now):
    bad = _decision(now, outcome="routed")
    bad.outcome = "dispatched"
    with pytest.raises(Exception):
        decisions.record(conn, bad)


# --------------------------------------------------------------------------- 查询
def test_get_and_find_anchor(conn, now):
    stored, _ = decisions.record(conn, _decision(now))
    assert decisions.get(conn, stored.decision_id).decision_id == stored.decision_id
    assert decisions.get(conn, str(stored.decision_id)).decision_id == stored.decision_id

    found = decisions.find_anchor(conn, snapshot_ts=now, quote_version=1,
                                  policy_version="000000000000", digest="a" * 64)
    assert found is not None and found.decision_id == stored.decision_id
    assert decisions.find_anchor(conn, snapshot_ts=now, quote_version=9,
                                 policy_version="000000000000", digest="a" * 64) is None
    with pytest.raises(NotFound):
        decisions.get(conn, str(uuid.uuid4()))
    with pytest.raises(NotFound):
        decisions.get(conn, "not-a-uuid")


def test_window_filters_by_time_and_ids(conn, now):
    early = _decision(now - timedelta(minutes=5), trace_id="t-early", digest="c" * 64)
    late = _decision(now, trace_id="t-late", digest="d" * 64)
    early.decided_at = now - timedelta(minutes=5)
    late.decided_at = now
    decisions.record(conn, early)
    decisions.record(conn, late)

    found = decisions.window(conn, from_ts=now - timedelta(minutes=10),
                              to_ts=now + timedelta(minutes=1))
    assert [item.trace_id for item in found] == ["t-early", "t-late"]

    narrowed = decisions.window(conn, from_ts=now - timedelta(minutes=10),
                                to_ts=now + timedelta(minutes=1),
                                decision_ids=[str(late.decision_id)])
    assert [item.trace_id for item in narrowed] == ["t-late"]


def test_count_by_outcome(conn, now):
    decisions.record(conn, _decision(now, digest="e" * 64))
    rejected = _decision(now, digest="f" * 64, outcome="rejected", trace_id="trace-r")
    decisions.record(conn, rejected)
    counts = decisions.count_by_outcome(conn, from_ts=now - timedelta(minutes=1),
                                        to_ts=now + timedelta(minutes=1))
    assert counts == {"routed": 1, "rejected": 1}


def test_replay_anchor_echoes_the_four_values(conn, now):
    stored, _ = decisions.record(conn, _decision(now))
    anchor = decisions.replay_anchor(stored)
    assert set(anchor) == {"snapshot_ts", "quote_version", "policy_version", "request_digest"}
    assert anchor["quote_version"] == 1


# --------------------------------------------------------------------------- 归档口径
def test_retention_cutoff_is_twelve_months():
    """CR-3 / M04 §5：决策日志保留 12 个月。"""
    moment = datetime(2026, 10, 23, tzinfo=timezone.utc)
    assert decisions.retention_cutoff(moment) == datetime(2025, 10, 23, tzinfo=timezone.utc)
    # 闰日兜底
    assert decisions.retention_cutoff(datetime(2028, 2, 29, tzinfo=timezone.utc)) \
        == datetime(2027, 2, 28, tzinfo=timezone.utc)


def test_archive_candidates_lists_only_expired_records(conn, now):
    old = _decision(now - timedelta(days=400), trace_id="t-old", digest="1" * 64)
    old.decided_at = now - timedelta(days=400)
    fresh = _decision(now, trace_id="t-new", digest="2" * 64)
    decisions.record(conn, old)
    decisions.record(conn, fresh)

    pending = decisions.archive_candidates(conn, now=now)
    assert [item.trace_id for item in pending] == ["t-old"]
