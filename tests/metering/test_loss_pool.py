# SPDX-License-Identifier: Apache-2.0
"""亏损池：只记「上游已消耗、用户未计费」；去重 / 只追加 / 注入 sink（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid

import psycopg
import pytest

from app.metering import errors, facts, loss_pool
from meterkit import NOW, connect, fetch_all


def test_record_loss_pool_entry(migrated, conn):
    request_id = f"req_{uuid.uuid4().hex[:10]}"
    result = loss_pool.record(conn, request_id=request_id, amount_minor=800,
                              reason="fallback_switch", evidence_ref="bill:row-1", now=NOW)
    assert result["created"] is True
    entry = result["entry"]
    assert entry["amount_minor"] == 800 and entry["reason"] == "fallback_switch"
    assert entry["evidence_ref"] == "bill:row-1"
    rows = fetch_all(migrated, "SELECT count(*) FROM usage_records WHERE request_id = %s",
                     (request_id,))
    assert rows[0][0] == 0                                  # 不写 usage（INV-09）


def test_duplicate_request_attempt_is_not_recorded_twice(migrated, conn):
    request_id = f"req_{uuid.uuid4().hex[:10]}"
    first = loss_pool.record(conn, request_id=request_id, amount_minor=800,
                             reason="fallback_switch", now=NOW)
    second = loss_pool.record(conn, request_id=request_id, amount_minor=900,
                              reason="stream_interrupt", now=NOW)
    assert first["created"] is True and second["created"] is False
    assert second["entry"]["entry_id"] == first["entry"]["entry_id"]
    assert second["entry"]["amount_minor"] == 800           # 首次结果为准


def test_same_request_other_attempt_is_allowed(migrated, conn):
    request_id = f"req_{uuid.uuid4().hex[:10]}"
    first = loss_pool.record(conn, request_id=request_id, attempt_no=1, amount_minor=100,
                             reason="fallback_switch", now=NOW)
    second = loss_pool.record(conn, request_id=request_id, attempt_no=2, amount_minor=200,
                              reason="stream_interrupt", now=NOW)
    assert first["created"] and second["created"]
    assert first["entry"]["entry_id"] != second["entry"]["entry_id"]


@pytest.mark.parametrize("kwargs", [
    {"request_id": "", "amount_minor": 1, "reason": "fallback_switch"},
    {"request_id": "r", "amount_minor": 0, "reason": "fallback_switch"},
    {"request_id": "r", "amount_minor": -5, "reason": "fallback_switch"},
    {"request_id": "r", "amount_minor": 1, "reason": "guessed"},
    {"request_id": "r", "amount_minor": 1, "reason": "fallback_switch", "attempt_no": 0},
    {"request_id": "r", "amount_minor": 1, "reason": "fallback_switch",
     "evidence_ref": "x" * (facts.MAX_EVIDENCE_LEN + 1)},
])
def test_record_validates_inputs(migrated, conn, kwargs):
    with pytest.raises(errors.InvalidArgument):
        loss_pool.record(conn, now=NOW, **kwargs)


def test_loss_pool_is_append_only(migrated, conn):
    result = loss_pool.record(conn, request_id=f"req_{uuid.uuid4().hex[:10]}",
                              amount_minor=100, reason="upstream_consumed", now=NOW)
    entry_id = result["entry"]["entry_id"]
    with pytest.raises(psycopg.Error) as exc:
        conn.execute("UPDATE loss_pool_entries SET amount_minor = 1 WHERE entry_id = %s",
                     (uuid.UUID(entry_id),))
    assert (exc.value.sqlstate or "") == "42501"
    with pytest.raises(psycopg.Error) as delete_exc:
        conn.execute("DELETE FROM loss_pool_entries WHERE entry_id = %s",
                     (uuid.UUID(entry_id),))
    assert (delete_exc.value.sqlstate or "") == "42501"


def test_injected_sink_receives_entry(migrated, conn):
    """sink 是 M06 落 E15 的注入点（M05 不 import 账本、不写分录）。"""
    seen: list[dict] = []
    result = loss_pool.record(conn, request_id=f"req_{uuid.uuid4().hex[:10]}",
                              amount_minor=800, reason="fallback_switch", now=NOW,
                              sink=lambda entry: seen.append(dict(entry)))
    assert seen == [result["entry"]]


def test_sink_hook_roundtrip():
    loss_pool.set_loss_pool_sink(lambda entry: None)
    try:
        assert loss_pool.current_sink() is not None
    finally:
        loss_pool.set_loss_pool_sink(None)
    assert loss_pool.current_sink() is None


def test_loss_pool_does_not_touch_ledger_or_usage(migrated, conn):
    """INV-09：亏损池不冲减 4101、不写 usage（只看表）：本用例锁定「只落 loss_pool_entries」。"""
    request_id = f"req_{uuid.uuid4().hex[:10]}"
    usage_before = fetch_all(migrated, "SELECT count(*) FROM usage_records")[0][0]
    outbox_before = fetch_all(migrated, "SELECT count(*) FROM metering_outbox")[0][0]
    loss_pool.record(conn, request_id=request_id, amount_minor=800, reason="fallback_switch",
                     now=NOW)
    assert fetch_all(migrated, "SELECT count(*) FROM usage_records")[0][0] == usage_before
    assert fetch_all(migrated, "SELECT count(*) FROM metering_outbox")[0][0] == outbox_before
