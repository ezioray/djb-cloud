# SPDX-License-Identifier: AGPL-3.0-or-later
"""事件 outbox：同事务入队 / 幂等 / 退避重试 / 死信（02-events §2）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import psycopg
import pytest

from app.notify import outbox
from app.notify.models import OutboxEvent
from notifykit import NOW, connect, count, scalar


def _event(*, event_id=None, key=None, **payload) -> OutboxEvent:
    notification_id = str(uuid.uuid4())
    return OutboxEvent(
        event_id=event_id or uuid.uuid4(), type="notification.requested",
        occurred_at=NOW, aggregate_id=notification_id,
        payload={"notification_id": notification_id, **payload})


def test_enqueue_is_idempotent_by_event_id(m12_only):
    conn = connect(m12_only)
    try:
        event = _event()
        assert outbox.enqueue(conn, event, now=NOW) is True
        conn.commit()
        assert outbox.enqueue(conn, event, now=NOW) is False      # 同 event_id 不重复
        conn.commit()
        assert count(conn, "notification_outbox") == 1
    finally:
        conn.close()


def test_enqueue_rejects_pii_payload(m12_only):
    conn = connect(m12_only)
    try:
        with pytest.raises(ValueError):
            outbox.enqueue(conn, _event(email="a@b.co"), now=NOW)
        conn.rollback()
    finally:
        conn.close()


def test_pending_only_returns_due_rows(m12_only):
    conn = connect(m12_only)
    try:
        outbox.enqueue(conn, _event(), now=NOW)
        conn.commit()
        assert len(outbox.pending(conn, now=NOW)) == 1
        assert outbox.pending(conn, now=NOW - timedelta(seconds=1)) == []
    finally:
        conn.close()


def test_dispatch_publishes_pending_rows(m12_only):
    conn = connect(m12_only)
    seen = []
    try:
        outbox.enqueue(conn, _event(), now=NOW)
        conn.commit()
        summary = outbox.dispatch(conn, seen.append, now=NOW)
        conn.commit()
        assert summary == {"published": 1, "retried": 0, "dead": 0, "scanned": 1}
        assert len(seen) == 1 and seen[0]["type"] == "notification.requested"
        assert scalar(conn, "SELECT (published_at IS NOT NULL) FROM notification_outbox") is True
        assert outbox.dispatch(conn, seen.append, now=NOW)["scanned"] == 0
    finally:
        conn.close()


def test_dispatch_retries_with_backoff(m12_only):
    conn = connect(m12_only)
    try:
        outbox.enqueue(conn, _event(), now=NOW)

        def boom(_envelope):
            raise RuntimeError("downstream down")

        summary = outbox.dispatch(conn, boom, now=NOW)
        conn.commit()
        assert summary["retried"] == 1
        row = conn.execute("SELECT attempts, next_attempt_at, last_error "
                           "FROM notification_outbox").fetchone()
        assert row[0] == 1
        assert row[1] == NOW + timedelta(seconds=1)          # 02-events §2.3 第一次退避 1s
        assert row[2] == "RuntimeError"
        # 没到点不会重试
        assert outbox.dispatch(conn, boom, now=NOW)["scanned"] == 0
        # 到点后第二次退避 5s
        second = outbox.dispatch(conn, boom, now=NOW + timedelta(seconds=1))
        conn.commit()
        assert second["retried"] == 1
        assert conn.execute("SELECT next_attempt_at FROM notification_outbox").fetchone()[0] == (
            NOW + timedelta(seconds=6))
    finally:
        conn.close()


def test_eight_failures_send_to_dead_letter(m12_only):
    conn = connect(m12_only)
    try:
        outbox.enqueue(conn, _event(), now=NOW)
        conn.commit()

        def boom(_envelope):
            raise RuntimeError("still down")

        moment = NOW
        for _ in range(8):
            outbox.dispatch(conn, boom, now=moment)
            conn.commit()
            moment = moment + timedelta(seconds=1800)
        assert outbox.dead_letters(conn) == 1
        assert outbox.pending(conn, now=moment) == []          # 死信不再自动重试
        error = scalar(conn, "SELECT last_error FROM notification_outbox")
        assert error.startswith("dlq:")
    finally:
        conn.close()


def test_published_rows_may_be_pruned_after_retention(m12_only):
    conn = connect(m12_only)
    try:
        outbox.enqueue(conn, _event(), now=NOW)
        conn.commit()
        outbox.dispatch(conn, lambda _envelope: None, now=NOW)
        conn.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM notification_outbox")   # 30 天内不可删
        conn.rollback()
        conn.execute("UPDATE notification_outbox SET published_at = %s",
                     (NOW - timedelta(days=31),))
        conn.commit()
        conn.execute("DELETE FROM notification_outbox")
        conn.commit()
        assert count(conn, "notification_outbox") == 0
    finally:
        conn.close()
