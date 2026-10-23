# SPDX-License-Identifier: Apache-2.0
"""outbox：同事务入队 / 至少一次派发 / 退避 / 死信 / 保留期（迁移 506，需要 DJB_DSN）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import psycopg
import pytest

from app.metering import events, facts, outbox
from meterkit import NOW, connect, fetch_all


def _envelope(*, usage_id: str | None = None, trace_id: str = "trace-outbox",
              amount_minor: int = 125) -> dict:
    return events.usage_recorded_event(usage_id=usage_id or f"u_{uuid.uuid4().hex[:10]}",
                                       account_id=str(uuid.uuid4()), request_id="req-1",
                                       amount_minor=amount_minor, source="dual",
                                       trace_id=trace_id, occurred_at=NOW)


def _row(schema: str, event_id: str) -> tuple:
    rows = fetch_all(schema, """SELECT type, attempts, published_at, last_error, payload
                                  FROM metering_outbox WHERE event_id = %s""", (event_id,))
    return rows[0] if rows else ()


# ─────────────────────────────────────────────────────── 入队 / 幂等
def test_append_writes_pending_row(migrated, conn):
    envelope = _envelope()
    assert outbox.append(conn, envelope) is True
    row = _row(migrated, envelope["event_id"])
    assert row[0] == "usage.recorded" and row[1] == 0 and row[2] is None
    assert row[4]["amount_minor"] == 125


def test_append_is_idempotent_by_idempotency_key(migrated, conn):
    envelope = _envelope(usage_id="u_idem_1")
    assert outbox.append(conn, envelope) is True
    # 同事实重放（即使 event_id 不同，业务幂等键相同）→ 不重复入队
    replay = dict(envelope, event_id=str(uuid.uuid4()))
    assert outbox.append(conn, replay) is False
    rows = fetch_all(migrated, "SELECT count(*) FROM metering_outbox WHERE aggregate_id = %s",
                     ("u_idem_1",))
    assert rows[0][0] == 1


def test_append_rolls_back_with_business_transaction(migrated):
    """CR-5 核心：事件与业务同事务——事务回滚则事件不存在。"""
    envelope = _envelope(usage_id="u_rollback_1")
    connection = connect(migrated, autocommit=False)
    try:
        outbox.append(connection, envelope)
        assert fetch_all(migrated, "SELECT count(*) FROM metering_outbox WHERE aggregate_id = %s",
                         ("u_rollback_1",))[0][0] == 0      # 未提交：别的连接看不到
        connection.rollback()
    finally:
        connection.close()
    assert fetch_all(migrated, "SELECT count(*) FROM metering_outbox WHERE aggregate_id = %s",
                     ("u_rollback_1",))[0][0] == 0


# ─────────────────────────────────────────────────────── 派发
def test_dispatch_publishes_and_marks(migrated, conn):
    envelope = _envelope()
    outbox.append(conn, envelope)
    seen: list[tuple[str, dict]] = []
    result = outbox.dispatch(conn, publisher=lambda event_type, body: seen.append((event_type, body)),
                             now=NOW)
    assert result["published"] >= 1
    assert any(item[1]["event_id"] == envelope["event_id"] for item in seen)
    assert _row(migrated, envelope["event_id"])[2] is not None      # published_at 已写


def test_dispatch_failure_backs_off_without_raising(migrated, conn):
    envelope = _envelope()
    outbox.append(conn, envelope)
    now = NOW

    def boom(event_type, body):
        raise RuntimeError("consumer down")

    result = outbox.dispatch(conn, publisher=boom, now=now)
    assert result["failed"] >= 1 and result["published"] == 0
    type_, attempts, published_at, last_error, _ = _row(migrated, envelope["event_id"])
    assert attempts == 1 and published_at is None
    assert "consumer down" in (last_error or "")
    # 退避：下次重试在 1s 之后，此刻再派发不会重试
    later = outbox.dispatch(conn, publisher=boom, now=now + timedelta(seconds=0.5))
    assert later["failed"] == 0
    retried = outbox.dispatch(conn, publisher=boom, now=now + timedelta(seconds=2))
    assert retried["failed"] >= 1


def test_dispatch_reaches_dead_letter_after_max_attempts(migrated, conn):
    envelope = _envelope()
    outbox.append(conn, envelope)
    moment = NOW

    def boom(event_type, body):
        raise RuntimeError("still down")

    for _ in range(facts.EVENT_MAX_ATTEMPTS):
        outbox.dispatch(conn, publisher=boom, now=moment)
        moment = moment + timedelta(seconds=facts.EVENT_BACKOFF_S[-1])
    attempts = _row(migrated, envelope["event_id"])[1]
    assert attempts == facts.EVENT_MAX_ATTEMPTS
    # 死信后不再前进（next_attempt_at 停在原地，等人工重放）
    outbox.dispatch(conn, publisher=boom, now=moment + timedelta(days=1))
    assert _row(migrated, envelope["event_id"])[1] == facts.EVENT_MAX_ATTEMPTS


def test_dispatch_refuses_to_run_inside_open_transaction(migrated):
    """防止「事务还没提交就把事件发出去」的幻影事件。"""
    connection = connect(migrated, autocommit=False)
    try:
        connection.execute("SELECT 1")
        with pytest.raises(RuntimeError):
            outbox.dispatch(connection)
        connection.rollback()
    finally:
        connection.close()


def test_pending_orders_by_next_attempt(migrated, conn):
    envelope = _envelope(usage_id=f"u_order_{uuid.uuid4().hex[:6]}")
    outbox.append(conn, envelope)
    pending = outbox.pending(conn, limit=facts.OUTBOX_PENDING_PAGE_DEFAULT, now=NOW)
    assert any(item["event_id"] == envelope["event_id"] for item in pending)
    keys = [(item["next_attempt_at"], item["occurred_at"]) for item in pending]
    assert keys == sorted(keys)                                  # 队列有序
    ours = next(item for item in pending if item["event_id"] == envelope["event_id"])
    assert ours["payload"]["amount_minor"] == 125


# ─────────────────────────────────────────────────────── 保留期 / 护栏
def test_purge_only_removes_published_rows_past_retention(migrated):
    published_old = _envelope(usage_id=f"u_purge_old_{uuid.uuid4().hex[:6]}")
    published_new = _envelope(usage_id=f"u_purge_new_{uuid.uuid4().hex[:6]}")
    pending_row = _envelope(usage_id=f"u_purge_pending_{uuid.uuid4().hex[:6]}")
    with connect(migrated, autocommit=False) as connection:
        for envelope in (published_old, published_new, pending_row):
            outbox.append(connection, envelope)
        connection.commit()
        # 用**数据库时钟**做基准，避免固定 NOW 与墙上时间漂移导致用例过期
        db_now = connection.execute("SELECT now()").fetchone()[0]
        connection.execute("UPDATE metering_outbox SET published_at = %s WHERE event_id = %s",
                           (db_now - timedelta(days=facts.OUTBOX_PUBLISHED_RETENTION_DAYS + 1),
                            uuid.UUID(published_old["event_id"])))
        connection.execute("UPDATE metering_outbox SET published_at = %s WHERE event_id = %s",
                           (db_now, uuid.UUID(published_new["event_id"])))
        connection.commit()
        removed = outbox.purge_published(connection, now=db_now)
        connection.commit()
    assert removed == 1
    ids = {row[0] for row in fetch_all(migrated, "SELECT event_id FROM metering_outbox")}
    assert str(published_old["event_id"]) not in {str(i) for i in ids}
    assert str(published_new["event_id"]) in {str(i) for i in ids}
    assert str(pending_row["event_id"]) in {str(i) for i in ids}


def test_outbox_envelope_is_immutable(migrated, conn):
    envelope = _envelope()
    outbox.append(conn, envelope)
    with pytest.raises(psycopg.Error) as exc:
        conn.execute("UPDATE metering_outbox SET payload = '{}'::jsonb WHERE event_id = %s",
                     (uuid.UUID(envelope["event_id"]),))
    assert (exc.value.sqlstate or "") == "42501"
    with pytest.raises(psycopg.Error) as delete_exc:
        conn.execute("DELETE FROM metering_outbox WHERE event_id = %s",
                     (uuid.UUID(envelope["event_id"]),))
    assert (delete_exc.value.sqlstate or "") == "42501"


def test_outbox_insert_guard_requires_pending(migrated, conn):
    envelope = _envelope()
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO metering_outbox
                 (event_id, type, version, occurred_at, producer, aggregate_type, aggregate_id,
                  trace_id, idempotency_key, payload, attempts, next_attempt_at, published_at)
               VALUES (%s,'usage.recorded',1,%s,'M05','usage_record','u1','t1','k1','{}'::jsonb,
                       0,%s,%s)""",
            (uuid.uuid4(), NOW, NOW, NOW))


def test_outbox_type_whitelist(migrated, conn):
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO metering_outbox
                 (event_id, type, version, occurred_at, producer, aggregate_type, aggregate_id,
                  trace_id, idempotency_key, payload, attempts, next_attempt_at)
               VALUES (%s,'usage.exploded',1,%s,'M05','usage_record','u1','t1','k2','{}'::jsonb,
                       0,%s)""",
            (uuid.uuid4(), NOW, NOW))
