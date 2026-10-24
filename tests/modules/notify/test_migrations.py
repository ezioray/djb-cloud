# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12 迁移验收：空库 001→1205、12xx 重复执行幂等、回滚两次干净、DB 层护栏。

对应任务卡验收 1：空库全通过 / 1201–1205 连跑两遍幂等 / 回滚两次干净。

性能约定：**前置段很重**（55 个文件），所以只有两条用例跑完整空库升级；
DB 护栏用例复用 ``migrated``（模块级已升级 schema）。
"""
from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg.types.json import Jsonb

from app.notify import migrate as m12_migrate
from notifykit import (
    M12_MIGRATIONS,
    M12_TABLES,
    NOW,
    apply_file,
    apply_migrations,
    connect,
    count,
    m12_migration_files,
    prerequisite_files,
    scalar,
    table_names,
)


def test_segment_is_owned_and_ordered():
    numbers = [int(name.split("_", 1)[0]) for name in M12_MIGRATIONS]
    assert numbers == [1201, 1202, 1203, 1204, 1205]
    assert all(1200 <= number <= 1299 for number in numbers)
    assert m12_migrate.MODULE_MIGRATIONS == M12_MIGRATIONS
    assert not [path for path in prerequisite_files() if 1200 <= int(path.name.split("_")[0])]
    assert m12_migrate.DOWN_SQL[0][0].startswith("1205")


def test_empty_database_upgrades_to_1205(schema):
    applied = apply_migrations(schema)
    assert applied[-5:] == list(M12_MIGRATIONS)
    assert set(M12_TABLES) <= table_names(schema)
    assert all(item["applied"] for item in _status(schema))
    assert {"config_items", "ledger_entry"} <= table_names(schema)   # 前置段对象仍在
    _assert_key_objects(schema)


def test_migrations_are_idempotent_when_repeated(schema):
    apply_migrations(schema)
    for _ in range(2):                                   # 连跑两遍（单文件级幂等）
        for path in m12_migration_files():
            apply_file(schema, path)
    assert set(M12_TABLES) <= table_names(schema)
    _assert_key_objects(schema)


def test_rollback_twice_is_clean_and_reversible(schema):
    apply_migrations(schema)
    for _ in range(2):                                   # 回滚两次都要成功
        results = _down(schema)
        assert [item["rc"] for item in results] == [0] * 5
    assert not set(M12_TABLES) & table_names(schema)
    assert {"config_items", "ledger_entry"} <= table_names(schema)   # 前置对象未被删
    # 回滚后再升级仍然通过（可重复执行）
    apply_migrations(schema, files=list(m12_migration_files()))
    assert set(M12_TABLES) <= table_names(schema)


def test_status_reports_missing_before_and_after(schema):
    assert all(item["applied"] is False for item in _status(schema))
    apply_migrations(schema, files=list(m12_migration_files()))
    assert all(item["applied"] is True for item in _status(schema))
    assert m12_migrate.migration_files()[-5:] == tuple(m12_migration_files())


def _status(schema: str) -> list[dict]:
    conn = connect(schema)
    try:
        return m12_migrate.status(conn)
    finally:
        conn.close()


def _down(schema: str) -> list[dict]:
    conn = connect(schema)
    try:
        return m12_migrate.down(conn)
    finally:
        conn.close()


def _assert_key_objects(schema: str) -> None:
    conn = connect(schema, autocommit=True)
    try:
        assert scalar(conn, """SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema()
                                AND indexname IN ('notifications_dedupe_uq',
                                                  'notifications_source_event_uq',
                                                  'notification_outbox_event_uq',
                                                  'webhook_subscriptions_account_url_uq',
                                                  'delivery_attempts_channel_attempt_uq')""") == 5
        for function in ("m12_notification_guard", "m12_outbox_guard", "m12_webhook_guard",
                         "m12_attempt_immutable", "m12_forbid_truncate"):
            assert scalar(conn, "SELECT count(*) FROM pg_proc WHERE proname = %s",
                          (function,)) == 1
        assert count(conn, "notifications") == 0
    finally:
        conn.close()


# ─────────────────────────────────────────────────── DB 层护栏（绕过 API 也写不进非法数据）
def test_p0_opt_out_true_is_rejected_by_database(migrated):
    conn = connect(migrated)
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO notification_preferences
                           (account_id, email, in_app, webhook, digest, p0_opt_out, updated_at)
                       VALUES (%s, true, true, false, 'realtime', true, now())""",
                    (uuid.uuid4(),))
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO notification_preferences
                       (account_id, email, in_app, webhook, digest, p0_opt_out, updated_at)
                   VALUES (%s, true, true, false, 'realtime', false, now())""",
                (uuid.uuid4(),))
        conn.commit()
    finally:
        conn.close()


def test_notification_guards_reject_bad_rows(migrated):
    conn = connect(migrated)
    account = uuid.uuid4()
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            _insert_notification(conn, account, channels=["email"])      # 缺 in_app（INV-02）
        conn.rollback()
        with pytest.raises(psycopg.errors.CheckViolation):
            _insert_notification(conn, account, channels=["in_app"],
                                 channel_count=2)                        # 计数不自洽（INV-03）
        conn.rollback()
        with pytest.raises(psycopg.errors.CheckViolation):
            _insert_notification(conn, account, channels=["in_app"],
                                 payload={"email": "a@b.co"})             # 零 PII（INV-07）
        conn.rollback()
        _insert_notification(conn, account, channels=["in_app"])
        conn.commit()
        with pytest.raises(psycopg.errors.CheckViolation):                # 跳步状态机
            with conn.cursor() as cur:
                cur.execute("UPDATE notifications SET status = 'delivered' WHERE account_id = %s",
                            (account,))
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):         # 180 天内不可删
            with conn.cursor() as cur:
                cur.execute("DELETE FROM notifications WHERE account_id = %s", (account,))
        conn.rollback()
    finally:
        conn.close()


def test_delivery_attempts_are_append_only(migrated):
    conn = connect(migrated)
    account = uuid.uuid4()
    try:
        notification_id = _insert_notification(conn, account, channels=["in_app"])
        conn.commit()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO delivery_attempts
                       (id, notification_id, channel, attempt_no, status, error_code,
                        provider_ref, latency_ms, occurred_at)
                   VALUES (%s, %s, 'in_app', 1, 'success', NULL, NULL, 3, %s)""",
                (uuid.uuid4(), notification_id, NOW))
        conn.commit()
        for sql in ("UPDATE delivery_attempts SET status = 'permanent'",
                    "DELETE FROM delivery_attempts"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.cursor() as cur:
                    cur.execute(sql)
            conn.rollback()
        with pytest.raises(psycopg.errors.UniqueViolation):               # INV-04 尝试唯一
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO delivery_attempts
                           (id, notification_id, channel, attempt_no, status, error_code,
                            occurred_at)
                       VALUES (%s, %s, 'in_app', 1, 'retryable', 'x_test', %s)""",
                    (uuid.uuid4(), notification_id, NOW))
        conn.rollback()
    finally:
        conn.close()


def test_outbox_guards(migrated):
    conn = connect(migrated)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO notification_outbox
                       (id, event_id, type, occurred_at, producer, aggregate_type,
                        aggregate_id, trace_id, idempotency_key, payload, attempts,
                        next_attempt_at, created_at)
                   VALUES (%s, %s, 'notification.requested', %s, 'M12', 'notification', 'x',
                           'trace-1', 'notification.requested:x', '{}'::jsonb, 0, %s, now())""",
                (uuid.uuid4(), uuid.uuid4(), NOW, NOW))
        conn.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):         # 未发布不可删
            with conn.cursor() as cur:
                cur.execute("DELETE FROM notification_outbox")
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):         # 信封不可改写
            with conn.cursor() as cur:
                cur.execute("UPDATE notification_outbox SET type = 'notification.failed'")
        conn.rollback()
    finally:
        conn.close()


def _insert_notification(conn, account_id, *, channels, channel_count=1, payload=None):
    notification_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO notifications
                   (id, account_id, level, type, template_key, template_scope, payload_ref,
                    channels, channel_count, dedupe_bucket, status, created_at)
               VALUES (%s, %s, 'P1', 'payment.paid', 'customer.payment.paid', 'customer',
                       %s::jsonb, %s, %s, 0, 'queued', %s)""",
            (notification_id, account_id, Jsonb(payload or {}), channels, channel_count,
             NOW))
    return notification_id
