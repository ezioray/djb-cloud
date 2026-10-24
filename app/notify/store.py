# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12 持久化（notifications / delivery_attempts）。**只有 SQL，没有业务判定。**

约定：

* 每个函数都显式收 ``conn``（连接由调用方/路由工厂注入，事务边界在调用方）；
* 所有按账户的查询都带 ``account_id`` 条件——账户隔离写在 SQL 里，不靠上层自觉
  （越权一律「查不到」，路由再翻成 ``40401``，避免枚举他人通知是否存在）；
* 合并去重（INV-03）与事件幂等（02-events §5）用**数据库唯一索引 + ON CONFLICT** 兜底，
  应用层只决定「合并还是新建」，并发下不会落两条。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Mapping

from psycopg.rows import dict_row

from . import errors
from .models import DeliveryAttempt, Notification, as_uuid

__all__ = [
    "dict_cursor", "find_by_source_event", "find_by_dedupe", "insert_notification",
    "bump_merged", "get_notification", "insert_attempt", "attempts_for", "claim_batch",
    "finish", "attempts_count", "row_to_notification",
]

_NOTIFICATION_COLUMNS = """id, account_id, level, type, template_key, template_scope,
    payload_ref, channels, channel_count, dedupe_bucket, source_event_id, merged_event_ids,
    status, created_at, sent_at, read_at"""


def dict_cursor(conn: Any) -> Any:
    """字典行 cursor（与 ``tests`` 里的连接工厂保持同一口径）。"""
    return conn.cursor(row_factory=dict_row)


def row_to_notification(row: Mapping[str, Any]) -> Notification:
    return Notification.from_row(row)


def find_by_source_event(conn: Any, event_id: uuid.UUID | str) -> Notification | None:
    """事件幂等（02-events §5）：``source_event_id`` 或合并记录里出现该 event_id 即已消费过。"""
    event = as_uuid(event_id)
    with dict_cursor(conn) as cur:
        cur.execute(
            f"""SELECT {_NOTIFICATION_COLUMNS} FROM notifications
                 WHERE source_event_id = %s OR %s = ANY (merged_event_ids)
                 ORDER BY created_at LIMIT 1""",
            (event, event))
        row = cur.fetchone()
    return Notification.from_row(row) if row else None


def find_by_dedupe(conn: Any, account_id: uuid.UUID | str, type_: str, bucket: int, *,
                   for_update: bool = True) -> Notification | None:
    """INV-03：同账户 + 同类型 + 同合并窗口的既有通知（默认加行锁，防并发双写）。"""
    lock = " FOR UPDATE" if for_update else ""
    with dict_cursor(conn) as cur:
        cur.execute(
            f"""SELECT {_NOTIFICATION_COLUMNS} FROM notifications
                 WHERE account_id = %s AND type = %s AND dedupe_bucket = %s{lock}""",
            (as_uuid(account_id), type_, int(bucket)))
        row = cur.fetchone()
    return Notification.from_row(row) if row else None


def insert_notification(conn: Any, notification: Notification) -> Notification:
    """落一条通知（新建）。唯一冲突原样抛给上层（由 events 层决定合并 / 幂等）。"""
    with dict_cursor(conn) as cur:
        cur.execute(
            f"""INSERT INTO notifications
                   (id, account_id, level, type, template_key, template_scope, payload_ref,
                    channels, channel_count, dedupe_bucket, source_event_id, merged_event_ids,
                    status, created_at, sent_at, read_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING {_NOTIFICATION_COLUMNS}""",
            (notification.id, notification.account_id, notification.level, notification.type,
             notification.template_key, notification.template_scope,
             _jsonb(notification.payload), list(notification.channels),
             notification.channel_count, notification.dedupe_bucket,
             notification.source_event_id, [str(item) for item in notification.merged_event_ids],
             notification.status, notification.created_at, notification.sent_at,
             notification.read_at))
        row = cur.fetchone()
    return Notification.from_row(row)


def bump_merged(conn: Any, notification_id: uuid.UUID | str,
                event_id: uuid.UUID | str) -> Notification:
    """INV-03 合并：次数 +1，并把被合并的 event_id 追加进 ``merged_event_ids``。

    只动「合并计数」两列（1201 的护栏允许）；状态、payload、渠道一律不变。
    """
    with dict_cursor(conn) as cur:
        cur.execute(
            f"""UPDATE notifications
                   SET channel_count = channel_count + 1,
                       merged_event_ids = array_append(merged_event_ids, %s)
                 WHERE id = %s
                RETURNING {_NOTIFICATION_COLUMNS}""",
            (as_uuid(event_id), as_uuid(notification_id)))
        row = cur.fetchone()
    if row is None:                                        # pragma: no cover - 行锁内不会发生
        raise errors.StoreUnavailable("合并通知失败：通知行不存在")
    return Notification.from_row(row)


def get_notification(conn: Any, account_id: uuid.UUID | str,
                     notification_id: uuid.UUID | str) -> Notification | None:
    """按账户 + id 取一条（账户隔离在 SQL 里）。"""
    with dict_cursor(conn) as cur:
        cur.execute(
            f"""SELECT {_NOTIFICATION_COLUMNS} FROM notifications
                 WHERE account_id = %s AND id = %s""",
            (as_uuid(account_id), as_uuid(notification_id)))
        row = cur.fetchone()
    return Notification.from_row(row) if row else None


def insert_attempt(conn: Any, attempt: DeliveryAttempt) -> DeliveryAttempt:
    """INV-04：每次尝试只追加一条（重复的 (notification_id, channel, attempt_no) 会冲突）。"""
    with dict_cursor(conn) as cur:
        cur.execute(
            """INSERT INTO delivery_attempts
                   (id, notification_id, channel, attempt_no, status, error_code,
                    provider_ref, latency_ms, occurred_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id, notification_id, channel, attempt_no, status, error_code,
                         provider_ref, latency_ms, occurred_at""",
            (attempt.id, attempt.notification_id, attempt.channel, attempt.attempt_no,
             attempt.status, attempt.error_code, attempt.provider_ref, attempt.latency_ms,
             attempt.occurred_at))
        row = cur.fetchone()
    return DeliveryAttempt.from_row(row)


def attempts_for(conn: Any, notification_id: uuid.UUID | str) -> list[DeliveryAttempt]:
    with dict_cursor(conn) as cur:
        cur.execute(
            """SELECT id, notification_id, channel, attempt_no, status, error_code,
                      provider_ref, latency_ms, occurred_at
                 FROM delivery_attempts WHERE notification_id = %s
                ORDER BY occurred_at, attempt_no""",
            (as_uuid(notification_id),))
        return [DeliveryAttempt.from_row(row) for row in cur.fetchall()]


def attempts_count(conn: Any, notification_id: uuid.UUID | str, channel: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT count(*) FROM delivery_attempts
                WHERE notification_id = %s AND channel = %s""",
            (as_uuid(notification_id), channel))
        return int(cur.fetchone()[0])


def claim_batch(conn: Any, *, now: datetime, limit: int) -> list[Notification]:
    """dispatcher 取一批 ``queued`` → ``sending``（``FOR UPDATE SKIP LOCKED``，可多实例并行）。"""
    with dict_cursor(conn) as cur:
        cur.execute(
            f"""UPDATE notifications SET status = 'sending'
                 WHERE id IN (
                     SELECT id FROM notifications
                      WHERE status = 'queued'
                      ORDER BY created_at
                      LIMIT %s
                      FOR UPDATE SKIP LOCKED)
                RETURNING {_NOTIFICATION_COLUMNS}""",
            (int(limit),))
        rows = cur.fetchall()
    return [Notification.from_row(row) for row in rows]


def finish(conn: Any, notification_id: uuid.UUID | str, status: str,
           sent_at: datetime | None) -> None:
    """写终态（状态机由 1201 的触发器校验，非法迁移直接报错）。"""
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE notifications SET status = %s, sent_at = COALESCE(%s, sent_at)
                WHERE id = %s""",
            (status, sent_at, as_uuid(notification_id)))


def _jsonb(value: Any) -> Any:
    from psycopg.types.json import Jsonb

    return Jsonb(dict(value or {}))
