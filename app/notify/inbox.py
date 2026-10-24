# SPDX-License-Identifier: AGPL-3.0-or-later
"""站内信列表与已读（spec 1.2.3 ``/api/v1/user/notifications``，M12 §4.1 / INV-02）。

要点：

* **游标分页**（00-conventions §5：不得用 offset）：游标是 ``(created_at, id)`` 的 keyset，
  不透明、带校验位；篡改/乱构造一律 ``40001 cursor_invalid``（不泄露内部结构）；
* **账户隔离**：所有 SQL 都带 ``account_id``；别人的通知只能得到「查不到」；
* **已读幂等**（spec 描述）：重复标记无副作用；``id=all`` 是保留字（``notification_id=null``）；
* **已读不删记录**（INV-02）：只写 ``read_at``，记录与 ``payload`` 保留到 180 天归档。
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from . import clock, errors, facts
from .models import Notification, as_uuid
from .store import dict_cursor

__all__ = ["encode_cursor", "decode_cursor", "list_page", "unread_count", "mark_read",
           "READ_ALL", "notification_ids"]

#: spec：``id=all`` 是保留字，不对应任何真实通知 id
READ_ALL = "all"

_CURSOR_SEPARATOR = "."


def encode_cursor(created_at: datetime, notification_id: uuid.UUID | str) -> str:
    """把 ``(created_at, id)`` 编成不透明游标：base64url(payload) + "." + 校验位。"""
    payload = json.dumps({"t": clock.isoformat(created_at), "i": str(notification_id)},
                         separators=(",", ":"), sort_keys=True).encode("utf-8")
    checksum = hashlib.sha256(payload).hexdigest()[:8]
    token = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{token}{_CURSOR_SEPARATOR}{checksum}"


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    """解析游标；任何异常都翻成 ``40001 cursor_invalid``（不把内部结构回给客户端）。"""
    if not isinstance(cursor, str) or len(cursor) > 512 or _CURSOR_SEPARATOR not in cursor:
        raise errors.CursorInvalid("游标不合法（首次请求不要传 cursor）")
    token, _, checksum = cursor.rpartition(_CURSOR_SEPARATOR)
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:                                # noqa: BLE001 - 统一翻成 40001
        raise errors.CursorInvalid("游标不合法（无法解码）") from exc
    if hashlib.sha256(payload).hexdigest()[:8] != checksum:
        raise errors.CursorInvalid("游标不合法（校验位不匹配）")
    try:
        data = json.loads(payload.decode("utf-8"))
        created_at = datetime.fromisoformat(str(data["t"]))
        notification_id = as_uuid(data["i"])
    except Exception as exc:                                # noqa: BLE001
        raise errors.CursorInvalid("游标不合法（内容缺失）") from exc
    return clock.to_utc(created_at), notification_id


def _limit(value: Any) -> int:
    if value is None:
        return facts.DEFAULT_LIMIT
    if isinstance(value, bool):                             # bool 是 int 的子类，先挡掉
        raise errors.InvalidArgument("limit 必须是整数", field="limit")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument("limit 必须是整数", field="limit") from exc
    if number < 1 or number > facts.MAX_LIMIT:
        raise errors.InvalidArgument(f"limit 必须在 1–{facts.MAX_LIMIT}", field="limit")
    return number


def _level(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise errors.InvalidArgument("level 必须是 P0/P1/P2", field="level")
    try:
        return facts.validate_level(value)
    except ValueError as exc:
        raise errors.InvalidArgument(str(exc), field="level") from exc


def _unread_only(value: Any) -> bool:
    if value in (None, "", False):
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise errors.InvalidArgument("unread_only 必须是布尔值", field="unread_only")


def notification_ids(rows: list[Notification]) -> list[str]:
    return [str(row.id) for row in rows]


def unread_count(conn: Any, account_id: uuid.UUID | str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM notifications WHERE account_id = %s AND read_at IS NULL",
            (as_uuid(account_id),))
        return int(cur.fetchone()[0])


def list_page(conn: Any, account_id: uuid.UUID | str, *,
              level: Any = None, unread_only: Any = False,
              limit: Any = None, cursor: Any = None) -> dict[str, Any]:
    """站内信列表：``created_at DESC, id DESC`` keyset 分页 + ``level`` / ``unread_only`` 过滤。"""
    account = as_uuid(account_id)
    page_limit = _limit(limit)
    level_filter = _level(level)
    only_unread = _unread_only(unread_only)

    where = ["account_id = %s"]
    params: list[Any] = [account]
    if level_filter is not None:
        where.append("level = %s")
        params.append(level_filter)
    if only_unread:
        where.append("read_at IS NULL")
    if cursor not in (None, ""):
        last_created, last_id = decode_cursor(cursor)
        where.append("(created_at, id) < (%s, %s)")
        params.extend([last_created, last_id])

    sql = (f"""SELECT id, account_id, level, type, template_key, template_scope, payload_ref,
                      channels, channel_count, dedupe_bucket, source_event_id,
                      merged_event_ids, status, created_at, sent_at, read_at
                 FROM notifications
                WHERE {' AND '.join(where)}
                ORDER BY created_at DESC, id DESC
                LIMIT %s""")
    params.append(page_limit + 1)                       # 多取一条判断 has_more

    with dict_cursor(conn) as cur:
        cur.execute(sql, params)
        rows = [Notification.from_row(row) for row in cur.fetchall()]

    has_more = len(rows) > page_limit
    page_rows = rows[:page_limit]
    next_cursor = None
    if has_more and page_rows:
        tail = page_rows[-1]
        next_cursor = encode_cursor(tail.created_at, tail.id)
    return {
        "data": [row.to_api() for row in page_rows],
        "page": {
            "cursor": cursor if isinstance(cursor, str) else "",
            "has_more": has_more,
            "next_cursor": next_cursor,
        },
        "unread": unread_count(conn, account),
    }


def mark_read(conn: Any, account_id: uuid.UUID | str, notification_id: str | uuid.UUID | None,
              *, now: datetime) -> dict[str, Any]:
    """标记已读。``id=all`` → 全部未读；单条不存在 / 不属于本账户 → ``40401``。

    幂等（spec）：已读过的再标记返回 ``marked=0``，``read_at`` 保持首次时刻不变。
    """
    account = as_uuid(account_id)

    if notification_id in (None, "", READ_ALL):
        with dict_cursor(conn) as cur:
            cur.execute(
                """UPDATE notifications SET read_at = %s
                    WHERE account_id = %s AND read_at IS NULL
                RETURNING id""",
                (now, account))
            marked = len(cur.fetchall())
        return {"notification_id": None, "marked": marked,
                "unread": unread_count(conn, account), "read_at": clock.isoformat(now)}

    try:
        target = as_uuid(notification_id)
    except (TypeError, ValueError) as exc:                # 非法 id 等同「不存在」
        raise errors.NotFound("通知不存在") from exc
    with dict_cursor(conn) as cur:
        cur.execute(
            """SELECT id, read_at FROM notifications WHERE account_id = %s AND id = %s""",
            (account, target))
        row = cur.fetchone()
        if row is None:
            raise errors.NotFound("通知不存在")
        if row["read_at"] is not None:
            existing = clock.to_utc(row["read_at"])
            return {"notification_id": str(row["id"]), "marked": 0,
                    "unread": unread_count(conn, account),
                    "read_at": clock.isoformat(existing)}
        cur.execute(
            """UPDATE notifications SET read_at = %s
                WHERE account_id = %s AND id = %s AND read_at IS NULL
            RETURNING id""",
            (now, account, target))
        updated = cur.fetchone()
    return {"notification_id": str(updated["id"]) if updated else str(notification_id),
            "marked": 1 if updated else 0,
            "unread": unread_count(conn, account), "read_at": clock.isoformat(now)}
