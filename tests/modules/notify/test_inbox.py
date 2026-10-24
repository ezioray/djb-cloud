# SPDX-License-Identifier: AGPL-3.0-or-later
"""站内信：游标分页 / 过滤 / 已读幂等 / 账户隔离（M12 §4.1 / INV-02）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.notify import errors, inbox, store
from notifykit import NOW, build_notification


def _seed(conn, account_id, count=5, *, level="P1", start=NOW, tag="a"):
    rows = []
    for index in range(count):
        notification = build_notification(
            account_id, type_=f"test.{tag}{index}", level=level,
            created_at=start + timedelta(minutes=index), dedupe_bucket=index)
        rows.append(store.insert_notification(conn, notification))
    conn.commit()
    return rows


def test_cursor_pagination_walks_all_pages(conn, account_id):
    _seed(conn, account_id, 5)
    first = inbox.list_page(conn, account_id, limit=2)
    assert first["page"]["has_more"] is True
    assert first["page"]["cursor"] == ""
    assert len(first["data"]) == 2
    assert first["unread"] == 5
    # 倒序：最新一条在前
    assert first["data"][0]["created_at"] > first["data"][1]["created_at"]

    second = inbox.list_page(conn, account_id, limit=2, cursor=first["page"]["next_cursor"])
    third = inbox.list_page(conn, account_id, limit=2, cursor=second["page"]["next_cursor"])
    assert len(second["data"]) == 2 and len(third["data"]) == 1
    assert third["page"]["has_more"] is False
    assert third["page"]["next_cursor"] is None
    seen = [row["id"] for page in (first, second, third) for row in page["data"]]
    assert len(seen) == len(set(seen)) == 5


def test_limit_defaults_and_bounds(conn, account_id):
    _seed(conn, account_id, 3)
    assert len(inbox.list_page(conn, account_id)["data"]) == 3
    for bad in (0, -1, 201, "abc", True):
        with pytest.raises(errors.InvalidArgument):
            inbox.list_page(conn, account_id, limit=bad)


def test_level_and_unread_filters(conn, account_id):
    _seed(conn, account_id, 2, level="P0", tag="p0")
    _seed(conn, account_id, 3, level="P2", start=NOW + timedelta(hours=1), tag="p2")
    p0 = inbox.list_page(conn, account_id, level="P0")
    assert len(p0["data"]) == 2 and all(row["level"] == "P0" for row in p0["data"])
    with pytest.raises(errors.InvalidArgument):
        inbox.list_page(conn, account_id, level="P9")
    with pytest.raises(errors.InvalidArgument):
        inbox.list_page(conn, account_id, unread_only="maybe")
    assert inbox._unread_only("TRUE") is True
    assert inbox._unread_only("0") is False


def test_unread_only_hides_read_rows(conn, account_id):
    rows = _seed(conn, account_id, 3)
    inbox.mark_read(conn, account_id, rows[0].id, now=NOW)
    conn.commit()
    page = inbox.list_page(conn, account_id, unread_only=True)
    assert len(page["data"]) == 2
    assert page["unread"] == 2


def test_mark_read_is_idempotent(conn, account_id):
    rows = _seed(conn, account_id, 1)
    first = inbox.mark_read(conn, account_id, rows[0].id, now=NOW)
    conn.commit()
    assert first["marked"] == 1
    assert first["unread"] == 0
    second = inbox.mark_read(conn, account_id, rows[0].id, now=NOW + timedelta(hours=2))
    conn.commit()
    assert second["marked"] == 0
    assert second["read_at"] == first["read_at"]          # 首次已读时刻不变（幂等）


def test_mark_all_read_uses_reserved_id(conn, account_id):
    _seed(conn, account_id, 4)
    ack = inbox.mark_read(conn, account_id, "all", now=NOW)
    conn.commit()
    assert ack["notification_id"] is None
    assert ack["marked"] == 4
    assert ack["unread"] == 0
    again = inbox.mark_read(conn, account_id, "all", now=NOW)
    conn.commit()
    assert again["marked"] == 0


def test_mark_read_unknown_or_foreign_is_not_found(conn, account_id):
    rows = _seed(conn, account_id, 1)
    with pytest.raises(errors.NotFound):
        inbox.mark_read(conn, account_id, uuid.uuid4(), now=NOW)
    with pytest.raises(errors.NotFound):                  # 账户隔离：别人的通知 = 不存在
        inbox.mark_read(conn, uuid.uuid4(), rows[0].id, now=NOW)
    conn.rollback()


def test_list_is_account_scoped(conn, account_id):
    other = uuid.uuid4()
    _seed(conn, account_id, 2)
    _seed(conn, other, 3)
    assert len(inbox.list_page(conn, account_id)["data"]) == 2
    assert len(inbox.list_page(conn, other)["data"]) == 3
    assert inbox.unread_count(conn, account_id) == 2
    assert inbox.unread_count(conn, other) == 3


def test_cursor_tampering_is_rejected(conn, account_id):
    _seed(conn, account_id, 2)
    page = inbox.list_page(conn, account_id, limit=1)
    cursor = page["page"]["next_cursor"]
    for bad in ("not-a-cursor", cursor[:-1] + ("0" if cursor[-1] != "0" else "1"),
                "aGVsbG8=.deadbeef", "", 12):
        if bad == "":
            continue
        with pytest.raises(errors.CursorInvalid):
            inbox.list_page(conn, account_id, cursor=bad)
    roundtrip = inbox.decode_cursor(cursor)
    assert roundtrip[0] is not None and roundtrip[1] is not None


def test_cursor_requires_both_parts():
    with pytest.raises(errors.CursorInvalid):
        inbox.decode_cursor("abcdef")
    with pytest.raises(errors.CursorInvalid):
        inbox.decode_cursor(None)


def test_notification_api_shape(conn, account_id):
    rows = _seed(conn, account_id, 1)
    payload = inbox.list_page(conn, account_id)["data"][0]
    assert set(payload) >= {"id", "level", "type", "template_key", "channels", "channel_count",
                            "status", "created_at", "sent_at", "read_at", "payload"}
    assert payload["channel_count"] == 1
    assert rows[0].id is not None
