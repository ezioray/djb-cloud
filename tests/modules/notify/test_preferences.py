# SPDX-License-Identifier: Apache-2.0
"""偏好：P0 不可退订（INV-01）、覆盖式写入、静默时段 / 摘要规则。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.notify import errors, preferences
from app.notify.models import Preference
from notifykit import NOW, connect


def _body(**overrides):
    base = {"email": True, "in_app": True, "webhook": False, "digest": "realtime",
            "quiet_hours": None}
    base.update(overrides)
    return base


def test_defaults_when_no_row(conn, account_id):
    pref = preferences.get(conn, account_id)
    assert pref.to_api() == {"email": True, "in_app": True, "webhook": False,
                             "quiet_hours": None, "digest": "realtime", "p0_opt_out": False}


def test_put_then_get_roundtrip(conn, account_id):
    saved = preferences.put(conn, account_id, _body(
        webhook=True, digest="daily",
        quiet_hours={"start": "22:00", "end": "07:30", "timezone": "Asia/Shanghai"}), now=NOW)
    conn.commit()
    assert saved.webhook is True
    assert saved.digest == "daily"
    assert saved.quiet_hours["start"] == "22:00"
    loaded = preferences.get(conn, account_id)
    assert loaded.to_api()["quiet_hours"]["timezone"] == "Asia/Shanghai"


def test_put_is_full_overwrite(conn, account_id):
    preferences.put(conn, account_id, _body(digest="weekly", quiet_hours=None), now=NOW)
    conn.commit()
    preferences.put(conn, account_id, _body(digest="realtime"), now=NOW)
    conn.commit()
    assert preferences.get(conn, account_id).digest == "realtime"


def test_p0_opt_out_true_is_rejected_and_changes_nothing(conn, account_id):
    preferences.put(conn, account_id, _body(email=False, digest="daily"), now=NOW)
    conn.commit()
    with pytest.raises(errors.P0OptOutRejected) as caught:
        preferences.put(conn, account_id, _body(email=True, digest="weekly",
                                                p0_opt_out=True), now=NOW)
    assert caught.value.status_code == 409
    assert caught.value.code == "40902"
    conn.rollback()
    after = preferences.get(conn, account_id)
    assert after.email is False and after.digest == "daily"     # 偏好一个字都没改


def test_p0_opt_out_false_is_accepted(conn, account_id):
    saved = preferences.put(conn, account_id, _body(p0_opt_out=False), now=NOW)
    conn.commit()
    assert saved.p0_opt_out is False


def test_p0_opt_out_must_be_bool(conn, account_id):
    with pytest.raises(errors.InvalidArgument):
        preferences.put(conn, account_id, _body(p0_opt_out="yes"), now=NOW)


@pytest.mark.parametrize("body", [
    {"email": True, "in_app": True},                             # 缺 webhook
    {"email": "true", "in_app": True, "webhook": False},         # 类型错
    _body(digest="hourly"),
    _body(quiet_hours={"start": "25:00", "end": "07:00"}),
    _body(quiet_hours={"start": "22:00"}),
    _body(quiet_hours={"start": "22:00", "end": "07:00", "timezone": "Mars/Olympus"}),
    _body(quiet_hours={"start": "22:00", "end": "07:00", "extra": "x"}),
    _body(quiet_hours="22:00-07:00"),
])
def test_invalid_preference_bodies_are_rejected(conn, account_id, body):
    with pytest.raises(errors.InvalidArgument):
        preferences.put(conn, account_id, body, now=NOW)


def test_body_must_be_object(conn, account_id):
    with pytest.raises(errors.InvalidArgument):
        preferences.put(conn, account_id, ["email"], now=NOW)


# ─────────────────────────────────────────────────── 静默时段 / 摘要（INV-01）
QUIET = {"start": "22:00", "end": "07:00", "timezone": "UTC"}


@pytest.mark.parametrize("level", ["P1", "P2"])
def test_quiet_hours_defer_p1_p2(level):
    pref = Preference(quiet_hours=QUIET)
    decision = preferences.apply_time_rules(level, pref, datetime(2026, 10, 23, 23, 30,
                                                                 tzinfo=timezone.utc))
    assert decision.deferred is True
    assert decision.reason == "quiet_hours"


def test_quiet_hours_never_affect_p0():
    pref = Preference(quiet_hours=QUIET, digest="weekly")
    decision = preferences.apply_time_rules("P0", pref, datetime(2026, 10, 23, 23, 30,
                                                                 tzinfo=timezone.utc))
    assert decision.immediate is True
    assert decision.reason == "p0_immediate"


def test_quiet_hours_window_math():
    pref = Preference(quiet_hours=QUIET)
    # 跨零点窗口：23:30 / 02:00 在窗口内，12:00 在窗口外
    assert preferences.apply_time_rules("P1", pref, datetime(2026, 10, 23, 2, 0,
                                                             tzinfo=timezone.utc)).deferred
    assert not preferences.apply_time_rules("P1", pref, datetime(2026, 10, 23, 12, 0,
                                                                tzinfo=timezone.utc)).deferred
    # 同日窗口 09:00–17:00
    daytime = Preference(quiet_hours={"start": "09:00", "end": "17:00", "timezone": "UTC"})
    assert preferences.apply_time_rules("P2", daytime, datetime(2026, 10, 23, 10, 0,
                                                               tzinfo=timezone.utc)).deferred
    assert not preferences.apply_time_rules("P2", daytime, datetime(2026, 10, 23, 18, 0,
                                                                    tzinfo=timezone.utc)).deferred
    # 零长度窗口视为未启用
    zero = Preference(quiet_hours={"start": "09:00", "end": "09:00", "timezone": "UTC"})
    assert not preferences.apply_time_rules("P1", zero, datetime(2026, 10, 23, 9, 0,
                                                                tzinfo=timezone.utc)).deferred


def test_quiet_hours_respect_timezone():
    pref = Preference(quiet_hours={"start": "22:00", "end": "23:00",
                                   "timezone": "Asia/Shanghai"})
    # UTC 14:30 = 上海 22:30 → 在静默时段内
    assert preferences.apply_time_rules("P1", pref, datetime(2026, 10, 23, 14, 30,
                                                             tzinfo=timezone.utc)).deferred
    # UTC 11:00 = 上海 19:00 → 不在
    assert not preferences.apply_time_rules("P1", pref, datetime(2026, 10, 23, 11, 0,
                                                                tzinfo=timezone.utc)).deferred


def test_digest_defers_p1_but_not_p0():
    pref = Preference(digest="daily")
    assert preferences.apply_time_rules("P1", pref, NOW).reason == "digest_daily"
    assert preferences.apply_time_rules("P2", pref, NOW).deferred
    assert preferences.apply_time_rules("P0", pref, NOW).immediate


def test_enforcement_can_be_disabled_for_rollout():
    pref = Preference(quiet_hours=QUIET, digest="weekly")
    decision = preferences.apply_time_rules("P1", pref, datetime(2026, 10, 23, 23, 30,
                                                                 tzinfo=timezone.utc),
                                             enforce=False)
    assert decision.immediate is True
    assert decision.reason == "not_enforced"


def test_at_local_helper():
    moment = preferences.at_local("09:00", zone="Asia/Shanghai", on=NOW)
    assert moment.hour == 9
    assert moment.tzinfo is not None
    with pytest.raises(ValueError):
        preferences.at_local("9:00", zone="UTC", on=NOW)


def test_applying_rules_rejects_unknown_level():
    with pytest.raises(ValueError):
        preferences.apply_time_rules("P9", Preference(), NOW)


def test_db_row_ignores_bypassed_opt_out(migrated):
    """绕过 API 直接写 true 也必须失败（1205 的 CHECK 兜底 INV-01）。"""
    import uuid

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
    finally:
        conn.close()


def test_quiet_hours_in_db_must_be_valid(migrated):
    import uuid

    conn = connect(migrated)
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO notification_preferences
                           (account_id, email, in_app, webhook, quiet_hours, digest, updated_at)
                       VALUES (%s, true, true, false, '{"start":"22:00"}'::jsonb, 'realtime',
                               now())""",
                    (uuid.uuid4(),))
        conn.rollback()
    finally:
        conn.close()


def test_updated_at_moves_forward(conn, account_id):
    first = preferences.put(conn, account_id, _body(), now=NOW)
    conn.commit()
    later = NOW + timedelta(hours=1)
    second = preferences.put(conn, account_id, _body(digest="weekly"), now=later)
    conn.commit()
    assert second.updated_at > first.updated_at
