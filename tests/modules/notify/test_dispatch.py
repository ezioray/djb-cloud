# SPDX-License-Identifier: AGPL-3.0-or-later
"""分派与投递：状态机 / 重试次数 / 降级 / 事件（INV-04 / INV-06）。用独立 schema 隔离全表扫描。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.notify import channels, dispatch, events, preferences, store, webhooks
from app.notify.channels import ChannelResult, WebhookTarget
from notifykit import NOW, TEST_WEBHOOK_SECRET, connect, count, scalar


def _conn(schema: str):
    return connect(schema)


def _consume(conn, account_id, *, event_type="payment.paid", prefs=None, at=NOW):
    if prefs is not None:
        preferences.put(conn, account_id, prefs, now=at)
    result = events.consume(conn, notifykit_event(event_type, account_id, at=at), now=at)
    conn.commit()
    return result


def notifykit_event(event_type, account_id, *, at=NOW):
    from notifykit import event

    return event(event_type, account_id=account_id, occurred_at=at)


def _webhook_target(conn, account_id, *, event="payment.settled"):
    subscription, secret = webhooks.create(
        conn, account_id=account_id, url="https://hooks.example.com/cb",
        events=[event], now=NOW)
    conn.commit()
    return WebhookTarget(subscription_id=str(subscription.id), url=subscription.url,
                         secret=TEST_WEBHOOK_SECRET, event=event)


def test_in_app_only_is_delivered(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        result = _consume(conn, account, prefs={"email": False, "in_app": True,
                                                "webhook": False})
        summary = dispatch.dispatch_batch(conn, now=NOW)
        conn.commit()
        assert summary == {"scanned": 1, "delivered": 1, "partial": 0, "failed": 0}
        assert scalar(conn, "SELECT status FROM notifications WHERE id = %s",
                      (result.notification_id,)) == "delivered"
        assert count(conn, "delivery_attempts", "notification_id = %s",
                     (uuid.UUID(result.notification_id),)) == 1
        types = [row[0] for row in conn.execute(
            "SELECT type FROM notification_outbox WHERE aggregate_id = %s",
            (result.notification_id,)).fetchall()]
        assert types.count("notification.delivered") == 1
        assert "notification.failed" not in types
    finally:
        conn.close()


def test_email_transport_not_wired_degrades_to_partial(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        result = _consume(conn, account)                 # email 默认开
        delays = []
        summary = dispatch.dispatch_batch(conn, now=NOW, sleeper=delays.append)
        conn.commit()
        assert summary["partial"] == 1
        attempts = conn.execute(
            """SELECT channel, attempt_no, status, error_code FROM delivery_attempts
                WHERE notification_id = %s ORDER BY channel, attempt_no""",
            (uuid.UUID(result.notification_id),)).fetchall()
        assert [row[0] for row in attempts] == ["email", "email", "email", "in_app"]
        assert [row[1] for row in attempts] == [1, 2, 3, 1]
        assert all(row[2] == "retryable" and row[3] == "transport_not_wired"
                   for row in attempts[:3])
        assert attempts[3][2] == "success"
        assert delays == [1.0, 10.0]                      # 1s / 10s 退避，第 3 次不再重试
        assert scalar(conn, "SELECT status FROM notifications WHERE id = %s",
                      (result.notification_id,)) == "partial"
        failed = conn.execute(
            """SELECT count(*) FROM notification_outbox
                WHERE aggregate_id = %s AND type = 'notification.failed'""",
            (result.notification_id,)).fetchone()[0]
        assert failed == 1                                # INV-06：不静默
    finally:
        conn.close()


def test_email_transport_success(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        _consume(conn, account)
        adapters = dispatch.default_adapters(transport_email=lambda notification: True)
        summary = dispatch.dispatch_batch(conn, adapters=adapters, now=NOW)
        conn.commit()
        assert summary == {"scanned": 1, "delivered": 1, "partial": 0, "failed": 0}
    finally:
        conn.close()


def test_email_transport_exception_is_retryable(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        _consume(conn, account)

        def broken(_notification):
            raise TimeoutError("smtp timeout")

        adapters = dispatch.default_adapters(transport_email=broken)
        dispatch.dispatch_batch(conn, adapters=adapters, now=NOW, sleeper=lambda _s: None)
        conn.commit()
        codes = [row[0] for row in conn.execute(
            "SELECT error_code FROM delivery_attempts WHERE channel = 'email'").fetchall()]
        assert codes == ["smtp_timeout"] * 3
    finally:
        conn.close()


def test_webhook_success_uses_signature_headers(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    captured = {}
    try:
        target = _webhook_target(conn, account)
        _consume(conn, account, event_type="payment.paid",
                 prefs={"email": False, "in_app": True, "webhook": True})

        def transport(url, headers, body, timeout):
            captured.update(url=url, headers=headers, body=body, timeout=timeout)
            return 200

        adapters = dispatch.default_adapters(transport_webhook=transport)
        summary = dispatch.dispatch_batch(
            conn, adapters=adapters, webhook_targets=lambda _n: target, now=NOW)
        conn.commit()
        assert summary["delivered"] == 1
        assert captured["url"] == "https://hooks.example.com/cb"
        assert captured["headers"]["X-DJB-Event"] == "payment.settled"
        assert captured["headers"]["X-DJB-Timestamp"] == str(int(NOW.timestamp()))
        assert captured["headers"]["X-DJB-Signature"].startswith("sha256=")
        assert b"notification_id" in captured["body"]
        assert captured["timeout"] == 10.0
    finally:
        conn.close()


def test_webhook_4xx_is_permanent_and_pauses_subscription(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        target = _webhook_target(conn, account)
        _consume(conn, account, event_type="payment.paid",
                 prefs={"email": False, "in_app": True, "webhook": True})
        adapters = dispatch.default_adapters(transport_webhook=lambda *_: 404)
        summary = dispatch.dispatch_batch(
            conn, adapters=adapters, webhook_targets=lambda _n: target, now=NOW)
        conn.commit()
        assert summary["partial"] == 1
        assert count(conn, "delivery_attempts", "channel = 'webhook'") == 1   # 永久失败不重试
        assert scalar(conn, "SELECT status FROM webhook_subscriptions WHERE id = %s",
                      (uuid.UUID(target.subscription_id),)) == "paused"
    finally:
        conn.close()


def test_webhook_5xx_retries_three_times(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    delays = []
    try:
        target = _webhook_target(conn, account)
        _consume(conn, account, event_type="payment.paid",
                 prefs={"email": False, "in_app": True, "webhook": True})
        adapters = dispatch.default_adapters(transport_webhook=lambda *_: 503)
        summary = dispatch.dispatch_batch(conn, adapters=adapters,
                                          webhook_targets=lambda _n: target, now=NOW,
                                          sleeper=delays.append)
        conn.commit()
        assert summary["partial"] == 1
        assert count(conn, "delivery_attempts", "channel = 'webhook'") == 3
        assert delays == [1.0, 10.0]
        assert scalar(conn, "SELECT status FROM webhook_subscriptions WHERE id = %s",
                      (uuid.UUID(target.subscription_id),)) == "paused"
    finally:
        conn.close()


def test_webhook_transport_exception_and_timeout(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        target = _webhook_target(conn, account)
        _consume(conn, account, event_type="payment.paid",
                 prefs={"email": False, "in_app": True, "webhook": True})

        def boom(*_args):
            raise ConnectionError("dns")

        adapters = dispatch.default_adapters(transport_webhook=boom)
        dispatch.dispatch_batch(conn, adapters=adapters, webhook_targets=lambda _n: target,
                                now=NOW, sleeper=lambda _s: None)
        conn.commit()
        codes = [row[0] for row in conn.execute(
            "SELECT error_code FROM delivery_attempts WHERE channel = 'webhook'").fetchall()]
        assert codes[0].startswith("transport_")
    finally:
        conn.close()


def test_no_active_subscription_and_not_wired(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        _consume(conn, account, event_type="payment.paid",
                 prefs={"email": False, "in_app": True, "webhook": True})
        # 没有订阅 → 事件层不会加 webhook 渠道；这里直接构造一条带 webhook 渠道的通知来测适配器
        from notifykit import build_notification

        notification = store.insert_notification(conn, build_notification(
            account, type_="payment.settled", channels=("in_app", "webhook"),
            created_at=NOW + timedelta(minutes=5), dedupe_bucket=999))
        conn.commit()
        summary = dispatch.dispatch_batch(conn, now=NOW + timedelta(minutes=5),
                                          sleeper=lambda _s: None)
        conn.commit()
        assert summary["partial"] == 1
        codes = [row[0] for row in conn.execute(
            """SELECT error_code FROM delivery_attempts
                WHERE notification_id = %s AND channel = 'webhook'""",
            (notification.id,)).fetchall()]
        assert codes == ["no_active_subscription"] * 3
    finally:
        conn.close()


def test_attempts_are_capped_at_three(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        from notifykit import build_notification

        notification = store.insert_notification(conn, build_notification(
            account, channels=("in_app", "email"), created_at=NOW, dedupe_bucket=1))
        conn.commit()
        # 手工塞满 3 条 email 尝试，dispatch 应直接判 attempts_exhausted
        for attempt_no in (1, 2, 3):
            store.insert_attempt(conn, _attempt(notification, attempt_no))
        conn.commit()
        claimed = store.claim_batch(conn, now=NOW, limit=10)
        conn.commit()
        outcome = dispatch.deliver_notification(
            conn, claimed[0], adapters=dispatch.default_adapters(),
            now=NOW, sleeper=lambda _s: None)
        conn.commit()
        assert outcome["status"] == "partial"            # in_app 成功、邮件次数已用尽
        assert any(result.error_code == "attempts_exhausted" for result in outcome["results"])
    finally:
        conn.close()


def _attempt(notification, attempt_no):
    from app.notify.models import DeliveryAttempt

    return DeliveryAttempt(id=uuid.uuid4(), notification_id=notification.id, channel="email",
                           attempt_no=attempt_no, status="retryable",
                           occurred_at=NOW, error_code="smtp_x")


def test_unknown_channel_is_permanent_failure(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        from notifykit import build_notification

        notification = store.insert_notification(conn, build_notification(
            account, channels=("in_app", "email"), created_at=NOW, dedupe_bucket=2))
        conn.commit()
        adapters = {"in_app": channels.InAppChannel()}           # email 未注册适配器
        claimed = store.claim_batch(conn, now=NOW, limit=10)
        conn.commit()
        outcome = dispatch.deliver_notification(conn, claimed[0], adapters=adapters, now=NOW)
        conn.commit()
        assert outcome["status"] == "partial"
        assert any(result.error_code == "channel_not_wired" for result in outcome["results"])
    finally:
        conn.close()


def test_claim_batch_marks_sending_and_skips_claimed(m12_only):
    conn = _conn(m12_only)
    account = uuid.uuid4()
    try:
        _consume(conn, account, at=NOW)
        _consume(conn, account, at=NOW + timedelta(hours=2))
        first = store.claim_batch(conn, now=NOW, limit=1)
        conn.commit()
        second = store.claim_batch(conn, now=NOW, limit=10)
        conn.commit()
        third = store.claim_batch(conn, now=NOW, limit=10)
        conn.commit()
        assert len(first) == 1 and len(second) == 1 and third == []
        assert {row.status for row in first + second} == {"sending"}
    finally:
        conn.close()


def test_decide_status_pure():
    assert dispatch.decide_status([]) == "failed"
    assert dispatch.decide_status([ChannelResult("success")]) == "delivered"
    assert dispatch.decide_status([
        ChannelResult("success"), ChannelResult("permanent", "http_404")]) == "partial"
    assert dispatch.decide_status([
        ChannelResult("permanent", "http_404"), ChannelResult("retryable", "x")]) == "failed"


def test_classify_http_status():
    assert channels.classify_http_status(204) == "success"
    assert channels.classify_http_status(301) == "retryable"
    assert channels.classify_http_status(429) == "retryable"
    assert channels.classify_http_status(400) == "permanent"
    assert channels.classify_http_status(503) == "retryable"


def test_channel_result_validation():
    with pytest.raises(ValueError):
        ChannelResult("nope")
    with pytest.raises(ValueError):
        ChannelResult("success", "x")
    with pytest.raises(ValueError):
        ChannelResult("retryable")
    from types import SimpleNamespace

    assert channels.InAppChannel().deliver(SimpleNamespace(id="n-1")).status == "success"
    assert channels.WebhookChannel().deliver(None).error_code == "no_active_subscription"
