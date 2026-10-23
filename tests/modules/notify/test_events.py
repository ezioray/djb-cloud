# SPDX-License-Identifier: Apache-2.0
"""事件消费：矩阵映射 / event_id 幂等 / 合并去重 / 对客-内部模板隔离（INV-03 / INV-09）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.notify import events, facts, preferences, store
from notifykit import NOW, count, event, scalar


def _payload(conn, notification_id):
    return scalar(conn, "SELECT payload FROM notification_outbox WHERE aggregate_id = %s",
                  (str(notification_id),))


def test_matrix_covers_registered_consumers():
    for event_type in ("account.created", "cop.earned", "payment.paid", "payout.paid",
                       "refund.completed", "por.published", "risk.case.opened",
                       "risk.case.closed", "risk.limit.hit", "recon.completed",
                       "exception.opened", "exception.closed", "wallet.switched",
                       "deploy.completed", "backup.completed", "ticket.created"):
        assert event_type in events.EVENT_TEMPLATES, event_type
    assert events.template_for("unknown.event") is None
    assert events.template_for("payment.paid").level == "P1"
    assert events.template_for("session.revoked").level == "P0"


def test_consume_creates_notification_and_outbox_in_one_transaction(conn, account_id):
    result = events.consume(conn, event("payment.paid", account_id=account_id,
                                        order_no="ord-1", amount_minor=5000), now=NOW)
    conn.commit()
    assert result.status == "created"
    assert result.level == "P1"
    assert result.template_key == "customer.payment.paid"
    assert count(conn, "notifications", "account_id = %s", (account_id,)) == 1
    assert count(conn, "notification_outbox", "aggregate_id = %s",
                 (result.notification_id,)) == 1
    assert _payload(conn, result.notification_id)["notification_id"] == result.notification_id


def test_consume_is_rolled_back_with_business_transaction(conn, account_id):
    before = count(conn, "notification_outbox")
    events.consume(conn, event("payment.paid", account_id=account_id), now=NOW)
    conn.rollback()                                       # INV-08：通知与事件同生共死
    assert count(conn, "notifications", "account_id = %s", (account_id,)) == 0
    assert count(conn, "notification_outbox") == before


def test_same_event_id_is_idempotent(conn, account_id):
    envelope = event("payment.paid", account_id=account_id, order_no="ord-2")
    first = events.consume(conn, envelope, now=NOW)
    conn.commit()
    second = events.consume(conn, envelope, now=NOW)
    conn.commit()
    assert second.status == "replay"
    assert second.notification_id == first.notification_id
    assert count(conn, "notifications", "account_id = %s", (account_id,)) == 1
    assert count(conn, "notification_outbox", "aggregate_id = %s",
                 (first.notification_id,)) == 1


def test_same_window_merges_into_one_notification(conn, account_id):
    first = events.consume(conn, event("payment.paid", account_id=account_id,
                                       order_no="a"), now=NOW)
    conn.commit()
    second = events.consume(conn, event("payment.paid", account_id=account_id,
                                        order_no="b"), now=NOW)
    conn.commit()
    third = events.consume(conn, event("payment.paid", account_id=account_id,
                                       order_no="c"), now=NOW)
    conn.commit()
    assert [first.status, second.status, third.status] == ["created", "merged", "merged"]
    assert second.notification_id == first.notification_id
    assert third.channel_count == 3                      # INV-03：合并次数
    assert count(conn, "notifications", "account_id = %s", (account_id,)) == 1
    row = conn.execute("SELECT channel_count, merged_event_ids FROM notifications "
                       "WHERE account_id = %s", (account_id,)).fetchone()
    assert row[0] == 3 and len(row[1]) == 2


def test_replay_of_merged_event_is_recognised(conn, account_id):
    first = events.consume(conn, event("payment.paid", account_id=account_id), now=NOW)
    conn.commit()
    merged_envelope = event("payment.paid", account_id=account_id)
    events.consume(conn, merged_envelope, now=NOW)
    conn.commit()
    again = events.consume(conn, merged_envelope, now=NOW)   # 第二次重放
    conn.commit()
    assert again.status == "replay"
    assert again.notification_id == first.notification_id
    assert again.channel_count == 2


def test_new_window_creates_second_notification(conn, account_id):
    events.consume(conn, event("payment.paid", account_id=account_id), now=NOW)
    conn.commit()
    later = event("payment.paid", account_id=account_id,
                  occurred_at=NOW + timedelta(seconds=facts.MERGE_WINDOW_S + 1))
    second = events.consume(conn, later, now=NOW)
    conn.commit()
    assert second.status == "created"
    assert count(conn, "notifications", "account_id = %s", (account_id,)) == 2


def test_unregistered_event_is_ignored(conn, account_id):
    result = events.consume(conn, event("order.something", account_id=account_id), now=NOW)
    conn.commit()
    assert result.status == "ignored"
    assert result.reason == "unregistered_event"
    assert count(conn, "notifications", "account_id = %s", (account_id,)) == 0


def test_event_without_recipient_is_ignored(conn, account_id):
    envelope = event("deploy.completed", account_id=None)
    result = events.consume(conn, envelope, now=NOW)
    conn.commit()
    assert result.status == "ignored"
    assert result.reason == "no_recipient"


def test_internal_template_keeps_operational_fields(conn, account_id):
    result = events.consume(conn, event("recon.completed", account_id=account_id,
                                        run_id="run-1", period="2026-10-22",
                                        p0="0", p1="2", txid="0xabc"), now=NOW)
    conn.commit()
    notification = store.get_notification(conn, account_id, result.notification_id)
    assert notification.template_scope == facts.SCOPE_INTERNAL
    assert notification.template_key == "internal.recon.completed"
    assert notification.payload["txid"] == "0xabc"        # 内部模板可含批次 / txid（INV-09）
    assert notification.level == "P1"


def test_customer_template_drops_internal_details(conn, account_id):
    result = events.consume(conn, event("risk.limit.hit", account_id=account_id,
                                        limit_type="daily", txid="0xdead",
                                        reason_code="limit_hit", amount_minor=100), now=NOW)
    conn.commit()
    notification = store.get_notification(conn, account_id, result.notification_id)
    assert notification.template_scope == facts.SCOPE_CUSTOMER
    assert "txid" not in notification.payload
    assert "limit_type" not in notification.payload        # 判定阈属内部处置细节
    assert notification.payload["reason_code"] == "limit_hit"
    assert notification.level == "P0"


def test_customer_payload_with_email_is_rejected(conn, account_id):
    with pytest.raises(ValueError):
        events.consume(conn, event("payment.paid", account_id=account_id,
                                   reason_code="ok", email="a@b.co"), now=NOW)
    conn.rollback()


def test_p0_channels_ignore_preferences(conn, account_id):
    preferences.put(conn, account_id, {"email": False, "in_app": True, "webhook": False},
                    now=NOW)
    conn.commit()
    result = events.consume(conn, event("session.revoked", account_id=account_id,
                                        session_id="s-1", reason_code="logout_all"), now=NOW)
    conn.commit()
    notification = store.get_notification(conn, account_id, result.notification_id)
    assert "in_app" in notification.channels
    assert "email" in notification.channels               # INV-01：P0 邮件不可退订
    assert notification.level == "P0"


def test_in_app_off_suppresses_unread_but_keeps_record(conn, account_id):
    preferences.put(conn, account_id, {"email": True, "in_app": False, "webhook": False},
                    now=NOW)
    conn.commit()
    result = events.consume(conn, event("payment.paid", account_id=account_id), now=NOW)
    conn.commit()
    notification = store.get_notification(conn, account_id, result.notification_id)
    assert notification.read_at is not None                # INV-02：不产生未读提醒
    assert count(conn, "notifications", "account_id = %s", (account_id,)) == 1


def test_webhook_channel_requires_pref_and_active_subscription(conn, account_id):
    from app.notify import webhooks

    webhooks.create(conn, account_id=account_id, url="https://hooks.example.com/cb",
                    events=["payment.settled"], now=NOW)
    conn.commit()
    result = events.consume(conn, event("payment.paid", account_id=account_id), now=NOW)
    conn.commit()
    notification = store.get_notification(conn, account_id, result.notification_id)
    assert "webhook" not in notification.channels          # 偏好默认关
    preferences.put(conn, account_id, {"email": True, "in_app": True, "webhook": True},
                    now=NOW)
    conn.commit()
    result2 = events.consume(conn, event("payment.paid", account_id=account_id,
                                         occurred_at=NOW + timedelta(hours=2)), now=NOW)
    conn.commit()
    notification2 = store.get_notification(conn, account_id, result2.notification_id)
    assert "webhook" in notification2.channels


def test_request_notification_entry_point(conn, account_id):
    result = events.request_notification(conn, account_id=account_id, type="payout.paid",
                                         payload={"batch_no": "b-1", "amount_minor": 900},
                                         now=NOW)
    conn.commit()
    assert result.status == "created"
    with pytest.raises(ValueError):
        events.request_notification(conn, account_id=account_id, type="nope.event", now=NOW)


@pytest.mark.parametrize("bad", [
    {"type": "payment.paid", "payload": {}},                             # 缺 event_id
    {"event_id": "not-a-uuid", "type": "payment.paid", "occurred_at": NOW},
    {"event_id": str(uuid.uuid4()), "type": "payment.paid"},             # 缺 occurred_at
    {"event_id": str(uuid.uuid4()), "type": "payment.paid", "occurred_at": "not-a-date"},
    {"event_id": str(uuid.uuid4()), "type": "", "occurred_at": NOW},
    {"event_id": str(uuid.uuid4()), "type": "payment.paid", "occurred_at": NOW,
     "payload": ["x"]},
    "not-an-event",
])
def test_malformed_envelopes_are_rejected(conn, bad):
    with pytest.raises(ValueError):
        events.consume(conn, bad, now=NOW)
    conn.rollback()


def test_iso_string_occurred_at_is_accepted(conn, account_id):
    envelope = event("payment.paid", account_id=account_id)
    envelope["occurred_at"] = NOW.isoformat()
    result = events.consume(conn, envelope, now=NOW)
    conn.commit()
    assert result.status == "created"


def test_aggregate_id_fallback_for_account_scope(conn, account_id):
    envelope = event("cop.earned", account_id=None)
    envelope["aggregate_type"] = "account"
    envelope["aggregate_id"] = str(account_id)
    envelope["payload"] = {"amount_minor": 10}
    result = events.consume(conn, envelope, now=NOW)
    conn.commit()
    assert result.status == "created"
