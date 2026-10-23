# SPDX-License-Identifier: Apache-2.0
"""对外 Webhook（T4 / M03 §4.3）：签名、载荷、重试、台账、密钥缺失不投递。"""
from __future__ import annotations

import json
import uuid
import pytest

from app.gateway import facts, models, providers, store, webhook
from gatewaykit import (NOW, FakeWebhookSender, apply_migrations, connect, create_schema,
                        drop_schema)


@pytest.fixture(scope="module")
def hook_schema(db, schema_prefix) -> str:              # noqa: ARG001
    name = f"{schema_prefix}_wh_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def hc(hook_schema: str):
    connection = connect(hook_schema, autocommit=True)
    try:
        yield connection
    finally:
        connection.close()


def _batch(hc, *, webhook_url: str | None = "https://example.test/hook",
           account_id: str | None = None) -> models.BatchView:
    batch_id = str(uuid.uuid4())
    account = account_id or str(uuid.uuid4())
    store.insert_batch(hc, batch_id=batch_id, account_id=account, tenant_id=None,
                       api_key_id=1, kind="chat", model="m1", status="queued",
                       request_id=None, idempotency_key=None, total_items=3,
                       eta_seconds=42, cost_estimate_minor=500, deadline_seconds=None,
                       webhook_url=webhook_url, metadata={}, now=NOW)
    store.insert_batch_items(hc, batch_id=batch_id, custom_ids=["c1", "c2", "c3"], now=NOW)
    batch = store.get_batch(hc, batch_id=batch_id)
    assert batch is not None
    return batch


# ─────────────────────────────────────────────────────── 签名与载荷
def test_signature_is_hmac_sha256_over_timestamp_and_body():
    body = b'{"event":"batch.queued"}'
    signature = webhook.sign("whsec_test", "1700000000", body)
    assert len(signature) == 64 and signature == signature.lower()
    # 同输入同输出（确定性）、换时间戳就不同
    assert signature == webhook.sign("whsec_test", "1700000000", body)
    assert signature != webhook.sign("whsec_test", "1700000001", body)


def test_headers_carry_event_timestamp_and_signature():
    headers = webhook.headers(event_type="batch.completed", timestamp="1700000000",
                              signature="abc")
    assert headers[facts.WEBHOOK_EVENT_HEADER] == "batch.completed"
    assert headers[facts.WEBHOOK_TIMESTAMP_HEADER] == "1700000000"
    assert headers[facts.WEBHOOK_SIGNATURE_HEADER] == "hmac-sha256=abc"
    assert headers["Content-Type"] == "application/json"


def test_payload_has_contract_fields_and_no_bodies(hc):
    batch = _batch(hc)
    payload = webhook.build_payload(event_type="batch.queued", batch=batch, occurred_at=NOW)
    assert set(payload) == {"event", "batch_id", "status", "progress", "eta_seconds",
                            "checkpoint_resumes", "occurred_at", "cost"}
    assert payload["progress"] == {"completed": 0, "total": 3}
    assert payload["cost"] == {"estimated": {"amount": "5.00", "unit": "USD"}}
    assert payload["occurred_at"].endswith("Z")
    assert "prompt" not in json.dumps(payload)


def test_unregistered_event_is_rejected(hc):
    batch = _batch(hc)
    with pytest.raises(ValueError):
        webhook.build_payload(event_type="batch.canceled", batch=batch, occurred_at=NOW)


def test_coerce_status_handles_shapes():
    assert webhook.coerce_status(204) == 204
    assert webhook.coerce_status(True) == 200
    assert webhook.coerce_status("201") == 201
    assert webhook.coerce_status(None) is None
    assert webhook.coerce_status("nope") is None


# ─────────────────────────────────────────────────────── 投递 / 重试 / 台账
def test_deliver_success_records_delivered(hc):
    batch = _batch(hc)
    sender = FakeWebhookSender(statuses=[200])
    result = webhook.deliver(hc, event_type="batch.queued", batch=batch, now=NOW, sender=sender,
                             secret_provider=lambda account_id: "whsec_test")
    assert result.state == webhook.DELIVERED and result.attempts == 1
    row = hc.execute("SELECT webhook_state, webhook_attempts, webhook_delivered_at"
                     " FROM batch_jobs WHERE batch_id = %s", (batch.batch_id,)).fetchone()
    assert row[0] == "delivered" and row[1] == 1 and row[2] is not None
    sent = sender.calls[0]
    assert sent["url"] == batch.webhook_url
    body = json.loads(sent["body"])
    assert body["batch_id"] == batch.batch_id
    # 签名可复算
    timestamp = sent["headers"][facts.WEBHOOK_TIMESTAMP_HEADER]
    expected = webhook.sign("whsec_test", timestamp, sent["body"])
    assert sent["headers"][facts.WEBHOOK_SIGNATURE_HEADER] == f"hmac-sha256={expected}"


def test_deliver_retries_then_marks_failed(hc):
    batch = _batch(hc)
    sender = FakeWebhookSender(statuses=[500, 500, 500])
    result = webhook.deliver(hc, event_type="batch.completed", batch=batch, now=NOW,
                             sender=sender, secret_provider=lambda account_id: "whsec_test",
                             sleep=lambda seconds: None)
    assert result.state == webhook.FAILED
    assert result.attempts == facts.WEBHOOK_MAX_ATTEMPTS
    assert result.last_status == 500
    row = hc.execute("SELECT webhook_state, webhook_attempts, webhook_last_error"
                     " FROM batch_jobs WHERE batch_id = %s", (batch.batch_id,)).fetchone()
    assert row[0] == "failed" and row[1] == 3 and "500" in row[2]


def test_deliver_succeeds_on_second_attempt(hc):
    batch = _batch(hc)
    sender = FakeWebhookSender(statuses=[503, 200])
    result = webhook.deliver(hc, event_type="batch.started", batch=batch, now=NOW,
                             sender=sender, secret_provider=lambda account_id: "whsec_test",
                             sleep=lambda seconds: None)
    assert result.state == webhook.DELIVERED and result.attempts == 2


def test_deliver_retries_when_sender_raises(hc):
    batch = _batch(hc)
    sender = FakeWebhookSender(statuses=[200], raises=1)
    result = webhook.deliver(hc, event_type="batch.failed", batch=batch, now=NOW,
                             sender=sender, secret_provider=lambda account_id: "whsec_test",
                             sleep=lambda seconds: None)
    assert result.state == webhook.DELIVERED and result.attempts == 2


def test_missing_secret_skips_delivery(hc):
    batch = _batch(hc)
    sender = FakeWebhookSender()
    result = webhook.deliver(hc, event_type="batch.queued", batch=batch, now=NOW, sender=sender,
                             secret_provider=lambda account_id: None)
    assert result.state == webhook.SKIPPED and sender.calls == []
    state = hc.execute("SELECT webhook_state FROM batch_jobs WHERE batch_id = %s",
                       (batch.batch_id,)).fetchone()[0]
    assert state == "skipped"


def test_no_webhook_url_means_no_delivery(hc):
    batch = _batch(hc, webhook_url=None)
    sender = FakeWebhookSender()
    result = webhook.deliver(hc, event_type="batch.queued", batch=batch, now=NOW, sender=sender,
                             secret_provider=lambda account_id: "whsec_test")
    assert result.state == webhook.SKIPPED and sender.calls == []


def test_sender_not_wired_is_skipped(hc):
    batch = _batch(hc)
    providers.reset_providers()
    result = webhook.deliver(hc, event_type="batch.queued", batch=batch, now=NOW,
                             secret_provider=lambda account_id: "whsec_test",
                             sleep=lambda seconds: None)
    assert result.state == webhook.FAILED and result.attempts == facts.WEBHOOK_MAX_ATTEMPTS


# ─────────────────────────────────────────────────────── 迁移 306 的列
def test_webhook_columns_exist(hc):
    row = hc.execute("SELECT column_name FROM information_schema.columns"
                     " WHERE table_schema = current_schema() AND table_name = 'batch_jobs'"
                     " AND column_name LIKE 'webhook%' ORDER BY 1").fetchall()
    # webhook_url 来自 302，其余 4 列来自 306
    assert [item[0] for item in row] == ["webhook_attempts", "webhook_delivered_at",
                                         "webhook_last_error", "webhook_state",
                                         "webhook_url"]


def test_webhook_state_is_constrained(hc):
    batch = _batch(hc)
    with pytest.raises(Exception):
        store.update_batch_webhook(hc, batch_id=batch.batch_id, state="bogus", attempts=0,
                                   last_error=None, delivered_at=None)
