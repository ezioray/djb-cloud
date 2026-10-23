# SPDX-License-Identifier: Apache-2.0
"""慢任务（T4 / M03 §6 流程 3 / §3.1 状态机 / INV-M03-06 / INV-M03-09）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.gateway import batches, errors, facts, features, models, providers, store
from gatewaykit import (NOW, FakeAuth, FakeNode, FakeRoute, FakeSigner, FakeStream, FakeUsage,
                        FakeWebhookSender, apply_migrations, connect, create_schema, drop_schema,
                        principal_dict)


@pytest.fixture(scope="module")
def batch_schema(db, schema_prefix) -> str:            # noqa: ARG001
    name = f"{schema_prefix}_bat_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def bc(batch_schema: str):
    connection = connect(batch_schema, autocommit=True)
    try:
        yield connection
    finally:
        connection.close()


def _principal(**kwargs):
    values = {"qps": 100}
    values.update(kwargs)
    return models.coerce_principal(principal_dict(account_id=uuid.uuid4(),
                                                  tenant_id=uuid.uuid4(), api_key_id=7,
                                                  **values))


def _body(items: int = 2, **overrides):
    body = {
        "kind": "chat",
        "model": "m1",
        "items": [{"custom_id": f"c{index}", "input": {"messages": [
            {"role": "user", "content": f"prompt-{index}"}]}} for index in range(items)],
    }
    body.update(overrides)
    return body


def _wire(*, price_minor: int = 250, eta_seconds: int = 30, route=None):
    provider = route or FakeRoute(price_minor=price_minor, eta_seconds=eta_seconds)
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(provider)
    providers.set_node_client(FakeNode())
    providers.set_stream_client(FakeStream())
    providers.set_usage_provider(FakeUsage())
    return provider


def _submit(conn, principal=None, *, body=None, key=None, now=NOW):
    return batches.submit(conn, principal=principal or _principal(), body=body or _body(),
                          request_id=str(uuid.uuid4()), trace_id="trace-b",
                          idempotency_key=key, now=now)


# ─────────────────────────────────────────────────────── 校验
def test_validate_accepts_minimal_batch():
    draft = batches.validate_batch(_body(items=3))
    assert draft.kind == "chat" and draft.model == "m1"
    assert [item.custom_id for item in draft.items] == ["c0", "c1", "c2"]


@pytest.mark.parametrize("body", [
    {},
    {"kind": "unknown", "model": "m1", "items": [{"custom_id": "c1"}]},
    {"kind": "chat", "model": "", "items": [{"custom_id": "c1"}]},
    {"kind": "chat", "model": "m1", "items": []},
    {"kind": "chat", "model": "m1", "items": "x"},
    {"kind": "chat", "model": "m1", "items": [{"custom_id": "c1"}, {"custom_id": "c1"}]},
    {"kind": "chat", "model": "m1", "items": [{}]},
    {"kind": "chat", "model": "m1", "items": [{"custom_id": "x" * 129}]},
    {"kind": "chat", "model": "m1", "items": [{"custom_id": "c1"}], "deadline_seconds": 30},
    {"kind": "chat", "model": "m1", "items": [{"custom_id": "c1"}], "webhook_url": "ftp://x"},
    {"kind": "chat", "model": "m1", "items": [{"custom_id": "c1"}], "metadata": "x"},
    {"kind": "chat", "model": "m1", "items": [{"custom_id": "c1", "input": "x"}]},
])
def test_validate_rejects_bad_batches(body):
    with pytest.raises(errors.GatewayError) as info:
        batches.validate_batch(body)
    assert info.value.code in (40001, 40013)


def test_validate_caps_item_count():
    body = {"kind": "chat", "model": "m1",
            "items": [{"custom_id": f"c{index}"} for index in range(
                facts.BATCH_MAX_ITEMS + 1)]}
    with pytest.raises(errors.GatewayError) as info:
        batches.validate_batch(body)
    assert (info.value.http_status, info.value.code) == (413, 40013)


def test_validate_reads_confirm_flag_from_metadata():
    draft = batches.validate_batch(_body(metadata={"confirm_cost": True, "x": 1}))
    assert draft.confirm_cost is True and draft.metadata == {"x": 1}


# ─────────────────────────────────────────────────────── 提交
def test_submit_creates_batch_and_returns_202(bc):
    _wire()
    result = _submit(bc)
    assert result.status_code == 202
    payload = result.payload
    assert payload["status"] == "queued"
    assert payload["eta_seconds"] == 30
    assert payload["cost_estimate"] == {"amount": "5.00", "unit": "USD"}   # 250 × 2 条 = 500 分
    batch = store.get_batch(bc, batch_id=payload["batch_id"])
    assert batch is not None
    assert batch.total_items == 2 and batch.completed_items == 0
    assert batch.cost_estimate_minor == 500
    items = store.list_batch_items(bc, batch_id=batch.batch_id)
    assert [row["custom_id"] for row in items] == ["c0", "c1"]
    assert all(row["status"] == "queued" for row in items)


def test_submit_does_not_persist_item_bodies(bc):
    """INV-M03-02：条目正文不落库。"""
    _wire()
    result = _submit(bc, body=_body(items=1))
    row = bc.execute("SELECT to_jsonb(t)::text FROM batch_items t WHERE batch_id = %s",
                     (result.payload["batch_id"],)).fetchone()[0]
    assert "prompt-0" not in row


def test_submit_is_idempotent_with_key(bc):
    _wire()
    principal = _principal()
    key = "batch-key-0123456789"
    first = _submit(bc, principal, key=key)
    second = _submit(bc, principal, key=key)
    assert second.replayed is True
    assert second.payload == first.payload
    count = bc.execute("SELECT count(*) FROM batch_jobs WHERE account_id = %s",
                       (principal.account_id,)).fetchone()[0]
    assert count == 1


def test_submit_same_key_different_body_is_409(bc):
    _wire()
    principal = _principal()
    key = "batch-key-0123456789"
    _submit(bc, principal, key=key)
    with pytest.raises(errors.GatewayError) as info:
        _submit(bc, principal, key=key, body=_body(items=3))
    assert (info.value.http_status, info.value.code) == (409, 40919)


def test_submit_fingerprint_dedupes_without_key(bc):
    _wire()
    principal = _principal()
    body = _body(items=1)
    first = _submit(bc, principal, body=body)
    second = _submit(bc, principal, body=body)
    assert second.replayed is True and second.payload == first.payload


def test_submit_over_ten_usd_requires_confirmation(bc):
    _wire(price_minor=600)                      # 600 × 2 = 1200 分 = 12 USD > 10 USD
    principal = _principal()
    result = _submit(bc, principal)
    assert result.status_code == 202 and result.needs_confirm is True
    error = result.payload["error"]
    assert error["code"] == 45202
    assert error["confirm_required"] is True
    assert error["cost_estimate"] == {"amount": "12.00", "unit": "USD"}
    assert bc.execute("SELECT count(*) FROM batch_jobs WHERE account_id = %s",
                      (principal.account_id,)).fetchone()[0] == 0


def test_submit_with_confirmation_creates_the_batch(bc):
    _wire(price_minor=600)
    result = _submit(bc, body=_body(metadata={"confirm_cost": True}))
    assert result.status_code == 202 and result.needs_confirm is False
    assert result.batch is not None


def test_submit_without_route_is_503(bc):
    _wire(route=FakeRoute(fail_times=99))
    with pytest.raises(errors.GatewayError) as info:
        _submit(bc)
    assert (info.value.http_status, info.value.code) == (503, 50901)


def test_submit_queues_webhook_when_gated_on(bc, monkeypatch):
    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "gateway.batch_webhook_delivery")
    sender = FakeWebhookSender()
    providers.set_webhook_sender(sender)
    providers.set_webhook_secret_provider(lambda account_id: "whsec_test")
    _wire()
    result = _submit(bc, body=_body(items=1, webhook_url="https://example.test/hook"))
    assert result.status_code == 202
    assert len(sender.calls) == 1
    assert sender.calls[0]["headers"][facts.WEBHOOK_EVENT_HEADER] == "batch.queued"
    batch = store.get_batch(bc, batch_id=result.payload["batch_id"])
    assert batch is not None
    state = bc.execute("SELECT webhook_state FROM batch_jobs WHERE batch_id = %s",
                       (batch.batch_id,)).fetchone()[0]
    assert state == "delivered"


def test_submit_does_not_deliver_webhook_by_default(bc):
    sender = FakeWebhookSender()
    providers.set_webhook_sender(sender)
    providers.set_webhook_secret_provider(lambda account_id: "whsec_test")
    _wire()
    _submit(bc, body=_body(items=1, webhook_url="https://example.test/hook"))
    assert sender.calls == []                   # 闸门默认关闭：只落库


# ─────────────────────────────────────────────────────── 轮询
def test_get_returns_progress_and_cost(bc):
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=2))
    payload = batches.get(bc, principal=principal, batch_id=created.payload["batch_id"], now=NOW)
    assert payload["status"] == "queued"
    assert payload["progress"] == {"completed": 0, "total": 2}
    assert payload["cost_estimate"] == {"amount": "5.00", "unit": "USD"}
    assert len(payload["items"]) == 2
    assert payload["created_at"].endswith("Z")


def test_get_unknown_batch_is_404(bc):
    _wire()
    with pytest.raises(errors.GatewayError) as info:
        batches.get(bc, principal=_principal(), batch_id=str(uuid.uuid4()), now=NOW)
    assert (info.value.http_status, info.value.code) == (404, 40401)


def test_get_other_accounts_batch_is_404(bc):
    _wire()
    owner = _principal()
    outsider = _principal()
    created = _submit(bc, owner, body=_body(items=1))
    with pytest.raises(errors.GatewayError) as info:
        batches.get(bc, principal=outsider, batch_id=created.payload["batch_id"], now=NOW)
    assert info.value.code == 40401


def test_results_ref_is_signed_and_reissued_after_expiry(bc):
    signer = FakeSigner()
    providers.set_result_signer(signer)
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=1))
    batch_id = created.payload["batch_id"]
    batches.advance(bc, batch_id=batch_id, status="running", now=NOW)
    batches.advance(bc, batch_id=batch_id, status="succeeded", now=NOW, completed=1)
    first = batches.get(bc, principal=principal, batch_id=batch_id, now=NOW)
    assert first["results_ref"].startswith("https://files.example/")
    # 过期后重新签发（INV-M03-09）
    expired = first["results_ref"]
    later = NOW + timedelta(seconds=facts.BATCH_RESULT_URL_TTL_S + 1)
    second = batches.get(bc, principal=principal, batch_id=batch_id, now=later)
    assert second["results_ref"] != expired
    assert len(signer.calls) == 2


def test_without_signer_results_ref_is_absent(bc):
    providers.reset_providers()
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=1))
    batch_id = created.payload["batch_id"]
    batches.advance(bc, batch_id=batch_id, status="running", now=NOW)
    batches.advance(bc, batch_id=batch_id, status="succeeded", now=NOW, completed=1)
    payload = batches.get(bc, principal=principal, batch_id=batch_id, now=NOW)
    assert "results_ref" not in payload


# ─────────────────────────────────────────────────────── 取消（幂等）
def test_cancel_is_idempotent(bc):
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=2))
    batch_id = created.payload["batch_id"]
    first = batches.cancel(bc, principal=principal, batch_id=batch_id, now=NOW)
    assert first["status"] == "canceled" and first["canceled_at"].endswith("Z")
    second = batches.cancel(bc, principal=principal, batch_id=batch_id,
                            now=NOW + timedelta(seconds=5))
    assert second["status"] == "canceled"
    assert second["canceled_at"] == first["canceled_at"]
    items = store.list_batch_items(bc, batch_id=batch_id)
    assert all(row["status"] == "canceled" for row in items)


def test_cancel_terminal_batch_returns_current_state(bc):
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=1))
    batch_id = created.payload["batch_id"]
    batches.advance(bc, batch_id=batch_id, status="running", now=NOW)
    batches.advance(bc, batch_id=batch_id, status="succeeded", now=NOW, completed=1)
    payload = batches.cancel(bc, principal=principal, batch_id=batch_id, now=NOW)
    assert payload["status"] == "succeeded"       # 终态不迁移、不报错（INV-M03-06）
    assert "canceled_at" not in payload


def test_cancel_unknown_batch_is_404(bc):
    _wire()
    with pytest.raises(errors.GatewayError) as info:
        batches.cancel(bc, principal=_principal(), batch_id=str(uuid.uuid4()), now=NOW)
    assert info.value.code == 40401


def test_cancel_with_idempotency_key_replays(bc):
    _wire()
    principal = _principal()
    key = "cancel-key-0123456789"
    created = _submit(bc, principal, body=_body(items=1))
    batch_id = created.payload["batch_id"]
    first = batches.cancel(bc, principal=principal, batch_id=batch_id, now=NOW,
                           idempotency_key=key)
    second = batches.cancel(bc, principal=principal, batch_id=batch_id,
                            now=NOW + timedelta(seconds=1), idempotency_key=key)
    assert second == first


# ─────────────────────────────────────────────────────── 执行推进（worker API）
def test_advance_walks_the_state_machine(bc):
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=3))
    batch_id = created.payload["batch_id"]
    running = batches.advance(bc, batch_id=batch_id, status="running", now=NOW)
    assert running.status == "running" and running.checkpoint_resumes == 0
    resumed = batches.advance(bc, batch_id=batch_id, status="running", now=NOW,
                              checkpoint_resumes=2)
    assert resumed.checkpoint_resumes == 2
    done = batches.advance(bc, batch_id=batch_id, status="succeeded", now=NOW, completed=3,
                           cost_actual_minor=480)
    assert done.status == "succeeded" and done.completed_items == 3
    assert done.cost_actual_minor == 480 and done.completed_at is not None


def test_advance_rejects_illegal_transition(bc):
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=1))
    batch_id = created.payload["batch_id"]
    batches.advance(bc, batch_id=batch_id, status="running", now=NOW)
    batches.advance(bc, batch_id=batch_id, status="succeeded", now=NOW, completed=1)
    with pytest.raises(errors.GatewayError) as info:
        batches.advance(bc, batch_id=batch_id, status="failed", now=NOW)
    assert (info.value.http_status, info.value.code) == (409, 40919)


def test_advance_unknown_batch_is_404(bc):
    _wire()
    with pytest.raises(errors.GatewayError) as info:
        batches.advance(bc, batch_id=str(uuid.uuid4()), status="running", now=NOW)
    assert info.value.code == 40401


def test_advance_emits_webhook_events_when_gated_on(bc, monkeypatch):
    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "gateway.batch_webhook_delivery")
    sender = FakeWebhookSender(statuses=[200, 200, 200])
    providers.set_webhook_sender(sender)
    providers.set_webhook_secret_provider(lambda account_id: "whsec_test")
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=2, webhook_url="https://example.test/h"))
    batch_id = created.payload["batch_id"]
    batches.advance(bc, batch_id=batch_id, status="running", now=NOW)
    batches.advance(bc, batch_id=batch_id, status="succeeded", now=NOW, completed=2)
    events = [call["headers"][facts.WEBHOOK_EVENT_HEADER] for call in sender.calls]
    assert events == ["batch.queued", "batch.started", "batch.completed"]


def test_advance_emits_checkpoint_restored_event(bc, monkeypatch):
    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "gateway.batch_webhook_delivery")
    sender = FakeWebhookSender()
    providers.set_webhook_sender(sender)
    providers.set_webhook_secret_provider(lambda account_id: "whsec_test")
    _wire()
    principal = _principal()
    created = _submit(bc, principal, body=_body(items=2, webhook_url="https://example.test/h"))
    batch_id = created.payload["batch_id"]
    batches.advance(bc, batch_id=batch_id, status="running", now=NOW)
    batches.advance(bc, batch_id=batch_id, status="running", now=NOW, checkpoint_resumes=1)
    events = [call["headers"][facts.WEBHOOK_EVENT_HEADER] for call in sender.calls]
    assert "batch.checkpoint_restored" in events
