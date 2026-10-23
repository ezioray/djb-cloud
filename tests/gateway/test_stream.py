# SPDX-License-Identifier: Apache-2.0
"""SSE 流式（T3 / M03 §6 流程 2 / §4.3 / INV-M03-04）：分帧、中断、估算用量、建立去重。"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest

from app.gateway import (errors, facts, features, models, providers, ratelimit, store, stream)
from gatewaykit import (NOW, FakeAuth, FakeNode, FakeRoute, FakeStream, FakeUsage,
                        apply_migrations, connect, create_schema, drop_schema, principal_dict)


@pytest.fixture(scope="module")
def sse_schema(db, schema_prefix) -> str:               # noqa: ARG001
    """流式用例专用 schema：流结束后的落库走**独立事务**，用 autocommit 连接最直观。"""
    name = f"{schema_prefix}_sse_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def sse_conn(sse_schema: str):
    connection = connect(sse_schema, autocommit=True)
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


def _body(**overrides):
    body = {"model": "m1", "stream": True,
            "messages": [{"role": "user", "content": "hi"}]}
    body.update(overrides)
    return body


def _wire(*, stream_client=None, route=None, usage=None):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(route or FakeRoute())
    providers.set_node_client(FakeNode())
    providers.set_stream_client(stream_client or FakeStream())
    providers.set_usage_provider(usage or FakeUsage())


def _prepare(conn, *, schema, principal=None, body=None, key=None, now=NOW):
    return stream.prepare(conn, principal=principal or _principal(), body=body or _body(),
                          request_id=str(uuid.uuid4()), trace_id="trace-s",
                          idempotency_key=key, now=now,
                          connection_factory=lambda: connect(schema, autocommit=True))


def _frames(plan) -> list[str]:
    return list(plan.frames())


def _payloads(frames: list[str]) -> list[dict]:
    out = []
    for frame in frames:
        text = frame.strip()
        if not text.startswith("data: "):
            continue
        data = text[len("data: "):]
        if data == facts.SSE_DONE:
            out.append({"done": True})
            continue
        out.append(json.loads(data))
    return out


# ─────────────────────────────────────────────────────── 正常收尾
def test_stream_success_ends_with_done_and_records_metadata(sse_schema, sse_conn):
    _wire()
    plan = _prepare(sse_conn, schema=sse_schema)
    frames = _frames(plan)
    assert frames[0].startswith("data: {")
    assert frames[-1] == f"data: {facts.SSE_DONE}\n\n"
    payloads = _payloads(frames)
    assert payloads[0]["object"] == facts.SSE_CHUNK_OBJECT
    assert payloads[0]["choices"][0]["delta"]["role"] == "assistant"
    assert payloads[0]["choices"][0]["delta"]["content"] == "hello"
    assert payloads[-2]["choices"][0]["finish_reason"] == "stop"
    assert payloads[-2]["usage"]["total_tokens"] == 5

    row = store.fetch_request_log(sse_conn, plan.request_id)
    assert row is not None
    assert row["status"] == "completed" and row["http_status"] == 200
    assert row["stream"] is True
    assert row["tokens_in"] == 3 and row["tokens_out"] == 2
    assert row["usage_source"] == "actual"
    assert row["first_byte_ms"] == 5


def test_stream_success_emits_request_completed(sse_conn, sse_schema):
    _wire()
    plan = _prepare(sse_conn, schema=sse_schema)
    _frames(plan)
    rows = sse_conn.execute("SELECT type, payload FROM m03_outbox WHERE aggregate_id = %s",
                            (plan.request_id,)).fetchall()
    assert [row[0] for row in rows] == ["request.completed"]


def test_stream_usage_is_estimated_when_upstream_omits_tokens(sse_schema, sse_conn):
    usage = FakeUsage()
    _wire(stream_client=FakeStream(tokens_in=None, tokens_out=None), usage=usage)
    plan = _prepare(sse_conn, schema=sse_schema)
    _frames(plan)
    row = store.fetch_request_log(sse_conn, plan.request_id)
    assert row["usage_source"] == "estimated"
    assert row["tokens_in"] > 0 and row["tokens_out"] > 0
    assert usage.drafts and usage.drafts[0].usage_source == "estimated"


def test_stream_first_byte_ms_falls_back_to_elapsed(sse_schema, sse_conn):
    _wire(stream_client=FakeStream(first_byte_ms=None))
    plan = _prepare(sse_conn, schema=sse_schema)
    _frames(plan)
    row = store.fetch_request_log(sse_conn, plan.request_id)
    assert row["first_byte_ms"] is not None and row["first_byte_ms"] >= 0


# ─────────────────────────────────────────────────────── 中断
def test_stream_interruption_after_first_byte_marks_interrupted(sse_schema, sse_conn):
    usage = FakeUsage()
    _wire(stream_client=FakeStream(chunks=["a", "b", "c"], fail_after=1), usage=usage)
    plan = _prepare(sse_conn, schema=sse_schema)
    frames = _frames(plan)
    assert frames[-1] == f"data: {facts.SSE_DONE}\n\n"
    payloads = _payloads(frames)
    error = [item for item in payloads if "error" in item]
    assert error, "中断必须在流内给 error 帧"
    assert error[0]["error"]["code"] == 44101
    assert error[0]["error"]["request_id"] == plan.request_id

    row = store.fetch_request_log(sse_conn, plan.request_id)
    assert row["status"] == "interrupted"
    assert row["http_status"] == 441
    assert row["error_code"] == 44101
    assert row["usage_source"] == "estimated"
    # 关闭（默认）时不主动写 M05 估算用量，由 M05 事后校正
    assert usage.drafts == []


def test_stream_interruption_with_sync_feature_writes_estimated_usage(sse_schema, sse_conn,
                                                                     monkeypatch):
    monkeypatch.setattr(features, "enabled",
                        lambda name: name == "gateway.stream_estimated_usage_sync")
    usage = FakeUsage()
    _wire(stream_client=FakeStream(chunks=["a", "b"], fail_after=1), usage=usage)
    plan = _prepare(sse_conn, schema=sse_schema)
    _frames(plan)
    assert len(usage.drafts) == 1
    assert usage.drafts[0].usage_source == "estimated"
    assert usage.drafts[0].request_id == plan.request_id


def test_stream_interruption_emits_request_failed(sse_conn, sse_schema):
    _wire(stream_client=FakeStream(chunks=["a", "b"], fail_after=1))
    plan = _prepare(sse_conn, schema=sse_schema)
    _frames(plan)
    rows = sse_conn.execute("SELECT type, payload FROM m03_outbox WHERE aggregate_id = %s",
                            (plan.request_id,)).fetchall()
    assert [row[0] for row in rows] == ["request.failed"]
    payload = rows[0][1] if isinstance(rows[0][1], dict) else json.loads(rows[0][1])
    assert payload["error_code"] == 44101
    assert payload["upstream_error_class"] == "upstream_error"


def test_client_disconnect_marks_interrupted(sse_schema, sse_conn):
    _wire(stream_client=FakeStream(chunks=["a", "b", "c", "d"]))
    plan = _prepare(sse_conn, schema=sse_schema)
    iterator = plan.frames()
    next(iterator)                                    # 已发出首帧
    iterator.close()                                  # 客户端断开（GeneratorExit）
    row = store.fetch_request_log(sse_conn, plan.request_id)
    assert row["status"] == "interrupted" and row["error_code"] == 44101
    assert row["usage_source"] == "estimated"


# ─────────────────────────────────────────────────────── 首字节前失败
def test_first_byte_timeout_twice_is_504(sse_schema, sse_conn):
    _wire(stream_client=FakeStream(timeouts=2))
    with pytest.raises(errors.GatewayError) as info:
        _prepare(sse_conn, schema=sse_schema)
    assert (info.value.http_status, info.value.code) == (504, 50902)
    assert info.value.details["attempts"] == facts.STREAM_MAX_ATTEMPTS


def test_first_byte_failure_then_success_reroutes(sse_schema, sse_conn):
    route = FakeRoute()
    client = FakeStream(timeouts=1)
    _wire(route=route, stream_client=client)
    plan = _prepare(sse_conn, schema=sse_schema)
    assert plan.attempts == 2
    assert [item.attempt_no for item in route.requests] == [1, 2]
    frames = _frames(plan)
    assert frames[-1] == f"data: {facts.SSE_DONE}\n\n"


def test_empty_upstream_stream_is_upstream_error(sse_schema, sse_conn):
    _wire(stream_client=FakeStream(chunks=[]))
    with pytest.raises(errors.GatewayError) as info:
        _prepare(sse_conn, schema=sse_schema)
    assert (info.value.http_status, info.value.code) == (502, 50903)


def test_no_route_is_503(sse_schema, sse_conn):
    _wire(route=FakeRoute(fail_times=99))
    with pytest.raises(errors.GatewayError) as info:
        _prepare(sse_conn, schema=sse_schema)
    assert (info.value.http_status, info.value.code) == (503, 50901)


def test_stream_client_missing_is_fail_closed(sse_schema, sse_conn):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode())
    with pytest.raises(errors.GatewayError) as info:
        _prepare(sse_conn, schema=sse_schema)
    assert (info.value.http_status, info.value.code) == (503, 45001)


def test_non_stream_body_is_rejected_by_stream_entry(sse_schema, sse_conn):
    _wire()
    with pytest.raises(errors.GatewayError) as info:
        _prepare(sse_conn, schema=sse_schema, body={"model": "m1",
                                                    "messages": [{"role": "user",
                                                                  "content": "hi"}]})
    assert info.value.code == 40001


# ─────────────────────────────────────────────────────── 限流 / 建立去重
def test_stream_rate_limited_before_first_byte(sse_schema, sse_conn):
    _wire()
    bucket = ratelimit.SlidingWindowLimiter()
    principal = _principal(qps=1)
    stream.prepare(sse_conn, principal=principal, body=_body(), request_id=str(uuid.uuid4()),
                   trace_id="t", now=NOW, limiter=bucket,
                   connection_factory=lambda: connect(sse_schema, autocommit=True))
    with pytest.raises(errors.GatewayError) as info:
        stream.prepare(sse_conn, principal=principal,
                       body=_body(messages=[{"role": "user", "content": "again"}]),
                       request_id=str(uuid.uuid4()), trace_id="t", now=NOW, limiter=bucket,
                       connection_factory=lambda: connect(sse_schema, autocommit=True))
    assert info.value.code == 42901


def test_duplicate_stream_establishment_within_60s_is_409(sse_schema, sse_conn):
    _wire()
    principal = _principal()
    body = _body(messages=[{"role": "user", "content": "dedupe"}])
    first = _prepare(sse_conn, schema=sse_schema, body=body, principal=principal)
    _frames(first)
    with pytest.raises(errors.GatewayError) as info:
        _prepare(sse_conn, schema=sse_schema, body=body, principal=principal,
                 now=NOW + timedelta(seconds=5))
    assert (info.value.http_status, info.value.code) == (409, 40919)


def test_stream_can_be_established_again_after_the_60s_window(sse_schema, sse_conn):
    _wire()
    principal = _principal()
    body = _body(messages=[{"role": "user", "content": "reopen"}])
    first = _prepare(sse_conn, schema=sse_schema, body=body, principal=principal)
    _frames(first)
    second = _prepare(sse_conn, schema=sse_schema, body=body, principal=principal,
                      now=NOW + timedelta(seconds=facts.STREAM_DEDUP_WINDOW_S + 1))
    assert second.request_id != first.request_id


def test_stream_with_idempotency_key_is_deduplicated(sse_schema, sse_conn):
    _wire()
    principal = _principal()
    key = "stream-key-0123456789"
    first = _prepare(sse_conn, schema=sse_schema, key=key, principal=principal)
    _frames(first)
    with pytest.raises(errors.GatewayError) as info:
        _prepare(sse_conn, schema=sse_schema, key=key, principal=principal)
    assert info.value.code == 40919


# ─────────────────────────────────────────────────────── 帧格式
def test_frame_helpers_are_openai_compatible():
    frame = stream.chunk_frame(request_id="r1", created=1_700_000_000, model="m1",
                               delta={"content": "x"})
    assert frame.startswith("data: {")
    payload = json.loads(frame[len("data: "):])
    assert payload["object"] == "chat.completion.chunk"
    assert payload["choices"][0]["delta"] == {"content": "x"}
    assert stream.done_frame() == "data: [DONE]\n\n"
    error = errors.GatewayError("stream_interrupted", "中断")
    assert json.loads(stream.error_frame(request_id="r1", exc=error)[6:])["error"]["code"] == 44101
