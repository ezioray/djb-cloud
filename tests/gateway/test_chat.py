# SPDX-License-Identifier: AGPL-3.0-or-later
"""实时非流式主链路（M03 §6 流程 1 / T2）：鉴权 → 限流/配额 → 校验 → 幂等 → 路由 →
派发（≤2 次尝试）→ 计量 → 日志 + 事件。DB 用例（隔离 schema）。"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest

from app.gateway import (chat, errors, facts, features, models, providers, store)
from gatewaykit import NOW, FakeAuth, FakeCatalog, FakeNode, FakeRoute, FakeUsage, principal_dict


def _body(**overrides):
    body = {"model": "m1", "messages": [{"role": "user", "content": "hi"}]}
    body.update(overrides)
    return body


def _principal(**kwargs):
    return models.coerce_principal(principal_dict(account_id=uuid.uuid4(),
                                                  tenant_id=uuid.uuid4(), api_key_id=7,
                                                  **kwargs))


def _run(conn, principal, *, body=None, request_id=None, key=None, now=NOW, limiter=None):
    return chat.complete(conn, principal=principal, body=body or _body(),
                         request_id=request_id or str(uuid.uuid4()), trace_id="trace-1",
                         idempotency_key=key, now=now, limiter=limiter)


def _outbox(conn, request_id: str) -> list[dict]:
    rows = conn.execute("SELECT type, payload FROM m03_outbox WHERE aggregate_id = %s"
                        " ORDER BY occurred_at", (request_id,)).fetchall()
    return [{"type": row[0], "payload": row[1] if isinstance(row[1], dict) else json.loads(row[1])}
            for row in rows]


def _count(conn, table: str, request_id: str) -> int:
    return int(conn.execute(f"SELECT count(*) FROM {table} WHERE request_id = %s",
                            (request_id,)).fetchone()[0])


# ─────────────────────────────────────────────────────── 成功路径
def test_success_returns_chat_completion_and_records_metadata(conn, wired):
    principal = _principal(qps=100)
    request_id = str(uuid.uuid4())
    outcome = _run(conn, principal, request_id=request_id)
    payload = outcome.payload
    assert outcome.status_code == 200 and outcome.replayed is False
    assert payload["object"] == "chat.completion"
    assert payload["id"] == request_id
    assert payload["model"] == "m1"
    assert payload["choices"][0]["message"] == {"role": "assistant", "content": "hello"}
    assert payload["choices"][0]["finish_reason"] == "stop"
    assert payload["usage"] == {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
    assert payload["created"] == int(NOW.timestamp())

    row = store.fetch_request_log(conn, request_id)
    assert row is not None
    assert row["status"] == "completed" and row["http_status"] == 200
    assert row["node_id"] == "n_001" and row["model"] == "m1"
    assert row["tokens_in"] == 3 and row["tokens_out"] == 2
    assert row["usage_source"] == "actual"
    assert row["first_byte_ms"] == 9 and row["latency_ms"] == 12
    assert row["account_id"] == uuid.UUID(principal.account_id)


def test_success_emits_request_completed_event(conn, wired):
    request_id = str(uuid.uuid4())
    _run(conn, _principal(qps=100), request_id=request_id)
    events = _outbox(conn, request_id)
    assert [item["type"] for item in events] == ["request.completed"]
    payload = events[0]["payload"]
    assert set(payload) == set(facts.EVENT_PAYLOAD_KEYS["request.completed"])
    assert payload["request_id"] == request_id
    assert payload["usage_source"] == "actual"


def test_success_records_usage_with_m05(conn, wired):
    request_id = str(uuid.uuid4())
    _run(conn, _principal(qps=100), request_id=request_id)
    drafts = wired["usage"].drafts
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.request_id == request_id and draft.attempt_no == 1
    assert draft.node_id == "n_001" and draft.access == "A1"
    assert draft.tokens_in == 3 and draft.tokens_out == 2
    assert draft.amount_minor == 250               # M04 决策报价（USD 分）
    assert draft.policy_version == "pv-1"
    assert draft.usage_source == "actual"


def test_body_and_completion_text_are_never_persisted(conn, wired):
    """INV-M03-02：日志与事件里只有元数据。"""
    secret = "SUPER-SECRET-PROMPT-TEXT"
    request_id = str(uuid.uuid4())
    _run(conn, _principal(qps=100), body=_body(messages=[{"role": "user", "content": secret}]),
         request_id=request_id)
    row = store.fetch_request_log(conn, request_id)
    assert secret not in json.dumps(row, default=str)
    assert secret not in json.dumps(_outbox(conn, request_id), ensure_ascii=False)


def test_estimated_usage_when_upstream_omits_tokens(conn):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode(tokens_in=None, tokens_out=None, usage_source="estimated"))
    providers.set_usage_provider(FakeUsage())
    request_id = str(uuid.uuid4())
    _run(conn, _principal(qps=100), request_id=request_id)
    row = store.fetch_request_log(conn, request_id)
    assert row["usage_source"] == "estimated"
    assert row["tokens_in"] > 0 and row["tokens_out"] > 0


# ─────────────────────────────────────────────────────── 幂等 / 指纹
def test_idempotency_key_replays_the_first_result(conn, wired):
    principal = _principal(qps=100)
    key = "idem-key-0123456789"
    first = _run(conn, principal, key=key)
    second = _run(conn, principal, key=key)
    assert second.replayed is True
    assert second.payload == first.payload
    assert second.headers[facts.IDEMPOTENT_REPLAY_HEADER] == "true"
    # 只派发一次、只记一次用量、只发一条事件（INV-M03-03）
    assert len(wired["node"].calls) == 1
    assert len(wired["usage"].drafts) == 1
    assert len(_outbox(conn, first.payload["id"])) == 1


def test_same_idempotency_key_with_different_payload_is_409(conn, wired):
    principal = _principal(qps=100)
    key = "idem-key-0123456789"
    _run(conn, principal, key=key)
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, principal, key=key, body=_body(model="m2"))
    assert (info.value.http_status, info.value.code) == (409, 40919)


def test_request_fingerprint_dedupes_without_a_key(conn, wired):
    principal = _principal(qps=100)
    first = _run(conn, principal)
    second = _run(conn, principal)
    assert second.replayed is True and second.payload == first.payload
    assert len(wired["node"].calls) == 1


def test_fingerprint_expires_after_300_seconds(conn, wired):
    principal = _principal(qps=100)
    _run(conn, principal)
    later = _run(conn, principal, now=NOW + timedelta(seconds=facts.FINGERPRINT_WINDOW_S + 1))
    assert later.replayed is False
    assert len(wired["node"].calls) == 2


def test_replay_does_not_emit_new_event_or_usage(conn, wired):
    principal = _principal(qps=100)
    key = "idem-key-0123456789"
    first = _run(conn, principal, key=key)
    request_ids_before = _count(conn, "api_request_log", first.payload["id"])
    _run(conn, principal, key=key)
    assert _count(conn, "api_request_log", first.payload["id"]) == request_ids_before
    assert len(_outbox(conn, first.payload["id"])) == 1
    assert len(wired["usage"].drafts) == 1


# ─────────────────────────────────────────────────────── 限流 / 配额
def test_qps_limit_returns_429_with_retry_after(conn, wired):
    principal = _principal(qps=1)
    _run(conn, principal)
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, principal)
    exc = info.value
    assert (exc.http_status, exc.code) == (429, 42901)
    assert exc.retry_after_s and exc.headers[facts.RETRY_AFTER_HEADER]
    assert exc.headers[facts.RATE_LIMIT_LIMIT_HEADER] == "1"


def test_rate_limited_request_writes_failed_log(conn, wired):
    principal = _principal(qps=1)
    _run(conn, principal)
    request_id = str(uuid.uuid4())
    with pytest.raises(errors.GatewayError):
        _run(conn, principal, request_id=request_id)
    row = store.fetch_request_log(conn, request_id)
    assert row is not None and row["status"] == "failed" and row["http_status"] == 429
    assert row["error_code"] == 42901


def test_daily_spend_cap_returns_42902(conn, wired):
    principal = _principal(qps=100, daily_cap_minor=1_000, daily_spend_minor=1_000)
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, principal)
    assert (info.value.http_status, info.value.code) == (429, 42902)


def test_global_qps_from_config_center_is_applied(conn, wired):
    from app.gateway import config_source

    config_source.set_provider(lambda: {"gateway.rate_limit_qps": 1})
    principal = _principal(qps=100)
    _run(conn, principal)
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, principal)
    assert info.value.code == 42901


def test_node_layer_limit_is_off_by_default(conn, monkeypatch):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute(node_qps=1))
    providers.set_node_client(FakeNode())
    providers.set_usage_provider(FakeUsage())
    principal = _principal(qps=100)
    _run(conn, principal)
    _run(conn, principal)                    # 开关关闭 → 不做节点层二次限流
    assert all(value is True for key, value in providers.current().items()
               if key in {"auth", "route", "node", "usage"})


def test_node_layer_limit_enforced_when_feature_is_on(conn, monkeypatch):
    monkeypatch.setattr(features, "enabled", lambda name: name == "gateway.node_layer_rate_limit")
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute(node_qps=1))
    providers.set_node_client(FakeNode())
    providers.set_usage_provider(FakeUsage())
    principal = _principal(qps=100)
    _run(conn, principal)
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, principal, body=_body(messages=[{"role": "user", "content": "again"}]))
    assert info.value.code == 42901


# ─────────────────────────────────────────────────────── 失败映射
def test_no_route_returns_503_and_50901(conn):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute(fail_times=99))
    providers.set_node_client(FakeNode())
    providers.set_usage_provider(FakeUsage())
    request_id = str(uuid.uuid4())
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, _principal(qps=100), request_id=request_id)
    assert (info.value.http_status, info.value.code) == (503, 50901)
    row = store.fetch_request_log(conn, request_id)
    assert row["status"] == "failed" and row["error_code"] == 50901
    assert _outbox(conn, request_id)[0]["type"] == "request.failed"


def test_upstream_timeout_twice_is_504_and_not_billed(conn):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode(timeouts=2))
    usage = FakeUsage()
    providers.set_usage_provider(usage)
    request_id = str(uuid.uuid4())
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, _principal(qps=100), request_id=request_id)
    assert (info.value.http_status, info.value.code) == (504, 50902)
    assert usage.drafts == []                       # 两次失败不计费（INV-M03-01）
    event = _outbox(conn, request_id)[0]
    assert event["type"] == "request.failed"
    assert event["payload"]["attempts"] == 2
    assert event["payload"]["upstream_error_class"] == "timeout"


def test_upstream_failure_twice_is_502(conn):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode(failures=2))
    providers.set_usage_provider(FakeUsage())
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, _principal(qps=100))
    assert (info.value.http_status, info.value.code) == (502, 50903)


def test_retry_after_timeout_succeeds_on_second_node(conn):
    """首字节前可重路由（M03 §7）：第 2 次尝试成功时只计一次费。"""
    route = FakeRoute()
    node = FakeNode(timeouts=1)
    usage = FakeUsage()
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(route)
    providers.set_node_client(node)
    providers.set_usage_provider(usage)
    request_id = str(uuid.uuid4())
    _run(conn, _principal(qps=100), request_id=request_id)
    assert [item.attempt_no for item in route.requests] == [1, 2]
    assert len(usage.drafts) == 1
    assert usage.drafts[0].attempt_no == 2          # 计费的是成功那次尝试
    assert _outbox(conn, request_id)[0]["type"] == "request.completed"


def test_attempt_count_never_exceeds_two(conn):
    route = FakeRoute()
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(route)
    providers.set_node_client(FakeNode(timeouts=5))
    providers.set_usage_provider(FakeUsage())
    with pytest.raises(errors.GatewayError):
        _run(conn, _principal(qps=100))
    assert len(route.requests) == facts.RETRY_MAX_ATTEMPTS


def test_usage_provider_failure_does_not_break_the_response(conn):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode())
    providers.set_usage_provider(FakeUsage(fail=True))
    request_id = str(uuid.uuid4())
    outcome = _run(conn, _principal(qps=100), request_id=request_id)
    assert outcome.status_code == 200
    # 事件仍在 outbox 里，M05 侧可补偿
    assert _outbox(conn, request_id)[0]["type"] == "request.completed"


def test_stream_true_is_rejected_until_t3(conn, wired):
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, _principal(qps=100), body=_body(stream=True))
    assert (info.value.http_status, info.value.code) == (400, 40001)
    assert info.value.details["field"] == "stream"


def test_fail_closed_when_route_provider_missing(conn):
    providers.set_auth_provider(FakeAuth(qps=100))
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, _principal(qps=100))
    assert (info.value.http_status, info.value.code) == (503, 45001)


def test_fail_closed_when_node_client_missing(conn):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, _principal(qps=100))
    assert info.value.http_status == 503


def test_validation_error_is_400_and_logged(conn, wired):
    request_id = str(uuid.uuid4())
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, _principal(qps=100), body={"model": "m1"}, request_id=request_id)
    assert info.value.code == 40001
    row = store.fetch_request_log(conn, request_id)
    assert row["status"] == "failed" and row["error_code"] == 40001


class _ExplodingNode:
    """上游通道抛未预期异常（例如连接被重置）。"""

    def complete(self, call):
        raise RuntimeError("connection reset")


def test_unexpected_upstream_exception_is_classified_as_502(conn):
    """未分类的上游异常按「上游异常」处理（502 / 50903），并走首字节前重试。"""
    providers.set_auth_provider(FakeAuth(qps=100))
    route = FakeRoute()
    providers.set_route_provider(route)
    providers.set_node_client(_ExplodingNode())
    providers.set_usage_provider(FakeUsage())
    with pytest.raises(errors.GatewayError) as info:
        _run(conn, _principal(qps=100))
    assert (info.value.http_status, info.value.code) == (502, 50903)
    assert len(route.requests) == facts.RETRY_MAX_ATTEMPTS


# ─────────────────────────────────────────────────────── 模型清单 provider
def test_model_catalog_provider_is_coerced():
    providers.set_model_catalog_provider(FakeCatalog())
    items = providers.list_models()
    assert items[0]["id"] == "m1"


def test_model_catalog_missing_is_fail_closed():
    with pytest.raises(errors.GatewayError) as info:
        providers.list_models()
    assert info.value.http_status == 503
