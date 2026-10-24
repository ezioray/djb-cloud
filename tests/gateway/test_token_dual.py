# SPDX-License-Identifier: Apache-2.0
"""C9a 网关双计（PROBE-TOKEN-AUDIT §2.2 / §5 C9）：开关语义、>1% 告警、口径不被本地覆盖。

三层用例：

1. **纯函数层**（无 DB）：:func:`app.gateway.chat._usage_of` 的四条分支；
2. **非流式主链路**（DB）：dual 落到 ``api_request_log`` / outbox 事件 / M05 草稿，
   而**响应 ``usage`` 与金额仍是上游的**；
3. **流式**（DB）：最终帧 ``usage`` 不被本地计数改写，流结束的事实与事件标 ``dual``。

开关 ``gateway.token.dual.enabled`` 默认关闭：打开一律用 ``monkeypatch.setattr(features,
"enabled", …)``（与 test_chat / test_stream 的既有做法一致），不引入写入口。
"""
from __future__ import annotations

import json
import logging
import uuid

import pytest

from app.gateway import chat, facts, features, models, providers, store, stream, tokenizer
from gatewaykit import (NOW, FakeAuth, FakeNode, FakeRoute, FakeStream, FakeUsage, connect,
                        principal_dict)

DUAL = facts.TOKEN_DUAL_SWITCH
MESSAGES = ({"role": "user", "content": "hi"},)
CHINESE_MESSAGES = ({"role": "user", "content": "这是一段中文提示词"},)


# ─────────────────────────────────────────────────────── 夹具
def _principal(**kwargs):
    values = {"qps": 100}
    values.update(kwargs)
    return models.coerce_principal(principal_dict(account_id=uuid.uuid4(),
                                                  tenant_id=uuid.uuid4(), api_key_id=7,
                                                  **values))


def _body(**overrides):
    body = {"model": "m1", "messages": [{"role": "user", "content": "hi"}]}
    body.update(overrides)
    return body


def _stream_body(**overrides):
    body = {"model": "m1", "stream": True,
            "messages": [{"role": "user", "content": "hi"}]}
    body.update(overrides)
    return body


def _result(**overrides) -> models.NodeResult:
    values = {"content": "hello", "tokens_in": 9, "tokens_out": 2, "model": "m1"}
    values.update(overrides)
    return models.NodeResult(**values)


def _dual_on(monkeypatch) -> None:
    monkeypatch.setattr(features, "enabled", lambda name: name == DUAL)


def _mismatch_records(caplog) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.message == "gateway.token_mismatch"]


def _outbox(conn, request_id: str) -> list[dict]:
    rows = conn.execute("SELECT type, payload FROM m03_outbox WHERE aggregate_id = %s",
                        (request_id,)).fetchall()
    return [{"type": row[0],
             "payload": row[1] if isinstance(row[1], dict) else json.loads(row[1])}
            for row in rows]


@pytest.fixture
def stream_conn(migrated: str):
    """流式落库走**独立事务**：用 autocommit 连接最直观（与 test_stream 同口径）。"""
    connection = connect(migrated, autocommit=True)
    try:
        yield connection
    finally:
        connection.close()


def _wire_node(*, node=None, usage=None):
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(node or FakeNode())
    providers.set_usage_provider(usage or FakeUsage())


# ─────────────────────────────────────────────────────── 1) 纯函数层
def test_usage_of_keeps_actual_when_the_switch_is_off():
    tokens_in, tokens_out, source = chat._usage_of(_result(), MESSAGES, model="m1",
                                                   request_id="r-1")
    assert (tokens_in, tokens_out, source) == (9, 2, "actual")


def test_usage_of_returns_dual_but_upstream_numbers_when_the_switch_is_on(monkeypatch):
    """双计的**唯一**语义：口径标 dual，数值仍取上游（本地只用于告警）。"""
    _dual_on(monkeypatch)
    upstream = _result(tokens_in=9, tokens_out=2)
    tokens_in, tokens_out, source = chat._usage_of(upstream, CHINESE_MESSAGES, model="m1",
                                                   request_id="r-1")
    assert (tokens_in, tokens_out) == (9, 2)              # 上游值原样返回
    assert source == "dual"                                # 但口径是 dual


def test_usage_of_warns_when_local_and_upstream_differ_by_more_than_one_percent(
        monkeypatch, caplog):
    _dual_on(monkeypatch)
    caplog.set_level(logging.WARNING, logger="djb.gateway.chat")
    chat._usage_of(_result(tokens_in=1, tokens_out=1), CHINESE_MESSAGES, model="m1",
                   request_id="r-mismatch")
    records = _mismatch_records(caplog)
    assert {record.source for record in records} == {"prompt", "completion"}
    prompt = next(record for record in records if record.source == "prompt")
    assert (prompt.local, prompt.upstream) == (17, 1)       # 3 + 4 + 1(“user”) + 9(中文)
    assert prompt.delta_pct == 1600.0
    assert prompt.request_id == "r-mismatch" and prompt.model == "m1"
    # 不落正文：日志里没有提示词文本
    assert "这是一段中文提示词" not in caplog.text


def test_usage_of_is_silent_when_the_difference_is_within_one_percent(monkeypatch, caplog):
    _dual_on(monkeypatch)
    caplog.set_level(logging.WARNING, logger="djb.gateway.chat")
    local_in = tokenizer.count_prompt_tokens("m1", MESSAGES)
    local_out = tokenizer.count_completion_tokens("m1", "hello")
    chat._usage_of(_result(tokens_in=local_in, tokens_out=local_out), MESSAGES, model="m1",
                   request_id="r-ok")
    assert _mismatch_records(caplog) == []
    # 边界确认（与 tokenizer 侧同一阈值）：正好 1% 不算超
    assert tokenizer.is_mismatch(101, 100, facts.TOKEN_DUAL_MISMATCH_RATIO) is False


def test_usage_of_estimates_chinese_with_the_tokenizer_not_len_division(caplog):
    caplog.set_level(logging.WARNING, logger="djb.gateway.chat")
    tokens_in, tokens_out, source = chat._usage_of(
        _result(content="你好世界", tokens_in=None, tokens_out=None), CHINESE_MESSAGES,
        model="m1", request_id="r-est")
    assert source == "estimated"
    assert tokens_in == 3 + 4 + 1 + 9                       # 模板 + “user” + 9 个汉字
    assert tokens_out == 4
    assert tokens_in > max(1, len("user这是一段中文提示词") // 4)   # 旧口径只给 3
    assert _mismatch_records(caplog) == []                  # 估算路径不告警


def test_usage_of_keeps_the_side_the_upstream_did_report():
    tokens_in, tokens_out, source = chat._usage_of(
        _result(content="你好", tokens_in=100, tokens_out=None), MESSAGES, model="m1")
    assert (tokens_in, tokens_out, source) == (100, 2, "estimated")


def test_request_record_accepts_dual_and_still_rejects_unknown_sources():
    record = models.RequestRecord(request_id="r-1", status="completed", http_status=200,
                                  usage_source="dual")
    assert record.usage_source == "dual"
    with pytest.raises(ValueError):
        models.RequestRecord(request_id="r-1", status="completed", http_status=200,
                             usage_source="client_reported")


# ─────────────────────────────────────────────────────── 2) 非流式主链路（DB）
def test_dual_request_persists_dual_but_keeps_upstream_usage_and_amount(conn, monkeypatch,
                                                                        caplog):
    """开关打开：日志 / 事件 / M05 草稿都标 dual，**响应 usage 与金额不变**。"""
    _dual_on(monkeypatch)
    caplog.set_level(logging.WARNING, logger="djb.gateway.chat")
    usage = FakeUsage()
    _wire_node(node=FakeNode(content="hello", tokens_in=999, tokens_out=500), usage=usage)
    request_id = str(uuid.uuid4())

    outcome = chat.complete(conn, principal=_principal(), body=_body(), request_id=request_id,
                            trace_id="trace-dual", now=NOW)

    # 响应契约不变：usage 仍是上游值（不被本地计数覆盖）
    assert outcome.payload["usage"] == {"prompt_tokens": 999, "completion_tokens": 500,
                                        "total_tokens": 1499}
    row = store.fetch_request_log(conn, request_id)
    assert row["usage_source"] == "dual"
    assert (row["tokens_in"], row["tokens_out"]) == (999, 500)
    events = _outbox(conn, request_id)
    assert [item["type"] for item in events] == ["request.completed"]
    assert events[0]["payload"]["usage_source"] == "dual"
    # M05 草稿：dual + 上游 tokens；报价金额一字不动
    assert len(usage.drafts) == 1
    draft = usage.drafts[0]
    assert draft.usage_source == "dual"
    assert (draft.tokens_in, draft.tokens_out) == (999, 500)
    assert draft.amount_minor == 250
    # 差异远大于 1% → 两路都告警
    assert {record.source for record in _mismatch_records(caplog)} == {"prompt", "completion"}


def test_dual_request_is_logged_even_though_the_enum_was_widened(conn, monkeypatch):
    """307 的 CHECK 放宽是这条用例的前提：不改它，dual 行会因 23514 静默丢失。"""
    _dual_on(monkeypatch)
    _wire_node()
    request_id = str(uuid.uuid4())
    chat.complete(conn, principal=_principal(), body=_body(), request_id=request_id,
                  trace_id="trace-dual-2", now=NOW)
    assert store.fetch_request_log(conn, request_id) is not None


def test_switch_off_keeps_actual_and_never_warns(conn, caplog):
    caplog.set_level(logging.WARNING, logger="djb.gateway.chat")
    usage = FakeUsage()
    _wire_node(node=FakeNode(content="hello", tokens_in=999, tokens_out=500), usage=usage)
    request_id = str(uuid.uuid4())

    outcome = chat.complete(conn, principal=_principal(), body=_body(), request_id=request_id,
                            trace_id="trace-actual", now=NOW)

    assert outcome.payload["usage"]["prompt_tokens"] == 999
    row = store.fetch_request_log(conn, request_id)
    assert row["usage_source"] == "actual"
    assert usage.drafts[0].usage_source == "actual"
    assert _outbox(conn, request_id)[0]["payload"]["usage_source"] == "actual"
    assert _mismatch_records(caplog) == []


def test_switch_off_estimated_request_still_uses_the_tokenizer(conn):
    """缺上游 usage 时不再 len//4（与开关无关的兜底口径）。"""
    _wire_node(node=FakeNode(content="你好世界", tokens_in=None, tokens_out=None,
                             usage_source="estimated"))
    request_id = str(uuid.uuid4())
    chat.complete(conn, principal=_principal(), body=_body(), request_id=request_id,
                  trace_id="trace-est", now=NOW)
    row = store.fetch_request_log(conn, request_id)
    assert row["usage_source"] == "estimated"
    assert (row["tokens_in"], row["tokens_out"]) == (9, 4)


# ─────────────────────────────────────────────────────── 3) 流式（DB）
def _frame_payloads(frames: list[str]) -> list[dict]:
    out = []
    for frame in frames:
        text = frame.strip()
        if not text.startswith("data: "):
            continue
        data = text[len("data: "):]
        out.append({"done": True} if data == facts.SSE_DONE else json.loads(data))
    return out


def test_stream_dual_keeps_frame_usage_and_marks_dual(stream_conn, migrated, monkeypatch,
                                                      caplog):
    _dual_on(monkeypatch)
    caplog.set_level(logging.WARNING, logger="djb.gateway.stream")
    usage = FakeUsage()
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode())
    providers.set_stream_client(FakeStream(chunks=["你好", "世界"], tokens_in=50, tokens_out=40))
    providers.set_usage_provider(usage)
    plan = stream.prepare(stream_conn, principal=_principal(), body=_stream_body(),
                          request_id=str(uuid.uuid4()), trace_id="trace-s1", now=NOW,
                          connection_factory=lambda: connect(migrated, autocommit=True))

    payloads = _frame_payloads(list(plan.frames()))
    final_usage = payloads[-2]["usage"]
    assert final_usage == {"prompt_tokens": 50, "completion_tokens": 40, "total_tokens": 90}

    row = store.fetch_request_log(stream_conn, plan.request_id)
    assert row["usage_source"] == "dual"
    assert (row["tokens_in"], row["tokens_out"]) == (50, 40)
    events = _outbox(stream_conn, plan.request_id)
    assert events[0]["payload"]["usage_source"] == "dual"
    assert usage.drafts[0].usage_source == "dual"
    assert usage.drafts[0].amount_minor == 250                     # 金额不变
    assert {record.source for record in _mismatch_records(caplog)} == {"prompt", "completion"}


def test_stream_switch_off_keeps_actual(stream_conn, migrated, caplog):
    caplog.set_level(logging.WARNING, logger="djb.gateway.stream")
    usage = FakeUsage()
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode())
    providers.set_stream_client(FakeStream(chunks=["你好", "世界"], tokens_in=50, tokens_out=40))
    providers.set_usage_provider(usage)
    plan = stream.prepare(stream_conn, principal=_principal(), body=_stream_body(),
                          request_id=str(uuid.uuid4()), trace_id="trace-s2", now=NOW,
                          connection_factory=lambda: connect(migrated, autocommit=True))

    payloads = _frame_payloads(list(plan.frames()))
    assert payloads[-2]["usage"]["total_tokens"] == 90
    assert store.fetch_request_log(stream_conn, plan.request_id)["usage_source"] == "actual"
    assert usage.drafts[0].usage_source == "actual"
    assert _mismatch_records(caplog) == []


def test_stream_estimated_completion_uses_the_collected_content(stream_conn, migrated):
    """上游没给用量时，流式 completion 用**已收集正文**计数（不是 len//4）。"""
    usage = FakeUsage()
    providers.set_auth_provider(FakeAuth(qps=100))
    providers.set_route_provider(FakeRoute())
    providers.set_node_client(FakeNode())
    providers.set_stream_client(FakeStream(chunks=["你好世界"], tokens_in=None, tokens_out=None))
    providers.set_usage_provider(usage)
    plan = stream.prepare(stream_conn, principal=_principal(), body=_stream_body(),
                          request_id=str(uuid.uuid4()), trace_id="trace-s3", now=NOW,
                          connection_factory=lambda: connect(migrated, autocommit=True))

    _frame_payloads(list(plan.frames()))
    row = store.fetch_request_log(stream_conn, plan.request_id)
    assert row["usage_source"] == "estimated"
    assert (row["tokens_in"], row["tokens_out"]) == (9, 4)
    assert usage.drafts[0].usage_source == "estimated"
