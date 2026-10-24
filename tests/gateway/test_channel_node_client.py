# SPDX-License-Identifier: AGPL-3.0-or-later
"""C10b ``ChannelNodeClient``：把通道结果投影成 ``NodeResult``，失败按 M03 既有口径抛错。

不连 DB、不联网：节点侧用线程扮演（``poll`` → ``submit``），网关侧直接 ``complete()``。
断言重点：超时 / 失败**不伪造成功**、错误类型能被 ``dispatch`` 识别（``providers.UpstreamTimeout``
/ ``UpstreamFailure``）、``usage_source`` 只会落在契约枚举内、开关默认关闭。
"""
from __future__ import annotations

import time

import pytest

from app.gateway import channel, features, models, providers
from gatewaykit import NOW

SECRET_PROMPT = "PROMPT-BODY-MUST-NOT-LEAK-4b7e"
SECRET_ANSWER = "ANSWER-BODY-MUST-NOT-LEAK-8d1c"


def _queue(**kwargs) -> channel.ChannelQueue:
    kwargs.setdefault("now_fn", lambda: NOW)
    kwargs.setdefault("per_node_max", 64)
    return channel.ChannelQueue(**kwargs)


def _call(*, timeout_s=None, model: str = "m1", node_id: str = "n1") -> models.NodeCall:
    return models.NodeCall(node_id=node_id, upstream_id="u1", access="A1", model=model,
                           messages=({"role": "user", "content": SECRET_PROMPT},),
                           request_id="r-1", trace_id="t-1", attempt_no=1,
                           timeout_s=timeout_s)


def _serve(queue: channel.ChannelQueue, node_id: str, payload, *, wait_s: float = 2.0,
           action: str = "submit"):
    """线程扮演节点：poll 一次；``action=submit`` 回结果，``cancel`` 取消任务。"""
    import threading

    def run() -> None:
        job = queue.poll(node_id, wait_s)
        if job is None:
            return
        if action == "cancel":
            queue.cancel(job.job_id)
        elif action == "submit":
            queue.submit(node_id, job.job_id, payload(job) if callable(payload) else payload)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


# ─────────────────────────────────────────────────────── 正常结果投影
def test_complete_projects_the_channel_result_into_a_node_result():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=2.0)
    _serve(queue, "n1", {"status": "completed", "content": SECRET_ANSWER,
                         "finish_reason": "length", "model": "m1-remote",
                         "tokens_in": 11, "tokens_out": 7, "usage_source": "dual",
                         "first_byte_ms": 3, "upstream_request_id": "up-42"})

    result = client.complete(_call())

    assert isinstance(result, models.NodeResult)
    assert result.content == SECRET_ANSWER
    assert result.finish_reason == "length" and result.model == "m1-remote"
    assert (result.tokens_in, result.tokens_out) == (11, 7)
    assert result.usage_source == "dual" and result.first_byte_ms == 3
    assert result.upstream_request_id == "up-42"
    assert isinstance(result.latency_ms, int) and result.latency_ms >= 0


def test_complete_defaults_the_missing_metadata():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=2.0)
    _serve(queue, "n1", {"status": "completed", "content": "hi"})

    result = client.complete(_call())

    assert (result.finish_reason, result.model) == ("stop", "m1")   # 缺省取调用侧的 model
    assert result.upstream_request_id.startswith("ch-")             # 通道侧生成的引用
    assert result.tokens_in is None and result.tokens_out is None


def test_illegal_usage_source_is_clamped_to_the_contract_enum():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=2.0)
    _serve(queue, "n1", {"status": "completed", "content": "hi", "usage_source": "made_up"})
    assert client.complete(_call()).usage_source == "actual"


def test_illegal_finish_reason_falls_back_to_stop():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=2.0)
    _serve(queue, "n1", {"status": "completed", "content": "hi", "finish_reason": "weird"})
    assert client.complete(_call()).finish_reason == "stop"


def test_client_is_a_node_client_provider():
    client = channel.ChannelNodeClient(_queue(), default_timeout_s=1.0)
    assert isinstance(client, providers.NodeClient)
    assert client.queue is not None


# ─────────────────────────────────────────────────────── 超时 / 失败（不伪造成功）
def test_timeout_raises_upstream_timeout_and_cancels_the_job():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=0.05)
    started = time.monotonic()
    with pytest.raises(providers.UpstreamTimeout):
        client.complete(_call())                                  # 没有节点接活
    assert time.monotonic() - started < 1.0
    assert queue.pending() == 0 and queue.in_flight("n1") is None  # 超时即取消，不留在队列里


def test_call_timeout_overrides_the_client_default():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=30.0)
    started = time.monotonic()
    with pytest.raises(providers.UpstreamTimeout):
        client.complete(_call(timeout_s=0.05))
    assert time.monotonic() - started < 1.0


def test_failed_result_raises_upstream_failure():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=2.0)
    _serve(queue, "n1", {"status": "failed", "error_class": "upstream_error",
                         "error_message": "上游 502"})
    with pytest.raises(providers.UpstreamFailure) as info:
        client.complete(_call())
    assert "502" in str(info.value)


def test_timeout_classed_result_raises_upstream_timeout():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=2.0)
    _serve(queue, "n1", {"status": "failed", "error_class": "timeout",
                         "error_message": "节点侧超时"})
    with pytest.raises(providers.UpstreamTimeout):
        client.complete(_call())


def test_canceled_job_raises_upstream_failure():
    queue = _queue()
    client = channel.ChannelNodeClient(queue, default_timeout_s=2.0)
    _serve(queue, "n1", None, action="cancel")
    with pytest.raises(providers.UpstreamFailure):
        client.complete(_call())


# ─────────────────────────────────────────────────────── 与 providers 接线
def test_providers_send_uses_the_channel_client():
    queue = _queue()
    providers.set_node_client(channel.ChannelNodeClient(queue, default_timeout_s=2.0))
    _serve(queue, "n1", {"status": "completed", "content": "via-providers",
                         "tokens_in": 1, "tokens_out": 1})
    result = providers.send(_call())
    assert result.content == "via-providers"


def test_providers_send_surfaces_the_channel_timeout():
    queue = _queue()
    providers.set_node_client(channel.ChannelNodeClient(queue, default_timeout_s=0.05))
    with pytest.raises(providers.UpstreamTimeout):
        providers.send(_call())                                   # dispatch 认这一类异常（504/50902）


# ─────────────────────────────────────────────────────── 开关
def test_channel_switch_is_registered_with_three_fields_and_off_by_default():
    switch = features.get(channel.CHANNEL_SWITCH)
    assert switch.name == "gateway.channel.enabled"
    assert switch.owner == "lead"
    assert switch.expire_at.isoformat() == "2026-12-31"
    assert "Echo" in switch.rollback_rule
    assert switch.default is False
    assert channel.enabled() is False


def test_enabled_follows_the_feature_gate(monkeypatch):
    monkeypatch.setattr(features, "enabled",
                        lambda name: name == channel.CHANNEL_SWITCH)
    assert channel.enabled() is True


def test_client_defaults_to_the_module_queue():
    client = channel.ChannelNodeClient()
    assert client.queue is channel.QUEUE
    assert channel.QUEUE.pending() == 0
