# SPDX-License-Identifier: Apache-2.0
"""C10b 平台内存队列（``app.gateway.channel.ChannelQueue``）语义。

纯内存、不连 DB、不联网；时钟用固定 ``NOW``（显式 ``now=``），只有「等待预算」用真实时间
（0.05~0.2s 量级，避免慢测）。覆盖：入队/取任务/回结果、等待超时返回 ``None``、租约 30s
重派 ≤2 次、同节点单在途、重复结果幂等、冲突 40919、取消、容量上限、能力过滤、线程安全、
以及**正文不进日志**。
"""
from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest

from app.gateway import channel, errors, models
from gatewaykit import NOW


def _call(node_id: str = "n1", model: str = "m1", request_id: str = "r1",
          content: str = "hello") -> models.NodeCall:
    return models.NodeCall(node_id=node_id, upstream_id="u1", access="A1", model=model,
                           messages=({"role": "user", "content": content},),
                           request_id=request_id, trace_id="t1", attempt_no=1)


def _queue(**kwargs) -> channel.ChannelQueue:
    kwargs.setdefault("now_fn", lambda: NOW)
    return channel.ChannelQueue(**kwargs)


def _completed(content: str = "hi") -> dict:
    return {"status": "completed", "content": content, "finish_reason": "stop",
            "model": "m1", "tokens_in": 3, "tokens_out": 2, "usage_source": "actual"}


# ─────────────────────────────────────────────────────── 正常往返
def test_enqueue_poll_submit_round_trip():
    queue = _queue()
    job = queue.enqueue(_call())
    assert job.status == "pending" and job.attempts == 0 and job.lease_until is None
    assert job.created_at == NOW and job.messages[0]["content"] == "hello"
    assert queue.pending("n1") == 1

    leased = queue.poll("n1", 0)
    assert leased is job
    assert job.status == "leased" and job.attempts == 1
    assert job.lease_until == NOW + timedelta(seconds=channel.LEASE_SECONDS)

    answer = queue.submit("n1", job.job_id, _completed())
    assert answer == {"status": "accepted", "job_id": job.job_id, "request_id": "r1",
                      "node_id": "n1"}
    assert job.status == "completed" and job.done
    assert job.result_event.is_set()
    assert job.result["content"] == "hi"
    assert queue.pending("n1") == 0 and queue.in_flight("n1") is None


def test_jobs_are_bucketed_per_node():
    queue = _queue()
    first = queue.enqueue(_call(node_id="n1"))
    second = queue.enqueue(_call(node_id="n2"))
    assert queue.pending() == 2 and queue.pending("n1") == 1 and queue.pending("n2") == 1

    assert queue.poll("n2", 0) is second
    assert first.status == "pending"                       # 别的节点取不走
    assert queue.poll("n1", 0) is first


def test_poll_returns_none_when_the_wait_budget_expires():
    queue = _queue()
    started = time.monotonic()
    assert queue.poll("n1", 0.05) is None                  # 无任务 → 等满 wait_s 再 None（对应 204）
    elapsed = time.monotonic() - started
    assert 0.04 <= elapsed < 1.0


def test_poll_rejects_missing_node_id():
    with pytest.raises(errors.GatewayError) as info:
        _queue().poll("", 0)
    assert info.value.code == 40001


# ─────────────────────────────────────────────────────── 单在途 / 租约
def test_only_one_job_in_flight_per_node():
    queue = _queue()
    first = queue.enqueue(_call(request_id="r1"))
    second = queue.enqueue(_call(request_id="r2"))
    assert queue.poll("n1", 0) is first
    assert queue.poll("n1", 0) is None                     # 同节点单在途
    assert queue.in_flight("n1") == first.job_id
    assert queue.pending("n1") == 2                        # 在途也算占用

    queue.submit("n1", first.job_id, _completed())
    assert queue.poll("n1", 0) is second                   # 交卷后才轮到下一个


def test_expired_lease_is_redispatched_to_the_same_job():
    queue = _queue()
    job = queue.enqueue(_call())
    assert queue.poll("n1", 0, now=NOW) is job
    assert job.attempts == 1

    again = queue.poll("n1", 0, now=NOW + timedelta(seconds=channel.LEASE_SECONDS + 1))
    assert again is job                                    # 同一任务重派，不丢不重
    assert (job.attempts, job.redispatches) == (2, 1)
    assert job.lease_until == NOW + timedelta(seconds=2 * channel.LEASE_SECONDS + 1)


def test_job_fails_after_the_redispatch_budget_is_used_up():
    queue = _queue()
    job = queue.enqueue(_call())
    assert queue.poll("n1", 0, now=NOW) is job
    step = timedelta(seconds=channel.LEASE_SECONDS + 1)
    assert queue.poll("n1", 0, now=NOW + step) is job                    # 重派 1
    assert queue.poll("n1", 0, now=NOW + step * 2) is job                # 重派 2
    assert job.attempts == channel.MAX_DELIVERIES == 3

    assert queue.poll("n1", 0, now=NOW + step * 3) is None               # 用尽 → 失败
    assert job.status == "failed" and job.result["error_class"] == "timeout"
    assert job.result_event.is_set()
    assert queue.pending("n1") == 0 and queue.in_flight("n1") is None


def test_submit_after_lease_expiry_is_rejected():
    queue = _queue()
    job = queue.enqueue(_call())
    queue.poll("n1", 0, now=NOW)
    with pytest.raises(errors.GatewayError) as info:
        queue.submit("n1", job.job_id, _completed(),
                     now=NOW + timedelta(seconds=channel.LEASE_SECONDS + 1))
    assert (info.value.http_status, info.value.code) == (409, 40919)


# ─────────────────────────────────────────────────────── 幂等 / 冲突 / 归属
def test_duplicate_submit_with_the_same_payload_is_idempotent():
    queue = _queue()
    job = queue.enqueue(_call())
    queue.poll("n1", 0)
    assert queue.submit("n1", job.job_id, _completed())["status"] == "accepted"
    assert queue.submit("n1", job.job_id, _completed())["status"] == "duplicate"
    assert job.result["content"] == "hi"


def test_duplicate_submit_ignores_volatile_timing_fields():
    """重放同一份结果时耗时可能不同：幂等比对不看 latency_ms / first_byte_ms。"""
    queue = _queue()
    job = queue.enqueue(_call())
    queue.poll("n1", 0)
    queue.submit("n1", job.job_id, dict(_completed(), latency_ms=12, first_byte_ms=4))
    replay = queue.submit("n1", job.job_id, dict(_completed(), latency_ms=99, first_byte_ms=1))
    assert replay["status"] == "duplicate"


def test_conflicting_resubmit_is_40919():
    queue = _queue()
    job = queue.enqueue(_call())
    queue.poll("n1", 0)
    queue.submit("n1", job.job_id, _completed("first"))
    with pytest.raises(errors.GatewayError) as info:
        queue.submit("n1", job.job_id, _completed("second"))
    assert (info.value.http_status, info.value.code) == (409, 40919)


def test_idempotent_window_is_bounded(monkeypatch):
    """幂等只在**最近** N 个已结束任务内有界保留（内存不随请求数增长）。"""
    monkeypatch.setattr(channel, "RECENT_RESULTS_MAX", 2)
    queue = _queue()
    finished = []
    for index in range(3):
        job = queue.enqueue(_call(request_id=f"r{index}"))
        queue.poll("n1", 0)
        queue.submit("n1", job.job_id, _completed())
        finished.append(job)

    assert queue.submit("n1", finished[2].job_id, _completed())["status"] == "duplicate"
    assert queue.submit("n1", finished[1].job_id, _completed())["status"] == "duplicate"
    with pytest.raises(errors.GatewayError) as info:
        queue.submit("n1", finished[0].job_id, _completed())    # 已滑出窗口
    assert info.value.code == 40919
    assert queue.pending() == 0                                # 窗口不占 pending 名额


def test_submit_rejects_unknown_jobs_and_wrong_owners():
    queue = _queue()
    with pytest.raises(errors.GatewayError) as unknown:
        queue.submit("n1", "no-such-job", _completed())
    assert unknown.value.code == 40919

    job = queue.enqueue(_call(node_id="n1"))
    queue.poll("n1", 0)
    with pytest.raises(errors.GatewayError) as foreign:
        queue.submit("n2", job.job_id, _completed())       # 归属不符
    assert foreign.value.code == 40919
    assert queue.pending("n1") == 1                        # 任务没被误回收


def test_submit_rejects_malformed_results():
    queue = _queue()
    job = queue.enqueue(_call())
    queue.poll("n1", 0)
    with pytest.raises(errors.GatewayError) as bad_status:
        queue.submit("n1", job.job_id, {"status": "weird"})
    assert bad_status.value.code == 40001
    with pytest.raises(errors.GatewayError) as not_mapping:
        queue.submit("n1", job.job_id, "completed")
    assert not_mapping.value.code == 40001


# ─────────────────────────────────────────────────────── 取消
def test_cancel_unblocks_the_waiter_and_rejects_late_results():
    queue = _queue()
    job = queue.enqueue(_call())
    queue.poll("n1", 0)
    assert queue.cancel(job.job_id) is True
    assert job.status == "canceled" and job.result_event.is_set()
    assert queue.pending("n1") == 0
    with pytest.raises(errors.GatewayError) as info:
        queue.submit("n1", job.job_id, _completed())
    assert info.value.code == 40919
    assert queue.cancel(job.job_id) is False               # 已经结束：不重复取消
    assert queue.cancel("no-such-job") is False


# ─────────────────────────────────────────────────────── 容量上限
def test_per_node_capacity_is_enforced():
    queue = _queue(per_node_max=2)
    queue.enqueue(_call(request_id="r1"))
    queue.enqueue(_call(request_id="r2"))
    with pytest.raises(errors.GatewayError) as info:
        queue.enqueue(_call(request_id="r3"))
    exc = info.value
    assert (exc.http_status, exc.code) == (429, 42901)
    assert exc.details["limit_kind"] == "node" and exc.retry_after_s is not None
    assert queue.pending("n1") == 2


def test_global_capacity_is_enforced_across_nodes():
    queue = _queue(per_node_max=10, global_max=2)
    queue.enqueue(_call(node_id="n1"))
    queue.enqueue(_call(node_id="n2"))
    with pytest.raises(errors.GatewayError) as info:
        queue.enqueue(_call(node_id="n3"))
    assert info.value.code == 42901 and info.value.details["limit_kind"] == "global"


def test_capacity_is_released_after_completion():
    queue = _queue(per_node_max=1)
    job = queue.enqueue(_call())
    queue.poll("n1", 0)
    queue.submit("n1", job.job_id, _completed())
    queue.enqueue(_call(request_id="r2"))                  # 名额释放，能继续入队
    assert queue.pending("n1") == 1


# ─────────────────────────────────────────────────────── 能力过滤
def test_capabilities_keep_unmatched_jobs_queued():
    queue = _queue()
    other = queue.enqueue(_call(model="m2", request_id="r2"))
    wanted = queue.enqueue(_call(model="m1", request_id="r1"))

    picked = queue.poll("n1", 0, capabilities={"m1"})
    assert picked is wanted
    assert other.status == "pending"                       # 不匹配的任务保留，不丢
    queue.submit("n1", wanted.job_id, _completed())

    assert queue.poll("n1", 0, capabilities={"m1"}) is None
    assert queue.poll("n1", 0, capabilities={"m2"}) is other


def test_enqueue_requires_node_and_model():
    queue = _queue()
    with pytest.raises(errors.GatewayError) as info:
        queue.enqueue(models.NodeCall(node_id="", upstream_id=None, access=None, model="m1",
                                      messages=(), request_id="r1", trace_id="t1",
                                      attempt_no=1))
    assert info.value.code == 40001


# ─────────────────────────────────────────────────────── 线程安全
def test_concurrent_enqueue_and_submit_keep_the_counters_consistent():
    queue = _queue(per_node_max=64, global_max=256)
    total = 24
    done: list[str] = []
    failures: list[BaseException] = []

    def producer(start: int) -> None:
        try:
            for index in range(start, total, 4):
                queue.enqueue(_call(request_id=f"r{index}"))
        except BaseException as exc:                       # pragma: no cover - 断言用
            failures.append(exc)

    def consumer() -> None:
        try:
            deadline = time.monotonic() + 5.0
            while len(done) < total and time.monotonic() < deadline:
                job = queue.poll("n1", 0.05)
                if job is None:
                    continue
                queue.submit("n1", job.job_id, _completed())
                done.append(job.request_id)
        except BaseException as exc:                       # pragma: no cover - 断言用
            failures.append(exc)

    workers = [threading.Thread(target=producer, args=(start,)) for start in range(4)]
    eater = threading.Thread(target=consumer)
    for worker in workers:
        worker.start()
    eater.start()
    for worker in workers:
        worker.join(timeout=10)
    eater.join(timeout=10)

    assert failures == []
    assert len(done) == total and len(set(done)) == total
    assert queue.pending() == 0 and queue.in_flight("n1") is None


# ─────────────────────────────────────────────────────── 不落正文
def test_message_bodies_never_reach_the_logs(caplog):
    caplog.set_level("INFO", logger="djb.gateway.channel")
    queue = _queue()
    secret_prompt = "SUPER-SECRET-PROMPT-9f2c"
    secret_answer = "SUPER-SECRET-ANSWER-7a1b"
    job = queue.enqueue(_call(content=secret_prompt))
    queue.poll("n1", 0)
    queue.submit("n1", job.job_id, _completed(secret_answer))

    assert secret_prompt not in caplog.text
    assert secret_answer not in caplog.text
    assert secret_prompt not in repr(job) and secret_answer not in repr(job)
    # 日志里该有的只有标识与状态
    events = {record.event for record in caplog.records if hasattr(record, "event")}
    assert {"channel.enqueued", "channel.leased", "channel.finished"} <= events
    for record in caplog.records:
        if hasattr(record, "job_id"):
            assert record.job_id == job.job_id
