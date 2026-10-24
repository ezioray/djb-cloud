# SPDX-License-Identifier: AGPL-3.0-or-later
"""C10b 平台**内存通道队列** + ``ChannelNodeClient``（M03 数据面，替换 ``EchoNodeClient``）。

为什么要内存队列：S2 阶段节点侧还没有出站长连接（PROBE-TOKEN-AUDIT §1「实时接入只有回环
端点」），网关需要一个**可被节点拉取**的任务队列把数据面先跑通——网关入队、节点侧（M02 端点，
C10a 写域）``poll`` 取任务、``submit`` 回结果。本模块只做**进程内**队列与客户端，不写 DB、
不建表、不碰账本。

两侧契约：

* **网关侧** ``ChannelNodeClient.complete(call)``：入队后阻塞等 ``threading.Event``；
  超时（``call.timeout_s``，缺省 60s）→ 取消任务并抛 :class:`providers.UpstreamTimeout`
  （dispatch 映射 504 / ``50902``）；节点回 ``failed`` → 抛
  :class:`providers.UpstreamFailure`（502 / ``50903``）。**绝不伪造成功**。
  两者都是 M03 **既有**的口径，不新增错误码（接口只加不改）。
* **节点侧** ``ChannelQueue.poll(node_id, wait_s, capabilities)``：租约 30s、
  **同节点单在途**、租约过期可重派 ≤2 次（合计 ≤3 次投递）；无任务时最多等 ``wait_s``
  再返回 ``None``（对应未来 M02 端点的 204）。
* ``ChannelQueue.submit(node_id, job_id, result)``：校验租约/归属；重复提交**同载荷**是幂等
  的（``accepted`` / ``duplicate``），**不同载荷** → 409 / ``40919``。

内存安全：

* 每节点 pending ≤ :data:`PER_NODE_PENDING_MAX`、全局 ≤ :data:`GLOBAL_PENDING_MAX`；
  超限拒绝 429 / ``42901``（``details.limit_kind`` 区分 ``node`` / ``global``），防内存放大。
* 重复提交的幂等只保留**最近** :data:`RECENT_RESULTS_MAX` 个已结束任务（有界窗口）：
  窗口内的同载荷重放 → ``duplicate``、不同载荷 → 409；窗口外按「未知任务」409 处理。
* **不持久化正文**：job 只在进程内存里过一手；``ChannelJob.messages`` / ``result`` 都是
  ``repr=False``，日志只记 ``job_id`` / ``node_id`` / ``status`` / 耗时 / ``attempts``。
  ``result`` 只保留 :data:`_RESULT_KEYS` 白名单键（节点塞别的字段一律丢弃）。

开关：``gateway.channel.enabled``（在 :mod:`app.gateway.features` 登记三字段，默认关闭）。
本模块提供 :func:`enabled` 供接线方判断——**关闭时保持原 NodeClient（Echo）**，队列里的在途
任务直接丢弃（内存态，不涉及持久化事实）。模块级 :data:`QUEUE` 只给接线用；测试各自 new。
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from . import clock, errors, facts, features, models, providers

log = logging.getLogger("djb.gateway.channel")

__all__ = [
    "CHANNEL_SWITCH", "LEASE_SECONDS", "MAX_REDISPATCHES", "MAX_DELIVERIES",
    "PER_NODE_PENDING_MAX", "GLOBAL_PENDING_MAX", "DEFAULT_TIMEOUT_S", "JOB_STATUSES",
    "RECENT_RESULTS_MAX",
    "ChannelJob", "ChannelQueue", "ChannelNodeClient", "QUEUE", "enabled",
]

#: 闸门名（features.py 已登记三字段；**默认关闭**，关闭时接线方继续用 Echo/原 NodeClient）
CHANNEL_SWITCH: str = "gateway.channel.enabled"

#: 任务租约：节点取走后 30s 内必须回结果，否则视为掉线、可重派
LEASE_SECONDS: float = 30.0

#: 租约过期后的**重派**次数上限（不含首次投递）
MAX_REDISPATCHES: int = 2

#: 合计投递次数上限（首次 + 重派 2 次）；用尽仍无结果 → 任务失败
MAX_DELIVERIES: int = 1 + MAX_REDISPATCHES

#: 每节点排队上限（含在途；超过即拒绝，防单节点把内存吃满）
PER_NODE_PENDING_MAX: int = 16

#: 全局排队上限（多节点合计）
GLOBAL_PENDING_MAX: int = 2048

#: ``complete()`` 缺省等待上限（``NodeCall.timeout_s`` 为空时用它）
DEFAULT_TIMEOUT_S: float = 60.0

#: 任务状态机（只加不改）
JOB_STATUSES: tuple[str, ...] = ("pending", "leased", "completed", "failed", "canceled")

#: 「最近完成」窗口：只保留最近这么多个已结束任务用于**重复提交幂等**判定
#: （内存有界；窗口外的重复提交按「未知任务」409 处理——节点侧本就不该重放这么久）
RECENT_RESULTS_MAX: int = 256

#: 节点回传结果的**白名单键**（其余字段丢弃：既防注入也防内存放大）
_RESULT_KEYS: tuple[str, ...] = (
    "status", "content", "finish_reason", "model", "tokens_in", "tokens_out",
    "usage_source", "latency_ms", "first_byte_ms", "upstream_request_id",
    "error_class", "error_code", "error_message",
)

#: ``poll`` 的等待切片（秒）：同时兼顾「新任务入队」「租约到期」两类唤醒
_WAIT_SLICE_S: float = 0.25


# --------------------------------------------------------------------------- 任务
@dataclass
class ChannelJob:
    """一次待投递的上游调用（**只在内存**：正文不落库、不进日志）。"""

    job_id: str
    request_id: str
    node_id: str
    model: str
    messages: tuple[Mapping[str, Any], ...] = field(default=(), repr=False)
    max_tokens: int | None = None
    temperature: float | None = None
    stop: tuple[str, ...] = ()
    timeout_s: float | None = None
    created_at: datetime | None = None
    lease_until: datetime | None = None
    attempts: int = 0
    status: str = "pending"
    result_event: threading.Event = field(default_factory=threading.Event, repr=False)
    result: dict[str, Any] | None = field(default=None, repr=False)
    redispatches: int = 0
    fingerprint: str | None = field(default=None, repr=False)

    @property
    def done(self) -> bool:
        return self.status in ("completed", "failed", "canceled")


# --------------------------------------------------------------------------- 工具
def enabled() -> bool:
    """接线判定：``gateway.channel.enabled``（默认关闭 → 继续用 Echo/原 NodeClient）。"""
    return features.enabled(CHANNEL_SWITCH)


def _now_of(now_fn: Any, now: datetime | None) -> datetime:
    return clock.as_utc(now if now is not None else (now_fn or clock.utcnow)())


def _result_payload(result: Any) -> dict[str, Any]:
    """把节点回传的结果规整成**白名单**字典（非法 → 400 / ``40001``；不含正文日志）。"""
    if not isinstance(result, Mapping):
        raise errors.GatewayError("bad_request", "节点结果必须是对象",
                                  details={"field": "result"})
    payload = {key: result[key] for key in _RESULT_KEYS if key in result}
    status = str(payload.get("status") or "completed").strip().lower()
    if status not in ("completed", "failed"):
        raise errors.GatewayError("bad_request", "节点结果 status 只能是 completed / failed",
                                  details={"field": "status"})
    payload["status"] = status
    if status == "completed":
        content = payload.get("content")
        payload["content"] = content if isinstance(content, str) else ("" if content is None
                                                                     else str(content))
        finish = payload.get("finish_reason")
        payload["finish_reason"] = finish if finish in facts.FINISH_REASONS else "stop"
    else:
        payload["error_class"] = str(payload.get("error_class") or "upstream_error").strip()
    return payload


#: 不参与幂等比对的**易变**字段：同一次结果被重放时耗时可能不同，但不影响「同一份结果」
_VOLATILE_KEYS: tuple[str, ...] = ("latency_ms", "first_byte_ms")


def _fingerprint(payload: Mapping[str, Any]) -> str:
    """同载荷判定（只用于幂等比对；摘要里有正文但不外泄，也不落到日志）。"""
    stable = {key: value for key, value in payload.items() if key not in _VOLATILE_KEYS}
    text = json.dumps(stable, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- 队列
class ChannelQueue:
    """线程安全的任务队列（``threading.Condition`` + 按 ``node_id`` 分桶的 FIFO）。

    不变量：

    * **同节点单在途**：一个 ``node_id`` 同一时刻最多 1 个 leased 任务；
    * 租约 30s：过期未回结果 → 重派（≤2 次），次数用尽 → 任务 ``failed``；
    * 幂等：同一任务重复 ``submit`` 同载荷 → ``duplicate``；不同载荷 → 409 / ``40919``；
    * 容量：每节点 ≤16、全局 ≤2048（含在途），超限 429 / ``42901``。
    """

    def __init__(self, *, now_fn: Any = None, lease_s: float = LEASE_SECONDS,
                 per_node_max: int = PER_NODE_PENDING_MAX,
                 global_max: int = GLOBAL_PENDING_MAX,
                 max_deliveries: int = MAX_DELIVERIES) -> None:
        self._now_fn = now_fn
        self._lease = timedelta(seconds=float(lease_s))
        self._per_node_max = int(per_node_max)
        self._global_max = int(global_max)
        self._max_deliveries = int(max_deliveries)
        self._cond = threading.Condition(threading.RLock())
        self._jobs: dict[str, ChannelJob] = {}
        self._done: "deque[ChannelJob]" = deque()      # 有界：只留 RECENT_RESULTS_MAX 个
        self._done_index: dict[str, ChannelJob] = {}   # job_id → 已结束任务（幂等判定）
        self._pending: dict[str, deque[str]] = {}
        self._inflight: dict[str, str] = {}
        self._counts: dict[str, int] = {}
        self._total = 0

    # ------------------------------------------------------------------ 入队
    def enqueue(self, call: models.NodeCall, *, now: datetime | None = None) -> ChannelJob:
        """把一次 ``NodeCall`` 入队；容量超限 → 429 / ``42901``（不放大内存）。"""
        node_id = str(getattr(call, "node_id", "") or "").strip()
        model = str(getattr(call, "model", "") or "").strip()
        if not node_id or not model:
            raise errors.GatewayError("bad_request", "上游调用缺 node_id / model",
                                      details={"field": "node_id" if not node_id else "model"})
        moment = _now_of(self._now_fn, now)
        with self._cond:
            if self._total >= self._global_max:
                log.warning("gateway.channel.rejected",
                            extra={"event": "channel.rejected", "node_id": node_id,
                                   "limit_kind": "global", "total": self._total})
                raise errors.GatewayError(
                    "rate_limited", "通道队列已满（全局上限），请稍后重试", retry_after_s=1,
                    details={"limit_kind": "global", "limit": self._global_max})
            if self._counts.get(node_id, 0) >= self._per_node_max:
                log.warning("gateway.channel.rejected",
                            extra={"event": "channel.rejected", "node_id": node_id,
                                   "limit_kind": "node",
                                   "pending": self._counts.get(node_id, 0)})
                raise errors.GatewayError(
                    "rate_limited", "通道队列已满（单节点上限），请稍后重试", retry_after_s=1,
                    details={"limit_kind": "node", "limit": self._per_node_max})
            job = ChannelJob(
                job_id=uuid.uuid4().hex, request_id=str(getattr(call, "request_id", "") or ""),
                node_id=node_id, model=model,
                messages=tuple(getattr(call, "messages", ()) or ()),
                max_tokens=getattr(call, "max_tokens", None),
                temperature=getattr(call, "temperature", None),
                stop=tuple(getattr(call, "stop", ()) or ()),
                timeout_s=getattr(call, "timeout_s", None), created_at=moment)
            self._jobs[job.job_id] = job
            self._pending.setdefault(node_id, deque()).append(job.job_id)
            self._counts[node_id] = self._counts.get(node_id, 0) + 1
            self._total += 1
            self._cond.notify_all()
        # 只记标识与规模，不记 messages（不落正文）
        log.info("gateway.channel.enqueued",
                 extra={"event": "channel.enqueued", "job_id": job.job_id,
                        "request_id": job.request_id, "node_id": node_id, "model": model,
                        "pending": self.pending(node_id)})
        return job

    # ------------------------------------------------------------------ 取任务
    def poll(self, node_id: str, wait_s: float = 0.0,
             capabilities: Iterable[str] | None = None, *,
             now: datetime | None = None) -> ChannelJob | None:
        """节点取任务：``wait_s`` 内没有可投递任务 → ``None``（对应 204）。

        ``capabilities``：节点声明的可用 ``model`` 集合；给了就只投递命中的任务
        （未命中留在队列里，不会被丢弃）。租约过期在取任务时顺带回收。
        """
        node_id = str(node_id or "").strip()
        if not node_id:
            raise errors.GatewayError("bad_request", "poll 缺 node_id", details={"field": "node_id"})
        wanted = {str(item) for item in capabilities} if capabilities else None
        budget = max(0.0, float(wait_s))
        deadline = clock.monotonic_ms() + int(budget * 1000)
        with self._cond:
            while True:
                moment = _now_of(self._now_fn, now)
                self._reap_expired(node_id, moment)
                job = self._lease_next(node_id, moment, wanted)
                if job is not None:
                    log.info("gateway.channel.leased",
                             extra={"event": "channel.leased", "job_id": job.job_id,
                                    "request_id": job.request_id, "node_id": node_id,
                                    "attempts": job.attempts,
                                    "redispatches": job.redispatches})
                    return job
                remaining_ms = deadline - clock.monotonic_ms()
                if remaining_ms <= 0:
                    return None
                self._cond.wait(min(remaining_ms / 1000.0, _WAIT_SLICE_S))

    # ------------------------------------------------------------------ 回结果
    def submit(self, node_id: str, job_id: str, result: Any,
               *, now: datetime | None = None) -> dict[str, Any]:
        """节点回结果：校验租约/归属；同载荷重放幂等（``accepted`` / ``duplicate``）。"""
        node_id = str(node_id or "").strip()
        job_id = str(job_id or "").strip()
        payload = _result_payload(result)
        digest = _fingerprint(payload)
        moment = _now_of(self._now_fn, now)
        with self._cond:
            job = self._jobs.get(job_id) or self._done_index.get(job_id)
            if job is None:
                raise errors.GatewayError("conflict", "未知任务（不存在或已回收）",
                                          details={"job_id": job_id})
            if job.node_id != node_id:
                raise errors.GatewayError("conflict", "任务不属于该节点",
                                          details={"job_id": job_id})
            if job.status in ("completed", "failed"):
                if job.fingerprint == digest:
                    return {"status": "duplicate", "job_id": job_id,
                            "request_id": job.request_id, "node_id": node_id}
                log.warning("gateway.channel.result_conflict",
                            extra={"event": "channel.result_conflict", "job_id": job_id,
                                   "node_id": node_id})
                raise errors.GatewayError("conflict", "同一任务的重复结果与已记录结果不一致",
                                          details={"job_id": job_id})
            if job.status == "canceled":
                raise errors.GatewayError("conflict", "任务已取消",
                                          details={"job_id": job_id})
            if (job.status != "leased" or self._inflight.get(node_id) != job_id
                    or (job.lease_until is not None and job.lease_until <= moment)):
                raise errors.GatewayError("conflict", "租约已失效（请重新 poll）",
                                          details={"job_id": job_id})
            self._finish(job, status=payload["status"], payload=payload)
            return {"status": "accepted", "job_id": job_id, "request_id": job.request_id,
                    "node_id": node_id}

    # ------------------------------------------------------------------ 取消 / 观测
    def cancel(self, job_id: str) -> bool:
        """取消任务（网关侧超时 / 停机）：已结束或未知 → ``False``。"""
        with self._cond:
            job = self._jobs.get(str(job_id or "").strip())
            if job is None or job.done:
                return False
            self._finish(job, status="canceled", payload={"status": "canceled"})
            return True

    def pending(self, node_id: str | None = None) -> int:
        """排队规模观测（含在途）：给 ``node_id`` 就只看该节点。"""
        with self._cond:
            if node_id is None:
                return self._total
            return self._counts.get(str(node_id).strip(), 0)

    def in_flight(self, node_id: str) -> str | None:
        """该节点当前 leased 的 ``job_id``（没有则 ``None``）。"""
        with self._cond:
            return self._inflight.get(str(node_id).strip())

    # ------------------------------------------------------------------ 内部（须持锁）
    def _lease_next(self, node_id: str, moment: datetime,
                    wanted: set[str] | None) -> ChannelJob | None:
        if node_id in self._inflight:                       # 同节点单在途
            return None
        queue = self._pending.get(node_id)
        if not queue:
            return None
        examined = 0
        total = len(queue)
        while queue and examined < total:
            job_id = queue.popleft()
            examined += 1
            job = self._jobs.get(job_id)
            if job is None or job.status != "pending":
                continue
            if wanted is not None and job.model not in wanted:
                queue.append(job_id)                        # 能力不匹配：保留，不丢
                continue
            job.status = "leased"
            job.lease_until = moment + self._lease
            job.attempts += 1
            self._inflight[node_id] = job_id
            return job
        return None

    def _reap_expired(self, node_id: str, moment: datetime) -> None:
        job_id = self._inflight.get(node_id)
        if job_id is None:
            return
        job = self._jobs[job_id]
        if job.lease_until is None or job.lease_until > moment:
            return
        del self._inflight[node_id]
        if job.attempts >= self._max_deliveries:
            log.warning("gateway.channel.lease_exhausted",
                        extra={"event": "channel.lease_exhausted", "job_id": job.job_id,
                               "node_id": node_id, "attempts": job.attempts})
            self._finish(job, status="failed",
                         payload={"status": "failed", "error_class": "timeout",
                                  "error_message": "节点租约过期且重派次数用尽"})
            return
        job.status = "pending"
        job.lease_until = None
        job.redispatches += 1
        self._pending.setdefault(node_id, deque()).append(job.job_id)   # 放回队尾待重派
        log.warning("gateway.channel.lease_expired",
                    extra={"event": "channel.lease_expired", "job_id": job.job_id,
                           "node_id": node_id, "attempts": job.attempts,
                           "redispatches": job.redispatches})

    def _finish(self, job: ChannelJob, *, status: str,
                payload: dict[str, Any]) -> None:
        job.status = status
        job.result = payload
        job.fingerprint = _fingerprint(payload)
        job.lease_until = None
        self._drop(job)
        self._remember(job)
        job.result_event.set()                              # 唤醒 complete()
        log.info("gateway.channel.finished",
                 extra={"event": "channel.finished", "job_id": job.job_id,
                        "request_id": job.request_id, "node_id": job.node_id,
                        "status": status, "attempts": job.attempts,
                        "redispatches": job.redispatches})

    def _remember(self, job: ChannelJob) -> None:
        """把已结束任务放进有界窗口（重复 ``submit`` 要做幂等比对，不能立刻丢）。"""
        self._done_index[job.job_id] = job
        self._done.append(job)
        while len(self._done) > RECENT_RESULTS_MAX:
            oldest = self._done.popleft()
            if self._done_index.get(oldest.job_id) is oldest:
                del self._done_index[oldest.job_id]

    def _drop(self, job: ChannelJob) -> None:
        if self._inflight.get(job.node_id) == job.job_id:
            del self._inflight[job.node_id]
        queue = self._pending.get(job.node_id)
        if queue is not None:
            try:
                queue.remove(job.job_id)
            except ValueError:
                pass
        self._jobs.pop(job.job_id, None)
        count = self._counts.get(job.node_id, 0) - 1
        if count > 0:
            self._counts[job.node_id] = count
        else:
            self._counts.pop(job.node_id, None)
        self._total = max(0, self._total - 1)


# --------------------------------------------------------------------------- 客户端
class ChannelNodeClient:
    """M03 ``NodeClient`` 的通道实现：入队 → 等结果 → 返回 :class:`models.NodeResult`。

    失败语义（都走 M03 既有口径，不新增错误码）：

    * 等待超时（``call.timeout_s`` / 缺省 60s）→ 取消任务 + :class:`providers.UpstreamTimeout`
      （dispatch → 504 / ``50902``）；
    * 节点回 ``failed``（含租约重派用尽）→ :class:`providers.UpstreamFailure`
      （dispatch → 502 / ``50903``）；``error_class="timeout"`` 时抛前者；
    * 任务被取消 → :class:`providers.UpstreamFailure`（不伪造成功）。
    """

    def __init__(self, queue: ChannelQueue | None = None, *,
                 default_timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self._queue = queue if queue is not None else QUEUE
        self._default_timeout_s = float(default_timeout_s)

    @property
    def queue(self) -> ChannelQueue:
        return self._queue

    def complete(self, call: models.NodeCall) -> models.NodeResult:
        started = clock.monotonic_ms()
        job = self._queue.enqueue(call)
        timeout_s = (float(call.timeout_s) if call.timeout_s is not None
                     else self._default_timeout_s)
        if not job.result_event.wait(max(0.0, timeout_s)):
            canceled = self._queue.cancel(job.job_id)
            log.warning("gateway.channel.client_timeout",
                        extra={"event": "channel.client_timeout", "job_id": job.job_id,
                               "request_id": job.request_id, "node_id": job.node_id,
                               "timeout_s": timeout_s, "canceled": canceled})
            raise providers.UpstreamTimeout("节点通道超时：任务在期限内没有结果")
        payload = dict(job.result or {})
        if job.status == "canceled":
            raise providers.UpstreamFailure("节点通道任务被取消")
        if job.status != "completed":
            message = str(payload.get("error_message") or "节点返回失败")
            if str(payload.get("error_class") or "") == "timeout":
                raise providers.UpstreamTimeout(message)
            raise providers.UpstreamFailure(message)
        return self._to_result(call, job, payload, started)

    def _to_result(self, call: models.NodeCall, job: ChannelJob, payload: dict[str, Any],
                   started: int) -> models.NodeResult:
        """把通道结果投影成 ``NodeResult``（正文只在内存里过一手，不进日志）。"""
        source = str(payload.get("usage_source") or "actual")
        latency = models.int_or_none(payload.get("latency_ms"))
        return models.NodeResult(
            content=str(payload.get("content") or ""),
            finish_reason=str(payload.get("finish_reason") or "stop"),
            model=str(payload.get("model") or call.model),
            tokens_in=models.int_or_none(payload.get("tokens_in")),
            tokens_out=models.int_or_none(payload.get("tokens_out")),
            usage_source=source if source in facts.USAGE_SOURCES else "actual",
            latency_ms=latency if latency is not None else clock.elapsed_ms(started),
            first_byte_ms=models.int_or_none(payload.get("first_byte_ms")),
            upstream_request_id=str(payload.get("upstream_request_id") or f"ch-{job.job_id}"),
        )


#: 模块级队列（只给接线用；测试各自 ``ChannelQueue()``，避免状态串味）
QUEUE = ChannelQueue()
