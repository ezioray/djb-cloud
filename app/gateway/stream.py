# SPDX-License-Identifier: Apache-2.0
"""SSE 流式实时调用（T3 / M03 §6 流程 2 / §4.3 / INV-M03-04）。

口径：

* ``stream=true`` → ``text/event-stream``，逐帧 ``data: <json>``，**必须以 ``data: [DONE]``
  收尾**（INV-M03-04）；分块对象是 OpenAI 兼容的 ``chat.completion.chunk``。
* **首字节前**沿用非流式的重路由策略（≤2 次尝试）；**首字节之后不再重路由**
  （M03 §6.2 / §7）——已发出去的内容不重放。
* **中断**：客户端断开（GeneratorExit）或上游中断 → 标记 ``interrupted``、
  ``usage_source=estimated``、错误码 ``44101``；已建立连接时无法改 HTTP 状态，
  因此用一帧 ``data: {"error": ...}`` + ``data: [DONE]`` 告知客户端，并把
  ``api_request_log.http_status=441 / error_code=44101`` 落库（对外可见性由日志与事件保证）。
* **首字节前失败**：仍按普通错误返回 JSON（502 / 504 / 503 / 429 / 402 …），不计费。
* **幂等**：流式只做「请求建立」去重（``stream_dedup_window_s`` = 60s）。命中窗口时
  不重放流（不可能重放），返回 409 / 40919 让客户端识别重复建流（INV-M03-03 不重复计费）。
* **不落正文**：分块正文只在内存里过一手；日志 / 事件只有元数据。
* **计费**：正常收尾按上游用量（缺则估算）；中断一律 ``estimated``。开关
  ``gateway.stream_estimated_usage_sync`` 关闭时，中断**不主动**写 M05 估算用量
  （由 M05 用收据 / 上游账单校正），只在网关侧留事实。
* **双计（C9a）**：开关 ``gateway.token.dual.enabled`` 打开且上游给了两端用量时，本地
  tokenizer 复核并标 ``usage_source=dual``，差异 >1% 记 ``gateway.token_mismatch`` 告警；
  **响应帧里的 usage 数值不因本地计数改变**（计费口径不变）。关闭时回到 ``actual``。
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterator, Mapping

from . import (clock, config_source, errors, events, facts, features, idempotency, models,
               outbox, providers, quota, ratelimit, store, tokenizer, validation)

log = logging.getLogger("djb.gateway.stream")

__all__ = ["StreamOutcome", "StreamPlan", "prepare", "chunk_frame", "error_frame", "done_frame",
           "format_frame"]


# --------------------------------------------------------------------------- SSE 帧
def format_frame(payload: Mapping[str, Any]) -> str:
    """``data: <json>\\n\\n``（紧凑、保留非 ASCII）。"""
    return "data: " + json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")) + "\n\n"


def done_frame() -> str:
    """``data: [DONE]`` 收尾帧（INV-M03-04）。"""
    return f"data: {facts.SSE_DONE}\n\n"


def chunk_frame(*, request_id: str, created: int, model: str, delta: Mapping[str, Any],
                finish_reason: str | None = None, usage: Mapping[str, Any] | None = None,
                index: int = 0) -> str:
    """一帧 ``chat.completion.chunk``（可选带 ``usage``，属「只加不改」的新增信息）。"""
    payload: dict[str, Any] = {
        "id": request_id,
        "object": facts.SSE_CHUNK_OBJECT,
        "created": int(created),
        "model": model,
        "choices": [{"index": int(index), "delta": dict(delta),
                     "finish_reason": finish_reason}],
    }
    if usage is not None:
        payload["usage"] = dict(usage)
    return format_frame(payload)


def error_frame(*, request_id: str, exc: errors.GatewayError) -> str:
    """流内错误帧（已建立连接时无法改 HTTP 状态；444/441 语义靠这一帧 + 日志对外）。"""
    return format_frame(errors.error_body(exc, request_id))


# --------------------------------------------------------------------------- 计划与结果
@dataclass
class StreamOutcome:
    """一次流式调用的最终事实（落 ``api_request_log`` 与事件用）。"""

    request_id: str
    model: str
    status: str = "completed"
    http_status: int = 200
    error_code: int | None = None
    node_id: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    usage_source: str = "actual"
    first_byte_ms: int | None = None
    latency_ms: int | None = None
    attempts: int = 1
    frames: int = 0
    upstream_error_class: str | None = None


@dataclass
class StreamPlan:
    """``prepare`` 的产物：已经等到**首字节**，剩下的是把分块转成 SSE 并落事实。"""

    principal: models.Principal
    validated: validation.ValidatedChat
    decision: models.RouteDecision
    first_chunk: models.StreamChunk
    chunks: Iterator[Any]
    request_id: str
    trace_id: str
    now: datetime
    attempts: int = 1
    limit_headers: dict[str, str] = field(default_factory=dict)
    guard: idempotency.WriteGuard | None = None
    connection_factory: Callable[[], Any] | None = None
    started_ms: int = 0
    created: int = 0

    # ------------------------------------------------------------------ 帧序列
    def frames(self) -> Iterator[str]:
        """产出 SSE 帧；结束（正常 / 中断）后**落库**（日志 + 事件 + 用量 + 幂等标记）。"""
        outcome = StreamOutcome(request_id=self.request_id, model=self.validated.model,
                                node_id=self.decision.node_id, attempts=self.attempts)
        content: list[str] = []
        sent_error = False
        completed = False
        tokens_in = self.first_chunk.tokens_in
        tokens_out = self.first_chunk.tokens_out
        try:
            role = self.first_chunk.role or "assistant"
            yield chunk_frame(request_id=self.request_id, created=self.created,
                              model=self.validated.model,
                              delta={"role": role, "content": self.first_chunk.delta})
            if self.first_chunk.delta:
                content.append(self.first_chunk.delta)
            tokens_in = tokens_in if tokens_in is not None else self.first_chunk.tokens_in
            tokens_out = tokens_out if tokens_out is not None else self.first_chunk.tokens_out
            finish_reason = self.first_chunk.finish_reason
            for item in self.chunks:
                chunk = models.coerce_stream_chunk(item)
                if chunk.delta:
                    content.append(chunk.delta)
                if chunk.tokens_in is not None:
                    tokens_in = chunk.tokens_in
                if chunk.tokens_out is not None:
                    tokens_out = chunk.tokens_out
                if chunk.finish_reason:
                    finish_reason = chunk.finish_reason
                outcome.frames += 1
                yield chunk_frame(request_id=self.request_id, created=self.created,
                                  model=self.validated.model, delta={"content": chunk.delta})
                if finish_reason:
                    break
            final_reason = finish_reason or "stop"
            if final_reason not in facts.FINISH_REASONS:
                final_reason = "stop"
            prompt_tokens, completion_tokens, usage_source = self._usage(tokens_in, tokens_out,
                                                                        content)
            yield chunk_frame(request_id=self.request_id, created=self.created,
                              model=self.validated.model, delta={},
                              finish_reason=final_reason,
                              usage={"prompt_tokens": prompt_tokens,
                                     "completion_tokens": completion_tokens,
                                     "total_tokens": prompt_tokens + completion_tokens})
            yield done_frame()
            completed = True
            outcome.status, outcome.http_status = "completed", 200
            outcome.tokens_in, outcome.tokens_out = prompt_tokens, completion_tokens
            outcome.usage_source = usage_source
        except GeneratorExit:
            # 客户端断开：不重放已发内容、不再 yield，只把事实落库
            outcome.status, outcome.http_status = "interrupted", 441
            outcome.error_code = errors.spec("stream_interrupted").code
            outcome.upstream_error_class = "client_disconnect"
            raise
        except Exception as exc:                                # 上游中断 / 传输错
            outcome.status, outcome.http_status = "interrupted", 441
            outcome.error_code = errors.spec("stream_interrupted").code
            outcome.upstream_error_class = ("timeout" if isinstance(exc, TimeoutError)
                                           else "upstream_error")
            log.warning("gateway.stream.interrupted",
                        extra={"event": "stream.interrupted", "request_id": self.request_id,
                               "error": type(exc).__name__})
            exc_error = errors.GatewayError(
                "stream_interrupted", "流式中断：用量为估算值，计费按上游实际校正",
                reason=None, upstream_error_class=outcome.upstream_error_class,
                details={"request_id": self.request_id})
            if not sent_error:
                sent_error = True
                yield error_frame(request_id=self.request_id, exc=exc_error)
                yield done_frame()
        finally:
            if not completed and outcome.error_code is None:
                # 生成器被提前关闭但没走上面的分支（例如框架侧取消）
                outcome.status, outcome.http_status = "interrupted", 441
                outcome.error_code = errors.spec("stream_interrupted").code
            if outcome.tokens_in == 0 and outcome.tokens_out == 0:
                prompt_tokens, completion_tokens, usage_source = self._usage(
                    tokens_in, tokens_out, content)
                outcome.tokens_in, outcome.tokens_out = prompt_tokens, completion_tokens
                outcome.usage_source = (usage_source if completed else "estimated")
            if not completed:
                outcome.usage_source = "estimated"
            outcome.latency_ms = clock.elapsed_ms(self.started_ms)
            outcome.first_byte_ms = (self.first_chunk.first_byte_ms
                                     if self.first_chunk.first_byte_ms is not None
                                     else clock.elapsed_ms(self.started_ms))
            self._persist(outcome)

    # ------------------------------------------------------------------ 内部
    def _usage(self, tokens_in: int | None, tokens_out: int | None,
               content: list[str]) -> tuple[int, int, str]:
        """与 :func:`app.gateway.chat._usage_of` 同口径（C9a）：流式 completion 用已收集正文计数。

        * 上游两端都有：双计开关打开 → 本地复核 + 差异告警，标 ``dual``（**数值仍用上游**）；
          关闭 → ``actual``（行为不变）。
        * 缺一端：用本地 tokenizer 补齐（替代 ``len // 4``），标 ``estimated``。
        """
        text = "".join(content)
        if tokens_in is not None and tokens_out is not None:
            if not features.enabled(facts.TOKEN_DUAL_SWITCH):
                return int(tokens_in), int(tokens_out), "actual"
            local_in = tokenizer.count_prompt_tokens(self.validated.model, self.validated.messages)
            local_out = tokenizer.count_completion_tokens(self.validated.model, text)
            for event in tokenizer.dual_mismatch_events(
                    request_id=self.request_id, model=self.validated.model,
                    local_in=local_in, upstream_in=int(tokens_in),
                    local_out=local_out, upstream_out=int(tokens_out),
                    threshold=facts.TOKEN_DUAL_MISMATCH_RATIO):
                log.warning("gateway.token_mismatch", extra=event)
            return int(tokens_in), int(tokens_out), "dual"
        estimated_in = (int(tokens_in) if tokens_in is not None else max(
            1, tokenizer.count_prompt_tokens(self.validated.model, self.validated.messages)))
        estimated_out = (int(tokens_out) if tokens_out is not None else max(
            1, tokenizer.count_completion_tokens(self.validated.model, text)))
        return estimated_in, estimated_out, "estimated"

    def _connection(self) -> Any:
        if self.connection_factory is not None:
            return self.connection_factory()
        from app.db import conn as db_conn                   # 基础设施，非业务模块

        return db_conn()

    def _persist(self, outcome: StreamOutcome) -> None:
        """流结束后的**独立事务**：日志 + 事件 + 用量 + 幂等标记（失败只记日志）。"""
        try:
            with self._connection() as c:
                record = models.RequestRecord(
                    request_id=outcome.request_id, status=outcome.status,
                    http_status=outcome.http_status, service_tier="realtime", stream=True,
                    account_id=self.principal.account_id, tenant_id=self.principal.tenant_id,
                    api_key_id=self.principal.api_key_id, model=outcome.model,
                    error_code=outcome.error_code, node_id=outcome.node_id,
                    latency_ms=outcome.latency_ms, first_byte_ms=outcome.first_byte_ms,
                    tokens_in=outcome.tokens_in, tokens_out=outcome.tokens_out,
                    usage_source=outcome.usage_source, trace_id=self.trace_id)
                store.log_request(c, record, now=self.now)
                if outcome.status == "completed":
                    outbox.enqueue(c, events.request_completed_event(
                        request_id=outcome.request_id, model=outcome.model,
                        tokens_in=outcome.tokens_in, tokens_out=outcome.tokens_out,
                        latency_ms=int(outcome.latency_ms or 0), node_id=outcome.node_id or "",
                        usage_source=outcome.usage_source, trace_id=self.trace_id,
                        occurred_at=self.now))
                else:
                    outbox.enqueue(c, events.request_failed_event(
                        request_id=outcome.request_id, error_code=outcome.error_code,
                        upstream_error_class=outcome.upstream_error_class,
                        attempts=outcome.attempts, trace_id=self.trace_id,
                        occurred_at=self.now))
                if self.guard is not None:
                    self.guard.remember(
                        status_code=outcome.http_status,
                        payload={"stream": True, "request_id": outcome.request_id},
                        ttl_s=facts.STREAM_DEDUP_WINDOW_S, store_payload=False)
        except Exception:                                   # pragma: no cover - 防御
            log.warning("gateway.stream.persist_failed",
                        extra={"event": "stream.persist_failed",
                               "request_id": outcome.request_id})
        self._record_usage(outcome)

    def _record_usage(self, outcome: StreamOutcome) -> None:
        interrupted = outcome.status != "completed"
        if interrupted and not features.enabled("gateway.stream_estimated_usage_sync"):
            log.info("gateway.stream.estimated_usage_deferred",
                     extra={"event": "stream.estimated_usage_deferred",
                            "request_id": outcome.request_id})
            return
        draft = models.UsageDraft(
            request_id=outcome.request_id, attempt_no=outcome.attempts,
            account_id=self.principal.account_id, tenant_id=self.principal.tenant_id,
            api_key_id=self.principal.api_key_id, node_id=outcome.node_id or "",
            model=outcome.model, access=self.decision.chosen.access,
            tokens_in=outcome.tokens_in, tokens_out=outcome.tokens_out,
            usage_source=outcome.usage_source, amount_minor=self.decision.price_minor,
            policy_version=self._policy_version(), trace_id=self.trace_id,
            occurred_at=self.now)
        try:
            providers.record_usage(draft)
        except Exception as exc:                            # pragma: no cover - 防御
            log.warning("gateway.stream.usage_failed",
                        extra={"event": "stream.usage_failed",
                               "request_id": outcome.request_id,
                               "error": type(exc).__name__})

    def _policy_version(self) -> str | None:
        state = quota.from_snapshot(dict(self.principal.quotas or {}))
        return state.policy_version


# --------------------------------------------------------------------------- 建立
def prepare(c: Any, *, principal: models.Principal, body: Mapping[str, Any],
            request_id: str, trace_id: str, idempotency_key: str | None = None,
            now: datetime | None = None,
            limiter: ratelimit.SlidingWindowLimiter | None = None,
            connection_factory: Callable[[], Any] | None = None) -> StreamPlan:
    """建流：配额/限流 → 校验 → 请求建立去重 → 路由 → 等**首字节**（≤2 次尝试）。

    首字节前的一切失败都还来得及返回普通 JSON 错误（router 负责）；成功后返回
    :class:`StreamPlan`，由 router 交给 ``StreamingResponse``。
    """
    moment = clock.as_utc(now or clock.utcnow())
    bucket = limiter or ratelimit.LIMITER
    started = clock.monotonic_ms()

    config_values = config_source.snapshot()
    limit_decision, _state, limit_value = ratelimit.precheck(
        principal, now=moment, bucket=bucket, config_values=config_values)

    validated = validation.validate_chat(body)
    if not validated.stream:
        raise errors.GatewayError("bad_request", "非流式请求必须走普通通道",
                                  details={"field": "stream"})

    guard = idempotency.WriteGuard(c, principal=principal, method="POST",
                                   path="/v1/chat/completions", key=idempotency_key,
                                   body=dict(body), now=moment, stream=True)
    if guard.replay() is not None:
        raise errors.GatewayError(
            "conflict", "同一流式请求已在 60s 内建立过：请勿重复建流",
            details={"idempotency_key": idempotency_key})

    attempt_no = 1
    while True:
        decision = providers.route(models.RouteRequest(
            model=validated.model, kind="realtime", tenant_id=principal.tenant_id,
            account_id=principal.account_id, request_id=request_id, trace_id=trace_id,
            attempt_no=attempt_no, requested_tokens=validated.request_tokens_hint(),
            deadline_seconds=config_values.get("stream_timeout_s")))
        if decision.node_qps is not None and features.enabled("gateway.node_layer_rate_limit"):
            node_limit = quota.effective_qps(decision.node_qps, limit_value)
            ratelimit.enforce([bucket.take(f"node:{decision.node_id}", node_limit, now=moment)],
                              now=moment)
        call = models.NodeCall(
            node_id=decision.node_id, upstream_id=decision.chosen.upstream_id,
            access=decision.chosen.access, model=validated.model,
            messages=validated.messages, request_id=request_id, trace_id=trace_id,
            attempt_no=attempt_no, max_tokens=validated.max_tokens,
            temperature=validated.temperature, stop=validated.stop,
            timeout_s=config_values.get("stream_timeout_s"))
        iterator = None
        first = None
        try:
            iterator = providers.stream(call)          # 建连（可能在这里就抛超时 / 失败）
            first = next(iter(iterator))               # 等首字节
        except errors.GatewayError:
            raise                                      # 未接线 / fail-closed 直接上抛
        except StopIteration as exc:
            _log_attempt(request_id, trace_id, attempt_no, decision.node_id, "empty_stream")
            if attempt_no >= facts.STREAM_MAX_ATTEMPTS:
                raise errors.GatewayError("upstream_error", "上游返回空流，请稍后重试",
                                          upstream_error_class="upstream",
                                          details={"attempts": attempt_no}) from exc
            attempt_no += 1
            continue
        except (providers.UpstreamTimeout, providers.UpstreamFailure) as exc:
            error_class = ("timeout" if isinstance(exc, providers.UpstreamTimeout)
                           else "upstream_error")
            _log_attempt(request_id, trace_id, attempt_no, decision.node_id, error_class)
            if attempt_no >= facts.STREAM_MAX_ATTEMPTS:
                if error_class == "timeout":
                    raise errors.GatewayError("upstream_timeout", "上游超时，请稍后重试",
                                              retry_after_s=2, upstream_error_class="timeout",
                                              details={"attempts": attempt_no}) from exc
                raise errors.GatewayError("upstream_error", "上游返回异常，请稍后重试",
                                          upstream_error_class="upstream",
                                          details={"attempts": attempt_no}) from exc
            attempt_no += 1
            continue
        assert iterator is not None and first is not None       # 循环出口保证
        break

    return StreamPlan(principal=principal, validated=validated, decision=decision,
                      first_chunk=models.coerce_stream_chunk(first), chunks=iterator,
                      request_id=request_id, trace_id=trace_id, now=moment,
                      attempts=attempt_no, limit_headers=limit_decision.headers(),
                      guard=guard, connection_factory=connection_factory,
                      started_ms=started, created=int(moment.timestamp()))


def _log_attempt(request_id: str, trace_id: str, attempt_no: int, node_id: str,
                 error_class: str) -> None:
    log.warning("gateway.stream.attempt_failed",
                extra={"event": "stream.attempt_failed", "request_id": request_id,
                       "trace_id": trace_id, "attempt_no": attempt_no, "node_id": node_id,
                       "error_class": error_class})
