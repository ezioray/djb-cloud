# SPDX-License-Identifier: Apache-2.0
"""实时**非流式**主链路（M03 §6 流程 1 / T2）。

顺序严格按 M03 §6：

1. 入口生成 ``request_id`` / ``trace_id``；
2. M01 鉴权（Key、状态、IP、QPS、每日上限）——由 ``auth`` + ``quota`` 完成；
3. 参数校验（``validation``；413 / 40001）；
4. 幂等 / 指纹检查（``idempotency``；命中即回放，不重复计费）；
5. M04 路由与报价（``providers.route``）；
6. 节点执行（``dispatch``；首字节前最多 2 次尝试）；
7. M05 记录用量（``providers.record_usage``，按 ``request_id`` 幂等）；
8. 写 ``api_request_log`` + ``m03_outbox``（**同一本地事务**）；
9. 返回 JSON。

边界：

* 本函数**不碰 HTTP**（不 import fastapi），入参是 Principal + 已解析报文 + 连接；
  响应信封与状态码由 :mod:`app.gateway.router` 组装，便于纯函数测试。
* **不写别人的表**：路由 / 用量只经 provider；本模块只写 ``api_request_log`` /
  ``m03_outbox`` / ``m03_idempotency``。
* **不落正文**：``messages`` 与上游 ``content`` 只在内存里过一手。
* 回放（幂等命中）**不发** ``request.completed``：新 ``request_id`` 若发事件，M05 会按
  新 id 再记一条用量 → 重复计费。回放只留一条元数据日志（INV-M03-03「不重复落账」）。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from . import (clock, config_source, dispatch, errors, events, facts, features, idempotency,
               models, outbox, providers, quota, ratelimit, store, validation)

log = logging.getLogger("djb.gateway.chat")

__all__ = ["ChatOutcome", "complete"]


@dataclass
class ChatOutcome:
    """一次成功响应的结果（router 直接序列化 ``payload``）。"""

    payload: dict[str, Any]
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    replayed: bool = False


def _limit_headers(decision: ratelimit.LimitDecision | None) -> dict[str, str]:
    return {} if decision is None else decision.headers()


def _estimate_tokens(text: str) -> int:
    """粗略 token 估算（仅在上游未给用量时兜底，标 ``estimated``）。"""
    return max(1, len(text or "") // 4)


def _usage_of(result: models.NodeResult, messages: tuple[dict[str, str], ...]) -> tuple[int,
                                                                                       int, str]:
    """用量与口径：上游给了两端 → ``actual``；缺一端 → 按内容估算并标 ``estimated``。"""
    prompt_text = "".join(item.get("content") or "" for item in messages)
    tokens_in = result.tokens_in
    tokens_out = result.tokens_out
    if tokens_in is None or tokens_out is None:
        tokens_in = _estimate_tokens(prompt_text) if tokens_in is None else int(tokens_in)
        tokens_out = _estimate_tokens(result.content) if tokens_out is None else int(tokens_out)
        return int(tokens_in), int(tokens_out), "estimated"
    return int(tokens_in), int(tokens_out), "actual"


def _completion_payload(*, request_id: str, model: str, content: str, finish_reason: str,
                        tokens_in: int, tokens_out: int, created_at: datetime) -> dict[str, Any]:
    """spec ``ChatCompletionResponse``（``object`` 常量 + ``usage`` 三段）。"""
    return {
        "id": request_id,
        "object": "chat.completion",
        "created": int(clock.as_utc(created_at).timestamp()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": finish_reason if finish_reason in facts.FINISH_REASONS else "stop",
        }],
        "usage": {
            "prompt_tokens": int(tokens_in),
            "completion_tokens": int(tokens_out),
            "total_tokens": int(tokens_in) + int(tokens_out),
        },
    }


def _record(c: Any, record: models.RequestRecord, *, now: datetime) -> None:
    try:
        store.log_request(c, record, now=now)
    except Exception:                                       # pragma: no cover - 防御
        log.warning("gateway.chat.log_failed",
                    extra={"event": "log.failed", "request_id": record.request_id})


def _fail(c: Any, *, record: models.RequestRecord, envelope: Mapping[str, Any] | None,
          now: datetime) -> None:
    """失败留痕：``api_request_log`` + ``request.failed``（同一事务；失败不阻塞响应）。"""
    _record(c, record, now=now)
    if envelope is None:
        return
    try:
        outbox.enqueue(c, envelope)
    except Exception:                                       # pragma: no cover - 防御
        log.warning("gateway.chat.outbox_failed",
                    extra={"event": "outbox.failed", "request_id": record.request_id})


def complete(c: Any, *args: Any, principal: models.Principal, body: Mapping[str, Any],
             request_id: str, trace_id: str, idempotency_key: str | None = None,
             client_ip: str | None = None, now: datetime | None = None,
             limiter: ratelimit.SlidingWindowLimiter | None = None) -> ChatOutcome:
    """执行一次实时非流式调用；失败抛 :class:`app.gateway.errors.GatewayError`。"""
    if args:
        raise TypeError("complete() 只接受关键字参数（principal / body / request_id …）")
    moment = clock.as_utc(now or clock.utcnow())
    bucket = limiter or ratelimit.LIMITER
    started = clock.monotonic_ms()
    limit_decision: ratelimit.LimitDecision | None = None

    raw_model = body.get("model") if isinstance(body, Mapping) else None
    record = models.RequestRecord(
        request_id=request_id, status="failed", http_status=500,
        service_tier="realtime", stream=bool(body.get("stream")) if isinstance(body, Mapping)
        else False,
        account_id=principal.account_id, tenant_id=principal.tenant_id,
        api_key_id=principal.api_key_id,
        model=raw_model if isinstance(raw_model, str) and raw_model.strip() else None,
        trace_id=trace_id)

    try:
        # ---- 2) 配额 / 限流（M01 快照 → min(租户, Key) + M10 全局基线）
        state = quota.from_snapshot(dict(principal.quotas or {}))
        quota.assert_daily_cap(state)
        config_values = config_source.snapshot()
        limit_value = quota.effective_qps(state.qps, config_values.get("rate_limit_qps"))
        scope = (f"key:{principal.api_key_id}" if principal.api_key_id is not None
                 else f"tenant:{principal.tenant_id}")
        limit_decision = bucket.take(scope, limit_value, now=moment)
        ratelimit.enforce([limit_decision], now=moment)

        # ---- 3) 参数校验（413 / 40001）
        validated = validation.validate_chat(body)
        record.model = validated.model

        if validated.stream:
            # T3 的 SSE 闸门（features.gateway.stream_sse 默认关闭 → 显式 400）
            raise errors.GatewayError(
                "bad_request", "stream=true 暂不支持：本版本只提供非流式（T3 交付 SSE）",
                details={"field": "stream"})

        # ---- 4) 幂等 / 指纹
        body_hash = idempotency.body_hash(dict(body))
        if idempotency_key:
            idem_scope = idempotency.scope_of("POST", "/v1/chat/completions", principal)
            replay = idempotency.replay_or_conflict(c, scope=idem_scope, key=idempotency_key,
                                                    request_hash=body_hash, now=moment)
            if replay is not None:
                # 回放：只留一条元数据日志，**不发** request.completed、不写用量
                record.status, record.http_status = "completed", replay.status_code
                record.latency_ms = clock.elapsed_ms(started)
                record.usage_source = None
                _record(c, record, now=moment)
                return ChatOutcome(payload=dict(replay.payload),
                                   status_code=replay.status_code,
                                   headers={facts.IDEMPOTENT_REPLAY_HEADER: "true",
                                            **_limit_headers(limit_decision)},
                                   replayed=True)
        fp_scope = idempotency.fingerprint_scope("POST", "/v1/chat/completions", principal)
        window = idempotency.window_for(stream=False)
        fingerprint = idempotency.replay_or_conflict(
            c, scope=fp_scope, key=body_hash, request_hash=body_hash, now=moment,
            ttl_s=window, window_s=window, mode="fingerprint")
        if fingerprint is not None:
            record.status, record.http_status = "completed", fingerprint.status_code
            record.latency_ms = clock.elapsed_ms(started)
            _record(c, record, now=moment)
            return ChatOutcome(payload=dict(fingerprint.payload),
                               status_code=fingerprint.status_code,
                               headers={facts.IDEMPOTENT_REPLAY_HEADER: "true",
                                        **_limit_headers(limit_decision)},
                               replayed=True)

        # ---- 5) M04 路由 + 6) 节点执行（首字节前 ≤2 次尝试）
        def _route(attempt_no: int) -> models.RouteDecision:
            decision = providers.route(models.RouteRequest(
                model=validated.model, kind="realtime", tenant_id=principal.tenant_id,
                account_id=principal.account_id, request_id=request_id, trace_id=trace_id,
                attempt_no=attempt_no,
                requested_tokens=validated.request_tokens_hint(),
                deadline_seconds=None))
            # 节点层限流（min(租户, Key, 节点) 的第三层）。
            # 闸门 gateway.node_layer_rate_limit 默认关闭（硬约束第 4 条）：
            # 关闭时只依赖 M04 P3 的节点配额判定，网关不做二次限流。
            if decision.node_qps is not None and features.enabled("gateway.node_layer_rate_limit"):
                node_limit = quota.effective_qps(decision.node_qps, limit_value)
                node_decision = bucket.take(f"node:{decision.node_id}", node_limit, now=moment)
                ratelimit.enforce([node_decision], now=moment)
            return decision

        def _call(decision: models.RouteDecision) -> models.NodeCall:
            return models.NodeCall(
                node_id=decision.node_id, upstream_id=decision.chosen.upstream_id,
                access=decision.chosen.access, model=validated.model,
                messages=validated.messages, request_id=request_id, trace_id=trace_id,
                attempt_no=1, max_tokens=validated.max_tokens,
                temperature=validated.temperature, stop=validated.stop,
                timeout_s=config_values.get("stream_timeout_s"))

        outcome = dispatch.dispatch(route=_route, send=providers.send, call_factory=_call,
                                    request_id=request_id, trace_id=trace_id, now=moment)
        if outcome.error is not None:
            raise outcome.error
        result = outcome.result
        decision = outcome.decision
        assert result is not None and decision is not None       # dispatch 保证

        # ---- 7) 用量与口径
        tokens_in, tokens_out, usage_source = _usage_of(result, validated.messages)
        latency_ms = (result.latency_ms if result.latency_ms is not None
                      else clock.elapsed_ms(started))
        first_byte_ms = (result.first_byte_ms if result.first_byte_ms is not None
                         else latency_ms)
        draft = models.UsageDraft(
            request_id=request_id, attempt_no=outcome.attempt_count,
            account_id=principal.account_id, tenant_id=principal.tenant_id,
            api_key_id=principal.api_key_id, node_id=decision.node_id,
            model=validated.model, access=decision.chosen.access,
            tokens_in=tokens_in, tokens_out=tokens_out, usage_source=usage_source,
            amount_minor=decision.price_minor, policy_version=state.policy_version,
            trace_id=trace_id, occurred_at=moment)
        try:
            providers.record_usage(draft)
        except Exception as exc:                            # M05 不可用不阻塞 2xx
            log.warning("gateway.chat.usage_failed",
                        extra={"event": "usage.failed", "request_id": request_id,
                               "error": type(exc).__name__})
            # request.completed 仍会由 outbox 至少一次投递，M05 侧按 request_id 幂等补齐

        # ---- 8) 本地事务：日志 + 事件 + 幂等记录
        record.status, record.http_status = "completed", 200
        record.node_id, record.latency_ms = decision.node_id, latency_ms
        record.first_byte_ms = first_byte_ms
        record.tokens_in, record.tokens_out = tokens_in, tokens_out
        record.usage_source = usage_source
        payload = _completion_payload(request_id=request_id, model=validated.model,
                                      content=result.content,
                                      finish_reason=result.finish_reason,
                                      tokens_in=tokens_in, tokens_out=tokens_out,
                                      created_at=moment)
        _record(c, record, now=moment)
        try:
            outbox.enqueue(c, events.request_completed_event(
                request_id=request_id, model=validated.model, tokens_in=tokens_in,
                tokens_out=tokens_out, latency_ms=int(latency_ms),
                node_id=decision.node_id, usage_source=usage_source, trace_id=trace_id,
                occurred_at=moment))
        except Exception:                                   # pragma: no cover - 防御
            log.warning("gateway.chat.outbox_failed",
                        extra={"event": "outbox.failed", "request_id": request_id})
        _remember(c, principal=principal, request_id=request_id, idempotency_key=idempotency_key,
                  fp_key=body_hash, body_hash=body_hash, payload=payload, now=moment,
                  fp_ttl=window)
        # 顺带清理过期指纹（小批量、不阻塞）
        try:
            idempotency.delete_expired(c, now=moment)
        except Exception:                                   # pragma: no cover - 防御
            log.info("gateway.chat.purge_failed", extra={"event": "idempotency.purge_failed"})

        return ChatOutcome(payload=payload, status_code=200,
                           headers=_limit_headers(limit_decision))

    except errors.GatewayError as exc:
        record.status = "failed"
        record.http_status = exc.http_status
        record.error_code = exc.code
        record.latency_ms = (record.latency_ms if record.latency_ms is not None
                             else clock.elapsed_ms(started))
        envelope = None
        if not record.stream:
            try:
                envelope = events.request_failed_event(
                    request_id=request_id, error_code=exc.code,
                    upstream_error_class=exc.upstream_error_class,
                    attempts=int(exc.details.get("attempts") or 1), trace_id=trace_id,
                    occurred_at=moment)
            except ValueError:                              # pragma: no cover - 防御
                envelope = None
        _fail(c, record=record, envelope=envelope, now=moment)
        if not exc.headers:
            exc.headers.update(_limit_headers(limit_decision))
        raise


def _remember(c: Any, *, principal: models.Principal, request_id: str,
              idempotency_key: str | None, fp_key: str, body_hash: str,
              payload: Mapping[str, Any], now: datetime, fp_ttl: int) -> None:
    """记住首次结果：幂等键 24h + 请求体指纹 300s（同事务）。"""
    try:
        if idempotency_key:
            idempotency.remember(
                c, scope=idempotency.scope_of("POST", "/v1/chat/completions", principal),
                key=idempotency_key, request_hash=body_hash, status_code=200,
                payload=payload, now=now, ttl_s=facts.IDEMPOTENCY_TTL_S)
        idempotency.remember(
            c, scope=idempotency.fingerprint_scope("POST", "/v1/chat/completions", principal),
            key=fp_key, request_hash=body_hash, status_code=200, payload=payload,
            now=now, ttl_s=int(fp_ttl))
    except Exception:                                       # pragma: no cover - 防御
        log.warning("gateway.chat.idempotency_failed",
                    extra={"event": "idempotency.remember_failed", "request_id": request_id})
