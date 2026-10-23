# SPDX-License-Identifier: Apache-2.0
"""M03 T1+T2 HTTP 路由（独立模块，**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 spec 1.2.x 里本任务的两个操作::

    POST /v1/chat/completions   createChatCompletion   200（非流式；stream=true 属 T3）
    GET  /v1/models             listModels             200

约定（00-conventions §5 / spec ``Error``）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**，
  ``type`` 取 spec 枚举；**任何响应**（含错误）都回显 ``X-Request-Id``；
* 429 / 503 带 ``Retry-After``；429 另带 ``X-DJB-RateLimit-*`` 三件套；
* 请求体自己校验（不依赖框架 422）：不合法一律 400 / 40001，超上限 413 / 40013。

认证与依赖注入（默认 **fail-closed**，合并时由 Lead 接线，见 ``WIRING.md``）::

    providers.set_auth_provider(M01 verify_api_key 的投影)
    providers.set_route_provider(M04 /api/v1/schedule/route 客户端)
    providers.set_node_client(上游节点通道)
    providers.set_usage_provider(M05 用量写入口)
    providers.set_model_catalog_provider(M04 model_catalog 只读投影)
    config_source.set_provider(M10 配置只读快照)

数据库连接经 :func:`_connection`（``app.db`` 既有约定：成功提交、异常回滚）；
测试用 ``monkeypatch.setattr(router_module, "_connection", ...)`` 指向隔离 schema。
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import (auth, chat, clock, config_source, errors, facts, features, models, providers,
               quota, ratelimit, validation)

log = logging.getLogger("djb.gateway.http")

router = APIRouter(tags=["gateway"])

ClientIpResolver = Callable[[Request], "str | None"]

_client_ip_resolver: ClientIpResolver | None = None


def set_client_ip_resolver(resolver: ClientIpResolver | None) -> None:
    """注入客户端 IP 解析（只有部署层确认了受信代理才应注入 ``X-Forwarded-For`` 解析）。"""
    global _client_ip_resolver
    _client_ip_resolver = resolver


def _connection() -> Any:
    """请求级连接（app.db 的既有约定：成功提交、异常回滚）。"""
    from app.db import conn as db_conn                       # 基础设施，非业务模块

    return db_conn()


# --------------------------------------------------------------------------- 信封
def _request_id(request: Request) -> str:
    """``X-Request-Id`` 归一：合法 UUID 原样回显，否则服务端生成（见 models.parse_request_id）。"""
    return models.parse_request_id(request.headers.get(facts.REQUEST_ID_HEADER),
                                   now=clock.utcnow())


def _trace_id(request: Request, request_id: str) -> str:
    """trace 优先取 ``X-DJB-Trace-Id``（内部链路），缺省与 request_id 同值。"""
    trace = (request.headers.get("X-DJB-Trace-Id") or "").strip()
    return trace[:128] if trace else request_id


def _client_ip(request: Request) -> str | None:
    if _client_ip_resolver is not None:
        try:
            return _client_ip_resolver(request)
        except Exception:                                    # pragma: no cover - 防御
            log.warning("gateway.http.ip_resolver_failed")
    return getattr(getattr(request, "client", None), "host", None)


def _headers(request_id: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    merged = {facts.REQUEST_ID_HEADER: request_id}
    if extra:
        merged.update({key: value for key, value in extra.items() if value})
    return merged


def _ok(payload: dict[str, Any], request_id: str, *, status_code: int = 200,
        extra: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code,
                        headers=_headers(request_id, extra))


def _fail(exc: errors.GatewayError, request_id: str) -> JSONResponse:
    headers = _headers(request_id, dict(exc.headers))
    if exc.retry_after_s is not None and facts.RETRY_AFTER_HEADER not in headers:
        headers[facts.RETRY_AFTER_HEADER] = str(int(exc.retry_after_s))
    return JSONResponse(errors.error_body(exc, request_id), status_code=exc.http_status,
                        headers=headers)


def _unexpected(request_id: str, exc: BaseException) -> JSONResponse:
    log.exception("gateway.http.unexpected", extra={"request_id": request_id})
    return _fail(errors.server_error(request_id, detail=type(exc).__name__), request_id)


def _idempotency_key(request: Request) -> str | None:
    from . import idempotency

    return idempotency.require_key(request.headers.get(facts.IDEMPOTENCY_HEADER))


def _precheck_limit(principal: models.Principal, *, now: Any,
                    limiter: ratelimit.SlidingWindowLimiter | None = None) -> Any:
    """鉴权之后的限流 / 每日上限前置检查（``/v1/models`` 也走同一口径）。"""
    state = quota.from_snapshot(dict(principal.quotas or {}))
    quota.assert_daily_cap(state)
    config_values = config_source.snapshot()
    limit_value = quota.effective_qps(state.qps, config_values.get("rate_limit_qps"))
    scope = (f"key:{principal.api_key_id}" if principal.api_key_id is not None
             else f"tenant:{principal.tenant_id}")
    bucket = limiter or ratelimit.LIMITER
    decision = bucket.take(scope, limit_value, now=now)
    ratelimit.enforce([decision], now=now)
    return decision


# --------------------------------------------------------------------------- 对话
@router.post("/v1/chat/completions")
async def create_chat_completion(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    trace_id = _trace_id(request, request_id)
    moment = clock.utcnow()
    try:
        principal = auth.principal_from_headers(dict(request.headers), now=moment,
                                               client_ip=_client_ip(request),
                                               trace_id=trace_id)
        raw = await request.body()
        declared = validation.parse_content_length(request.headers.get("content-length"))
        body = validation.read_body(raw, declared_length=declared)
        key = _idempotency_key(request)
        with _connection() as c:
            outcome = chat.complete(c, principal=principal, body=body, request_id=request_id,
                                    trace_id=trace_id, idempotency_key=key,
                                    client_ip=_client_ip(request), now=moment)
        return _ok(outcome.payload, request_id, status_code=outcome.status_code,
                   extra=outcome.headers)
    except errors.GatewayError as exc:
        return _fail(exc, request_id)
    except Exception as exc:                                 # pragma: no cover - 防御
        return _unexpected(request_id, exc)


# --------------------------------------------------------------------------- 模型清单
@router.get("/v1/models")
def list_models(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    trace_id = _trace_id(request, request_id)
    moment = clock.utcnow()
    try:
        principal = auth.principal_from_headers(dict(request.headers), now=moment,
                                               client_ip=_client_ip(request),
                                               trace_id=trace_id)
        limit_decision = _precheck_limit(principal, now=moment)
        items = providers.list_models()
        payload = {"object": "list", "data": [_model_payload(item) for item in items]}
        return _ok(payload, request_id, extra=limit_decision.headers())
    except errors.GatewayError as exc:
        return _fail(exc, request_id)
    except Exception as exc:                                 # pragma: no cover - 防御
        return _unexpected(request_id, exc)


_MODEL_FIELDS = ("id", "object", "created", "owned_by", "context_window", "unit", "price")


def _model_payload(item: dict[str, Any]) -> dict[str, Any]:
    """spec ``Model``：``id`` / ``object`` / ``owned_by`` 必填；其余只加不改。"""
    payload: dict[str, Any] = {"id": str(item.get("id") or item.get("slug") or ""),
                               "object": "model",
                               "owned_by": str(item.get("owned_by") or "djb")}
    for field_name in _MODEL_FIELDS:
        if field_name in {"id", "object", "owned_by"}:
            continue
        if item.get(field_name) is not None:
            payload[field_name] = item[field_name]
    return payload


def health() -> dict[str, Any]:
    """接线自检（合并时给运维 / 证据用；不暴露 provider 本体）。"""
    return {"module": "M03", "protocol_version": facts.PROTOCOL_VERSION_CURRENT,
            "providers": providers.current(),
            "config": config_source.snapshot(),
            "features": {switch.name: switch.default for switch in features.switches()},
            "request_id": str(uuid.uuid4())}
