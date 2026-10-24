# SPDX-License-Identifier: AGPL-3.0-or-later
"""M03 T1–T4 HTTP 路由（独立模块，**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 spec 1.2.x 里本模块的全部五个操作::

    POST /v1/chat/completions        createChatCompletion   200（JSON）/ 200（SSE）
    GET  /v1/models                  listModels             200
    POST /v1/batches                 createBatch            202
    GET  /v1/batches/{id}            getBatch               200
    POST /v1/batches/{id}/cancel     cancelBatch            200

约定（00-conventions §5 / spec ``Error``）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**，
  ``type`` 取 spec 枚举；**任何响应**（含错误、含 SSE 建立前的失败）都回显 ``X-Request-Id``；
* 429 / 503 带 ``Retry-After``；429 另带 ``X-DJB-RateLimit-*`` 三件套；
* 请求体自己校验（不依赖框架 422）：不合法一律 400 / 40001，超上限 413 / 40013；
* 幂等：所有写端点走 :class:`app.gateway.idempotency.WriteGuard`（CR-10 规则）；
* 协议版本：``DJB-Protocol-Version`` 不兼容在严格模式下 426 / 42601（闸门默认关）；
  ``DJB-Capabilities`` 未知值忽略不报错。

认证与依赖注入（默认 **fail-closed**，合并时由 Lead 接线，见 ``WIRING.md``）::

    providers.set_auth_provider / set_route_provider / set_node_client / set_stream_client /
    set_usage_provider / set_model_catalog_provider / set_webhook_sender /
    set_webhook_secret_provider / set_result_signer
    config_source.set_provider

数据库连接经 :func:`_connection`（``app.db`` 既有约定：成功提交、异常回滚）；
测试用 ``monkeypatch.setattr(router_module, "_connection", ...)`` 指向隔离 schema。
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

from . import (auth, batches, chat, clock, config_source, errors, facts, features, models,
               protocol, providers, ratelimit, stream, validation)

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


# --------------------------------------------------------------------------- 公共前置
def _protocol_info(request: Request) -> protocol.ProtocolInfo:
    """协议版本判定（不兼容 + 严格模式 → 426 / 42601）；未知 capability 忽略。"""
    info = protocol.check(request.headers.get(facts.PROTOCOL_VERSION_HEADER))
    protocol.enabled_set(request.headers.get(facts.CAPABILITIES_HEADER))
    return info


def _authorize(request: Request, request_id: str, trace_id: str, moment: Any
               ) -> tuple[models.Principal, dict[str, str]]:
    """鉴权 + 协议版本；返回 ``(principal, 额外响应头)``。"""
    principal = auth.principal_from_headers(dict(request.headers), now=moment,
                                            client_ip=_client_ip(request), trace_id=trace_id)
    info = _protocol_info(request)
    return principal, protocol.response_headers(info)


def _precheck_limit(principal: models.Principal, *, now: Any,
                    limiter: ratelimit.SlidingWindowLimiter | None = None) -> Any:
    """鉴权之后的限流 / 每日上限前置检查（``/v1/models`` 与批次读端点用）。"""
    decision, _state, _limit = ratelimit.precheck(principal, now=now, bucket=limiter)
    return decision


# --------------------------------------------------------------------------- 对话
@router.post("/v1/chat/completions")
async def create_chat_completion(request: Request) -> Any:
    request_id = _request_id(request)
    trace_id = _trace_id(request, request_id)
    moment = clock.utcnow()
    try:
        principal, extra_headers = _authorize(request, request_id, trace_id, moment)
        raw = await request.body()
        declared = validation.parse_content_length(request.headers.get("content-length"))
        body = validation.read_body(raw, declared_length=declared,
                                    max_bytes=facts.CHAT_BODY_MAX_BYTES)
        key = _idempotency_key(request)
        if body.get("stream") is True:
            with _connection() as c:
                plan = stream.prepare(c, principal=principal, body=body, request_id=request_id,
                                      trace_id=trace_id, idempotency_key=key, now=moment,
                                      connection_factory=_connection)
            headers = _headers(request_id, {**extra_headers, **plan.limit_headers,
                                            "Cache-Control": "no-cache",
                                            "X-Accel-Buffering": "no"})
            return StreamingResponse(plan.frames(), media_type=facts.SSE_MEDIA_TYPE,
                                     headers=headers)
        with _connection() as c:
            outcome = chat.complete(c, principal=principal, body=body, request_id=request_id,
                                    trace_id=trace_id, idempotency_key=key,
                                    client_ip=_client_ip(request), now=moment)
        return _ok(outcome.payload, request_id, status_code=outcome.status_code,
                   extra={**extra_headers, **outcome.headers})
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
        principal, extra_headers = _authorize(request, request_id, trace_id, moment)
        limit_decision = _precheck_limit(principal, now=moment)
        items = providers.list_models()
        payload = {"object": "list", "data": [_model_payload(item) for item in items]}
        return _ok(payload, request_id, extra={**extra_headers, **limit_decision.headers()})
    except errors.GatewayError as exc:
        return _fail(exc, request_id)
    except Exception as exc:                                 # pragma: no cover - 防御
        return _unexpected(request_id, exc)


_MODEL_FIELDS = ("id", "object", "created", "owned_by", "context_window", "unit", "price",
                   "available", "probe")


def _model_payload(item: dict[str, Any]) -> dict[str, Any]:
    """spec ``Model``：``id`` / ``object`` / ``owned_by`` 必填；其余只加不改。

    ``price_version`` 是 spec 1.2.6 的**可选**字段（string|null）：有快照版本就带上，
    没有就缺省——公开侧 / 降级镜像允许不返回，客户端不得据此推断结算价。
    """
    payload: dict[str, Any] = {"id": str(item.get("id") or item.get("slug") or ""),
                               "object": "model",
                               "owned_by": str(item.get("owned_by") or "djb")}
    for field_name in _MODEL_FIELDS:
        if field_name in {"id", "object", "owned_by"}:
            continue
        if item.get(field_name) is not None:
            payload[field_name] = item[field_name]
    version = _price_version(item)
    if version is not None:
        payload["price_version"] = version
    return payload


def _price_version(item: Mapping[str, Any]) -> str | None:
    """价格快照版本（M04 ``model_catalog.price_version`` / 嵌套 ``price.price_version``）。

    宽容读取（INV-M03-07）：扁平字段优先，其次嵌套 ``price``；非字符串 / 空串一律不回
    （不猜、不把内部对象序列化进响应）。
    """
    value = item.get("price_version")
    if value is None:
        price = item.get("price")
        if isinstance(price, Mapping):
            value = price.get("price_version")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


# --------------------------------------------------------------------------- 慢任务
@router.post("/v1/batches")
async def create_batch(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    trace_id = _trace_id(request, request_id)
    moment = clock.utcnow()
    try:
        principal, extra_headers = _authorize(request, request_id, trace_id, moment)
        raw = await request.body()
        declared = validation.parse_content_length(request.headers.get("content-length"))
        body = validation.read_body(raw, declared_length=declared,
                                    max_bytes=facts.BATCH_BODY_MAX_BYTES)
        key = _idempotency_key(request)
        with _connection() as c:
            result = batches.submit(c, principal=principal, body=body, request_id=request_id,
                                    trace_id=trace_id, idempotency_key=key, now=moment)
        return _ok(result.payload, request_id, status_code=result.status_code,
                   extra={**extra_headers, **result.headers})
    except errors.GatewayError as exc:
        return _fail(exc, request_id)
    except Exception as exc:                                 # pragma: no cover - 防御
        return _unexpected(request_id, exc)


@router.get("/v1/batches/{id}")
def get_batch(id: str, request: Request) -> JSONResponse:   # noqa: A002 - 路径参数名必须与 spec 一致
    request_id = _request_id(request)
    trace_id = _trace_id(request, request_id)
    moment = clock.utcnow()
    try:
        principal, extra_headers = _authorize(request, request_id, trace_id, moment)
        _precheck_limit(principal, now=moment)
        with _connection() as c:
            payload = batches.get(c, principal=principal, batch_id=id, now=moment)
        return _ok(payload, request_id, extra=extra_headers)
    except errors.GatewayError as exc:
        return _fail(exc, request_id)
    except Exception as exc:                                 # pragma: no cover - 防御
        return _unexpected(request_id, exc)


@router.post("/v1/batches/{id}/cancel")
def cancel_batch(id: str, request: Request) -> JSONResponse:   # noqa: A002
    request_id = _request_id(request)
    trace_id = _trace_id(request, request_id)
    moment = clock.utcnow()
    try:
        principal, extra_headers = _authorize(request, request_id, trace_id, moment)
        _precheck_limit(principal, now=moment)
        key = _idempotency_key(request)
        with _connection() as c:
            payload = batches.cancel(c, principal=principal, batch_id=id, now=moment,
                                     idempotency_key=key)
        return _ok(payload, request_id, extra=extra_headers)
    except errors.GatewayError as exc:
        return _fail(exc, request_id)
    except Exception as exc:                                 # pragma: no cover - 防御
        return _unexpected(request_id, exc)


# --------------------------------------------------------------------------- 健康 / 接线自检
def health() -> dict[str, Any]:
    """接线自检（合并时给运维 / 证据用；不暴露 provider 本体）。"""
    return {"module": "M03", "protocol_version": facts.PROTOCOL_VERSION_CURRENT,
            "providers": providers.current(),
            "config": config_source.snapshot(),
            "features": {switch.name: switch.default for switch in features.switches()},
            "request_id": str(uuid.uuid4())}
