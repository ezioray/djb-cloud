# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12 HTTP 路由工厂（独立模块，**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 spec 1.2.3 里 M12 的七条操作::

    GET    /api/v1/user/notifications                     listNotifications          200
    POST   /api/v1/user/notifications/{id}/read           markNotificationRead       200 / 404
    GET    /api/v1/user/notifications/preferences         getNotificationPreferences 200
    PUT    /api/v1/user/notifications/preferences         updateNotificationPreferences 200 / 409
    GET    /api/v1/user/webhooks                          listWebhookSubscriptions   200
    POST   /api/v1/user/webhooks                          createWebhookSubscription  201 / 409
    DELETE /api/v1/user/webhooks/{id}                     deleteWebhookSubscription  204

约定（00-conventions §5 / spec ``Error``）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
  任何响应都回显 ``X-Request-Id``；
* 请求体自己校验（不依赖框架 422）：不合法一律 400 / 40001；P0 退订 409 / 40902；
* **两个依赖注入钩子**（默认 fail-closed，合并时由 Lead 接线）::

    create_router(connection_factory=..., principal_resolver=...)

  - ``principal_resolver(request) -> {"account_id": ...}``：未接线一律 401 / 40101；
  - ``connection_factory() -> ContextManager[Connection]``：未接线一律 503 / 50001；
* 账户一律从**主体**取，绝不从请求体 / 查询串取（防越权）；SQL 再按 account_id 过滤。
"""
from __future__ import annotations

import inspect
import json
import logging
import uuid
from typing import Any, Awaitable, Callable, Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from . import clock, config_source, errors, inbox, preferences, webhooks

log = logging.getLogger("djb.notify.http")

Principal = Callable[[Request], "Mapping[str, Any] | Awaitable[Mapping[str, Any]]"]
ConnectionFactory = Callable[[], Any]

MAX_BODY_BYTES = 64 * 1024
IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
IDEMPOTENCY_MIN_LENGTH = 16                       # spec IdempotencyKey.minLength
IDEMPOTENCY_MAX_LENGTH = 128                      # spec IdempotencyKey.maxLength


def create_router(*, connection_factory: ConnectionFactory | None = None,
                  principal_resolver: Principal | None = None,
                  config_provider: Callable[[], config_source.NotifyConfig] | None = None,
                  now_provider: Callable[[], Any] | None = None) -> APIRouter:
    """构造本模块路由（每个应用一个实例；依赖全部由调用方注入）。"""
    router = APIRouter(prefix="/api/v1", tags=["notify"])

    def _now() -> Any:
        return now_provider() if now_provider is not None else clock.now()

    def _config() -> config_source.NotifyConfig:
        return config_provider() if config_provider is not None else config_source.snapshot()

    def _connect() -> Any:
        if connection_factory is None:
            raise errors.StoreUnavailable("数据库连接未接线：合并时由 Lead 注入（fail-closed）")
        return connection_factory()

    async def _principal(request: Request) -> uuid.UUID:
        if principal_resolver is None:
            raise errors.AuthUnavailable("鉴权未接线：合并时由 Lead 注入（fail-closed）")
        resolved = principal_resolver(request)
        if inspect.isawaitable(resolved):
            resolved = await resolved
        if not isinstance(resolved, Mapping):
            raise errors.AuthUnavailable("鉴权返回非法主体")
        raw = resolved.get("account_id") or resolved.get("sub") or resolved.get("id")
        if not raw:
            raise errors.Unauthorized("主体缺少 account_id")
        try:
            return uuid.UUID(str(raw))
        except (TypeError, ValueError) as exc:
            raise errors.Unauthorized("主体 account_id 非法") from exc

    # ---------------------------------------------------------------- 站内信：列表
    @router.get("/user/notifications")
    async def list_notifications(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            params = request.query_params
            with _connect() as conn:
                payload = inbox.list_page(
                    conn, account_id, level=params.get("level"),
                    unread_only=params.get("unread_only"),
                    limit=params.get("limit"), cursor=params.get("cursor"))
            return _ok(payload, request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.http.list_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 站内信：已读
    @router.post("/user/notifications/{id}/read")
    async def mark_notification_read(id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            with _connect() as conn:
                ack = inbox.mark_read(conn, account_id, id, now=_now())
            return _ok(ack, request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.http.read_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 偏好：读
    @router.get("/user/notifications/preferences")
    async def get_notification_preferences(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            with _connect() as conn:
                pref = preferences.get(conn, account_id)
            return _ok(pref.to_api(), request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.http.preferences_get_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 偏好：写
    @router.put("/user/notifications/preferences")
    async def update_notification_preferences(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            _idempotency_key(request)                 # PUT 本身幂等；这里只校验键形态
            body = await _body(request)
            with _connect() as conn:
                pref = preferences.put(conn, account_id, body, now=_now())
            return _ok(pref.to_api(), request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.http.preferences_put_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- Webhook：列表
    @router.get("/user/webhooks")
    async def list_webhook_subscriptions(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            params = request.query_params
            with _connect() as conn:
                payload = webhooks.list_page(conn, account_id, limit=params.get("limit"),
                                             cursor=params.get("cursor"))
            return _ok(payload, request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.http.webhooks_list_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- Webhook：创建
    @router.post("/user/webhooks")
    async def create_webhook_subscription(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            body = await _body(request)
            if not isinstance(body, Mapping):
                raise errors.InvalidArgument("请求体必须是 JSON 对象")
            unknown = set(body) - {"url", "events", "description"}
            if unknown:                                  # spec additionalProperties: false
                raise errors.InvalidArgument(f"请求体含未知字段：{sorted(unknown)}")
            with _connect() as conn:
                subscription, secret = webhooks.create(
                    conn, account_id=account_id, url=body.get("url"),
                    events=body.get("events"), description=body.get("description"),
                    idempotency_key=_idempotency_key(request),
                    config=_config(), now=_now())
            payload = dict(subscription.to_api())
            payload["secret"] = secret                     # INV-05：只在此处返回一次
            return _ok(payload, request_id, status_code=201)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.http.webhooks_create_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- Webhook：删除
    @router.delete("/user/webhooks/{id}")
    async def delete_webhook_subscription(id: str, request: Request) -> Response:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            try:
                target = uuid.UUID(id)
            except (TypeError, ValueError) as exc:
                raise errors.NotFound("订阅不存在") from exc
            with _connect() as conn:
                webhooks.delete(conn, account_id, target)   # 幂等：不存在也 204
            return Response(status_code=204, headers={"X-Request-Id": request_id})
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.http.webhooks_delete_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    return router


# --------------------------------------------------------------------------- 信封工具
def _idempotency_key(request: Request) -> str | None:
    """校验 ``X-DJB-Idempotency-Key`` 形态（spec minLength 16 / maxLength 128）。"""
    raw = request.headers.get(IDEMPOTENCY_HEADER)
    if raw in (None, ""):
        return None
    key = raw.strip()
    if not IDEMPOTENCY_MIN_LENGTH <= len(key) <= IDEMPOTENCY_MAX_LENGTH:
        raise errors.InvalidArgument(
            f"幂等键长度必须 {IDEMPOTENCY_MIN_LENGTH}–{IDEMPOTENCY_MAX_LENGTH}",
            field=IDEMPOTENCY_HEADER)
    return key


def _request_id(request: Request) -> str:
    return (request.headers.get("X-Request-Id") or "").strip() or uuid.uuid4().hex


def _headers(request_id: str) -> dict[str, str]:
    return {"X-Request-Id": request_id}


def _ok(payload: Mapping[str, Any], request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(dict(payload), status_code=status_code,
                        headers=_headers(request_id))


def _fail(exc: errors.NotifyError, request_id: str) -> JSONResponse:
    body = {"error": {"type": errors.error_type_for(exc.status_code),
                      "code": int(exc.code), "message": exc.message,
                      "request_id": request_id, "reason": exc.reason,
                      **{key: value for key, value in exc.details.items()
                         if key not in {"reason", "message"}}}}
    return JSONResponse(body, status_code=exc.status_code, headers=_headers(request_id))


def _server_error(request_id: str) -> JSONResponse:
    exc = errors.StoreUnavailable("服务暂时不可用，请稍后重试")
    return _fail(exc, request_id)


async def _body(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        raise errors.InvalidArgument("请求体必填")
    if len(raw) > MAX_BODY_BYTES:
        raise errors.InvalidArgument("请求体过大")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise errors.InvalidArgument("请求体必须是合法 JSON") from exc


__all__ = ["create_router", "Principal", "ConnectionFactory"]
