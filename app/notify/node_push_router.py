# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12a 节点通知 HTTP 路由（**不接 app/api.py** —— 由 Lead 合并时 include）。

覆盖 **C15 的六条操作**（spec 1.2.13 由 Lead 登记）::

    GET  /api/v1/node/notifications                  pullNodeNotifications      200
    POST /api/v1/node/notifications/{id}/ack          ackNodeNotification       200 / 404
    POST /api/v1/node/notifications/{id}/read         readNodeNotification      200 / 404
    GET  /api/v1/node/notifications/unread_count      nodeNotificationUnread    200
    POST /api/v1/admin/notifications/node             enqueueNodeNotification   201 / 503
    GET  /api/v1/admin/notifications/node             listNodeNotifications     200

约定（与 :mod:`app.notify.router` 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
  任何响应都回显 ``X-Request-Id``；
* **两个鉴权注入**（默认 fail-closed，合并时由 Lead 接线）::

    create_router(connection_factory=..., node_auth=..., admin_auth=...)

  - ``node_auth(request) -> {"node_id": ...}``：节点身份（M02 节点令牌 / mTLS 映射）；
  - ``admin_auth(request) -> {"actor": ...}``：运营面主体（M01 会话 / 服务令牌）；
  - 未接线 → 401 / ``40101``；连接未接线 → 503 / ``50001``。
* 节点身份**只从主体取**，绝不从查询串 / 请求体取（防跨节点越权）；SQL 再按 node_id 过滤。
* 开关关闭时：``pull`` / ``enqueue`` 返回 503 / ``50001``（投递面 fail-closed），
  ``ack`` / ``read`` / ``unread_count`` / 管理面列表仍可用（回滚时存量可确认/可查）。
"""
from __future__ import annotations

import inspect
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable, Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import clock, errors, node_push

log = logging.getLogger("djb.notify.node_push_http")

__all__ = ["create_router"]

Principal = Callable[[Request], "Mapping[str, Any] | Awaitable[Mapping[str, Any]]"]
ConnectionFactory = Callable[[], Any]

MAX_BODY_BYTES = 64 * 1024


def create_router(*, connection_factory: ConnectionFactory | None = None,
                  node_auth: Principal | None = None,
                  admin_auth: Principal | None = None,
                  now_provider: Callable[[], Any] | None = None) -> APIRouter:
    """构造节点通知路由（依赖全部由调用方注入；默认 fail-closed）。"""
    router = APIRouter(prefix="/api/v1", tags=["node-push"])

    def _now() -> Any:
        return now_provider() if now_provider is not None else clock.now()

    def _connect() -> Any:
        if connection_factory is None:
            raise errors.StoreUnavailable("数据库连接未接线：合并时由 Lead 注入（fail-closed）")
        return connection_factory()

    async def _principal(request: Request, resolver: Principal | None, *,
                         field: str) -> Mapping[str, Any]:
        if resolver is None:
            raise errors.AuthUnavailable("鉴权未接线：合并时由 Lead 注入（fail-closed）")
        resolved = resolver(request)
        if inspect.isawaitable(resolved):
            resolved = await resolved
        if not isinstance(resolved, Mapping):
            raise errors.AuthUnavailable("鉴权返回非法主体")
        if not resolved.get(field):
            raise errors.Unauthorized(f"主体缺少 {field}")
        return resolved

    async def _node(request: Request) -> str:
        principal = await _principal(request, node_auth, field="node_id")
        return str(principal["node_id"])

    async def _admin(request: Request) -> Mapping[str, Any]:
        return await _principal(request, admin_auth,
                                field="actor" if admin_auth is not None else "node_id")

    # ---------------------------------------------------------------- 节点：拉取
    @router.get("/node/notifications")
    async def pull_node_notifications(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            node_id = await _node(request)
            params = request.query_params
            with _connect() as conn:
                payload = node_push.pull(conn, node_id, since=params.get("since"),
                                         limit=params.get("limit"),
                                         category=params.get("category"), now=_now())
            return _ok(payload, request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.node_push.pull_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 节点：未读数
    @router.get("/node/notifications/unread_count")
    async def node_notification_unread_count(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            node_id = await _node(request)
            with _connect() as conn:
                unread = node_push.unread_count(conn, node_id, now=_now())
            return _ok({"unread": unread}, request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.node_push.unread_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 节点：ack
    @router.post("/node/notifications/{notification_id}/ack")
    async def ack_node_notification(notification_id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            node_id = await _node(request)
            with _connect() as conn:
                payload = node_push.ack(conn, node_id, notification_id, now=_now())
            return _ok(payload, request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.node_push.ack_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 节点：read
    @router.post("/node/notifications/{notification_id}/read")
    async def read_node_notification(notification_id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            node_id = await _node(request)
            with _connect() as conn:
                payload = node_push.read(conn, node_id, notification_id, now=_now())
            return _ok(payload, request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.node_push.read_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 运营：入队
    @router.post("/admin/notifications/node")
    async def enqueue_node_notification(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            await _admin(request)
            body = await _body(request)
            if not isinstance(body, Mapping):
                raise errors.InvalidArgument("请求体必须是 JSON 对象")
            allowed = {"node_id", "severity", "category", "template_key", "payload",
                       "dedupe_key", "source_event_id", "expires_at"}
            unknown = set(body) - allowed
            if unknown:
                raise errors.InvalidArgument(f"请求体含未知字段：{sorted(unknown)}")
            with _connect() as conn:
                notification = node_push.enqueue(
                    conn, body.get("node_id"), body.get("severity"), body.get("category"),
                    body.get("template_key"), body.get("payload"),
                    dedupe_key=body.get("dedupe_key"),
                    source_event_id=body.get("source_event_id"), now=_now(),
                    expires_at=_parse_time(body.get("expires_at")))
            return _ok(notification, request_id, status_code=201)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.node_push.enqueue_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 运营：列表
    @router.get("/admin/notifications/node")
    async def list_node_notifications(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            await _admin(request)
            params = request.query_params
            with _connect() as conn:
                payload = node_push.list_for_admin(
                    conn, node_id=params.get("node_id"), state=params.get("state"),
                    limit=params.get("limit"), cursor=params.get("cursor"), now=_now())
            return _ok(payload, request_id)
        except errors.NotifyError as exc:
            return _fail(exc, request_id)
        except Exception:                                  # pragma: no cover - 防御
            log.exception("notify.node_push.admin_list_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    return router


# --------------------------------------------------------------------------- 辅助
def _request_id(request: Request) -> str:
    return (request.headers.get("X-Request-Id") or "").strip() or uuid.uuid4().hex


def _headers(request_id: str) -> dict[str, str]:
    return {"X-Request-Id": request_id}


def _ok(payload: Mapping[str, Any], request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(dict(payload), status_code=status_code, headers=_headers(request_id))


def _fail(exc: errors.NotifyError, request_id: str) -> JSONResponse:
    body = {"error": {"type": errors.error_type_for(exc.status_code), "code": int(exc.code),
                      "message": exc.message, "request_id": request_id, "reason": exc.reason,
                      **{key: value for key, value in exc.details.items()
                         if key not in {"reason", "message"}}}}
    return JSONResponse(body, status_code=exc.status_code, headers=_headers(request_id))


def _server_error(request_id: str) -> JSONResponse:
    return _fail(errors.StoreUnavailable("服务暂时不可用，请稍后重试"), request_id)


async def _body(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        raise errors.InvalidArgument("请求体必填")
    if len(raw) > MAX_BODY_BYTES:
        raise errors.InvalidArgument("请求体过大")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise errors.InvalidArgument("请求体不是合法 JSON") from exc


def _parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument("expires_at 必须是 RFC 3339 时间", field="expires_at") from exc
