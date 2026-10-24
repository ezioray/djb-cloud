# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 冻结段管理面路由（**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 C14 的 4 条管理面操作（spec 1.2.10 由 Lead 后续登记；本卡不改 spec）::

    GET  /api/v1/admin/supply/integrity/holds                       listIntegrityHolds   200 / 400 / 401 / 403
    GET  /api/v1/admin/supply/integrity/holds/{id}                  getIntegrityHold     200 / 401 / 403 / 404
    POST /api/v1/admin/supply/integrity/holds                       createIntegrityHold  201/200 / 400 / 401 / 403 / 409 / 503
    POST /api/v1/admin/supply/integrity/holds/{id}/release          releaseIntegrityHold 200 / 400 / 401 / 403 / 404 / 409 / 503

约定（与 M02/M05/M11 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``；``code`` 是整数（40001 / 40101 /
  40301 / 40401 / 40919 / 503+50001）；任何响应都回显 ``X-Request-Id``；
* 请求体自己校验（不用框架 422）：不合法一律 400 / 40001；
* 鉴权走 :func:`set_admin_authenticator` 注入钩子，**默认 fail-closed**（未接线即 401），
  合并时由 Lead 注入 M01 管理面主体（含 ``admin_id`` / ``scopes``）；
* scope：读 ``integrity.read``、写 ``integrity.write``；I3/I4 解除额外要求
  ``integrity:release:high``（由 ``holds.release`` 校验，越权 → 403）；
* **不碰账本**：本路由只调 ``app.integrity.holds``，不存在任何 ledger 写路径；
* 开关 ``supply.freeze.enabled`` 关闭时：写接口 503 / 50001 + ``reason=feature_disabled``
  （fail-closed，不静默放行）；读接口保持只读可用（rollback_rule：已有冻结保留可查）。
"""
from __future__ import annotations

import inspect
import logging
import uuid
from typing import Any, Awaitable, Callable, Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import clock, facts, holds, models
from .errors import (BadRequest, Forbidden, IntegrityError, NotFound, ServerError,
                     Unauthorized)

log = logging.getLogger("djb.integrity.http")

router = APIRouter(prefix="/api/v1/admin/supply/integrity", tags=["admin"])

REQUEST_ID_HEADER = "X-Request-Id"
MAX_BODY_BYTES = 64 * 1024

AdminAuthenticator = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
_admin_authenticator: AdminAuthenticator | None = None


# ───────────────────────────────────────────────────────── 接线钩子
def set_admin_authenticator(authenticator: AdminAuthenticator | None) -> None:
    """注入管理面鉴权（合并时由 Lead 接 M01）。传 ``None`` 恢复 fail-closed。"""
    global _admin_authenticator
    _admin_authenticator = authenticator


def admin_authenticator() -> AdminAuthenticator | None:
    return _admin_authenticator


def _connection() -> Any:
    """请求级连接（app.db 既有约定：成功提交、异常回滚）。测试 monkeypatch 到隔离 schema。"""
    from app.db import conn as db_conn                        # 基础设施，非业务模块

    return db_conn()                                          # pragma: no cover - 部署期接线


# ───────────────────────────────────────────────────────── 信封工具
def _request_id(request: Request) -> str:
    provided = (request.headers.get(REQUEST_ID_HEADER) or "").strip()
    return provided[:64] if provided else uuid.uuid4().hex


def _ok(payload: Any, request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code,
                        headers={REQUEST_ID_HEADER: request_id})


def _fail(exc: IntegrityError, request_id: str) -> JSONResponse:
    return JSONResponse(exc.as_envelope(request_id), status_code=exc.status_code,
                        headers={REQUEST_ID_HEADER: request_id})


def _server_error(request_id: str) -> JSONResponse:
    exc = ServerError("内部错误：请用 request_id 联系运维", reason="server_error")
    return _fail(exc, request_id)


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise BadRequest("请求体超过上限", field="body")
    if not raw:
        return {}
    import json

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BadRequest("请求体必须是合法 JSON", field="body") from exc
    if not isinstance(payload, dict):
        raise BadRequest("请求体必须是 JSON 对象", field="body")
    return payload


# ───────────────────────────────────────────────────────── 鉴权 / scope
def _scopes_of(principal: Mapping[str, Any]) -> set[str]:
    raw = principal.get("scopes")
    if raw is None:
        return set()
    if isinstance(raw, str):
        return {item.strip() for item in raw.split(",") if item.strip()}
    if isinstance(raw, (list, tuple, set, frozenset)):
        return {str(item) for item in raw}
    return set()


def _require_scope(principal: Mapping[str, Any], scope: str) -> None:
    scopes = _scopes_of(principal)
    if facts.WILDCARD_SCOPE in scopes or scope in scopes:
        return
    raise Forbidden(f"缺少 scope：{scope}", reason="forbidden")


async def _principal(request: Request, *, scope: str) -> dict[str, Any]:
    """fail-closed 主体解析：未接线 / 非法主体 → 401；缺 scope → 403。"""
    if _admin_authenticator is None:
        raise Unauthorized(
            "M17 管理面鉴权未接线：合并时由 Lead 注入（fail-closed）", reason="unauthorized")
    resolved = _admin_authenticator(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, Mapping) or not resolved.get("admin_id"):
        raise Unauthorized("鉴权返回非法主体", reason="unauthorized")
    principal = dict(resolved)
    _require_scope(principal, scope)
    return principal


def _actor(principal: Mapping[str, Any]) -> str:
    return str(principal.get("admin_id"))


# ───────────────────────────────────────────────────────── 路由
@router.get("/holds", operation_id="listIntegrityHolds",
            summary="待分润冻结列表（active/all + 节点/模型/等级过滤 + 游标分页）")
async def list_integrity_holds(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_READ)
        params = request.query_params
        state = params.get("state") or "active"
        node_id = params.get("node_id")
        model = params.get("model")
        level = params.get("level")
        limit = params.get("limit")
        cursor = params.get("cursor")

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return holds.list_holds(conn, state=state, node_id=node_id, model=model,
                                        level=level, limit=limit, cursor=cursor,
                                        now=clock.utcnow())

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.holds.list_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.get("/holds/{hold_id}", operation_id="getIntegrityHold",
            summary="冻结详情（含事件流水，便于复核）")
async def get_integrity_hold(request: Request, hold_id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_READ)
        identifier = models.parse_hold_id(hold_id)

        def _run() -> dict[str, Any] | None:
            with _connection() as conn:
                payload = holds.get_hold(conn, identifier)
                if payload is None:
                    return None
                return {"hold": payload, "events": holds.list_events(conn, identifier)}

        payload = await run_in_threadpool(_run)
        if payload is None:
            raise NotFound("冻结记录不存在", reason="not_found")
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.holds.get_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/holds", operation_id="createIntegrityHold",
             summary="创建 / 升级冻结（I0 只留事件；已有 active 只升不降）")
async def create_integrity_hold(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _principal(request, scope=facts.SCOPE_WRITE)
        body = await _body(request)
        actor = _actor(principal)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return holds.create_or_escalate(
                    conn, node_id=body.get("node_id"), model=body.get("model"),
                    level=body.get("level"), base_amount_micro=body.get("base_amount_micro"),
                    reason=body.get("reason"), evidence_ref=body.get("evidence_ref"),
                    actor=actor, now=clock.utcnow(),
                    upstream_id=body.get("upstream_id"))

        result = await run_in_threadpool(_run)
        status_code = 201 if result.get("action") == "created" else 200
        return _ok(result, request_id, status_code=status_code)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.holds.create_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/holds/{hold_id}/release", operation_id="releaseIntegrityHold",
             summary="解除冻结（I0/I1 一人；I2 双人；I3/I4 双人 + 高权限 scope）")
async def release_integrity_hold(request: Request, hold_id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _principal(request, scope=facts.SCOPE_WRITE)
        body = await _body(request)
        identifier = models.parse_hold_id(hold_id)
        actor = _actor(principal)
        reviewers = body.get("reviewers")
        reason = body.get("reason")
        scopes = _scopes_of(principal)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return holds.release(conn, identifier, reviewers=reviewers or [],
                                     reason=reason, actor=actor, now=clock.utcnow(),
                                     scopes=scopes)

        result = await run_in_threadpool(_run)
        return _ok(result, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.holds.release_failed request_id=%s", request_id)
        return _server_error(request_id)


__all__ = ["router", "set_admin_authenticator", "admin_authenticator"]
