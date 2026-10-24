# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 canary 管理面路由（C13；**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 5 条操作（spec 1.2.15 由 Lead 登记；本卡不改根 spec）::

    POST /api/v1/admin/supply/integrity/canary/runs               issueCanaryRun        201 / 400 / 401 / 403 / 409 / 503
    POST /api/v1/admin/supply/integrity/canary/runs/{id}/result   submitCanaryResult    200 / 400 / 401 / 403 / 404 / 409 / 503
    GET  /api/v1/admin/supply/integrity/canary/runs               listCanaryRuns        200 / 400 / 401 / 403
    GET  /api/v1/admin/supply/integrity/canary/stats              getCanaryStats        200 / 400 / 401 / 403
    POST /api/v1/admin/supply/integrity/canary/expire             expireCanaryRuns      200 / 401 / 403 / 503

响应形状（本卡定义，供 1.2.15 参考）：

* issue 201：``{run_id,node_id,upstream_id,model,prompt_key,prompt,nonce,max_tokens,
  issued_at,deadline_at,status}``（``prompt`` 为合成题面，可下发；响应正文永不入库）
* result 200：``{"run":{...}, "match":{passed,score,match,reason,response_hash}}``
* list 200：``{"items":[...], "has_more", "next_cursor"}``
* stats 200：``{node_id,model,window,total,passed,failed,missed,pass_rate}``
* expire 200：``{"runs": n}``

约定（与 M02/M05/M11/M17 其它段一致）：

* 错误信封 ``{"error": {type, code, message, request_id}}``；``code`` 整数
  （40001 / 40101 / 40301 / 40401 / 40919 / 503+50001）；任何响应回显 ``X-Request-Id``；
* 请求体自己校验（不用框架 422），不合法一律 400 / 40001；
* 鉴权走 :func:`set_admin_authenticator` 注入钩子，**默认 fail-closed**（未接线即 401）；
  scope：读 ``integrity.read``、写 ``integrity.write``；
* 开关 ``supply.canary.enabled`` 关闭时：写接口 503 / 50001 + ``reason=feature_disabled``，
  读接口只读可用（历史运行仍可统计）；
* **不落响应正文**：``response_text`` 只在请求体里用于比对，响应只回 hash；
* **不碰账本**：本路由只调 ``app.integrity.canary``，模块内不存在 ledger 写路径。
"""
from __future__ import annotations

import inspect
import json
import logging
import uuid
from typing import Any, Awaitable, Callable, Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import canary, clock, facts
from .errors import (BadRequest, Forbidden, IntegrityError, ServerError, Unauthorized)

log = logging.getLogger("djb.integrity.canary_http")

router = APIRouter(prefix="/api/v1/admin/supply/integrity/canary", tags=["admin"])

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
    return _fail(ServerError("内部错误：请用 request_id 联系运维", reason="server_error"),
                 request_id)


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise BadRequest("请求体超过上限", field="body")
    if not raw:
        return {}
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


async def _principal(request: Request, *, scope: str) -> dict[str, Any]:
    if _admin_authenticator is None:
        raise Unauthorized(
            "M17 canary 管理面鉴权未接线：合并时由 Lead 注入（fail-closed）",
            reason="unauthorized")
    resolved = _admin_authenticator(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, Mapping) or not resolved.get("admin_id"):
        raise Unauthorized("鉴权返回非法主体", reason="unauthorized")
    principal = dict(resolved)
    scopes = _scopes_of(principal)
    if facts.WILDCARD_SCOPE not in scopes and scope not in scopes:
        raise Forbidden(f"缺少 scope：{scope}", reason="forbidden")
    return principal


# ───────────────────────────────────────────────────────── 路由
@router.post("/runs", operation_id="issueCanaryRun",
             summary="发一条 canary（合成题面 + 120s deadline；同 node/model 只 1 条 issued）")
async def issue_canary_run(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_WRITE)
        body = await _body(request)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return canary.issue_run(conn, node_id=body.get("node_id"),
                                        model=body.get("model"),
                                        upstream_id=body.get("upstream_id"),
                                        now=clock.utcnow())

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id, status_code=201)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.canary.issue_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/runs/{run_id}/result", operation_id="submitCanaryResult",
             summary="回填 canary 响应（只比对 + 存 hash/score；正文不落库）")
async def submit_canary_result(request: Request, run_id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_WRITE)
        body = await _body(request)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return canary.submit_response(
                    conn, run_id=run_id, node_id=body.get("node_id"),
                    response_text=body.get("response_text"),
                    usage_prompt_tokens=body.get("usage_prompt_tokens"),
                    latency_ms=body.get("latency_ms"), now=clock.utcnow())

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.canary.result_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.get("/runs", operation_id="listCanaryRuns",
            summary="canary 运行列表（node / model / status 过滤 + 游标分页）")
async def list_canary_runs(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_READ)
        params = request.query_params

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return canary.list_runs(conn, node_id=params.get("node_id"),
                                        model=params.get("model"),
                                        status=params.get("status"),
                                        limit=params.get("limit"),
                                        cursor=params.get("cursor"))

        return _ok(await run_in_threadpool(_run), request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.canary.list_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.get("/stats", operation_id="getCanaryStats",
            summary="最近 N 次 canary 统计（pass / fail / missed / 通过率）")
async def get_canary_stats(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_READ)
        params = request.query_params

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return canary.stats(conn, node_id=params.get("node_id"),
                                    model=params.get("model"),
                                    window=params.get("window"))

        return _ok(await run_in_threadpool(_run), request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.canary.stats_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/expire", operation_id="expireCanaryRuns",
             summary="运维翻过期：issued 超 deadline → missed（+ 事件）")
async def expire_canary_runs(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_WRITE)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return canary.expire_due(conn, now=clock.utcnow())

        return _ok(await run_in_threadpool(_run), request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.canary.expire_failed request_id=%s", request_id)
        return _server_error(request_id)


__all__ = ["router", "set_admin_authenticator", "admin_authenticator"]
