# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 抽检段管理面路由（C14b；**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 6 条操作（spec 1.2.12 由 Lead 登记；本卡不改根 spec）::

    POST /api/v1/admin/supply/integrity/sampling/epochs               openSamplingEpoch      201 / 400 / 401 / 403 / 409 / 503
    POST /api/v1/admin/supply/integrity/sampling/epochs/{id}/reveal   revealSamplingEpoch    200 / 400 / 401 / 403 / 404 / 409 / 503
    GET  /api/v1/admin/supply/integrity/sampling/epochs               listSamplingEpochs     200 / 400 / 401 / 403
    GET  /api/v1/admin/supply/integrity/sampling/epochs/{id}          getSamplingEpoch       200 / 401 / 403 / 404
    POST /api/v1/admin/supply/integrity/sampling/draws/{id}/result    recordSamplingResult   200 / 400 / 401 / 403 / 404 / 409 / 503
    POST /api/v1/admin/supply/integrity/sampling/verify              verifySamplingEpoch    200 / 400 / 401 / 403 / 404 / 409

响应形状（本卡定义，供 1.2.12 参考）：

* open 201：``{"epoch":{id,epoch_no,seed_commit,seed_reveal,contributions,state,
  draw_count,committed_at,revealed_at,created_at}, "seed":"<64 hex>"}``
  （``seed`` 只在此响应出现一次，运维须安全保管；库里只有 sha256 承诺）
* reveal 200：``{"epoch":{...}, "draws":[...], "idempotent": bool}``
* result 200：``{"draw":{...}, "attestation":{...}|null}``
* verify 200：``{"epoch_id","consistent","commit_ok","draw_count","expected","actual"}``
* list 200：``{"items":[...], "has_more", "next_cursor"}``

约定（与 M02/M05/M11/M17 其它段一致）：

* 错误信封 ``{"error": {type, code, message, request_id}}``；``code`` 整数
  （40001 / 40101 / 40301 / 40401 / 40919 / 503+50001）；任何响应回显 ``X-Request-Id``；
* 请求体自己校验（不用框架 422），不合法一律 400 / 40001；
* 鉴权走 :func:`set_admin_authenticator` 注入钩子，**默认 fail-closed**（未接线即 401）；
  scope：读 ``integrity.read``、写 ``integrity.write``；
* 开关 ``supply.sampling.enabled`` 关闭时：写接口 503 / 50001 + ``reason=feature_disabled``，
  读接口只读可用（已揭示轮次仍可复算）；
* **不碰账本**：本路由只调 ``app.integrity.sampling``，模块内不存在 ledger 写路径。
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

from . import clock, facts, sampling
from .errors import (BadRequest, Forbidden, IntegrityError, ServerError, Unauthorized)

log = logging.getLogger("djb.integrity.sampling_http")

router = APIRouter(prefix="/api/v1/admin/supply/integrity/sampling", tags=["admin"])

REQUEST_ID_HEADER = "X-Request-Id"
MAX_BODY_BYTES = 128 * 1024

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
            "M17 抽检管理面鉴权未接线：合并时由 Lead 注入（fail-closed）",
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


def _actor(principal: Mapping[str, Any]) -> str:
    return str(principal.get("admin_id"))


# ───────────────────────────────────────────────────────── 路由
@router.post("/epochs", operation_id="openSamplingEpoch",
             summary="开轮次（先承诺：只存 sha256(seed)，seed 不落库）")
async def open_sampling_epoch(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _principal(request, scope=facts.SCOPE_WRITE)
        body = await _body(request)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return sampling.open_epoch(
                    conn, epoch_no=body.get("epoch_no"),
                    contributions=body.get("contributions"),
                    draw_count=body.get("draw_count"), now=clock.utcnow(),
                    actor=_actor(principal))

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id, status_code=201)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.sampling.open_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/epochs/{epoch_id}/reveal", operation_id="revealSamplingEpoch",
             summary="揭示 seed 并抽签（校验承诺 → 确定性加权无放回 → 建 C12 挑战）")
async def reveal_sampling_epoch(request: Request, epoch_id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _principal(request, scope=facts.SCOPE_WRITE)
        body = await _body(request)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return sampling.reveal_epoch(conn, epoch_id=epoch_id, seed=body.get("seed"),
                                             now=clock.utcnow(), actor=_actor(principal))

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.sampling.reveal_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.get("/epochs", operation_id="listSamplingEpochs",
            summary="轮次列表（state 过滤 + 游标分页）")
async def list_sampling_epochs(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_READ)
        params = request.query_params

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return sampling.list_epochs(conn, state=params.get("state"),
                                            limit=params.get("limit"),
                                            cursor=params.get("cursor"))

        return _ok(await run_in_threadpool(_run), request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.sampling.list_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.get("/epochs/{epoch_id}", operation_id="getSamplingEpoch",
            summary="轮次详情（含 draws）")
async def get_sampling_epoch(request: Request, epoch_id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_READ)

        def _run() -> dict[str, Any] | None:
            with _connection() as conn:
                return sampling.get_epoch(conn, epoch_id)

        payload = await run_in_threadpool(_run)
        if payload is None:
            from .errors import NotFound

            raise NotFound("轮次不存在", reason="not_found")
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.sampling.get_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/draws/{draw_id}/result", operation_id="recordSamplingResult",
             summary="回填抽检结果（复用 C12：L3+ → passed；L2/L1 → failed；过期 → missed）")
async def record_sampling_result(request: Request, draw_id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _principal(request, scope=facts.SCOPE_WRITE)
        body = await _body(request)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return sampling.record_result(conn, draw_id=draw_id,
                                              evidence=body.get("evidence"),
                                              now=clock.utcnow(), actor=_actor(principal))

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.sampling.result_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/verify", operation_id="verifySamplingEpoch",
             summary="复算验证（给定 seed_reveal + 抽样框重算，返回一致 / 不一致）")
async def verify_sampling_epoch(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(request, scope=facts.SCOPE_READ)
        body = await _body(request)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return sampling.verify_epoch(conn, body.get("epoch_id"))

        return _ok(await run_in_threadpool(_run), request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.sampling.verify_failed request_id=%s", request_id)
        return _server_error(request_id)


__all__ = ["router", "set_admin_authenticator", "admin_authenticator"]
