# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 证明段 HTTP 路由（C12；**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 3 条操作（spec 1.2.11 由 Lead 登记；本卡不改根 spec）::

    POST /api/v1/node/upstream/attest/challenge            issueAttestationChallenge  200 / 400 / 401 / 503
    POST /api/v1/node/upstream/attest                      submitAttestationEvidence  200 / 400 / 401 / 404 / 409 / 503
    GET  /api/v1/admin/supply/integrity/attestations       listModelAttestations      200 / 400 / 401 / 403

响应形状（Lead 1.2.11 定稿，一个不多一个不少）：

* challenge 200：``{challenge_id, model, upstream_id|null, prompt, nonce, expires_at}``
* evidence  200：``{attestation:{id,node_id,upstream_id,model,level,state,source,
  tokenizer_version,evidence_ref,verified_at,expires_at},
  event:{event_id,event,level,created_at}}``
* admin 列表 200：``{items:[attestation...], has_more, next_cursor}``

约定（与 M02/M05/M11/M17-C14 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``；``code`` 整数
  （40001 / 40101 / 40301 / 40401 / 40919 / 503+50001）；任何响应回显 ``X-Request-Id``；
* 请求体自己校验（不用框架 422），不合法一律 400 / 40001；
* 鉴权两个注入钩子，**默认 fail-closed**：

    :func:`set_node_authenticator`  节点侧（合并时接 M02 的 X-Client-Key 校验）→ 主体需含 ``node_id``
    :func:`set_admin_authenticator` 管理面（接 M01 会话）→ 主体需含 ``admin_id`` + scope ``integrity.read``

* **挑战重放 100% 拒绝**：service 的条件 UPDATE + DB 触发器双保险，重放一律 409 / 40919；
* 开关 ``supply.attestation.enabled`` 关闭时：写接口 503 / 50001 + ``reason=feature_disabled``，
  读接口（admin 列表）保持只读可用；
* **不碰账本**：本路由只调 ``app.integrity.attest``，模块内不存在 ledger 写路径。
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

from . import attest, clock, facts, models
from .errors import (BadRequest, Forbidden, IntegrityError, ServerError, Unauthorized)

log = logging.getLogger("djb.integrity.attest_http")

router = APIRouter(prefix="/api/v1", tags=["node"])

REQUEST_ID_HEADER = "X-Request-Id"
MAX_BODY_BYTES = 64 * 1024

Authenticator = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
_node_authenticator: Authenticator | None = None
_admin_authenticator: Authenticator | None = None


# ───────────────────────────────────────────────────────── 接线钩子
def set_node_authenticator(authenticator: Authenticator | None) -> None:
    """注入节点侧鉴权（合并时由 Lead 接 M02 X-Client-Key）。传 ``None`` 恢复 fail-closed。"""
    global _node_authenticator
    _node_authenticator = authenticator


def node_authenticator() -> Authenticator | None:
    return _node_authenticator


def set_admin_authenticator(authenticator: Authenticator | None) -> None:
    """注入管理面鉴权（合并时由 Lead 接 M01 会话 + scope）。传 ``None`` 恢复 fail-closed。"""
    global _admin_authenticator
    _admin_authenticator = authenticator


def admin_authenticator() -> Authenticator | None:
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


# ───────────────────────────────────────────────────────── 鉴权
def _scopes_of(principal: Mapping[str, Any]) -> set[str]:
    raw = principal.get("scopes")
    if raw is None:
        return set()
    if isinstance(raw, str):
        return {item.strip() for item in raw.split(",") if item.strip()}
    if isinstance(raw, (list, tuple, set, frozenset)):
        return {str(item) for item in raw}
    return set()


async def _resolve(hook: Authenticator | None, request: Request, *, what: str
                   ) -> dict[str, Any]:
    if hook is None:
        raise Unauthorized(f"{what}鉴权未接线：合并时由 Lead 注入（fail-closed）",
                           reason="unauthorized")
    resolved = hook(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, Mapping) or not resolved:
        raise Unauthorized(f"{what}鉴权返回非法主体", reason="unauthorized")
    return dict(resolved)


async def _node_principal(request: Request) -> dict[str, Any]:
    principal = await _resolve(_node_authenticator, request, what="节点侧")
    node_id = principal.get("node_id")
    if not isinstance(node_id, str) or not node_id.strip():
        raise Unauthorized("节点侧主体缺少 node_id", reason="unauthorized")
    principal["node_id"] = node_id.strip()
    return principal


async def _admin_principal(request: Request) -> dict[str, Any]:
    principal = await _resolve(_admin_authenticator, request, what="管理面")
    if not principal.get("admin_id"):
        raise Unauthorized("管理面主体缺少 admin_id", reason="unauthorized")
    scopes = _scopes_of(principal)
    if facts.WILDCARD_SCOPE not in scopes and facts.SCOPE_READ not in scopes:
        raise Forbidden(f"缺少 scope：{facts.SCOPE_READ}", reason="forbidden")
    return principal


# ───────────────────────────────────────────────────────── 路由
@router.post("/node/upstream/attest/challenge", operation_id="issueAttestationChallenge",
             summary="签发 L1–L3 身份证明挑战（合成 prompt + 一次性 nonce，TTL 5 min）")
async def issue_attestation_challenge(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _node_principal(request)
        body = await _body(request)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return attest.issue_challenge(
                    conn, node_id=principal["node_id"], upstream_id=body.get("upstream_id"),
                    model=body.get("model"), now=clock.utcnow())

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.attest.challenge_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/node/upstream/attest", operation_id="submitAttestationEvidence",
             summary="上报证明证据（服务端比对 tokenizer 后定级；挑战一次性）")
async def submit_attestation_evidence(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _node_principal(request)
        body = await _body(request)

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return attest.submit_evidence(
                    conn, node_id=principal["node_id"], payload=body, now=clock.utcnow())

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.attest.submit_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.get("/admin/supply/integrity/attestations", operation_id="listModelAttestations",
            summary="模型身份证明列表（node / model / level 过滤 + 游标分页）")
async def list_model_attestations(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _admin_principal(request)
        params = request.query_params

        def _run() -> dict[str, Any]:
            with _connection() as conn:
                return attest.list_attestations(
                    conn, node_id=params.get("node_id"), model=params.get("model"),
                    level=params.get("level"), limit=params.get("limit"),
                    cursor=params.get("cursor"), now=clock.utcnow())

        payload = await run_in_threadpool(_run)
        return _ok(payload, request_id)
    except IntegrityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("integrity.attest.list_failed request_id=%s", request_id)
        return _server_error(request_id)


__all__ = ["router", "set_node_authenticator", "node_authenticator",
           "set_admin_authenticator", "admin_authenticator"]
