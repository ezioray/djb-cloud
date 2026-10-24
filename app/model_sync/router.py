# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 model-sync HTTP 路由（**不接 app/api.py** —— 由 Lead 合并时统一 include）。

**不改根 spec**：wire 形状由 Lead 写进 1.2.12；本模块只实现。覆盖 7 条操作::

    GET  /api/v1/node/model-catalog?since=<version>     getNodeModelCatalog        200 / 400 / 401 / 503
    POST /api/v1/node/model-sync/state                  reportNodeModelSyncState   200 / 400 / 401 / 503
    GET  /api/v1/admin/model-sync/bundles               listModelSyncBundles       200 / 400 / 401 / 403
    POST /api/v1/admin/model-sync/bundles               createModelSyncBundle      201 / 400 / 401 / 403 / 503
    POST /api/v1/admin/model-sync/bundles/{id}/publish  publishModelSyncBundle     200 / 400 401 403 404 409 503
    POST /api/v1/admin/model-sync/bundles/{id}/rollback rollbackModelSyncBundle    200 / 400 401 403 404 409 503
    GET  /api/v1/admin/model-sync/state                 listNodeModelSyncState     200 / 400 / 401 / 403

wire（lead 1.2.12 定稿）：

* node catalog 200：``{version, payload_hash, signature, expires_at, not_modified, models:[…]}``
  （``models[]`` 每项 ``{vendor, canonical, aliases, context_window, tokenizer_family,
  tokenizer_version, tokenizer_hash, effective_at}``）
* node state 200：``{accepted, server_version}``
* admin：``{items, has_more}`` / ``{bundle}`` / ``{items, server_version, has_more}``

约定（与 M02/M05/M17 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``；``code`` 整数
  （40001 / 40101 / 40301 / 40401 / 40919 / 503+50001）；任何响应回显 ``X-Request-Id``；
* 请求体自己校验（不用框架 422）：不合法一律 400 / 40001；
* 鉴权两个注入钩子，**默认 fail-closed**（未接线即 401）：
  :func:`set_node_authenticator`（合并时接 M02 X-Client-Key，主体需含 ``node_id``）/
  :func:`set_admin_authenticator`（接 M01 会话，主体需含 ``admin_id`` + scope）；
* 写路径（创建 / 发布 / 回滚 / 状态上报）受 ``model.sync.enabled`` 约束：关闭 →
  503 / 50001 + ``reason=feature_disabled``（fail-closed）；读路径保持可用（rollback_rule）；
* **不碰账本**：本路由只调 :mod:`app.model_sync.store`，模块内无 ledger 写路径。
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

from . import clock, facts, features, registry, signing, store
from .errors import (BadRequest, Conflict, FeatureUnavailable, Forbidden, ModelSyncError,
                     NotFound, ServerError, Unauthorized)

log = logging.getLogger("djb.model_sync.http")

router = APIRouter(prefix="/api/v1", tags=["node"])
admin_router = APIRouter(prefix="/api/v1/admin/model-sync", tags=["admin"])

REQUEST_ID_HEADER = "X-Request-Id"
MAX_BODY_BYTES = 64 * 1024
READ_SCOPE = "model_sync.read"
WRITE_SCOPE = "model_sync.write"
WILDCARD_SCOPE = "*"
DRIFT_FORBIDDEN_KEYS = ("content", "messages", "prompt", "response", "body", "text",
                        "api_key", "secret", "password", "token")
MAX_DRIFT_KEYS = 32

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


# ───────────────────────────────────────────────────────── 信封
def _request_id(request: Request) -> str:
    provided = (request.headers.get(REQUEST_ID_HEADER) or "").strip()
    return provided[:64] if provided else uuid.uuid4().hex


def _ok(payload: Any, request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code,
                        headers={REQUEST_ID_HEADER: request_id})


def _fail(exc: ModelSyncError, request_id: str) -> JSONResponse:
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
async def _principal(authenticator: Authenticator | None, request: Request,
                     *, key: str) -> Mapping[str, Any]:
    if authenticator is None:
        raise Unauthorized("鉴权未接线（fail-closed）", reason="unauthorized")
    principal = authenticator(request)
    if inspect.isawaitable(principal):
        principal = await principal
    if not isinstance(principal, Mapping) or not str(principal.get(key) or "").strip():
        raise Unauthorized(f"主体缺少 {key}（fail-closed）", reason="unauthorized")
    return principal


async def _node_principal(request: Request) -> Mapping[str, Any]:
    return await _principal(_node_authenticator, request, key="node_id")


async def _admin_principal(request: Request) -> Mapping[str, Any]:
    return await _principal(_admin_authenticator, request, key="admin_id")


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
    if WILDCARD_SCOPE in scopes or scope in scopes:
        return
    raise Forbidden(f"缺少 scope：{scope}", reason="forbidden", scope=scope)


def _require_feature() -> None:
    """写路径开关：默认关；S2 测试网 ``DJB_MODEL_SYNC=1`` 激活。"""
    if not features.active(facts.ENABLED_FLAG):
        raise FeatureUnavailable(
            "模型同步未启用（model.sync.enabled=false，默认关闭；S2 测试网用 "
            "DJB_MODEL_SYNC=1 激活）：写接口 fail-closed，读接口只读",
            reason="feature_disabled")


# ───────────────────────────────────────────────────────── 请求体校验
def _require_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRequest(f"{field} 必须是整数", field=field)
    if not minimum <= value <= maximum:
        raise BadRequest(f"{field} 必须在 {minimum}–{maximum} 之间", field=field)
    return int(value)


def _parse_since(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise BadRequest("since 必须是整数版本号", field="since") from exc
    if not 0 <= number <= facts.NODE_CATALOG_SINCE_MAX:
        raise BadRequest(f"since 必须在 0–{facts.NODE_CATALOG_SINCE_MAX} 之间", field="since")
    return number


def _parse_drift(value: Any) -> dict[str, Any]:
    """漂移摘要：**只接受扁平对象**（≤32 键、标量值），且禁止正文 / 凭据类键。"""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise BadRequest("drift 必须是 JSON 对象", field="drift")
    if len(value) > MAX_DRIFT_KEYS:
        raise BadRequest(f"drift 最多 {MAX_DRIFT_KEYS} 个键", field="drift")
    result: dict[str, Any] = {}
    for key, item in value.items():
        name = str(key)
        if name.lower() in DRIFT_FORBIDDEN_KEYS:
            raise BadRequest(f"drift.{name} 不允许上报（只收版本 / 差异摘要）",
                             field=f"drift.{name}")
        if isinstance(item, (Mapping, list, tuple)):
            raise BadRequest(f"drift.{name} 必须是标量（不落正文）", field=f"drift.{name}")
        if isinstance(item, str) and len(item) > facts.MAX_FIELD_LEN:
            raise BadRequest(f"drift.{name} 超长", field=f"drift.{name}")
        result[name] = item
    return result


def _parse_error_class(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise BadRequest("error_class 必须是非空字符串", field="error_class")
    text = value.strip()
    if len(text) > facts.MAX_ERROR_CLASS_LEN:
        raise BadRequest(f"error_class 超长（≤{facts.MAX_ERROR_CLASS_LEN}）",
                         field="error_class")
    return text


def _parse_limit(request: Request) -> int:
    raw = request.query_params.get("limit")
    if raw is None:
        return facts.DEFAULT_LIST_LIMIT
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise BadRequest("limit 必须是整数", field="limit") from exc
    if not 1 <= value <= facts.MAX_LIST_LIMIT:
        raise BadRequest(f"limit 必须在 1–{facts.MAX_LIST_LIMIT} 之间", field="limit")
    return value


def _parse_bundle_id(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise BadRequest("bundle_id 必须是 UUID", field="bundle_id") from exc


def _actor(principal: Mapping[str, Any], prefix: str) -> str:
    return f"{prefix}:{principal.get('admin_id') or principal.get('node_id')}"


# ───────────────────────────────────────────────────────── node：catalog
@router.get("/node/model-catalog", operation_id="getNodeModelCatalog",
            summary="拉取签名模型/tokenizer 清单（since=已应用版本）")
async def get_node_model_catalog(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _node_principal(request)
        since = _parse_since(request.query_params.get("since"))
        with _connection() as c:
            if features.active(facts.ENABLED_FLAG):
                bundle = await run_in_threadpool(store.current_bundle, c)
            else:
                bundle = None                                  # 关闭 → 内置回退（不伪造版本）
        payload = registry.catalog_payload(bundle, since=since)
        log.info("model_sync.catalog", extra={"event": "model_sync.catalog",
                                              "node_id": principal.get("node_id"),
                                              "version": payload["version"],
                                              "not_modified": payload["not_modified"],
                                              "trace_id": request_id})
        return _ok(payload, request_id)
    except ModelSyncError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("model_sync.catalog_failed request_id=%s", request_id)
        return _server_error(request_id)


# ───────────────────────────────────────────────────────── node：state
@router.post("/node/model-sync/state", operation_id="reportNodeModelSyncState",
             summary="上报已应用的 bundle 版本 / 漂移 / 错误类")
async def report_node_model_sync_state(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _node_principal(request)
        body = await _body(request)
        applied_version = _require_int(body.get("applied_version"), field="applied_version",
                                       minimum=0, maximum=2**62)
        drift = _parse_drift(body.get("drift"))
        error_class = _parse_error_class(body.get("error_class"))
        _require_feature()
        node_id = str(principal["node_id"])
        with _connection() as c:
            with c.transaction():
                row = await run_in_threadpool(
                    store.record_state, c, node_id=node_id, applied_version=applied_version,
                    drift=drift, error_class=error_class, now=clock.utcnow())
                server_version = await run_in_threadpool(store.latest_version, c)
        payload = {"accepted": int(row["applied_version"]) == int(server_version)
                   and error_class is None,
                   "server_version": int(server_version)}
        log.info("model_sync.state", extra={"event": "model_sync.state", "node_id": node_id,
                                            "applied_version": applied_version,
                                            "server_version": server_version,
                                            "trace_id": request_id})
        return _ok(payload, request_id)
    except ModelSyncError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("model_sync.state_failed request_id=%s", request_id)
        return _server_error(request_id)


# ───────────────────────────────────────────────────────── admin：bundles
@admin_router.get("/bundles", operation_id="listModelSyncBundles",
                  summary="bundle 列表（版本倒序，可按 state 过滤）")
async def list_model_sync_bundles(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _admin_principal(request)
        _require_scope(principal, READ_SCOPE)
        limit = _parse_limit(request)
        state = (request.query_params.get("state") or "").strip() or None
        if state is not None and state not in facts.BUNDLE_STATES:
            raise BadRequest(f"state 必须是 {'/'.join(facts.BUNDLE_STATES)} 之一",
                             field="state")
        with _connection() as c:
            rows = await run_in_threadpool(store.list_bundles, c, state=state, limit=limit + 1)
        has_more = len(rows) > limit
        items = [registry.bundle_summary(row) for row in rows[:limit]]
        return _ok({"items": items, "has_more": has_more}, request_id)
    except ModelSyncError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("model_sync.bundles_list_failed request_id=%s", request_id)
        return _server_error(request_id)


@admin_router.post("/bundles", operation_id="createModelSyncBundle", status_code=201,
                   summary="从注册表生成 draft（auto_publish 打开时直接发布）")
async def create_model_sync_bundle(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _admin_principal(request)
        _require_scope(principal, WRITE_SCOPE)
        _require_feature()
        actor = _actor(principal, "admin")
        auto = features.active(facts.AUTO_PUBLISH_FLAG)
        with _connection() as c:
            with c.transaction():
                bundle = await run_in_threadpool(store.create_draft, c, actor=actor,
                                                 now=clock.utcnow())
                if auto:
                    bundle = await run_in_threadpool(store.publish, c, bundle["id"],
                                                     actor=f"{actor}:auto",
                                                     now=clock.utcnow())
        payload = {"bundle": registry.bundle_summary(bundle), "auto_published": auto}
        log.info("model_sync.bundle_created",
                 extra={"event": "model_sync.bundle_created", "actor": actor,
                        "version": int(bundle["version"]), "auto": auto,
                        "trace_id": request_id})
        return _ok(payload, request_id, status_code=201)
    except ModelSyncError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("model_sync.bundle_create_failed request_id=%s", request_id)
        return _server_error(request_id)


@admin_router.post("/bundles/{bundle_id}/publish", operation_id="publishModelSyncBundle",
                   summary="发布 draft（签名 + TTL 24h）")
async def publish_model_sync_bundle(bundle_id: str, request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _admin_principal(request)
        _require_scope(principal, WRITE_SCOPE)
        _require_feature()
        identifier = _parse_bundle_id(bundle_id)
        actor = _actor(principal, "admin")
        with _connection() as c:
            with c.transaction():
                bundle = await run_in_threadpool(store.publish, c, identifier, actor=actor,
                                                 now=clock.utcnow())
        log.info("model_sync.bundle_published",
                 extra={"event": "model_sync.bundle_published", "actor": actor,
                        "version": int(bundle["version"]), "trace_id": request_id})
        return _ok({"bundle": registry.bundle_summary(bundle)}, request_id)
    except ModelSyncError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("model_sync.bundle_publish_failed request_id=%s", request_id)
        return _server_error(request_id)


@admin_router.post("/bundles/{bundle_id}/rollback", operation_id="rollbackModelSyncBundle",
                   summary="回滚到指定 bundle（新建更高版本，不改历史）")
async def rollback_model_sync_bundle(bundle_id: str, request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _admin_principal(request)
        _require_scope(principal, WRITE_SCOPE)
        _require_feature()
        identifier = _parse_bundle_id(bundle_id)
        actor = _actor(principal, "admin")
        with _connection() as c:
            with c.transaction():
                bundle = await run_in_threadpool(store.rollback, c, identifier, actor=actor,
                                                 now=clock.utcnow())
        log.info("model_sync.bundle_rolled_back",
                 extra={"event": "model_sync.bundle_rolled_back", "actor": actor,
                        "version": int(bundle["version"]), "trace_id": request_id})
        return _ok({"bundle": registry.bundle_summary(bundle)}, request_id)
    except ModelSyncError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("model_sync.bundle_rollback_failed request_id=%s", request_id)
        return _server_error(request_id)


@admin_router.get("/state", operation_id="listNodeModelSyncState",
                  summary="节点应用状态 / 漂移（只读）")
async def list_node_model_sync_state(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _admin_principal(request)
        _require_scope(principal, READ_SCOPE)
        limit = _parse_limit(request)
        with _connection() as c:
            server_version = await run_in_threadpool(store.latest_version, c)
            rows = await run_in_threadpool(store.list_node_states, c, limit=limit,
                                           server_version=server_version)
        items = [store.state_view(row, server_version=server_version) for row in rows]
        return _ok({"items": items, "server_version": int(server_version),
                    "has_more": False}, request_id)
    except ModelSyncError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("model_sync.state_list_failed request_id=%s", request_id)
        return _server_error(request_id)


__all__ = ["router", "admin_router", "set_node_authenticator", "set_admin_authenticator",
           "node_authenticator", "admin_authenticator"]
