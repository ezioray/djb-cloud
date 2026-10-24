# SPDX-License-Identifier: AGPL-3.0-or-later
"""M14 管理面 HTTP 路由工厂（**不接 app/api.py** —— 由 Lead 合并时统一 include）。

十条端点（M14 §4.1；CR-2 待 Lead 裁决后写入 spec）::

    GET  /api/v1/admin/data/export-requests               listAdminDataExportRequests
    POST /api/v1/admin/data/export-requests               createAdminDataExportRequest   201
    GET  /api/v1/admin/data/export-requests/{export_id}   getAdminDataExportRequest
    POST /api/v1/admin/data/export-requests/{id}/cancel   cancelAdminDataExportRequest
    POST /api/v1/admin/data/retention-jobs                createRetentionJob             201
    GET  /api/v1/admin/data/retention-jobs                listRetentionJobs
    GET  /api/v1/admin/ops/health                         getOpsHealth
    GET  /api/v1/admin/ops/changes                        listOpsChanges
    POST /api/v1/admin/ops/batch-ops                      executeOpsBatch
    GET  /api/v1/admin/ops/audit-replay                   replayOpsAudit

约定（00-conventions §5 / 05-security-observability）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 为整数且**只用已登记码**；
* 每个响应回显 ``X-Request-Id``；请求体自校验（不依赖框架 422）；
* 写接口必带 ``X-DJB-Idempotency-Key``（16..128）且需 step-up（424 / 42401）；
* 三个依赖注入钩子默认 **fail-closed**：

    ``admin_resolver``       管理面会话（M01）→ {admin_id, tenant_id, scopes|roles}
    ``step_up_verifier``     二次认证（≤5 分钟）；未接线时只校验请求头存在
    ``connection_factory``   请求级连接（合并时注入 ``app.db.conn``）

* 权限点：data.read / data.write / data.approve / ops.read / ops.write；``roles`` 缺省时按
  ``facts.ROLE_SCOPES`` 映射（SUPER/OPS/AUDIT/VIEWER 有读；FIN/RISK/CS/SVC 默认拒绝）。
* OUT：INV-01（只读聚合）、INV-10（不展示 PII / 凭据 / 完整签名）、INV-08（审计只追加）。
"""
from __future__ import annotations

import inspect
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable, Mapping

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import audit as audit_hook
from . import batch as batch_service
from . import clock, errors, facts, models, ops, policy, retention, store
from . import export as export_service

log = logging.getLogger("djb.m14.http")

IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
STEP_UP_HEADER = "X-Admin-Step-Up"
REQUEST_ID_HEADER = "X-Request-Id"
TRACE_HEADER = "X-Trace-Id"

ADMIN_SCOPES: dict[str, str] = {
    "data_read": "data.read",
    "data_write": "data.write",
    "data_approve": "data.approve",
    "ops_read": "ops.read",
    "ops_write": "ops.write",
}

Principal = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
StepUpVerifier = Callable[[Request], "bool | Awaitable[bool]"]


# ───────────────────────────────────────────────────────────── 基础工具
def _request_id(request: Request) -> str:
    value = (request.headers.get(REQUEST_ID_HEADER) or "").strip()
    return value or str(uuid.uuid4())


def _trace_id(request: Request) -> str:
    value = (request.headers.get(TRACE_HEADER) or request.headers.get(REQUEST_ID_HEADER)
             or "").strip()
    return value or str(uuid.uuid4())


def _ok(payload: Any, request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code,
                        headers={REQUEST_ID_HEADER: request_id})


def _fail(exc: errors.M14Error, request_id: str) -> JSONResponse:
    return JSONResponse(exc.as_envelope(request_id), status_code=exc.status_code,
                        headers={REQUEST_ID_HEADER: request_id, "X-Error-Code": str(exc.code)})


def _failure(request_id: str, exc: BaseException) -> JSONResponse:
    if isinstance(exc, errors.M14Error):
        return _fail(exc, request_id)
    mapped = _db_error(exc)
    if mapped is not None:
        return _fail(mapped, request_id)
    log.exception("m14.http.failed", extra={"request_id": request_id})
    return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > facts.MAX_BODY_BYTES:
        raise errors.BadRequest("请求体超过上限", field="body")
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise errors.BadRequest("请求体必须是合法 JSON") from exc
    if not isinstance(payload, dict):
        raise errors.BadRequest("请求体必须是 JSON 对象")
    return payload


def _principal_scopes(principal: Mapping[str, Any]) -> list[str]:
    scopes = principal.get("scopes")
    if isinstance(scopes, str):
        scopes = [item.strip() for item in scopes.split(",") if item.strip()]
    if scopes is None:
        roles = principal.get("roles") or []
        if isinstance(roles, str):
            roles = [item.strip() for item in roles.split(",") if item.strip()]
        resolved: list[str] = []
        for role in roles:
            resolved.extend(facts.ROLE_SCOPES.get(str(role).strip().upper(), ()))
        scopes = resolved
    return [str(item) for item in scopes]


def _is_super(principal: Mapping[str, Any]) -> bool:
    return "*" in _principal_scopes(principal)


def _require_scope(principal: Mapping[str, Any], scope: str) -> None:
    scopes = _principal_scopes(principal)
    if "*" in scopes or scope in scopes:
        return
    raise errors.Forbidden(f"缺少权限点：{scope}（默认拒绝，向管理员申请权限）",
                           required_scope=scope)


def _principal_sync(resolver: Principal | None, request: Request, *, scope: str) -> dict:
    if resolver is None:
        raise errors.Unauthorized("M14 管理面鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):                     # pragma: no cover - 接线错误
        resolved.close()
        raise errors.Unauthorized("鉴权钩子在同步端点上返回了 awaitable")
    if not isinstance(resolved, Mapping) or not resolved:
        raise errors.Unauthorized("鉴权返回非法主体")
    principal = dict(resolved)
    _require_scope(principal, scope)
    return principal


async def _principal(resolver: Principal | None, request: Request, *, scope: str) -> dict:
    if resolver is None:
        raise errors.Unauthorized("M14 管理面鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, Mapping) or not resolved:
        raise errors.Unauthorized("鉴权返回非法主体")
    principal = dict(resolved)
    _require_scope(principal, scope)
    return principal


async def _require_step_up(verifier: StepUpVerifier | None, request: Request) -> None:
    value = (request.headers.get(STEP_UP_HEADER) or "").strip()
    if not value:
        raise errors.StepUpRequired()
    if verifier is None:
        return                                           # 未接线：存在性校验（真实校验由 M01 接线）
    result = verifier(request)
    if inspect.isawaitable(result):
        result = await result
    if not result:
        raise errors.StepUpRequired("step-up 已过期或无效：请重新完成二次认证")


def _actor(principal: Mapping[str, Any]) -> str:
    value = (principal.get("admin_id") or principal.get("actor")
             or principal.get("sub") or principal.get("service_id"))
    if not value:
        raise errors.Unauthorized("鉴权主体缺少 admin_id（fail-closed）")
    return str(value)[:facts.MAX_ACTOR_LEN]


def _tenant(principal: Mapping[str, Any]) -> str:
    value = principal.get("tenant_id") or principal.get("tenant")
    if not value:
        raise errors.Unauthorized("鉴权主体缺少 tenant_id（fail-closed）")
    return str(value)[:facts.MAX_ACTOR_LEN]


def _idempotency(request: Request, *, required: bool = True) -> str | None:
    key = models.require_idempotency_key(request.headers.get(IDEMPOTENCY_HEADER))
    if key is None and required:
        raise errors.BadRequest(
            "写接口必须带 X-DJB-Idempotency-Key（16..128）", field=IDEMPOTENCY_HEADER)
    return key


def _limit(raw: str | None) -> int:
    if raw in (None, ""):
        return facts.DEFAULT_PAGE_SIZE
    text = str(raw).strip()
    if not text.isdigit():
        raise errors.BadRequest("limit 必须是整数", field="limit")
    value = int(text)
    if not (facts.MIN_PAGE_SIZE <= value <= facts.MAX_PAGE_SIZE):
        raise errors.BadRequest(
            f"limit 必须在 {facts.MIN_PAGE_SIZE}..{facts.MAX_PAGE_SIZE}", field="limit")
    return value


def _bool_param(raw: str | None, *, field: str) -> bool | None:
    if raw in (None, ""):
        return None
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes"):
        return True
    if text in ("0", "false", "no"):
        return False
    raise errors.BadRequest(f"{field} 必须是布尔值", field=field)


def _enum_param(raw: str | None, *, field: str, allowed) -> str | None:
    if raw in (None, ""):
        return None
    return models.require_enum(str(raw).strip(), field=field, allowed=allowed)


def _ts_param(raw: str | None, *, field: str) -> datetime | None:
    if raw in (None, ""):
        return None
    return clock.parse_datetime(raw, field=field)


def _optional_str(raw: str | None, *, field: str, max_len: int = 128) -> str | None:
    if raw in (None, ""):
        return None
    return models.require_text(raw, field=field, max_len=max_len)


def _db_error(exc: BaseException) -> errors.M14Error | None:
    """库层护栏 → 契约码（库层是最后一道防线，不是常规路径）。"""
    if isinstance(exc, psycopg.errors.UniqueViolation):
        constraint = getattr(getattr(exc, "diag", None), "constraint_name", None) or ""
        if "uq_retention_jobs_object_cutoff" in constraint:
            return errors.Conflict(
                "同一 (object, cutoff) 已执行（INV-07）：请查询既有任务报告",
                reason="retention_already_executed")
        if "uq_export_requests_idem" in constraint:
            return errors.Conflict("幂等键已用于不同载荷（导出申请）",
                                   reason="idempotency_key_reused")
        if "data_gov_outbox" in constraint:
            return errors.Conflict("事件重复：已按 event_id / 幂等键去重",
                                   reason="duplicate_event")
        return errors.Conflict("唯一约束冲突：请查询既有对象或换幂等键",
                               reason="unique_conflict")
    if isinstance(exc, (psycopg.errors.CheckViolation, psycopg.errors.InsufficientPrivilege)):
        return errors.Conflict("库层护栏拒绝写入（状态机 / 不变式 / 不可改不可删）",
                               reason="guard_violation")
    if isinstance(exc, psycopg.errors.ForeignKeyViolation):
        return errors.NotFound("引用的对象不存在")
    if isinstance(exc, psycopg.errors.InvalidTextRepresentation):
        return errors.NotFound("对象不存在")
    if isinstance(exc, psycopg.errors.OperationalError):
        return errors.ServerError("服务暂时不可用：请稍后重试", reason="db_unavailable")
    return None


# ───────────────────────────────────────────────────────────── 路由
def create_router(*, connection_factory: Callable[[], Any],
                  admin_resolver: Principal | None = None,
                  step_up_verifier: StepUpVerifier | None = None,
                  now_provider: Callable[[], datetime] | None = None,
                  config_provider: Callable[[], Mapping[str, Any] | None] | None = None,
                  audit_sink: audit_hook.AuditSink | None = None,
                  retention_executor: retention.RetentionExecutor | None = None,
                  health_probes: Mapping[str, ops.HealthProbe] | None = None,
                  batch_store: batch_service.BatchStore | None = None,
                  batch_probe: batch_service.BatchProbe | None = None,
                  batch_executor: batch_service.BatchExecutor | None = None,
                  batch_undoer: batch_service.BatchExecutor | None = None,
                  link_secret: bytes | str | None = None,
                  link_base_url: str | None = None) -> APIRouter:
    """构造 M14 管理面路由（十条端点，默认 fail-closed）。"""
    router = APIRouter(tags=["admin"])          # 1.2.6 tag 归一：/api/v1/admin/** → admin
    now_source = now_provider or clock.utcnow
    store_handle = batch_store or batch_service.InMemoryBatchStore()
    secret = (link_secret.encode("utf-8") if isinstance(link_secret, str) else link_secret)
    if secret is None:
        secret = policy.link_secret_from_env()
    base_url = link_base_url or os.environ.get("DJB_ADMIN_BASE_URL")         or "https://tkbank.ai/admin"

    def _connection() -> Any:
        return connection_factory()

    def _config() -> Mapping[str, Any] | None:
        return config_provider() if config_provider is not None else None

    def _now() -> datetime:
        return clock.as_utc(now_source())

    # ─────────────────────────────────────── 导出：列表 / 申请
    @router.get("/api/v1/admin/data/export-requests",
                operation_id="listAdminDataExportRequests")
    def list_export_requests(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request,
                                        scope=ADMIN_SCOPES["data_read"])
            params = request.query_params
            state = _enum_param(params.get("state"), field="state",
                                allowed=facts.EXPORT_STATES)
            object_name = _enum_param(params.get("object"), field="object",
                                      allowed=facts.EXPORT_OBJECTS)
            requester = _optional_str(params.get("requester"), field="requester")
            from_at = _ts_param(params.get("from"), field="from")
            to_at = _ts_param(params.get("to"), field="to")
            limit = _limit(params.get("limit"))
            now = _now()
            with _connection() as connection:
                with connection.transaction():
                    rows, has_more, next_cursor = export_service.list_requests(
                        connection, state=state, object_name=object_name,
                        requester=requester, from_at=from_at, to_at=to_at,
                        cursor=params.get("cursor"), limit=limit, now=now,
                        audit_sink=audit_sink, trace_id=_trace_id(request),
                        visible_to=None if _is_super(principal) else _actor(principal))
            return _ok({"data": [models.export_payload(row) for row in rows],
                        "page": models.page_payload(cursor=params.get("cursor"),
                                                    has_more=has_more,
                                                    next_cursor=next_cursor)}, request_id)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    @router.post("/api/v1/admin/data/export-requests",
                 operation_id="createAdminDataExportRequest")
    async def create_export_request(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request,
                                         scope=ADMIN_SCOPES["data_write"])
            await _require_step_up(step_up_verifier, request)
            idempotency = _idempotency(request)
            body = await _body(request)
            actor, tenant = _actor(principal), _tenant(principal)
            now = _now()
            with _connection() as connection:
                with connection.transaction():
                    row = export_service.create_request(
                        connection, requester=actor, tenant_id=tenant, body=body,
                        now=now, idempotency_key=idempotency,
                        trace_id=_trace_id(request), audit_sink=audit_sink, config=_config())
            return _ok(models.export_payload(row), request_id, status_code=201)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    @router.get("/api/v1/admin/data/export-requests/{export_id}",
                operation_id="getAdminDataExportRequest")
    def get_export_request(request: Request, export_id: str) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request,
                                        scope=ADMIN_SCOPES["data_read"])
            identifier = models.require_uuid(export_id, field="export_id")
            now = _now()
            with _connection() as connection:
                with connection.transaction():
                    _row, payload = export_service.get_request(
                        connection, identifier, now=now, config=_config(), secret=secret,
                        base_url=base_url, actor=_actor(principal),
                        audit_sink=audit_sink, trace_id=_trace_id(request),
                        is_super=_is_super(principal))
            return _ok(payload, request_id)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    @router.post("/api/v1/admin/data/export-requests/{export_id}/cancel",
                 operation_id="cancelAdminDataExportRequest")
    async def cancel_export_request(request: Request, export_id: str) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request,
                                         scope=ADMIN_SCOPES["data_write"])
            await _require_step_up(step_up_verifier, request)
            _idempotency(request)
            identifier = models.require_uuid(export_id, field="export_id")
            now = _now()
            with _connection() as connection:
                with connection.transaction():
                    row = export_service.cancel_request(
                        connection, identifier, actor=_actor(principal), now=now,
                        audit_sink=audit_sink, trace_id=_trace_id(request))
            return _ok(models.export_payload(row), request_id)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    # ─────────────────────────────────────── 保留任务：创建 / 列表
    @router.post("/api/v1/admin/data/retention-jobs", operation_id="createRetentionJob")
    async def create_retention_job(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request,
                                         scope=ADMIN_SCOPES["data_write"])
            await _require_step_up(step_up_verifier, request)
            idempotency = _idempotency(request)
            body = await _body(request)
            now = _now()
            with _connection() as connection:
                with connection.transaction():
                    row = retention.create_job(
                        connection, requested_by=_actor(principal), body=body, now=now,
                        idempotency_key=idempotency, trace_id=_trace_id(request),
                        audit_sink=audit_sink, executor=retention_executor)
            return _ok(models.retention_payload(row, now=now), request_id, status_code=201)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    @router.get("/api/v1/admin/data/retention-jobs", operation_id="listRetentionJobs")
    def list_retention_jobs(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["data_read"])
            params = request.query_params
            object_name = _enum_param(params.get("object"), field="object",
                                      allowed=facts.RETENTION_OBJECTS)
            state = _enum_param(params.get("state"), field="state",
                                allowed=facts.RETENTION_STATES)
            dry_run = _bool_param(params.get("dry_run"), field="dry_run")
            limit = _limit(params.get("limit"))
            now = _now()
            with _connection() as connection:
                rows, has_more, next_cursor = retention.list_jobs(
                    connection, object_name=object_name, state=state, dry_run=dry_run,
                    cursor=params.get("cursor"), limit=limit)
            return _ok({"data": [models.retention_payload(row, now=now) for row in rows],
                        "page": models.page_payload(cursor=params.get("cursor"),
                                                    has_more=has_more,
                                                    next_cursor=next_cursor)}, request_id)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    # ─────────────────────────────────────── Ops 只读面
    @router.get("/api/v1/admin/ops/health", operation_id="getOpsHealth")
    def get_ops_health(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["ops_read"])
            now = _now()
            with _connection() as connection:
                payload = ops.health(connection, now=now, probes=health_probes)
            return _ok(payload, request_id)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    @router.get("/api/v1/admin/ops/changes", operation_id="listOpsChanges")
    def list_ops_changes(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["ops_read"])
            params = request.query_params
            from_at = _ts_param(params.get("from"), field="from")
            to_at = _ts_param(params.get("to"), field="to")
            limit = _limit(params.get("limit"))
            with _connection() as connection:
                payload = ops.changes(connection, from_at=from_at, to_at=to_at,
                                      cursor=params.get("cursor"), limit=limit,
                                      now=_now())
            return _ok(payload, request_id)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    @router.post("/api/v1/admin/ops/batch-ops", operation_id="executeOpsBatch")
    async def execute_ops_batch(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request,
                                         scope=ADMIN_SCOPES["ops_write"])
            await _require_step_up(step_up_verifier, request)
            idempotency = _idempotency(request)
            body = await _body(request)
            step = models.require_enum(body.get("step"), field="step",
                                       allowed=facts.BATCH_STEPS)
            actor, tenant = _actor(principal), _tenant(principal)
            now = _now()
            trace = _trace_id(request)
            if step == "preview":
                payload = batch_service.preview(
                    store_handle, body=body, actor=actor, tenant_id=tenant, now=now,
                    probe=batch_probe, audit_sink=audit_sink, trace_id=trace,
                    idempotency_key=idempotency)
                return _ok(payload, request_id, status_code=201)
            if step == "execute":
                payload = batch_service.execute(
                    store_handle, body=body, actor=actor, tenant_id=tenant, now=now,
                    executor=batch_executor, audit_sink=audit_sink, trace_id=trace,
                    idempotency_key=idempotency)
                return _ok(payload, request_id)
            payload = batch_service.undo(
                store_handle, body=body, actor=actor, tenant_id=tenant, now=now,
                undoer=batch_undoer, audit_sink=audit_sink, trace_id=trace,
                idempotency_key=idempotency)
            return _ok(payload, request_id)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    @router.get("/api/v1/admin/ops/audit-replay", operation_id="replayOpsAudit")
    def replay_ops_audit(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["ops_read"])
            params = request.query_params
            from_at = _ts_param(params.get("from"), field="from")
            to_at = _ts_param(params.get("to"), field="to")
            limit = _limit(params.get("limit"))
            with _connection() as connection:
                payload = ops.audit_replay(
                    connection, trace_id=_optional_str(params.get("trace_id"),
                                                       field="trace_id"),
                    owner_id=_optional_str(params.get("owner_id"), field="owner_id"),
                    action=_optional_str(params.get("action"), field="action", max_len=64),
                    from_at=from_at, to_at=to_at, cursor=params.get("cursor"),
                    limit=limit, now=_now())
            return _ok(payload, request_id)
        except Exception as exc:                       # noqa: BLE001
            return _failure(request_id, exc)

    return router
