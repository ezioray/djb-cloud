# SPDX-License-Identifier: Apache-2.0
"""M11 管理面 HTTP 路由工厂（**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 spec 1.2.4 的 9 条操作（与 M11 §4.1 一一对应）::

    GET  /api/v1/admin/risk/rules                     listRiskRules           200 / 401 / 403
    POST /api/v1/admin/risk/rules                     createRiskRule          201 / 400 / 401 / 403 / 409(48005) / 424
    GET  /api/v1/admin/risk/limits                    listRiskLimits          200 / 400 / 401 / 403 / 404
    POST /api/v1/admin/risk/limits                    setRiskLimit            201 / 400 / 401 / 403 / 409(48005) / 424
    GET  /api/v1/admin/risk/cases                     listRiskCases           200 / 400 / 401 / 403
    GET  /api/v1/admin/risk/cases/{id}                getRiskCase             200 / 401 / 403 / 404
    POST /api/v1/admin/risk/cases/{id}/decisions      decideRiskCase          201 / 400(48004) / 401 / 403(48006) / 404 / 409 / 424
    POST /api/v1/admin/risk/appeals                   createRiskAppeal        201 / 400 / 401 / 403 / 409(48003)
    POST /api/v1/admin/risk/appeals/{id}/decide       decideRiskAppeal        200 / 400 / 401 / 403(48006) / 404 / 409 / 424

约定（00-conventions §5 / spec ``Error``）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**且已登记；
* 任何响应都回显 ``X-Request-Id``；请求体自己校验（不依赖框架 422）；
* 写接口的 ``X-DJB-Idempotency-Key``（16..128）命中即返回首次结果；**同键不同载荷**按
  状态机 / 唯一约束拒绝（不静默覆盖）；
* 三个依赖注入钩子，默认 **fail-closed**：

    ``admin_resolver``   管理面会话（M01）→ {"admin_id", "tenant_id", "scopes"}
    ``step_up_verifier`` 敏感操作二次认证（≤5 分钟）；未接线时只校验请求头是否存在
    ``connection_factory`` 请求级连接（合并时注入 ``app.db.conn``）

* INV-01 / INV-02：响应只出元数据与粗粒度 reason；阈值 / 权重 / 名单 / 规则命中细节
  一律不出现在响应里（序列化走 ``models.*_payload`` 白名单）。
"""
from __future__ import annotations

import inspect
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable, Mapping

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import appeals as appeals_service
from . import audit as audit_hook
from . import cases as cases_service
from . import clock, config_source, errors, facts, models, store

log = logging.getLogger("djb.risk.http")

IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
STEP_UP_HEADER = "X-Admin-Step-Up"
REQUEST_ID_HEADER = "X-Request-Id"
MAX_BODY_BYTES = 64 * 1024

Principal = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
StepUpVerifier = Callable[[Request], "bool | Awaitable[bool]"]

#: 管理面 scope（M01 角色 → scope 的映射在接线时完成）
ADMIN_SCOPES = {"read": "risk.read", "write": "risk.write"}


# ───────────────────────────────────────────────────────────── 基础工具
def _request_id(request: Request) -> str:
    value = (request.headers.get(REQUEST_ID_HEADER) or "").strip()
    return value or str(uuid.uuid4())


def _ok(payload: Any, request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code,
                        headers={REQUEST_ID_HEADER: request_id})


def _fail(exc: errors.RiskError, request_id: str) -> JSONResponse:
    return JSONResponse(exc.as_envelope(request_id), status_code=exc.status_code,
                        headers={REQUEST_ID_HEADER: request_id})


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
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


async def _principal(resolver: Principal | None, request: Request, *,
                     scope: str) -> dict[str, Any]:
    """fail-closed 主体解析 + scope 校验：未接线 / 非法主体 / 缺 scope → 401 或 403。"""
    if resolver is None:
        raise errors.Unauthorized("M11 管理面鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, Mapping) or not resolved:
        raise errors.Unauthorized("鉴权返回非法主体")
    _require_scope(dict(resolved), scope)
    return dict(resolved)


def _principal_sync(resolver: Principal | None, request: Request, *, scope: str) -> dict[str, Any]:
    if resolver is None:
        raise errors.Unauthorized("M11 管理面鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):                    # pragma: no cover - 接线错误
        resolved.close()
        raise errors.Unauthorized("鉴权钩子在同步端点上返回了 awaitable")
    if not isinstance(resolved, Mapping) or not resolved:
        raise errors.Unauthorized("鉴权返回非法主体")
    _require_scope(dict(resolved), scope)
    return dict(resolved)


def _require_scope(principal: Mapping[str, Any], scope: str) -> None:
    scopes = principal.get("scopes")
    if scopes is None:
        return
    if isinstance(scopes, str):
        scopes = [item.strip() for item in scopes.split(",") if item.strip()]
    if "*" in scopes or scope in scopes:
        return
    raise errors.Forbidden(f"缺少 scope：{scope}")


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


def _tenant(principal: Mapping[str, Any]) -> str:
    value = principal.get("tenant_id") or principal.get("tenant")
    if not value:
        raise errors.Unauthorized("鉴权主体缺少 tenant_id（fail-closed）")
    return str(value)


def _actor(principal: Mapping[str, Any]) -> str:
    value = (principal.get("admin_id") or principal.get("admin")
             or principal.get("sub") or principal.get("service_id"))
    if not value:
        raise errors.Unauthorized("鉴权主体缺少 admin_id（fail-closed）")
    return str(value)


def _idempotency(request: Request) -> str | None:
    return models.require_idempotency_key(request.headers.get(IDEMPOTENCY_HEADER))


def _limit(raw: str | None) -> int:
    if raw in (None, ""):
        return facts.DEFAULT_PAGE_SIZE
    if not str(raw).strip().isdigit():
        raise errors.BadRequest("limit 必须是整数", field="limit")
    value = int(str(raw).strip())
    if not (facts.MIN_PAGE_SIZE <= value <= facts.MAX_PAGE_SIZE):
        raise errors.BadRequest(
            f"limit 必须在 {facts.MIN_PAGE_SIZE}..{facts.MAX_PAGE_SIZE}", field="limit")
    return value


def _flag(raw: str | None, *, field: str) -> bool | None:
    if raw in (None, ""):
        return None
    text = str(raw).strip().lower()
    if text in ("1", "true", "yes"):
        return True
    if text in ("0", "false", "no"):
        return False
    raise errors.BadRequest(f"{field} 必须是布尔值", field=field)


def _db_error(exc: Exception) -> errors.RiskError | None:
    """库层护栏 → 契约码（库层是最后一道防线，不是常规路径）。"""
    if isinstance(exc, psycopg.errors.UniqueViolation):
        constraint = getattr(getattr(exc, "diag", None), "constraint_name", None) or ""
        if "uq_cases_open" in constraint:
            return errors.CaseExists("同主体同类型已有未结案件（INV-06）", reason="case_exists")
        if "uq_appeals_open" in constraint:
            return errors.AppealConflict("同一案件已有未结申诉（重复申诉）",
                                         reason="appeal_duplicate")
        return errors.Conflict("唯一约束冲突：请查询既有对象或换幂等键", reason="unique_conflict")
    if isinstance(exc, psycopg.errors.CheckViolation):
        return errors.Conflict("库层护栏拒绝写入（状态机 / 不变式不满足）",
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
                  config_provider: Callable[[], config_source.ConfigProvider | None] | None = None,
                  audit_sink: audit_hook.AuditSink | None = None,
                  ) -> APIRouter:
    """构造 M11 路由（九条管理面操作）。"""
    router = APIRouter(tags=["risk"])
    now_source = now_provider or clock.utcnow

    def _connection() -> Any:
        return connection_factory()

    def _cfg_provider() -> config_source.ConfigProvider | None:
        return config_provider() if config_provider is not None else None

    # ─────────────────────────────────────────────── 规则（rules ×2）
    @router.get("/api/v1/admin/risk/rules", operation_id="listRiskRules")
    def list_risk_rules(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            params = request.query_params
            enabled = _flag(params.get("enabled"), field="enabled")
            limit = _limit(params.get("limit"))
            with _connection() as connection:
                rows, has_more, next_cursor = store.list_rules(
                    connection, enabled=enabled, cursor=params.get("cursor"), limit=limit)
            data = [models.rule_payload(row) for row in rows]
            return _ok({"data": data,
                        "page": models.page_payload(cursor=params.get("cursor"),
                                                    has_more=has_more,
                                                    next_cursor=next_cursor)}, request_id)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.list_rules_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/risk/rules", operation_id="createRiskRule")
    async def create_risk_rule(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request, scope=ADMIN_SCOPES["write"])
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_rule(await _body(request))
            actor = _actor(principal)
            idempotency = _idempotency(request)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    if idempotency:
                        replay = store.find_rule_by_idempotency(connection, idempotency)
                        if replay is not None:
                            if not _same_rule(replay, draft):
                                raise errors.Conflict(
                                    "幂等键已用于不同载荷（规则元数据）",
                                    reason="idempotency_key_reused")
                            return _ok(models.rule_payload(replay), request_id,
                                       status_code=201)
                    current = store.get_latest_rule(connection, draft.rule_key)
                    if draft.expected_version is not None and (
                            current is None or int(current["version"]) != draft.expected_version):
                        raise errors.RuleVersionConflict(
                            "规则版本冲突：expected_version 与当前版本不一致",
                            reason="rule_version_conflict")
                    if current is not None and _same_rule(current, draft):
                        return _ok(models.rule_payload(current), request_id, status_code=201)
                    version = 1 if current is None else int(current["version"]) + 1
                    stamp = config_source.stamp_for(draft.config_ref, _cfg_provider(), now=now)
                    if stamp.source == "lkg" and draft.config_ref is not None:
                        # 规则包不可用 → 只登记元数据；不读任何阈值（INV-01 / §7）
                        log.info("risk.http.rule_lkg", extra={"request_id": request_id,
                                                              "config_ref": draft.config_ref})
                    row = store.insert_rule(connection, draft, version=version,
                                            created_by=actor,
                                            idempotency_key=idempotency)
            return _ok(models.rule_payload(row), request_id, status_code=201)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.create_rule_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 限额（limits ×2）
    @router.get("/api/v1/admin/risk/limits", operation_id="listRiskLimits")
    def list_risk_limits(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            params = request.query_params
            subject_type = params.get("subject_type") or None
            if subject_type is not None and subject_type not in facts.SUBJECT_TYPES:
                raise errors.BadRequest(
                    f"subject_type 必须是 {list(facts.SUBJECT_TYPES)} 之一",
                    field="subject_type")
            subject_id = params.get("subject_id") or None
            if subject_id is not None:
                subject_id = models.require_subject_hash(subject_id, field_name="subject_id")
            limit = _limit(params.get("limit"))
            with _connection() as connection:
                rows, has_more, next_cursor = store.list_limits(
                    connection, tenant_id=_tenant(principal), subject_type=subject_type,
                    subject_id=subject_id, cursor=params.get("cursor"), limit=limit)
            if subject_id is not None and not rows and not params.get("cursor"):
                raise errors.NotFound("该主体没有生效限额")
            data = [models.limit_payload(row) for row in rows]
            return _ok({"data": data,
                        "page": models.page_payload(cursor=params.get("cursor"),
                                                    has_more=has_more,
                                                    next_cursor=next_cursor)}, request_id)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.list_limits_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/risk/limits", operation_id="setRiskLimit")
    async def set_risk_limit(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request, scope=ADMIN_SCOPES["write"])
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_limit(await _body(request))
            actor = _actor(principal)
            tenant_id = _tenant(principal)
            idempotency = _idempotency(request)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    if idempotency:
                        replay = store.find_limit_by_idempotency(connection, idempotency)
                        if replay is not None:
                            if not _same_limit(replay, draft):
                                raise errors.Conflict(
                                    "幂等键已用于不同载荷（限额）",
                                    reason="idempotency_key_reused")
                            return _ok(models.limit_payload(replay), request_id,
                                       status_code=201)
                    existing = store.get_limit(
                        connection, tenant_id=tenant_id, subject_type=draft.subject_type,
                        subject_id=draft.subject_id, limit_type=draft.limit_type, lock=True)
                    if (draft.expected_version is not None
                            and (existing is None
                                 or int(existing["revision"]) != draft.expected_version)):
                        raise errors.RuleVersionConflict(
                            "限额版本冲突：expected_version 与当前 revision 不一致",
                            reason="limit_version_conflict")
                    row, _created = store.upsert_limit(
                        connection, draft, tenant_id=tenant_id, set_by=actor,
                        idempotency_key=idempotency, now=now)
            return _ok(models.limit_payload(row), request_id, status_code=201)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.set_limit_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 案件（cases ×3）
    @router.get("/api/v1/admin/risk/cases", operation_id="listRiskCases")
    def list_risk_cases(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            params = request.query_params
            status = params.get("status") or None
            if status is not None and status not in facts.CASE_STATUSES:
                raise errors.BadRequest(
                    f"status 必须是 {list(facts.CASE_STATUSES)} 之一", field="status")
            subject = params.get("subject") or None
            if subject is not None:
                subject = models.require_subject_hash(subject, field_name="subject")
            limit = _limit(params.get("limit"))
            with _connection() as connection:
                rows, has_more, next_cursor = store.list_cases(
                    connection, tenant_id=_tenant(principal), status=status, subject=subject,
                    cursor=params.get("cursor"), limit=limit)
            data = [models.case_payload(row) for row in rows]
            return _ok({"data": data,
                        "page": models.page_payload(cursor=params.get("cursor"),
                                                    has_more=has_more,
                                                    next_cursor=next_cursor)}, request_id)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.list_cases_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.get("/api/v1/admin/risk/cases/{id}", operation_id="getRiskCase")
    def get_risk_case(id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            with _connection() as connection:
                row = cases_service.require_case(
                    connection, id, tenant_id=_tenant(principal))
                detail = cases_service.case_detail(connection, row)
            return _ok(detail, request_id)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.get_case_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/risk/cases/{id}/decisions", operation_id="decideRiskCase")
    async def decide_risk_case(id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request, scope=ADMIN_SCOPES["write"])
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_decision(await _body(request))
            actor = _actor(principal)
            tenant_id = _tenant(principal)
            idempotency = _idempotency(request)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    row = cases_service.require_case(connection, id,
                                                     tenant_id=tenant_id, lock=True)
                    updated, decision, _replayed = cases_service.decide(
                        connection, row, draft, actor=actor, now=now,
                        idempotency_key=idempotency)
                    # INV-07：处置必须同时写审计（sink 抛错 → 事务回滚，fail-closed）
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action=draft.action, object_type="risk_case",
                        object_id=str(row["case_id"]), actor=actor, reason=draft.reason,
                        occurred_at=now, details={"proposal_id": decision.get("proposal_id")}))
            return _ok(decision, request_id, status_code=201)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.decide_case_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 申诉（appeals ×2）
    @router.post("/api/v1/admin/risk/appeals", operation_id="createRiskAppeal")
    async def create_risk_appeal(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request, scope=ADMIN_SCOPES["write"])
            draft = models.parse_appeal(await _body(request))
            actor = _actor(principal)
            tenant_id = _tenant(principal)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    case = cases_service.require_case(connection, draft.case_id,
                                                      tenant_id=tenant_id, lock=True)
                    appeal = appeals_service.submit(connection, case, draft, actor=actor,
                                                    now=now)
            return _ok(models.appeal_payload(appeal), request_id, status_code=201)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.create_appeal_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/risk/appeals/{id}/decide", operation_id="decideRiskAppeal")
    async def decide_risk_appeal(id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request, scope=ADMIN_SCOPES["write"])
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_appeal_decision(await _body(request))
            actor = _actor(principal)
            tenant_id = _tenant(principal)
            idempotency = _idempotency(request)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    appeal = appeals_service.require_appeal(connection, id,
                                                            tenant_id=tenant_id, lock=True)
                    if idempotency and appeal.get("idempotency_key") == idempotency:
                        if appeal.get("outcome") == draft.outcome:
                            return _ok(models.appeal_payload(appeal), request_id)
                        raise errors.Conflict("幂等键已用于不同裁决结果",
                                              reason="idempotency_key_reused")
                    case = cases_service.require_case(connection, str(appeal["case_id"]),
                                                      tenant_id=tenant_id, lock=True)
                    decided, _case, _escalated = appeals_service.decide(
                        connection, appeal, case, draft, actor=actor, now=now,
                        idempotency_key=idempotency)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action=f"appeal_{draft.outcome}", object_type="risk_appeal",
                        object_id=str(appeal["appeal_id"]), actor=actor,
                        reason=draft.reason, occurred_at=now,
                        details={"case_id": str(case["case_id"])}))
            return _ok(models.appeal_payload(decided), request_id)
        except errors.RiskError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("risk.http.decide_appeal_failed", extra={"request_id": request_id})
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    return router


def _same_limit(current: Mapping[str, Any], draft: models.LimitDraft) -> bool:
    """同幂等键重放：载荷必须一致（否则 409/40919，不静默覆盖）。"""
    current_expiry = current.get("expires_at")
    if isinstance(current_expiry, datetime):
        current_expiry = clock.iso(current_expiry)
    draft_expiry = clock.iso(draft.expires_at) if draft.expires_at is not None else None
    return (str(current.get("subject_type")) == draft.subject_type
            and str(current.get("subject_id")) == draft.subject_id
            and str(current.get("limit_type")) == draft.limit_type
            and int(current.get("value") or 0) == draft.value
            and int(current.get("window_s") or 0) == draft.window_s
            and current_expiry == draft_expiry)


def _same_rule(current: Mapping[str, Any], draft: models.RuleDraft) -> bool:
    """同 rule_key 的最新版本与请求完全一致 → 视为重放（不新增版本）。"""
    return (bool(current.get("enabled")) == bool(draft.enabled)
            and current.get("severity") == draft.severity
            and current.get("action_class") == draft.action_class
            and (current.get("config_ref") or None) == (draft.config_ref or None))

