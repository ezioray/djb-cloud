# SPDX-License-Identifier: Apache-2.0
"""M09 HTTP 路由工厂（**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 spec 1.2.3 的 8 条 recon 端点 + 本轮实现的 2 条报表端点::

    GET  /api/v1/admin/treasury/recon/runs                        listReconRuns
    GET  /api/v1/admin/treasury/recon/runs/{run_id}               getReconRun
    POST /api/v1/admin/treasury/recon/runs/{run_id}/sign-off      signOffReconRun
    GET  /api/v1/admin/treasury/recon/exceptions                  listReconExceptions
    POST /api/v1/admin/treasury/recon/exceptions/{id}/resolve     resolveReconException
    POST /api/v1/admin/treasury/recon/attestations                submitReconAttestation
    GET  /api/v1/admin/treasury/recon/attestations/{id}           getReconAttestation
    GET  /api/v1/admin/treasury/recon/attestations/{id}/validate  validateReconAttestation（服务间）
    GET  /api/v1/admin/reports/recon-daily                        REP-01
    GET  /api/v1/admin/reports/exceptions                         REP-02

**未注册**（T4，依赖未合并的 M08 / PoR）：``/reports/por``、``/reports/wallet-pool``、
``/reports/monthly``、``/reports/{id}/renders/{period}.svg|.pdf``。不注册 = 不会返回假数据。

约定（00-conventions §5 / spec ``Error``）：
* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是整数且已登记；
* 任何响应都回显 ``X-Request-Id``；
* 写接口的 ``X-DJB-Idempotency-Key``（16..128）命中即返回首次结果；缺省时不做跨请求重放
  （状态机本身会挡住重复：已签核再签 49203 / 已关闭再处置 49204）。

接线（三个依赖注入钩子，默认 **fail-closed**）::

    admin_resolver    管理面会话（M01）→ {"admin_id", "tenant_id", "scopes"}
    service_resolver  服务间身份（mTLS / 服务令牌）→ {"service_id", "scopes"}
    step_up_verifier  敏感操作二次认证（≤5 分钟）；未接线时只校验请求头是否存在
"""
from __future__ import annotations

import dataclasses
import inspect
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import attestation as attestations
from . import clock, engine, errors, facts, models, reports, store

log = logging.getLogger("djb.recon.http")

IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
STEP_UP_HEADER = "X-Admin-Step-Up"
REQUEST_ID_HEADER = "X-Request-Id"

Principal = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
StepUpVerifier = Callable[[Request], "bool | Awaitable[bool]"]

#: 管理面 scope 名（M01 角色 → scope 的映射在接线性时完成）
ADMIN_SCOPES = {"read": "recon.read", "write": "recon.write"}


# --------------------------------------------------------------------------- 基础工具
def _request_id(request: Request) -> str:
    value = (request.headers.get(REQUEST_ID_HEADER) or "").strip()
    return value or str(uuid.uuid4())


def _ok(payload: Any, request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code,
                        headers={REQUEST_ID_HEADER: request_id})


def _fail(exc: errors.ReconError, request_id: str) -> JSONResponse:
    return JSONResponse(exc.as_envelope(request_id), status_code=exc.status_code,
                        headers={REQUEST_ID_HEADER: request_id})


def _server_error(request_id: str) -> JSONResponse:
    return _fail(errors.ServiceUnavailable("服务端未就绪：请稍后重试", reason="server_error"),
                 request_id)


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise errors.BadRequest("请求体必须是合法 JSON") from exc
    if not isinstance(payload, dict):
        raise errors.BadRequest("请求体必须是 JSON 对象")
    return payload


async def _principal(resolver: Principal | None, request: Request, *, what: str) -> dict[str, Any]:
    """fail-closed 主体解析：未接线即 401，主体非法即 401。"""
    if resolver is None:
        raise errors.Unauthorized(f"{what}鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, dict) or not resolved:
        raise errors.Unauthorized(f"{what}鉴权返回非法主体")
    return resolved


def _require_scope(principal: dict[str, Any], scope: str) -> None:
    """``scopes`` 缺省视为上游已授权；给了就必须命中（或 ``*``）。"""
    scopes = principal.get("scopes")
    if scopes is None:
        return
    if isinstance(scopes, str):
        scopes = [item.strip() for item in scopes.split(",") if item.strip()]
    if "*" in scopes or scope in scopes:
        return
    raise errors.Forbidden(f"缺少 scope：{scope}")


async def _require_step_up(verifier: StepUpVerifier | None, request: Request) -> None:
    """step-up 缺失 / 过期 → 424 + 42401（spec `StepUpRequired`）。"""
    value = (request.headers.get(STEP_UP_HEADER) or "").strip()
    if not value:
        raise errors.StepUpRequired()
    if verifier is None:
        return                                   # 未接线：存在性校验（真实校验由 M01 接线）
    result = verifier(request)
    if inspect.isawaitable(result):
        result = await result
    if not result:
        raise errors.StepUpRequired("step-up 已过期或无效：请重新完成二次认证")


def _tenant(principal: dict[str, Any]) -> str | None:
    value = principal.get("tenant_id")
    return str(value) if value else None


def _idempotency(request: Request) -> str | None:
    """显式幂等键（16..128）；缺省返回 None —— 不跨请求猜测指纹（避免误重放）。"""
    return models.require_idempotency_key(request.headers.get(IDEMPOTENCY_HEADER))


def _db_error(exc: Exception) -> errors.ReconError | None:
    """库层护栏 → 契约码（库层是最后一道防线，不是常规路径）。"""
    if isinstance(exc, psycopg.errors.UniqueViolation):
        return errors.Conflict("唯一约束冲突：请查询既有对象或换幂等键", reason="unique_conflict")
    if isinstance(exc, psycopg.errors.CheckViolation):
        return errors.Conflict("库层护栏拒绝写入（状态机 / 不变式不满足）",
                               reason="guard_violation")
    if isinstance(exc, psycopg.errors.ForeignKeyViolation):
        return errors.NotFound("引用的对象不存在")
    if isinstance(exc, psycopg.errors.InvalidTextRepresentation):
        return errors.NotFound("对象不存在")
    if isinstance(exc, psycopg.OperationalError):
        return errors.ServiceUnavailable("数据库不可用：请稍后重试", reason="db_unavailable")
    return None


# --------------------------------------------------------------------------- 路由
def create_router(*, connection_factory: Callable[[], Any],
                  admin_resolver: Principal | None = None,
                  service_resolver: Principal | None = None,
                  step_up_verifier: StepUpVerifier | None = None,
                  now_provider: Callable[[], datetime] | None = None,
                  engine_deps: engine.EngineDeps | None = None) -> APIRouter:
    """构造 M09 路由（八条 recon + 两条报表）。"""
    now_source = now_provider or clock.utcnow
    deps = engine_deps or engine.EngineDeps()
    router = APIRouter(tags=["recon"])

    def _connection() -> Any:
        return connection_factory()

    # ─────────────────────────────────────────────── 批次列表 / 详情
    @router.get("/api/v1/admin/treasury/recon/runs")
    def list_recon_runs(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            params = request.query_params
            scope = params.get("scope") or None
            if scope is not None and scope not in facts.SCOPES:
                raise errors.BadRequest(f"scope 必须是 {list(facts.SCOPES)} 之一", field="scope")
            status = params.get("status") or None
            if status is not None and status not in facts.RUN_STATUSES:
                raise errors.BadRequest(f"status 必须是 {list(facts.RUN_STATUSES)} 之一",
                                        field="status")
            limit = _limit(params.get("limit"))
            from_ts = (clock.parse_datetime(params["from"], field="from")
                       if params.get("from") else None)
            to_ts = (clock.parse_datetime(params["to"], field="to")
                     if params.get("to") else None)
            with _connection() as connection:
                rows, has_more, next_cursor = store.list_runs(
                    connection, scope=scope, status=status, from_ts=from_ts, to_ts=to_ts,
                    tenant_id=_tenant(principal), cursor=params.get("cursor"), limit=limit)
            data = [models.run_payload(row) for row in rows]
            return _ok({"data": data,
                        "page": models.page_payload(rows, cursor=params.get("cursor"),
                                                    has_more=has_more,
                                                    next_cursor=next_cursor)}, request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.list_runs_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    @router.get("/api/v1/admin/treasury/recon/runs/{run_id}")
    def get_recon_run(run_id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            with _connection() as connection:
                row = store.require_run(connection, run_id, tenant_id=_tenant(principal))
                summary = store.diff_summary(connection, str(row["run_id"]))
            return _ok({"run": models.run_payload(row), "diff_summary": summary}, request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.get_run_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ─────────────────────────────────────────────── 双人签核
    @router.post("/api/v1/admin/treasury/recon/runs/{run_id}/sign-off")
    async def sign_off_recon_run(run_id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request, what="管理面")
            _require_scope(principal, ADMIN_SCOPES["write"])
            await _require_step_up(step_up_verifier, request)
            body = await _body(request)
            parsed = models.parse_sign_off(body)
            now = clock.as_utc(now_source())
            idempotency = _idempotency(request)
            reviewer = principal.get("admin_id") or principal.get("admin") or principal.get("sub")
            with _connection() as connection:
                with connection.transaction():
                    row = store.require_run(connection, run_id,
                                            tenant_id=_tenant(principal), lock=True)
                    if idempotency and row.get("signoff_idempotency_key") == idempotency:
                        return _ok(models.run_payload(row, duplicate=True), request_id)
                    if row["status"] in facts.RUN_SIGNOFF_READONLY:
                        raise errors.AlreadySignedOff(
                            f"批次已 {row['status']}：签核后只读，不得再签（M09 §3.2）")
                    pending = store.pending_p0_p1(connection, str(row["run_id"]))
                    if pending["pending"] > 0:
                        raise errors.PendingDifferencesBlockSignOff(
                            "存在未结 P0/P1 差异：不得签核（INV-03 / I-17）",
                            pending=pending["pending"], by_severity=pending["by_severity"])
                    if parsed.attestation_id:
                        attestation_row = store.get_attestation(
                            connection, parsed.attestation_id)
                        if attestation_row is None:
                            raise errors.AttestationNotFound("复核凭证不存在")
                        if attestation_row["status"] != "valid":
                            raise errors.AttestationConflict(
                                f"凭证状态为 {attestation_row['status']}：不可用于签核（INV-05）",
                                reason="attestation_not_valid")
                    maker = row.get("created_by")
                    if maker and reviewer and maker == reviewer:
                        raise errors.Conflict("复核人不得等于制单人（INV-05 双人原则）",
                                              reason="reviewer_equals_maker")
                    updated = store.update_run(
                        connection, str(row["run_id"]), status=facts.RUN_STATUS_SIGNED_OFF,
                        signed_off_by=reviewer, signed_off_at=now,
                        reviewer_note=parsed.reviewer_note,
                        signoff_idempotency_key=idempotency, now=now)
            return _ok(models.run_payload(updated, duplicate=False), request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.sign_off_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ─────────────────────────────────────────────── 差异列表 / 处置
    @router.get("/api/v1/admin/treasury/recon/exceptions")
    def list_recon_exceptions(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            params = request.query_params
            severity = params.get("severity") or None
            if severity is not None and severity not in facts.SEVERITIES:
                raise errors.BadRequest(f"severity 必须是 {list(facts.SEVERITIES)} 之一",
                                        field="severity")
            status = params.get("status") or None
            if status is not None and status not in facts.EXCEPTION_STATUSES:
                raise errors.BadRequest(
                    f"status 必须是 {list(facts.EXCEPTION_STATUSES)} 之一", field="status")
            limit = _limit(params.get("limit"))
            with _connection() as connection:
                rows, has_more, next_cursor = store.list_exceptions(
                    connection, run_id=params.get("run_id") or None, severity=severity,
                    status=status, owner=params.get("owner") or None,
                    tenant_id=_tenant(principal), cursor=params.get("cursor"), limit=limit)
            data = [models.exception_payload(row) for row in rows]
            return _ok({"data": data,
                        "page": models.page_payload(rows, cursor=params.get("cursor"),
                                                    has_more=has_more,
                                                    next_cursor=next_cursor)}, request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.list_exceptions_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    @router.post("/api/v1/admin/treasury/recon/exceptions/{exception_id}/resolve")
    async def resolve_recon_exception(exception_id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request, what="管理面")
            _require_scope(principal, ADMIN_SCOPES["write"])
            await _require_step_up(step_up_verifier, request)
            body = await _body(request)
            parsed = models.parse_resolve(body)
            now = clock.as_utc(now_source())
            idempotency = _idempotency(request)
            actor = principal.get("admin_id") or principal.get("admin") or principal.get("sub")
            with _connection() as connection:
                with connection.transaction():
                    row = store.get_exception(connection, exception_id, lock=True)
                    if row is None:
                        raise errors.NotFound("差异不存在")
                    run_row = store.require_run(connection, str(row["run_id"]),
                                                tenant_id=_tenant(principal), lock=True)
                    if idempotency and row.get("resolve_idempotency_key") == idempotency:
                        return _ok(models.exception_payload(row), request_id)
                    if parsed.resolution_journal_id:
                        _require_journal(connection, parsed.resolution_journal_id)
                    updated = store.resolve_exception_row(
                        connection, row, parsed, actor=actor, idempotency_key=idempotency,
                        now=now)
                # 事务外读一次 run，便于前端看到最新 diff（触发器已同步）
                _ = run_row
            return _ok(models.exception_payload(updated), request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.resolve_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ─────────────────────────────────────────────── 复核凭证
    @router.post("/api/v1/admin/treasury/recon/attestations")
    async def submit_recon_attestation(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _principal(admin_resolver, request, what="管理面")
            _require_scope(principal, ADMIN_SCOPES["write"])
            await _require_step_up(step_up_verifier, request)
            body = await _body(request)
            now = clock.as_utc(now_source())
            idempotency = _idempotency(request)
            draft = models.parse_attestation(body, idempotency_key=idempotency)
            if draft.tenant_id is None:
                draft = dataclasses.replace(draft, tenant_id=_tenant(principal))
            reviewer = principal.get("admin_id") or principal.get("admin") or principal.get("sub")
            with _connection() as connection:
                result = attestations.submit(connection, draft, reviewer_id=reviewer, now=now)
            return _ok(models.attestation_payload(result["attestation"],
                                                  duplicate=result["duplicate"]),
                       request_id, status_code=201)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.attestation_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    @router.get("/api/v1/admin/treasury/recon/attestations/{attestation_id}")
    def get_recon_attestation(attestation_id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            with _connection() as connection:
                row = store.get_attestation(connection, attestation_id)
            if row is None:
                raise errors.AttestationNotFound("复核凭证不存在")
            tenant = _tenant(principal)
            if tenant is not None and row.get("tenant_id") != tenant:
                raise errors.AttestationNotFound("复核凭证不存在")   # 不泄露跨租户存在性
            return _ok(models.attestation_payload(row), request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.get_attestation_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    @router.get("/api/v1/admin/treasury/recon/attestations/{attestation_id}/validate")
    def validate_recon_attestation(attestation_id: str, request: Request) -> JSONResponse:
        """服务间出款前校验：**只返回结论**（valid / status / checked_at / reasons）。"""
        request_id = _request_id(request)
        try:
            _principal_validate(service_resolver, request)
            with _connection() as connection:
                row = store.get_attestation(connection, attestation_id)
            if row is None:
                raise errors.AttestationNotFound("复核凭证不存在")
            return _ok(attestations.validate(row, now=clock.as_utc(now_source())), request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.validate_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ─────────────────────────────────────────────── 报表（本轮 2 条）
    @router.get("/api/v1/admin/reports/recon-daily")
    def get_recon_daily_report(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            period = _period(request)
            with _connection() as connection:
                payload = reports.recon_daily(connection, period=period,
                                              tenant_id=_tenant(principal),
                                              now=clock.as_utc(now_source()))
            return _ok(payload, request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.report_daily_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    @router.get("/api/v1/admin/reports/exceptions")
    def get_exception_report(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _principal_sync(admin_resolver, request, scope=ADMIN_SCOPES["read"])
            period = _period(request)
            with _connection() as connection:
                payload = reports.exceptions_report(connection, period=period,
                                                    tenant_id=_tenant(principal),
                                                    now=clock.as_utc(now_source()))
            return _ok(payload, request_id)
        except errors.ReconError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("recon.http.report_exceptions_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    return router


# --------------------------------------------------------------------------- 小工具
def _principal_sync(resolver: Principal | None, request: Request, *, scope: str) -> dict[str, Any]:
    if resolver is None:
        raise errors.Unauthorized("M09 接口鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):                   # pragma: no cover - 接线错误
        resolved.close()
        raise errors.Unauthorized("鉴权钩子在同步端点上返回了 awaitable")
    if not isinstance(resolved, dict) or not resolved:
        raise errors.Unauthorized("鉴权返回非法主体")
    _require_scope(resolved, scope)
    return resolved


def _principal_validate(resolver: Principal | None, request: Request) -> dict[str, Any]:
    """服务间身份（mTLS / 服务令牌）+ 校验 scope：缺 scope 用 49206（M08 必须拒付）。"""
    if resolver is None:
        raise errors.Unauthorized("校验接口的服务身份未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):                    # pragma: no cover - 接线错误
        resolved.close()
        raise errors.Unauthorized("鉴权钩子在同步端点上返回了 awaitable")
    if not isinstance(resolved, dict) or not resolved:
        raise errors.Unauthorized("鉴权返回非法主体")
    scopes = resolved.get("scopes")
    if scopes is None:
        return resolved
    if isinstance(scopes, str):
        scopes = [item.strip() for item in scopes.split(",") if item.strip()]
    if "*" in scopes or facts.SERVICE_SCOPES["validate"] in scopes:
        return resolved
    raise errors.AttestationValidationUnavailable(
        f"服务主体缺少 {facts.SERVICE_SCOPES['validate']}：拒绝出款（fail-closed）",
        reason="attestation_validation_unavailable")


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


def _period(request: Request) -> str:
    raw = (request.query_params.get("period") or "").strip()
    if not raw:
        raise errors.BadRequest("缺 period（必填，YYYY-MM）", field="period")
    return raw


def _require_journal(connection: Any, journal_id: str) -> None:
    """adjust_journal 必须指向一条已入账的 M06 凭证（只读校验，不写账本）。"""
    try:
        normalized = str(uuid.UUID(str(journal_id)))
    except (ValueError, AttributeError, TypeError) as exc:
        raise errors.ExceptionStateConflict("resolution_journal_id 形态非法",
                                           reason="journal_not_found") from exc
    with connection.cursor() as cur:
        cur.execute("SELECT status FROM journal_entry WHERE journal_id = %s", (normalized,))
        row = cur.fetchone()
    if row is None:
        raise errors.ExceptionStateConflict(
            "resolution_journal_id 未在账本中找到（调整分录必须先由 M06 入账）",
            reason="journal_not_found")
    if row[0] != "posted":
        raise errors.ExceptionStateConflict(
            f"resolution_journal_id 状态为 {row[0]}：只有 posted 凭证可作为处置依据",
            reason="journal_not_posted")


__all__ = ["create_router", "ADMIN_SCOPES", "IDEMPOTENCY_HEADER", "STEP_UP_HEADER",
           "REQUEST_ID_HEADER", "Principal", "StepUpVerifier"]
