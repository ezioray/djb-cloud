# SPDX-License-Identifier: Apache-2.0
"""M08 HTTP 路由工厂（**不接 app/api.py** —— 由 Lead 合并时统一 include）。

严格对齐 spec 1.2.5 的 M08 段：**17 路径 / 21 操作，operationId 逐字一致**（route-vs-spec 差集 0）::

    POST /api/v1/pay/orders                                    createPaymentOrder          201
    GET  /api/v1/pay/orders/{id}                               getPaymentOrder             200
    POST /api/v1/pay/webhooks/{provider}                       receivePaymentWebhook       200
    POST /api/v1/pay/refund-requests                           createRefundRequest         201
    GET  /api/v1/provider/payouts                              listProviderPayouts         200
    POST /api/v1/provider/payout-address                       updateProviderPayoutAddress 200
    GET  /api/v1/admin/treasury/pools                          listTreasuryPools           200
    POST /api/v1/admin/treasury/pools                          createTreasuryPool          201
    POST /api/v1/admin/treasury/provision                      provisionTreasuryWallets    201
    POST /api/v1/admin/treasury/activate/{batch}               activateTreasuryBatch       200
    POST /api/v1/admin/treasury/switch                         switchTreasuryWallet        200
    POST /api/v1/admin/treasury/retire                         retireTreasuryWallet        200
    POST /api/v1/admin/treasury/payouts                        createTreasuryPayoutBatch   201
    POST /api/v1/admin/treasury/payouts/{id}/approve           approveTreasuryPayoutBatch  200
    POST /api/v1/admin/treasury/payouts/{id}/sign-request      requestTreasuryPayoutSignature 201
    GET  /api/v1/admin/treasury/addresses                      listTreasuryAddresses       200
    POST /api/v1/admin/treasury/addresses                      upsertTreasuryAddress       201
    GET  /api/v1/admin/treasury/deposit-address                getTreasuryDepositAddress   200
    POST /api/v1/admin/treasury/deposit-address                publishTreasuryDepositAddress 200
    GET  /api/v1/admin/treasury/gas-policy                     getTreasuryGasPolicy        200
    POST /api/v1/admin/treasury/gas-policy                     updateTreasuryGasPolicy     200

约定（00-conventions §5 / spec Error）：

* 错误信封 {"error": {type, code, message, request_id}}，code 是**整数**且已登记；
* 任何响应回显 X-Request-Id；请求体自己校验（未知字段拒绝）；
* 写接口的 X-DJB-Idempotency-Key（16..128）命中即返回首次结果；
* 回调错误按 Lead 2026-10-24 裁决：验签失败 400/40001、重复回调 409/40910、
  金额 / 币种不符 409/40911；
* 依赖注入钩子默认 **fail-closed**：

    user_resolver     用户会话（M01）→ {"account_id", "tenant_id"}
    provider_resolver 共享方会话（可选；缺省用 user_resolver）
    admin_resolver    管理面会话 → {"admin_id", "tenant_id", "scopes"}
    step_up_verifier  敏感操作二次认证（≤5 分钟）；未接线时只校验请求头存在
    connection_factory 请求级连接（合并时注入 app.db.conn）
    ledger_poster     M06 posting API 适配器（未接线 → 入账 fail-closed）
    attestation_verifier M09 出款前校验（未接线 → 视为无效 → 40916）
    revenue_verifier  累计已确认收入 ≥ 本批应付（未接线 → 跳过）
    risk_check / consumed_provider   M11 风控 / M05 已消耗金额（未接线 → 不伪造判定）
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

from . import audit as audit_hook
from . import clock, config_source, errors, facts, ledger, models, order as order_service
from . import payout as payout_service
from . import provider as provider_mod
from . import refund as refund_service
from . import store, wallet as wallet_service

log = logging.getLogger("djb.treasury.http")

IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
STEP_UP_HEADER = "X-Admin-Step-Up"
REQUEST_ID_HEADER = "X-Request-Id"
MAX_BODY_BYTES = facts.MAX_BODY_BYTES

Principal = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
StepUpVerifier = Callable[[Request], "bool | Awaitable[bool]"]

#: 管理面权限点（产品 §19.11.2；角色 → scope 的映射在 M01 接线时完成）
SCOPE_READ = "treasury.read"
SCOPE_WALLET_READ = "treasury.wallet.read"
SCOPE_PROVISION = "treasury.wallet.provision"
SCOPE_ACTIVATE = "treasury.wallet.activate"
SCOPE_SWITCH = "treasury.wallet.switch"
SCOPE_RETIRE = "treasury.wallet.retire"
SCOPE_PAYOUT_PROPOSE = "treasury.payout.propose"
SCOPE_PAYOUT_APPROVE = "treasury.payout.approve"
SCOPE_PAYOUT_SIGN = "treasury.payout.sign.request"
SCOPE_ADDRESS_APPROVE = "treasury.address.approve"
SCOPE_POLICY_PUBLISH = "treasury.policy.publish"
SCOPE_DEPOSIT_PUBLISH = "treasury.deposit_address.publish"


# ───────────────────────────────────────────────────────────── 基础工具
def _request_id(request: Request) -> str:
    value = (request.headers.get(REQUEST_ID_HEADER) or "").strip()
    return value or str(uuid.uuid4())


def _ok(payload: Any, request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code,
                        headers={REQUEST_ID_HEADER: request_id})


def _fail(exc: errors.TreasuryError, request_id: str) -> JSONResponse:
    return JSONResponse(exc.as_envelope(request_id), status_code=exc.status_code,
                        headers={REQUEST_ID_HEADER: request_id})


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise errors.BadRequest("请求体超过上限（64KB）", field="body")
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise errors.BadRequest("请求体必须是合法 JSON") from exc
    if not isinstance(payload, dict):
        raise errors.BadRequest("请求体必须是 JSON 对象")
    return payload


async def _resolve(resolver: Principal | None, request: Request) -> dict[str, Any]:
    if resolver is None:
        raise errors.Unauthorized("M08 鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, Mapping) or not resolved:
        raise errors.Unauthorized("鉴权返回非法主体")
    return dict(resolved)


def _resolve_sync(resolver: Principal | None, request: Request) -> dict[str, Any]:
    if resolver is None:
        raise errors.Unauthorized("M08 鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):                     # pragma: no cover - 接线错误
        resolved.close()
        raise errors.Unauthorized("鉴权钩子在同步端点上返回了 awaitable")
    if not isinstance(resolved, Mapping) or not resolved:
        raise errors.Unauthorized("鉴权返回非法主体")
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


async def _admin(resolver: Principal | None, request: Request, *, scope: str
                 ) -> dict[str, Any]:
    principal = await _resolve(resolver, request)
    _require_scope(principal, scope)
    if not (principal.get("admin_id") or principal.get("admin") or principal.get("sub")):
        raise errors.Unauthorized("鉴权主体缺少 admin_id（fail-closed）")
    return principal


def _admin_sync(resolver: Principal | None, request: Request, *, scope: str) -> dict[str, Any]:
    principal = _resolve_sync(resolver, request)
    _require_scope(principal, scope)
    if not (principal.get("admin_id") or principal.get("admin") or principal.get("sub")):
        raise errors.Unauthorized("鉴权主体缺少 admin_id（fail-closed）")
    return principal


def _actor(principal: Mapping[str, Any]) -> str:
    return str(principal.get("admin_id") or principal.get("admin") or principal.get("sub"))


def _account(principal: Mapping[str, Any]) -> str:
    value = principal.get("account_id") or principal.get("account")
    if not value:
        raise errors.Unauthorized("鉴权主体缺少 account_id（fail-closed）")
    return str(value)


async def _require_step_up(verifier: StepUpVerifier | None, request: Request) -> None:
    value = (request.headers.get(STEP_UP_HEADER) or "").strip()
    if not value:
        raise errors.StepUpRequired()
    if verifier is None:
        return
    result = verifier(request)
    if inspect.isawaitable(result):
        result = await result
    if not result:
        raise errors.StepUpRequired("step-up 已过期或无效：请重新完成二次认证")


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


def _time_param(raw: str | None, *, field: str) -> datetime | None:
    return None if not raw else clock.parse_datetime(raw, field=field)


def _db_error(exc: Exception) -> errors.TreasuryError | None:
    """库层护栏 → 契约码（库层是最后一道防线，不是常规路径）。"""
    if isinstance(exc, psycopg.errors.UniqueViolation):
        constraint = getattr(getattr(exc, "diag", None), "constraint_name", None) or ""
        if "uq_refund_open" in constraint:
            return errors.RefundInProgress("该订单已有未结退款（40917）",
                                           reason="refund_in_progress")
        if "payout_addresses" in constraint or "deposit_address" in constraint:
            return errors.AddressConflict("地址冲突（40915）", reason="address_conflict")
        if "idem" in constraint:
            return errors.Conflict("幂等键已用于不同载荷", reason="idempotency_key_reused")
        return errors.Conflict("唯一约束冲突：请查询既有对象或换幂等键", reason="unique_conflict")
    if isinstance(exc, psycopg.errors.CheckViolation):
        return errors.Conflict("库层护栏拒绝写入（状态机 / 不变量不满足）",
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
                  user_resolver: Principal | None = None,
                  provider_resolver: Principal | None = None,
                  admin_resolver: Principal | None = None,
                  step_up_verifier: StepUpVerifier | None = None,
                  now_provider: Callable[[], datetime] | None = None,
                  config_provider: Callable[[], config_source.ConfigProvider | None] | None = None,
                  ledger_poster: ledger.LedgerPoster | None = None,
                  provider_registry: provider_mod.ProviderRegistry | None = None,
                  address_allocator: wallet_service.AddressAllocator | None = None,
                  attestation_verifier: Callable[[str], bool] | None = None,
                  revenue_verifier: Callable[[int], Any] | None = None,
                  risk_check: Callable[..., Any] | None = None,
                  consumed_provider: Callable[[str], int] | None = None,
                  audit_sink: audit_hook.AuditSink | None = None,
                  ) -> APIRouter:
    """构造 M08 路由（用户 / 共享方 / 管理面 / 回调；21 个操作）。"""
    router = APIRouter(tags=["Treasury"])
    now_source = now_provider or clock.utcnow
    registry = provider_registry or provider_mod.build_registry()
    allocator = address_allocator or wallet_service.SyntheticAddressAllocator()

    def _connection() -> Any:
        return connection_factory()

    def _cfg_provider() -> config_source.ConfigProvider | None:
        return config_provider() if config_provider is not None else None

    def _attestation_valid(ref: str | None) -> bool:
        if not ref or attestation_verifier is None:
            return False
        return bool(attestation_verifier(ref))

    def _shared_principal(request: Request) -> dict[str, Any]:
        resolver = provider_resolver or user_resolver
        return _resolve_sync(resolver, request)

    def _shared_principal_async(request: Request) -> Any:
        resolver = provider_resolver or user_resolver
        return _resolve(resolver, request)

    # ─────────────────────────────────────────────── 用户：订单
    @router.post("/api/v1/pay/orders", operation_id="createPaymentOrder")
    async def create_payment_order(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _resolve(user_resolver, request)
            draft = models.parse_order(await _body(request), account_id=_account(principal))
            idempotency = _idempotency(request)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = order_service.create_order(
                        connection, draft, account_id=_account(principal),
                        tenant_id=(str(principal.get("tenant_id"))
                                   if principal.get("tenant_id") else None),
                        idempotency_key=idempotency, provider_registry=registry,
                        config=config_source.load(_cfg_provider(), role="hot",
                                                  fund_class="CLIENT"),
                        ledger_poster=ledger_poster, now=now, trace_id=request_id,
                        created_by=_account(principal), risk_check=risk_check)
            return _ok(models.order_payload(result["order"]), request_id, status_code=201)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.create_order_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.get("/api/v1/pay/orders/{id}", operation_id="getPaymentOrder")
    def get_payment_order(id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _resolve_sync(user_resolver, request)
            with _connection() as connection:
                payload = order_service.get_order_view(
                    connection, id, account_id=_account(principal))
            return _ok(payload, request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.get_order_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 回调（独立端点，无用户鉴权）
    @router.post("/api/v1/pay/webhooks/{provider}", operation_id="receivePaymentWebhook")
    async def receive_payment_webhook(provider: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            raw = await request.body()
            if len(raw) > MAX_BODY_BYTES:
                raise errors.BadRequest("回调 body 超过上限（64KB）", field="body")
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = order_service.handle_webhook(
                        connection, provider_name=provider, raw_body=raw,
                        headers=dict(request.headers), provider_registry=registry,
                        config=config_source.load(_cfg_provider(), role="hot",
                                                  fund_class="CLIENT"),
                        ledger_poster=ledger_poster, now=now, trace_id=request_id)
            attempt = result.get("attempt") or {}
            return _ok(models.webhook_ack_payload(
                order=result.get("order"), duplicate=bool(result.get("duplicate")),
                provider_txn_id=attempt.get("provider_txn_id")), request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.webhook_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 用户：退款申请
    @router.post("/api/v1/pay/refund-requests", operation_id="createRefundRequest")
    async def create_refund_request(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _resolve(user_resolver, request)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_refund(await _body(request), account_id=_account(principal))
            idempotency = _idempotency(request)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = refund_service.create_refund_request(
                        connection, draft, account_id=_account(principal),
                        requested_by=_account(principal), idempotency_key=idempotency,
                        config=config_source.load(_cfg_provider(), role="warm",
                                                  fund_class="CLIENT"),
                        consumed_provider=consumed_provider, risk_check=risk_check, now=now)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="refund_request", object_type="refund_request",
                        object_id=str(result["refund"]["refund_request_id"]),
                        actor=_account(principal), reason=draft.reason_code,
                        occurred_at=now,
                        details={"order_no": draft.order_no,
                                 "amount_minor": int(draft.amount_minor)}))
            return _ok(models.refund_payload(result["refund"]), request_id, status_code=201)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.create_refund_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 共享方
    @router.get("/api/v1/provider/payouts", operation_id="listProviderPayouts")
    def list_provider_payouts(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = _shared_principal(request)
            params = request.query_params
            with _connection() as connection:
                items, has_more, next_cursor = payout_service.provider_payouts(
                    connection, account_id=_account(principal),
                    status=params.get("status") or None,
                    from_ts=_time_param(params.get("from"), field="from"),
                    to_ts=_time_param(params.get("to"), field="to"),
                    cursor=params.get("cursor"), limit=_limit(params.get("limit")))
            return _ok({"data": items, "page": models.page_payload(
                cursor=params.get("cursor"), has_more=has_more,
                next_cursor=next_cursor)}, request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.provider_payouts_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/provider/payout-address", operation_id="updateProviderPayoutAddress")
    async def update_provider_payout_address(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _shared_principal_async(request)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_address(await _body(request),
                                        account_id=_account(principal))
            idempotency = _idempotency(request)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = payout_service.submit_payout_address(
                        connection, draft, idempotency_key=idempotency, now=now)
            return _ok(models.address_payload(result["address"]), request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.update_payout_address_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 管理面：池
    @router.get("/api/v1/admin/treasury/pools", operation_id="listTreasuryPools")
    def list_treasury_pools(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _admin_sync(admin_resolver, request, scope=SCOPE_WALLET_READ)
            params = request.query_params
            with _connection() as connection:
                pools = wallet_service.list_pools(
                    connection, config_provider=_cfg_provider(),
                    status=params.get("status") or None, role=params.get("role") or None)
                data = []
                for pool in pools:
                    detail = wallet_service.pool_detail(
                        connection, pool["pool_id"], config_provider=_cfg_provider())
                    data.append(detail)
            limit = _limit(params.get("limit"))
            has_more = len(data) > limit
            return _ok({"data": data[:limit], "page": models.page_payload(
                cursor=params.get("cursor"), has_more=has_more,
                next_cursor=None)}, request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.list_pools_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/pools", operation_id="createTreasuryPool")
    async def create_treasury_pool(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_POLICY_PUBLISH)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_pool(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = wallet_service.create_pool(
                        connection, draft, actor=_actor(principal), now=now,
                        idempotency_key=_idempotency(request),
                        config_provider=_cfg_provider())
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="pool_create", object_type="wallet_pool",
                        object_id=str(result["pool"]["pool_id"]), actor=_actor(principal),
                        reason=draft.reason or "create", occurred_at=now,
                        details={"role": draft.role, "fund_class": draft.fund_class,
                                 "max_active": draft.max_active}))
            return _ok(models.pool_payload(result["pool"]), request_id, status_code=201)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.create_pool_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/provision", operation_id="provisionTreasuryWallets")
    async def provision_treasury_wallets(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_PROVISION)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_provision(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = wallet_service.provision(
                        connection, draft, actor=_actor(principal),
                        idempotency_key=_idempotency(request), config_provider=_cfg_provider(),
                        allocator=allocator, now=now, trace_id=request_id)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="wallet_provision", object_type="wallet_provision_batch",
                        object_id=str(result["batch"]["batch_id"]), actor=_actor(principal),
                        reason="provision", occurred_at=now,
                        details={"pool_id": draft.pool_id,
                                 "count": int(result["batch"]["wallet_count"])}))
            return _ok(models.provision_batch_payload(result["batch"]), request_id,
                       status_code=201)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.provision_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/activate/{batch}", operation_id="activateTreasuryBatch")
    async def activate_treasury_batch(batch: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_ACTIVATE)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_activate(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = wallet_service.activate_batch(
                        connection, batch, actor=_actor(principal), now=now,
                        signing_request_id=draft.signing_request_id, trace_id=request_id)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="wallet_activate", object_type="wallet_provision_batch",
                        object_id=str(result["batch"]["batch_id"]), actor=_actor(principal),
                        reason=draft.reason or "2-of-3 signed", occurred_at=now,
                        details={"wallet_count": len(result["wallets"]),
                                 "descriptor_merkle_root":
                                     result["batch"]["descriptor_merkle_root"]}))
            return _ok(models.provision_batch_payload(result["batch"]), request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.activate_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/switch", operation_id="switchTreasuryWallet")
    async def switch_treasury_wallet(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_SWITCH)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_switch(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = wallet_service.switch_address(
                        connection, draft, actor=_actor(principal),
                        config_provider=_cfg_provider(), now=now, trace_id=request_id)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="wallet_switch", object_type="wallet_pool",
                        object_id=draft.pool_id, actor=_actor(principal),
                        reason=draft.reason, occurred_at=now))
            return _ok(result["ack"], request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.switch_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/retire", operation_id="retireTreasuryWallet")
    async def retire_treasury_wallet(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_RETIRE)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_retire(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = wallet_service.retire_wallet(
                        connection, draft, actor=_actor(principal),
                        attestation_valid=_attestation_valid(draft.attestation_ref), now=now,
                        trace_id=request_id)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action=f"wallet_retire_{draft.step}", object_type="wallet",
                        object_id=draft.wallet_id, actor=_actor(principal),
                        reason=draft.reason or draft.step, occurred_at=now,
                        details={"status": result.get("status")}))
            return _ok(result, request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.retire_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 管理面：出款
    @router.post("/api/v1/admin/treasury/payouts", operation_id="createTreasuryPayoutBatch")
    async def create_treasury_payout_batch(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_PAYOUT_PROPOSE)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_payout_batch(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = payout_service.create_payout_batch(
                        connection, draft, maker=_actor(principal),
                        idempotency_key=_idempotency(request),
                        config_provider=_cfg_provider(), now=now, trace_id=request_id)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="payout_propose", object_type="payout_batch",
                        object_id=str(result["batch"]["batch_id"]), actor=_actor(principal),
                        reason="propose", occurred_at=now,
                        details={"item_count": int(result["batch"]["item_count"]),
                                 "total_net_minor": int(result["batch"]["total_net_minor"])}))
            return _ok(models.payout_batch_payload(result["batch"], result["items"]),
                       request_id, status_code=201)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.create_payout_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/payouts/{id}/approve",
                 operation_id="approveTreasuryPayoutBatch")
    async def approve_treasury_payout_batch(id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_PAYOUT_APPROVE)
            await _require_step_up(step_up_verifier, request)
            parsed = models.parse_payout_approve(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = payout_service.approve_payout_batch(
                        connection, id, checker=_actor(principal),
                        attestation_checker=_attestation_valid,
                        revenue_verifier=revenue_verifier, now=now, note=parsed.get("note"))
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="payout_approve", object_type="payout_batch",
                        object_id=str(result["batch"]["batch_id"]), actor=_actor(principal),
                        reason=parsed.get("note") or "attestation verified", occurred_at=now,
                        details={"total_net_minor": int(result["batch"]["total_net_minor"])}))
            return _ok(models.payout_batch_payload(result["batch"], result["items"]),
                       request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.approve_payout_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/payouts/{id}/sign-request",
                 operation_id="requestTreasuryPayoutSignature")
    async def request_treasury_payout_signature(id: str, request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_PAYOUT_SIGN)
            await _require_step_up(step_up_verifier, request)
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = payout_service.request_payout_signature(
                        connection, id, actor=_actor(principal), now=now, trace_id=request_id,
                        idempotency_key=_idempotency(request))
            intent = result.get("intent") or {}
            return _ok(models.signing_request_payload(
                result["signing_request"], auth_hash=intent.get("auth_hash")),
                request_id, status_code=201)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.payout_sign_request_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 管理面：白名单
    @router.get("/api/v1/admin/treasury/addresses", operation_id="listTreasuryAddresses")
    def list_treasury_addresses(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _admin_sync(admin_resolver, request, scope=SCOPE_READ)
            params = request.query_params
            chain = params.get("chain") or None
            status = params.get("status") or None
            if status is not None and status not in facts.PAYOUT_ADDRESS_STATUSES:
                raise errors.BadRequest(
                    f"status 必须是 {list(facts.PAYOUT_ADDRESS_STATUSES)} 之一", field="status")
            with _connection() as connection:
                items = payout_service.list_payout_addresses(connection)
            if chain is not None:
                items = [item for item in items if item.get("chain") == chain]
            if status is not None:
                items = [item for item in items if item.get("status") == status]
            limit = _limit(params.get("limit"))
            has_more = len(items) > limit
            return _ok({"data": items[:limit], "page": models.page_payload(
                cursor=params.get("cursor"), has_more=has_more, next_cursor=None)},
                request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.list_addresses_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/addresses", operation_id="upsertTreasuryAddress")
    async def upsert_treasury_address(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_ADDRESS_APPROVE)
            await _require_step_up(step_up_verifier, request)
            body = await _body(request)
            draft = models.parse_address(body, account_id="")
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    existing = store.get_payout_address(connection, draft.address)
                    if existing is None:
                        raise errors.PayeeNotEligible(
                            "出款主体未通过准入：地址须先由共享方提交（42210）",
                            reason="payee_not_eligible")
                    result = payout_service.approve_payout_address(
                        connection, str(existing["address_id"]),
                        approver=_actor(principal), risk_check=risk_check, now=now)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="address_upsert", object_type="payout_address",
                        object_id=str(result["address"]["address_id"]),
                        actor=_actor(principal), reason=draft.label or "whitelist",
                        occurred_at=now))
            return _ok(models.address_payload(result["address"]), request_id, status_code=201)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.upsert_address_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    # ─────────────────────────────────────────────── 管理面：平台收款地址 / gas
    @router.get("/api/v1/admin/treasury/deposit-address",
                operation_id="getTreasuryDepositAddress")
    def get_treasury_deposit_address(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _admin_sync(admin_resolver, request, scope=SCOPE_READ)
            chain = request.query_params.get("chain") or facts.CHAIN_ID
            with _connection() as connection:
                payload = wallet_service.get_deposit_address_view(connection, chain_id=chain)
            return _ok(payload, request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.get_deposit_address_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/deposit-address",
                 operation_id="publishTreasuryDepositAddress")
    async def publish_treasury_deposit_address(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_DEPOSIT_PUBLISH)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_deposit_address(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    payload = wallet_service.publish_platform_deposit_address(
                        connection, draft, actor=_actor(principal), now=now)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="deposit_address_publish", object_type="deposit_address",
                        object_id=str(payload["address"]), actor=_actor(principal),
                        reason=draft.reason, occurred_at=now,
                        details={"chain": draft.chain, "ticket": draft.ticket}))
            return _ok(payload, request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.publish_deposit_address_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.get("/api/v1/admin/treasury/gas-policy", operation_id="getTreasuryGasPolicy")
    def get_treasury_gas_policy(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            _admin_sync(admin_resolver, request, scope=SCOPE_READ)
            with _connection() as connection:
                payload = payout_service.gas_policy_view(
                    connection, config_provider=_cfg_provider(),
                    now=clock.as_utc(now_source()))
            return _ok(payload, request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.gas_policy_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    @router.post("/api/v1/admin/treasury/gas-policy", operation_id="updateTreasuryGasPolicy")
    async def update_treasury_gas_policy(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            principal = await _admin(admin_resolver, request, scope=SCOPE_POLICY_PUBLISH)
            await _require_step_up(step_up_verifier, request)
            draft = models.parse_gas_policy(await _body(request))
            now = clock.as_utc(now_source())
            with _connection() as connection:
                with connection.transaction():
                    result = payout_service.propose_gas_policy(
                        connection, draft, actor=_actor(principal),
                        config_provider=_cfg_provider(), now=now, trace_id=request_id)
                    audit_hook.emit(audit_sink, audit_hook.AuditRecord(
                        action="gas_policy_propose", object_type="treasury_intent",
                        object_id=str(result["intent"]["intent_id"]),
                        actor=_actor(principal), reason=draft.reason or "gas policy",
                        occurred_at=now,
                        details={"gas_mode": draft.gas_mode, "scope": draft.scope}))
            return _ok(result["policy"], request_id)
        except errors.TreasuryError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                      # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("treasury.http.update_gas_policy_failed")
            return _fail(errors.ServerError("服务端未就绪：请稍后重试"), request_id)

    return router

