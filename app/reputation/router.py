# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 HTTP 路由工厂（独立模块，**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 spec 1.2.4 里 M07 的**十条**操作::

    GET  /api/v1/user/reputation                    getMyReputation              200
    GET  /api/v1/user/reputation/events             listMyReputationEvents       200
    GET  /api/v1/user/cop                           getMyCopBalance              200
    GET  /api/v1/user/cop/ledger                    listMyCopLedger              200
    POST /api/v1/user/cop/redemptions               createCopRedemption          201
    GET  /api/v1/user/cop/redemptions/{id}          getCopRedemption             200 / 404
    POST /api/v1/user/cop/transfers                 createCopTransfer            201
    GET  /api/v1/user/cop/invites                   listMyInvites                200
    GET  /api/v1/admin/reputation/scores            listReputationScores         200
    POST /api/v1/admin/reputation/grants            createReputationGrant        201

约定（00-conventions §5 / spec ``Error``）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
  任何响应都回显 ``X-Request-Id``；
* 请求体自己校验（不依赖框架 422）：不合法一律 400 / 40001；
* **四个依赖注入钩子**（默认 fail-closed，合并时由 Lead 接线）::

    create_router(connection_factory=..., principal_resolver=..., admin_resolver=...,
                  step_up_verifier=..., config_provider=..., now_provider=...)

  - ``connection_factory() -> ContextManager[Connection]``：未接线一律 503 / 50001；
  - ``principal_resolver(request) -> {"account_id": ...}``：未接线一律 401 / 40101；
  - ``admin_resolver(request) -> {"actor": ..., "roles": [...]}``：未接线一律 401 / 40101；
    已认证但无管理角色 → **404 / 40401**（M07 §4.1「后台越权统一 40401，不泄露存在性」）；
  - ``step_up_verifier(request) -> bool``：缺 ``X-Admin-Step-Up`` 或校验不过 → 424 / 42401；
  - ``config_provider() -> ReputationConfig``：评分配置（默认取 facts 默认值）。
* 账户一律从**主体**取，绝不从请求体 / 查询串取（防越权）；SQL 再按 account_id 过滤。
"""
from __future__ import annotations

import hashlib
import inspect
import json
import logging
import uuid
from decimal import Decimal
from typing import Any, Awaitable, Callable, Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from . import clock, cop, errors, grants, invites, models, store
from .facts import DEFAULT_CONFIG, ReputationConfig
from .models import ReputationScore

log = logging.getLogger("djb.reputation.http")

Principal = Callable[[Request], "Mapping[str, Any] | Awaitable[Mapping[str, Any]]"]
ConnectionFactory = Callable[[], Any]

MAX_BODY_BYTES = 64 * 1024
IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
IDEMPOTENCY_MIN_LENGTH = 16                        # spec IdempotencyKey.minLength
IDEMPOTENCY_MAX_LENGTH = 128                       # spec IdempotencyKey.maxLength
REQUEST_ID_HEADER = "X-Request-Id"
STEP_UP_HEADER = "X-Admin-Step-Up"
APPROVER_HEADER = "X-Admin-Approver"
#: 管理角色白名单（其余角色一律 404，不泄露端点存在性）
ADMIN_ROLES = ("admin", "superadmin", "ops")
#: 缺省幂等：按请求体指纹 300s 去重（spec IdempotencyKey 描述）
FINGERPRINT_WINDOW_S = 300


def create_router(*, connection_factory: ConnectionFactory | None = None,
                  principal_resolver: Principal | None = None,
                  admin_resolver: Principal | None = None,
                  step_up_verifier: Callable[[Request], Any] | None = None,
                  config_provider: Callable[[], ReputationConfig] | None = None,
                  now_provider: Callable[[], Any] | None = None) -> APIRouter:
    """构造本模块路由（每个应用一个实例；依赖全部由调用方注入）。"""
    router = APIRouter(prefix="/api/v1", tags=["reputation"])

    def _now() -> Any:
        return now_provider() if now_provider is not None else clock.now()

    def _config() -> ReputationConfig:
        return config_provider() if config_provider is not None else DEFAULT_CONFIG

    def _connect() -> Any:
        if connection_factory is None:
            raise errors.StoreUnavailable("数据库连接未接线：合并时由 Lead 注入（fail-closed）")
        return connection_factory()

    async def _principal(request: Request) -> str:
        if principal_resolver is None:
            raise errors.AuthUnavailable("鉴权未接线：合并时由 Lead 注入（fail-closed）")
        resolved = principal_resolver(request)
        if inspect.isawaitable(resolved):
            resolved = await resolved
        if not isinstance(resolved, Mapping):
            raise errors.AuthUnavailable("鉴权返回非法主体")
        raw = resolved.get("account_id") or resolved.get("sub") or resolved.get("id")
        if not raw:
            raise errors.Unauthorized("主体缺少 account_id")
        return str(raw)

    async def _admin(request: Request) -> dict[str, Any]:
        if admin_resolver is None:
            raise errors.AuthUnavailable("管理鉴权未接线：合并时由 Lead 注入（fail-closed）")
        resolved = admin_resolver(request)
        if inspect.isawaitable(resolved):
            resolved = await resolved
        if not isinstance(resolved, Mapping):
            raise errors.AuthUnavailable("管理鉴权返回非法主体")
        actor = resolved.get("actor") or resolved.get("account_id") or resolved.get("sub")
        roles = resolved.get("roles") or resolved.get("role") or ()
        if isinstance(roles, str):
            roles = (roles,)
        if not actor:
            raise errors.Unauthorized("管理主体缺少 actor")
        # 角色大小写不敏感（M01 会话可能给 "ADMIN"，本模块常量是小写）
        if not {str(r).lower() for r in roles} & set(ADMIN_ROLES):
            raise errors.NotFound("资源不存在")               # 越权统一 404（M07 §4.1）
        return {"actor": str(actor), "roles": tuple(map(str, roles)),
                "approved_by": resolved.get("approved_by")}

    async def _step_up(request: Request) -> None:
        token = (request.headers.get(STEP_UP_HEADER) or "").strip()
        if not token:
            raise errors.StepUpRequired("该操作需要二次认证（X-Admin-Step-Up）")
        if step_up_verifier is None:
            return                                          # 未接线：只校验存在性（fail-closed 由网关）
        verdict = step_up_verifier(request)
        if inspect.isawaitable(verdict):
            verdict = await verdict
        if not verdict:
            raise errors.StepUpRequired("二次认证无效或已过期")

    # ---------------------------------------------------------------- 1) 我的信誉
    @router.get("/user/reputation")
    async def get_my_reputation(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            with _connect() as conn:
                row = store.get_score(conn, account_id)
            if row is None:
                row = _empty_profile(account_id, _config(), _now())
            return _ok(models.profile_payload(row), request_id)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.profile_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 2) 指标事件
    @router.get("/user/reputation/events")
    async def list_my_reputation_events(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            params = request.query_params
            occurred_from = clock.parse_datetime(params.get("from"))
            occurred_to = clock.parse_datetime(params.get("to"))
            if params.get("from") and occurred_from is None:
                raise errors.InvalidArgument("from 必须是 RFC 3339 时间")
            if params.get("to") and occurred_to is None:
                raise errors.InvalidArgument("to 必须是 RFC 3339 时间")
            with _connect() as conn:
                items, next_cursor = store.events_page(
                    conn, account_id, occurred_from=occurred_from, occurred_to=occurred_to,
                    limit=params.get("limit"), cursor=params.get("cursor"))
            return _ok({"data": [item.as_dict() for item in items],
                        "page": models.page_block(start_cursor=params.get("cursor"),
                                                  next_cursor=next_cursor)}, request_id)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.events_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 3) COP 余额
    @router.get("/user/cop")
    async def get_my_cop_balance(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            with _connect() as conn:
                payload = cop.balance(conn, account_id, now=_now())
            return _ok(payload.as_dict(), request_id)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.cop_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 4) COP 台账
    @router.get("/user/cop/ledger")
    async def list_my_cop_ledger(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            params = request.query_params
            with _connect() as conn:
                items, next_cursor = cop.ledger_page(
                    conn, account_id, limit=params.get("limit"), cursor=params.get("cursor"))
            return _ok({"data": [item.as_dict() for item in items],
                        "page": models.page_block(start_cursor=params.get("cursor"),
                                                  next_cursor=next_cursor)}, request_id)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.ledger_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 5) 申请兑换
    @router.post("/user/cop/redemptions")
    async def create_cop_redemption(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            body = await _body(request)
            request_key = _idempotency(request, body, scope="redeem", now=_now())
            with _connect() as conn:
                redemption = cop.redeem(conn, account_id, body.get("units"),
                                        request_id=request_key, actor=f"user:{account_id}",
                                        target=body.get("target"), now=_now())
            return _ok(redemption.as_dict(), request_id, status_code=201)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.redeem_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 6) 兑换单状态
    @router.get("/user/cop/redemptions/{id}")
    async def get_cop_redemption(id: str, request: Request) -> JSONResponse:   # noqa: A002 - spec 路径参数名
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            with _connect() as conn:
                payload = cop.redemption(conn, account_id, id)
            return _ok(payload.as_dict(), request_id)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.redemption_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 7) 转让
    @router.post("/user/cop/transfers")
    async def create_cop_transfer(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            body = await _body(request)
            request_key = _idempotency(request, body, scope="transfer", now=_now())
            with _connect() as conn:
                payload = cop.transfer(conn, account_id, str(body.get("to_account_id") or ""),
                                       body.get("units"), request_id=request_key, now=_now(),
                                       actor=f"user:{account_id}")
            return _ok(payload.as_dict(), request_id, status_code=201)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.transfer_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 8) 邀请
    @router.get("/user/cop/invites")
    async def list_my_invites(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            account_id = await _principal(request)
            params = request.query_params
            with _connect() as conn:
                overview = invites.list_overview(
                    conn, account_id, limit=params.get("limit"),
                    cursor=params.get("cursor"), invite_months=_config().invite_months)
            return _ok(overview.as_dict(), request_id)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.invites_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 9) 后台评分
    @router.get("/admin/reputation/scores")
    async def list_reputation_scores(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            await _admin(request)
            params = request.query_params
            with _connect() as conn:
                items, next_cursor = store.score_page(
                    conn, tier=params.get("tier"), min_score=params.get("min_score"),
                    limit=params.get("limit"), cursor=params.get("cursor"))
            return _ok({"data": [item.as_admin_row() for item in items],
                        "page": models.page_block(start_cursor=params.get("cursor"),
                                                  next_cursor=next_cursor)}, request_id)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.scores_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    # ---------------------------------------------------------------- 10) 人工授予
    @router.post("/admin/reputation/grants")
    async def create_reputation_grant(request: Request) -> JSONResponse:
        request_id = _request_id(request)
        try:
            admin = await _admin(request)
            await _step_up(request)
            body = await _body(request)
            request_key = _idempotency(request, body, scope="grant", now=_now())
            approver = (request.headers.get(APPROVER_HEADER) or "").strip() \
                or body.get("approved_by") or admin.get("approved_by")
            with _connect() as conn:
                payload = grants.create(
                    conn, account_id=body.get("account_id"), kind=body.get("kind"),
                    units=body.get("units"), reason=body.get("reason"),
                    actor=admin["actor"], approved_by=approver,
                    approval_id=body.get("approval_id"), request_id=request_key, now=_now())
            return _ok(payload.as_dict(), request_id, status_code=201)
        except errors.ReputationError as exc:
            return _fail(exc, request_id)
        except Exception:                                   # pragma: no cover - 防御
            log.exception("reputation.http.grant_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    return router


# --------------------------------------------------------------------------- 信封工具
def _empty_profile(account_id: str, config: ReputationConfig, moment: Any) -> ReputationScore:
    """从未重算过的账户：返回 L1 初始档案（不是 404——「还没评分」是正常态）。"""
    return ReputationScore(
        account_id=account_id, score=0, tier="L1", quality_coef=Decimal("0.5"),
        stability_coef=Decimal("0.5"), window_days=int(config.window_days),
        policy_version=str(config.policy_version), computed_at=clock.as_utc(moment),
        tier_since=None, prev_tier=None, manual_tier=False, reasons=())


def _idempotency(request: Request, body: Mapping[str, Any], *, scope: str,
                 now: Any) -> str:
    """幂等键：优先用 ``X-DJB-Idempotency-Key``；缺省按请求体指纹做 **300s** 去重。

    指纹键里带时间窗（``int(ts/300)``），因此同一请求体只在 5 分钟窗口内折叠成一次，
    窗口外可以再次提交同样金额的请求（否则重复兑换会被永久挡住）。
    """
    raw = request.headers.get(IDEMPOTENCY_HEADER)
    if raw not in (None, ""):
        key = raw.strip()
        if not IDEMPOTENCY_MIN_LENGTH <= len(key) <= IDEMPOTENCY_MAX_LENGTH:
            raise errors.InvalidArgument(
                f"幂等键长度必须 {IDEMPOTENCY_MIN_LENGTH}–{IDEMPOTENCY_MAX_LENGTH}",
                field=IDEMPOTENCY_HEADER)
        return f"m07:{scope}:{key}"
    canonical = json.dumps(_canonical(body), separators=(",", ":"), sort_keys=True,
                           ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()[:32]
    window = int(clock.as_utc(now).timestamp() // FINGERPRINT_WINDOW_S)
    return f"m07:{scope}:fp:{digest}:{window}"


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, Decimal):
        return str(value)
    return value


def _request_id(request: Request) -> str:
    return (request.headers.get(REQUEST_ID_HEADER) or "").strip() or uuid.uuid4().hex


def _headers(request_id: str) -> dict[str, str]:
    return {REQUEST_ID_HEADER: request_id}


def _ok(payload: Mapping[str, Any], request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(dict(payload), status_code=status_code,
                        headers=_headers(request_id))


def _fail(exc: errors.ReputationError, request_id: str) -> JSONResponse:
    body = {"error": {"type": errors.error_type_for(exc.status_code),
                      "code": int(exc.code), "message": exc.message,
                      "request_id": request_id, "reason": exc.reason,
                      **{key: value for key, value in exc.details.items()
                         if key not in {"reason", "message"}}}}
    return JSONResponse(body, status_code=exc.status_code, headers=_headers(request_id))


def _server_error(request_id: str) -> JSONResponse:
    exc = errors.StoreUnavailable("服务暂时不可用，请稍后重试")
    return _fail(exc, request_id)


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw:
        raise errors.InvalidArgument("请求体必填")
    if len(raw) > MAX_BODY_BYTES:
        raise errors.InvalidArgument("请求体过大")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise errors.InvalidArgument("请求体必须是合法 JSON") from exc
    if not isinstance(parsed, dict):
        raise errors.InvalidArgument("请求体必须是 JSON 对象")
    return parsed


__all__ = ["create_router", "Principal", "ConnectionFactory", "ADMIN_ROLES"]
