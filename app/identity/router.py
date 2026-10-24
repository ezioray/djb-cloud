# SPDX-License-Identifier: AGPL-3.0-or-later
"""M01 T2 HTTP 路由（独立模块，**不接 app/api.py**——由 Lead 合并时统一 include）。

覆盖 spec 1.2.0 中 M01 的 5 个认证/档案操作：

| 方法 | 路径 | operationId | 认证 |
| --- | --- | --- | --- |
| POST | /api/v1/auth/login | createAuthSession | security: []（公开；扫码轮询复用） |
| POST | /api/v1/auth/refresh | refreshAuthSession | security: []（公开） |
| POST | /api/v1/auth/logout | revokeAuthSession | userBearer |
| GET  | /api/v1/user/profile | getUserProfile | userBearer |
| PATCH | /api/v1/user/profile | updateUserProfile | userBearer |

约定（00-conventions §5 / spec `Error`）：
- 错误信封 ``{"error": {"type", "code", "message", "request_id"}}``，``code`` 是**整数**；
  ``type`` 取 spec 枚举（见 ``errors.error_type_for``）。
- 任何响应都回显 ``X-Request-Id``（客户端传了就用客户端的）。
- 请求体校验自己做（不用 422）：不合法一律 400 / 40001，避免 FastAPI 默认 422 与 spec 冲突。
- 写接口支持 ``X-DJB-Idempotency-Key``（24 h）：
  * 令牌类接口的重放**不产生第二个会话**：同一会话重新绑定一对新令牌后返回；
  * 非令牌类（logout / profile）直接回放首次响应体；
  * 同键不同载荷 → 409 / 40919。
- 明文令牌只在该响应里出现一次；幂等表里只存 session_id 与元数据，不存令牌。
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid as _uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import admin, api_keys, clock, credentials, errors, models, tokens

log = logging.getLogger("djb.identity.http")

IDENTITY_PREFIX = "/api/v1"
IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
ADMIN_STEP_UP_HEADER = "X-Admin-Step-Up"
IDEMPOTENCY_TTL = timedelta(hours=24)

router = APIRouter(prefix=IDENTITY_PREFIX, tags=["identity"])


# --------------------------------------------------------------------------- 连接
def _connection() -> Any:
    """请求级连接（app.db 的既有约定：成功提交、异常回滚）。

    测试通过 ``monkeypatch.setattr(router_module, "_connection", ...)`` 指向测试 schema。
    """
    from app.db import conn as db_conn                        # 基础设施，非业务模块

    return db_conn()                                         # pragma: no cover - 部署期接线


# --------------------------------------------------------------------------- 信封
def _request_id(request: Request) -> str:
    provided = (request.headers.get("X-Request-Id") or "").strip()
    return provided[:64] if provided else models.uuid7().hex


def _headers(request_id: str, **extra: str) -> dict[str, str]:
    return {"X-Request-Id": request_id, **extra}


def _ok(payload: dict[str, Any], request_id: str, *, status_code: int = 200,
        **extra_headers: str) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code,
                        headers=_headers(request_id, **extra_headers))


def _fail(exc: errors.IdentityError, request_id: str) -> JSONResponse:
    body = {"error": {"type": errors.error_type_for(exc.status_code),
                      "code": int(exc.code),
                      "message": exc.message,
                      "request_id": request_id,
                      "reason": exc.reason,
                      **{k: v for k, v in exc.details.items() if k != "reason"}}}
    extra: dict[str, str] = {}
    retry_after = exc.details.get("retry_after_s")
    if exc.status_code == 429 and retry_after:
        extra["Retry-After"] = str(int(retry_after))
    return JSONResponse(body, status_code=exc.status_code,
                        headers=_headers(request_id, **extra))


def _server_error(request_id: str) -> JSONResponse:
    body = {"error": {"type": "server_error", "code": 50001,
                      "message": "服务繁忙", "request_id": request_id}}
    return JSONResponse(body, status_code=500, headers=_headers(request_id))


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise models.InvalidArgument("请求体不是合法 JSON", reason="malformed_json") from exc
    if not isinstance(parsed, dict):
        raise models.InvalidArgument("请求体必须是 JSON 对象", reason="malformed_json")
    return parsed


def _require_str(body: dict[str, Any], field: str, *, max_len: int = 320) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value.strip():
        raise models.InvalidArgument(f"{field} 必填", field=field)
    if len(value) > max_len:
        raise models.InvalidArgument(f"{field} 超长", field=field)
    return value


def _bearer(request: Request) -> str:
    header = request.headers.get("Authorization") or ""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise models.SessionInvalid("缺少 Bearer 令牌", reason="missing_token")
    return token.strip()


def _parse_datetime(value: Any, field: str) -> datetime | None:
    """RFC 3339 → aware datetime（spec format: date-time）；非法即 400。"""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise models.InvalidArgument(f"{field} 必须是 RFC 3339 字符串", field=field)
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise models.InvalidArgument(f"{field} 不是合法时间", field=field) from exc
    if parsed.tzinfo is None:
        raise models.InvalidArgument(f"{field} 必须带时区（UTC）", field=field)
    return parsed


def _plaintext_not_replayable(record: "_IdemRecord", request_id: str) -> JSONResponse:
    """Key 创建 / 轮换的幂等重放：明文不可回读，故不重发，只回已有 key_id。

    与 T2 的令牌重放同一裁决口径：**幂等表不存任何明文**（存了就等于凭据落库）。
    """
    raise errors.IdempotencyConflict(
        "重复请求：Key 明文不可重放，请用列表接口核对本次请求已创建的 Key",
        reason="plaintext_not_replayable", key_id=record.response.get("key_id"))


# --------------------------------------------------------------------------- 幂等
@dataclass(frozen=True)
class _IdemRecord:
    request_hash: str
    status_code: int
    response: dict[str, Any]


def _body_hash(body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_SCOPE_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                            r"[0-9a-fA-F]{12}")
_SCOPE_INT_RE = re.compile(r"(?<=/)\d+(?=/|$)")


def _idem_scope(request: Request) -> str:
    """幂等作用域 = 方法 + 归一化路径（路径参数折成 ``{id}``）。

    归一化的两点好处：① 同一操作在不同资源实例上共用同一作用域，避免键跨资源串用；
    ② 长度稳定落在 ``identity_idempotency.scope`` 的 64 字符上限内；仍然超长时存摘要兜底。
    """
    path = _SCOPE_UUID_RE.sub("{id}", request.url.path)
    path = _SCOPE_INT_RE.sub("{id}", path)
    scope = f"{request.method} {path}"
    if len(scope) > 64:                                        # pragma: no cover - 兜底
        scope = f"{request.method} #{hashlib.sha256(path.encode()).hexdigest()[:32]}"
    return scope


def _idem_lookup(c, scope: str, key: str, request_hash: str,
                 now: datetime) -> _IdemRecord | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT request_hash, status_code, response FROM identity_idempotency
                WHERE scope = %s AND idem_key = %s AND expires_at > %s""",
            (scope, key, now))
        row = models._one(cur)
    if row is None:
        return None
    record = _IdemRecord(request_hash=row["request_hash"], status_code=int(row["status_code"]),
                         response=dict(row["response"]))
    if record.request_hash != request_hash:
        raise errors.IdempotencyConflict("同一幂等键携带了不同载荷", reason="idempotency_conflict")
    return record


def _idem_store(c, scope: str, key: str, request_hash: str, status_code: int,
                response: dict[str, Any], now: datetime) -> None:
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO identity_idempotency
                   (id, scope, idem_key, request_hash, status_code, response, created_at, expires_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (scope, idem_key) DO NOTHING""",
            (models.uuid7(), scope, key, request_hash, status_code,
             models.Jsonb(response), now, now + IDEMPOTENCY_TTL))


def _idem_key(request: Request) -> str | None:
    key = (request.headers.get(IDEMPOTENCY_HEADER) or "").strip()
    return key or None


# --------------------------------------------------------------------------- 载荷
def account_payload(account: models.Account, user: models.User,
                    roles: tuple[str, ...]) -> dict[str, Any]:
    """脱敏账户视图（spec AccountProfile）。``balance`` 由 M06 提供，M01 不读其基表。"""
    return {
        "account_id": str(account.id),
        "tenant_id": str(account.tenant_id),
        "display_name": user.display_name,
        "locale": user.locale,
        "state": account.state,
        "frozen_until": account.frozen_until.isoformat() if account.frozen_until else None,
        "roles": list(roles),
        "created_at": account.created_at.isoformat(),
        "type": account.type,
        "mfa_state": user.mfa_state,
    }


def profile_payload(ctx: tokens.AuthContext) -> dict[str, Any]:
    return account_payload(ctx.account, ctx.user, ctx.roles)


def key_summary(key: models.ApiKey) -> dict[str, Any]:
    """spec ApiKeySummary：只回前缀与元数据，**永不**回明文或哈希。"""
    payload: dict[str, Any] = {
        "key_id": str(key.id),
        "prefix": key.key_prefix,
        "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None,
        "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
        "expires_at": key.expires_at.isoformat() if key.expires_at else None,
        "created_at": key.created_at.isoformat(),
    }
    if key.label is not None:
        payload["name"] = key.label
    if key.scopes is not None:
        payload["scopes"] = list(key.scopes)
    if key.qps is not None:
        payload["qps"] = key.qps
    return payload


def key_created(key: models.ApiKey, plaintext: str) -> dict[str, Any]:
    """spec ApiKeyCreated：``key`` 只在本次响应出现一次。"""
    payload = {"key_id": str(key.id), "key": plaintext, "prefix": key.key_prefix,
               "created_at": key.created_at.isoformat()}
    if key.label is not None:
        payload["name"] = key.label
    if key.scopes is not None:
        payload["scopes"] = list(key.scopes)
    if key.expires_at is not None:
        payload["expires_at"] = key.expires_at.isoformat()
    return payload


def _path_id(value: str) -> int:
    """路径参数 ``{id}``（spec 声明为 string）→ 内部整型主键；非法即 400。"""
    try:
        key_id = int(str(value))
    except (TypeError, ValueError) as exc:
        raise models.InvalidArgument("Key id 非法", field="id") from exc
    if key_id <= 0:
        raise models.InvalidArgument("Key id 非法", field="id")
    return key_id


def _flag(request: Request, name: str, default: bool = False) -> bool:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# 内部票据状态 → spec ScanStatus.status 枚举（1.2.1）
SCAN_STATUS_MAP = {"created": "pending", "scanned": "scanned",
                   "confirmed": "confirmed", "expired": "expired"}


def _scan_payload(scan_result: dict[str, Any]) -> dict[str, Any]:
    """扫码中间态响应体（spec 1.2.1 ScanStatus）。

    顶层给 ``status / expires_at / retry_after_s`` 三个规范字段；
    同时保留 ``scan`` 包裹（CR-5 落地前的形状），便于已对接的调用方零改动过渡——
    纯增量，不改变 202 的语义与时序。
    """
    flat = {"status": SCAN_STATUS_MAP.get(scan_result["status"], scan_result["status"]),
            "expires_at": scan_result["expires_at"],
            "retry_after_s": int(scan_result["retry_after_s"])}
    return {**flat, "scan": {**flat}}


def _tokens_payload(result: tokens.LoginResult) -> dict[str, Any]:
    session = result.session
    assert session is not None
    refresh_expires = result.refresh_expires_at
    payload: dict[str, Any] = {
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": "Bearer",
        "expires_in": max(int(result.expires_in), 1),
        "session_id": str(session.id),
        "expires_at": session.expires_at.isoformat(),
    }
    if refresh_expires is not None:
        payload["refresh_expires_at"] = refresh_expires.isoformat()
    return payload


# --------------------------------------------------------------------------- 端点
@router.post("/auth/login", operation_id="createAuthSession",
             openapi_extra={"security": []}, summary="登录（密码 / 扫码轮询）")
async def create_auth_session(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        method = _require_str(body, "method", max_len=32)
        identifier = _require_str(body, "identifier")
        secret = body.get("secret")
        mfa_code = body.get("mfa_code")
        if secret is not None and not isinstance(secret, str):
            raise models.InvalidArgument("secret 必须是字符串", field="secret")
        if mfa_code is not None and not isinstance(mfa_code, str):
            raise models.InvalidArgument("mfa_code 必须是字符串", field="mfa_code")
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash({"method": method, "identifier": identifier,
                                   "secret": secret, "mfa_code": mfa_code,
                                   "provider": body.get("provider")})
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _replay_tokens(c, record, request_id, now, wrap_login=True)
            with c.transaction():
                result = tokens.login(c, method=method, identifier=identifier, secret=secret,
                                      provider=body.get("provider"), mfa_code=mfa_code,
                                      client_ip=request.client.host if request.client else None,
                                      now=now, trace_id=request_id)
                if result.scan is not None:           # 扫码中间态：202，不落幂等
                    return _ok(_scan_payload(result.scan), request_id, status_code=202)
                payload = {"tokens": _tokens_payload(result),
                           "account": account_payload(result.account, result.user, result.roles),
                           "mfa_required": result.mfa_required}
                if key:
                    _idem_store(c, scope, key, request_hash, 200,
                                {"kind": "tokens", "session_id": str(result.session.id)}, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        _bump_failures(exc, now=clock.utcnow(), trace_id=request_id)
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.login.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/auth/refresh", operation_id="refreshAuthSession",
             openapi_extra={"security": []}, summary="刷新令牌（轮换）")
async def refresh_auth_session(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        refresh_token = _require_str(body, "refresh_token", max_len=200)
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash({"refresh_token": refresh_token})
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _replay_tokens(c, record, request_id, now)
            with c.transaction():
                result = tokens.refresh(c, refresh_token, now=now, trace_id=request_id,
                                        client_ip=request.client.host if request.client else None)
                payload = _tokens_payload(result)
                if key:
                    _idem_store(c, scope, key, request_hash, 200,
                                {"kind": "tokens", "session_id": str(result.session.id)}, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.refresh.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/auth/logout", operation_id="revokeAuthSession", summary="退出（撤销会话）")
async def revoke_auth_session(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        all_devices = bool(body.get("all_devices", False))
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash({"all_devices": all_devices})
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                session = tokens.resolve_session(c, _bearer(request))
                revoked, revoked_at = tokens.logout(c, session=session,
                                                    all_devices=all_devices, now=now,
                                                    trace_id=request_id)
                payload = {"revoked_sessions": revoked, "revoked_at": revoked_at.isoformat()}
                if key:
                    _idem_store(c, scope, key, request_hash, 200, payload, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.logout.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.get("/user/profile", operation_id="getUserProfile", summary="账户视图（脱敏）")
def get_user_profile(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        now = clock.utcnow()
        with _connection() as c:
            ctx = tokens.authenticate(c, _bearer(request), now=now, trace_id=request_id)
            return _ok(profile_payload(ctx), request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.profile.get.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.patch("/user/profile", operation_id="updateUserProfile", summary="改昵称与语言")
async def update_user_profile(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        if not body:
            raise models.InvalidArgument("至少提供一个可改字段", reason="empty_update")
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash(body)
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                ctx = tokens.authenticate(c, _bearer(request), now=now, trace_id=request_id)
                # frozen / closing / closed 只读（M01 §3），先过状态闸门再校验字段
                models.assert_writable(ctx.account, action="修改账户档案")
                # 身份字段（account_id / tenant_id / state）不在白名单 → 400
                models.update_user_profile(c, ctx.user.id, body, now=now)
                refreshed = tokens.authenticate(c, _bearer(request), now=now, touch=False)
                payload = profile_payload(refreshed)
                if key:
                    _idem_store(c, scope, key, request_hash, 200, payload, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.profile.patch.failed request_id=%s", request_id)
        return _server_error(request_id)


def _bump_failures(exc: errors.IdentityError, *, now: datetime, trace_id: str) -> None:
    """登录失败留痕：在业务事务回滚**之后**用独立连接补记（M01 §8.2 锁定依赖它）。"""
    user_id = getattr(exc, "bump_user_id", None)
    if user_id is None:
        return
    try:
        with _failure_sink() as sink:
            tokens.register_failure(sink, user_id, now)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.login.failure_bump_failed request_id=%s", trace_id)


# --------------------------------------------------------------------------- 管理面身份
def admin_context(c, request: Request, *, now: datetime, trace_id: str) -> tokens.AuthContext:
    """adminBearer + 后台角色 + step-up（spec 1.2.1 admin 段）。

    step-up 两种承载都接受：``X-Admin-Step-Up`` 头里带 step_up 令牌（spec 的「凭据」语义），
    或同一会话在 5 分钟内刚完成过 step-up（T2 的 ``step_up_until``）。
    """
    ctx = tokens.authenticate(c, _bearer(request), now=now, trace_id=trace_id)
    if not ctx.roles:
        raise errors.AdminForbidden("需要后台角色")
    step_token = (request.headers.get(ADMIN_STEP_UP_HEADER) or "").strip()
    if step_token:
        grant = tokens.authenticate(c, step_token, now=now, allow_pending=True, touch=False)
        if grant.account.id != ctx.account.id or grant.session is None \
                or grant.session.kind != "step_up":
            raise errors.StepUpRequired("step-up 凭据无效或不属于该账户")
    elif not ctx.step_up_active:
        raise errors.StepUpRequired("需要二次认证（step-up ≤5 分钟）")
    return ctx


def _state_ack(account: models.Account, changed_at: datetime) -> dict[str, Any]:
    """spec AccountStateAck（脱敏：不含邮箱 / 手机 / 操作者身份）。"""
    return {"account_id": str(account.id), "state": account.state,
            "frozen_until": account.frozen_until.isoformat() if account.frozen_until else None,
            "changed_at": changed_at.isoformat()}


def _roles_ack(payload: dict[str, Any]) -> dict[str, Any]:
    return {"account_id": payload["account_id"], "roles": payload["roles"],
            "session_epoch": payload["session_epoch"]}


def _quotas_ack(payload: dict[str, Any]) -> dict[str, Any]:
    return {"tenant_id": payload["tenant_id"], "quotas": payload["quotas"],
            "policy_version": payload["policy_version"],
            "effective_at": payload.get("effective_at")}


# --------------------------------------------------------------------------- API Key 生命周期
@router.get("/user/api-keys", operation_id="listApiKeys", summary="列举 API Key（只回前缀）")
def list_api_keys(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        limit = request.query_params.get("limit")
        cursor = request.query_params.get("cursor")
        now = clock.utcnow()
        with _connection() as c:
            ctx = tokens.authenticate(c, _bearer(request), now=now, trace_id=request_id)
            page = api_keys.list_page(
                c, account_id=ctx.account.id, tenant_id=ctx.tenant_id,
                include_revoked=_flag(request, "include_revoked"),
                cursor=cursor or None,
                limit=int(limit) if limit is not None and limit.isdigit() else None,
                now=now)
            payload = {"data": [key_summary(key) for key in page.items],
                       "page": {"has_more": page.has_more,
                                "cursor": page.cursor or "",
                                "next_cursor": page.next_cursor}}
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.apikeys.list.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/user/api-keys", operation_id="createApiKey", status_code=201,
             summary="创建 API Key（明文只回一次）")
async def create_api_key(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        name = _require_str(body, "name", max_len=api_keys.KEY_NAME_MAX)
        scopes = body.get("scopes")
        expires_raw = body.get("expires_at")
        expires_at = _parse_datetime(expires_raw, "expires_at")
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash({"name": name, "scopes": scopes, "expires_at": expires_raw})
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _plaintext_not_replayable(record, request_id)
            with c.transaction():
                ctx = tokens.authenticate(c, _bearer(request), now=now, trace_id=request_id)
                created, plaintext = api_keys.create(
                    c, account_id=ctx.account.id, tenant_id=ctx.tenant_id, name=name,
                    scopes=scopes, expires_at=expires_at, now=now, trace_id=request_id)
                payload = key_created(created, plaintext)
                if key:
                    _idem_store(c, scope, key, request_hash, 201,
                                {"kind": "api_key", "key_id": str(created.id)}, now)
            log.info("identity.apikey.created_via_api key_id=%s account_id=%s prefix=%s",
                     created.id, ctx.account.id, created.key_prefix)
            return _ok(payload, request_id, status_code=201)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.apikeys.create.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.delete("/user/api-keys/{id}", operation_id="revokeApiKey",
               summary="撤销 API Key（幂等）")
def revoke_api_key(request: Request, id: str) -> JSONResponse:      # noqa: A002 - spec 路径参数名
    request_id = _request_id(request)
    try:
        target = _path_id(id)
        now = clock.utcnow()
        scope, idem = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash({"id": target})
        with _connection() as c:
            if idem:
                record = _idem_lookup(c, scope, idem, request_hash, now)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                ctx = tokens.authenticate(c, _bearer(request), now=now, trace_id=request_id)
                revoked, _changed = api_keys.revoke(c, key_id=target,
                                                    account_id=ctx.account.id,
                                                    tenant_id=ctx.tenant_id, now=now,
                                                    trace_id=request_id)
                payload = key_summary(revoked)
                if idem:
                    _idem_store(c, scope, idem, request_hash, 200, payload, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.apikeys.revoke.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/user/api-keys/{id}/rotate", operation_id="rotateApiKey", status_code=201,
             summary="轮换 API Key（旧钥立即失效 / 可声明重叠期）")
async def rotate_api_key(request: Request, id: str) -> JSONResponse:   # noqa: A002 - spec 路径参数名
    request_id = _request_id(request)
    try:
        target = _path_id(id)
        body = await _body(request)
        name = body.get("name")
        if name is not None:
            name = _require_str(body, "name", max_len=api_keys.KEY_NAME_MAX)
        overlap = body.get("overlap_seconds", 0)
        if not isinstance(overlap, int) or isinstance(overlap, bool):
            raise models.InvalidArgument("overlap_seconds 必须是整数", field="overlap_seconds")
        now = clock.utcnow()
        scope, idem = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash({"id": target, "name": name, "overlap_seconds": overlap})
        with _connection() as c:
            if idem:
                record = _idem_lookup(c, scope, idem, request_hash, now)
                if record is not None:
                    return _plaintext_not_replayable(record, request_id)
            with c.transaction():
                ctx = tokens.authenticate(c, _bearer(request), now=now, trace_id=request_id)
                new_key, plaintext = api_keys.rotate(
                    c, key_id=target, account_id=ctx.account.id, tenant_id=ctx.tenant_id,
                    name=name, overlap_seconds=overlap, now=now, trace_id=request_id)
                payload = key_created(new_key, plaintext)
                if idem:
                    _idem_store(c, scope, idem, request_hash, 201,
                                {"kind": "api_key", "key_id": str(new_key.id)}, now)
            log.info("identity.apikey.rotated key_id=%s replaced=%s account_id=%s",
                     new_key.id, target, ctx.account.id)
            return _ok(payload, request_id, status_code=201)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.apikeys.rotate.failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- 管理面
async def _admin_body(request: Request) -> dict[str, Any]:
    body = await _body(request)
    if not body:
        raise models.InvalidArgument("请求体必填", reason="empty_body")
    return body


@router.post("/admin/accounts/{id}/freeze", operation_id="freezeAccount",
             summary="冻结账户（理由 + 期限必填）")
async def freeze_account(request: Request, id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _admin_body(request)
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash(body)
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                ctx = admin_context(c, request, now=now, trace_id=request_id)
                account = admin.freeze(c, account_id=id, operator_id=ctx.account.id,
                                       payload=body, now=now, trace_id=request_id)
                payload = _state_ack(account, now)
                if key:
                    _idem_store(c, scope, key, request_hash, 200, payload, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.admin.freeze.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/admin/accounts/{id}/unfreeze", operation_id="unfreezeAccount",
             summary="解冻账户（非原冻结人）")
async def unfreeze_account(request: Request, id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _admin_body(request)
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash(body)
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                ctx = admin_context(c, request, now=now, trace_id=request_id)
                account = admin.unfreeze(c, account_id=id, operator_id=ctx.account.id,
                                         payload=body, now=now, trace_id=request_id)
                payload = _state_ack(account, now)
                if key:
                    _idem_store(c, scope, key, request_hash, 200, payload, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.admin.unfreeze.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/admin/accounts/{id}/roles", operation_id="updateAccountRoles",
             summary="授予 / 回收后台角色（第二人确认）")
async def update_account_roles(request: Request, id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _admin_body(request)
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash(body)
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                ctx = admin_context(c, request, now=now, trace_id=request_id)
                result = admin.set_roles(c, account_id=id, operator_id=ctx.account.id,
                                         payload=body, now=now, trace_id=request_id)
                payload = _roles_ack(result)
                if key:
                    _idem_store(c, scope, key, request_hash, 200, payload, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.admin.roles.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/admin/tenants/{id}/quotas", operation_id="updateTenantQuotas",
             summary="修改租户配额（升配额需复核）")
async def update_tenant_quotas(request: Request, id: str) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _admin_body(request)
        now = clock.utcnow()
        scope, key = _idem_scope(request), _idem_key(request)
        request_hash = _body_hash(body)
        with _connection() as c:
            if key:
                record = _idem_lookup(c, scope, key, request_hash, now)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                ctx = admin_context(c, request, now=now, trace_id=request_id)
                result = admin.set_quotas(c, tenant_id=id, operator_id=ctx.account.id,
                                          payload=body, now=now, trace_id=request_id)
                payload = _quotas_ack(result)
                if key:
                    _idem_store(c, scope, key, request_hash, 200, payload, now)
            return _ok(payload, request_id)
    except errors.IdentityError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("identity.admin.quotas.failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- 令牌重放
def _replay_tokens(c, record: _IdemRecord, request_id: str, now: datetime, *,
                   wrap_login: bool = False) -> JSONResponse:
    """令牌接口的幂等重放：**不新建会话**，在同一会话上重绑一对新令牌后返回。

    为什么不在幂等表里存令牌明文：那等于把凭据落库（违反 INV-04 / 09 安全）。
    因此只存 ``session_id``，重放时复用同一会话重新绑定令牌——对外副作用仍是「一次登录一个会话」。
    """
    session_id = record.response.get("session_id")
    if not session_id:                                         # pragma: no cover - 防御
        return _ok(record.response, request_id)
    try:
        session = models.get_session(c, _uuid.UUID(str(session_id)))
    except models.SessionInvalid:
        raise errors.RefreshTokenRejected("原会话已失效，请重新登录", reason="session_gone")
    if session.revoked_at is not None or session.expires_at <= now:
        raise errors.RefreshTokenRejected("原会话已失效，请重新登录", reason="session_gone")
    with c.transaction():
        access, access_hash = credentials.new_token()
        refresh = None
        sets = ["access_hash = %s", "last_seen_at = %s"]
        params: list[Any] = [access_hash, now]
        if session.refresh_expires_at is not None:
            refresh, refresh_hash = credentials.new_token()
            sets.append("refresh_hash = %s")
            params.append(refresh_hash)
        params.append(session.id)
        with c.cursor() as cur:
            cur.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE id = %s", params)
        # 校验新令牌可用（顺带触发 epoch / 状态闸门）
        tokens.authenticate(c, access, now=now, touch=False)
    payload: dict[str, Any] = {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": max(int((session.expires_at - now).total_seconds()), 1),
        "session_id": str(session.id),
        "expires_at": session.expires_at.isoformat(),
    }
    if session.refresh_expires_at is not None:
        payload["refresh_expires_at"] = session.refresh_expires_at.isoformat()
    if wrap_login:
        ctx = tokens.authenticate(c, access, now=now, touch=False)
        payload = {"tokens": payload,
                   "account": account_payload(ctx.account, ctx.user, ctx.roles),
                   "mfa_required": False}
    return _ok(payload, request_id)


# --------------------------------------------------------------------------- 装配
def _failure_sink() -> Any:
    """登录失败计数的**独立提交通道**（autocommit）。

    业务事务在凭据错误时会回滚；失败计数若跟着回滚，连续猜口令永远锁不住账号。
    生产用一条短连接（写一条 UPDATE 即提交），测试由 fixture 换成测试事务连接。
    """
    import psycopg

    from app.config import dsn as dsn_of                             # 基础设施

    connection = psycopg.connect(dsn_of(), autocommit=True,
                                 options="-c synchronous_commit=off")
    return _Sink(connection)


class _Sink:
    """极简 autocommit 连接包装：退出即关闭。"""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def __enter__(self) -> Any:
        return self._connection

    def __exit__(self, *exc_info) -> bool:
        self._connection.close()
        return False


def include_in(app: Any) -> None:
    """把本路由挂到 FastAPI 应用（Lead 合并时调用；不在模块内自行 include）。"""
    app.include_router(router)


__all__ = ["router", "include_in", "profile_payload", "account_payload", "IDENTITY_PREFIX",
           "IDEMPOTENCY_HEADER", "IDEMPOTENCY_TTL"]
