# SPDX-License-Identifier: Apache-2.0
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
import uuid as _uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import clock, credentials, errors, models, tokens

log = logging.getLogger("djb.identity.http")

IDENTITY_PREFIX = "/api/v1"
IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
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


# --------------------------------------------------------------------------- 幂等
@dataclass(frozen=True)
class _IdemRecord:
    request_hash: str
    status_code: int
    response: dict[str, Any]


def _body_hash(body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _idem_scope(request: Request) -> str:
    return f"{request.method} {request.url.path}"


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
