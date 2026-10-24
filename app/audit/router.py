# SPDX-License-Identifier: AGPL-3.0-or-later
"""M16 审计链 HTTP 路由（**工厂注入，不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 spec-1.2.2 的三条操作::

    POST /internal/ops/audit/entries      appendAuditEntry   201（幂等命中 duplicate=true）
    GET  /internal/ops/audit/entries      listAuditEntries   200（只读分页，无 UPDATE/DELETE）
    POST /internal/ops/audit/verify       verifyAuditChain   200（ok=false 表示断链，不修链）

依赖注入（三件，全部 fail-closed）::

    create_router(
        connection_factory=…,     # 返回上下文管理器；app.db.conn 即可（成功提交 / 异常回滚）
        principal_resolver=…,     # request → 服务主体 dict（mTLS + 服务令牌由网关验证）
        key_provider=…,           # keys.from_env() / StaticKeyProvider / FileKeyProvider
    )

* ``principal_resolver`` 未接线 → 401 / 40101；主体非法 → 401；带 ``scopes`` 但缺所需 scope → 403 / 40301；
* ``key_provider`` 缺失 → 写入 423 / 42301，verify 返回 ``ok=false``（不静默通过）；
* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**，任何响应都回显
  ``X-Request-Id``。

审计追加只验"服务身份 + 幂等键"（M16 §4.1），不做 step-up / 不做业务规则——那是各业务模块的事。
"""
from __future__ import annotations

import inspect
import json
import logging
import uuid
from typing import Any, Awaitable, Callable

import psycopg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import (clock, errors, facts, models, policy, store, verify as verify_module)

log = logging.getLogger("djb.audit.http")

IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"

Principal = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]

#: 各端点所需的服务能力位（主体带 ``scopes`` 时校验；不带则只验身份 —— M16 §4.1 只验服务身份）
SCOPES = {
    "append": "audit:append",
    "read": "audit:read",
    "verify": "audit:verify",
}


# --------------------------------------------------------------------------- 信封
def _request_id(request: Request) -> str:
    return (request.headers.get("X-Request-Id") or "").strip() or uuid.uuid4().hex


def _headers(request_id: str) -> dict[str, str]:
    return {"X-Request-Id": request_id}


def _ok(payload: dict[str, Any], request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=_headers(request_id))


def _fail(exc: errors.AuditError, request_id: str) -> JSONResponse:
    return JSONResponse({"error": exc.as_dict(request_id)}, status_code=exc.status_code,
                        headers=_headers(request_id))


def _server_error(request_id: str) -> JSONResponse:
    body = {"error": {"type": "server_error", "code": 50001, "message": "服务繁忙",
                      "request_id": request_id}}
    return JSONResponse(body, status_code=500, headers=_headers(request_id))


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise errors.InvalidArgument("请求体不是合法 JSON", reason="malformed_json") from exc
    if not isinstance(parsed, dict):
        raise errors.InvalidArgument("请求体必须是 JSON 对象", reason="malformed_json")
    return parsed


# --------------------------------------------------------------------------- 主体
def _check_scope(principal: dict[str, Any], scope: str) -> None:
    scopes = principal.get("scopes")
    if scopes is None:
        return
    if not isinstance(scopes, (list, tuple, set, frozenset)) or scope not in scopes:
        raise errors.Forbidden(f"服务身份缺少能力位 {scope}")


async def _principal_async(resolver: Principal | None, request: Request,
                           *, scope: str) -> dict[str, Any]:
    if resolver is None:
        raise errors.Unauthorized("审计接口鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, dict) or not resolved:
        raise errors.Unauthorized("鉴权返回非法服务主体")
    _check_scope(resolved, scope)
    return resolved


def _principal_sync(resolver: Principal | None, request: Request, *, scope: str) -> dict[str, Any]:
    if resolver is None:
        raise errors.Unauthorized("审计接口鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = resolver(request)
    if inspect.isawaitable(resolved):                   # pragma: no cover - 接线错误
        resolved.close()
        raise errors.Unauthorized("鉴权钩子在同步端点上返回了 awaitable")
    if not isinstance(resolved, dict) or not resolved:
        raise errors.Unauthorized("鉴权返回非法服务主体")
    _check_scope(resolved, scope)
    return resolved


def _idempotency_key(request: Request, body: dict[str, Any], now: Any) -> str:
    """幂等键：优先取头（16..128 字符）；缺省按请求体指纹 300s 去重（00-conventions §5）。"""
    value = (request.headers.get(IDEMPOTENCY_HEADER) or "").strip()
    if value:
        if not (facts.MIN_IDEMPOTENCY_LEN <= len(value) <= facts.MAX_IDEMPOTENCY_LEN):
            raise errors.InvalidArgument(
                f"{IDEMPOTENCY_HEADER} 长度必须是 "
                f"{facts.MIN_IDEMPOTENCY_LEN}..{facts.MAX_IDEMPOTENCY_LEN}",
                field="Idempotency-Key")
        return value
    return models.fingerprint_request(body, now=now)


# --------------------------------------------------------------------------- 数据库异常 → 错误码
def _db_error(exc: Exception) -> errors.AuditError | None:
    """把库层护栏的报错映射成契约码（库层是最后一道防线，不是常规路径）。"""
    if isinstance(exc, psycopg.errors.UniqueViolation):
        return errors.Conflict("审计链写入冲突（幂等键 / 序号 / 哈希唯一）：请重试或查询既有条目",
                               reason="unique_conflict")
    if isinstance(exc, psycopg.errors.CheckViolation):
        return errors.Conflict("审计链护栏拒绝写入（链形状 / 字段约束不满足）",
                               reason="chain_guard_violation")
    if isinstance(exc, psycopg.errors.ForeignKeyViolation):
        return errors.Conflict("审计链护栏拒绝写入（事件引用了不存在的审计条目）",
                               reason="outbox_reference_missing")
    if isinstance(exc, psycopg.OperationalError):
        return errors.ServiceUnavailable("数据库不可用：请稍后重试", reason="db_unavailable")
    return None


# --------------------------------------------------------------------------- 路由
def create_router(*, connection_factory: Callable[[], Any],
                  principal_resolver: Principal | None = None,
                  key_provider: Any = None,
                  now_provider: Callable[[], Any] | None = None) -> APIRouter:
    """构造审计链路由（append / list / verify）。"""
    now_source = now_provider or clock.utcnow
    router = APIRouter(tags=["ops"])

    def _connection() -> Any:
        return connection_factory()

    @router.post("/internal/ops/audit/entries")
    async def append_audit_entry(request: Request) -> JSONResponse:
        """追加审计条目（append-only；高危字段缺失即拒；幂等键命中返回首次结果）。"""
        request_id = _request_id(request)
        try:
            await _principal_async(principal_resolver, request, scope=SCOPES["append"])
            body = await _body(request)
            moment = clock.as_utc(now_source())
            draft = models.draft_from_request(body, now=moment)
            policy.validate_new_entry(draft)
            idempotency_key = _idempotency_key(request, body, moment)
            with _connection() as connection:
                result = store.append(connection, draft, key_provider=key_provider, now=moment,
                                      trace_id=request_id, idempotency_key=idempotency_key)
            entry = result["entry"]
            payload = {
                "entry_id": str(entry["entry_id"]),
                "seq": int(entry["seq"]),
                "ts": clock.iso_micros(entry["ts"]),
                "alg": entry["alg"],
                "prev_hash": entry["prev_hash"],
                "hash": entry["hash"],
                "status": entry["status"],
                "duplicate": bool(result["duplicate"]),
            }
            return _ok(payload, request_id, status_code=201)
        except errors.AuditError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                        # noqa: BLE001 - 显式映射库层护栏
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("audit.http.append_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    @router.get("/internal/ops/audit/entries")
    def list_audit_entries(request: Request) -> JSONResponse:
        """只读查询审计链（按 seq 升序；不提供 UPDATE / DELETE）。"""
        request_id = _request_id(request)
        try:
            _principal_sync(principal_resolver, request, scope=SCOPES["read"])
            params = request.query_params
            from_seq: int | None = None
            raw_from = params.get("from_seq")
            if raw_from not in (None, ""):
                if not raw_from.strip().isdigit():
                    raise errors.InvalidArgument("from_seq 必须是正整数", field="from_seq")
                from_seq = int(raw_from)
                if from_seq < 1:
                    raise errors.InvalidArgument("from_seq 必须是正整数", field="from_seq")
            limit: int | None = None
            raw_limit = params.get("limit")
            if raw_limit not in (None, ""):
                if not raw_limit.strip().isdigit():
                    raise errors.InvalidArgument("limit 必须是整数", field="limit")
                limit = int(raw_limit)
            with _connection() as connection:
                page = store.list_page(connection, from_seq=from_seq,
                                       action=params.get("action") or None,
                                       target=params.get("target") or None, limit=limit)
            data = [{
                "seq": int(entry["seq"]),
                "entry_id": str(entry["entry_id"]),
                "ts": clock.iso_micros(entry["ts"]),
                "actor": entry["actor"],
                "actor_type": entry["actor_type"],
                "role": entry["role"],
                "action": entry["action"],
                "target": entry["target"],
                "before": entry["before"],
                "after": entry["after"],
                "reason_code": entry["reason_code"],
                "ticket": entry["ticket"],
                "evidence": entry["evidence"],
                "approval_chain": entry["approval_chain"],
                "status": entry["status"],
                "alg": entry["alg"],
                "prev_hash": entry["prev_hash"],
                "hash": entry["hash"],
            } for entry in page["data"]]
            return _ok({"data": data, "page": page["page"]}, request_id)
        except errors.AuditError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                        # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("audit.http.list_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    @router.post("/internal/ops/audit/verify")
    async def verify_audit_chain(request: Request) -> JSONResponse:
        """逐条重算校验审计链（可选固化当日 Merkle 根；断链返回 ok=false，不修链）。"""
        request_id = _request_id(request)
        try:
            await _principal_async(principal_resolver, request, scope=SCOPES["verify"])
            body = await _body(request)
            moment = clock.as_utc(now_source())
            seal = body.get("seal", False)
            if not isinstance(seal, bool):
                raise errors.InvalidArgument("seal 必须是布尔值", field="seal")
            with _connection() as connection:
                payload = verify_module.verify_chain(
                    connection, key_provider=key_provider, period=body.get("period"),
                    seal=seal, expected_alg=body.get("expected_alg"), now=moment,
                    evidence_ref=body.get("evidence_ref"))
            return _ok(payload, request_id)
        except errors.AuditError as exc:
            return _fail(exc, request_id)
        except Exception as exc:                        # noqa: BLE001
            mapped = _db_error(exc)
            if mapped is not None:
                return _fail(mapped, request_id)
            log.exception("audit.http.verify_failed", extra={"request_id": request_id})
            return _server_error(request_id)

    return router


__all__ = ["create_router", "IDEMPOTENCY_HEADER", "SCOPES"]
