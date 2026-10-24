# SPDX-License-Identifier: Apache-2.0
"""M02 T2 HTTP 路由（独立模块，**不接 app/api.py**——由 Lead 合并时统一 include）。

覆盖 spec 1.2.0/1.2.1 中 M02 的 T2 六个操作（T3–T6 的其余端点后续补齐）::

    POST   /api/v1/node/register                         registerNode          201
    POST   /api/v1/node/pair                             pairNodeClientKey     201
    GET    /api/v1/node/binding                          getNodeBinding        200
    POST   /api/v1/node/binding                          bindNode              200
    DELETE /api/v1/node/binding                          unbindNode            200
    POST   /api/v1/admin/supply/nodes/{id}/review        reviewSupplyNode      200
    GET    /api/v1/user/nodes                            listUserNodes         200（spec 1.2.6）
    POST   /api/v1/user/nodes/{node_id}/unbind           unbindUserNode        200（spec 1.2.6，step-up）
    POST   /api/v1/node/channel/poll                     pollNodeChannel       200 / 204（spec 1.2.9）
    POST   /api/v1/node/channel/result                   submitNodeChannelResult 200（spec 1.2.9）

节点通道（C10a）只做**契约与端点**：队列由 C10b 经 ``channel.set_channel_backend`` 注入；
未接线一律 503 / 50903（fail-closed，不 import ``app.gateway``、不写队列、不落正文）。

约定（00-conventions §5 / spec ``Error``）：

- 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**，``type`` 取
  spec 枚举；任何响应都回显 ``X-Request-Id``。
- 请求体校验自己做（不用 FastAPI 的 422）：不合法一律 400 / 40001。
- 写接口支持 ``X-DJB-Idempotency-Key``（24 h）：回放首次响应；同键不同载荷 → 40919；
  **含一次性明文的响应（register / pair）不入幂等表**，重放回 40919 + ``key_id`` 提示。
- 一次性明文（``client_key``）只在该响应出现一次；库里只有 sha256 + 8 位前缀。

认证与接线：

- 节点侧 ``X-Client-Key``（本模块自己的 ``nodes.key_hash``，不 import 任何其它模块）。
- 管理面（审核）走**依赖注入钩子** :func:`set_admin_authenticator`：默认 **fail-closed**
  （未接线即 401，绝不静默放行），合并时由 Lead 注入 M01 管理面鉴权与 step-up 判定。
- 数据库连接经 :func:`_connection`（app.db 既有约定：成功提交、异常回滚）；测试用
  ``monkeypatch.setattr(router_module, "_connection", ...)`` 指向隔离 schema。
"""
from __future__ import annotations

import inspect
import logging
import uuid
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import (channel, clock, config_source, errors, facts, features, heartbeat, idempotency,
               models, policy, protocol, security, state as state_machine, upstream, user_nodes)

log = logging.getLogger("djb.supply.http")

router = APIRouter(prefix="/api/v1", tags=["node"])

NODE_KEY_HEADER = "X-Client-Key"
PROTOCOL_HEADER = "DJB-Protocol-Version"
CAPABILITIES_HEADER = "DJB-Capabilities"
IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
STEP_UP_HEADER = "X-Admin-Step-Up"

AdminAuthenticator = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
_admin_authenticator: AdminAuthenticator | None = None
_user_authenticator: AdminAuthenticator | None = None


# --------------------------------------------------------------------------- 接线钩子
def set_admin_authenticator(authenticator: AdminAuthenticator | None) -> None:
    """注入管理面鉴权（合并时由 Lead 接 M01）。传 ``None`` 恢复 fail-closed。"""
    global _admin_authenticator
    _admin_authenticator = authenticator


def admin_authenticator() -> AdminAuthenticator | None:
    return _admin_authenticator


def set_user_authenticator(authenticator: AdminAuthenticator | None) -> None:
    """注入用方鉴权（合并时由 Lead 接 M01 会话 / API Key）。传 `None` 恢复 fail-closed。"""
    global _user_authenticator
    _user_authenticator = authenticator


def user_authenticator() -> AdminAuthenticator | None:
    return _user_authenticator


def _user_principal_sync(request: Request) -> dict[str, Any]:
    """用方主体（`/api/v1/user/*`）：未接线即 401（fail-closed），不静默放行。

    GET 端点走同步钩子（与 M05 同款）：钩子返回 awaitable 时不支持，直接 401 而不是猜。
    """
    if _user_authenticator is None:
        raise errors.UserAuthUnavailable(
            "用方鉴权未接线：合并时由 Lead 注入 M01 会话 / API Key（fail-closed）")
    principal = _user_authenticator(request)
    if inspect.isawaitable(principal):                          # pragma: no cover - 防御
        principal.close()
        raise errors.UserAuthUnavailable("用方鉴权钩子必须是同步函数")
    if not isinstance(principal, dict):
        raise errors.UserAuthUnavailable("用方鉴权返回非法主体")
    return principal


def _account_uuid(principal: dict[str, Any]) -> uuid.UUID:
    """用方主体必须有账户（M01）；缺失 / 非法即 401（不猜、不回落）。"""
    value = principal.get("account_id")
    if not value:
        raise errors.Unauthorized("主体缺少 account_id")
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise errors.Unauthorized("主体 account_id 非法") from exc


async def _admin_principal(request: Request) -> dict[str, Any]:
    """管理面主体；未接线即 401（fail-closed），并强制 step-up（M02 §4.1）。"""
    if _admin_authenticator is None:
        raise errors.AdminAuthUnavailable(
            "管理面鉴权未接线：合并时由 Lead 注入 M01 管理面鉴权 + step-up")
    principal = _admin_authenticator(request)
    if inspect.isawaitable(principal):
        principal = await principal
    if not isinstance(principal, dict) or not principal.get("admin_id"):
        raise errors.AdminAuthUnavailable("管理面鉴权返回非法主体")
    if not principal.get("step_up"):
        raise errors.StepUpRequired("高危动作需要 step-up（X-Admin-Step-Up）")
    return principal


def _connection() -> Any:
    """请求级连接（app.db 的既有约定：成功提交、异常回滚）。"""
    from app.db import conn as db_conn                        # 基础设施，非业务模块

    return db_conn()                                          # pragma: no cover - 部署期接线


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


def _no_content(request_id: str) -> Response:
    """204：无任务（长轮询到点）。仍回显 ``X-Request-Id``，保证链路可追。"""
    return Response(status_code=204, headers=_headers(request_id))


def _fail(exc: errors.SupplyError, request_id: str) -> JSONResponse:
    body = {"error": {"type": errors.error_type_for(exc.status_code),
                      "code": int(exc.code),
                      "message": exc.message,
                      "request_id": request_id,
                      "reason": exc.reason,
                      **{key: value for key, value in exc.details.items() if key != "reason"}}}
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
    import json

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


def _node_key(request: Request) -> str | None:
    value = (request.headers.get(NODE_KEY_HEADER) or "").strip()
    return value or None


def _idem_key(request: Request) -> str | None:
    return idempotency.require_key(request.headers.get(IDEMPOTENCY_HEADER))


def _plaintext_not_replayable(key_id: Any, request_id: str) -> JSONResponse:
    """含一次性明文的响应重放：明文不可回读 → 40919 + key_id 提示（与 M01 同口径）。"""
    exc = errors.IdempotencyConflict(
        "重复请求：密钥明文不可重放（平台只存哈希）；可用原密钥，或去掉幂等键重新注册以轮换",
        reason="plaintext_not_replayable", key_id=str(key_id) if key_id else None)
    return _fail(exc, request_id)


# --------------------------------------------------------------------------- 凭据扫描留痕（INV-04）
def _record_credential_rejection(request: Request, fields: list[str],
                                 request_id: str) -> None:
    """疑似凭据被拒：**只记字段名**（不落值），尽量落到 node_events；失败不影响 400。"""
    log.warning("supply.credential_field_rejected request_id=%s fields=%s",
                request_id, ",".join(fields))
    key = _node_key(request)
    if not key:
        return
    try:
        with _connection() as c:
            with c.transaction():
                auth = models.authenticate(c, key, allow_previous=True)
                models.record_credential_rejection(c, auth.node, fields,
                                                   now=clock.utcnow())
    except Exception:                                          # pragma: no cover - 审计不阻断
        log.warning("supply.credential_rejection_audit_failed request_id=%s", request_id)


def _scan(body: dict[str, Any], request: Request, request_id: str) -> None:
    try:
        security.scan_credentials(body)
    except errors.CredentialFieldRejected as exc:
        fields = list(exc.details.get("fields") or [])
        _record_credential_rejection(request, fields, request_id)
        raise


# --------------------------------------------------------------------------- 序列化
def _node_ack(node: models.Node, *, server_time: Any = None) -> dict[str, Any]:
    """注册响应（spec ``NodeRegisterResponse`` + 可选的明文密钥字段）。"""
    moment = server_time or clock.utcnow()
    return {
        "node_id": node.id,
        "state": node.state,
        "policy_version": node.policy_version,
        "protocol_version": node.protocol_version,
        "server_time": models.iso(moment),
        "lifecycle_state": node.lifecycle_state,
        "protocol_version_min": protocol.min_supported_version(),
        "bound": node.bound_account_id is not None and node.revoked_at is None,
    }


def _register_payload(result: models.RegisterResult, request_id: str) -> dict[str, Any]:
    payload = _node_ack(result.node)
    payload.update({"created": result.created, "key_id": str(result.key_id)
                    if result.key_id else None,
                    "key_prefix": result.node.key_prefix})
    if result.client_key is not None:
        # 明文只在此响应出现一次；库 / 日志 / 幂等表都不落
        payload["client_key"] = result.client_key
    return payload


def _pair_payload(rotation: models.KeyRotation) -> dict[str, Any]:
    return {
        "node_id": rotation.node.id,
        "key_id": str(rotation.key_id),
        "client_key": rotation.client_key,
        "key_prefix": rotation.node.key_prefix,
        "previous_key_expires_at": models.iso(rotation.previous_key_expires_at),
        "created_at": models.iso(rotation.node.key_issued_at),
    }


def _review_ack(node: models.Node) -> dict[str, Any]:
    return {
        "node_id": node.id,
        "state": node.state,
        "reviewed_at": models.iso(node.reviewed_at),
        "policy_version": node.policy_version,
    }


# --------------------------------------------------------------------------- 注册
@router.post("/node/register", operation_id="registerNode", status_code=201,
             summary="节点注册（首次 pending；同指纹幂等）")
async def register_node(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        key = _node_key(request)
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash(body)
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _plaintext_not_replayable(record.response.get("key_id"), request_id)
            with c.transaction():
                result = models.register(
                    c, platform=body.get("platform"),
                    hardware_fingerprint=body.get("hardware_fingerprint"),
                    client_version=body.get("client_version"),
                    protocol_version=body.get("protocol_version"),
                    capabilities=body.get("capabilities"),
                    access_modes=body.get("access_modes"),
                    region=body.get("region"),
                    labels=body.get("labels"),
                    client_key=key, now=clock.utcnow(), trace_id=request_id)
                payload = _register_payload(result, request_id)
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem, request_hash=request_hash,
                                     status_code=201, response=payload, now=clock.utcnow())
            return _ok(payload, request_id, status_code=201)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.register.failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- pair
@router.post("/node/pair", operation_id="pairNodeClientKey", status_code=201,
             summary="生成 / 轮换客户端密钥（明文只回一次）")
async def pair_node_client_key(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash(body)
        node_id = body.get("node_id")
        if not isinstance(node_id, str) or not node_id.strip():
            raise errors.InvalidArgument("node_id 必填", field="node_id")
        rotate = body.get("rotate", False)
        overlap = body.get("overlap_seconds", 0)
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _plaintext_not_replayable(record.response.get("key_id"), request_id)
            with c.transaction():
                auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                           now=clock.utcnow())
                if auth.node.id != node_id.strip():
                    raise errors.NodeNotFound("节点不存在", node_id=node_id.strip())
                rotation = models.rotate_key(c, auth.node, rotate=rotate or False,
                                             overlap_seconds=overlap or 0,
                                             now=clock.utcnow(), trace_id=request_id)
                payload = _pair_payload(rotation)
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem, request_hash=request_hash,
                                     status_code=201, response=payload, now=clock.utcnow())
            return _ok(payload, request_id, status_code=201)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.pair.failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- 绑定
@router.get("/node/binding", operation_id="getNodeBinding", summary="查询节点绑定")
def get_node_binding(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        node_id = (request.query_params.get("node_id") or "").strip()
        if not node_id:
            raise errors.InvalidArgument("node_id 必填", field="node_id")
        with _connection() as c:
            auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                       now=clock.utcnow())
            if auth.node.id != node_id:
                raise errors.NodeNotFound("节点不存在", node_id=node_id)
            return _ok(models.binding_dict(auth.node.binding()), request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.binding.get.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/node/binding", operation_id="bindNode", summary="网页端绑定节点（一次性码）")
async def bind_node(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash(body)
        node_id = body.get("node_id")
        code = body.get("code")
        account_id = body.get("account_id")
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                           now=clock.utcnow())
                if not isinstance(node_id, str) or auth.node.id != node_id.strip():
                    raise errors.NodeNotFound("节点不存在", node_id=str(node_id))
                parsed_account = None
                if account_id is not None:
                    import uuid as _uuid

                    try:
                        parsed_account = _uuid.UUID(str(account_id))
                    except (ValueError, TypeError) as exc:
                        raise errors.InvalidArgument("account_id 必须是 UUID",
                                                     field="account_id") from exc
                binding, _node = models.bind(c, node_id=auth.node.id,
                                             code=code if isinstance(code, str) else "",
                                             account_id=parsed_account,
                                             now=clock.utcnow(), trace_id=request_id)
                payload = models.binding_dict(binding)
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem, request_hash=request_hash,
                                     status_code=200, response=payload, now=clock.utcnow())
            return _ok(payload, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.binding.post.failed request_id=%s", request_id)
        return _server_error(request_id)


@router.delete("/node/binding", operation_id="unbindNode", summary="解绑节点（幂等）")
def unbind_node(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        node_id = (request.query_params.get("node_id") or "").strip()
        if not node_id:
            raise errors.InvalidArgument("node_id 必填", field="node_id")
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash({"node_id": node_id})
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                           now=clock.utcnow())
                if auth.node.id != node_id:
                    raise errors.NodeNotFound("节点不存在", node_id=node_id)
                binding, _node = models.unbind(c, node=auth.node, now=clock.utcnow(),
                                               trace_id=request_id)
                payload = models.binding_dict(binding)
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem, request_hash=request_hash,
                                     status_code=200, response=payload, now=clock.utcnow())
            return _ok(payload, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.binding.delete.failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- 准入审核（管理面）
@router.post("/admin/supply/nodes/{id}/review", operation_id="reviewSupplyNode",
             summary="节点准入审核（approve / reject）")
async def review_supply_node(id: str, request: Request) -> JSONResponse:  # noqa: A002 (spec 路径参数名)
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        principal = await _admin_principal(request)
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash(body)
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                node = models.review(
                    c, node_id=id, decision=body.get("decision"),
                    reason=body.get("reason"), actor=str(principal.get("admin_id")),
                    tier=body.get("tier"), now=clock.utcnow(), trace_id=request_id)
                payload = _review_ack(node)
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem, request_hash=request_hash,
                                     status_code=200, response=payload, now=clock.utcnow())
            return _ok(payload, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.review.failed request_id=%s", request_id)
        return _server_error(request_id)



# --------------------------------------------------------------------------- 心跳 + 容量公告（T3）
@router.post("/node/heartbeat", operation_id="postNodeHeartbeat",
             summary="心跳 + 本轮容量公告")
async def post_node_heartbeat(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash(body)
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                           now=clock.utcnow())
                node_id = body.get("node_id")
                if not isinstance(node_id, str) or auth.node.id != node_id.strip():
                    raise errors.NodeNotFound("节点不存在", node_id=str(node_id))
                result = heartbeat.pulse(
                    c, node=auth.node,
                    protocol_version=body.get("protocol_version"),
                    policy_version=body.get("policy_version"),
                    runtime_state=body.get("runtime_state"),
                    capacity_entries=body.get("capacity"),
                    load=body.get("load"),
                    now=clock.utcnow(), trace_id=request_id)
                payload = heartbeat.heartbeat_payload(result)
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem, request_hash=request_hash,
                                     status_code=200, response=payload, now=clock.utcnow())
            return _ok(payload, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.heartbeat.failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- 上游申报（T4）
@router.post("/node/upstream", operation_id="declareNodeUpstream", summary="申报接入方式（A1/A2/B）")
async def declare_node_upstream(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash(body)
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                           now=clock.utcnow())
                declared, created = upstream.declare(
                    c, node=auth.node,
                    access_type=body.get("access_type"),
                    base_url=body.get("base_url"),
                    models_list=body.get("models"),
                    upstream_protocol=body.get("protocol"),
                    credential_handle=body.get("credential_handle"),
                    now=clock.utcnow(), trace_id=request_id)
                payload = upstream.upstream_payload(declared)
                payload["created"] = created
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem, request_hash=request_hash,
                                     status_code=200, response=payload, now=clock.utcnow())
            return _ok(payload, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.upstream.declare_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/node/upstream/probe", operation_id="reportNodeUpstreamProbe",
             summary="上报本地体检结论（回执式，服务端不探测）")
async def report_node_upstream_probe(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash(body)
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                           now=clock.utcnow())
                updated = upstream.report_probe(
                    c, node=auth.node,
                    upstream_id=body.get("upstream_id"),
                    reachable=body.get("reachable"),
                    latency_ms=body.get("latency_ms"),
                    error_class=body.get("error_class"),
                    model_checks=body.get("model_checks"),
                    checked_at=body.get("checked_at"),
                    now=clock.utcnow(), trace_id=request_id)
                payload = upstream.probe_ack_payload(updated, clock.utcnow())
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem, request_hash=request_hash,
                                     status_code=200, response=payload, now=clock.utcnow())
            return _ok(payload, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.upstream.probe_failed request_id=%s", request_id)
        return _server_error(request_id)



# --------------------------------------------------------------------------- 节点通道（C10a）
# 端点归 M02（鉴权 / 状态 / 协议 / 校验 / 信封 / 幂等）；队列归 M03，经 channel 接线位注入。
@router.post("/node/channel/poll", operation_id="pollNodeChannel",
             summary="长轮询取一个任务（wait_s 内无任务 → 204）")
async def poll_node_channel(request: Request) -> Response:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        wait_s, capabilities = channel.validate_poll(body)
        with _connection() as c:
            auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                       now=clock.utcnow())
            state_machine.require_active(auth.node.state, action="channel_poll")   # INV-02
            protocol.check(request.headers.get(PROTOCOL_HEADER) or auth.node.protocol_version)
        backend = channel.require_channel_backend()            # 未接线 → 503 / 50903
        # 长等待（≤30 s）离开事件循环，且不占着数据库连接
        job = await run_in_threadpool(backend.poll, auth.node.id, wait_s=wait_s,
                                      capabilities=capabilities)
        if job is None:
            return _no_content(request_id)
        # 只记「有/无任务 + 等待时长」：任务正文（messages/content）绝不进日志
        log.info("supply.channel.poll", extra={"event": "channel.poll",
                                               "node_id": auth.node.id, "dispatched": True,
                                               "wait_s": wait_s, "trace_id": request_id})
        return _ok({"job": dict(job), "server_time": models.iso(clock.utcnow())}, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.channel.poll_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/node/channel/result", operation_id="submitNodeChannelResult",
             summary="回传任务结果（按 job_id 幂等）")
async def submit_node_channel_result(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        body = await _body(request)
        _scan(body, request, request_id)
        result = channel.validate_result(body)
        with _connection() as c:
            auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                       now=clock.utcnow())
            state_machine.require_active(auth.node.state, action="channel_result")  # INV-02
            protocol.check(request.headers.get(PROTOCOL_HEADER) or auth.node.protocol_version)
            backend = channel.require_channel_backend()        # 未接线 → 503 / 50903
            # 结果级幂等：作用域按 job_id（不含正文），同键不同载荷由 lookup 抛 40919
            scope = f"{facts.CHANNEL_IDEMPOTENCY_SCOPE_PREFIX}:{result['job_id']}"
            request_hash = idempotency.body_hash(result)
            with c.transaction():
                record = idempotency.lookup(c, scope=scope, key=auth.node.id,
                                            request_hash=request_hash)
                if record is not None:                         # 同 job 同载荷重放
                    ack = {"accepted": bool(record.response.get("accepted", True)),
                           "duplicate": True}
                else:
                    reply = backend.submit(auth.node.id, result["job_id"], result)
                    ack = {"accepted": bool(reply.get("accepted", True)),
                           "duplicate": bool(reply.get("duplicate", False))}
                    idempotency.save(c, scope=scope, key=auth.node.id,
                                     request_hash=request_hash, status_code=200,
                                     response=ack, now=clock.utcnow())
            log.info("supply.channel.result", extra={"event": "channel.result",
                                                     "node_id": auth.node.id,
                                                     "status": result["status"],
                                                     "duplicate": ack["duplicate"],
                                                     "trace_id": request_id})
            return _ok(ack, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.channel.result_failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- 策略（T5）
POLICY_ETAG_SWITCH = "supply.policy_etag_304"
_CONDITIONAL_SWITCH = POLICY_ETAG_SWITCH


@router.get("/node/policy", operation_id="getNodePolicy", summary="拉取策略与配额（版本化）")
def get_node_policy(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        with _connection() as c:
            auth = models.authenticate(c, _node_key(request), allow_previous=True,
                                       now=clock.utcnow())
            node = auth.node
            # pending（未准入）/ retired 不发放策略；frozen 允许读（只读提示，M02 §3）
            if node.state == "retired":
                raise errors.NodeStateForbidden("节点已清退，不再下发策略", state=node.state,
                                                action="fetch_policy")
            if node.state not in ("active", "frozen"):
                state_machine.require_active(node.state, action="fetch_policy")
            # 协议版本：优先用请求头（spec ProtocolVersion），缺省用节点注册时的版本
            protocol.check(request.headers.get(PROTOCOL_HEADER) or node.protocol_version)
            with c.transaction():
                current = policy.ensure_for_node(c, node=node, now=clock.utcnow())
            body = policy.policy_payload(current)
            etag = current.etag
            if features.enabled(_CONDITIONAL_SWITCH) \
                    and policy.etag_matches(request.headers.get("If-None-Match"), current):
                return JSONResponse(None, status_code=304,
                                    headers=_headers(request_id, ETag=etag))
            return _ok(body, request_id, ETag=etag)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.policy.failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- 协议（T6）
@router.get("/protocol/capabilities", operation_id="getProtocolCapabilities",
            summary="能力协商（双方只启用交集）", openapi_extra={"security": []})
def get_protocol_capabilities(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        client_version = request.headers.get(PROTOCOL_HEADER)
        if client_version:
            protocol.check(client_version)
        payload = protocol.capabilities_payload(
            server_time=clock.utcnow(), client_version=client_version,
            client_capabilities=protocol.parse_capability_header(
                request.headers.get(CAPABILITIES_HEADER)))
        return _ok(payload, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.protocol.capabilities_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.get("/protocol/deprecations", operation_id="getProtocolDeprecations",
            summary="弃用清单与退役日期", openapi_extra={"security": []})
def get_protocol_deprecations(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        raw_major = request.query_params.get("protocol_major")
        protocol_major = None
        if raw_major is not None:
            try:
                protocol_major = int(raw_major)
            except (TypeError, ValueError) as exc:
                raise errors.InvalidArgument("protocol_major 必须是整数",
                                             field="protocol_major") from exc
        return _ok(protocol.deprecations_payload(protocol_major=protocol_major), request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.protocol.deprecations_failed request_id=%s", request_id)
        return _server_error(request_id)


# --------------------------------------------------------------------------- 用户态节点面（spec 1.2.6）
@router.get("/user/nodes", operation_id="listUserNodes",
            summary="我的节点（绑定状态 / 最近心跳 / 已生效版本）")
def list_user_nodes(request: Request) -> JSONResponse:
    """分页返回本账户节点（含已解绑历史）；越权一律 404（不泄露存在性）。"""
    request_id = _request_id(request)
    try:
        principal = _user_principal_sync(request)
        account_id = _account_uuid(principal)
        limit = None
        raw_limit = request.query_params.get("limit")
        if raw_limit is not None:
            if not raw_limit.strip().isdigit():
                raise errors.InvalidArgument("limit 必须是整数", field="limit")
            limit = int(raw_limit)
        with _connection() as c:
            payload = user_nodes.list_page(
                c, account_id=account_id, state=request.query_params.get("state"),
                lifecycle_state=request.query_params.get("lifecycle_state"),
                cursor=request.query_params.get("cursor"), limit=limit)
        return _ok(payload, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.user_nodes.list_failed request_id=%s", request_id)
        return _server_error(request_id)


@router.post("/user/nodes/{node_id}/unbind", operation_id="unbindUserNode",
             summary="解绑我的节点（幂等；需 step-up）")
async def unbind_user_node(node_id: str, request: Request) -> JSONResponse:
    """会话态解绑：撤销客户端密钥 + 解除绑定；重复调用返回同一结果（spec 1.2.6）。"""
    request_id = _request_id(request)
    try:
        principal = _user_principal_sync(request)
        account_id = _account_uuid(principal)
        if not principal.get("step_up"):
            raise errors.StepUpRequired("解绑节点需要 step-up（M02 §4.1）")
        body = await _body(request)
        _scan(body, request, request_id)
        key_idem = _idem_key(request)
        scope = idempotency.scope_of(request.method, request.url.path)
        request_hash = idempotency.body_hash(body)
        with _connection() as c:
            if key_idem:
                record = idempotency.lookup(c, scope=scope, key=key_idem,
                                            request_hash=request_hash)
                if record is not None:
                    return _ok(record.response, request_id)
            with c.transaction():
                view = user_nodes.unbind(c, node_id=node_id, account_id=account_id,
                                         reason=body.get("reason"), now=clock.utcnow(),
                                         trace_id=request_id)
                if key_idem:
                    idempotency.save(c, scope=scope, key=key_idem,
                                     request_hash=request_hash, status_code=200,
                                     response=view, now=clock.utcnow())
            return _ok(view, request_id)
    except errors.SupplyError as exc:
        return _fail(exc, request_id)
    except Exception:                                          # pragma: no cover - 兜底
        log.exception("supply.user_nodes.unbind_failed request_id=%s", request_id)
        return _server_error(request_id)


__all__ = ["router", "set_admin_authenticator", "admin_authenticator",
           "set_user_authenticator", "user_authenticator",
           "NODE_KEY_HEADER", "IDEMPOTENCY_HEADER", "STEP_UP_HEADER"]
