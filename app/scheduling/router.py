# SPDX-License-Identifier: Apache-2.0
"""M04 T1/T2 HTTP 路由（独立模块，**不接 app/api.py**——由 Lead 合并时统一 include）。

覆盖 spec 1.2.x 中 M04 的六个操作::

    POST /api/v1/schedule/quotes                   createQuote            201
    POST /api/v1/schedule/bids                     createBid              201
    POST /api/v1/schedule/route                    createRouteDecision    201
    POST /api/v1/schedule/replay                   createScheduleReplay   202
    GET  /api/v1/schedule/decisions/{decision_id}  getRoutingDecision     200
    GET  /api/v1/schedule/snapshot/{period}        ——（公开只读）          200

约定（00-conventions §5 / spec ``Error``）：

- 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**，
  ``type`` 取 spec 枚举；任何响应都回显 ``X-Request-Id``。
- 请求体自己校验（不依赖框架 422）：不合法一律 400 / 40001。
- 金额走 spec ``Amount``（十进制字符串），进门即转整数分；超精度 400 / 40001（INV-13）。
- 幂等：M04 §3 的「(scope, key) 唯一 24 h」需要幂等表，而 M04 §5 只登记了 6 张表，
  幂等表未登记 → T1/T2 用**业务幂等**覆盖同等语义：报价 / 出价「内容不变不升版本」、
  route 走「四元锚点唯一」（重复提交回同一 ``decision_id``，不重复锁量）。

认证（四个**依赖注入钩子**，默认 **fail-closed**，合并时由 Lead 接线）::

    set_node_authenticator     节点侧 X-Client-Key（M02 已验证的节点身份）
    set_user_authenticator     用方 JWT / API Key（M01）
    set_internal_authenticator 服务间 mTLS（M03 网关调用 route）
    set_admin_authenticator    管理面（M01 会话 + step-up），replay / decisions 用

数据库连接经 :func:`_connection`（app.db 既有约定：成功提交、异常回滚）；
测试用 ``monkeypatch.setattr(router_module, "_connection", ...)`` 指向隔离 schema。
"""
from __future__ import annotations

import inspect
import logging
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import (bids, candidates, clock, decisions, errors, facts, models, pipeline, quotes,
               replay, snapshot)

log = logging.getLogger("djb.scheduling.http")

router = APIRouter(prefix="/api/v1", tags=["schedule"])

NODE_KEY_HEADER = "X-Client-Key"
IDEMPOTENCY_HEADER = "X-DJB-Idempotency-Key"
STEP_UP_HEADER = "X-Admin-Step-Up"

Principal = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
_node_authenticator: Principal | None = None
_user_authenticator: Principal | None = None
_internal_authenticator: Principal | None = None
_admin_authenticator: Principal | None = None


# --------------------------------------------------------------------------- 接线钩子
def set_node_authenticator(authenticator: Principal | None) -> None:
    global _node_authenticator
    _node_authenticator = authenticator


def set_user_authenticator(authenticator: Principal | None) -> None:
    global _user_authenticator
    _user_authenticator = authenticator


def set_internal_authenticator(authenticator: Principal | None) -> None:
    global _internal_authenticator
    _internal_authenticator = authenticator


def set_admin_authenticator(authenticator: Principal | None) -> None:
    global _admin_authenticator
    _admin_authenticator = authenticator


async def _principal(authenticator: Principal | None, request: Request, *, what: str,
                     require_step_up: bool = False) -> dict[str, Any]:
    """统一的 fail-closed 主体解析：未接线即 401，主体非法即 401，缺 step-up 即 424。"""
    if authenticator is None:
        raise errors.AuthUnavailable(f"{what}鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = authenticator(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, dict):
        raise errors.AuthUnavailable(f"{what}鉴权返回非法主体")
    if require_step_up and not resolved.get("step_up"):
        raise errors.StepUpRequired("高危动作需要 step-up（X-Admin-Step-Up）")
    return resolved


def _connection() -> Any:
    """请求级连接（app.db 的既有约定：成功提交、异常回滚）。"""
    from app.db import conn as db_conn                     # 基础设施，非业务模块

    return db_conn()                                       # pragma: no cover - 部署期接线


# --------------------------------------------------------------------------- 信封
def _request_id(request: Request) -> str:
    return (request.headers.get("X-Request-Id") or "").strip() or uuid.uuid4().hex


def _headers(request_id: str, **extra: str) -> dict[str, str]:
    merged = {"X-Request-Id": request_id}
    merged.update({key: value for key, value in extra.items() if value})
    return merged


def _ok(payload: dict[str, Any], request_id: str, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=_headers(request_id))


def _fail(exc: errors.SchedulingError, request_id: str) -> JSONResponse:
    body = {"error": {"type": errors.error_type_for(exc.status_code),
                      "code": int(exc.code), "message": exc.message,
                      "request_id": request_id, "reason": exc.reason,
                      **{key: value for key, value in exc.details.items()
                         if key != "reason"}}}
    extra: dict[str, str] = {}
    retry_after = exc.details.get("retry_after_s")
    if exc.status_code == 429 and retry_after:
        extra["Retry-After"] = str(int(retry_after))
    return JSONResponse(body, status_code=exc.status_code,
                        headers=_headers(request_id, **extra))


def _server_error(request_id: str) -> JSONResponse:
    body = {"error": {"type": "server_error", "code": 50001, "message": "服务繁忙",
                      "request_id": request_id}}
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


def _idem_key(request: Request) -> str | None:
    value = (request.headers.get(IDEMPOTENCY_HEADER) or "").strip()
    if not value:
        return None
    if len(value) > facts.IDEMPOTENCY_KEY_MAX_LEN:
        raise errors.InvalidArgument(
            f"{IDEMPOTENCY_HEADER} 最多 {facts.IDEMPOTENCY_KEY_MAX_LEN} 字符",
            field=IDEMPOTENCY_HEADER)
    return value


# --------------------------------------------------------------------------- 公开快照
@router.get("/schedule/snapshot/{period}")
def get_schedule_snapshot(period: str, request: Request) -> JSONResponse:
    """公开快照（输入 + ``quote_version``）；只读、无需鉴权。"""
    request_id = _request_id(request)
    model = (request.query_params.get("model") or "").strip() or None
    try:
        with _connection() as c:
            payload = snapshot.build(c, period=period, model=model)
        return _ok(payload, request_id)
    except errors.SchedulingError as exc:
        return _fail(exc, request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("scheduling.http.snapshot_failed")
        return _server_error(request_id)


# --------------------------------------------------------------------------- 报价
@router.post("/schedule/quotes")
async def create_quote(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _principal(_node_authenticator, request, what="节点侧")
        body = await _body(request)
        _idem_key(request)
        node_id = (body.get("node_id") or principal.get("node_id") or "").strip()
        if not node_id:
            raise errors.InvalidArgument("缺 node_id（或未接线节点身份）", field="node_id")
        if principal.get("node_id") and node_id != principal["node_id"]:
            raise errors.Forbidden("不能代表其它节点报价", reason="node_identity_mismatch")
        access = str(body.get("access") or "").strip().upper()
        model = models.normalize_model(body.get("model") or "")
        unit = str(body.get("unit") or "").strip()
        if not unit:
            raise errors.InvalidArgument("缺 unit（计量单位）", field="unit")
        models.check_currency(body)
        ask_minor, max_minor = models.parse_price_pair(
            body, low_key="price_min", high_key="price_max")
        ttl_s = body.get("ttl_s")
        if not isinstance(ttl_s, int) or isinstance(ttl_s, bool):
            raise errors.InvalidArgument("ttl_s 必须是整数秒（spec QuoteRequest 必填）",
                                         field="ttl_s")
        with _connection() as c:
            result = quotes.register(c, node_id=node_id, access=access, model=model, unit=unit,
                                     ask_price_minor=ask_minor, price_max_minor=max_minor,
                                     ttl_s=ttl_s, now=clock.utcnow(), trace_id=request_id)
        quote = result.quote
        return _ok({"quote_id": quote.quote_id, "state": quote.state,
                    "quote_version": quote.quote_version,
                    "expires_at": quote.expires_at.isoformat(),
                    "created": result.created}, request_id, status_code=201)
    except errors.SchedulingError as exc:
        return _fail(exc, request_id)
    except ValueError as exc:
        return _fail(errors.InvalidArgument(str(exc)), request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("scheduling.http.quote_failed")
        return _server_error(request_id)


# --------------------------------------------------------------------------- 出价
@router.post("/schedule/bids")
async def create_bid(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _principal(_user_authenticator, request, what="用方")
        body = await _body(request)
        _idem_key(request)
        tenant_id = parse_tenant_id(principal.get("tenant_id"), "tenant_id")
        model = models.normalize_model(body.get("model") or "")
        models.check_currency(body)
        min_minor, max_minor = models.parse_price_pair(
            body, low_key="min_price", high_key="max_price")
        window = body.get("window_seconds")
        if window is not None and (not isinstance(window, int) or isinstance(window, bool)):
            raise errors.InvalidArgument("window_seconds 必须是整数秒", field="window_seconds")
        with _connection() as c:
            result = bids.register(c, tenant_id=tenant_id, model=model,
                                   min_price_minor=min_minor, max_price_minor=max_minor,
                                   strategy=body.get("strategy"), window_seconds=window,
                                   now=clock.utcnow(), trace_id=request_id)
        bid = result.bid
        return _ok({"bid_id": bid.bid_id, "state": bid.state,
                    "expires_at": bid.expires_at.isoformat(),
                    "strategy": bid.strategy, "created": result.created},
                   request_id, status_code=201)
    except errors.SchedulingError as exc:
        return _fail(exc, request_id)
    except ValueError as exc:
        return _fail(errors.InvalidArgument(str(exc)), request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("scheduling.http.bid_failed")
        return _server_error(request_id)


# --------------------------------------------------------------------------- 路由
@router.post("/schedule/route")
async def create_route_decision(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        principal = await _principal(_internal_authenticator, request, what="内部调用")
        body = await _body(request)
        _idem_key(request)
        route = _route_input(body, principal, request_id)
        concurrency = _concurrency(principal, body)
        with _connection() as c:
            decision, created = pipeline.execute(
                c, route, now=clock.utcnow(),
                platform_concurrency=concurrency[0], terminal_concurrency=concurrency[1],
                request_id=request_id)
        if decision.outcome in ("rejected",):
            raise errors.NoRoute("无可用节点（45001）", reason="no_route",
                                 reason_codes=list(decision.reason_codes),
                                 actions=list(facts.REJECT_ACTIONS),
                                 eliminated=list(decision.eliminated),
                                 decision_id=str(decision.decision_id))
        payload = decision.as_dict()
        payload["created"] = created
        return _ok(payload, request_id, status_code=201)
    except errors.SchedulingError as exc:
        return _fail(exc, request_id)
    except ValueError as exc:
        return _fail(errors.InvalidArgument(str(exc)), request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("scheduling.http.route_failed")
        return _server_error(request_id)


def _route_input(body: dict[str, Any], principal: dict[str, Any], request_id: str) \
        -> candidates.RouteInput:
    model = models.normalize_model(body.get("model") or "")
    kind = str(body.get("kind") or "").strip().lower()
    if kind not in facts.TIERS:
        raise errors.InvalidArgument(f"kind 必须是 {facts.TIERS} 之一", field="kind")
    tenant_id = parse_tenant_id(principal.get("tenant_id"), "tenant_id")
    claimed = body.get("tenant_id")
    if claimed is not None and str(claimed).strip() and str(claimed).strip() != str(tenant_id):
        raise errors.Forbidden("请求体 tenant_id 与认证主体不一致（伪造 tenant_id）",
                               reason="tenant_mismatch")     # M04 §9 安全用例
    required_access = body.get("required_access") or []
    if not isinstance(required_access, list) or any(item not in facts.ACCESS_TYPES
                                                    for item in required_access):
        raise errors.InvalidArgument(f"required_access 必须是 {facts.ACCESS_TYPES} 的子集",
                                     field="required_access")
    requested_tokens = body.get("requested_tokens")
    if requested_tokens is not None and (not isinstance(requested_tokens, int)
                                         or isinstance(requested_tokens, bool)
                                         or requested_tokens < 1):
        raise errors.InvalidArgument("requested_tokens 必须是正整数", field="requested_tokens")
    deadline = body.get("deadline_seconds")
    if deadline is not None and (not isinstance(deadline, int) or isinstance(deadline, bool)
                                 or deadline < 1):
        raise errors.InvalidArgument("deadline_seconds 必须是正整数", field="deadline_seconds")
    max_price = body.get("max_price")
    max_minor = models.parse_amount(max_price, field_name="max_price") \
        if max_price is not None else None
    attempt_no = body.get("attempt_no", 1)
    if not isinstance(attempt_no, int) or isinstance(attempt_no, bool) \
            or not 1 <= attempt_no <= facts.MAX_ATTEMPTS:
        raise errors.InvalidArgument(f"attempt_no 必须是 1–{facts.MAX_ATTEMPTS}（INV-12）",
                                     field="attempt_no")
    return candidates.RouteInput(
        model=model, kind=kind, tenant_id=tenant_id,
        trace_id=str(body.get("trace_id") or request_id).strip()[:128],
        requested_tokens=requested_tokens, deadline_seconds=deadline,
        required_access=tuple(required_access), max_price_minor=max_minor,
        attempt_no=attempt_no)


def _concurrency(principal: dict[str, Any], body: dict[str, Any]) \
        -> tuple[int | None, int | None]:
    """平台下发 / 终端上报的并发（INV-07）：先看主体，再看请求体覆盖。"""
    platform = body.get("platform_concurrency", principal.get("platform_concurrency"))
    terminal = body.get("terminal_concurrency", principal.get("terminal_concurrency"))
    return (_opt_int(platform, "platform_concurrency"), _opt_int(terminal, "terminal_concurrency"))


def _opt_int(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise errors.InvalidArgument(f"{field_name} 必须是非负整数", field=field_name)
    return value


def parse_tenant_id(value: Any, field_name: str) -> uuid.UUID:
    """把认证主体里的租户标识解析成 UUID（缺失 / 非法 → 401，不猜）。"""
    if value is None:
        raise errors.Unauthorized(f"认证主体缺 {field_name}", reason="missing_principal_field")
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError) as exc:
        raise errors.Unauthorized(f"认证主体的 {field_name} 形态非法",
                                  reason="bad_principal_field") from exc


# --------------------------------------------------------------------------- 复算
@router.post("/schedule/replay")
async def create_schedule_replay(request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        await _principal(_admin_authenticator, request, what="管理面", require_step_up=True)
        body = await _body(request)
        _idem_key(request)
        from_ts = _parse_ts(body.get("from"), "from")
        to_ts = _parse_ts(body.get("to"), "to")
        decision_ids = body.get("decision_ids")
        if decision_ids is not None and (not isinstance(decision_ids, list)
                                         or any(not isinstance(item, str) for item in decision_ids)):
            raise errors.InvalidArgument("decision_ids 必须是字符串数组", field="decision_ids")
        with _connection() as c:
            job = replay.start(c, from_ts=from_ts, to_ts=to_ts,
                               decision_ids=decision_ids, now=clock.utcnow())
        return _ok({"job_id": job.as_dict()["job_id"], "state": job.state,
                    "requested_at": job.requested_at.isoformat(),
                    "decisions_total": job.decisions_total,
                    "consistent": job.consistent,
                    "inconsistent": job.report.get("inconsistent")},
                   request_id, status_code=202)
    except errors.SchedulingError as exc:
        return _fail(exc, request_id)
    except ValueError as exc:
        return _fail(errors.InvalidArgument(str(exc)), request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("scheduling.http.replay_failed")
        return _server_error(request_id)


def _parse_ts(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise errors.InvalidArgument(f"{field_name} 必须是 ISO-8601 时刻", field=field_name)
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise errors.InvalidArgument(f"{field_name} 不是合法的 ISO-8601 时刻",
                                     field=field_name) from exc


# --------------------------------------------------------------------------- 决策下钻
@router.get("/schedule/decisions/{decision_id}")
def get_routing_decision(decision_id: str, request: Request) -> JSONResponse:
    request_id = _request_id(request)
    try:
        _principal_sync(_admin_authenticator, request, what="管理面")
        with _connection() as c:
            record = decisions.get(c, decision_id)
        return _ok(record.as_dict(), request_id)
    except errors.SchedulingError as exc:
        return _fail(exc, request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("scheduling.http.decision_failed")
        return _server_error(request_id)


def _principal_sync(authenticator: Principal | None, request: Request, *, what: str,
                    require_step_up: bool = False) -> dict[str, Any]:
    """同步端点的主体解析（钩子允许返回 awaitable 时，sync 端点只接受同步结果）。"""
    if authenticator is None:
        raise errors.AuthUnavailable(f"{what}鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = authenticator(request)
    if inspect.isawaitable(resolved):                      # pragma: no cover - 接线约束
        raise errors.AuthUnavailable(f"{what}鉴权钩子必须同步可返回（sync 端点）")
    if not isinstance(resolved, dict):
        raise errors.AuthUnavailable(f"{what}鉴权返回非法主体")
    if require_step_up and not resolved.get("step_up"):
        raise errors.StepUpRequired("高危动作需要 step-up（X-Admin-Step-Up）")
    return resolved


__all__ = ["router", "set_node_authenticator", "set_user_authenticator",
           "set_internal_authenticator", "set_admin_authenticator", "parse_tenant_id"]
