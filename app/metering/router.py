# SPDX-License-Identifier: Apache-2.0
"""M05 T1/T2 HTTP 路由（独立模块，**不接 app/api.py** —— 由 Lead 合并时统一 include）。

覆盖 spec 1.2.x 里 M05 的四条操作::

    POST /api/v1/node/receipts                  submitNodeReceipts      200（逐条受理）
    GET  /api/v1/node/receipts/{receipt_id}     getNodeReceipt          200 / 404
    GET  /api/v1/user/usage/summary             getUserUsageSummary     200
    GET  /api/v1/user/usage/records             listUserUsageRecords    200

约定（00-conventions §5 / spec ``Error``）：

- 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
  任何响应都回显 ``X-Request-Id``。
- 请求体自己校验（不依赖框架 422）：不合法一律 400 / 40001；收据批 >500 条 → 413 / 40013。
- 逐条拒收**不进 HTTP 信封**：``{accepted[], rejected[{receipt_id, code, message}], duplicates[]}``，
  HTTP 仍是 200（M05 §4.1 / spec ``ReceiptBatchResponse``）。
- 金额只在入口解析成整数分，出口一律 ``Amount``（十进制字符串 + USD）。

认证（两个**依赖注入钩子**，默认 **fail-closed**，合并时由 Lead 接线）::

    set_node_authenticator   节点侧 X-Client-Key（M02 已验证的节点身份 → {"node_id": ...}）
    set_user_authenticator   用方 JWT / API Key（M01 → {"account_id": ..., "tenant_id": ...}）

数据库连接经 :func:`_connection`（``app.db`` 既有约定：成功提交、异常回滚）；
测试用 ``monkeypatch.setattr(router_module, "_connection", ...)`` 指向隔离 schema。
"""
from __future__ import annotations

import inspect
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import clock, errors, facts, models, receipts, usage

log = logging.getLogger("djb.metering.http")

router = APIRouter(prefix="/api/v1", tags=["metering"])

NODE_KEY_HEADER = "X-Client-Key"

Principal = Callable[[Request], "dict[str, Any] | Awaitable[dict[str, Any]]"]
_node_authenticator: Principal | None = None
_user_authenticator: Principal | None = None


# --------------------------------------------------------------------------- 接线钩子
def set_node_authenticator(authenticator: Principal | None) -> None:
    global _node_authenticator
    _node_authenticator = authenticator


def set_user_authenticator(authenticator: Principal | None) -> None:
    global _user_authenticator
    _user_authenticator = authenticator


async def _principal(authenticator: Principal | None, request: Request, *,
                     what: str) -> dict[str, Any]:
    """统一的 fail-closed 主体解析：未接线即 401，主体非法即 401。"""
    if authenticator is None:
        raise errors.AuthUnavailable(f"{what}鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = authenticator(request)
    if inspect.isawaitable(resolved):
        resolved = await resolved
    if not isinstance(resolved, dict):
        raise errors.AuthUnavailable(f"{what}鉴权返回非法主体")
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


def _fail(exc: errors.MeteringError, request_id: str) -> JSONResponse:
    body = {"error": {"type": errors.error_type_for(exc.status_code),
                      "code": int(exc.code), "message": exc.message,
                      "request_id": request_id, "reason": exc.reason,
                      **{key: value for key, value in exc.details.items()
                         if key != "reason"}}}
    return JSONResponse(body, status_code=exc.status_code, headers=_headers(request_id))


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


def _account_id(principal: dict[str, Any]) -> str:
    """用方主体必须有账户（M01）；缺失即 401（不猜、不回落）。"""
    value = principal.get("account_id")
    if not value:
        raise errors.Unauthorized("主体缺少 account_id")
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError) as exc:
        raise errors.Unauthorized("主体 account_id 非法") from exc


# --------------------------------------------------------------------------- 收据受理
@router.post("/node/receipts")
async def submit_node_receipts(request: Request) -> JSONResponse:
    """批量双签收据（1–500 条，逐条受理，INV-02）。"""
    request_id = _request_id(request)
    try:
        principal = await _principal(_node_authenticator, request, what="节点侧")
        body = await _body(request)
        batch = body.get("receipts")
        if not isinstance(batch, list):
            raise errors.InvalidArgument("receipts 必须是数组（spec ReceiptBatchRequest）",
                                         field="receipts")
        if len(batch) < facts.BATCH_MIN:
            raise errors.InvalidArgument("receipts 至少 1 条（spec minItems）", field="receipts")
        if len(batch) > facts.BATCH_MAX:
            raise errors.BatchTooLarge(
                f"收据批最多 {facts.BATCH_MAX} 条（spec maxItems=500）")
        node_id = (principal.get("node_id") or "").strip() or None
        with _connection() as c:
            outcome = receipts.accept_batch(c, batch, node_id=node_id, trace_id=request_id)
        return _ok(outcome.as_response(), request_id)
    except errors.MeteringError as exc:
        return _fail(exc, request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("metering.http.receipts_failed", extra={"request_id": request_id})
        return _server_error(request_id)


@router.get("/node/receipts/{receipt_id}")
def get_node_receipt(receipt_id: str, request: Request) -> JSONResponse:
    """单条收据受理结果（节点自查；跨节点一律 404，不泄露存在性）。"""
    request_id = _request_id(request)
    try:
        principal = _principal_sync(_node_authenticator, request, what="节点侧")
        node_id = (principal.get("node_id") or "").strip() or None
        with _connection() as c:
            status = receipts.receipt_status(c, receipt_id=receipt_id, node_id=node_id)
        if status is None:
            raise errors.NotFound("收据不存在", object="receipt")
        return _ok(status, request_id)
    except errors.MeteringError as exc:
        return _fail(exc, request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("metering.http.receipt_failed", extra={"request_id": request_id})
        return _server_error(request_id)


def _principal_sync(authenticator: Principal | None, request: Request, *,
                    what: str) -> dict[str, Any]:
    """同步端点用的主体解析（钩子返回 awaitable 时不支持：GET 一律走同步钩子）。"""
    if authenticator is None:
        raise errors.AuthUnavailable(f"{what}鉴权未接线：合并时由 Lead 注入（fail-closed）")
    resolved = authenticator(request)
    if inspect.isawaitable(resolved):                      # pragma: no cover - 防御
        resolved.close()
        raise errors.AuthUnavailable(f"{what}鉴权钩子必须是同步函数")
    if not isinstance(resolved, dict):
        raise errors.AuthUnavailable(f"{what}鉴权返回非法主体")
    return resolved


# --------------------------------------------------------------------------- 用量查询
def _default_window(request: Request) -> tuple[datetime, datetime]:
    """未传 from/to 时的默认窗口：``to`` 所在月份 1 日 00:00 UTC → ``to``。

    口径来源 00-conventions §4.2（报表周期按 UTC 日 / 月）：默认给「本月至今」，
    既不是随手拍的天数，也不受本地时区影响；``to`` 是日期时按当日末含端点。
    """
    to_raw = request.query_params.get("to")
    end = models.parse_moment(to_raw, field="to", end_of_day=True) if to_raw else clock.utcnow()
    from_raw = request.query_params.get("from")
    if from_raw:
        start = models.parse_moment(from_raw, field="from")
    else:
        moment = end.astimezone(timezone.utc)
        start = moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start, end


@router.get("/user/usage/summary")
def get_user_usage_summary(request: Request) -> JSONResponse:
    """用量汇总（``group_by=model|day``；只读本账户）。"""
    request_id = _request_id(request)
    try:
        principal = _principal_sync(_user_authenticator, request, what="用方")
        account_id = _account_id(principal)
        group_by = (request.query_params.get("group_by") or "model").strip()
        start, end = _default_window(request)
        with _connection() as c:
            payload = usage.summary(c, account_id=account_id, date_from=start, date_to=end,
                                    group_by=group_by)
        return _ok(payload, request_id)
    except errors.MeteringError as exc:
        return _fail(exc, request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("metering.http.summary_failed", extra={"request_id": request_id})
        return _server_error(request_id)


@router.get("/user/usage/records")
def list_user_usage_records(request: Request) -> JSONResponse:
    """用量明细（游标分页，默认 50 / 上限 200）。"""
    request_id = _request_id(request)
    try:
        principal = _principal_sync(_user_authenticator, request, what="用方")
        account_id = _account_id(principal)
        params = request.query_params
        limit_raw = params.get("limit")
        limit = None
        if limit_raw is not None:
            if not limit_raw.strip().isdigit():
                raise errors.InvalidArgument("limit 必须是整数", field="limit")
            limit = int(limit_raw)
        with _connection() as c:
            payload = usage.records_page(
                c, account_id=account_id, limit=limit, cursor=params.get("cursor"),
                model=params.get("model"), state=params.get("state"),
                date_from=params.get("from"), date_to=params.get("to"))
        return _ok(payload, request_id)
    except errors.MeteringError as exc:
        return _fail(exc, request_id)
    except Exception:                                      # pragma: no cover - 防御
        log.exception("metering.http.records_failed", extra={"request_id": request_id})
        return _server_error(request_id)


__all__ = ["router", "set_node_authenticator", "set_user_authenticator", "submit_node_receipts",
           "get_node_receipt", "get_user_usage_summary", "list_user_usage_records"]
