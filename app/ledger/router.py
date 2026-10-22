# SPDX-License-Identifier: Apache-2.0
"""M06 管理面路由（6 端点）：试算 / 科目余额 / Merkle / 复算 / 凭证 / 冲正。

**不修改 ``app/api.py``**：本文件只导出 ``router``，接线由 lead 合并时做::

    from app.ledger.router import router as ledger_router
    app.include_router(ledger_router)

契约（spec 1.2.1，operationId 是硬门，``OPERATIONS`` 与注册路由导入期互相校验）::

    getLedgerTrialBalance   GET  /api/v1/admin/ledger/trial-balance
    listLedgerAccounts      GET  /api/v1/admin/ledger/accounts
    getLedgerMerkleRoot     GET  /api/v1/admin/ledger/merkle/{period}
    recomputeLedger         POST /api/v1/admin/ledger/recompute
    getLedgerJournal        GET  /api/v1/admin/ledger/journals/{id}
    createLedgerReversal    POST /api/v1/admin/ledger/reversals

错误信封（spec Error）：``{"error": {type, code, message, request_id}}``；码值段
``40920–40924`` / ``42220–42223``（CR-L1）+ ``42401``（step-up）+ ``40301``（403 段唯一已登记码）
+ ``40902``（复核人 = 操作人，spec 1.2.1 的 reversals 描述）。

鉴权（过渡期实现，接线时替换）：只校验 step-up 头存在与新鲜度（≤5 分钟）+ 角色白名单；
真正的签名与权限判定由 M01 的管理面鉴权中间件提供，权限位登记在 ``OPERATIONS`` 里供接线方对齐。
"""
from __future__ import annotations

import functools
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from .. import db
from . import balances, merkle, reversal, trial, verify
from .constants import MAX_REASON_TEXT_LEN, RECOMPUTE_LOCK_ID, STEP_UP_MAX_AGE_S, UNIT_TYPES
from .errors import LedgerError
from .gateway import load_journal

router = APIRouter(prefix="/api/v1/admin/ledger", tags=["admin"])

# operationId → 权限位（permission 供 M01 鉴权接线对齐；step_up/write 决定本文件的过渡期校验）
OPERATIONS: dict[str, dict[str, Any]] = {
    "getLedgerTrialBalance": {"method": "GET", "path": "/api/v1/admin/ledger/trial-balance",
                              "permission": "ledger.read", "step_up": True, "write": False},
    "listLedgerAccounts": {"method": "GET", "path": "/api/v1/admin/ledger/accounts",
                           "permission": "ledger.read", "step_up": True, "write": False},
    "getLedgerMerkleRoot": {"method": "GET", "path": "/api/v1/admin/ledger/merkle/{period}",
                            "permission": "ledger.read", "step_up": True, "write": False},
    "recomputeLedger": {"method": "POST", "path": "/api/v1/admin/ledger/recompute",
                        "permission": "ledger.recompute", "step_up": True, "write": True},
    "getLedgerJournal": {"method": "GET", "path": "/api/v1/admin/ledger/journals/{id}",
                         "permission": "ledger.read", "step_up": True, "write": False},
    "createLedgerReversal": {"method": "POST", "path": "/api/v1/admin/ledger/reversals",
                             "permission": "ledger.reversal", "step_up": True, "write": True},
}

_READ_ROLES = frozenset({"super", "ops", "fin", "audit", "viewer"})
_WRITE_ROLES = frozenset({"super", "fin"})

# 域码 → HTTP 状态（spec 1.2.1：40921 原凭证已冲正 / 40920 并发冲突 / 40924 不存在 / 422xx 语义）
_STATUS_BY_CODE = {
    "42401": 424, "40301": 403, "40902": 409,
    "40920": 409, "40921": 409, "40924": 404,
    "42220": 422, "42221": 422, "42222": 422, "42223": 422,
}
_TYPE_BY_STATUS = {
    400: "invalid_request_error", 401: "authentication_error", 403: "permission_error",
    404: "not_found_error", 409: "conflict_error", 422: "invalid_request_error",
    424: "authentication_error",
}


class ApiError(Exception):
    """管理面错误（携带 HTTP 状态 + 数字码）。"""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Principal:
    actor: str
    roles: frozenset[str]
    step_up_ref: str | None


# ────────────────────────────────────────────── 信封 / 请求上下文
def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-Id") or uuid.uuid4().hex


def _envelope(code: str, message: str, request_id: str, *, status: int) -> dict:
    return {"error": {"type": _TYPE_BY_STATUS.get(status, "server_error"),
                      "code": int(code) if code.isdigit() else code,
                      "message": message, "request_id": request_id}}


def _respond(payload: Any, request_id: str, status: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status, content=jsonable_encoder(payload),
                        headers={"X-Request-Id": request_id})


def _fail(error: ApiError, request_id: str) -> JSONResponse:
    return JSONResponse(status_code=error.status,
                        content=_envelope(error.code, error.message, request_id, status=error.status),
                        headers={"X-Request-Id": request_id})


def _api_errors(fn: Callable) -> Callable:
    """把 ApiError / 域错误统一渲染成 spec 的 Error 信封（不泄漏内部堆栈）。"""

    @functools.wraps(fn)
    def wrapper(request: Request, *args, **kwargs):
        request_id = _request_id(request)
        try:
            return fn(request, *args, **kwargs)
        except ApiError as exc:
            return _fail(exc, request_id)
        except LedgerError as exc:
            status = _STATUS_BY_CODE.get(str(exc.code), 422)
            return JSONResponse(
                status_code=status,
                content=_envelope(str(exc.code), exc.message, request_id, status=status),
                headers={"X-Request-Id": request_id})

    return wrapper


def require_admin(request: Request, *, write: bool) -> Principal:
    """过渡期鉴权：step-up 必须存在且新鲜；写操作要 FIN/SUPER 角色。

    真正的签名校验 / 角色来源由 M01 管理面鉴权中间件在接线时提供（OPERATIONS.permission 是权限位）。
    """
    step_up = (request.headers.get("X-Admin-Step-Up") or "").strip()
    if not step_up:
        raise ApiError(424, "42401",
                       "缺少 X-Admin-Step-Up：敏感操作需 ≤5 分钟内完成二次认证（step-up）")
    if step_up.isdigit():                      # 过渡期约定：纯数字视为签发时刻（epoch 秒）
        if abs(time.time() - int(step_up)) > STEP_UP_MAX_AGE_S:
            raise ApiError(424, "42401", f"step-up 已过期（有效期 {STEP_UP_MAX_AGE_S}s），请重新认证")
    roles = frozenset(role.strip().lower()
                      for role in (request.headers.get("X-Admin-Roles") or "viewer").split(",")
                      if role.strip())
    if write and not (roles & _WRITE_ROLES):
        raise ApiError(403, "40301",
                       f"权限不足：该操作需要 {sorted(_WRITE_ROLES)} 之一，当前角色 {sorted(roles)}")
    actor = (request.headers.get("X-Admin-Actor") or "admin").strip() or "admin"
    return Principal(actor=actor, roles=roles & _READ_ROLES if not write else roles,
                     step_up_ref=step_up)


def _parse_ts(value: str | None, field: str = "as_of") -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiError(400, "40013", f"{field} 不是合法的 ISO-8601 时间：{value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ────────────────────────────────────────────── 1 试算平衡
@router.get("/trial-balance", operation_id="getLedgerTrialBalance")
@_api_errors
def get_ledger_trial_balance(request: Request, as_of: str | None = None,
                             unit_type: str = "USD") -> JSONResponse:
    require_admin(request, write=False)
    payload = None
    with db.conn() as conn:
        payload = trial.trial_balance(conn, unit_type=unit_type, as_of=_parse_ts(as_of))
    return _respond(payload, _request_id(request))


# ────────────────────────────────────────────── 2 科目与余额
@router.get("/accounts", operation_id="listLedgerAccounts")
@_api_errors
def list_ledger_accounts(request: Request, cursor: str | None = None, limit: int = 50,
                         fund_class: str | None = None, unit_type: str = "USD") -> JSONResponse:
    require_admin(request, write=False)
    with db.conn() as conn:
        payload = trial.accounts_overview(conn, unit_type=unit_type, fund_class=fund_class,
                                          cursor=cursor, limit=limit)
    return _respond(payload, _request_id(request))


# ────────────────────────────────────────────── 3 期间根（只读）
@router.get("/merkle/{period}", operation_id="getLedgerMerkleRoot")
@_api_errors
def get_ledger_merkle_root(request: Request, period: str, kind: str = "journal") -> JSONResponse:
    require_admin(request, write=False)
    with db.conn() as conn:
        record = merkle.get(conn, kind=kind, period=period)
    if record is None:
        raise ApiError(404, "40924", f"{kind}/{period} 还没有发布过期间根（先跑 merkle_anchor）")
    return _respond(record, _request_id(request))


# ────────────────────────────────────────────── 4 复算（只读，不修数据）
@router.post("/recompute", operation_id="recomputeLedger")
@_api_errors
def recompute_ledger(request: Request, body: dict[str, Any] | None = None) -> JSONResponse:
    require_admin(request, write=True)
    body = body or {}
    period = body.get("period")
    scope = body.get("scope", "all")
    dry_run = bool(body.get("dry_run", True))
    if scope not in ("period", "all"):
        raise ApiError(400, "40013", f"scope 必须是 period / all，收到 {scope!r}")
    if scope == "period" and not period:
        raise ApiError(400, "40013", "scope=period 时必须给 period")
    if period is not None:
        merkle.period_format(str(period))       # 形状不对 → 422/42222

    requested_at = datetime.now(timezone.utc)
    with db.conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s)", (RECOMPUTE_LOCK_ID,))
            acquired = bool(cur.fetchone()[0])
        if not acquired:
            raise ApiError(409, "40920", "已有复算作业在跑：同一时刻只允许 1 个（spec recomputeLedger）")
        try:
            report = verify.verify_ledger(conn)
            period_ok = True
            if period is not None:
                record = merkle.get(conn, kind="journal", period=str(period))
                period_ok = bool(record and record["reproducible"])
            diff_count = int(report["diff"]) + (0 if period_ok else 1)
        finally:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock(%s)", (RECOMPUTE_LOCK_ID,))

    payload = {
        "job_id": f"recompute-{uuid.uuid4().hex[:12]}",
        "state": "succeeded" if diff_count == 0 else "failed",
        "dry_run": dry_run,
        "diff_count": diff_count,
        "verified": diff_count == 0,
        "requested_at": requested_at.isoformat(),
        "period": period,
        "scope": scope,
        "report": {"chain": report["chain"], "balances": {
            key: report["balances"][key] for key in
            ("derived_keys", "stored_keys", "mismatched", "diff")}, "net_minor": report["net_minor"]},
    }
    return _respond(payload, _request_id(request), status=202)


# ────────────────────────────────────────────── 5 凭证详情
def _voucher(conn, journal: dict) -> dict:
    """库内凭证 → spec JournalVoucher（dc 转 debit/credit；金额转十进制字符串）。"""
    chain: list[str] = []
    if journal["reversal_of_journal"]:
        chain.append(str(journal["reversal_of_journal"]))
    reversed_by = reversal.find_reversal(conn, journal["journal_id"])
    if reversed_by:
        chain.append(reversed_by)
    lines = [
        {"line_no": line["line_no"], "ledger_entry_id": line["ledger_entry_id"],
         "account_id": line["account_id"], "coa_code": line["coa_code"],
         "dc": "debit" if line["dc"] == "D" else "credit",
         "amount": trial.amount(line["amount_minor"], journal["unit_type"]),
         "qty_minor": line["qty_minor"], "fund_class": line["fund_class"]}
        for line in journal["lines"]
    ]
    return {
        "journal_id": journal["journal_id"],
        "ts": journal["ts"].astimezone(timezone.utc).isoformat(),
        "unit_type": journal["unit_type"],
        "source_type": journal["source_type"],
        "source_id": journal["source_id"],
        "event_seq": journal["event_seq"],
        "policy_version": journal["policy_version"],
        "fx_rate_ref": str(journal["fx_rate_id"]),
        "reversal_of_journal": (None if journal["reversal_of_journal"] is None
                                else str(journal["reversal_of_journal"])),
        "reverse_chain": chain,
        "hash": journal["hash"],
        "state": journal["status"],
        "lines": lines,
    }


@router.get("/journals/{id}", operation_id="getLedgerJournal")
@_api_errors
def get_ledger_journal(request: Request, id: str) -> JSONResponse:
    require_admin(request, write=False)
    with db.conn() as conn:
        journal = load_journal(conn, id)
        if journal is None:
            raise ApiError(404, "40924", f"凭证 {id} 不存在（或已归档）")
        payload = _voucher(conn, journal)
    return _respond(payload, _request_id(request))


# ────────────────────────────────────────────── 6 冲正（唯一写路径）
@router.post("/reversals", operation_id="createLedgerReversal")
@_api_errors
def create_ledger_reversal(request: Request, body: dict[str, Any] | None = None) -> JSONResponse:
    principal = require_admin(request, write=True)
    body = body or {}
    journal_id = body.get("journal_id")
    reason = body.get("reason")
    second_approver = body.get("second_approver")
    missing = [name for name, value in (("journal_id", journal_id), ("reason", reason),
                                        ("second_approver", second_approver)) if not value]
    if missing:
        raise ApiError(400, "40013", f"请求体缺必填字段：{missing}")
    if not isinstance(reason, str) or len(reason) > MAX_REASON_TEXT_LEN:
        raise ApiError(400, "40013", f"reason 必须是 ≤{MAX_REASON_TEXT_LEN} 字符的字符串")
    if str(second_approver).strip() == principal.actor:
        raise ApiError(409, "40902", "复核人不得等于操作人（SoD）")

    requested_at = datetime.now(timezone.utc)
    with db.conn() as conn:
        result = reversal.reverse_journal(conn, str(journal_id), reason_code=str(reason)[:64],
                                          approval_chain={"requested_by": principal.actor,
                                                          "second_approver": str(second_approver),
                                                          "evidence_ref": body.get("evidence_ref")})
    payload = {
        "reversal_id": result.reversal_journal_id,
        "journal_id": result.reversal_of,
        "state": "posted",
        "created_at": requested_at.isoformat(),
        "line_count": result.lines,
        "total": trial.amount(result.total_minor, "USD"),
    }
    return _respond(payload, _request_id(request), status=201)


def _assert_registry_matches_routes() -> None:
    """导入期硬门：注册的路由与 OPERATIONS 必须一一对应（少一条 / 多一条都起不来）。"""
    declared = {(item["method"], item["path"]) for item in OPERATIONS.values()}
    registered = {(method, route.path)
                  for route in router.routes
                  for method in (getattr(route, "methods", set()) or set()) - {"HEAD", "OPTIONS"}}
    if registered != declared:
        raise RuntimeError(
            f"LEDGER 路由与 OPERATIONS 不一致：多 {sorted(registered - declared)}，"
            f"少 {sorted(declared - registered)}")
    ids = {getattr(route, "operation_id", None) for route in router.routes}
    if ids != set(OPERATIONS):
        raise RuntimeError(f"operationId 不一致：路由 {sorted(ids)} vs 登记 {sorted(OPERATIONS)}")


_assert_registry_matches_routes()

__all__ = ["router", "OPERATIONS", "ApiError", "Principal", "require_admin"]
