# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08c 退款（M08 §3 / §6 流程 5 / §4.1 / INV-12 / 03-facts §5）。

规则：

* 窗口 **14 天**（payment.refund_window_days，7–30 可配；默认 14）→ 超窗 409 / 40919；
* **只回原路**：1.2.7 起 original_route 可选——省略时从订单**唯一成功 attempt** 推导
  （psp:<provider>:<txn>）并按它执行；提供时必须逐字相等，掩码串不接受；
  0 条或多条成功 attempt 无法唯一确定 → 409/40919 reason=original_route_unavailable；
  原路字段落库后不可改（库层触发器兜底），不接受第三方地址；
* 金额 ≤ 已付未消耗；币种与原单一致；同一订单同一时刻最多 1 条未结退款；
* 双人 + **24h 冷却**：requested → approved（审批人 ≠ 申请人，且冷却已过）→ executing
  → succeeded（refund.completed，E11 由 M06 消费事件入账）/ failed（40918，转工单不换路）；
* 幂等：X-DJB-Idempotency-Key；同键同载荷返回首次结果，不同载荷 409 / 40919。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock, config_source, events, facts, ids, models, policy, store
from .errors import (
    AmountMismatch,
    Conflict,
    NotFound,
    RefundFailed,
    RefundInProgress,
    RiskLevelRequired,
)

__all__ = [
    "create_refund_request", "approve_refund_request", "execute_refund_request",
    "complete_refund_request", "fail_refund_request", "refund_view", "list_refund_requests",
]

RiskCheck = Callable[..., Any]
ConsumedProvider = Callable[[str], int]


def _route_hash(route: str) -> str:
    return hashlib.sha256(route.encode("utf-8")).hexdigest()


def create_refund_request(conn: Any, draft: models.RefundDraft, *, account_id: str,
                          requested_by: str, idempotency_key: str | None,
                          config: config_source.TreasuryConfig,
                          consumed_provider: ConsumedProvider | None,
                          risk_check: RiskCheck | None, now: datetime) -> dict[str, Any]:
    """退款申请（requested）：窗口 / 原路 / 金额 / 双人前置于此校验。"""
    moment = clock.as_utc(now)
    if idempotency_key:
        replay = store.find_refund_by_idempotency(conn, idempotency_key)
        if replay is not None:
            same = (str(replay["order_no"]) == draft.order_no
                    and int(replay["amount_minor"]) == int(draft.amount_minor))
            if not same:
                raise Conflict("幂等键已用于不同退款载荷", reason="idempotency_key_reused")
            return {"refund": replay, "replayed": True}
    order = store.get_order(conn, draft.order_no, account_id=account_id, lock=True)
    if order is None:
        raise NotFound("支付订单不存在")
    if str(order["status"]) not in facts.ORDER_PAYABLE:
        raise Conflict(f"订单状态 {order['status']} 不支持退款（未支付 / 已关闭）",
                       reason="order_not_payable")
    window_days = int(config.refund_window_days)
    deadline = policy.refund_deadline(order["paid_at"] or order["created_at"], window_days)
    policy.check_refund_window(deadline, moment)
    currency = str(order["currency"])
    open_refund = store.find_open_refund(conn, draft.order_no)
    if open_refund is not None:
        raise RefundInProgress("该订单已有未结退款（40917）", reason="refund_in_progress")
    latest_failed = None
    with conn.cursor() as cur:
        cur.execute("SELECT status FROM refund_requests WHERE order_no = %s"
                    " ORDER BY created_at DESC LIMIT 1", (draft.order_no,))
        row = cur.fetchone()
        latest_failed = None if row is None else row[0]
    if latest_failed == "failed":
        raise RefundFailed("上一条退款失败：转人工核对后再发起（40918）",
                           reason="refund_failed")
    # 1.2.7：原路以**唯一成功 attempt** 为准；0 条或 >1 条 → 409/40919 original_route_unavailable。
    # 省略 original_route：服务端推导真实原路并按它执行；提供：必须逐字相等（掩码值在解析层已拒）。
    attempts = store.list_attempts(conn, str(order["order_id"]))
    route = policy.resolve_original_route(attempts)
    if draft.original_route is not None:
        policy.check_original_route(route, draft.original_route)
    refunded = store.refunded_total(conn, draft.order_no)
    consumed = int(consumed_provider(draft.order_no)) if consumed_provider else 0
    remaining = policy.remaining_refundable(
        paid_minor=int(order["credited_minor"] or order["amount_minor"]),
        refunded_minor=refunded, consumed_minor=consumed)
    if int(draft.amount_minor) > remaining:
        raise AmountMismatch(
            f"退款金额超过已付未消耗（可退 {remaining} 分，申请 {int(draft.amount_minor)} 分）",
            reason="amount_mismatch")
    if risk_check is not None:
        verdict = risk_check(account_id=account_id, amount_minor=int(draft.amount_minor),
                             order_no=draft.order_no)
        if verdict is False or str(verdict).lower() in ("deny", "blocked", "insufficient"):
            raise RiskLevelRequired("退款需完成风控验证（40312）", reason="risk_level_required")
    refund = store.insert_refund(
        conn, refund_request_id=str(ids.uuid7()), account_id=account_id,
        order_no=draft.order_no, payment_ref=route, amount_minor=int(draft.amount_minor),
        currency=str(order["currency"]), reason_code=draft.reason_code,
        evidence_ref=draft.evidence_ref, original_route=route,
        original_route_hash=_route_hash(route), status="requested", deadline_at=deadline,
        requested_by=requested_by,
        cooldown_until=clock.add_seconds(moment, facts.REFUND_COOLDOWN_H * 3600),
        idempotency_key=idempotency_key, now=moment)
    return {"refund": refund, "replayed": False}


def approve_refund_request(conn: Any, identifier: str, *, approver: str, now: datetime,
                           idempotency_key: str | None = None) -> dict[str, Any]:
    """审批：双人 + 24h 冷却（approved_at 之后才能执行）。"""
    refund = store.get_refund(conn, identifier, lock=True)
    if refund is None:
        raise NotFound("退款申请不存在")
    if refund["status"] == "approved":
        return {"refund": refund, "replayed": True}
    if refund["status"] != "requested":
        raise Conflict(f"退款状态 {refund['status']} 不允许审批", reason="illegal_transition")
    policy.ensure_dual_control(str(refund["requested_by"]), approver)
    moment = clock.as_utc(now)
    if not policy.approval_cooldown_ready(refund["cooldown_until"], moment):
        raise Conflict("退款 24h 冷却未结束：不得审批（§19.11.3）", reason="refund_cooldown")
    updated = store.update_refund(conn, str(refund["refund_request_id"]),
                                 status="approved", approved_by=approver,
                                 approved_at=moment)
    return {"refund": updated, "replayed": False}


def execute_refund_request(conn: Any, identifier: str, *, actor: str, now: datetime,
                           failure_code: str | None = None,
                           trace_id: str | None = None) -> dict[str, Any]:
    """执行（原路打款）：approved → executing；带 failure_code 表示通道失败（40918）。"""
    refund = store.get_refund(conn, identifier, lock=True)
    if refund is None:
        raise NotFound("退款申请不存在")
    if refund["status"] not in ("approved", "executing"):
        raise Conflict(f"退款状态 {refund['status']} 不允许执行", reason="illegal_transition")
    moment = clock.as_utc(now)
    if failure_code:
        if refund["status"] == "executing":
            return fail_refund_request(conn, identifier, failure_code=failure_code, now=now)
        raise RefundFailed(f"退款未成功（40918）：{failure_code}", reason="refund_failed")
    if refund["status"] == "executing":
        return {"refund": refund, "replayed": True}
    updated = store.update_refund(conn, str(refund["refund_request_id"]),
                                 status="executing", executing_at=moment)
    return {"refund": updated, "replayed": False}


def complete_refund_request(conn: Any, identifier: str, *, now: datetime,
                            journal_id: str | None = None,
                            trace_id: str | None = None) -> dict[str, Any]:
    """打款成功：executing → succeeded；生产 refund.completed（E11 由 M06 消费）。"""
    refund = store.get_refund(conn, identifier, lock=True)
    if refund is None:
        raise NotFound("退款申请不存在")
    if refund["status"] == "succeeded":
        return {"refund": refund, "replayed": True}
    if refund["status"] != "executing":
        raise Conflict(f"退款状态 {refund['status']} 不允许完成", reason="illegal_transition")
    moment = clock.as_utc(now)
    updated = store.update_refund(conn, str(refund["refund_request_id"]),
                                 status="succeeded", succeeded_at=moment,
                                 journal_id=journal_id)
    events.refund_completed(conn, updated, succeeded_at=moment, trace_id=trace_id)
    return {"refund": updated, "replayed": False}


def fail_refund_request(conn: Any, identifier: str, *, failure_code: str, now: datetime
                        ) -> dict[str, Any]:
    """失败：executing → failed（40918；转工单，不换路）。"""
    refund = store.get_refund(conn, identifier, lock=True)
    if refund is None:
        raise NotFound("退款申请不存在")
    if refund["status"] == "failed":
        return {"refund": refund, "replayed": True}
    if refund["status"] not in ("requested", "executing"):
        raise Conflict(f"退款状态 {refund['status']} 不允许置失败", reason="illegal_transition")
    moment = clock.as_utc(now)
    updated = store.update_refund(conn, str(refund["refund_request_id"]), status="failed",
                                 failed_at=moment, failure_code=failure_code)
    return {"refund": updated, "replayed": False}


def refund_view(conn: Any, identifier: str, *, account_id: str | None) -> dict[str, Any]:
    refund = store.get_refund(conn, identifier)
    if refund is None or (account_id is not None
                          and str(refund["account_id"]) != str(account_id)):
        raise NotFound("退款申请不存在")
    return models.refund_payload(refund)


def list_refund_requests(conn: Any, *, account_id: str, cursor: str | None = None,
                         limit: int = facts.DEFAULT_PAGE_SIZE
                         ) -> tuple[list[dict[str, Any]], bool, str | None]:
    rows, has_more, next_cursor = store.list_refunds(conn, account_id=account_id,
                                                    cursor=cursor, limit=limit)
    return ([models.refund_payload(row) for row in rows], has_more, next_cursor)