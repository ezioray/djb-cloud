# SPDX-License-Identifier: AGPL-3.0-or-later
"""M11 申诉领域服务（受理 / 窗口 / SLA / 裁决 / 误伤恢复）。

* 受理：30 天窗口（APPEAL_WINDOW_D）+ 同案件最多 1 条未结（部分唯一索引）→ 409/48003；
* SLA：7 个工作日（跳过周末）；超期由 ``escalate_overdue`` 打点升级 P1（幂等）；
* 裁决：裁决人 ≠ 原处置人（403/48006）；``overturned`` 时额外发 ``risk.action.requested``
  （action=unfreeze）通知 M01 解冻 —— 本模块仍不改账户状态（INV-04）。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from . import clock, events, facts, ids, policy, store
from .errors import AppealConflict, Conflict, NotFound

__all__ = ["submit", "decide", "escalate_overdue", "require_appeal"]


def require_appeal(conn: Any, appeal_id: str, *, tenant_id: str | None = None,
                   lock: bool = False) -> dict[str, Any]:
    row = store.get_appeal(conn, appeal_id, tenant_id=tenant_id, lock=lock)
    if row is None:
        raise NotFound("申诉不存在")
    return row


def submit(conn: Any, case: Any, draft: Any, *, actor: str, now: datetime,
           trace_id: str | None = None) -> dict[str, Any]:
    """受理申诉：写申诉 + 案件转 appealed（同事务）。"""
    case_id = str(case["case_id"])
    status = str(case["status"])
    if status in facts.TERMINAL_CASE_STATUSES:
        raise AppealConflict("案件已终局：不能申诉", reason="case_closed")
    if store.find_open_appeal(conn, case_id) is not None:
        raise AppealConflict("同一案件已有未结申诉（重复申诉）", reason="appeal_duplicate")
    if case.get("decided_at") is None:
        raise AppealConflict("案件尚未处置：不能申诉", reason="case_not_actioned")
    policy.check_appeal_window(case["decided_at"], now)      # 超 30 天 → 409/48003

    submitted_at = clock.as_utc(now)
    row = store.insert_appeal(
        conn, appeal_id=str(ids.uuid7()), case_id=case_id,
        tenant_id=str(case["tenant_id"]), reason=draft.reason,
        submitted_at=submitted_at, sla_due=policy.sla_due(submitted_at))
    store.set_case_status(conn, case_id, status="appealed")
    return row


def decide(conn: Any, appeal: Any, case: Any, draft: Any, *, actor: str, now: datetime,
           trace_id: str | None = None,
           idempotency_key: str | None = None) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """裁决申诉；返回 ``(appeal_row, case_row, escalated)``。"""
    if str(appeal["status"]) not in facts.APPEAL_OPEN_STATUSES:
        raise Conflict("申诉已裁决：不能重复裁决", reason="appeal_already_decided")
    # 裁决人 ≠ 原处置人（403/48006）
    policy.ensure_separation(actor, case.get("decided_by"), what="裁决")

    escalated = False
    if appeal.get("escalated_at") is None and policy.is_overdue(appeal["sla_due"], now):
        # 超 SLA 未答复 → 升级 P1（打点；不阻塞裁决）
        store.escalate_overdue_appeals(conn, now)
        escalated = True

    decided = store.decide_appeal(
        conn, str(appeal["appeal_id"]), outcome=draft.outcome, reason=draft.reason,
        decided_by=actor, decided_at=now, idempotency_key=idempotency_key)

    closed_case = store.set_case_status(conn, str(case["case_id"]), status="closed",
                                        closed_at=now)
    events.case_closed(conn, closed_case, outcome=draft.outcome, closed_at=now,
                       trace_id=trace_id)
    if draft.outcome == "overturned":
        # 误伤恢复：通知 M01 解冻（本模块仍不改账户状态，INV-04）
        events.action_requested(
            conn, closed_case, action="unfreeze", reason_code="risk_case_overturned",
            expires_at=None, sequence=len(store.case_decisions(closed_case)) + 1,
            trace_id=trace_id)
    return decided, closed_case, escalated


def escalate_overdue(conn: Any, now: datetime) -> list[dict[str, Any]]:
    """SLA 超期自动升级 P1 的批处理入口（S1 无后台 job，合并期由 M14/调度触发）。"""
    return store.escalate_overdue_appeals(conn, now)
