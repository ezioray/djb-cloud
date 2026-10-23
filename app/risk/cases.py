# SPDX-License-Identifier: Apache-2.0
"""M11 案件领域服务（开案 / 去重 / 处置分级 / 只提案）。

入口分两类：

* **事件驱动（内部）**：``open_case`` / ``open_or_merge``——消费信号后开案；重复触发按
  INV-06 处理（``open_case`` 直接 409/48002；``open_or_merge`` 把证据并入既有案件并返回
  ``merged=True``，**不新建案件**）；
* **管理面（HTTP）**：``decide``——九个操作里的 ``POST /cases/{id}/decisions``。

处置只有两种落库结果：案件状态 / 处置历史（本模块表）+ ``risk.action.requested`` 提案事件。
**绝不改 accounts 状态**（INV-04）：冻结 / 解冻 / 清退都由 M01 消费提案后落地。
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Mapping

from . import clock, events, facts, policy, store
from .errors import CaseExists, Conflict, EvidenceMissing, NotFound

__all__ = [
    "open_case", "open_or_merge", "decide", "replay_decision", "case_detail",
    "require_case", "action_reason_code",
]


def action_reason_code(action: str) -> str:
    """提案事件的 reason_code：机器可判的短码（不含阈值 / 规则名，INV-01/INV-02）。"""
    return f"risk_case_{action}"


def require_case(conn: Any, case_id: str, *, tenant_id: str | None = None,
                 lock: bool = False) -> dict[str, Any]:
    row = store.get_case(conn, case_id, tenant_id=tenant_id, lock=lock)
    if row is None:
        raise NotFound("案件不存在")
    return row


def open_case(conn: Any, draft: Any, *, trace_id: str | None = None) -> dict[str, Any]:
    """开案（INV-03 证据必填；INV-06 重复 → 409/48002；INV-05 主体只存哈希）。"""
    if not draft.evidence_refs:
        raise EvidenceMissing("证据缺失：无证据不得开案（INV-03）")
    # 先查重（友好错误 48002）；并发下的兜底由部分唯一索引 uq_cases_open 负责
    if store.find_open_case(conn, draft.subject_hash, draft.risk_type) is not None:
        raise CaseExists("同主体同类型已有未结案件（INV-06）", reason="case_exists")
    row = store.insert_case(conn, draft)
    events.case_opened(conn, row, trace_id=trace_id)
    return row


def open_or_merge(conn: Any, draft: Any, *, trace_id: str | None = None
                  ) -> tuple[dict[str, Any], bool]:
    """信号入口：已有未结案件 → 并入（追加证据），否则新建。

    返回 ``(case, merged)``；``merged=True`` 表示这次触发被并进既有案件（不新建）。
    """
    if not draft.evidence_refs:
        raise EvidenceMissing("证据缺失：无证据不得开案（INV-03）")
    existing = store.find_open_case(conn, draft.subject_hash, draft.risk_type)
    if existing is not None:
        merged = store.append_evidence(conn, str(existing["case_id"]), draft.evidence_refs)
        return merged, True
    return open_case(conn, draft, trace_id=trace_id), False


def replay_decision(case: Mapping[str, Any], idempotency_key: str | None
                    ) -> dict[str, Any] | None:
    """同幂等键重放：返回首次处置记录（不重复推进状态 / 不重复发事件）。"""
    if not idempotency_key:
        return None
    for entry in store.case_decisions(case):
        if entry.get("idempotency_key") == idempotency_key:
            return entry
    return None


def decide(conn: Any, case: Mapping[str, Any], draft: Any, *, actor: str,
           now: datetime, idempotency_key: str | None = None,
           trace_id: str | None = None) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """执行一次处置决定；返回 ``(case_row, decision_payload, replayed)``。

    不变量：
    * INV-03：``evidence_refs`` 非空（models 层已校验，这里再兜一次）；
    * INV-04：freeze 必带 ≤180 天期限；retire_proposal 在申诉期内拒绝；只发提案事件；
    * INV-07：reason 必填（models 层已校验）并写入处置历史；
    * SoD：开案人不得对同一案件自行做冻结 / 清退终局处置 → 403/48006。
    """
    replayed = replay_decision(case, idempotency_key)
    if replayed is not None:
        return dict(case), replayed, True
    if not draft.evidence_refs:
        raise EvidenceMissing("证据缺失：无证据不得处置（INV-03）")

    status = str(case["status"])
    # INV-04：申诉期内不得清退（先判，给出明确的 409 理由而不是泛化的非法迁移）
    if draft.action == "retire_proposal":
        policy.ensure_retire_allowed(
            open_appeal=store.find_open_appeal(conn, str(case["case_id"])) is not None)
    new_status = policy.transition_for(status, draft.action)   # 非法迁移 → 409/40919
    expires_at = None
    proposal_id: str | None = None
    closed_at: datetime | None = None
    merged_into: str | None = None
    outcome: str | None = None

    if draft.action == "freeze":
        if actor and case.get("opened_by") and actor == case["opened_by"]:
            from .errors import SeparationOfDuty

            raise SeparationOfDuty("开案人不得自行冻结（职责分离）", reason="self_freeze")
        expires_at = policy.check_freeze_window(draft.expires_at, now)
    elif draft.action == "retire_proposal":
        if actor and case.get("opened_by") and actor == case["opened_by"]:
            from .errors import SeparationOfDuty

            raise SeparationOfDuty("开案人不得自行清退（职责分离）", reason="self_retire")
    elif draft.action == "merge":
        if not draft.merge_into:
            raise Conflict("并案必须指定 merge_into（同主体未结案件）", reason="merge_target_missing")
        target = require_case(conn, draft.merge_into, tenant_id=str(case["tenant_id"]),
                              lock=True)
        if str(target["case_id"]) == str(case["case_id"]):
            raise Conflict("不能并入自身", reason="merge_self")
        if target["status"] in facts.TERMINAL_CASE_STATUSES:
            raise Conflict("并案目标已终局（不可并入）", reason="merge_target_terminal")
        if str(target["subject_hash"]) != str(case["subject_hash"]):
            raise Conflict("并案目标主体不同（INV-06）", reason="merge_subject_mismatch")
        merged_into = str(target["case_id"])
        closed_at = now

    if draft.action in {"dismiss", "merge", "close"}:
        closed_at = now
        outcome = {"dismiss": "dismissed", "merge": "merged", "close": "closed"}[draft.action]
    if new_status in facts.TERMINAL_CASE_STATUSES and closed_at is None:
        closed_at = now

    # 只提案（INV-04）：冻结 / 解冻 / 清退 → risk.action.requested，交给 M01 落地
    if draft.action in facts.PROPOSAL_ACTIONS:
        proposal_id = events.action_requested(
            conn, case, action=draft.action, reason_code=action_reason_code(draft.action),
            expires_at=expires_at,
            sequence=len(store.case_decisions(case)) + 1, trace_id=trace_id)

    entry = {
        "action": draft.action,
        "reason": draft.reason,
        "evidence_refs": list(draft.evidence_refs),
        "decided_by": actor,
        "decided_at": clock.iso(now),
        "expires_at": clock.iso(expires_at) if expires_at is not None else None,
        "proposal_id": proposal_id,
        "idempotency_key": idempotency_key,
    }
    updated = store.append_decision(
        conn, str(case["case_id"]), entry, status=new_status, decision=draft.action,
        decided_by=actor, decided_at=now, proposal_id=proposal_id, closed_at=closed_at,
        merged_into=merged_into, evidence_refs=draft.evidence_refs)

    if outcome is not None:
        events.case_closed(conn, updated, outcome=outcome, closed_at=closed_at or now,
                           trace_id=trace_id)

    payload = {
        "case_id": str(updated["case_id"]),
        "action": draft.action,
        "reason": draft.reason,
        "decided_by": actor,
        "decided_at": clock.iso(now),
        "proposal_id": proposal_id,
    }
    return updated, payload, False


def case_detail(conn: Any, case: Mapping[str, Any]) -> dict[str, Any]:
    """RiskCaseDetail（spec）：case + evidence_refs + decisions + appeals（不含阈值 / PII）。"""
    raw = case.get("decisions") or []
    if isinstance(raw, str):
        raw = json.loads(raw)
    decisions = []
    for entry in raw:
        decisions.append({
            "case_id": str(case["case_id"]),
            "action": entry.get("action"),
            "reason": entry.get("reason"),
            "decided_by": entry.get("decided_by"),
            "decided_at": entry.get("decided_at"),
            "proposal_id": entry.get("proposal_id"),
        })
    appeals = store.list_appeals_for_case(conn, str(case["case_id"]))
    from . import models

    return {
        "case": models.case_payload(case),
        "evidence_refs": list(case.get("evidence_refs") or []),
        "decisions": decisions,
        "appeals": [models.appeal_payload(row) for row in appeals],
    }
