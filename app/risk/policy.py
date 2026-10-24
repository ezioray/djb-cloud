# SPDX-License-Identifier: AGPL-3.0-or-later
"""M11 领域策略（纯函数，零 IO）：案件 / 申诉状态机、冻结期限、申诉窗口与 SLA、SoD、粗粒度原因。

这些函数是**不变量唯一入口**：cases / appeals / router 都只通过它们判定，测试也直接打这里。

对应规格：
* §3 案件状态机 / 申诉状态机；
* INV-01（阈值只留 config_ref / rule_version）、INV-02（对外粗粒度 reason）、
  INV-03（证据必填）、INV-04（只提案；冻结 ≤180 天；申诉期内不得清退）、
  INV-06（同主体同类型未结唯一）、INV-07（处置必须留理由）；
* §8.2 常量：APPEAL_WINDOW_D=30 / APPEAL_SLA_WORKDAYS=7 / FREEZE_MAX_D=180。
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable

from . import clock, facts
from .errors import AppealConflict, BadRequest, Conflict, SeparationOfDuty

__all__ = [
    "transition_for", "is_terminal", "check_freeze_window", "check_appeal_window",
    "sla_due", "is_overdue", "ensure_separation", "coarse_reason", "validate_config_ref",
    "ensure_retire_allowed", "appeal_window_closes",
]

#: 状态机（M11 §3）：(当前状态, 处置动作) → 新状态
_TRANSITIONS: dict[str, dict[str, str]] = {
    "opened": {"freeze": "actioned", "retire_proposal": "actioned", "dismiss": "dismissed",
               "merge": "merged"},
    "triaged": {"freeze": "actioned", "retire_proposal": "actioned", "dismiss": "dismissed",
                "merge": "merged", "close": "closed"},
    "actioned": {"freeze": "actioned", "unfreeze": "actioned",
                 "retire_proposal": "actioned", "merge": "merged", "close": "closed"},
    "appealed": {"unfreeze": "actioned", "close": "closed"},
    "in_review": {"unfreeze": "actioned", "close": "closed"},
    # 终态：不再接受任何处置（closed / merged / dismissed）
}


def is_terminal(status: str) -> bool:
    return status in facts.TERMINAL_CASE_STATUSES


def transition_for(status: str, action: str) -> str:
    """按状态机返回新状态；终态或未登记迁移 → 409/40919（不泄露内部状态枚举细节）。"""
    if is_terminal(status):
        raise Conflict(f"案件已处于终态（{status}）：不得再处置", reason="case_terminal")
    target = _TRANSITIONS.get(status, {}).get(action)
    if target is None:
        raise Conflict(f"状态迁移不允许：{status} → {action}", reason="illegal_transition")
    return target


def check_freeze_window(expires_at: datetime | None, now: datetime) -> datetime:
    """INV-04：冻结必带期限，且 ≤ FREEZE_MAX_D（180）天、必须晚于当前时刻。"""
    if expires_at is None:
        raise BadRequest("冻结必须带期限（expires_at）", reason="freeze_requires_expiry",
                         field="expires_at")
    moment = clock.as_utc(expires_at)
    current = clock.as_utc(now)
    if moment <= current:
        raise BadRequest("冻结期限必须晚于当前时刻", reason="freeze_expiry_in_past",
                         field="expires_at")
    if moment > current + timedelta(days=facts.FREEZE_MAX_D):
        raise BadRequest("冻结期限超过单次上限", reason="freeze_window_exceeded",
                         field="expires_at")
    return moment


def appeal_window_closes(decided_at: datetime) -> datetime:
    """申诉提交窗口关闭时刻 = 处置时刻 + APPEAL_WINDOW_D（自然日）。"""
    return clock.as_utc(decided_at) + timedelta(days=facts.APPEAL_WINDOW_D)


def check_appeal_window(decided_at: datetime | None, now: datetime) -> None:
    """超过 30 天窗口 → 409/48003（M11 §6 流程 3）。"""
    if decided_at is None:
        raise AppealConflict("案件尚未处置：不能申诉", reason="case_not_actioned")
    if clock.as_utc(now) > appeal_window_closes(decided_at):
        raise AppealConflict("申诉已超过 30 天提交窗口", reason="appeal_window_expired")


def _is_workday(moment: datetime) -> bool:
    return moment.weekday() < 5          # 周一..周五（S1 不含法定节假日日历）


def sla_due(submitted_at: datetime) -> datetime:
    """SLA = 提交时刻 + APPEAL_SLA_WORKDAYS 个工作日（跳过周六 / 周日）。

    S1 口径：只用周历（不含法定节假日表）；口径差异已写进证据「决策与遗留」。
    """
    moment = clock.as_utc(submitted_at)
    remaining = facts.APPEAL_SLA_WORKDAYS
    while remaining > 0:
        moment += timedelta(days=1)
        if _is_workday(moment):
            remaining -= 1
    return moment


def is_overdue(sla_due_at: datetime, now: datetime) -> bool:
    """超 SLA 未答复 → 应升级 P1（M11 §6 流程 3）。"""
    return clock.as_utc(now) > clock.as_utc(sla_due_at)


def ensure_separation(actor: str | None, original: str | None, *, what: str = "裁决") -> None:
    """INV-04 / §4.1：裁决人 ≠ 原处置人 → 否则 403/48006。"""
    if actor and original and str(actor) == str(original):
        raise SeparationOfDuty(f"{what}人不得是原处置人（职责分离）", reason="same_actor")


def ensure_retire_allowed(*, open_appeal: bool) -> None:
    """INV-04：申诉期内不得清退。"""
    if open_appeal:
        raise Conflict("申诉期内不得清退（INV-04）", reason="appeal_window_open")


def coarse_reason(code: int | str) -> str:
    """INV-02：任何 48xxx / 上游错误 → 4 个粗粒度 reason 之一（不含规则 / 阈值 / 命中条目）。"""
    try:
        numeric = int(code)
    except (TypeError, ValueError):
        return "policy_blocked"
    return facts.COARSE_REASON_BY_CODE.get(numeric, "policy_blocked")


def validate_config_ref(config_ref: str | None) -> str | None:
    """INV-01：只接受 M10 的 ``risk.*`` 键；空值表示纯监控规则（不取阈值）。"""
    if config_ref is None:
        return None
    text = str(config_ref).strip()
    if not text:
        return None
    if not text.startswith("risk.") or len(text) > 128:
        raise BadRequest("config_ref 必须是 M10 的 risk.* 配置键（阈值不入库）",
                         field="config_ref")
    return text
