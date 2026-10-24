# SPDX-License-Identifier: AGPL-3.0-or-later
"""M11 risk-abuse 常量与枚举（规格 §3 / §5 / §8.2 / 02-events §3）。

**INV-01 在此文件里的落地方式**：本文件只有**枚举、时长常量、事件 payload 白名单**，
没有任何阈值 / 权重 / 名单数值；规则阈值只存在于 M10 私有 risk-config，本模块只持有
``config_ref``（``risk.*``）与 ``rule_version``。``FORBIDDEN_PAYLOAD_KEYS`` 是扫描用的
**键名**白名单（不是数值），用于在入队 / 落库前拒绝携带阈值语义的字段。
"""
from __future__ import annotations

from typing import Final

# ── 领域枚举（M11 §3 / §5 / spec 1.2.4 components）
RISK_TYPES: Final[tuple[str, ...]] = (
    "self_trade", "wash_volume", "sybil", "malicious_occupancy", "receipt_mismatch",
    "key_leak", "chargeback_abuse", "payout_address", "content_abuse",
)
SEVERITIES: Final[tuple[str, ...]] = ("P0", "P1", "P2", "P3")
CASE_STATUSES: Final[tuple[str, ...]] = (
    "opened", "triaged", "actioned", "appealed", "in_review",
    "closed", "merged", "dismissed",
)
TERMINAL_CASE_STATUSES: Final[frozenset[str]] = frozenset({"closed", "merged", "dismissed"})
ACTION_CLASSES: Final[tuple[str, ...]] = (
    "observe", "throttle", "freeze", "retire", "manual_review",
)
DECISION_ACTIONS: Final[tuple[str, ...]] = (
    "freeze", "unfreeze", "retire_proposal", "dismiss", "merge", "close",
)
APPEAL_STATUSES: Final[tuple[str, ...]] = ("submitted", "in_review", "upheld", "overturned", "closed")
APPEAL_OPEN_STATUSES: Final[frozenset[str]] = frozenset({"submitted", "in_review"})
APPEAL_OUTCOMES: Final[tuple[str, ...]] = ("upheld", "overturned")
SUBJECT_TYPES: Final[tuple[str, ...]] = ("account", "node", "key", "address")

# ── 对外粗粒度原因码（INV-02：只有这 4 个，不含规则名 / 阈值 / 命中条目）
COARSE_REASONS: Final[tuple[str, ...]] = (
    "rate_limited", "quota_exceeded", "account_restricted", "policy_blocked",
)
#: 48xxx 段里「限额命中」对外只映射到粗粒度 reason（M11 §6 流程 1）
LIMIT_HIT_CODE: Final[int] = 48001
COARSE_REASON_BY_CODE: Final[dict[int, str]] = {
    48001: "rate_limited",
    48002: "policy_blocked",
    48003: "policy_blocked",
    48004: "policy_blocked",
    48005: "policy_blocked",
    48006: "account_restricted",
}

# ── 本模块常量（M11 §8.2；都是**时长 / 保留期**，不是命中阈值）
APPEAL_WINDOW_D: Final[int] = 30          # 申诉提交窗口（§12.8.5）
APPEAL_SLA_WORKDAYS: Final[int] = 7       # 答复 SLA，超期 P1（§12.8.5）
FREEZE_MAX_D: Final[int] = 180            # 单次冻结上限（03-facts §8）
CASE_RETENTION_Y: Final[int] = 5          # 案件 / 申诉保留（§12.8.2）
SIGNAL_RETENTION_M: Final[int] = 12       # 信号流水滚动保留
LKG_TTL_H: Final[int] = 24                # 规则包 LKG 过期即只监控（与 M10 同口径）

# ── 分页 / 幂等键（spec parameters）
MIN_PAGE_SIZE: Final[int] = 1
MAX_PAGE_SIZE: Final[int] = 100
DEFAULT_PAGE_SIZE: Final[int] = 50
MIN_IDEMPOTENCY_LEN: Final[int] = 16
MAX_IDEMPOTENCY_LEN: Final[int] = 128
MAX_REASON_LEN: Final[int] = 512
MAX_EVIDENCE_REFS: Final[int] = 100

# ── 事件（02-events §3 已登记；未登记事件不得上线）
EVENT_CASE_OPENED: Final[str] = "risk.case.opened"
EVENT_CASE_CLOSED: Final[str] = "risk.case.closed"
EVENT_LIMIT_HIT: Final[str] = "risk.limit.hit"
EVENT_ACTION_REQUESTED: Final[str] = "risk.action.requested"
PRODUCED_EVENTS: Final[tuple[str, ...]] = (
    EVENT_CASE_OPENED, EVENT_CASE_CLOSED, EVENT_LIMIT_HIT, EVENT_ACTION_REQUESTED,
)
#: payload 白名单（02-events §3 + 模块 §4.2）；INV-01：不得出现阈值 / 权重 / 名单字段
EVENT_PAYLOAD_FIELDS: Final[dict[str, frozenset[str]]] = {
    EVENT_CASE_OPENED: frozenset({"case_id", "subject_id", "risk_type", "severity", "rule_version"}),
    EVENT_CASE_CLOSED: frozenset({"case_id", "outcome", "closed_at"}),
    EVENT_LIMIT_HIT: frozenset({"subject_id", "limit_type", "value", "window_s"}),
    EVENT_ACTION_REQUESTED: frozenset(
        {"case_id", "subject_type", "subject_id", "action", "reason_code", "expires_at"}),
}
#: 生产侧业务幂等键前缀（02-events §1 idempotency_key）
EVENT_IDEMPOTENCY_PREFIX: Final[dict[str, str]] = {
    EVENT_CASE_OPENED: "risk_case",
    EVENT_CASE_CLOSED: "risk_case_closed",
    EVENT_LIMIT_HIT: "risk_limit_hit",
    EVENT_ACTION_REQUESTED: "risk_action",
}

#: 提案动作（只提案，不改账户状态；INV-04）
PROPOSAL_ACTIONS: Final[frozenset[str]] = frozenset({"freeze", "unfreeze", "retire_proposal"})

#: 禁止出现在 payload / 响应 / 库表里的**键**（阈值 / 权重 / 名单 / PII）
FORBIDDEN_PAYLOAD_KEYS: Final[frozenset[str]] = frozenset({
    "threshold", "thresholds", "weight", "weights", "blocklist", "blacklist",
    "allowlist", "whitelist", "score_weight", "score", "rule_score",
    "ip", "email", "phone", "card", "card_no", "pan", "id_card",
})

#: 规则列表 / 详情的对外键（INV-01：只暴露元数据）
RULE_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset({
    "rule_key", "version", "enabled", "severity", "action_class", "config_ref", "created_at",
})
LIMIT_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset({
    "subject_type", "subject_id", "limit_type", "value", "window_s", "expires_at", "revision",
})
CASE_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset({
    "case_id", "case_no", "subject_hash", "risk_type", "severity", "status",
    "opened_at", "closed_at",
})
APPEAL_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset({
    "appeal_id", "case_id", "status", "submitted_at", "sla_due", "outcome",
})
DECISION_PUBLIC_FIELDS: Final[frozenset[str]] = frozenset({
    "case_id", "action", "reason", "decided_by", "decided_at", "proposal_id",
})
