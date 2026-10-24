# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 冻结段常量（唯一来源；业务代码不得再写字面量）。

口径来源：

* M17-supply-integrity.md §6.1（作弊升级与待分润冻结）/ §7（数据模型 1700–1799）/ §9（开关）；
* **task-15 决策（覆盖 §6.1 草案比例）**：S2 全开 I0–I4，
  比例 ``I0=0 / I1=50% / I2=80% / I3=I4=100%``（草案里的 10% / 50% 以本决策为准，
  待 Lead 回写 M17 §6.1；见证据文件「规格差异」一节）。
"""
from __future__ import annotations

from datetime import timedelta
from typing import Final

MODULE_ID: Final[str] = "M17"

# ───────────────────────────────────────────────────────── 等级 / 比例 / TTL
LEVELS: Final[tuple[str, ...]] = ("I0", "I1", "I2", "I3", "I4")
"""§6.1 作弊升级等级（S2 全开）。"""

LEVEL_RATIO_BP: Final[dict[str, int]] = {
    "I0": 0,        # 观察：不建 hold（只留事件）
    "I1": 5000,     # 50%，7 天
    "I2": 8000,     # 80%，人工复核
    "I3": 10000,    # 100%
    "I4": 10000,    # 100% + 清退流程（S3 罚没不在本模块）
}
"""冻结比例（基点，10000 = 100%）。**决策值**，同时写进 DB CHECK 兜底。"""

LEVEL_RANK: Final[dict[str, int]] = {level: index for index, level in enumerate(LEVELS)}
"""等级单调序（只升不降的判据）。"""

LEVEL_LABELS: Final[dict[str, str]] = {
    "I0": "observe", "I1": "minor", "I2": "moderate", "I3": "severe", "I4": "retire",
}

I1_TTL: Final[timedelta] = timedelta(days=7)
"""I1 自动到期窗口（§6.1：10%→决策 50%，7 天）；I2+ 无自动到期。"""

HOLD_STATES: Final[tuple[str, ...]] = ("active", "released", "expired")
TERMINAL_STATES: Final[tuple[str, ...]] = ("released", "expired")
EVENT_TYPES: Final[tuple[str, ...]] = ("created", "escalated", "released", "expired")
EVENT_CREATED: Final[str] = "created"
EVENT_ESCALATED: Final[str] = "escalated"
EVENT_RELEASED: Final[str] = "released"
EVENT_EXPIRED: Final[str] = "expired"

# ───────────────────────────────────────────────────────── 复核（双人）
REVIEWERS_REQUIRED: Final[dict[str, int]] = {"I0": 1, "I1": 1, "I2": 2, "I3": 2, "I4": 2}
"""解除冻结所需**不同**复核人数（I2+ 双人复核，§6.1）。"""

HIGH_LEVELS: Final[tuple[str, ...]] = ("I3", "I4")
HIGH_RELEASE_SCOPE: Final[str] = "integrity:release:high"
"""I3/I4 解除额外需要的 actor scope（由路由注入的主体提供）。"""

MAX_REVIEWERS: Final[int] = 4
ACTOR_MAX_LEN: Final[int] = 128
REASON_MAX_LEN: Final[int] = 64
EVIDENCE_MAX_LEN: Final[int] = 128
NODE_MAX_LEN: Final[int] = 128
MODEL_MAX_LEN: Final[int] = 128
BASE_AMOUNT_MAX_MICRO: Final[int] = 10**15
"""单笔待分润上限（micro；防脏数据把 BIGINT 打爆，超过即 400）。"""

# ───────────────────────────────────────────────────────── 管理面 scope / 分页
SCOPE_READ: Final[str] = "integrity.read"
SCOPE_WRITE: Final[str] = "integrity.write"
WILDCARD_SCOPE: Final[str] = "*"

DEFAULT_PAGE_SIZE: Final[int] = 50
MAX_PAGE_SIZE: Final[int] = 100
CURSOR_MAX_LEN: Final[int] = 512

HOLD_STATE_FILTERS: Final[tuple[str, ...]] = ("active", "all", "released", "expired")
"""列表过滤：``active``（默认，含「未逻辑到期」）/ ``all`` / 单态。"""

# ───────────────────────────────────────────────────────── 开关
FEATURE_NAME: Final[str] = "supply.freeze.enabled"
"""§9：owner=risk-seat / expire_at=2026-12-31 / 默认关闭；关闭时写路径 fail-closed。"""

# ───────────────────────────────────────────────────────── 列清单（SQL 唯一来源）
HOLD_COLUMNS: Final[str] = (
    "id, node_id, upstream_id, model, level, ratio_bp, base_amount_micro,"
    " frozen_amount_micro, state, reason, evidence_ref, created_at, expires_at,"
    " released_at, release_reason, reviewer_a, reviewer_b, version, updated_at")
EVENT_COLUMNS: Final[str] = (
    "event_id, hold_id, node_id, model, event, from_level, to_level, detail, actor, created_at")

# ───────────────────────────────────────────────────────── 账本边界（证据用）
LEDGER_TABLES: Final[tuple[str, ...]] = (
    "journal_entry", "journal_line", "ledger_entry", "account_balances",
    "merkle_commitments", "m06_outbox", "loss_pool_entries")
"""本模块**只读不写**的账本对象（用于迁移/用例的 diff=0 证明；代码里没有任何写入）。"""

PENDING_PAYOUT_SOURCE: Final[str] = "M05.pending_payout_snapshot"
"""``base_amount_micro`` 的唯一合法来源：调用方给的 M05 待分润快照（本模块不查账本）。"""

COARSE_REASONS: Final[tuple[str, ...]] = (
    "created", "escalated", "not_escalation", "downgrade_rejected", "hold_expired",
    "reviewers_insufficient", "reviewers_not_distinct", "scope_required",
    "feature_disabled", "invalid_argument", "not_found", "unauthorized", "forbidden",
    "conflict", "server_error",
)
"""对外 reason 只给这些短码（机器可判，不含阈值 / 名单 / PII）。"""
