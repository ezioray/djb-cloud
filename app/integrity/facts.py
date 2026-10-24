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

# ───────────────────────────────────────────────────────── C12 模型身份证明（M17 §5.1–5.3 / §5.7）
# 只加不改：本段不修改上面任何冻结段常量。
ATTEST_LEVELS: Final[tuple[str, ...]] = ("L0", "L1", "L2", "L3", "L4", "L5")
"""§5.1 证据等级：declared / reachable / inference / tokenizer / behavioral / provider。"""

ATTEST_LEVEL_RANK: Final[dict[str, int]] = {
    level: index for index, level in enumerate(ATTEST_LEVELS)}
"""等级单调序（只升不降的判据，与 DB 触发器 CASE 一致）。"""

ATTEST_LEVEL_LABELS: Final[dict[str, str]] = {
    "L0": "declared", "L1": "reachable", "L2": "inference",
    "L3": "tokenizer", "L4": "behavioral", "L5": "provider",
}

ATTEST_LEVEL_TTL: Final[dict[str, timedelta]] = {
    "L1": timedelta(hours=24),
    "L2": timedelta(hours=24),
    "L3": timedelta(days=7),
    "L4": timedelta(days=30),
    "L5": timedelta(days=90),
}
"""§5.7 TTL（L4/L5 本卡不产出，但表与常量先留好）。"""

ATTEST_STATES: Final[tuple[str, ...]] = ("active", "expired", "suspended")
ATTEST_SOURCES: Final[tuple[str, ...]] = ("server_challenge", "client_report", "provider")
ATTEST_SERVICE_MIN_LEVEL: Final[str] = "L3"
"""§5.1：容量公告 / 调度 / 结算只认 L3+ 且未过期。"""

ATTEST_FLAG: Final[str] = "supply.attestation.enabled"
ATTEST_ENV: Final[str] = "DJB_ATTEST"
"""S2 测试网显式激活：``DJB_ATTEST=1``；代码默认仍关闭。"""

CHALLENGE_TTL: Final[timedelta] = timedelta(minutes=5)
CHALLENGE_NONCE_BYTES: Final[int] = 16
"""nonce = 16 字节随机 → 32 hex；DB CHECK ``^[0-9a-f]{16,64}$``。"""

TOKENIZER_TOLERANCE_PCT: Final[float] = 1.0
TOKENIZER_MIN_TOLERANCE: Final[int] = 1
"""§5.1 / §5.3 容差：``max(1, ceil(prompt_tokens * 1%))``（整数化，边界可复算）。"""

EVIDENCE_RESULTS: Final[tuple[str, ...]] = (
    "reachable", "inference_ok", "tokenizer_match", "failed")
"""客户端上报的 result 枚举（Lead 1.2.11 定稿）；**等级由服务端判**，不采信该字段。"""

ATTEST_EVENTS: Final[tuple[str, ...]] = (
    "challenge_issued", "evidence_submitted", "tokenizer_mismatch", "failed",
    "level_up", "expired", "suspended")

PROMPT_MIN_LEN: Final[int] = 32
PROMPT_MAX_LEN: Final[int] = 2048
PROMPT_TOKENS_MAX: Final[int] = 100000
RESPONSE_HASH_MAX_LEN: Final[tuple[int, int]] = (64, 71)
"""``response_hash``：64 hex 或 ``sha256:<64 hex>``（71 字符）。"""

LATENCY_MAX_MS: Final[int] = 3_600_000
ERROR_CLASS_MAX_LEN: Final[int] = 64

SYNTHETIC_PROMPTS: Final[tuple[str, ...]] = (
    "You are a tokenizer probe. Repeat the following sentence exactly once, word for word, "
    "then stop: the quick brown fox jumps over the lazy dog while the calm river keeps "
    "flowing past the old stone bridge.",
    "Tokenizer probe: write the numbers one through twelve in words, separated by commas, "
    "then add the single word done and stop immediately without any extra commentary.",
    "请把下面这句话逐字复述一遍，不要添加任何解释：清晨的河面很安静，远处的山脊上还留着"
    "一层薄薄的雾，渔船慢慢划过水面，留下了一道很长的波纹。",
    "语言抽样检查：请依次写出春、夏、秋、冬四个字，每个字之间用顿号分隔，然后在最后"
    "加上「完成」两个字并停止，不要输出多余内容。",
    "Synthetic probe (no user data): list the first eight prime numbers separated by spaces, "
    "then output the word end and terminate the response immediately.",
    "合成探针（不含任何用户数据）：依次写出从一到十的阿拉伯数字，用逗号分隔，"
    "最后输出「结束」并停止，不要添加解释或标题。",
)
"""合成 prompt 池：固定、非用户数据、英文 / 中文各 3 条（§T9 最小探针与隐私）。

nonce 由 service 追加为独立一行（``challenge nonce: <hex>``），保证每次 prompt 计数不同、
不可预先缓存，同时仍然**不含任何用户正文**。
"""

ATTESTATION_COLUMNS: Final[str] = (
    "id, node_id, upstream_id, model, level, state, source, tokenizer_version,"
    " evidence_ref, verified_at, expires_at, created_at, updated_at")
CHALLENGE_COLUMNS: Final[str] = (
    "id, node_id, upstream_id, model, prompt, prompt_tokens, nonce, state,"
    " expires_at, created_at, consumed_at")
ATTEST_EVENT_COLUMNS: Final[str] = (
    "event_id, attestation_id, challenge_id, node_id, model, event, level, detail,"
    " actor, created_at")

# ───────────────────────────────────────────────────────── C14b 可验证随机抽检（M17 §5.10 / §5.11）
# 只加不改：本段不修改上面任何常量。
SAMPLING_FLAG: Final[str] = "supply.sampling.enabled"
SAMPLING_ENV: Final[str] = "DJB_SAMPLING"
"""S2 测试网显式激活：``DJB_SAMPLING=1``；代码默认仍关闭。"""

SAMPLING_SEED_BYTES: Final[int] = 32
"""seed = 32 字节随机（256 bit）；库里只存 sha256 承诺与揭示后的十六进制值。"""

SAMPLING_EPOCH_STATES: Final[tuple[str, ...]] = ("committed", "revealed", "expired")
SAMPLING_DRAW_STATUSES: Final[tuple[str, ...]] = ("pending", "passed", "failed", "missed")
SAMPLING_EVENTS: Final[tuple[str, ...]] = (
    "committed", "revealed", "drawn", "passed", "failed", "missed")

SAMPLING_MAX_CONTRIBUTIONS: Final[int] = 10000
SAMPLING_MAX_DRAW_COUNT: Final[int] = 1000
SAMPLING_WEIGHT_MAX: Final[int] = 10**15
"""单条贡献权重上限（bigint 安全；0 = 不参与抽签）。"""

SAMPLING_CONTRIBUTION_KEYS: Final[tuple[str, ...]] = ("node_id", "model", "weight")
SAMPLING_ACTOR_SYSTEM: Final[str] = "system:sampling"

#: 抽检建议阈值（与 M17 §6.1 的 I0/I1/I2 行对齐：单次 → I0；24h 内 2 次 → I1；7d 内 3 次 → I2）
SAMPLING_ESCALATION_24H: Final[timedelta] = timedelta(hours=24)
SAMPLING_ESCALATION_7D: Final[timedelta] = timedelta(days=7)
SAMPLING_LEVEL_24H_I0: Final[int] = 1
SAMPLING_LEVEL_24H_I1: Final[int] = 2
SAMPLING_LEVEL_7D_I2: Final[int] = 3

SAMPLING_EPOCH_COLUMNS: Final[str] = (
    "id, epoch_no, seed_commit, seed_reveal, contributions, state, committed_at,"
    " revealed_at, draw_count, created_at")
SAMPLING_DRAW_COLUMNS: Final[str] = (
    "id, epoch_id, node_id, model, weight, rank, challenge_id, status, level, detail,"
    " created_at, resolved_at")
SAMPLING_EVENT_COLUMNS: Final[str] = (
    "event_id, epoch_id, draw_id, event, detail, actor, created_at")
