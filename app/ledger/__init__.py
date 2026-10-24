# SPDX-License-Identifier: AGPL-3.0-or-later
"""M06 ledger（DEV-M06-T2：记账网关 = 校验 → 落账 → 哈希链 → outbox）。

本包是新账本（600–604 五表）的**唯一写入口**，也是旧符号的兼容出口::

    凭证：journal_entry ──N:1── journal_line ──1:1── ledger_entry
    派生：account_balances（T3 写，本包只读常量口径）
    期间：merkle_commitments（T4 写）
    事件：m06_outbox（journal.posted / ledger.reversed / merkle.anchored）

分层::

    facts.py       contracts/facts.yaml 读取层（科目数 / E1–E17 / Merkle 四类，只读、无第三方依赖）
    constants.py   42 科目 · fund_class 归属 · 单位 / 来源 / entry_type 枚举 · 本模块常量（单点定义 + 出处）
    errors.py      CR-L1 码值的类型化错误（42220/42221/40920/40924 …，不做 HTTP 包装）
    validate.py    纯校验 + 规范化（INV-01/03/04/05/11）
    hashchain.py   规范化哈希与链校验（与 600 迁移的 prev_hash/hash 列一一对应）
    outbox.py      三类事件的构造与同事务落库（02-events §3 业务键）
    gateway.py     post_journal / find_existing / load_journal
    legacy.py      001 旧路径（ledger_entries + accounts 余额），行为冻结

边界：不 import 其它 ``app.*`` 业务模块（架构门禁）；不写余额（T3）；不建 accounts（CR-L6）；
不实现 HTTP 端点（T4）；不带任何业务数字（facts.yaml + 本包常量表 + 迁移 CHECK 三处对齐）。
"""
from __future__ import annotations

from . import (balances, constants, errors, facts, gateway, hashchain, legacy, merkle, outbox,
               reversal, trial, validate, verify)
from .constants import (
    ALL_COA,
    COA_FUND_CLASS,
    COA_GROUPS,
    COA_NORMAL_DC,
    COA_QTY_REQUIRED,
    ENTRY_TYPES,
    EVENT_TYPES,
    HASH_ALGO,
    HASH_LEN,
    JOURNAL_MAX_LINES,
    JOURNAL_MIN_LINES,
    LEDGER_APPEND_LOCK_ID,
    MAX_ID_LEN,
    MAX_POLICY_VERSION_LEN,
    MAX_REASON_CODE_LEN,
    MAX_UNIT_SCALE,
    MERKLE_KINDS_OWNED,
    MINOR_UNIT_SCALE,
    NEGATIVE_FORBIDDEN_COA,
    REVERSAL_COOLDOWN_H,
    REVERSAL_EVENT_TYPE,
    REVERSAL_SOURCE_TYPE,
    SUB_ACCOUNT_BY_COA,
    SOURCE_TYPES,
    UNIT_TYPES,
)
from .errors import (
    AmountOutOfRange,
    ConcurrentReversalConflict,
    FundClassMismatch,
    InvalidEntryType,
    InvalidEventType,
    InvalidSourceType,
    InvalidUnitType,
    JournalNotFound,
    JournalValidationError,
    LedgerError,
    LineCountOutOfRange,
    InvariantViolation,
    MissingAssetQuantity,
    PartialReversalNotAllowed,
    ReversalCooldown,
    ReversalNotAllowed,
    TransactionRequired,
    UnbalancedJournal,
    UnknownCoaCode,
)
from .gateway import PostJournalResult, find_existing, load_journal, post_journal, require_transaction
from .hashchain import canonical_bytes, canonical_payload, journal_hash, verify_chain
from .outbox import (
    OutboxEvent,
    OutboxEventInvalid,
    append_event,
    journal_posted_event,
    ledger_reversed_event,
    merkle_anchored_event,
    pending_events,
)
from .validate import JournalDraft, JournalLine, NormalizedJournal, normalize
from .balances import (
    apply_journal,
    balance_drift,
    check_negative_liabilities,
    deltas_for_journal,
    derive_balances,
    latest_balances,
    sub_account_for,
)
from .merkle import MerkleError, MerklePublishedImmutable, anchor_period, merkle_root
from .reversal import ReversalResult, find_reversal, reverse_journal
from .trial import accounts_overview, decimal_str, trial_balance
from .verify import verify_ledger
from .legacy import GENESIS, PostResult, entry_hash, post_entry, recompute

__version__ = "0.3.0-dev-m06t3"

__all__ = [
    # 包内模块
    "balances", "constants", "errors", "facts", "gateway", "hashchain", "legacy", "merkle",
    "outbox", "reversal", "trial", "validate", "verify",
    # 新账本 API
    "JournalDraft", "JournalLine", "NormalizedJournal", "normalize",
    "PostJournalResult", "post_journal", "find_existing", "load_journal", "require_transaction",
    "canonical_payload", "canonical_bytes", "journal_hash", "verify_chain",
    "OutboxEvent", "OutboxEventInvalid", "append_event", "pending_events",
    "journal_posted_event", "ledger_reversed_event", "merkle_anchored_event",
    # 冲正
    "ReversalResult", "reverse_journal", "find_reversal",
    # 余额与复算
    "apply_journal", "derive_balances", "latest_balances", "balance_drift",
    "check_negative_liabilities", "deltas_for_journal", "sub_account_for", "verify_ledger",
    # 试算 / Merkle
    "trial_balance", "accounts_overview", "decimal_str", "merkle_root", "MerkleError",
    "MerklePublishedImmutable", "anchor_period",
    # 常量
    "ALL_COA", "COA_FUND_CLASS", "COA_GROUPS", "COA_NORMAL_DC", "COA_QTY_REQUIRED",
    "ENTRY_TYPES", "EVENT_TYPES", "SOURCE_TYPES", "UNIT_TYPES",
    "HASH_ALGO", "HASH_LEN", "JOURNAL_MAX_LINES", "JOURNAL_MIN_LINES", "LEDGER_APPEND_LOCK_ID",
    "MAX_ID_LEN", "MAX_POLICY_VERSION_LEN", "MAX_REASON_CODE_LEN", "MAX_UNIT_SCALE",
    "MERKLE_KINDS_OWNED", "MINOR_UNIT_SCALE", "NEGATIVE_FORBIDDEN_COA",
    "REVERSAL_COOLDOWN_H", "REVERSAL_EVENT_TYPE", "REVERSAL_SOURCE_TYPE", "SUB_ACCOUNT_BY_COA",
    # 错误
    "LedgerError", "JournalValidationError", "UnbalancedJournal", "LineCountOutOfRange",
    "AmountOutOfRange", "MissingAssetQuantity", "UnknownCoaCode", "FundClassMismatch",
    "InvalidUnitType", "InvalidEventType", "InvalidSourceType", "InvalidEntryType",
    "JournalNotFound", "ReversalNotAllowed", "ReversalCooldown", "ConcurrentReversalConflict",
    "PartialReversalNotAllowed", "InvariantViolation", "TransactionRequired",
    # 旧符号（app/api.py、app/chain/polygon.py、app/wallet_pool.py、scripts、旧测试）
    "GENESIS", "PostResult", "entry_hash", "post_entry", "recompute",
]
