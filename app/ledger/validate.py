# SPDX-License-Identifier: Apache-2.0
"""凭证校验与规范化（纯函数，不碰数据库）。

校验口径逐条对应 M06 不变量，失败即抛 :mod:`app.ledger.errors` 里的类型错误：
  INV-01 每凭证 Σ借 = Σ贷、同一 unit_type、整数 amount_minor、行数 ≥2（上限 JOURNAL_MAX_LINES）
  INV-03 科目在 42 条白名单内，且 fund_class 与科目归属一致
  INV-04 只在本 unit_type 内平衡（行不携带单位 → 跨单位混记结构上不可表达）
  INV-05 未知科目 / entry_type / event_type / source_type 一律拒绝，不静默跳过
  INV-11 资产行（1101/1102/1103）必须同时记 qty_minor
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from . import facts
from .constants import (
    ALL_COA,
    COA_FUND_CLASS,
    COA_QTY_REQUIRED,
    ENTRY_TYPES,
    EVENT_TYPES,
    JOURNAL_MAX_LINES,
    JOURNAL_MIN_LINES,
    MAX_AGGREGATE_ID_LEN,
    MAX_ID_LEN,
    MAX_IDEMPOTENCY_KEY_LEN,
    MAX_POLICY_VERSION_LEN,
    MAX_UNIT_SCALE,
    MINOR_UNIT_SCALE,
    SOURCE_TYPES,
    UNIT_TYPES,
)
from .errors import (
    AmountOutOfRange,
    InvalidEntryType,
    FundClassMismatch,
    InvalidEventType,
    InvalidSourceType,
    InvalidUnitType,
    JournalValidationError,
    LineCountOutOfRange,
    MissingAssetQuantity,
    UnbalancedJournal,
    UnknownCoaCode,
)

FUND_CLASSES = ("CLIENT", "PLATFORM", "FEE")
DC_VALUES = ("D", "C")


@dataclass(frozen=True)
class JournalLine:
    """一行凭证（会计视角）。``fund_class`` 省略时按科目自动推导，但仍会校验是否配对。"""

    account_id: str
    coa_code: str
    dc: str
    amount_minor: int
    entry_type: str
    qty_minor: int | None = None
    unit_scale: int = MINOR_UNIT_SCALE
    wallet_id: str | None = None
    fund_class: str | None = None


@dataclass(frozen=True)
class JournalDraft:
    """一张待落账的凭证（一次资金事件）。"""

    event_type: str
    unit_type: str
    source_type: str
    source_id: str
    policy_version: str
    lines: Sequence[JournalLine]
    ts: datetime | None = None
    event_seq: int = 0
    fx_rate_id: int = 1
    reversal_of_journal: str | None = None
    merkle_period: str | None = None
    approval_chain: Mapping[str, Any] | None = None
    ref_id: str | None = None
    trace_id: str | None = None
    correlation_id: str | None = None
    idempotency_key: str | None = None

    # ── 派生标识（不参与哈希） ──
    def key(self) -> tuple[str, str, int]:
        """幂等键（INV-06 / I-8）。"""
        return (self.source_type, self.source_id, int(self.event_seq))

    def resolved_ref_id(self) -> str:
        return self.ref_id or self.source_id

    def resolved_trace_id(self) -> str:
        return self.trace_id or uuid.uuid4().hex

    def resolved_idempotency_key(self) -> str:
        return self.idempotency_key or ":".join(
            [self.source_type, self.source_id, str(int(self.event_seq))])


@dataclass(frozen=True)
class NormalizedJournal:
    """校验通过后的凭证：默认值补齐、行号已分配、合计已算好。"""

    draft: JournalDraft
    lines: tuple[JournalLine, ...]
    total_debit_minor: int
    total_credit_minor: int
    idempotency_key: str
    trace_id: str
    ref_id: str
    ts: datetime


def _require_len(value: Any, name: str, *, low: int = 1, high: int = MAX_ID_LEN) -> str:
    if not isinstance(value, str) or not (low <= len(value) <= high):
        raise JournalValidationError(f"{name} 必须是 {low}..{high} 字符的字符串，收到 {value!r}")
    return value


def _normalize_line(index: int, line: JournalLine) -> JournalLine:
    where = f"第 {index} 行"
    if line.coa_code not in COA_FUND_CLASS:
        raise UnknownCoaCode(f"{where}：科目 {line.coa_code!r} 不在 42 条白名单内（INV-03）",
                             detail={"coa_code": line.coa_code, "allowed": len(ALL_COA)})
    expected_fund_class = COA_FUND_CLASS[line.coa_code]
    fund_class = line.fund_class or expected_fund_class
    if fund_class not in FUND_CLASSES:
        raise FundClassMismatch(f"{where}：fund_class {fund_class!r} 不是 CLIENT/PLATFORM/FEE")
    if fund_class != expected_fund_class:
        raise FundClassMismatch(
            f"{where}：科目 {line.coa_code} 的 fund_class 应为 {expected_fund_class}，收到 {fund_class}（INV-03）",
            detail={"coa_code": line.coa_code, "expected": expected_fund_class, "actual": fund_class})
    if line.dc not in DC_VALUES:
        raise JournalValidationError(f"{where}：dc 必须是 D 或 C，收到 {line.dc!r}")
    if not isinstance(line.amount_minor, int) or isinstance(line.amount_minor, bool) \
            or line.amount_minor <= 0:
        raise AmountOutOfRange(f"{where}：amount_minor 必须是正整数最小单位，收到 {line.amount_minor!r}")
    if not isinstance(line.entry_type, str) or line.entry_type not in ENTRY_TYPES:
        raise InvalidEntryType(
            f"{where}：entry_type {line.entry_type!r} 不在 §20.4.4 白名单内（INV-05）",
            detail={"allowed": list(ENTRY_TYPES)})
    if line.qty_minor is not None:
        if not isinstance(line.qty_minor, int) or isinstance(line.qty_minor, bool) or line.qty_minor <= 0:
            raise JournalValidationError(f"{where}：qty_minor 必须是正整数，收到 {line.qty_minor!r}")
    elif line.coa_code in COA_QTY_REQUIRED:
        raise MissingAssetQuantity(
            f"{where}：科目 {line.coa_code} 必须同时记 qty_minor（INV-11 / §20.2.8 C4）")
    if not isinstance(line.unit_scale, int) or isinstance(line.unit_scale, bool) \
            or not (0 <= line.unit_scale <= MAX_UNIT_SCALE):
        raise JournalValidationError(f"{where}：unit_scale 必须在 0..{MAX_UNIT_SCALE}，收到 {line.unit_scale!r}")
    _require_len(line.account_id, f"{where} 的 account_id")
    if line.wallet_id is not None:
        _require_len(line.wallet_id, f"{where} 的 wallet_id")
    return JournalLine(
        account_id=line.account_id,
        coa_code=line.coa_code,
        dc=line.dc,
        amount_minor=int(line.amount_minor),
        entry_type=line.entry_type,
        qty_minor=None if line.qty_minor is None else int(line.qty_minor),
        unit_scale=int(line.unit_scale),
        wallet_id=line.wallet_id,
        fund_class=fund_class,
    )


def normalize(draft: JournalDraft) -> NormalizedJournal:
    """校验并规范化一张凭证；任何不合法都抛类型化错误（不写库、不带副作用）。"""
    if draft.unit_type not in UNIT_TYPES:
        raise InvalidUnitType(f"unit_type {draft.unit_type!r} 不在 {UNIT_TYPES}（INV-04）")
    if draft.event_type not in EVENT_TYPES:
        raise InvalidEventType(
            f"event_type {draft.event_type!r} 不在 facts.yaml 的资金事件 {EVENT_TYPES[0]}–{EVENT_TYPES[-1]} 内")
    if draft.source_type not in SOURCE_TYPES:
        raise InvalidSourceType(
            f"source_type {draft.source_type!r} 不在 spec SourceType 的 {len(SOURCE_TYPES)} 值内（INV-05）")
    _require_len(draft.source_id, "source_id")
    _require_len(draft.policy_version, "policy_version", high=MAX_POLICY_VERSION_LEN)
    if not isinstance(draft.event_seq, int) or isinstance(draft.event_seq, bool) or draft.event_seq < 0:
        raise JournalValidationError(f"event_seq 必须是 ≥0 的整数，收到 {draft.event_seq!r}")
    if not isinstance(draft.fx_rate_id, int) or isinstance(draft.fx_rate_id, bool) or draft.fx_rate_id <= 0:
        raise JournalValidationError(f"fx_rate_id 必须是正整数（1 = 同币种无换汇），收到 {draft.fx_rate_id!r}")

    lines = tuple(draft.lines or ())
    if not (JOURNAL_MIN_LINES <= len(lines) <= JOURNAL_MAX_LINES):
        raise LineCountOutOfRange(
            f"凭证行数必须在 {JOURNAL_MIN_LINES}..{JOURNAL_MAX_LINES}，收到 {len(lines)}（INV-01 / M06 §8.2）")
    normalized = tuple(_normalize_line(i, line) for i, line in enumerate(lines, start=1))

    debit = sum(line.amount_minor for line in normalized if line.dc == "D")
    credit = sum(line.amount_minor for line in normalized if line.dc == "C")
    if debit != credit:
        raise UnbalancedJournal(
            f"借贷不平：Σ借={debit} ≠ Σ贷={credit}（INV-01）",
            detail={"debit_minor": debit, "credit_minor": credit})
    if debit <= 0:
        raise UnbalancedJournal("凭证合计必须 > 0（INV-01）")

    ts = draft.ts or datetime.now(timezone.utc)
    if not isinstance(ts, datetime):
        raise JournalValidationError(f"ts 必须是 datetime，收到 {type(ts).__name__}")
    if ts.tzinfo is None:
        raise JournalValidationError("ts 必须带时区（账本一律 UTC）")

    key = draft.resolved_idempotency_key()
    if len(key) > MAX_IDEMPOTENCY_KEY_LEN:
        raise JournalValidationError(f"idempotency_key 超过 {MAX_IDEMPOTENCY_KEY_LEN} 字符")
    if draft.reversal_of_journal is not None:
        try:
            uuid.UUID(str(draft.reversal_of_journal))
        except (ValueError, AttributeError) as exc:
            raise JournalValidationError(f"reversal_of_journal 不是合法 UUID：{draft.reversal_of_journal!r}") from exc

    return NormalizedJournal(
        draft=draft,
        lines=normalized,
        total_debit_minor=debit,
        total_credit_minor=credit,
        idempotency_key=key,
        trace_id=draft.resolved_trace_id(),
        ref_id=draft.resolved_ref_id(),
        ts=ts,
    )


def facts_snapshot() -> dict:
    """校验器用到的常量快照（证据/排障用，不含业务数据）。"""
    return {
        "coa_total": len(ALL_COA),
        "coa_from_facts": facts.coa_count(),
        "event_types": len(EVENT_TYPES),
        "source_types": len(SOURCE_TYPES),
        "entry_types": len(ENTRY_TYPES),
        "unit_types": list(UNIT_TYPES),
        "journal_max_lines": JOURNAL_MAX_LINES,
    }
