# SPDX-License-Identifier: AGPL-3.0-or-later
"""冲正：整单等额取反（INV-07 / R5 / M06 §6「冲正」/ §7 失败表 / §8.2 冷却 24h）。

协议（顺序不能变，逐条对应 600/601 的库内护栏）::

    1. 读原凭证 + 行：不存在 → 40924；非 posted / 已有冲正 → 40920；
    2. 冷却期：同一 ref_id（source_type + source_id）已有**别的**凭证在 24h 内被冲正 → 40921；
    3. 新凭证：E16 / source_type=void / source_id=原凭证 journal_id / event_seq=1 /
       reversal_of_journal=原凭证；行 = 原行**逐行取反**（dc 翻转，金额与 qty 不变，
       reverse_of 指向原分录 entry_id）；
    4. 落账走 :func:`app.ledger.gateway.post_journal`（同一事务，含余额派生与 journal.posted）；
    5. 原分录 → voided、原凭证 → voided（601 允许的唯一 UPDATE 迁移，先插后改）；
    6. 发 ``ledger.reversed`` 事件（02-events §3）；
    7. INV-14：重算 I-4（负债不得为负）与 I-5 的可判部分（余额派生漂移），失败整笔回滚。

幂等口径（按 M06 §7，和普通落账不同）：**冲正不返回成功缓存** ——
同一原凭证的第二次冲正请求一律 40920（"重复冲正 → 拒绝"），
"绝不产生第二条冲正" 由 ``journal_entry_reversal_uq`` 与 ``ledger_entry_reverse_uq`` 双保险。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

import psycopg

from . import balances, gateway, outbox
from .constants import (
    MAX_REASON_CODE_LEN,
    REVERSAL_COOLDOWN_H,
    REVERSAL_EVENT_SEQ,
    REVERSAL_EVENT_TYPE,
    REVERSAL_SOURCE_TYPE,
)
from .errors import (
    ConcurrentReversalConflict,
    InvariantViolation,
    JournalNotFound,
    JournalValidationError,
    ReversalCooldown,
    ReversalNotAllowed,
)
from .validate import JournalDraft, JournalLine


@dataclass(frozen=True)
class ReversalResult:
    reversal_journal_id: str
    reversal_of: str
    seq: int
    hash: bytes
    lines: int
    total_minor: int
    event_ids: tuple[str, ...]
    voided_entries: int
    invariants: dict = field(default_factory=dict)

    @property
    def hash_hex(self) -> str:
        return self.hash.hex()


def _existing_reversal(conn, journal_id: str) -> str | None:
    with conn.cursor() as cur:
        cur.execute("SELECT journal_id FROM journal_entry WHERE reversal_of_journal = %s",
                    (journal_id,))
        row = cur.fetchone()
    return None if row is None else str(row[0])


def find_reversal(conn, journal_id: str) -> str | None:
    """读路径：某原凭证的冲正凭证 id（没有则 None）。T4 管理面用。"""
    return _existing_reversal(conn, journal_id)


def _check_cooldown(conn, original: dict, cooldown_hours: int) -> None:
    if cooldown_hours <= 0:
        return
    with conn.cursor() as cur:
        cur.execute(
            """SELECT r.journal_id, o.journal_id AS other_journal
                 FROM journal_entry r
                 JOIN journal_entry o ON o.journal_id = r.reversal_of_journal
                WHERE o.source_type = %s AND o.source_id = %s
                  AND o.journal_id <> %s
                  AND r.created_at > now() - make_interval(hours => %s)
                LIMIT 1""",
            (original["source_type"], original["source_id"], original["journal_id"], cooldown_hours))
        row = cur.fetchone()
    if row is not None:
        raise ReversalCooldown(
            f"冷却期：{original['source_type']}:{original['source_id']} 在 {cooldown_hours}h 内已被冲正"
            f"（另见 journal {row[1]}）",
            detail={"cooldown_hours": cooldown_hours, "other_journal": str(row[1]),
                    "previous_reversal": str(row[0])})


def _negative_snapshot(conn, account_ids: list[str]) -> dict[tuple[str, str], int]:
    """冲正前记录「已经是负」的负债快照，用于判断冲正是否让情况更糟。"""
    return {(v["account_id"], v["coa_code"]): v["normal_balance_minor"]
            for v in balances.check_negative_liabilities(conn, account_ids=account_ids)}


def _worsened_liabilities(before: dict[tuple[str, str], int], after: list[dict]) -> list[dict]:
    """I-4 的判定：冲正后不得出现新的负负债，也不得让已有负负债更负。

    只比「增量」而不是一刀切禁止负值：历史遗留的负负债不该挡住正常冲正
    （例如把一笔错账冲掉反而是修复）；但把已花掉的充值冲回去必须拦住。
    """
    return [item for item in after
            if item["normal_balance_minor"] < min(before.get((item["account_id"], item["coa_code"]), 0), 0)]


def _flip(dc: str) -> str:
    return "C" if dc == "D" else "D"


def _reversal_lines(original: dict) -> tuple[JournalLine, ...]:
    return tuple(
        JournalLine(
            account_id=line["account_id"], coa_code=line["coa_code"], dc=_flip(line["dc"]),
            amount_minor=line["amount_minor"], entry_type="void",
            qty_minor=line["qty_minor"], unit_scale=line["unit_scale"],
            wallet_id=line["wallet_id"], fund_class=line["fund_class"],
            reverse_of=line["ledger_entry_id"])
        for line in original["lines"])


def _void_original(conn, journal_id: str, line_count: int) -> int:
    """把原分录 / 原凭证置 voided（唯一合法迁移，601 的护栏只放行 posted→voided）。"""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE ledger_entry SET status = 'voided' "
            " WHERE journal_id = %s AND status = 'posted'", (journal_id,))
        voided_entries = cur.rowcount
        cur.execute(
            "UPDATE journal_entry SET status = 'voided' "
            " WHERE journal_id = %s AND status = 'posted'", (journal_id,))
        voided_journal = cur.rowcount
    if voided_entries != line_count or voided_journal != 1:
        raise ConcurrentReversalConflict(
            f"冲正状态迁移失败：分录 {voided_entries}/{line_count}、凭证 {voided_journal}/1（并发冲正？）")
    return voided_entries


def reverse_journal(conn, journal_id: str, *, reason_code: str,
                    policy_version: str | None = None, ts: datetime | None = None,
                    trace_id: str | None = None, approval_chain: dict | None = None,
                    cooldown_hours: int = REVERSAL_COOLDOWN_H,
                    enforce_invariants: bool = True) -> ReversalResult:
    """冲正一张 posted 凭证（调用方给事务；任何一步失败都整笔回滚）。"""
    if not isinstance(reason_code, str) or not (1 <= len(reason_code) <= MAX_REASON_CODE_LEN):
        raise JournalValidationError(
            f"reason_code 必须是 1..{MAX_REASON_CODE_LEN} 字符（ledger.reversed 必填）")

    gateway.require_transaction(conn)
    try:
        gateway._acquire_append_lock(conn)
    except psycopg.errors.LockNotAvailable as exc:      # 另一笔写入正持有账本追加锁
        raise ConcurrentReversalConflict(
            "账本追加锁等待超时：存在并发写入/冲正（40920）", detail={"stage": "append_lock"}) from exc

    original = gateway.load_journal(conn, journal_id)
    if original is None:
        raise JournalNotFound(f"凭证 {journal_id} 不存在（40924）")
    if original["status"] != "posted":
        raise ReversalNotAllowed(f"凭证 {journal_id} 已是 {original['status']}，不可再冲正（40920）")
    if original["reversal_of_journal"] is not None:
        raise ReversalNotAllowed(
            f"凭证 {journal_id} 本身是冲正凭证，不得再被冲正（保守口径，需 lead 裁决才放开）")
    previous = _existing_reversal(conn, journal_id)
    if previous is not None:
        raise ReversalNotAllowed(f"凭证 {journal_id} 已有冲正 {previous}（INV-07：至多一条，40920）")
    _check_cooldown(conn, original, cooldown_hours)

    account_ids = sorted({line["account_id"] for line in original["lines"]})
    before_negative = _negative_snapshot(conn, account_ids)

    lines = _reversal_lines(original)
    if len(lines) != len(original["lines"]) or not lines:
        raise JournalValidationError("冲正行数必须与原凭证一致（整单取反）")

    draft = JournalDraft(
        event_type=REVERSAL_EVENT_TYPE, unit_type=original["unit_type"],
        source_type=REVERSAL_SOURCE_TYPE, source_id=original["journal_id"],
        event_seq=REVERSAL_EVENT_SEQ,
        policy_version=policy_version or original["policy_version"],
        lines=lines, ts=ts, reversal_of_journal=original["journal_id"],
        merkle_period=original["merkle_period"], approval_chain=approval_chain,
        ref_id=original["source_id"], trace_id=trace_id)
    try:
        posted = gateway.post_journal(conn, draft)
    except psycopg.errors.UniqueViolation as exc:
        # 并发冲正：唯一索引（journal_entry_reversal_uq / ledger_entry_reverse_uq / hash）兜底
        raise ConcurrentReversalConflict(f"并发冲正：{journal_id} 的冲正已存在（INV-07）") from exc

    voided_entries = _void_original(conn, journal_id, len(lines))

    event = outbox.ledger_reversed_event(
        journal_id=posted.journal_id, reverse_of=journal_id, reason_code=reason_code,
        trace_id=trace_id or uuid.uuid4().hex, correlation_id=original["source_id"],
        occurred_at=ts)
    event_ids = posted.event_ids + (outbox.append_event(conn, event),)

    invariants: dict = {}
    if enforce_invariants:
        violations = balances.check_negative_liabilities(conn, account_ids=account_ids)
        worsened = _worsened_liabilities(before_negative, violations)
        if worsened:
            raise InvariantViolation(
                "冲正后 I-4 失败：负债科目变得更负", detail={"violations": worsened})
        drift = balances.balance_drift(conn)
        if drift["diff"]:
            raise InvariantViolation(
                "冲正后 I-5/INV-10 失败：余额派生与分录不一致", detail={"drift": drift})
        invariants = {"i4_violations": 0, "i5_drift": 0}

    return ReversalResult(
        reversal_journal_id=posted.journal_id, reversal_of=journal_id, seq=posted.seq,
        hash=posted.hash, lines=len(lines),
        total_minor=sum(line.amount_minor for line in lines if line.dc == "D"),
        event_ids=tuple(event_ids), voided_entries=voided_entries, invariants=invariants)
