# SPDX-License-Identifier: AGPL-3.0-or-later
"""三方对账 planner（M09 §6.1）：scope=psp / chain / bank。

本模块只产出 engine.Observation（纯数据），落库 / INV-04 幂等 / 差异台账 / 状态机 /
分级 / 复核仍由 engine.run 统一处理——与 receipt / daily_close 完全同一条路径，
没有第二套写库逻辑。

数据边界（只读，不写业务表）
----------------------------
* psp   M08 payment_attempts（provider_txn_id / amount / currency / status /
  settled_minor / settlement_fee_minor）↔ M06 journal_entry(journal_line) 的 E3 / E4
  （source_type='payment_attempt'、source_id=provider_txn_id、event_seq 1/2/3）。
* chain M08 wallet.balance_minor（USD 分）↔ M06 journal_line(wallet_id, 1101/1102)
  截止 cutoff_at 的累计净额（借 − 贷）。容差 0；1101/1102 行缺 wallet_id 一律结构性 P0。
* bank  M08 payout_batches / payout_items（txid / net_minor / status）与 refund_requests
  （原路 / 金额 / status）↔ M06 E8 / E11 分录 + 银行流水夹具
  （txid / amount / currency / posted_at）。

金额纪律（INV-08 / 03-facts §6）
-------------------------------
* 比较单位统一 micro-USD（unit_scale=6）：M08 的「分」×10,000（MICRO_PER_MINOR），
  M06 行按 unit_scale 归一（2 → ×10,000，6 → ×1）；全部整数运算，不出现浮点。
* diff_minor 有符号 = book − external；run 的 diff_minor 仍由 902 触发器按
  「未关闭差异之和」维护（INV-01），planner 不写它。
* 分级阈值（03-facts §7）以「USD 分」表达，本模块的 diff 是 micro：比较前把阈值
  ×10,000 归一，避免把 1.00 USD 误判成 P0。

外部输入（不落库）
------------------
PSP 结算文件与银行流水只以调用方注入的内存夹具进入本模块
（EngineDeps.psp_settlement / EngineDeps.bank_statement）；落库仅存整份夹具的
canonical JSON SHA-256（metrics.settlement_sha256 / metrics.bank_statement_sha256），
不存行正文（M09 §5 数据纪律）。没有数据源时如实标 no_source，不伪造 matched。
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping, Sequence

import psycopg

from . import clock, facts, grading, models
from .engine import EngineDeps, Observation
from .errors import BadRequest

__all__ = [
    "SettlementRow", "BankRow", "parse_settlement_file", "parse_bank_statement",
    "settlement_fingerprint", "bank_statement_fingerprint",
    "observe_psp", "observe_chain", "observe_bank", "plan",
]

_CURRENCY = re.compile(r"^[A-Z]{3}$")
#: PSP 结算到账时间容差 ±T+3（03-facts §7）
_PSP_WINDOW = timedelta(hours=facts.PSP_SETTLEMENT_WINDOW_HOURS)


# ───────────────────────────────────────────────────────────── 金额 / 夹具
def _micro(amount_minor: int, unit_scale: int) -> int:
    """整数最小单位 → micro-USD。unit_scale > 6 无法整数归一，fail-closed。"""
    if isinstance(amount_minor, bool) or not isinstance(amount_minor, int):
        raise BadRequest("金额必须是整数最小单位", field="amount_minor")
    scale = int(unit_scale)
    if scale > facts.RECON_UNIT_SCALE:
        raise BadRequest(
            f"unit_scale={scale} 超出对账归一范围（≤{facts.RECON_UNIT_SCALE}）：拒绝近似比较",
            field="unit_scale")
    return int(amount_minor) * (10 ** (facts.RECON_UNIT_SCALE - scale))


def _currency(value: Any, field: str) -> str:
    text = models.require_text(value, field=field, max_len=8)
    assert text is not None
    text = text.upper()
    if not _CURRENCY.fullmatch(text):
        raise BadRequest(f"{field} 必须是 ISO-4217 三字母币种", field=field)
    return text


@dataclass(frozen=True)
class SettlementRow:
    """PSP 结算文件一行（金额单位：USD 分，与 M08 支付单据一致）。"""

    provider_txn_id: str
    settled_minor: int
    fee_minor: int
    currency: str


@dataclass(frozen=True)
class BankRow:
    """银行流水一行（金额单位：USD 分，03-facts §6「银行单据以分为单位」）。"""

    txid: str
    amount_minor: int
    currency: str
    posted_at: datetime


def _rows_input(rows: Any, field: str) -> Sequence[Mapping[str, Any]]:
    if rows is None:
        return ()
    if isinstance(rows, (str, bytes, Mapping)):
        raise BadRequest(f"{field} 必须是对象数组", field=field)
    return rows


def parse_settlement_file(rows: Any) -> list[SettlementRow]:
    """校验并归一 PSP 结算文件夹具；非法行返回 400/40001（不静默丢弃）。"""
    parsed: list[SettlementRow] = []
    for index, raw in enumerate(_rows_input(rows, "psp_settlement")):
        where = f"psp_settlement[{index}]"
        if not isinstance(raw, Mapping):
            raise BadRequest(f"{where} 必须是对象", field="psp_settlement")
        parsed.append(SettlementRow(
            provider_txn_id=models.require_text(raw.get("provider_txn_id"),
                                                field=f"{where}.provider_txn_id", max_len=128),
            settled_minor=models.require_int(raw.get("settled_minor"),
                                             field=f"{where}.settled_minor", minimum=0),
            fee_minor=models.require_int(raw.get("fee_minor", 0),
                                         field=f"{where}.fee_minor", minimum=0),
            currency=_currency(raw.get("currency"), f"{where}.currency"),
        ))
    return parsed


def parse_bank_statement(rows: Any) -> list[BankRow]:
    """校验并归一银行流水夹具（amount 与 amount_minor 都接受，单位分）。"""
    parsed: list[BankRow] = []
    for index, raw in enumerate(_rows_input(rows, "bank_statement")):
        where = f"bank_statement[{index}]"
        if not isinstance(raw, Mapping):
            raise BadRequest(f"{where} 必须是对象", field="bank_statement")
        amount = raw.get("amount_minor", raw.get("amount"))
        parsed.append(BankRow(
            txid=models.require_text(raw.get("txid"), field=f"{where}.txid", max_len=128),
            amount_minor=models.require_int(amount, field=f"{where}.amount_minor", minimum=0),
            currency=_currency(raw.get("currency"), f"{where}.currency"),
            posted_at=clock.parse_datetime(raw.get("posted_at"), field=f"{where}.posted_at"),
        ))
    return parsed


def _sha256(payload: Any) -> str:
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def settlement_fingerprint(rows: Iterable[SettlementRow]) -> str:
    """只有引用 / 哈希落库：canonical JSON 的 SHA-256（按 provider_txn_id 排序，行序无关）。"""
    ordered = sorted(rows, key=lambda row: row.provider_txn_id)
    return _sha256([{"provider_txn_id": row.provider_txn_id,
                     "settled_minor": row.settled_minor, "fee_minor": row.fee_minor,
                     "currency": row.currency} for row in ordered])


def bank_statement_fingerprint(rows: Iterable[BankRow]) -> str:
    ordered = sorted(rows, key=lambda row: (row.txid, row.posted_at))
    return _sha256([{"txid": row.txid, "amount_minor": row.amount_minor,
                     "currency": row.currency, "posted_at": clock.iso_micros(row.posted_at)}
                    for row in ordered])


def _scoped_spec(spec: models.RunSpec) -> models.RunSpec:
    """三方 scope 在未显式指定 rule_version 时用各自的比较口径版本。"""
    version = facts.RULE_VERSION_BY_SCOPE.get(spec.scope)
    if version and spec.rule_version == facts.RULE_VERSION:
        return replace(spec, rule_version=version)
    return spec


#: 分级阈值在 facts 里是「USD 分」（03-facts §7）；三方 scope 的 diff 是 micro-USD，
#: 因此按 ×10,000 换算阈值后再比较（不把 micro 当分去套 P0/P1 边界）。
_GRADE_MICRO = facts.MICRO_PER_MINOR


def _severity(diff_minor: int, kind: str) -> str:
    if grading.is_structural(kind):
        return "P0"
    magnitude = abs(int(diff_minor))
    if magnitude > facts.P0_AMOUNT_MINOR_EXCLUSIVE * _GRADE_MICRO:
        return "P0"
    if magnitude >= facts.P1_AMOUNT_MINOR_MIN * _GRADE_MICRO:
        return "P1"
    return "P2"


def _add(obs: Observation, *, scope: str, deps: EngineDeps, moment: datetime, kind: str,
         ref_type: str, ref_id: str | None, diff_minor: int, root_cause: str | None = None,
         evidence_ref: str | None = None) -> None:
    severity = _severity(diff_minor, kind)
    obs.exceptions.append(models.ExceptionDraft(
        kind=kind, severity=severity, ref_type=ref_type, ref_id=ref_id,
        diff_minor=int(diff_minor), sla_due=grading.sla_due(moment, severity), scope=scope,
        owner=deps.default_owner, root_cause=root_cause, evidence_ref=evidence_ref))


# ═══════════════════════════════════════════════════════════════════════ scope=psp
_PSP_ATTEMPTS_SQL = """
SELECT a.attempt_id::text AS attempt_id, a.provider, a.provider_txn_id,
       a.status, a.amount_minor, a.fee_minor, a.net_minor, a.currency,
       a.settled_minor, a.settlement_fee_minor, a.created_at,
       o.order_id::text AS order_id, o.order_no, o.account_id
  FROM payment_attempts a
  JOIN payment_orders o ON o.order_id = a.order_id
 WHERE a.created_at >= %s AND a.created_at < %s AND a.created_at <= %s
 ORDER BY a.provider_txn_id NULLS LAST, a.attempt_id
"""

_PSP_JOURNAL_SQL = """
SELECT j.journal_id::text AS journal_id, j.event_type, j.source_type, j.source_id,
       j.event_seq, j.ts, l.line_no, l.coa_code, l.dc, l.amount_minor, l.unit_scale
  FROM journal_entry j
  JOIN journal_line l ON l.journal_id = j.journal_id
 WHERE j.status = 'posted' AND j.unit_type = 'USD'
   AND j.event_type IN ('E3', 'E4') AND j.source_type = 'payment_attempt'
   AND j.ts >= %s AND j.ts < %s AND j.ts <= %s
 ORDER BY j.source_id, j.event_seq, j.journal_id, l.line_no
"""


@dataclass
class _PspBook:
    """一个 provider_txn_id 在账本侧的 E3 / E4 金额（micro-USD）。"""

    journals: dict[int, set[str]] = field(default_factory=dict)
    e3_gross: int = 0
    e4_net: int = 0
    e4_fee: int = 0

    @property
    def total(self) -> int:
        """book 侧总额：优先 E3 毛额；只有 E4 时用「净额 + 手续费」还原毛额。"""
        return self.e3_gross if self.e3_gross else self.e4_net + self.e4_fee

    @property
    def empty(self) -> bool:
        return self.e3_gross == 0 and self.e4_net == 0 and self.e4_fee == 0


def _psp_attempts(conn: psycopg.Connection, spec: models.RunSpec) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(_PSP_ATTEMPTS_SQL, (spec.period_start, spec.period_end, spec.cutoff_at))
        rows = cur.fetchall()
    return [
        {"attempt_id": row[0], "provider": row[1], "provider_txn_id": row[2],
         "status": row[3], "amount_minor": int(row[4]), "fee_minor": int(row[5]),
         "net_minor": int(row[6]), "currency": row[7],
         "settled_minor": None if row[8] is None else int(row[8]),
         "settlement_fee_minor": None if row[9] is None else int(row[9]),
         "created_at": row[10], "order_id": row[11], "order_no": row[12],
         "account_id": row[13]}
        for row in rows
    ]


def _psp_books(conn: psycopg.Connection, spec: models.RunSpec
               ) -> tuple[dict[str, _PspBook], int]:
    """按 provider_txn_id 聚合 E3/E4 的借贷金额（逐 journal 取数后累加）。"""
    with conn.cursor() as cur:
        cur.execute(_PSP_JOURNAL_SQL, (spec.period_start, spec.period_end, spec.cutoff_at))
        rows = cur.fetchall()

    per_journal: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        source_id = row[3]
        journal_id = row[0]
        seq = int(row[4])
        amount = _micro(int(row[9]), int(row[10]))
        agg = per_journal.setdefault((source_id, journal_id),
                                     {"seq": seq, "e3": 0, "e4_net": 0, "e4_fee": 0})
        coa, dc = row[7], row[8]
        if seq == 1 and coa == "1120" and dc == "D":
            agg["e3"] += amount
        elif seq == 2 and coa == "1121" and dc == "D":
            agg["e4_net"] += amount
        elif seq == 3 and coa == "1121" and dc == "D":
            agg["e4_fee"] += amount

    books: dict[str, _PspBook] = {}
    for (source_id, journal_id), agg in per_journal.items():
        book = books.setdefault(source_id, _PspBook())
        seq = int(agg["seq"])
        book.journals.setdefault(seq, set()).add(journal_id)
        book.e3_gross += int(agg["e3"])
        book.e4_net += int(agg["e4_net"])
        book.e4_fee += int(agg["e4_fee"])
    return books, len(rows)


def observe_psp(conn: psycopg.Connection, spec: models.RunSpec, *,
                deps: EngineDeps, now: datetime) -> Observation:
    """scope=psp：payment_attempts ↔ E3/E4，逐笔按 provider_txn_id 比对。"""
    moment = clock.as_utc(now)
    attempts = _psp_attempts(conn, spec)
    books, journal_lines = _psp_books(conn, spec)
    settlement = parse_settlement_file(deps.psp_settlement)
    settlement_provided = deps.psp_settlement is not None

    obs = Observation(external_minor=0, book_minor=0)
    bad_keys: set[str] = set()
    timing = 0
    skipped_no_txn = 0
    attempts_by_txn: dict[str, dict[str, Any]] = {}

    def add(key: str, **kwargs: Any) -> None:
        bad_keys.add(key)
        _add(obs, scope=spec.scope, deps=deps, moment=moment, **kwargs)

    for attempt in attempts:
        txn = attempt["provider_txn_id"]
        if not txn:
            if attempt["status"] == "succeeded":
                add(f"attempt:{attempt['attempt_id']}",
                    kind="unidentified", ref_type="payment_attempt",
                    ref_id=attempt["attempt_id"], diff_minor=0,
                    root_cause="missing_provider_txn_id",
                    evidence_ref=f"order:{attempt['order_no']}")
            else:
                skipped_no_txn += 1
            continue
        attempts_by_txn.setdefault(txn, attempt)
        if attempt["status"] == "succeeded":
            obs.external_minor += _micro(attempt["amount_minor"], facts.M08_UNIT_SCALE)

    keys = sorted(set(attempts_by_txn) | set(books))
    for txn in keys:
        attempt = attempts_by_txn.get(txn)
        book = books.get(txn)
        book_total = book.total if book is not None else 0
        obs.book_minor += book_total
        if attempt is None:
            events = ",".join(str(seq) for seq in sorted(book.journals)) if book else ""
            add(txn, kind="missing_external", ref_type="payment_attempt", ref_id=txn,
                diff_minor=book_total, root_cause="journal_without_attempt",
                evidence_ref=f"journal_events:{events}")
            continue

        gross = _micro(attempt["amount_minor"], facts.M08_UNIT_SCALE)
        if attempt["currency"] != "USD":
            add(txn, kind="unidentified", ref_type="payment_attempt", ref_id=txn,
                diff_minor=0, root_cause="unsupported_currency",
                evidence_ref=f"currency:{attempt['currency']}")
            continue
        if attempt["status"] != "succeeded":
            if book_total:
                events = ",".join(str(seq) for seq in sorted(book.journals))
                add(txn, kind="missing_external", ref_type="payment_attempt", ref_id=txn,
                    diff_minor=book_total, root_cause="attempt_not_succeeded",
                    evidence_ref=f"status:{attempt['status']};journal_events:{events}")
            continue
        if book is None or book.empty:
            add(txn, kind="missing_in_ledger", ref_type="payment_attempt", ref_id=txn,
                diff_minor=-gross, root_cause="attempt_not_booked",
                evidence_ref=f"order:{attempt['order_no']}")
            continue

        # 同一 event_seq 出现多张凭证 = 重复入账（INV-02，结构性 P0）
        for seq in (1, 2, 3):
            journal_ids = book.journals.get(seq, set())
            if len(journal_ids) > 1:
                add(txn, kind="duplicate", ref_type="payment_attempt", ref_id=txn,
                    diff_minor=0, root_cause=f"duplicate_event_seq_{seq}",
                    evidence_ref="journals:" + ",".join(sorted(journal_ids)))
        if book.e3_gross and book.e3_gross != gross:
            add(txn, kind="amount_mismatch", ref_type="payment_attempt", ref_id=txn,
                diff_minor=book.e3_gross - gross, root_cause="e3_gross_mismatch",
                evidence_ref=f"book:{book.e3_gross};external:{gross}")
        elif book.e3_gross == 0 and (book.e4_net or book.e4_fee):
            add(txn, kind="missing_in_ledger", ref_type="payment_attempt", ref_id=txn,
                diff_minor=-(gross - (book.e4_net + book.e4_fee)),
                root_cause="e3_missing", evidence_ref="journal_events:2,3")

        settled = attempt["settled_minor"]
        if settled is not None:
            settled_micro = _micro(settled, facts.M08_UNIT_SCALE)
            fee_minor = attempt["settlement_fee_minor"] or 0
            fee_micro = _micro(fee_minor, facts.M08_UNIT_SCALE)
            if book.e4_net == 0 and book.e4_fee == 0:
                add(txn, kind="missing_in_ledger", ref_type="payment_attempt", ref_id=txn,
                    diff_minor=-settled_micro, root_cause="settlement_not_booked",
                    evidence_ref=f"settled:{settled_micro}")
            else:
                if book.e4_net != settled_micro:
                    add(txn, kind="amount_mismatch", ref_type="payment_attempt", ref_id=txn,
                        diff_minor=book.e4_net - settled_micro,
                        root_cause="settlement_amount_mismatch",
                        evidence_ref=f"book:{book.e4_net};external:{settled_micro}")
                tolerance = _psp_fee_tolerance(gross)
                if abs(book.e4_fee - fee_micro) > tolerance:
                    add(txn, kind="fee_diff", ref_type="payment_attempt", ref_id=txn,
                        diff_minor=book.e4_fee - fee_micro,
                        root_cause="fee_out_of_tolerance",
                        evidence_ref=f"book:{book.e4_fee};external:{fee_micro};"
                                     f"tolerance:{tolerance}")
        elif book.e4_net or book.e4_fee:
            add(txn, kind="missing_external", ref_type="payment_attempt", ref_id=txn,
                diff_minor=book.e4_net + book.e4_fee, root_cause="settlement_not_recorded",
                evidence_ref="journal_events:2,3")
        else:
            timing += 1

    settlement_metrics: dict[str, Any] = {
        "settlement_source": "provided" if settlement_provided else "absent",
        "settlement_rows": len(settlement),
    }
    if settlement_provided:
        settlement_metrics["settlement_sha256"] = settlement_fingerprint(settlement)
        by_txn: dict[str, SettlementRow] = {}
        duplicate_rows = 0
        for row in settlement:
            if row.provider_txn_id in by_txn:
                duplicate_rows += 1
                add(row.provider_txn_id, kind="duplicate", ref_type="psp_settlement",
                    ref_id=row.provider_txn_id, diff_minor=0,
                    root_cause="duplicate_settlement_row",
                    evidence_ref="settlement_sha256:"
                                 + settlement_metrics["settlement_sha256"][:16])
                continue
            by_txn[row.provider_txn_id] = row
        for txn in sorted(by_txn):
            row = by_txn[txn]
            attempt = attempts_by_txn.get(txn)
            if attempt is None:
                if txn in books:
                    continue        # 账本有、M08 尝试缺失：上面已按 missing_external 记过
                add(txn, kind="missing_in_ledger", ref_type="psp_settlement", ref_id=txn,
                    diff_minor=-_micro(row.settled_minor, facts.M08_UNIT_SCALE),
                    root_cause="settlement_without_attempt",
                    evidence_ref="settlement_sha256:"
                                 + settlement_metrics["settlement_sha256"][:16])
                continue
            if row.currency != "USD" or attempt["currency"] != row.currency:
                add(txn, kind="unidentified", ref_type="psp_settlement", ref_id=txn,
                    diff_minor=0, root_cause="currency_mismatch",
                    evidence_ref=f"attempt:{attempt['currency']};settlement:{row.currency}")
                continue
            if attempt["settled_minor"] is None:
                add(txn, kind="missing_in_ledger", ref_type="psp_settlement", ref_id=txn,
                    diff_minor=-_micro(row.settled_minor, facts.M08_UNIT_SCALE),
                    root_cause="settlement_not_recorded",
                    evidence_ref="attempt.settled_minor IS NULL")
                continue
            attempt_settled = _micro(attempt["settled_minor"], facts.M08_UNIT_SCALE)
            row_settled = _micro(row.settled_minor, facts.M08_UNIT_SCALE)
            if attempt_settled != row_settled:
                add(txn, kind="amount_mismatch", ref_type="psp_settlement", ref_id=txn,
                    diff_minor=attempt_settled - row_settled,
                    root_cause="settlement_file_mismatch",
                    evidence_ref=f"attempt:{attempt_settled};file:{row_settled}")
            gross = _micro(attempt["amount_minor"], facts.M08_UNIT_SCALE)
            attempt_fee = _micro(attempt["settlement_fee_minor"] or 0, facts.M08_UNIT_SCALE)
            row_fee = _micro(row.fee_minor, facts.M08_UNIT_SCALE)
            tolerance = _psp_fee_tolerance(gross)
            if abs(attempt_fee - row_fee) > tolerance:
                add(txn, kind="fee_diff", ref_type="psp_settlement", ref_id=txn,
                    diff_minor=attempt_fee - row_fee,
                    root_cause="settlement_fee_out_of_tolerance",
                    evidence_ref=f"attempt:{attempt_fee};file:{row_fee};"
                                 f"tolerance:{tolerance}")
        # 结算文件缺行：超过 T+3 才开差异，窗口内只记 timing（§6.1 / §7）
        for txn, attempt in attempts_by_txn.items():
            if attempt["settled_minor"] is None or txn in by_txn:
                continue
            age = moment - clock.as_utc(attempt["created_at"])
            if age > _PSP_WINDOW:
                add(txn, kind="missing_external", ref_type="payment_attempt", ref_id=txn,
                    diff_minor=_micro(attempt["settled_minor"], facts.M08_UNIT_SCALE),
                    root_cause="settlement_file_missing",
                    evidence_ref="settlement_sha256:"
                                 + settlement_metrics["settlement_sha256"][:16])
            else:
                timing += 1
        settlement_metrics["settlement_duplicate_rows"] = duplicate_rows

    obs.matched_count = sum(
        1 for txn in keys
        if txn not in bad_keys and txn in attempts_by_txn
        and attempts_by_txn[txn]["status"] == "succeeded"
        and txn in books and not books[txn].empty)
    obs.metrics = {
        "source": "payment_attempts↔journal:E3/E4",
        "attempt_rows": len(attempts),
        "journal_rows": journal_lines,
        "attempts_without_txn": skipped_no_txn,
        "timing_pending": timing,
        "matched_txns": obs.matched_count,
        "exception_txns": len(bad_keys),
        "book_total_micro": obs.book_minor,
        "external_total_micro": obs.external_minor,
        **settlement_metrics,
    }
    return obs


def _psp_fee_tolerance(gross_micro: int) -> int:
    """PSP 手续费容差 = max(±0.10% × 毛额, ±0.01 USD)（micro）。"""
    return max(abs(gross_micro) * facts.PSP_FEE_TOLERANCE_BPS // 10_000,
               facts.PSP_FEE_TOLERANCE_MIN_MINOR)


# ═════════════════════════════════════════════════════════════════════ scope=chain
_WALLET_SQL = """
SELECT w.wallet_id, w.chain_id, w.address, w.pool_role, w.fund_class, w.status,
       w.switch_state, w.balance_minor,
       p.fund_class AS pool_fund_class, p.role AS pool_role
  FROM wallet w
  LEFT JOIN wallet_pool p ON p.pool_id = w.pool_id
 ORDER BY w.chain_id, w.wallet_id
"""

_CHAIN_BOOK_SQL = """
SELECT j.journal_id::text AS journal_id, j.event_type, j.source_type, j.source_id,
       j.ts, l.line_no, l.wallet_id, l.coa_code, l.dc, l.amount_minor, l.unit_scale
  FROM journal_line l
  JOIN journal_entry j ON j.journal_id = l.journal_id
 WHERE j.status = 'posted' AND j.unit_type = 'USD'
   AND j.ts <= %s AND l.coa_code IN ('1101', '1102')
 ORDER BY l.wallet_id NULLS FIRST, j.ts, j.journal_id, l.line_no
"""

_CHAIN_TX_SQL = """
SELECT t.to_address, count(*) AS rows,
       count(*) FILTER (WHERE EXISTS (
         SELECT 1 FROM chain_tx_event e
          WHERE e.chain_tx_id = t.chain_tx_id AND e.event = 'confirmed')) AS confirmed,
       COALESCE(sum(t.amount_minor), 0) AS amount_minor
  FROM chain_tx t
 WHERE t.detected_at >= %s AND t.detected_at < %s AND t.detected_at <= %s
 GROUP BY t.to_address
 ORDER BY t.to_address
"""


def _chain_wallets(conn: psycopg.Connection) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(_WALLET_SQL)
        rows = cur.fetchall()
    wallets = []
    for row in rows:
        fund_class = (row[4] or row[8] or "").lower()
        role = row[3] or row[9]
        wallets.append({
            "wallet_id": row[0], "chain_id": row[1], "address": row[2], "role": role,
            "fund_class": fund_class, "status": row[5], "switch_state": row[6],
            "balance_minor": int(row[7]),
        })
    return wallets


def _chain_book(conn: psycopg.Connection, spec: models.RunSpec
                ) -> tuple[dict[str, int], list[dict]]:
    """wallet_id → 净额（借 − 贷，micro）与「缺 wallet_id 的资产行」清单。"""
    with conn.cursor() as cur:
        cur.execute(_CHAIN_BOOK_SQL, (spec.cutoff_at,))
        rows = cur.fetchall()
    book: dict[str, int] = {}
    null_ref: list[dict[str, Any]] = []
    for row in rows:
        amount = _micro(int(row[9]), int(row[10]))
        if row[6] is None:
            null_ref.append({"journal_id": row[0], "line_no": int(row[5]),
                             "event_type": row[1], "source_type": row[2],
                             "source_id": row[3], "coa_code": row[7], "dc": row[8],
                             "amount_minor": amount, "ts": row[4]})
            continue
        book[row[6]] = book.get(row[6], 0) + (amount if row[8] == "D" else -amount)
    return book, null_ref


def _chain_tx_metrics(conn: psycopg.Connection, spec: models.RunSpec
                      ) -> tuple[dict[str, dict[str, Any]], int]:
    with conn.cursor() as cur:
        cur.execute(_CHAIN_TX_SQL, (spec.period_start, spec.period_end, spec.cutoff_at))
        rows = cur.fetchall()
        cur.execute("SELECT max(block_number) FROM chain_tx WHERE detected_at <= %s",
                    (spec.cutoff_at,))
        latest_block = cur.fetchone()[0]
    by_address = {
        row[0]: {"tx_rows": int(row[1]), "confirmed": int(row[2]), "amount_minor": int(row[3])}
        for row in rows
    }
    return by_address, -1 if latest_block is None else int(latest_block)


def observe_chain(conn: psycopg.Connection, spec: models.RunSpec, *,
                  deps: EngineDeps, now: datetime) -> Observation:
    """scope=chain：wallet.balance_minor ↔ journal_line(1101/1102, wallet_id) 累计净额。"""
    moment = clock.as_utc(now)
    wallets = _chain_wallets(conn)
    if spec.subject_ref:
        wallets = [wallet for wallet in wallets if wallet["chain_id"] == spec.subject_ref]
    customer = {wallet["wallet_id"]: wallet for wallet in wallets
                if wallet["fund_class"] == "customer"}
    excluded_platform = sum(1 for wallet in wallets if wallet["fund_class"] != "customer")
    book_all, null_ref = _chain_book(conn, spec)
    if spec.subject_ref:
        book = {key: value for key, value in book_all.items() if key in customer}
    else:
        book = dict(book_all)
    chain_tx, latest_block = _chain_tx_metrics(conn, spec)

    obs = Observation()
    bad_keys: set[str] = set()

    def add(key: str, **kwargs: Any) -> None:
        bad_keys.add(key)
        _add(obs, scope=spec.scope, deps=deps, moment=moment, **kwargs)

    # 结构性 P0：1101/1102 资产行没有 wallet_id → 无法归属到地址
    null_lines = len(null_ref) if not spec.subject_ref else 0
    for line in (null_ref if not spec.subject_ref else ()):
        diff = line["amount_minor"] if line["dc"] == "D" else -line["amount_minor"]
        add(f"journal:{line['journal_id']}:{line['line_no']}",
            kind="missing_wallet_ref", ref_type="journal_line",
            ref_id=f"{line['journal_id']}:{line['line_no']}", diff_minor=diff,
            root_cause="wallet_id_missing",
            evidence_ref=f"{line['event_type']}/{line['source_type']}:{line['source_id']};"
                         f"coa:{line['coa_code']}")

    keys = sorted(set(customer) | set(book))
    for wallet_id in keys:
        wallet = customer.get(wallet_id)
        book_value = int(book.get(wallet_id, 0))
        external = _micro(wallet["balance_minor"], facts.M08_UNIT_SCALE) if wallet else 0
        obs.book_minor += book_value
        obs.external_minor += external
        if book_value == external:
            obs.matched_count += 1
            continue
        if wallet is None:
            root_cause = "wallet_unknown_in_m08"
            evidence = "wallet.not_found"
        elif book_value == 0:
            root_cause = "balance_not_booked"
            evidence = f"chain:{wallet['chain_id']};balance_src:M08"
        elif external == 0:
            root_cause = "external_balance_zero"
            evidence = f"chain:{wallet['chain_id']};balance_src:M08"
        else:
            root_cause = "address_balance_mismatch"
            evidence = f"chain:{wallet['chain_id']};balance_src:M08"
        tx = chain_tx.get(wallet["address"]) if wallet else None
        if tx:
            evidence += f";chain_tx_rows:{tx['tx_rows']};chain_tx_confirmed:{tx['confirmed']}"
        add(wallet_id, kind="chain_balance_mismatch", ref_type="wallet", ref_id=wallet_id,
            diff_minor=book_value - external, root_cause=root_cause, evidence_ref=evidence)

    obs.metrics = {
        "source": "wallet.balance_minor↔journal_line(1101,1102)",
        "balance_source": "M08 wallet.balance_minor（当前快照；M08 无余额历史表）",
        "book_scope": "journal_line 累计到 cutoff（借 − 贷，含历史）",
        "wallets_checked": len(customer),
        "wallets_excluded_platform": excluded_platform,
        "wallets_without_journal": sum(1 for wid in customer if wid not in book),
        "journal_wallets_unknown": sum(1 for wid in book if wid not in customer),
        "null_wallet_lines": null_lines,
        "chain_tx_rows": sum(item["tx_rows"] for item in chain_tx.values()),
        "chain_tx_confirmed": sum(item["confirmed"] for item in chain_tx.values()),
        "chain_tx_amount_micro": sum(item["amount_minor"] for item in chain_tx.values()),
        "block_height_latest": latest_block,
        "book_total_micro": obs.book_minor,
        "external_total_micro": obs.external_minor,
        "chains": sorted({wallet["chain_id"] for wallet in customer.values()}),
    }
    return obs


# ═════════════════════════════════════════════════════════════════════ scope=bank
_PAYOUT_ITEMS_SQL = """
SELECT i.item_id::text AS item_id, i.batch_id::text AS batch_id, b.batch_no,
       b.status AS batch_status, i.payee_account_id, i.payee_address,
       i.gross_minor, i.fee_minor, i.net_minor, i.status AS item_status,
       i.chain_tx_id, i.journal_id::text AS journal_id, i.created_at
  FROM payout_items i
  JOIN payout_batches b ON b.batch_id = i.batch_id
 WHERE i.created_at >= %s AND i.created_at < %s AND i.created_at <= %s
 ORDER BY i.batch_id, i.item_id
"""

_PAYOUT_BATCHES_SQL = """
SELECT b.batch_id::text AS batch_id, b.batch_no, b.status, b.total_gross_minor,
       b.total_fee_minor, b.total_net_minor, b.item_count,
       COALESCE(sum(i.net_minor), 0) AS items_net,
       COALESCE(sum(i.gross_minor), 0) AS items_gross,
       count(i.item_id) AS items_count
  FROM payout_batches b
  LEFT JOIN payout_items i ON i.batch_id = b.batch_id
 WHERE b.created_at >= %s AND b.created_at < %s AND b.created_at <= %s
 GROUP BY b.batch_id
 ORDER BY b.batch_id
"""

_REFUNDS_SQL = """
SELECT refund_request_id::text AS refund_request_id, refund_no, account_id, order_no,
       payment_ref, amount_minor, currency, status, journal_id::text AS journal_id,
       created_at
  FROM refund_requests
 WHERE created_at >= %s AND created_at < %s AND created_at <= %s
 ORDER BY refund_request_id
"""

_BANK_JOURNAL_SQL = """
SELECT j.journal_id::text AS journal_id, j.event_type, j.source_type, j.source_id,
       j.event_seq, j.ts, l.line_no, l.coa_code, l.dc, l.amount_minor, l.unit_scale
  FROM journal_entry j
  JOIN journal_line l ON l.journal_id = j.journal_id
 WHERE j.status = 'posted' AND j.unit_type = 'USD'
   AND j.event_type IN ('E8', 'E11')
   AND j.ts >= %s AND j.ts < %s AND j.ts <= %s
 ORDER BY j.journal_id, l.line_no
"""

#: 出款批次「明细冻结」后的状态（总账必须 = 明细之和，§19.8.3）
_BATCH_FROZEN = ("checked", "signed", "broadcast", "settled", "partial")


@dataclass
class _JournalFact:
    journal_id: str
    event_type: str
    source_type: str
    source_id: str
    event_seq: int
    ts: datetime
    c1102: int = 0       # E8：付给收款方 / 客户资金温钱包贷方
    c2203: int = 0       # E11：受理（应付退款贷方）
    d2203: int = 0       # E11：打款（应付退款借方）

    @property
    def refund_out(self) -> int:
        return max(self.c2203, self.d2203)


def _bank_journals(conn: psycopg.Connection, spec: models.RunSpec
                   ) -> tuple[dict[str, _JournalFact], int]:
    with conn.cursor() as cur:
        cur.execute(_BANK_JOURNAL_SQL, (spec.period_start, spec.period_end, spec.cutoff_at))
        rows = cur.fetchall()
    facts_by_id: dict[str, _JournalFact] = {}
    for row in rows:
        journal_id = row[0]
        fact = facts_by_id.get(journal_id)
        if fact is None:
            fact = _JournalFact(journal_id=journal_id, event_type=row[1], source_type=row[2],
                                source_id=row[3], event_seq=int(row[4]), ts=row[5])
            facts_by_id[journal_id] = fact
        amount = _micro(int(row[9]), int(row[10]))
        coa, dc = row[7], row[8]
        if coa == "1102" and dc == "C":
            fact.c1102 += amount
        elif coa == "2203" and dc == "C":
            fact.c2203 += amount
        elif coa == "2203" and dc == "D":
            fact.d2203 += amount
    return facts_by_id, len(rows)


def _bank_facts(conn: psycopg.Connection, spec: models.RunSpec
                ) -> tuple[list[dict], list[dict], list[dict]]:
    with conn.cursor() as cur:
        cur.execute(_PAYOUT_ITEMS_SQL, (spec.period_start, spec.period_end, spec.cutoff_at))
        item_rows = cur.fetchall()
        cur.execute(_PAYOUT_BATCHES_SQL, (spec.period_start, spec.period_end, spec.cutoff_at))
        batch_rows = cur.fetchall()
        cur.execute(_REFUNDS_SQL, (spec.period_start, spec.period_end, spec.cutoff_at))
        refund_rows = cur.fetchall()
    items = [
        {"item_id": row[0], "batch_id": row[1], "batch_no": row[2], "batch_status": row[3],
         "payee_account_id": row[4], "payee_address": row[5], "gross_minor": int(row[6]),
         "fee_minor": int(row[7]), "net_minor": int(row[8]), "item_status": row[9],
         "chain_tx_id": row[10], "journal_id": row[11], "created_at": row[12]}
        for row in item_rows
    ]
    batches = [
        {"batch_id": row[0], "batch_no": row[1], "status": row[2],
         "total_gross_minor": int(row[3]), "total_fee_minor": int(row[4]),
         "total_net_minor": int(row[5]), "item_count": int(row[6]),
         "items_net": int(row[7]), "items_gross": int(row[8]), "items_count": int(row[9])}
        for row in batch_rows
    ]
    refunds = [
        {"refund_request_id": row[0], "refund_no": row[1], "account_id": row[2],
         "order_no": row[3], "payment_ref": row[4], "amount_minor": int(row[5]),
         "currency": row[6], "status": row[7], "journal_id": row[8], "created_at": row[9]}
        for row in refund_rows
    ]
    return items, batches, refunds


def _pick_payout_journal(item: dict[str, Any], facts_by_id: dict[str, _JournalFact],
                         index: dict[str, list[_JournalFact]]
                         ) -> tuple[_JournalFact | None, bool]:
    """选出「付给收款方」的 E8 凭证：优先 M08 journal_id，其次 source_id=item_id。

    多个候选时取 1102 贷方金额最大的那张（E8 2b 打款凭证）；出现多张有效打款凭证
    视为重复入账（返回 duplicate=True）。
    """
    seen: dict[str, _JournalFact] = {}
    journal_id = item.get("journal_id")
    if journal_id and journal_id in facts_by_id:
        seen[journal_id] = facts_by_id[journal_id]
    for fact in index.get(item["item_id"], ()):
        seen[fact.journal_id] = fact
    outflows = [fact for fact in seen.values() if fact.c1102 > 0]
    if not outflows:
        return None, False
    chosen = max(outflows, key=lambda fact: (fact.c1102, fact.journal_id))
    return chosen, len(outflows) > 1


def _pick_refund_journal(refund: dict[str, Any], facts_by_id: dict[str, _JournalFact],
                         index: dict[str, list[_JournalFact]]
                         ) -> tuple[_JournalFact | None, bool]:
    seen: dict[str, _JournalFact] = {}
    journal_id = refund.get("journal_id")
    if journal_id and journal_id in facts_by_id:
        seen[journal_id] = facts_by_id[journal_id]
    for fact in index.get(refund["refund_request_id"], ()):
        seen[fact.journal_id] = fact
    paid = [fact for fact in seen.values() if fact.d2203 > 0]
    amounts = [fact for fact in seen.values() if fact.refund_out > 0]
    if not amounts:
        return None, False
    chosen = max(amounts, key=lambda fact: (fact.refund_out, fact.journal_id))
    return chosen, len(paid) > 1


def _pick_statement(keys: Iterable[str | None], rows_by_txid: Mapping[str, BankRow],
                    consumed: set[str]) -> tuple[str | None, BankRow | None]:
    for key in keys:
        if key and key in rows_by_txid and key not in consumed:
            return key, rows_by_txid[key]
    return None, None


def observe_bank(conn: psycopg.Connection, spec: models.RunSpec, *,
                 deps: EngineDeps, now: datetime) -> Observation:
    """scope=bank：payout / refund ↔ E8/E11 ↔ 银行流水夹具（金额容差 0）。"""
    moment = clock.as_utc(now)
    items, batches, refunds = _bank_facts(conn, spec)
    facts_by_id, journal_lines = _bank_journals(conn, spec)
    statement_provided = deps.bank_statement is not None
    statement = parse_bank_statement(deps.bank_statement) if statement_provided else []

    payout_index: dict[str, list[_JournalFact]] = {}
    refund_index: dict[str, list[_JournalFact]] = {}
    for fact in facts_by_id.values():
        if fact.event_type == "E8" and fact.source_type == "payout_item" and fact.source_id:
            payout_index.setdefault(fact.source_id, []).append(fact)
        elif fact.event_type == "E11" and fact.source_type == "refund" and fact.source_id:
            refund_index.setdefault(fact.source_id, []).append(fact)

    obs = Observation()
    bad_keys: set[str] = set()
    mapped_journals: set[str] = set()
    consumed: set[str] = set()
    metrics: dict[str, Any] = {
        "source": "payout_items/refund_requests↔journal:E8/E11↔bank_statement",
        "bank_statement_source": "provided" if statement_provided else "absent",
        "payout_items": len(items),
        "refunds": len(refunds),
        "journal_rows": journal_lines,
        "bank_rows": len(statement),
        "payout_duplicates": 0,
        "refund_duplicates": 0,
        "bank_duplicate_rows": 0,
        "currency_skipped": 0,
        "batch_checked": 0,
        "batch_inconsistent": 0,
    }

    def add(key: str, **kwargs: Any) -> None:
        bad_keys.add(key)
        _add(obs, scope=spec.scope, deps=deps, moment=moment, **kwargs)

    # ── 银行流水：期间过滤 / 重复 txid / 币种 ──────────────────────────────
    rows_by_txid: dict[str, BankRow] = {}
    if statement_provided:
        metrics["bank_statement_sha256"] = bank_statement_fingerprint(statement)
        in_period = [row for row in statement
                     if spec.period_start <= row.posted_at < spec.period_end
                     and row.posted_at <= spec.cutoff_at]
        metrics["bank_rows_in_period"] = len(in_period)
        for row in in_period:
            if row.txid in rows_by_txid:
                metrics["bank_duplicate_rows"] += 1
                add(f"bank:{row.txid}", kind="duplicate", ref_type="bank_row",
                    ref_id=row.txid, diff_minor=0, root_cause="duplicate_bank_row",
                    evidence_ref="bank_statement_sha256:"
                                 + metrics["bank_statement_sha256"][:16])
                continue
            rows_by_txid[row.txid] = row
            if row.currency != "USD":
                metrics["currency_skipped"] += 1
                add(f"bank:{row.txid}", kind="unidentified", ref_type="bank_row",
                    ref_id=row.txid, diff_minor=0, root_cause="unsupported_currency",
                    evidence_ref=f"currency:{row.currency}")
                consumed.add(row.txid)
                continue
            obs.external_minor += _micro(row.amount_minor, facts.M08_UNIT_SCALE)

    # ── 出款明细 ↔ E8 ↔ 银行流水 ─────────────────────────────────────────
    for item in items:
        key = item["item_id"]
        journal, journal_duplicate = _pick_payout_journal(item, facts_by_id, payout_index)
        journal_amount = journal.c1102 if journal else None
        if journal is not None:
            mapped_journals.add(journal.journal_id)
        if journal_duplicate:
            metrics["payout_duplicates"] += 1
            add(key, kind="duplicate", ref_type="payout_item", ref_id=key, diff_minor=0,
                root_cause="duplicate_payout_journal",
                evidence_ref=f"batch:{item['batch_no']}")
        tx_key, bank_row = _pick_statement(
            (item["chain_tx_id"], key), rows_by_txid, consumed)
        if bank_row is not None:
            consumed.add(tx_key)  # type: ignore[arg-type]
        net = _micro(item["net_minor"], facts.M08_UNIT_SCALE)
        if journal_amount is not None:
            obs.book_minor += journal_amount
        status = item["item_status"]
        if status != "sent":
            if journal_amount:
                add(key, kind="missing_external", ref_type="payout_item", ref_id=key,
                    diff_minor=journal_amount, root_cause="payout_item_not_sent",
                    evidence_ref=f"status:{status};batch:{item['batch_no']}")
            elif bank_row is not None:
                add(key, kind="missing_in_ledger", ref_type="bank_row",
                    ref_id=bank_row.txid,
                    diff_minor=-_micro(bank_row.amount_minor, facts.M08_UNIT_SCALE),
                    root_cause="payout_item_not_sent",
                    evidence_ref=f"status:{status};batch:{item['batch_no']}")
            continue
        if journal is None:
            if bank_row is not None:
                diff = -_micro(bank_row.amount_minor, facts.M08_UNIT_SCALE)
                root_cause = "journal_missing"
                evidence = f"batch:{item['batch_no']};txid:{bank_row.txid}"
            else:
                diff = -net
                root_cause = "journal_and_bank_missing"
                evidence = f"batch:{item['batch_no']}"
            add(key, kind="missing_in_ledger", ref_type="payout_item", ref_id=key,
                diff_minor=diff, root_cause=root_cause, evidence_ref=evidence)
            continue
        if bank_row is None:
            add(key, kind="missing_external", ref_type="payout_item", ref_id=key,
                diff_minor=journal_amount, root_cause="bank_row_missing",
                evidence_ref=f"batch:{item['batch_no']};txid:{item['chain_tx_id'] or '-'}")
            continue
        bank_amount = _micro(bank_row.amount_minor, facts.M08_UNIT_SCALE)
        if journal_amount != bank_amount:
            add(key, kind="amount_mismatch", ref_type="payout_item", ref_id=key,
                diff_minor=journal_amount - bank_amount,
                root_cause=("overpaid" if bank_amount > journal_amount else "underpaid"),
                evidence_ref=f"journal:{journal_amount};bank:{bank_amount};"
                             f"txid:{bank_row.txid}")
            continue
        if journal_amount != net:
            add(key, kind="amount_mismatch", ref_type="payout_item", ref_id=key,
                diff_minor=journal_amount - net, root_cause="m08_vs_journal",
                evidence_ref=f"item:{net};journal:{journal_amount}")
            continue
        obs.matched_count += 1

    # ── 退款 ↔ E11 ↔ 银行流水 ────────────────────────────────────────────
    for refund in refunds:
        key = refund["refund_request_id"]
        journal, journal_duplicate = _pick_refund_journal(refund, facts_by_id, refund_index)
        journal_amount = journal.refund_out if journal else None
        if journal is not None:
            mapped_journals.add(journal.journal_id)
        if journal_duplicate:
            metrics["refund_duplicates"] += 1
            add(key, kind="duplicate", ref_type="refund", ref_id=key, diff_minor=0,
                root_cause="duplicate_refund_journal",
                evidence_ref=f"refund_no:{refund['refund_no']}")
        tx_key, bank_row = _pick_statement(
            (refund["refund_request_id"], refund["refund_no"], refund["payment_ref"],
             refund["order_no"]), rows_by_txid, consumed)
        if bank_row is not None:
            consumed.add(tx_key)  # type: ignore[arg-type]
        amount = _micro(refund["amount_minor"], facts.M08_UNIT_SCALE)
        if journal_amount is not None:
            obs.book_minor += journal_amount
        status = refund["status"]
        if status != "succeeded":
            if journal_amount:
                add(key, kind="missing_external", ref_type="refund", ref_id=key,
                    diff_minor=journal_amount, root_cause="refund_not_succeeded",
                    evidence_ref=f"status:{status};refund_no:{refund['refund_no']}")
            elif bank_row is not None:
                add(key, kind="missing_in_ledger", ref_type="bank_row",
                    ref_id=bank_row.txid,
                    diff_minor=-_micro(bank_row.amount_minor, facts.M08_UNIT_SCALE),
                    root_cause="refund_not_succeeded",
                    evidence_ref=f"status:{status};refund_no:{refund['refund_no']}")
            continue
        if journal is None:
            if bank_row is not None:
                diff = -_micro(bank_row.amount_minor, facts.M08_UNIT_SCALE)
                root_cause = "journal_missing"
                evidence = f"refund_no:{refund['refund_no']};txid:{bank_row.txid}"
            else:
                diff = -amount
                root_cause = "journal_and_bank_missing"
                evidence = f"refund_no:{refund['refund_no']}"
            add(key, kind="missing_in_ledger", ref_type="refund", ref_id=key,
                diff_minor=diff, root_cause=root_cause, evidence_ref=evidence)
            continue
        if bank_row is None:
            add(key, kind="missing_external", ref_type="refund", ref_id=key,
                diff_minor=journal_amount, root_cause="bank_row_missing",
                evidence_ref=f"refund_no:{refund['refund_no']};payment_ref:"
                             f"{refund['payment_ref']}")
            continue
        bank_amount = _micro(bank_row.amount_minor, facts.M08_UNIT_SCALE)
        if journal_amount != bank_amount:
            add(key, kind="amount_mismatch", ref_type="refund", ref_id=key,
                diff_minor=journal_amount - bank_amount,
                root_cause=("overpaid" if bank_amount > journal_amount else "underpaid"),
                evidence_ref=f"journal:{journal_amount};bank:{bank_amount};"
                             f"txid:{bank_row.txid}")
            continue
        if journal_amount != amount:
            add(key, kind="amount_mismatch", ref_type="refund", ref_id=key,
                diff_minor=journal_amount - amount, root_cause="m08_vs_journal",
                evidence_ref=f"refund:{amount};journal:{journal_amount}")
            continue
        obs.matched_count += 1

    # ── 银行流水里没有任何 M08 事实的流水（外部有、内部无） ─────────────────
    for txid in sorted(set(rows_by_txid) - consumed):
        row = rows_by_txid[txid]
        add(f"bank:{txid}", kind="missing_in_ledger", ref_type="bank_row", ref_id=txid,
            diff_minor=-_micro(row.amount_minor, facts.M08_UNIT_SCALE),
            root_cause="unmatched_bank_row",
            evidence_ref="bank_statement_sha256:"
                         + metrics.get("bank_statement_sha256", "")[:16])

    # ── 账本里有 E8/E11 出款分录、但 M08 没有对应事实（内部有、外部无） ──────
    unmapped = 0
    for fact in facts_by_id.values():
        if fact.journal_id in mapped_journals:
            continue
        amount = fact.c1102 if fact.event_type == "E8" else fact.refund_out
        if amount <= 0:
            continue
        unmapped += 1
        _add(obs, scope=spec.scope, deps=deps, moment=moment, kind="missing_external",
             ref_type="journal", ref_id=fact.journal_id, diff_minor=amount,
             root_cause="journal_without_m08_fact",
             evidence_ref=f"{fact.event_type}/{fact.source_type}:{fact.source_id}")
    metrics["journal_unmapped"] = unmapped

    # ── 批次总额 = 明细之和（明细冻结后） ────────────────────────────────
    for batch in batches:
        if batch["status"] not in _BATCH_FROZEN or batch["item_count"] <= 0:
            continue
        if batch["items_count"] != batch["item_count"]:
            continue
        metrics["batch_checked"] += 1
        expected = _micro(batch["items_net"], facts.M08_UNIT_SCALE)
        recorded = _micro(batch["total_net_minor"], facts.M08_UNIT_SCALE)
        if expected != recorded:
            metrics["batch_inconsistent"] += 1
            add(f"batch:{batch['batch_id']}", kind="amount_mismatch",
                ref_type="payout_batch", ref_id=batch["batch_no"],
                diff_minor=recorded - expected, root_cause="batch_totals_mismatch",
                evidence_ref=f"batch:{recorded};items:{expected}")

    obs.metrics = metrics
    return obs


def plan(conn: psycopg.Connection, spec: models.RunSpec, *, deps: EngineDeps,
         now: datetime) -> list[tuple[models.RunSpec, Observation]]:
    """按 scope 生成 (RunSpec, Observation)；只读，不写库。"""
    scoped = _scoped_spec(spec)
    if scoped.scope == "psp":
        return [(scoped, observe_psp(conn, scoped, deps=deps, now=now))]
    if scoped.scope == "chain":
        return [(scoped, observe_chain(conn, scoped, deps=deps, now=now))]
    if scoped.scope == "bank":
        return [(scoped, observe_bank(conn, scoped, deps=deps, now=now))]
    raise BadRequest(f"scope 必须是 {list(facts.SCOPES)} 之一", field="scope")
