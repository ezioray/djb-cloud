# SPDX-License-Identifier: AGPL-3.0-or-later
"""试算平衡与科目余额（只读，管理面用；M06 §4.1 / spec 1.2.1 TrialBalance · LedgerAccountPage）。

口径：
  · 一律从**分录**（journal_line）聚合，不读缓存表 —— 余额真值在分录里，缓存坏了不该污染报表；
  · `balance = Σ借 − Σ贷`（借方为正，与 T3 的 account_balances 同口径）；
  · 借贷平衡只在本 `unit_type` 内判定（INV-04）；COP 与 USD 不互转；
  · 未知科目不会出现在结果里（DB 白名单已在写入时拒绝，读路径再断言一次，INV-05）；
  · 尾差累积在 2901，单独给 `tail_diff`（§20.3 / INV-12），不混进普通科目。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .constants import (ALL_COA, COA_FUND_CLASS, COA_NAMES, DECIMAL_BASE, DEFAULT_PAGE_SIZE,
                        MAX_PAGE_SIZE, MINOR_UNIT_SCALE, UNIT_TYPES)
from .errors import InvalidUnitType

_TAIL_COA = "2901"           # 尾差科目（§20.2.3 / INV-12）
_DECIMALS = DECIMAL_BASE ** MINOR_UNIT_SCALE


def decimal_str(amount_minor: int) -> str:
    """整数最小单位 → 十进制字符串（不经过浮点；去掉无意义的尾零）。"""
    value = int(amount_minor)
    sign = "-" if value < 0 else ""
    whole, frac = divmod(abs(value), _DECIMALS)
    if not frac:
        return f"{sign}{whole}"
    return f"{sign}{whole}.{str(frac).rjust(MINOR_UNIT_SCALE, '0').rstrip('0')}"


def amount(minor: int, unit: str) -> dict[str, str]:
    """spec 的 Amount：{amount: 十进制字符串, unit}。"""
    return {"amount": decimal_str(minor), "unit": unit}


def _require_unit(unit_type: str) -> str:
    if unit_type not in UNIT_TYPES:
        raise InvalidUnitType(f"unit_type {unit_type!r} 不在 {UNIT_TYPES}（INV-04）")
    return unit_type


def _per_coa_totals(conn, unit_type: str, as_of: datetime | None) -> dict[str, dict[str, int]]:
    """按科目聚合：{coa: {"debit", "credit", "lines", "last_ts"}}（只统计本 unit_type）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT l.coa_code,
                      COALESCE(sum(l.amount_minor) FILTER (WHERE l.dc = 'D'), 0) AS debit,
                      COALESCE(sum(l.amount_minor) FILTER (WHERE l.dc = 'C'), 0) AS credit,
                      count(*) AS lines,
                      max(j.ts) AS last_ts
                 FROM journal_line l JOIN journal_entry j ON j.journal_id = l.journal_id
                WHERE j.unit_type = %s AND (%s::timestamptz IS NULL OR j.ts <= %s::timestamptz)
                GROUP BY 1""",
            (unit_type, as_of, as_of))
        rows = cur.fetchall()
    return {
        coa: {"debit": int(debit), "credit": int(credit), "lines": int(lines), "last_ts": last_ts}
        for coa, debit, credit, lines, last_ts in rows
    }


def trial_balance(conn, *, unit_type: str = "USD", as_of: datetime | None = None) -> dict[str, Any]:
    """试算平衡（spec TrialBalance）：42 科目逐行 + 合计 + 尾差 + balanced。"""
    unit_type = _require_unit(unit_type)
    as_of = as_of or datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)

    totals = _per_coa_totals(conn, unit_type, as_of)
    unknown = sorted(set(totals) - set(ALL_COA))
    if unknown:                                    # 理论上不可能：写入侧白名单已拦
        raise InvalidUnitType(f"分录里出现白名单外的科目：{unknown}（INV-05）")

    lines: list[dict[str, Any]] = []
    debit_total = credit_total = 0
    for coa in ALL_COA:
        row = totals.get(coa, {"debit": 0, "credit": 0})
        debit, credit = int(row["debit"]), int(row["credit"])
        debit_total += debit
        credit_total += credit
        lines.append({
            "coa_code": coa,
            "name": COA_NAMES[coa],
            "fund_class": COA_FUND_CLASS[coa],
            "debit": amount(debit, unit_type),
            "credit": amount(credit, unit_type),
            "balance": amount(debit - credit, unit_type),
        })

    with conn.cursor() as cur:
        cur.execute(
            """SELECT count(*) FROM journal_entry
                WHERE unit_type = %s AND ts <= %s::timestamptz""", (unit_type, as_of))
        entry_count = int(cur.fetchone()[0])

    tail = totals.get(_TAIL_COA, {"debit": 0, "credit": 0})
    return {
        "as_of": as_of.astimezone(timezone.utc).isoformat(),
        "unit_type": unit_type,
        "balanced": debit_total == credit_total,
        "totals": {"debit": amount(debit_total, unit_type),
                   "credit": amount(credit_total, unit_type)},
        "tail_diff": amount(int(tail["debit"]) - int(tail["credit"]), unit_type),
        "entry_count": entry_count,
        "accounts": lines,
    }


def accounts_overview(conn, *, unit_type: str = "USD", fund_class: str | None = None,
                      cursor: str | None = None,
                      limit: int = DEFAULT_PAGE_SIZE) -> dict[str, Any]:
    """42 科目 + 派生余额（spec LedgerAccountPage）：按 coa_code 字典序游标分页。"""
    unit_type = _require_unit(unit_type)
    if fund_class is not None and fund_class not in ("CLIENT", "PLATFORM", "FEE"):
        raise InvalidUnitType(f"fund_class {fund_class!r} 不是 CLIENT/PLATFORM/FEE")
    limit = max(1, min(int(limit), MAX_PAGE_SIZE))

    totals = _per_coa_totals(conn, unit_type, None)
    codes = [coa for coa in ALL_COA
             if fund_class is None or COA_FUND_CLASS[coa] == fund_class]
    if cursor:
        codes = [coa for coa in codes if coa > cursor]
    page_codes = codes[:limit]
    has_more = len(codes) > len(page_codes)

    data = []
    for coa in page_codes:
        row = totals.get(coa, {"debit": 0, "credit": 0, "last_ts": None})
        item = {
            "coa_code": coa,
            "name": COA_NAMES[coa],
            "unit_type": unit_type,
            "fund_class": COA_FUND_CLASS[coa],
            "balance": amount(int(row["debit"]) - int(row["credit"]), unit_type),
        }
        if row.get("last_ts") is not None:
            item["updated_at"] = row["last_ts"].astimezone(timezone.utc).isoformat()
        data.append(item)

    return {
        "data": data,
        "page": {"cursor": cursor or "", "has_more": has_more,
                 "next_cursor": page_codes[-1] if has_more and page_codes else None},
    }
