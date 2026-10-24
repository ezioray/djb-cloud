# SPDX-License-Identifier: AGPL-3.0-or-later
"""M06 只读适配层（试算平衡 / 科目余额漂移）。

为什么在本模块里再写一条 SQL：M06 的 ``app.ledger.trial.trial_balance`` 出口把金额转成
**十进制字符串**（spec ``Amount``），而 M09 的对账差一律用**整数最小单位**（INV-08），
来回解析十进制字符串容易踩精度坑。因此这里用与 M06 **同一算式**（同一张表、同一条
``Σ借 − Σ贷``、同一个 as-of 口径）直接取整数，并在 ``tests/recon/test_m06_adapter.py``
里与 M06 的公开 API 逐单位对拍（口径漂移立刻红）。

边界：**只读**。不写 journal_entry / journal_line / account_balances，不建外键。

另有 scope=daily_close 的一处口径限制（已在证据「遗留」登记）：
``account_balances`` 是版本化派生缓存，这里按 ``created_at <= cutoff`` 取「截止时刻的最新版本」，
与分录侧 ``j.ts <= cutoff`` 对齐；若 M06 将来引入补记（ts 早于 created_at 的迟到分录），
两者需要一起改成同一口径。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import psycopg

__all__ = ["trial_totals", "balance_drift_as_of", "unit_types_as_of"]


def unit_types_as_of(conn: psycopg.Connection, as_of: datetime) -> list[str]:
    """截止时刻出现过分录的单位（未出现过的单位不生成 run，避免空批次）。"""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT DISTINCT unit_type FROM journal_entry WHERE ts <= %s ORDER BY unit_type",
            (as_of,))
        return [row[0] for row in cur.fetchall()]


def trial_totals(conn: psycopg.Connection, *, unit_type: str, as_of: datetime) -> dict[str, Any]:
    """试算平衡的整数口径：``Σ借`` / ``Σ贷`` / 行数 / 凭证数（与 M06 同算式）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT COALESCE(sum(l.amount_minor) FILTER (WHERE l.dc = 'D'), 0) AS debit,
                      COALESCE(sum(l.amount_minor) FILTER (WHERE l.dc = 'C'), 0) AS credit,
                      count(*) AS lines
                 FROM journal_line l JOIN journal_entry j ON j.journal_id = l.journal_id
                WHERE j.unit_type = %s AND j.ts <= %s""",
            (unit_type, as_of))
        debit, credit, lines = cur.fetchone()
        cur.execute(
            """SELECT count(*) FROM journal_entry WHERE unit_type = %s AND ts <= %s""",
            (unit_type, as_of))
        entries = int(cur.fetchone()[0])
    debit, credit = int(debit), int(credit)
    return {
        "unit_type": unit_type,
        "as_of": as_of,
        "debit_minor": debit,
        "credit_minor": credit,
        "diff_minor": debit - credit,
        "balanced": debit == credit,
        "line_count": int(lines),
        "entry_count": entries,
    }


def balance_drift_as_of(conn: psycopg.Connection, *, unit_type: str,
                        as_of: datetime) -> dict[str, Any]:
    """INV-10 的 as-of 版本：分录重建值 vs ``account_balances`` 截止时刻最新版本。

    返回 ``{"derived_keys", "stored_keys", "missing_in_store", "missing_in_ledger",
    "mismatched", "diff"}``；``diff`` 是问题键数（不是金额），金额级差另见 ``amount_gap_minor``。
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT l.account_id,
                      CASE WHEN l.coa_code = ANY(%s) THEN 'LOCKED' ELSE 'AVAILABLE' END AS sub,
                      sum(CASE WHEN l.dc = 'D' THEN l.amount_minor ELSE -l.amount_minor END) AS net
                 FROM journal_line l JOIN journal_entry j ON j.journal_id = l.journal_id
                WHERE j.unit_type = %s AND j.ts <= %s
                GROUP BY 1, 2""",
            (list(_LOCKED_COA), unit_type, as_of))
        derived = {(row[0], row[1]): int(row[2]) for row in cur.fetchall()}

        cur.execute(
            """SELECT DISTINCT ON (account_id, sub_account)
                      account_id, sub_account, version, balance_minor
                 FROM account_balances
                WHERE unit_type = %s AND created_at <= %s
                ORDER BY account_id, sub_account, version DESC""",
            (unit_type, as_of))
        stored = {(row[0], row[1]): {"version": int(row[2]), "balance_minor": int(row[3])}
                  for row in cur.fetchall()}

    missing_in_store = sorted(set(derived) - set(stored))
    missing_in_ledger = sorted(set(stored) - set(derived))
    mismatched = sorted((key for key in set(derived) & set(stored)
                         if derived[key] != stored[key]["balance_minor"]))
    gap = sum(abs(derived[key] - stored[key]["balance_minor"]) for key in mismatched)
    return {
        "unit_type": unit_type,
        "as_of": as_of,
        "derived_keys": len(derived),
        "stored_keys": len(stored),
        "missing_in_store": missing_in_store,
        "missing_in_ledger": missing_in_ledger,
        "mismatched": mismatched,
        "diff": len(missing_in_store) + len(missing_in_ledger) + len(mismatched),
        "amount_gap_minor": int(gap),
    }


#: 与 M06 ``ledger.constants.SUB_ACCOUNT_BY_COA`` 对齐（科目 2102 记 LOCKED，其余 AVAILABLE）。
#: 硬编码一份是为了「不 import M06 代码也能跑纯 SQL」；tests/recon 里有一条断言把它钉住。
_LOCKED_COA = ("2102",)
