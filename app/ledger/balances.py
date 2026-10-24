# SPDX-License-Identifier: AGPL-3.0-or-later
"""余额派生：``account_balances`` 版本化只追加（INV-10 / CR-L3 / M06 §6 事务边界）。

口径（与 602 迁移、T1 注释一致）::

    键 = (account_id, unit_type, sub_account)
    version  从 1 起，每次写入 = 该键的「上一版本 + 1」（跳号/回退由 602 触发器拒绝）
    balance_minor = Σ借 − Σ贷（借方为正；贷方科目因此为负值，展示正常方向余额由读方取反）
    sub_account：2102（锁定服务预付款）→ LOCKED，其余 → AVAILABLE（§20.2.7）

三条纪律：
  1. **只 INSERT**：UPDATE/DELETE 会被 602 的触发器拒绝，历史版本永远可回溯；
  2. **同事务持锁**：写余额前抢与账本追加同一把 ``pg_advisory_xact_lock``，
     与凭证写入同一事务 → 并发下版本连续、不跳版、不丢更新；
  3. **幂等**：某凭证已经写过余额（``account_balances.journal_id`` 命中）就不再写第二次，
     重复调用 ``apply_journal`` 不会重复累加。

余额真值永远在分录里：``derive_balances`` 随时可从 journal_line 全量重建，
``balance_drift`` 把「重建值」与「最新版本」逐键比对（INV-10 的判定入口）。
"""
from __future__ import annotations

from typing import Iterable, Sequence

from .constants import (
    DEFAULT_SUB_ACCOUNT,
    LEDGER_APPEND_LOCK_ID,
    NEGATIVE_FORBIDDEN_COA,
    SUB_ACCOUNT_BY_COA,
)

BalanceKey = tuple[str, str, str]


def sub_account_for(coa_code: str) -> str:
    """科目 → 子账户（§20.2.7）。锁定类科目落 LOCKED，其余落 AVAILABLE。"""
    return SUB_ACCOUNT_BY_COA.get(coa_code, DEFAULT_SUB_ACCOUNT)


def _acquire_append_lock(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (LEDGER_APPEND_LOCK_ID,))


def already_applied(conn, journal_id: str) -> bool:
    """该凭证是否已经写过余额（幂等判据）。"""
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM account_balances WHERE journal_id = %s LIMIT 1", (journal_id,))
        return cur.fetchone() is not None


def deltas_for_journal(conn, journal_id: str) -> dict[BalanceKey, int]:
    """把一张凭证的行折叠成「(account, unit, sub) → 净额变化」，借方为正。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT j.unit_type, l.account_id, l.coa_code, l.dc, l.amount_minor
                 FROM journal_line l JOIN journal_entry j ON j.journal_id = l.journal_id
                WHERE l.journal_id = %s""", (journal_id,))
        rows = cur.fetchall()
    deltas: dict[BalanceKey, int] = {}
    for unit_type, account_id, coa_code, dc, amount_minor in rows:
        key = (account_id, unit_type, sub_account_for(coa_code))
        deltas[key] = deltas.get(key, 0) + (amount_minor if dc == "D" else -amount_minor)
    return deltas


def apply_journal(conn, journal_id: str) -> list[dict]:
    """把一张凭证的净额写进 account_balances（每键 version+1）。返回写入的版本行。

    必须在记账的同一个事务里调用（§6：凭证 + 行 + 分录 + 余额 + outbox 同事务）。
    """
    _acquire_append_lock(conn)
    if already_applied(conn, journal_id):
        return []

    deltas = deltas_for_journal(conn, journal_id)
    written: list[dict] = []
    with conn.cursor() as cur:
        for (account_id, unit_type, sub_account), delta in sorted(deltas.items()):
            cur.execute(
                """SELECT version, balance_minor FROM account_balances_latest
                    WHERE account_id = %s AND unit_type = %s AND sub_account = %s""",
                (account_id, unit_type, sub_account))
            row = cur.fetchone()
            if row is None:
                version, balance = 1, delta
            else:
                version, balance = int(row[0]) + 1, int(row[1]) + delta
            cur.execute(
                """INSERT INTO account_balances
                     (account_id, unit_type, sub_account, version, balance_minor, journal_id)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                (account_id, unit_type, sub_account, version, balance, journal_id))
            written.append({"account_id": account_id, "unit_type": unit_type,
                            "sub_account": sub_account, "version": version,
                            "balance_minor": balance, "delta_minor": delta,
                            "journal_id": journal_id})
    return written


def derive_balances(conn, *, unit_type: str | None = None) -> dict[BalanceKey, int]:
    """从分录全量重建余额（INV-10）：(account, unit, sub) → Σ借 − Σ贷。"""
    sql = """
        SELECT j.unit_type, l.account_id, l.coa_code, l.dc, l.amount_minor
          FROM journal_line l JOIN journal_entry j ON j.journal_id = l.journal_id
         {where}"""
    where = "WHERE j.unit_type = %s" if unit_type else ""
    with conn.cursor() as cur:
        cur.execute(sql.format(where=where), (unit_type,) if unit_type else ())
        rows = cur.fetchall()
    derived: dict[BalanceKey, int] = {}
    for row_unit, account_id, coa_code, dc, amount_minor in rows:
        key = (account_id, row_unit, sub_account_for(coa_code))
        derived[key] = derived.get(key, 0) + (amount_minor if dc == "D" else -amount_minor)
    return derived


def latest_balances(conn) -> dict[BalanceKey, dict]:
    """读 account_balances_latest（增量写入后的最新版本）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT account_id, unit_type, sub_account, version, balance_minor, journal_id
                 FROM account_balances_latest""")
        return {
            (account_id, unit_type, sub_account):
                {"version": int(version), "balance_minor": int(balance_minor),
                 "journal_id": None if journal_id is None else str(journal_id)}
            for account_id, unit_type, sub_account, version, balance_minor, journal_id in cur.fetchall()
        }


def balance_drift(conn) -> dict:
    """INV-10：全量重建值 vs 最新版本逐键比对，返回差异（必须为 0）。"""
    derived = derive_balances(conn)
    stored = latest_balances(conn)
    missing_in_store = sorted(set(derived) - set(stored))
    missing_in_ledger = sorted(set(stored) - set(derived))
    mismatched = sorted(
        key for key in set(derived) & set(stored)
        if derived[key] != stored[key]["balance_minor"])
    return {
        "derived_keys": len(derived),
        "stored_keys": len(stored),
        "missing_in_store": missing_in_store,
        "missing_in_ledger": missing_in_ledger,
        "mismatched": mismatched,
        "diff": len(missing_in_store) + len(missing_in_ledger) + len(mismatched),
    }


def check_negative_liabilities(conn, *,
                               account_ids: Sequence[str] | None = None) -> list[dict]:
    """I-4：2101/2102/2103/2201/2202/2203 不得出现「正常方向为负」。

    正常方向余额 = Σ贷 − Σ借（这些科目都是贷方正常），<0 即违规。
    只看分录（余额真值），不看缓存表 —— 缓存坏了不该让不变量检查失真。
    """
    sql = """
        SELECT l.account_id, l.coa_code,
               COALESCE(sum(CASE WHEN l.dc = 'C' THEN l.amount_minor ELSE -l.amount_minor END), 0)
          FROM journal_line l
         WHERE l.coa_code = ANY(%s)
           {account_filter}
         GROUP BY 1, 2
        HAVING COALESCE(sum(CASE WHEN l.dc = 'C' THEN l.amount_minor ELSE -l.amount_minor END), 0) < 0
         ORDER BY 1, 2"""
    account_filter = "AND l.account_id = ANY(%s)" if account_ids is not None else ""
    params = [list(NEGATIVE_FORBIDDEN_COA)]
    if account_ids is not None:
        params.append(list(account_ids))
    with conn.cursor() as cur:
        cur.execute(sql.format(account_filter=account_filter), params)
        return [
            {"account_id": account_id, "coa_code": coa_code,
             "normal_balance_minor": int(normal_balance)}
            for account_id, coa_code, normal_balance in cur.fetchall()
        ]


def version_chain(conn, key: BalanceKey) -> list[dict]:
    """某键的全部版本（测试/排障用）：用于断言版本连续、无跳号。"""
    account_id, unit_type, sub_account = key
    with conn.cursor() as cur:
        cur.execute(
            """SELECT version, balance_minor, journal_id FROM account_balances
                WHERE account_id = %s AND unit_type = %s AND sub_account = %s ORDER BY version""",
            (account_id, unit_type, sub_account))
        return [{"version": int(v), "balance_minor": int(b), "journal_id": None if j is None else str(j)}
                for v, b, j in cur.fetchall()]
