# SPDX-License-Identifier: Apache-2.0
"""账本复算入口：链 + 余额派生 + 全局净额（T4 的 recompute 直接复用这份实现）。

    verify_ledger(conn) -> {
        "chain":    {"journals", "chain_bad", "hash_bad", "diff"},   # INV-13 / BUG-0002
        "balances": {"derived_keys", "stored_keys", "mismatched", "diff"},  # INV-10
        "net_minor": 0,                                             # 复式记账底线
        "diff": 0,                                                  # 三者之和，必须为 0
    }

只读、不修数据（M06 §6「复算：分页重算…差异 ≠0 即 P0；只读，不自动修」）。
"""
from __future__ import annotations

from . import balances, hashchain


def verify_ledger(conn) -> dict:
    chain = hashchain.verify_chain(conn)
    drift = balances.balance_drift(conn)
    net_minor = sum(balances.derive_balances(conn).values())
    net_bad = 0 if net_minor == 0 else 1
    return {"chain": chain, "balances": drift, "net_minor": net_minor,
            "diff": chain["diff"] + drift["diff"] + net_bad}
