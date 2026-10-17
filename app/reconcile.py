# SPDX-License-Identifier: Apache-2.0
"""双边对账：节点上报（供方视角） vs 平台记账（平台视角），差异必须为 0。

对账键：task_id（= 平台侧 request_id）。差异分四类：
  only_platform  平台有、节点没上报  → 节点漏报（可能掉线/丢批）
  only_node      节点上报、平台没有  → 平台漏记或伪造（高危）
  amount_mismatch 两侧金额不一致     → 计量口径分歧
  signature_bad  节点收据供方签名不可验 → 拒收前的漏网或密钥问题
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

from .nodes import derive_secret


def _canonical(rid, task_id, access, usage_amount, usage_unit, price_amount) -> bytes:
    return "|".join(map(str, (rid, task_id, access, usage_amount, usage_unit, price_amount))).encode()


def run(c) -> dict:
    with c.cursor() as cur:
        cur.execute("""SELECT r.task_id, r.amount_micro, nr.receipt_id, nr.usage_amount, nr.price_amount,
                              nr.sig_provider, nr.node_id, nr.access, nr.usage_unit
                       FROM receipts r FULL OUTER JOIN node_receipts nr ON r.task_id = nr.task_id
                       WHERE r.task_id IS NOT NULL OR nr.task_id IS NOT NULL""")
        rows = cur.fetchall()

    only_platform, only_node, mismatch, sig_bad = [], [], [], []
    matched = 0
    for task_id, amount_micro, rid_n, usage_amount, price_amount, sig_prov, node_id, access, unit in rows:
        if rid_n is None:
            only_platform.append(task_id)
            continue
        if task_id is None:
            only_node.append(rid_n)
            continue
        matched += 1
        # 平台以 micro 计；节点上报 price_amount 为同一口径的十进制字符串
        try:
            node_micro = int(round(float(price_amount) * 1_000_000))
        except Exception:
            mismatch.append({"task_id": task_id, "platform": amount_micro, "node": price_amount})
            continue
        if node_micro != int(amount_micro):
            mismatch.append({"task_id": task_id, "platform": amount_micro, "node": node_micro})
        # 供方签名复验（对账时再验一次，不信任入库时的状态）
        if node_id:
            secret = derive_secret(node_id).encode()
            want = "hmac-sha256:" + hmac.new(
                secret, _canonical(rid_n, task_id, access, usage_amount, unit, price_amount),
                hashlib.sha256).hexdigest()
            if not hmac.compare_digest(want, str(sig_prov)):
                sig_bad.append(rid_n)

    diff = len(only_platform) + len(only_node) + len(mismatch) + len(sig_bad)
    return {"matched": matched, "only_platform": only_platform, "only_node": only_node,
            "amount_mismatch": mismatch, "signature_bad": sig_bad,
            "diff": diff, "by_node": _by_node(c)}


def _by_node(c) -> dict:
    with c.cursor() as cur:
        cur.execute("""SELECT node_id, count(*), coalesce(sum(price_amount),0) FROM node_receipts GROUP BY node_id""")
        return {n: {"receipts": cnt, "amount": str(total)} for n, cnt, total in cur.fetchall()}
