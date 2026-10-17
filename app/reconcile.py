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

from .nodes import canonical_receipt, derive_secret


def run(c, task_ids: list[str] | None = None, grace_seconds: int | None = None) -> dict:
    """对账。

    grace_seconds：平台有、节点尚未上报的任务，在宽限期内算「在途」，不计入 diff
                   （节点批量上报有延迟属正常）。默认取 DJB_RECON_GRACE_SECONDS 或 300s。
    task_ids：只对指定批次对账（测试/单批结算用）。
    """
    if grace_seconds is None:
        grace_seconds = int(os.environ.get("DJB_RECON_GRACE_SECONDS", "300"))
    params: list = []
    where = ["(r.task_id IS NOT NULL OR nr.task_id IS NOT NULL)"]
    if task_ids:
        where.append("(r.task_id = ANY(%s) OR nr.task_id = ANY(%s))")
        params += [task_ids, task_ids]
    sql = f"""SELECT r.task_id, r.amount_micro, nr.receipt_id, nr.usage_amount, nr.price_amount,
                     nr.sig_provider, nr.node_id, nr.access, nr.usage_unit, nr.raw,
                     (r.created_at IS NOT NULL AND r.created_at < now() - make_interval(secs => %s)) AS past_grace
              FROM receipts r FULL OUTER JOIN node_receipts nr ON r.task_id = nr.task_id
              WHERE {' AND '.join(where)}"""
    with c.cursor() as cur:
        cur.execute(sql, [grace_seconds] + params)
        rows = cur.fetchall()

    only_platform, pending_upload, only_node, mismatch, sig_bad = [], [], [], [], []
    matched = 0
    for task_id, amount_micro, rid_n, usage_amount, price_amount, sig_prov, node_id, access, unit, raw, past_grace in rows:
        if rid_n is None:
            (only_platform if past_grace else pending_upload).append(task_id)
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
            u = (raw or {}).get("usage") or {}
            pr = (raw or {}).get("price") or {}
            norm = {"receipt_id": rid_n, "task_id": (raw or {}).get("task_id"),
                    "access": (raw or {}).get("access"),
                    "usage_amount": str(u.get("amount")), "usage_unit": str(u.get("unit")),
                    "price_amount": str(pr.get("amount") if isinstance(pr, dict) else pr)}
            want = "hmac-sha256:" + hmac.new(secret, canonical_receipt(norm), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(want, str(sig_prov)):
                sig_bad.append(rid_n)

    diff = len(only_platform) + len(only_node) + len(mismatch) + len(sig_bad)
    return {"matched": matched,
            "only_platform": only_platform,      # 超宽限期仍未上报 → 计入 diff
            "pending_upload": pending_upload,    # 宽限期内未上报 → 在途，不计 diff
            "only_node": only_node, "amount_mismatch": mismatch, "signature_bad": sig_bad,
            "grace_seconds": grace_seconds, "diff": diff, "by_node": _by_node(c)}


def _by_node(c) -> dict:
    with c.cursor() as cur:
        cur.execute("""SELECT node_id, count(*), coalesce(sum(price_amount),0) FROM node_receipts GROUP BY node_id""")
        return {n: {"receipts": cnt, "amount": str(total)} for n, cnt, total in cur.fetchall()}
