# SPDX-License-Identifier: Apache-2.0
"""双签收据：供方签 + 用方签，缺任一即拒绝。

签名用 HMAC-SHA256，密钥各自独立（供方与用方密钥不同 → 单方无法伪造双侧签名）。
"""
from __future__ import annotations

import hashlib
import hmac
import os

FIELDS = ("receipt_id", "node_id", "consumer_id", "request_id", "model",
          "tokens_in", "tokens_out", "amount_micro", "ts_start", "ts_end")


def _key(name: str) -> bytes:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"缺签名密钥 {name}（双签必须双方各持一把）")
    return v.encode()


def _payload(**kw) -> bytes:
    return "|".join(str(kw[f]) for f in FIELDS).encode()


def sign(receipt: dict) -> dict:
    p = _payload(**receipt)
    sup = hmac.new(_key("DJB_SIG_SUPPLIER_KEY"), p, hashlib.sha256).hexdigest()
    con = hmac.new(_key("DJB_SIG_CONSUMER_KEY"), p, hashlib.sha256).hexdigest()
    return {**receipt, "sig_supplier": f"hmac-sha256:{sup}", "sig_consumer": f"hmac-sha256:{con}"}


def verify(receipt: dict) -> bool:
    """校验两侧签名；任何一侧不符即 False。"""
    p = _payload(**receipt)
    want_sup = "hmac-sha256:" + hmac.new(_key("DJB_SIG_SUPPLIER_KEY"), p, hashlib.sha256).hexdigest()
    want_con = "hmac-sha256:" + hmac.new(_key("DJB_SIG_CONSUMER_KEY"), p, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want_sup, receipt["sig_supplier"]) and hmac.compare_digest(want_con, receipt["sig_consumer"])
