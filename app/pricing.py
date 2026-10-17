# SPDX-License-Identifier: Apache-2.0
"""价格表：**只从配置读，绝不硬编码**（价格与阈值属运营配置，不入公开仓）。"""
from __future__ import annotations

import json
import os
from functools import lru_cache


@lru_cache(maxsize=1)
def table() -> dict:
    path = os.environ.get("DJB_PRICING_FILE")
    if not path:
        raise RuntimeError("缺 DJB_PRICING_FILE（价格表必须来自配置，不能硬编码）")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def quote(model: str, prompt_tokens: int, completion_tokens: int) -> dict:
    t = table()
    m = (t.get("models") or {}).get(model)
    if not m:
        raise KeyError(f"未配置价格的模型: {model}")
    amount = prompt_tokens * int(m["in_micro_per_token"]) + completion_tokens * int(m["out_micro_per_token"])
    fee = amount * int(t.get("platform_fee_bps", 0)) // 10_000
    return {"amount_micro": amount, "fee_micro": fee, "currency": t.get("currency", "COIN")}
