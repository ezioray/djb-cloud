# SPDX-License-Identifier: AGPL-3.0-or-later
"""M06 E6 计量结算的**注入式**对接（M05 §6 流程 2 / CR-3 / 20-payment-ledger §20.3 E6）。

边界（硬规则）：

* M05 **不 import `app.ledger`**、不写分录、不开跨模块事务；E6 的落账由 M06 完成；
* 默认路径是**事件驱动**：M05 发 ``usage.recorded`` → M06 消费 → 按 E6 落一条分录
  （源键 ``usage_settle / usage_id / 1``）。本模块的同步调用**只用于管理面重放**，
  且被特性开关 ``metering.usage_settle_sync_fallback``（**默认关闭**）挡住；
* 金额单位换算在这里一次说清：M05 ``amount_minor`` 是 **USD 分**（1e-2），M06 凭证行的
  ``amount_minor`` 是 **micro-USD**（1e-6，03-facts §6 / M06 ``unit_scale=6``），
  所以 E6 金额 = ``amount_minor × 10^4``（整数乘，无舍入）。

E6 口径（product/v4/src/20-payment-ledger.md §20.3.1）：借 **2101**（服务预付款）/
贷 **4101**（服务费收入，**毛额法全额**），行 ``entry_type=consume``。
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from . import amounts, clock, errors, facts, features

log = logging.getLogger("djb.metering.settlement")

#: ``provider(request: Mapping) -> Any``：由 Lead 合并时接到 M06 的 `/internal/ledger` 或网关函数
LedgerProvider = Callable[[Mapping[str, Any]], Any]

_ledger_provider: LedgerProvider | None = None


def set_ledger_provider(provider: LedgerProvider | None) -> None:
    global _ledger_provider
    _ledger_provider = provider


def current_ledger_provider() -> LedgerProvider | None:
    return _ledger_provider


def load_usage(c: Any, usage_id: str) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT usage_id, request_id, account_id, node_id, model, state, amount_minor,
                      recorded_at, receipt_id
                 FROM usage_records WHERE usage_id = %s""", (usage_id,))
        row = cur.fetchone()
    if row is None:
        return None
    keys = ("usage_id", "request_id", "account_id", "node_id", "model", "state",
            "amount_minor", "recorded_at", "receipt_id")
    usage = dict(zip(keys, row))
    usage["usage_id"] = str(usage["usage_id"])
    usage["account_id"] = str(usage["account_id"])
    return usage


def e6_request(usage: Mapping[str, Any], *, policy_version: str,
               trace_id: str | None = None) -> dict[str, Any]:
    """构造一张 E6 凭证请求（纯函数；金额由「分」换算成 M06 的 micro）。"""
    if not isinstance(policy_version, str) or not (1 <= len(policy_version) <= 64):
        raise errors.InvalidArgument("policy_version 必须是 1..64 字符（M06 INV-05）",
                                     field="policy_version")
    amount_minor = int(usage["amount_minor"])
    if amount_minor <= 0:
        raise errors.InvalidArgument("E6 金额必须 > 0（零额不入账）", field="amount_minor")
    amount_micro = amount_minor * facts.MICRO_PER_MINOR        # 分 → micro（整数乘）
    usage_id = str(usage["usage_id"])
    lines = []
    for coa_code, dc in facts.E6_LINES:
        account_id = str(usage["account_id"]) if dc == "D" else facts.E6_CREDIT_ACCOUNT
        lines.append({"coa_code": coa_code, "dc": dc, "amount_minor": amount_micro,
                      "account_id": account_id, "entry_type": facts.E6_ENTRY_TYPE})
    return {
        "event_type": facts.E6_EVENT_TYPE,
        "unit_type": facts.CURRENCY,
        "source_type": facts.E6_SOURCE_TYPE,
        "source_id": usage_id,
        "event_seq": facts.E6_EVENT_SEQ,
        "idempotency_key": f"{facts.E6_SOURCE_TYPE}:{usage_id}:{facts.E6_EVENT_SEQ}",
        "policy_version": policy_version,
        "correlation_id": usage.get("request_id"),
        "trace_id": trace_id or usage_id,
        "lines": lines,
        "amount_minor_cents": amount_minor,
        "amount_micro": amount_micro,
    }


def post_usage_settle(c: Any, usage_id: str, *, policy_version: str | None = None,
                      provider: LedgerProvider | None = None, force: bool = False,
                      trace_id: str | None = None, now: Any = None) -> dict[str, Any]:
    """同步落一张 E6（**仅管理面重放**）：默认被开关挡住，不改变事件驱动主路径。"""
    if not force and not features.enabled("metering.usage_settle_sync_fallback"):
        return {"posted": False, "reason": "switch_off"}
    usage = load_usage(c, usage_id)
    if usage is None:
        raise errors.NotFound("用量不存在", object="usage")
    if int(usage["amount_minor"]) <= 0:
        return {"posted": False, "reason": "zero_amount", "usage_id": usage_id}
    version = policy_version or ""
    if not version:
        raise errors.InvalidArgument("同步落账需要 policy_version（M04 成交价版本）",
                                     field="policy_version")
    request = e6_request(usage, policy_version=version, trace_id=trace_id)
    active = provider if provider is not None else _ledger_provider
    if active is None:
        raise errors.LedgerUnavailable("M06 账本 provider 未接线（fail-closed，不假装已入账）")
    result = active(request)
    log.info("metering.settlement.posted", extra={"usage_id": usage_id,
                                                  "amount_minor": int(usage["amount_minor"]),
                                                  "amount_micro": request["amount_micro"],
                                                  "occurred_at": clock.as_utc(
                                                      now or clock.utcnow()).isoformat()})
    return {"posted": True, "usage_id": usage_id, "request": request,
            "idempotency_key": request["idempotency_key"], "provider_result": result,
            "amount_minor": int(usage["amount_minor"]),
            "amount_micro": request["amount_micro"],
            "amount_text": amounts.format_minor(int(usage["amount_minor"]))}


__all__ = ["LedgerProvider", "set_ledger_provider", "current_ledger_provider", "load_usage",
           "e6_request", "post_usage_settle"]
