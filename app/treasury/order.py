# SPDX-License-Identifier: Apache-2.0
"""M08a 支付订单 / PSP 适配 / 回调（M08 §3 / §4.1 / §6 流程 2 / §7）。

流程（§19.6.5.3–19.6.5.6）：

    下单（幂等键 → 通道能力校验 → 订单 created → 收银台会话 → payment.created）
      → 收银台 / 二维码
      → 服务端回调：验签 → 四项目校验（merId/merOrderId/amount/currency）→ 幂等（provider_txn_id）
        → 查询二次确认（冲突以查询为准）→ E3 入账（M06 posting）→ paid → credited → payment.paid
      → 失败：failed → payment.failed；未知：只查询、不换单重下

硬约束：

* **不持钥**：密钥由 provider 适配器从 KMS 引用取；本层不接触任何私钥 / 卡号；
* **不自己记账**：E3 只交出 ledger.PostingRequest，真正落账由注入的 M06 posting API 完成；
  未接线时 fail-closed（LedgerUnavailable）→ 回调失败由 PSP 按语义重试；
* **幂等**：下单按 X-DJB-Idempotency-Key；回调按 (provider, provider_txn_id) 唯一；
  重复回调返回首次结果（40910 语义），不重复入账（INV-08）；
* **金额**：一律整数分；金额 / 币种 / 订单号不符 → 40911，挂账不落账。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Mapping

from . import clock, config_source, events, facts, ids, ledger, models, policy, provider as provider_mod
from . import store
from .errors import (
    AmountMismatch,
    ChainUnsupported,
    Conflict,
    Forbidden,
    LedgerUnavailable,
    NotFound,
    PaymentMethodClosed,
    RegionUnsupported,
    RiskLevelRequired,
    ServerError,
)

__all__ = [
    "create_order", "get_order_view", "cancel_order", "handle_webhook", "settle_attempt",
    "requery", "attach_checkout", "ORDER_EVENT_AGGREGATE",
]

ORDER_EVENT_AGGREGATE = "payment_order"


def _provider_or_fail(registry: provider_mod.ProviderRegistry, name: str
                      ) -> provider_mod.PaymentProvider:
    provider = registry.get(name)
    if provider is None:
        raise PaymentMethodClosed(f"支付通道未开启：{name}（§19.10.4 40310）",
                                  reason="payment_method_closed")
    return provider


def _check_capabilities(provider: provider_mod.PaymentProvider, method: str) -> None:
    capabilities = provider.capabilities()
    if method not in capabilities.get("methods", ()):
        raise PaymentMethodClosed(f"该支付方式暂未开放：{method}（40310）",
                                  reason="payment_method_closed")
    # 地区限制：S1/S2 没有地区名单来源（M10 partner.* 未登记 region 键）→ 不伪造判定；
    # 保留 RegionUnsupported 的注入点由 M10/M11 在合并期接线（证据「遗留」CR-P8）。
    if capabilities.get("region_supported") is False:
        raise RegionUnsupported("当前地区暂不支持该支付方式（40311）",
                                reason="region_unsupported")


def _check_risk(risk_check: Any, *, account_id: str, draft: models.OrderDraft) -> None:
    """风控升级门槛（40312）：注入的 M11 判定；未接线默认放行（S1 无风控规则）。"""
    if risk_check is None:
        return
    verdict = risk_check(account_id=account_id, amount_minor=draft.amount_minor,
                         method=draft.method)
    if verdict is False or str(verdict).lower() in ("deny", "blocked", "insufficient"):
        raise RiskLevelRequired("完成风控验证后可继续（40312）", reason="risk_level_required")


def create_order(conn: Any, draft: models.OrderDraft, *, account_id: str,
                 tenant_id: str | None, idempotency_key: str | None,
                 provider_registry: provider_mod.ProviderRegistry,
                 config: config_source.TreasuryConfig,
                 ledger_poster: ledger.LedgerPoster | None,
                 now: datetime, trace_id: str | None, created_by: str,
                 risk_check: Any = None, checkout_base: Mapping[str, str] | None = None
                 ) -> dict[str, Any]:
    """创建支付订单（同一事务：订单 + attempt + payment.created + 收银台会话）。"""
    draft = models.OrderDraft(**{**draft.__dict__, "account_id": account_id})
    if idempotency_key:
        existing = store.find_order_by_idempotency(conn, idempotency_key)
        if existing is not None:
            if existing.get("request_hash") != draft.request_hash:
                raise Conflict("幂等键已用于不同载荷（金额 / 币种 / 方式 / 描述）",
                               reason="idempotency_key_reused")
            return {"order": existing, "replayed": True, "checkout": None}
    provider = _provider_or_fail(provider_registry, draft.provider)
    _check_capabilities(provider, draft.method)
    _check_risk(risk_check, account_id=account_id, draft=draft)

    order_id = str(ids.uuid7())
    expires_at = (clock.add_seconds(now, draft.expires_in_s)
                  if draft.expires_in_s else None)
    row = store.insert_order(conn, order_id=order_id, draft=draft,
                             policy_version=config.policy_version, trace_id=trace_id or "",
                             created_by=created_by, idempotency_key=idempotency_key,
                             now=clock.as_utc(now), expires_at=expires_at)
    attempt = store.insert_attempt(
        conn, attempt_id=str(ids.uuid7()), order_id=order_id,
        provider=draft.provider, provider_txn_id=None, provider_status="0",
        status="initiated", amount_minor=draft.amount_minor, fee_minor=0,
        net_minor=draft.amount_minor, currency=draft.currency, signature_verified=False,
        payload_hash=None, failure_code=None, now=clock.as_utc(now))
    try:
        checkout = provider.create_checkout({
            "order_no": row["order_no"], "amount_minor": draft.amount_minor,
            "currency": draft.currency, "method": draft.method, "now": now,
            "backend_url": (checkout_base or {}).get("backend_url", ""),
            "response_url": (checkout_base or {}).get("response_url", ""),
        })
    except provider_mod.ProviderUnavailable as exc:
        raise ServerError("支付通道暂不可用（未接线 KMS / transport）：请稍后重试",
                          reason="provider_unavailable") from exc
    events.payment_created(conn, row, trace_id=trace_id)
    return {"order": row, "attempt": attempt, "replayed": False,
            "checkout": {"provider": checkout["provider"], "pay_url": checkout["pay_url"],
                         "qr": checkout["qr"]}}


def attach_checkout(order: Mapping[str, Any], checkout: Mapping[str, Any] | None
                    ) -> dict[str, Any]:
    payload = models.order_payload(order)
    if checkout:
        payload["checkout"] = dict(checkout)
    return payload


def get_order_view(conn: Any, identifier: str, *, account_id: str | None) -> dict[str, Any]:
    """订单详情（含尝试摘要）：跨账户一律 404（不泄露存在性）。"""
    row = store.get_order(conn, identifier, account_id=account_id)
    if row is None:
        raise NotFound("支付订单不存在")
    attempts = store.list_attempts(conn, str(row["order_id"]))
    return models.order_detail_payload(row, attempts)


def cancel_order(conn: Any, identifier: str, *, account_id: str | None,
                 reason: str | None, now: datetime) -> dict[str, Any]:
    """取消：只允许 created / pending（已支付只能退款）。"""
    row = store.get_order(conn, identifier, account_id=account_id, lock=True)
    if row is None:
        raise NotFound("支付订单不存在")
    if not policy.can_cancel_order(str(row["status"])):
        raise Conflict(f"订单状态 {row['status']} 不允许取消（已支付只能退款）",
                       reason="order_not_cancelable")
    updated = store.update_order(conn, str(row["order_id"]), status="closed",
                                 closed_at=clock.as_utc(now))
    return models.order_payload(updated)


def _decode_body(raw_body: bytes) -> Mapping[str, Any]:
    import json

    try:
        body = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        from .errors import BadRequest

        raise BadRequest("回调必须是 JSON（原始字节参与验签）") from exc
    if not isinstance(body, Mapping):
        from .errors import BadRequest

        raise BadRequest("回调必须是 JSON 对象")
    return body


def _find_or_open_attempt(conn: Any, *, order: Mapping[str, Any], provider: str,
                          provider_txn_id: str, amount_minor: int, currency: str,
                          provider_status: str, signature_verified: bool,
                          payload_hash: str, now: datetime) -> dict[str, Any]:
    existing = store.get_attempt_by_txn(conn, provider, provider_txn_id)
    if existing is not None:
        return existing
    attempts = store.list_attempts(conn, str(order["order_id"]))
    for attempt in attempts:
        if attempt["provider"] == provider and attempt["provider_txn_id"] is None:
            return store.update_attempt(conn, str(attempt["attempt_id"]),
                                        provider_txn_id=provider_txn_id,
                                        provider_status=provider_status,
                                        signature_verified=signature_verified,
                                        fee_minor=0, net_minor=amount_minor)
    return store.insert_attempt(
        conn, attempt_id=str(ids.uuid7()), order_id=str(order["order_id"]), provider=provider,
        provider_txn_id=provider_txn_id, provider_status=provider_status, status="initiated",
        amount_minor=amount_minor, fee_minor=0, net_minor=amount_minor, currency=currency,
        signature_verified=signature_verified, payload_hash=payload_hash,
        failure_code=None, now=clock.as_utc(now))


def _query_status(provider: provider_mod.PaymentProvider, txn_id: str) -> tuple[str | None, bool]:
    """查询二次确认：返回 (查询状态, 是否确认成功)；通道不可用 → (None, False)。"""
    try:
        result = provider.query_payment(txn_id)
    except provider_mod.ProviderUnavailable:
        return None, False
    raw = result.get("status") if isinstance(result, Mapping) else result
    if raw is None:
        return None, False
    try:
        return policy.provider_status(raw), True
    except Exception:  # noqa: BLE001 - 通道返回未知状态码：不猜，交给人工
        return None, True


def handle_webhook(conn: Any, *, provider_name: str, raw_body: bytes,
                   headers: Mapping[str, str],
                   provider_registry: provider_mod.ProviderRegistry,
                   config: config_source.TreasuryConfig,
                   ledger_poster: ledger.LedgerPoster | None,
                   now: datetime, trace_id: str | None = None) -> dict[str, Any]:
    """PSP 服务端回调：验签 → 四项目校验 → 幂等 → 查询二次确认 → E3 → paid/credited。

    返回 {"ack": True/False, "duplicate": bool, "order": row|None, "reason": str|None}：
    调用方按通道语义把 ack=False 映射为 -1（触发重试），ack=True 映射为成功。
    """
    provider = provider_registry.get(provider_name)
    if provider is None:
        from .errors import BadRequest

        raise BadRequest(f"未知支付通道：{provider_name}", field="provider")
    try:
        event = provider.verify_webhook(raw_body, headers, now=now)
    except provider_mod.ProviderUnavailable as exc:
        raise ServerError("通道验签不可用（密钥未接线）：拒绝回调（fail-closed）",
                          reason="provider_unavailable") from exc
    if not event.signature_verified:
        from .errors import BadRequest

        # Lead 2026-10-24 裁决：验签失败 → 400 + 40001（不落账、不重试猜测）
        raise BadRequest("回调验签失败：拒绝处理（不落账）", field="signature")
    body = dict(event.fields)
    webhook = models.parse_webhook(provider_name, body, raw_body,
                                   payload_hash=event.payload_hash)
    order = store.get_order(conn, webhook.order_no, lock=True)
    if order is None:
        raise NotFound("回调指向的订单不存在")
    if webhook.currency != str(order["currency"]):
        raise AmountMismatch(
            f"回调币种与订单不符：订单 {order['currency']}，回调 {webhook.currency}",
            reason="amount_mismatch")
    # INV-08：重复回调（已入账达订单金额）→ 409 + 40910；幂等返回首次结果，不重复入账
    if policy.is_duplicate_callback(int(order["credited_minor"]), int(order["amount_minor"])):
        from .errors import DuplicateCallback

        raise DuplicateCallback("重复回调：订单已入账，幂等返回首次结果（不重复入账）",
                                reason="duplicate_callback")
    attempt = _find_or_open_attempt(
        conn, order=order, provider=provider_name, provider_txn_id=webhook.provider_txn_id,
        amount_minor=webhook.amount_minor, currency=webhook.currency,
        provider_status=webhook.provider_status, signature_verified=True,
        payload_hash=event.payload_hash, now=now)

    query_status, query_confirmed = _query_status(provider, webhook.provider_txn_id)
    effective = webhook.status
    if query_confirmed and query_status is not None and query_status != webhook.status:
        # 回调与查询冲突：以查询为准（§19.6.5.5）。不猜成功，交由人工 / 后续查询收敛。
        store.update_attempt(conn, str(attempt["attempt_id"]), provider_status=effective,
                             query_confirmed=True, query_result=query_status,
                             status="failed", failure_code="query_conflict")
        return {"ack": True, "duplicate": False, "order": order,
                "reason": "query_conflict", "query_status": query_status}
    if query_confirmed and query_status is not None:
        effective = query_status

    if effective == "pending":
        store.update_attempt(conn, str(attempt["attempt_id"]), provider_status="pending",
                             query_confirmed=query_confirmed, query_result=query_status)
        if order["status"] == "created":
            order = store.update_order(conn, str(order["order_id"]), status="pending")
        return {"ack": True, "duplicate": False, "order": order, "reason": "pending"}
    if effective in ("failed", "closed"):
        failed = store.update_attempt(conn, str(attempt["attempt_id"]),
                                      provider_status=effective,
                                      query_confirmed=query_confirmed,
                                      query_result=query_status, status="failed",
                                      failure_code=effective)
        if not policy.order_is_terminal(str(order["status"])):
            order = store.update_order(conn, str(order["order_id"]),
                                       status="failed" if effective == "failed" else "closed",
                                       closed_at=clock.as_utc(now))
        events.payment_failed(conn, order, error_code=effective, occurred_at=now,
                              trace_id=trace_id)
        return {"ack": True, "duplicate": False, "order": order, "reason": effective,
                "attempt": failed}

    # ── 成功路径：四项目校验 → E3 → paid → credited
    policy.check_callback_amount(order_status=str(order["status"]),
                                 order_amount_minor=int(order["amount_minor"]),
                                 paid_minor=int(webhook.amount_minor),
                                 credited_minor=int(order["credited_minor"]))
    attempt = store.update_attempt(conn, str(attempt["attempt_id"]),
                                   provider_status="succeeded",
                                   query_confirmed=query_confirmed,
                                   query_result=query_status, status="succeeded",
                                   fee_minor=0, net_minor=int(order["amount_minor"]))
    if order["status"] == "created":
        order = store.update_order(conn, str(order["order_id"]), status="pending")
    paid_at = webhook.paid_at or clock.as_utc(now)
    request = ledger.e3_request(attempt=attempt, order=order,
                                policy_version=config.policy_version,
                                occurred_at=paid_at, trace_id=trace_id)
    ledger.post_one(conn, ledger_poster, request)
    order = store.update_order(conn, str(order["order_id"]), status="paid", paid_at=paid_at)
    order = store.update_order(conn, str(order["order_id"]), status="credited",
                               credited_at=paid_at,
                               credited_minor=int(order["amount_minor"]))
    events.payment_paid(conn, order, provider_ref=webhook.provider_txn_id, paid_at=paid_at,
                        trace_id=trace_id)
    return {"ack": True, "duplicate": False, "order": order, "reason": "credited",
            "attempt": attempt}


def requery(conn: Any, identifier: str, *, provider_registry: provider_mod.ProviderRegistry,
            ledger_poster: ledger.LedgerPoster | None,
            config: config_source.TreasuryConfig, now: datetime,
            trace_id: str | None = None) -> dict[str, Any]:
    """未知状态只查询（不换单重下）：按最后一次尝试的通道单号查询并推进状态。"""
    order = store.get_order(conn, identifier, lock=True)
    if order is None:
        raise NotFound("支付订单不存在")
    attempts = [item for item in store.list_attempts(conn, str(order["order_id"]))
                if item.get("provider_txn_id")]
    if not attempts:
        raise Conflict("该订单没有可查询的通道单号（未知状态只查询）",
                       reason="no_provider_ref")
    attempt = attempts[-1]
    provider = _provider_or_fail(provider_registry, str(attempt["provider"]))
    status, confirmed = _query_status(provider, str(attempt["provider_txn_id"]))
    if not confirmed:
        raise ServerError("通道查询不可用：请稍后重试（不换单重下）",
                          reason="provider_unavailable")
    if status == "succeeded":
        policy.check_callback_amount(order_status=str(order["status"]),
                                     order_amount_minor=int(order["amount_minor"]),
                                     paid_minor=int(attempt["amount_minor"]),
                                     credited_minor=int(order["credited_minor"]))
        attempt = store.update_attempt(conn, str(attempt["attempt_id"]), provider_status="succeeded",
                                       query_confirmed=True, query_result=status,
                                       status="succeeded")
        paid_at = clock.as_utc(now)
        if order["status"] == "created":
            order = store.update_order(conn, str(order["order_id"]), status="pending")
        request = ledger.e3_request(attempt=attempt, order=order,
                                    policy_version=config.policy_version,
                                    occurred_at=paid_at, trace_id=trace_id)
        ledger.post_one(conn, ledger_poster, request)
        order = store.update_order(conn, str(order["order_id"]), status="paid", paid_at=paid_at)
        order = store.update_order(conn, str(order["order_id"]), status="credited",
                                   credited_at=paid_at,
                                   credited_minor=int(order["amount_minor"]))
        events.payment_paid(conn, order, provider_ref=str(attempt["provider_txn_id"]),
                            paid_at=paid_at, trace_id=trace_id)
        return {"order": order, "reason": "credited"}
    if status in ("failed", "closed"):
        store.update_attempt(conn, str(attempt["attempt_id"]), provider_status=status,
                             query_confirmed=True, query_result=status, status="failed",
                             failure_code=status)
        order = store.update_order(conn, str(order["order_id"]),
                                   status="failed" if status == "failed" else "closed",
                                   closed_at=clock.as_utc(now))
        events.payment_failed(conn, order, error_code=status, occurred_at=now,
                              trace_id=trace_id)
        return {"order": order, "reason": status}
    return {"order": order, "reason": "pending"}


def settle_attempt(conn: Any, *, identifier: str, provider_txn_id: str,
                   settled_minor: int, fee_minor: int,
                   provider_registry: provider_mod.ProviderRegistry,
                   ledger_poster: ledger.LedgerPoster | None,
                   config: config_source.TreasuryConfig, now: datetime,
                   trace_id: str | None = None) -> dict[str, Any]:
    """E4（PSP 结算到账，两步记法）：净额 + 平台补足手续费，两步之后覆盖率仍 100%。"""
    order = store.get_order(conn, identifier, lock=True)
    if order is None:
        raise NotFound("支付订单不存在")
    if str(order["status"]) not in facts.ORDER_PAYABLE:
        raise Conflict("订单未支付，不能结算", reason="order_not_paid")
    attempt = store.get_attempt_by_txn(conn, str(order["provider"]), provider_txn_id)
    if attempt is None:
        raise NotFound("该通道单号没有支付尝试")
    requests = ledger.e4_requests(attempt=attempt, order=order, settled_minor=settled_minor,
                                  fee_minor=fee_minor, policy_version=config.policy_version,
                                  occurred_at=clock.as_utc(now), trace_id=trace_id)
    results = ledger.post_many(conn, ledger_poster, requests)
    store.update_attempt(conn, str(attempt["attempt_id"]), settled_minor=int(settled_minor),
                         settlement_fee_minor=int(fee_minor))
    return {"order_no": order["order_no"], "provider_txn_id": provider_txn_id,
            "settled_minor": int(settled_minor), "fee_minor": int(fee_minor),
            "journal_ids": [str(item.get("journal_id")) for item in results]}
