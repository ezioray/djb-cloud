# SPDX-License-Identifier: Apache-2.0
"""M08 请求解析 / 行映射 / 对客序列化（对齐 spec 1.2.5 M08 段）。

红线：

* 对客 payload 只从白名单键构造（字段名与 spec 1.2.5 components 一致）；
* 请求体校验自己做（不依赖框架 422）：不合法一律 400/40001；未知字段拒绝（05-security §1 S3）；
* 不把卡号 / 渠道原文 / 完整签名 / 原路明细回给客户端（原路只回 hash）；
* 金额一律整数最小单位；游标是 base64url(<UTC iso>|<identity>)，服务端生成、不可猜。
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from . import clock, facts, policy
from .errors import BadRequest, ChainUnsupported

__all__ = [
    "OrderDraft", "CancelDraft", "WebhookDraft", "RefundDraft", "PayoutItemDraft",
    "PayoutBatchDraft", "PoolDraft", "ProvisionDraft", "ActivateDraft", "SwitchDraft",
    "RetireDraft", "SigningEventDraft", "AddressDraft", "GasPolicyDraft", "DepositAddressDraft",
    "parse_order", "parse_cancel", "parse_webhook", "parse_refund", "parse_payout_batch",
    "parse_pool", "parse_provision", "parse_activate", "parse_switch", "parse_retire",
    "parse_signing_event", "parse_address", "parse_gas_policy", "parse_deposit_address",
    "parse_payout_approve", "require_idempotency_key", "require_known_keys",
    "order_payload", "attempt_payload", "order_detail_payload", "webhook_ack_payload",
    "wallet_payload", "pool_payload", "provision_batch_payload", "activate_payload",
    "switch_ack_payload", "payout_batch_payload", "payout_item_payload", "refund_payload",
    "intent_payload", "signing_request_payload", "signing_event_payload", "address_payload",
    "deposit_address_payload", "gas_policy_payload", "page_payload", "encode_cursor",
    "decode_cursor",
]

#: 地址形态：EVM 小写 0x + 40 hex（一期仅 Polygon）
_EVM_RE_LEN = 42


def _text(value: Any, *, field_name: str, min_len: int = 1, max_len: int = facts.MAX_TEXT_LEN,
          required: bool = True) -> str | None:
    if value is None:
        if required:
            raise BadRequest(f"{field_name} 必填", field=field_name)
        return None
    if not isinstance(value, str):
        raise BadRequest(f"{field_name} 必须是字符串", field=field_name)
    text = value.strip()
    if not text:
        if required:
            raise BadRequest(f"{field_name} 不能为空", field=field_name)
        return None
    if not (min_len <= len(text) <= max_len):
        raise BadRequest(f"{field_name} 长度必须是 {min_len}..{max_len}", field=field_name)
    return text


def _int(value: Any, *, field_name: str, minimum: int = 0, maximum: int | None = None,
         required: bool = True, default: int | None = None) -> int | None:
    if value is None:
        if required:
            raise BadRequest(f"{field_name} 必填", field=field_name)
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRequest(f"{field_name} 必须是整数（不接受浮点 / 字符串）", field=field_name)
    if value < minimum or (maximum is not None and value > maximum):
        raise BadRequest(f"{field_name} 超出允许范围", field=field_name)
    return int(value)


def require_known_keys(body: Mapping[str, Any], allowed: Sequence[str]) -> None:
    """S3：未知字段直接拒绝（防止事实上的契约漂移，也防夹带敏感字段）。"""
    unknown = sorted(set(body) - set(allowed))
    if unknown:
        raise BadRequest(f"请求体含未知字段：{unknown}", field="body")


def require_idempotency_key(value: Any) -> str | None:
    """X-DJB-Idempotency-Key：16..128 字符；缺省返回 None（资金写不自动重试）。"""
    if value is None:
        return None
    if not isinstance(value, str):
        raise BadRequest("幂等键必须是字符串", field="Idempotency-Key")
    text = value.strip()
    if not text:
        return None
    if not (facts.MIN_IDEMPOTENCY_LEN <= len(text) <= facts.MAX_IDEMPOTENCY_LEN):
        raise BadRequest(
            f"幂等键长度必须是 {facts.MIN_IDEMPOTENCY_LEN}..{facts.MAX_IDEMPOTENCY_LEN}",
            field="Idempotency-Key")
    return text


def _address(value: Any, *, field_name: str = "address") -> str:
    text = _text(value, field_name=field_name, min_len=20, max_len=facts.MAX_ADDRESS_LEN)
    assert text is not None
    lowered = text.lower()
    if not lowered.startswith("0x") or len(lowered) != _EVM_RE_LEN:
        raise BadRequest(f"{field_name} 必须是 0x 开头的 40 位十六进制地址", field=field_name)
    try:
        int(lowered[2:], 16)
    except ValueError as exc:
        raise BadRequest(f"{field_name} 不是合法十六进制地址", field=field_name) from exc
    return lowered


def _method(value: Any) -> str:
    text = _text(value, field_name="method", min_len=1, max_len=32)
    if text not in facts.PSP_METHODS:
        raise BadRequest(f"method 必须是 {list(facts.PSP_METHODS)} 之一", field="method")
    return text or ""


def _provider(value: Any) -> str:
    text = _text(value, field_name="provider", min_len=1, max_len=32, required=False)
    if text is None:
        return "mock"
    lowered = text.lower()
    if lowered not in facts.PROVIDERS:
        raise BadRequest(f"provider 必须是 {list(facts.PROVIDERS)} 之一", field="provider")
    return lowered


# ═══════════════════════════════════════════════════════════ 请求对象
@dataclass(frozen=True)
class OrderDraft:
    account_id: str
    amount_minor: int
    currency: str
    method: str
    provider: str
    description: str | None = None
    expires_in_s: int | None = None
    request_hash: str | None = None


@dataclass(frozen=True)
class CancelDraft:
    reason: str | None = None


@dataclass(frozen=True)
class WebhookDraft:
    provider: str
    order_no: str
    provider_txn_id: str
    provider_status: str
    status: str
    amount_minor: int
    currency: str
    paid_at: datetime | None
    raw_body: bytes
    payload_hash: str
    timestamp: int | None = None
    signature: str | None = None


@dataclass(frozen=True)
class RefundDraft:
    order_no: str
    amount_minor: int
    reason_code: str
    original_route: str
    evidence_ref: str | None = None


@dataclass(frozen=True)
class PayoutItemDraft:
    payee_account_id: str
    payee_address: str
    gross_minor: int
    fee_minor: int = 0
    address_id: str | None = None


@dataclass(frozen=True)
class PayoutBatchDraft:
    items: tuple[PayoutItemDraft, ...]
    gas_mode: str | None = None
    attestation_ref: str | None = None


@dataclass(frozen=True)
class PoolDraft:
    chain: str
    role: str
    fund_class: str
    min_spare: int
    max_active: int
    switch_threshold_pct: int
    pool_cap_minor: int
    activate_batch_size: int
    provision_lead_time_h: int
    reason: str | None = None


@dataclass(frozen=True)
class ProvisionDraft:
    pool_id: str
    wallet_count: int


@dataclass(frozen=True)
class ActivateDraft:
    signing_request_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class SwitchDraft:
    pool_id: str
    reason: str


@dataclass(frozen=True)
class RetireDraft:
    wallet_id: str
    step: str
    attestation_ref: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class SigningEventDraft:
    event: str
    signer_type: str
    signer_ref: str | None = None
    signature_hash: str | None = None
    device_id: str | None = None
    auth_hash: str | None = None
    txid: str | None = None
    error_code: str | None = None
    occurred_at: datetime | None = None


@dataclass(frozen=True)
class AddressDraft:
    account_id: str
    chain_id: str
    address: str
    ownership_challenge_ref: str
    risk_level: str = "low"
    label: str | None = None


@dataclass(frozen=True)
class GasPolicyDraft:
    gas_mode: str
    gas_bearer: str | None = None
    scope: str = "global"
    reason: str | None = None


@dataclass(frozen=True)
class DepositAddressDraft:
    chain: str
    address: str
    reason: str
    ticket: str
    effective_at: datetime | None = None


# ═══════════════════════════════════════════════════════════ 解析
def parse_order(body: Mapping[str, Any], *, account_id: str) -> OrderDraft:
    require_known_keys(body, ("amount_minor", "currency", "method", "provider", "description",
                              "expires_in_s"))
    amount = policy.validate_amount(body.get("amount_minor"))
    currency = policy.validate_currency(body.get("currency"), amount_minor=amount)
    method = _method(body.get("method"))
    provider = _provider(body.get("provider"))
    description = _text(body.get("description"), field_name="description", min_len=1,
                        max_len=facts.MAX_TEXT_LEN, required=False)
    expires = _int(body.get("expires_in_s"), field_name="expires_in_s", minimum=60,
                   maximum=7 * 24 * 3600, required=False)
    fingerprint = f"{amount}|{currency}|{method}|{provider}|{description or ''}"
    return OrderDraft(account_id=account_id, amount_minor=amount, currency=currency,
                      method=method, provider=provider, description=description,
                      expires_in_s=expires, request_hash=fingerprint)


def parse_cancel(body: Mapping[str, Any]) -> CancelDraft:
    if body:
        require_known_keys(body, ("reason",))
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_REASON_LEN, required=False)
    return CancelDraft(reason=reason)


def parse_webhook(provider: str, body: Mapping[str, Any], raw_body: bytes, *,
                  payload_hash: str) -> WebhookDraft:
    """回调字段映射（§19.6.5.3 / §19.6.5.5）：merOrderId / platformOrderId / amount / currency。"""
    require_known_keys(body, ("merId", "merOrderId", "platformOrderId", "amount", "currency",
                              "status", "sign", "timestamp", "payTime", "memo"))
    order_no = _text(body.get("merOrderId"), field_name="merOrderId", min_len=3, max_len=32)
    txn_id = _text(body.get("platformOrderId"), field_name="platformOrderId", min_len=1,
                   max_len=128)
    raw_status = body.get("status")
    status = policy.provider_status(raw_status)
    amount = _int(body.get("amount"), field_name="amount", minimum=1)
    currency = policy.validate_currency(body.get("currency"))
    timestamp = _int(body.get("timestamp"), field_name="timestamp", minimum=0, required=False)
    paid_at = (clock.parse_datetime(body["payTime"], field="payTime")
               if body.get("payTime") else None)
    return WebhookDraft(provider=str(provider).lower(), order_no=order_no or "",
                        provider_txn_id=txn_id or "", provider_status=str(raw_status),
                        status=status, amount_minor=amount or 0, currency=currency,
                        paid_at=paid_at, raw_body=raw_body, payload_hash=payload_hash,
                        timestamp=timestamp, signature=body.get("sign"))


def parse_refund(body: Mapping[str, Any], *, account_id: str) -> RefundDraft:
    require_known_keys(body, ("order_no", "amount_minor", "reason_code", "original_route",
                              "evidence_ref"))
    order_no = _text(body.get("order_no"), field_name="order_no", min_len=3, max_len=32)
    amount = policy.validate_amount(body.get("amount_minor"))
    reason = _text(body.get("reason_code"), field_name="reason_code", min_len=1,
                   max_len=facts.MAX_TEXT_LEN)
    route = _text(body.get("original_route"), field_name="original_route", min_len=1,
                  max_len=facts.MAX_TEXT_LEN)
    evidence = _text(body.get("evidence_ref"), field_name="evidence_ref", min_len=1,
                     max_len=128, required=False)
    return RefundDraft(order_no=order_no or "", amount_minor=amount, reason_code=reason or "",
                       original_route=route or "", evidence_ref=evidence)


def parse_payout_batch(body: Mapping[str, Any]) -> PayoutBatchDraft:
    require_known_keys(body, ("items", "gas_mode", "attestation_ref"))
    raw_items = body.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise BadRequest("items 必须是非空数组", field="items")
    if len(raw_items) > facts.PAYOUT_BATCH_MAX_ITEMS:
        raise BadRequest(f"同批出款笔数上限 {facts.PAYOUT_BATCH_MAX_ITEMS}", field="items")
    items: list[PayoutItemDraft] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_items):
        if not isinstance(raw, Mapping):
            raise BadRequest(f"items[{index}] 必须是对象", field="items")
        require_known_keys(raw, ("payee_account_id", "payee_address", "gross_minor",
                                 "fee_minor", "address_id"))
        payee = _text(raw.get("payee_account_id"), field_name=f"items[{index}].payee_account_id",
                      min_len=1, max_len=128)
        address = _address(raw.get("payee_address"), field_name=f"items[{index}].payee_address")
        gross = policy.validate_amount(raw.get("gross_minor"),
                                       field=f"items[{index}].gross_minor")
        fee = _int(raw.get("fee_minor"), field_name=f"items[{index}].fee_minor", minimum=0,
                   required=False, default=0) or 0
        address_id = _text(raw.get("address_id"), field_name=f"items[{index}].address_id",
                           min_len=1, max_len=64, required=False)
        key = (payee or "", address)
        if key in seen:
            raise BadRequest(f"items[{index}] 与同批其他笔重复（同收款地址同账户）", field="items")
        seen.add(key)
        items.append(PayoutItemDraft(payee_account_id=payee or "", payee_address=address,
                                     gross_minor=gross, fee_minor=int(fee),
                                     address_id=address_id))
    gas_mode = _text(body.get("gas_mode"), field_name="gas_mode", min_len=1, max_len=32,
                     required=False)
    if gas_mode is not None:
        gas_mode = policy.normalize_gas_mode(gas_mode)
    attestation = _text(body.get("attestation_ref"), field_name="attestation_ref", min_len=1,
                        max_len=128, required=False)
    return PayoutBatchDraft(items=tuple(items), gas_mode=gas_mode, attestation_ref=attestation)


def parse_pool(body: Mapping[str, Any]) -> PoolDraft:
    """createTreasuryPool（spec 1.2.5 TreasuryPoolCreateRequest；字段按 facts §2）。"""
    require_known_keys(body, ("chain", "role", "fund_class", "min_spare", "max_active",
                              "switch_threshold_pct", "pool_cap_minor", "activate_batch_size",
                              "provision_lead_time_h", "reason"))
    chain = _text(body.get("chain"), field_name="chain", min_len=1, max_len=32)
    if chain != facts.CHAIN_ID:
        raise ChainUnsupported("一期仅 Polygon（K6）", reason="chain_unsupported")
    role = _text(body.get("role"), field_name="role", min_len=1, max_len=16)
    if role not in ("hot", "warm"):
        raise BadRequest("role 必须是 hot / warm", field="role")
    fund_class = policy.canonical_fund_class(body.get("fund_class"))
    if role == "hot" and fund_class == "PLATFORM":
        raise BadRequest("平台热池不建（决策 K5）", field="fund_class")
    default_max = facts.MAX_ACTIVE_HOT if role == "hot" else facts.MAX_ACTIVE_WARM
    min_spare = _int(body.get("min_spare"), field_name="min_spare", minimum=0,
                     maximum=facts.MIN_SPARE * 3, required=False, default=facts.MIN_SPARE) or 0
    max_active = _int(body.get("max_active"), field_name="max_active", minimum=1,
                      maximum=facts.MAX_ACTIVE_HARD_CAP, required=False,
                      default=default_max) or 1
    switch_pct = _int(body.get("switch_threshold_pct"), field_name="switch_threshold_pct",
                      minimum=facts.SWITCH_THRESHOLD_MIN_PCT,
                      maximum=facts.SWITCH_THRESHOLD_MAX_PCT, required=False,
                      default=facts.SWITCH_THRESHOLD_PCT) or 0
    pool_cap = _int(body.get("pool_cap_minor"), field_name="pool_cap_minor", minimum=1,
                    required=False, default=facts.POOL_CAP_MINOR) or 0
    batch_size = _int(body.get("activate_batch_size"), field_name="activate_batch_size",
                      minimum=facts.ACTIVATE_BATCH_MIN, maximum=facts.ACTIVATE_BATCH_MAX,
                      required=False, default=facts.ACTIVATE_BATCH_SIZE) or 0
    lead_h = _int(body.get("provision_lead_time_h"), field_name="provision_lead_time_h",
                  minimum=facts.PROVISION_LEAD_TIME_MIN_H,
                  maximum=facts.PROVISION_LEAD_TIME_MAX_H, required=False,
                  default=facts.PROVISION_LEAD_TIME_H) or 0
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_TEXT_LEN, required=False)
    return PoolDraft(chain=chain or "", role=role or "", fund_class=fund_class,
                     min_spare=int(min_spare), max_active=int(max_active),
                     switch_threshold_pct=int(switch_pct), pool_cap_minor=int(pool_cap),
                     activate_batch_size=int(batch_size),
                     provision_lead_time_h=int(lead_h), reason=reason)


def parse_provision(body: Mapping[str, Any]) -> ProvisionDraft:
    require_known_keys(body, ("pool_id", "wallet_count"))
    pool_id = _text(body.get("pool_id"), field_name="pool_id", min_len=5, max_len=64)
    policy.split_pool_key(pool_id or "")
    count = _int(body.get("wallet_count"), field_name="wallet_count",
                 minimum=facts.ACTIVATE_BATCH_MIN, maximum=facts.ACTIVATE_BATCH_MAX,
                 required=False, default=facts.ACTIVATE_BATCH_SIZE)
    return ProvisionDraft(pool_id=pool_id or "",
                          wallet_count=int(count or facts.ACTIVATE_BATCH_SIZE))


def parse_activate(body: Mapping[str, Any]) -> ActivateDraft:
    if body:
        require_known_keys(body, ("signing_request_id", "reason"))
    signing_request_id = _text(body.get("signing_request_id"),
                               field_name="signing_request_id", min_len=1, max_len=64,
                               required=False)
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_TEXT_LEN, required=False)
    return ActivateDraft(signing_request_id=signing_request_id, reason=reason)


def parse_switch(body: Mapping[str, Any]) -> SwitchDraft:
    require_known_keys(body, ("pool_id", "reason"))
    pool_id = _text(body.get("pool_id"), field_name="pool_id", min_len=5, max_len=64)
    policy.split_pool_key(pool_id or "")
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_TEXT_LEN)
    return SwitchDraft(pool_id=pool_id or "", reason=reason or "")


def parse_retire(body: Mapping[str, Any]) -> RetireDraft:
    require_known_keys(body, ("wallet_id", "step", "attestation_ref", "reason"))
    wallet_id = _text(body.get("wallet_id"), field_name="wallet_id", min_len=1, max_len=64)
    step = _text(body.get("step"), field_name="step", min_len=3, max_len=16)
    if step not in ("drain", "zero", "frozen", "retire"):
        raise BadRequest("step 必须是 drain / zero / frozen / retire 之一", field="step")
    attestation = _text(body.get("attestation_ref"), field_name="attestation_ref", min_len=1,
                        max_len=128, required=False)
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_TEXT_LEN, required=False)
    return RetireDraft(wallet_id=wallet_id or "", step=step or "",
                       attestation_ref=attestation, reason=reason)


def parse_signing_event(body: Mapping[str, Any]) -> SigningEventDraft:
    require_known_keys(body, ("event", "signer_type", "signer_ref", "signature_hash",
                              "device_id", "auth_hash", "txid", "error_code", "occurred_at"))
    event = _text(body.get("event"), field_name="event", min_len=1, max_len=32)
    if event not in facts.SIGNING_EVENTS:
        raise BadRequest(f"event 必须是 {list(facts.SIGNING_EVENTS)} 之一", field="event")
    signer_type = _text(body.get("signer_type"), field_name="signer_type", min_len=1, max_len=16)
    if signer_type not in facts.SIGNER_TYPES:
        raise BadRequest(f"signer_type 必须是 {list(facts.SIGNER_TYPES)} 之一",
                         field="signer_type")
    signature_hash = _text(body.get("signature_hash"), field_name="signature_hash", min_len=16,
                           max_len=128, required=False)
    occurred_at = (clock.parse_datetime(body["occurred_at"], field="occurred_at")
                   if body.get("occurred_at") is not None else None)
    return SigningEventDraft(
        event=event or "", signer_type=signer_type or "",
        signer_ref=_text(body.get("signer_ref"), field_name="signer_ref", min_len=1,
                         max_len=128, required=False),
        signature_hash=signature_hash,
        device_id=_text(body.get("device_id"), field_name="device_id", min_len=1, max_len=128,
                        required=False),
        auth_hash=_text(body.get("auth_hash"), field_name="auth_hash", min_len=1, max_len=128,
                        required=False),
        txid=_text(body.get("txid"), field_name="txid", min_len=1, max_len=128, required=False),
        error_code=_text(body.get("error_code"), field_name="error_code", min_len=1,
                         max_len=64, required=False),
        occurred_at=occurred_at)


def parse_address(body: Mapping[str, Any], *, account_id: str) -> AddressDraft:
    require_known_keys(body, ("chain", "address", "ownership_challenge_ref", "risk_level",
                              "label"))
    chain = _text(body.get("chain"), field_name="chain", min_len=1, max_len=32,
                  required=False) or facts.CHAIN_ID
    if chain != facts.CHAIN_ID:
        raise ChainUnsupported("一期仅 Polygon（K6）", reason="chain_unsupported")
    address = _address(body.get("address"))
    challenge = _text(body.get("ownership_challenge_ref"),
                      field_name="ownership_challenge_ref", min_len=1, max_len=128)
    risk = _text(body.get("risk_level"), field_name="risk_level", min_len=1, max_len=16,
                 required=False) or "low"
    if risk.lower() not in ("low", "medium", "high"):
        raise BadRequest("risk_level 必须是 low / medium / high", field="risk_level")
    label = _text(body.get("label"), field_name="label", min_len=1, max_len=128,
                  required=False)
    return AddressDraft(account_id=account_id, chain_id=chain, address=address,
                        ownership_challenge_ref=challenge or "", risk_level=risk.lower(),
                        label=label)


def parse_gas_policy(body: Mapping[str, Any]) -> GasPolicyDraft:
    require_known_keys(body, ("gas_mode", "gas_bearer", "scope", "reason"))
    raw_mode = _text(body.get("gas_mode"), field_name="gas_mode", min_len=1, max_len=32)
    bearer = _text(body.get("gas_bearer"), field_name="gas_bearer", min_len=1, max_len=16,
                   required=False)
    mode = policy.normalize_gas_mode(raw_mode, bearer)
    bearer_normalized = (str(bearer).strip().upper() if bearer else None)
    if mode in (facts.GAS_MODE_EXTERNAL_PLATFORM, facts.GAS_MODE_EXTERNAL_PAYER):
        if bearer_normalized not in ("PLATFORM", "PAYER"):
            raise BadRequest("EXTERNAL_* 必须指定 gas_bearer（PLATFORM / PAYER）",
                             field="gas_bearer")
        expected = ("PLATFORM" if mode == facts.GAS_MODE_EXTERNAL_PLATFORM else "PAYER")
        if bearer_normalized != expected:
            raise BadRequest(f"gas_bearer 与 gas_mode 不一致（应为 {expected}）",
                             field="gas_bearer")
    else:
        if bearer_normalized is not None:
            raise BadRequest("INTERNAL 时 gas_bearer 必须为 null", field="gas_bearer")
    scope = _text(body.get("scope"), field_name="scope", min_len=1, max_len=16,
                  required=False) or "global"
    if scope not in ("global", "chain", "batch"):
        raise BadRequest("scope 必须是 global / chain / batch 之一", field="scope")
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_TEXT_LEN, required=False)
    return GasPolicyDraft(gas_mode=mode, gas_bearer=bearer_normalized, scope=scope,
                          reason=reason)


def parse_deposit_address(body: Mapping[str, Any]) -> DepositAddressDraft:
    require_known_keys(body, ("chain", "address", "reason", "ticket", "effective_at"))
    chain = _text(body.get("chain"), field_name="chain", min_len=1, max_len=32)
    if chain != facts.CHAIN_ID:
        raise ChainUnsupported("一期仅 Polygon（K6）", reason="chain_unsupported")
    address = _address(body.get("address"))
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_TEXT_LEN)
    ticket = _text(body.get("ticket"), field_name="ticket", min_len=1, max_len=64)
    effective_at = (clock.parse_datetime(body["effective_at"], field="effective_at")
                    if body.get("effective_at") is not None else None)
    return DepositAddressDraft(chain=chain or "", address=address, reason=reason or "",
                               ticket=ticket or "", effective_at=effective_at)


def parse_payout_approve(body: Mapping[str, Any]) -> dict[str, Any]:
    if body:
        require_known_keys(body, ("note",))
    note = _text(body.get("note"), field_name="note", min_len=1, max_len=facts.MAX_TEXT_LEN,
                 required=False)
    return {"note": note}


# ═══════════════════════════════════════════════════════════ 行 → 对客 payload
def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return clock.iso(value)
    return str(value)


def order_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """PaymentOrder（spec 1.2.5）。"""
    return {
        "order_id": str(row.get("order_id")),
        "order_no": row.get("order_no"),
        "amount_minor": int(row.get("amount_minor") or 0),
        "currency": row.get("currency"),
        "method": row.get("method"),
        "provider": row.get("provider"),
        "status": row.get("status"),
        "credited_minor": int(row.get("credited_minor") or 0),
        "description": row.get("description"),
        "expires_at": _iso(row.get("expires_at")),
        "paid_at": _iso(row.get("paid_at")),
        "credited_at": _iso(row.get("credited_at")),
        "created_at": _iso(row.get("created_at")),
    }


def attempt_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """PaymentAttempt（spec 1.2.5）。"""
    return {
        "attempt_id": str(row.get("attempt_id")),
        "provider": row.get("provider"),
        "provider_status": row.get("provider_status"),
        "status": row.get("status"),
        "amount_minor": (None if row.get("amount_minor") is None
                         else int(row.get("amount_minor"))),
        "currency": row.get("currency"),
        "signature_verified": bool(row.get("signature_verified")),
        "failure_code": row.get("failure_code"),
        "created_at": _iso(row.get("created_at")),
    }


def order_detail_payload(order: Mapping[str, Any], attempts: Sequence[Mapping[str, Any]]
                         ) -> dict[str, Any]:
    """PaymentOrderDetail：{order, attempts}。"""
    return {"order": order_payload(order),
            "attempts": [attempt_payload(item) for item in attempts]}


def webhook_ack_payload(*, order: Mapping[str, Any] | None, duplicate: bool = False,
                        provider_txn_id: str | None = None) -> dict[str, Any]:
    """PaymentWebhookAck（received 恒 true；重复回调 409 + 40910 由 router 处理）。"""
    return {
        "received": True,
        "duplicate": bool(duplicate),
        "order_no": None if order is None else order.get("order_no"),
        "provider_txn_id": provider_txn_id,
        "status": None if order is None else order.get("status"),
    }


def wallet_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """TreasuryWallet（spec 1.2.5）：fund_class 归一为 CLIENT / PLATFORM，role 独立。"""
    storage_pool_id = row.get("pool_id")
    fund_class = policy.canonical_fund_class(row.get("fund_class")) if row.get("fund_class") else None
    role = row.get("pool_role") or row.get("role")
    return {
        "wallet_id": row.get("wallet_id"),
        "chain": row.get("chain_id"),
        "address": row.get("address"),
        "pool_id": (policy.canonical_pool_id(storage_pool_id) if storage_pool_id else None),
        "role": role,
        "fund_class": fund_class,
        "status": row.get("status"),
        "switch_state": row.get("switch_state"),
        "cap_minor": None if row.get("cap_minor") is None else int(row.get("cap_minor")),
        "balance_minor": int(row.get("balance_minor") or 0),
        "gas_ok": bool(row.get("gas_ok")),
        "ready": row.get("status") == "active" and bool(row.get("gas_ok")),
        "provisioned_at": _iso(row.get("provisioned_at")),
        "activated_at": _iso(row.get("activated_at")),
        "retired_at": _iso(row.get("retired_at")),
    }


def pool_payload(row: Mapping[str, Any], wallets: Sequence[Mapping[str, Any]] | None = None
                 ) -> dict[str, Any]:
    """TreasuryPool（spec 1.2.5）。"""
    payload = {
        "pool_id": policy.canonical_pool_id(row.get("pool_id") or ""),
        "chain": row.get("chain_id") or row.get("chain"),
        "role": row.get("role"),
        "fund_class": (policy.canonical_fund_class(row.get("fund_class"))
                       if row.get("fund_class") else None),
        "status": row.get("status") or row.get("pool_status"),
        "min_spare": int(row.get("min_spare_count") or row.get("min_spare") or 0),
        "max_active": int(row.get("max_active_count") or row.get("max_active") or 0),
        "switch_threshold_pct": int(row.get("switch_threshold_pct") or 0),
        "activate_batch_size": int(row.get("activate_batch_size") or 0),
        "provision_lead_time_h": int(row.get("provision_lead_time_h") or 0),
        "pool_cap_minor": int(row.get("pool_cap_minor") or 0),
        "depth_ready": int(row.get("depth_ready") or 0),
        "depth_available": int(row.get("depth_available") or 0),
        "in_service_count": int(row.get("in_service_count") or 0),
        "active_balance_minor": int(row.get("active_balance_minor") or 0),
        "policy_version": row.get("policy_version"),
    }
    if wallets is not None:
        payload["wallets"] = [wallet_payload(item) for item in wallets]
    return payload


def provision_batch_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """TreasuryProvisionBatch（spec 1.2.5）。"""
    return {
        "batch_id": str(row.get("batch_id")),
        "batch_no": row.get("batch_no"),
        "pool_id": (policy.canonical_pool_id(row["pool_id"])
                    if row.get("pool_id") else None),
        "kind": row.get("kind"),
        "wallet_count": int(row.get("wallet_count") or 0),
        "descriptor_merkle_root": row.get("descriptor_merkle_root"),
        "status": row.get("status"),
        "nonce": int(row.get("nonce") or 0),
        "expires_at": _iso(row.get("expires_at")),
        "signing_request_id": (None if row.get("signing_request_id") is None
                               else str(row.get("signing_request_id"))),
        "activated_at": _iso(row.get("activated_at")),
        "created_at": _iso(row.get("created_at")),
    }


def activate_payload(batch: Mapping[str, Any]) -> dict[str, Any]:
    return provision_batch_payload(batch)


def switch_ack_payload(*, pool_id: str, status: str, from_wallet_id: str | None,
                       to_wallet_id: str | None, switched_at: datetime | None,
                       plan: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """TreasurySwitchAck（status ∈ triggered / executing / done）。"""
    payload = {
        "pool_id": policy.canonical_pool_id(pool_id),
        "status": status,
        "from_wallet_id": from_wallet_id,
        "to_wallet_id": to_wallet_id,
        "switched_at": _iso(switched_at),
    }
    if plan is not None:
        payload["pool_empty_plan"] = dict(plan)
    return payload


def payout_item_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """PayoutItem（spec 1.2.5）。"""
    return {
        "item_id": str(row.get("item_id")),
        "payee_account_id": row.get("payee_account_id"),
        "payee_address": row.get("payee_address"),
        "gross_minor": int(row.get("gross_minor") or 0),
        "fee_minor": int(row.get("fee_minor") or 0),
        "net_minor": int(row.get("net_minor") or 0),
        "status": row.get("status"),
        "gas_mode": row.get("gas_mode"),
        "chain_tx_id": row.get("chain_tx_id"),
        "failure_reason": row.get("failure_reason"),
    }


def payout_batch_payload(row: Mapping[str, Any], items: Sequence[Mapping[str, Any]] | None = None
                         ) -> dict[str, Any]:
    """PayoutBatch（spec 1.2.5，含 items）。"""
    payload = {
        "batch_id": str(row.get("batch_id")),
        "batch_no": row.get("batch_no"),
        "status": row.get("status"),
        "item_count": int(row.get("item_count") or 0),
        "total_gross_minor": int(row.get("total_gross_minor") or 0),
        "total_fee_minor": int(row.get("total_fee_minor") or 0),
        "total_net_minor": int(row.get("total_net_minor") or 0),
        "items_hash": row.get("items_hash"),
        "attestation_ref": row.get("attestation_ref"),
        "gas_mode": row.get("gas_mode"),
        "policy_version": row.get("policy_version"),
        "maker_id": row.get("maker_id"),
        "checker_id": row.get("checker_id"),
        "checked_at": _iso(row.get("checked_at")),
        "settled_at": _iso(row.get("settled_at")),
        "chain_tx_id": row.get("chain_tx_id"),
        "failure_reason": row.get("failure_reason"),
        "created_at": _iso(row.get("created_at")),
    }
    if items is not None:
        payload["items"] = [payout_item_payload(item) for item in items]
    return payload


def refund_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """RefundRequest（spec 1.2.5）：原路只回指纹，不回地址 / 卡令牌。"""
    return {
        "refund_request_id": str(row.get("refund_request_id")),
        "refund_no": row.get("refund_no"),
        "order_no": row.get("order_no"),
        "amount_minor": int(row.get("amount_minor") or 0),
        "currency": row.get("currency"),
        "reason_code": row.get("reason_code"),
        "status": row.get("status"),
        "original_route_hash": row.get("original_route_hash"),
        "deadline_at": _iso(row.get("deadline_at")),
        "approved_at": _iso(row.get("approved_at")),
        "succeeded_at": _iso(row.get("succeeded_at")),
        "failure_code": row.get("failure_code"),
        "created_at": _iso(row.get("created_at")),
    }


def intent_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "intent_id": str(row.get("intent_id")),
        "kind": row.get("kind"),
        "chain_id": row.get("chain_id"),
        "asset": row.get("asset"),
        "total_amount_minor": int(row.get("total_amount_minor") or 0),
        "item_count": int(row.get("item_count") or 0),
        "recipients_hash": row.get("recipients_hash"),
        "nonce": int(row.get("nonce") or 0),
        "status": row.get("status"),
        "auth_object_type": row.get("auth_object_type"),
        "expires_at": _iso(row.get("expires_at")),
        "created_at": _iso(row.get("created_at")),
    }


def signing_request_payload(request: Mapping[str, Any], *, auth_hash: str | None = None
                            ) -> dict[str, Any]:
    """SigningRequest（spec 1.2.5）：只回 auth_hash 前 16 位，不回签名字节。"""
    prefix = None
    if auth_hash:
        prefix = str(auth_hash)[:16]
    return {
        "signing_request_id": str(request.get("signing_request_id")),
        "intent_id": str(request.get("intent_id")),
        "status": request.get("status"),
        "expires_at": _iso(request.get("expires_at")),
        "signer_threshold": int(request.get("threshold_n") or facts.SIGNER_THRESHOLD),
        "auth_hash_prefix": prefix,
        "created_at": _iso(request.get("created_at")),
    }


def signing_event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "signing_event_id": str(row.get("signing_event_id")),
        "signing_request_id": str(row.get("signing_request_id")),
        "event": row.get("event"),
        "signer_type": row.get("signer_type"),
        "signature_hash": row.get("signature_hash"),
        "txid": row.get("txid"),
        "occurred_at": _iso(row.get("occurred_at")),
    }


def address_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """TreasuryAddress（spec 1.2.5）。"""
    return {
        "address_id": str(row.get("address_id")),
        "account_id": row.get("account_id"),
        "chain": row.get("chain_id"),
        "address": row.get("address"),
        "status": row.get("status"),
        "label": row.get("label"),
        "cooldown_until": _iso(row.get("cooldown_until")),
        "first_transfer_at": _iso(row.get("first_transfer_at")),
        "first_transfer_minor": (None if row.get("first_transfer_minor") is None
                                 else int(row.get("first_transfer_minor"))),
        "changed_at": _iso(row.get("changed_at")),
        "approved_at": _iso(row.get("approved_at")),
        "risk_level": row.get("risk_level"),
    }


def deposit_address_payload(row: Mapping[str, Any] | None, *, chain: str = facts.CHAIN_ID,
                            updated_at: datetime | None = None) -> dict[str, Any]:
    """DepositAddress（spec 1.2.5）：无生效地址时返回 address='' 让调用方判空？"""
    if row is None:
        return {"chain": chain, "address": "", "status": "not_configured",
                "published_at": None, "retired_at": None, "monitoring_until": None,
                "updated_at": _iso(updated_at or clock.utcnow())}
    return {
        "chain": row.get("chain_id") or chain,
        "address": row.get("address"),
        "status": row.get("status"),
        "published_at": _iso(row.get("created_at")),
        "retired_at": _iso(row.get("retired_at")),
        "monitoring_until": _iso(row.get("monitoring_until")),
        "updated_at": _iso(row.get("updated_at") or row.get("created_at") or updated_at),
    }


def gas_policy_payload(*, gas_mode: str, gas_bearer: str | None, scope: str,
                       policy_version: str, updated_at: datetime | None = None,
                       pending: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """GasPolicy（spec 1.2.5）：INTERNAL 时 gas_bearer 必须为 null。"""
    bearer = None if gas_mode == facts.GAS_MODE_INTERNAL else gas_bearer
    payload = {
        "gas_mode": gas_mode,
        "gas_bearer": bearer,
        "scope": scope,
        "policy_version": policy_version,
        "updated_at": _iso(updated_at),
    }
    if pending is not None:
        payload["pending_change"] = dict(pending)
    return payload


def page_payload(*, cursor: str | None, has_more: bool, next_cursor: str | None) -> dict[str, Any]:
    """spec Page：{cursor, has_more, next_cursor}（首页 cursor 为空串）。"""
    return {"cursor": cursor or "", "has_more": bool(has_more),
            "next_cursor": None if not has_more else next_cursor}


# ═══════════════════════════════════════════════════════════ 游标
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def encode_cursor(moment: datetime, identity: str) -> str:
    return _b64encode(f"{clock.iso_micros(moment)}|{identity}".encode("utf-8"))


def decode_cursor(cursor: str | None) -> tuple[datetime, str] | None:
    if cursor is None or cursor == "":
        return None
    if not isinstance(cursor, str) or len(cursor) > 512:
        raise BadRequest("cursor 非法", field="cursor")
    try:
        raw = _b64decode(cursor).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - base64 各种错法都归 400
        raise BadRequest("cursor 非法", field="cursor") from exc
    head, _, tail = raw.partition("|")
    if not tail:
        raise BadRequest("cursor 结构非法", field="cursor")
    moment = clock.parse_datetime(head, field="cursor")
    return moment, tail
