# SPDX-License-Identifier: Apache-2.0
"""M08c 分润出款 / 退款 / 白名单 / gas 策略。

出款（§19.8.3 maker–checker–signer 三段 + INV-10 四要素）::

    制单 draft（≤50 笔；fee >= gross 或净额 <10 USDT → carried 滚存）
      → 复核 checked（复核人 ≠ 制单人；M09 attestation 有效；累计已确认收入 ≥ 本批应付）
      → 发起签名（PAYOUT 意图 ≤30 分钟；审批后 30 分钟内可执行）
      → 六事件签齐（2/3 + HSM）→ signed
      → 广播 broadcast（HSM 联签后中继广播）
      → 达确认 settled / partial → payout.paid（E8 由 M06 消费事件入账）

退款（§19.9.2 / INV-12）：

    申请 requested（14 天窗口；原路；≤已付未消耗）→ 双人 + 24h 冷却 → approved
      → executing → succeeded（E11 由 M06 落账）→ refund.completed；失败转工单不换路

gas 三模式（03-facts §4 / INV-14）：按批次快照，下一批生效、不追溯；切换只 propose
（POLICY_CHANGE 意图），真正发布在 M10。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from . import clock, config_source, events, facts, ids, models, policy, signing, store
from .errors import (
    AttestationMissing,
    BadRequest,
    Conflict,
    NotFound,
    PayeeNotEligible,
    RefundFailed,
    RefundInProgress,
    RiskLevelRequired,
)

__all__ = [
    "create_payout_batch", "approve_payout_batch", "request_payout_signature",
    "broadcast_payout_batch", "settle_payout_batch", "payout_detail", "list_payouts",
    "provider_payouts", "submit_payout_address", "approve_payout_address",
    "list_payout_addresses", "gas_policy_view", "propose_gas_policy", "record_first_transfer",
]

RiskCheck = Callable[..., Any]
RevenueVerifier = Callable[[int], Any]


# ═══════════════════════════════════════════════════════════ 分润出款
def _resolve_address(conn: Any, item: models.PayoutItemDraft, *,
                     now: datetime) -> dict[str, Any]:
    """INV-10 第三要素：白名单生效 + 首笔 ≤100 USDT（INV-13）。"""
    address = store.get_payout_address(conn, item.payee_address)
    if address is not None and str(address["account_id"]) != item.payee_account_id:
        raise PayeeNotEligible("收款地址不属于该共享方账户（不接受第三方地址）",
                               reason="payee_not_eligible")
    policy.check_payee_eligible(address, now=now)
    if address is not None and address.get("first_transfer_at") is None:
        policy.check_first_transfer(int(item.gross_minor))
    return address or {}


def create_payout_batch(conn: Any, draft: models.PayoutBatchDraft, *, maker: str,
                        idempotency_key: str | None,
                        config_provider: config_source.ConfigProvider | None,
                        now: datetime, trace_id: str | None = None) -> dict[str, Any]:
    """制单（maker）：明细校验 → 分类（carried 滚存）→ 合计 / Merkle → draft。"""
    moment = clock.as_utc(now)
    if idempotency_key:
        replay = store.find_payout_by_idempotency(conn, idempotency_key)
        if replay is not None:
            items = store.list_payout_items(conn, str(replay["batch_id"]))
            return {"batch": replay, "items": items, "replayed": True}
    if not draft.items:
        raise BadRequest("批次必须至少 1 笔明细", field="items")
    if len(draft.items) > facts.PAYOUT_BATCH_MAX_ITEMS:
        raise BadRequest(f"同批出款笔数上限 {facts.PAYOUT_BATCH_MAX_ITEMS}", field="items")
    config = config_source.load(config_provider, chain=facts.CHAIN_ID, role="warm",
                                fund_class="customer")
    gas_mode = draft.gas_mode or config.gas_mode
    prepared: list[dict[str, Any]] = []
    for item in draft.items:
        address = _resolve_address(conn, item, now=moment)
        classified = policy.classify_payout_item(gross_minor=item.gross_minor,
                                                 fee_minor=item.fee_minor)
        prepared.append({**classified, "payee_account_id": item.payee_account_id,
                         "payee_address": item.payee_address,
                         "address_id": (address or {}).get("address_id") or item.address_id,
                         "carry_of_item_id": None})
    totals = policy.payout_totals(prepared)
    merkle = policy.items_hash(prepared)
    batch = store.insert_payout_batch(
        conn, batch_id=str(ids.uuid7()), status="draft", item_count=int(totals["item_count"]),
        totals=totals, items_hash=merkle, gas_mode=gas_mode,
        policy_version=config.policy_version, maker_id=maker,
        idempotency_key=idempotency_key, now=moment,
        attestation_ref=draft.attestation_ref)
    rows: list[dict[str, Any]] = []
    for entry in prepared:
        rows.append(store.insert_payout_item(
            conn, item_id=str(ids.uuid7()), batch_id=str(batch["batch_id"]),
            payee_account_id=str(entry["payee_account_id"]),
            payee_address=str(entry["payee_address"]),
            gross_minor=int(entry["gross_minor"]), fee_minor=int(entry["fee_minor"]),
            net_minor=int(entry["net_minor"]), status=str(entry["status"]),
            gas_mode=gas_mode, policy_version=config.policy_version,
            address_id=entry.get("address_id"), carry_of_item_id=entry.get("carry_of_item_id"),
            now=moment))
    batch = store.update_payout_batch(conn, str(batch["batch_id"]), status="prepared")
    return {"batch": batch, "items": rows, "replayed": False,
            "carried_count": sum(1 for row in rows if row["status"] == "carried"),
            "gas_mode": gas_mode, "policy_version": config.policy_version}


def approve_payout_batch(conn: Any, batch_id: str, *, checker: str,
                         attestation_checker: Callable[[str | None], bool],
                         revenue_verifier: RevenueVerifier | None,
                         now: datetime, note: str | None = None) -> dict[str, Any]:
    """复核（checker）：SoD + attestation（40916）+ 收入覆盖校验 → checked。

    说明：spec 1.2.5 的 PayoutApproveRequest 只有 note（不含 attestation_ref）——
    attestation_ref 在制单时写入批次（PayoutBatchCreateRequest.attestation_ref），
    复核时按该引用向 M09 校验（attestation_checker 由接线注入）。
    """
    batch = store.get_payout_batch(conn, batch_id, lock=True)
    if batch is None:
        raise NotFound("出款批次不存在")
    if batch["status"] in facts.PAYOUT_BATCH_TERMINAL:
        raise Conflict(f"批次已是终态：{batch['status']}", reason="batch_terminal")
    if batch["status"] not in ("draft", "prepared"):
        raise Conflict(f"批次状态 {batch['status']} 不允许复核", reason="illegal_transition")
    policy.ensure_separation(str(batch["maker_id"]), checker)
    ref = batch.get("attestation_ref")
    policy.ensure_attestation(attestation_ref=ref,
                              valid=bool(attestation_checker(ref)))
    items = store.list_payout_items(conn, str(batch["batch_id"]))
    if revenue_verifier is not None:
        verdict = revenue_verifier(int(batch["total_net_minor"]))
        if verdict is False or str(verdict).lower() in ("insufficient", "deny"):
            raise Conflict("累计已确认收入不足本批应付：拒绝复核（§19.8.3）",
                           reason="insufficient_revenue")
    moment = clock.as_utc(now)
    batch = store.update_payout_batch(
        conn, str(batch["batch_id"]), status="checked", checker_id=checker,
        checked_at=moment, attestation_ref=str(ref), attestation_valid=True,
        failure_reason=note)
    return {"batch": batch, "items": items}


def request_payout_signature(conn: Any, batch_id: str, *, actor: str, now: datetime,
                             trace_id: str | None = None,
                             idempotency_key: str | None = None) -> dict[str, Any]:
    """发起决策人签名请求（不是签名）：PAYOUT 意图 ≤30 分钟，明细冻结。"""
    batch = store.get_payout_batch(conn, batch_id, lock=True)
    if batch is None:
        raise NotFound("出款批次不存在")
    if batch["status"] not in ("checked",):
        raise Conflict(f"批次状态 {batch['status']} 不允许发起签名（须先复核 checked）",
                       reason="illegal_transition")
    moment = clock.as_utc(now)
    if not policy.approval_window_open(checked_at=batch.get("checked_at"), now=moment):
        raise Conflict("审批后 30 分钟窗口已过：批次作废，需重新复核（§19.11.3）",
                       reason="approval_expired")
    if batch.get("signing_request_id"):
        existing = store.get_signing_request(conn, str(batch["signing_request_id"]))
        if existing is not None:
            return {"batch": batch, "intent": None, "signing_request": existing,
                    "replayed": True}
    items = store.list_payout_items(conn, str(batch["batch_id"]))
    recipients = policy.items_hash(items)
    result = signing.request_signature(
        conn, kind="PAYOUT", chain_id=facts.CHAIN_ID, asset=facts.PAYOUT_ASSET,
        total_amount_minor=int(batch["total_net_minor"]), item_count=int(batch["item_count"]),
        recipients_hash=recipients, policy_version=str(batch["policy_version"]),
        created_by=actor, correlation_id=str(batch["batch_no"]), now=moment,
        trace_id=trace_id, idempotency_key=idempotency_key,
        memo=f"PAYOUT {batch['batch_no']} net={batch['total_net_minor']}")
    batch = store.update_payout_batch(
        conn, str(batch["batch_id"]),
        signing_request_id=str(result["signing_request"]["signing_request_id"]),
        intent_id=str(result["intent"]["intent_id"]))
    return {"batch": batch, "intent": result["intent"],
            "signing_request": result["signing_request"], "replayed": False}


def broadcast_payout_batch(conn: Any, batch_id: str, *, txid: str, actor: str,
                           now: datetime) -> dict[str, Any]:
    """HSM 联签后广播：2/3 未齐 → 拒绝；广播只更新状态与 txid，不重复付款。"""
    batch = store.get_payout_batch(conn, batch_id, lock=True)
    if batch is None:
        raise NotFound("出款批次不存在")
    if batch["status"] == "broadcast":
        raise Conflict("批次已广播（幂等拒绝重复广播）", reason="already_broadcast")
    if batch["status"] not in ("checked", "signed"):
        raise Conflict(f"批次状态 {batch['status']} 不允许广播", reason="illegal_transition")
    if not batch.get("signing_request_id"):
        raise Conflict("批次未发起签名请求，不得广播（INV-10）", reason="signature_missing")
    signing.require_signed(conn, str(batch["signing_request_id"]))
    moment = clock.as_utc(now)
    items = store.list_payout_items(conn, str(batch["batch_id"]))
    for item in items:
        if item["status"] == "pending":
            store.update_payout_item(conn, str(item["item_id"]), status="sent",
                                     chain_tx_id=txid)
    batch = store.update_payout_batch(conn, str(batch["batch_id"]), status="broadcast",
                                      broadcast_at=moment, chain_tx_id=txid,
                                      signed_at=batch.get("signed_at") or moment)
    return {"batch": batch, "txid": txid}


def settle_payout_batch(conn: Any, batch_id: str, *, txid: str | None, actor: str,
                        now: datetime, trace_id: str | None = None) -> dict[str, Any]:
    """达确认：settled / partial → payout.paid（E8 由 M06 消费事件；本层不记账）。"""
    batch = store.get_payout_batch(conn, batch_id, lock=True)
    if batch is None:
        raise NotFound("出款批次不存在")
    if batch["status"] in facts.PAYOUT_BATCH_TERMINAL:
        raise Conflict(f"批次已是终态：{batch['status']}", reason="batch_terminal")
    if batch["status"] != "broadcast":
        raise Conflict("未广播的批次不得结算（未确认不得标 settled）",
                       reason="illegal_transition")
    items = store.list_payout_items(conn, str(batch["batch_id"]))
    failed = [item for item in items if str(item["status"]) == "failed"]
    moment = clock.as_utc(now)
    status = "partial" if failed else "settled"
    batch = store.update_payout_batch(conn, str(batch["batch_id"]), status=status,
                                      settled_at=moment,
                                      chain_tx_id=txid or batch.get("chain_tx_id"))
    events.payout_paid(conn, batch, txid=str(txid or batch.get("chain_tx_id") or ""),
                       settled_at=moment, trace_id=trace_id)
    for item in items:
        if item["status"] == "sent":
            record_first_transfer(conn, str(item["payee_address"]),
                                  amount_minor=int(item["gross_minor"]), now=moment)
    return {"batch": batch, "items": items, "failed_count": len(failed)}


def record_first_transfer(conn: Any, address: str, *, amount_minor: int,
                          now: datetime) -> None:
    """首笔试转落痕（≤100 USDT 已在上游校验；这里只记录事实）。"""
    row = store.get_payout_address(conn, address)
    if row is None or row.get("first_transfer_at") is not None:
        return
    policy.check_first_transfer(int(amount_minor))
    store.update_payout_address(conn, str(row["address_id"]),
                                first_transfer_at=clock.as_utc(now),
                                first_transfer_minor=int(amount_minor))


def payout_detail(conn: Any, identifier: str) -> dict[str, Any]:
    batch = store.get_payout_batch(conn, identifier)
    if batch is None:
        raise NotFound("出款批次不存在")
    items = store.list_payout_items(conn, str(batch["batch_id"]))
    return models.payout_batch_payload(batch, items)


def list_payouts(conn: Any, *, status: str | None = None, cursor: str | None = None,
                 limit: int = facts.DEFAULT_PAGE_SIZE
                 ) -> tuple[list[dict[str, Any]], bool, str | None]:
    rows, has_more, next_cursor = store.list_payout_batches(conn, status=status,
                                                            cursor=cursor, limit=limit)
    return ([models.payout_batch_payload(row) for row in rows], has_more, next_cursor)


def provider_payouts(conn: Any, *, account_id: str, status: str | None = None,
                     from_ts: datetime | None = None, to_ts: datetime | None = None,
                     cursor: str | None = None, limit: int = facts.DEFAULT_PAGE_SIZE
                     ) -> tuple[list[dict[str, Any]], bool, str | None]:
    """共享方视角：只出自己的批次与明细（不含他人明细 / 制单复核人）。"""
    if status is not None and status not in facts.PAYOUT_BATCH_STATUSES:
        raise BadRequest(f"status 必须是 {list(facts.PAYOUT_BATCH_STATUSES)} 之一",
                         field="status")
    rows, _has_more, _cursor = store.list_payout_batches(
        conn, status=status, cursor=cursor, limit=int(limit) + 1)
    payloads: list[dict[str, Any]] = []
    for batch in rows:
        if batch["status"] in ("draft", "prepared"):
            continue
        created = clock.as_utc(batch["created_at"])
        if from_ts is not None and created < clock.as_utc(from_ts):
            continue
        if to_ts is not None and created > clock.as_utc(to_ts):
            continue
        items = [item for item in store.list_payout_items(conn, str(batch["batch_id"]))
                 if str(item["payee_account_id"]) == str(account_id)]
        if not items:
            continue
        payload = models.payout_batch_payload(batch, items)
        payload.pop("maker_id", None)
        payload.pop("checker_id", None)
        payloads.append(payload)
    has_more = len(payloads) > int(limit)
    payloads = payloads[:int(limit)]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = models.encode_cursor(last["created_at"], str(last["batch_id"]))
    return payloads, has_more, next_cursor


# ═══════════════════════════════════════════════════════════ 收款地址白名单（INV-13）
def submit_payout_address(conn: Any, draft: models.AddressDraft, *, idempotency_key: str | None,
                          now: datetime) -> dict[str, Any]:
    """共享方新增 / 变更收款地址：所有权挑战必填（42210）、风险拒绝（42211）、24h 变更冷却。"""
    if not draft.ownership_challenge_ref:
        raise PayeeNotEligible("出款主体未通过准入：缺地址所有权挑战（42210）",
                               reason="payee_not_eligible")
    if draft.risk_level == "high":
        from .errors import AddressRiskRejected

        raise AddressRiskRejected("地址风险评分过高：拒绝（42211）",
                                  reason="address_risk_rejected")
    moment = clock.as_utc(now)
    if idempotency_key:
        replay = store.find_payout_address_by_idempotency(conn, idempotency_key)
        if replay is not None:
            return {"address": replay, "replayed": True}
    existing = store.find_payout_address_by_key(conn, draft.account_id, draft.chain_id,
                                                draft.address)
    if existing is not None:
        return {"address": existing, "replayed": True}
    previous = [row for row in store.list_payout_addresses(conn, account_id=draft.account_id)
                if row["status"] == "whitelisted"]
    if previous:
        policy.check_address_change_allowed(
            changed_at=previous[0]["changed_at"], next_payout_at=None, now=moment)
    verified_at = moment
    address = store.insert_payout_address(
        conn, address_id=str(ids.uuid7()), account_id=draft.account_id,
        chain_id=draft.chain_id, address=draft.address, status="pending",
        ownership_challenge_ref=draft.ownership_challenge_ref,
        ownership_verified_at=verified_at, risk_level=draft.risk_level,
        cooldown_until=policy.address_cooldown_until(verified_at), changed_at=moment,
        approved_by=None, approved_at=None, idempotency_key=idempotency_key, now=moment,
        label=draft.label)
    return {"address": address, "replayed": False,
            "cooldown_until": address["cooldown_until"]}


def approve_payout_address(conn: Any, address_id: str, *, approver: str,
                           risk_check: RiskCheck | None, now: datetime) -> dict[str, Any]:
    """管理面审批白名单：待审 → whitelisted（72h 冷却仍生效）；风险不足 → 40312。"""
    address = store.get_payout_address_by_id(conn, address_id, lock=True)
    if address is None:
        raise NotFound("收款地址不存在")
    if address["status"] == "whitelisted":
        return {"address": address, "replayed": True}
    if address["status"] in ("rejected", "revoked"):
        raise Conflict(f"地址已是终态：{address['status']}", reason="address_terminal")
    if address.get("risk_level") == "high":
        from .errors import AddressRiskRejected

        raise AddressRiskRejected("地址风险评分过高：拒绝审批（42211）",
                                  reason="address_risk_rejected")
    if risk_check is not None:
        verdict = risk_check(account_id=str(address["account_id"]),
                             address=str(address["address"]),
                             risk_level=address.get("risk_level"))
        if verdict is False or str(verdict).lower() in ("deny", "blocked", "insufficient"):
            raise RiskLevelRequired("完成风控验证后可出款（40312）", reason="risk_level_required")
    moment = clock.as_utc(now)
    # 72h 冷却从**所有权验证 / 登记**时刻起算（INV-13）；审批只决定是否进入白名单，
    # 不重置冷却与 changed_at（出款前 7 天禁改看的是地址变更时刻）。
    updated = store.update_payout_address(
        conn, str(address["address_id"]), status="whitelisted", approved_by=approver,
        approved_at=moment)
    return {"address": updated, "replayed": False}


def list_payout_addresses(conn: Any, *, account_id: str | None = None
                          ) -> list[dict[str, Any]]:
    rows = store.list_payout_addresses(conn, account_id=account_id)
    return [models.address_payload(row) for row in rows]


# ═══════════════════════════════════════════════════════════ gas 三模式（INV-14）
def gas_policy_view(conn: Any, *, config_provider: config_source.ConfigProvider | None = None,
                    now: datetime | None = None, pending: Mapping[str, Any] | None = None
                    ) -> dict[str, Any]:
    """GasPolicy（spec 1.2.5）：生效值 + policy_version；pending_change 为已登记未发布提案。"""
    config = config_source.load(config_provider, chain=facts.CHAIN_ID, role="warm",
                                fund_class="customer")
    rows, _has_more, _cursor = store.list_payout_batches(conn, limit=1)
    last = rows[0] if rows else None
    payload = models.gas_policy_payload(
        gas_mode=config.gas_mode, gas_bearer=config.gas_bearer, scope="global",
        policy_version=config.policy_version, updated_at=now,
        pending=pending)
    payload["takes_effect"] = "next_batch"
    payload["config_source"] = config.source
    payload["modes"] = list(facts.GAS_MODES)
    payload["asset"] = facts.PAYOUT_ASSET
    payload["chain"] = facts.CHAIN_ID
    payload["last_batch_snapshot"] = (None if last is None else
                                      {"batch_no": last["batch_no"],
                                       "gas_mode": last["gas_mode"],
                                       "policy_version": last["policy_version"]})
    return payload


def propose_gas_policy(conn: Any, draft: models.GasPolicyDraft, *, actor: str,
                       config_provider: config_source.ConfigProvider | None,
                       now: datetime, trace_id: str | None = None
                       ) -> dict[str, Any]:
    """只 propose：POLICY_CHANGE 意图 + 签名请求；发布在 M10（本模块不写配置）。"""
    config = config_source.load(config_provider, chain=facts.CHAIN_ID, role="warm",
                                fund_class="customer")
    result = signing.request_signature(
        conn, kind="POLICY_CHANGE", chain_id=facts.CHAIN_ID, asset=facts.PAYOUT_ASSET,
        total_amount_minor=0, item_count=0, recipients_hash=None,
        policy_version=config.policy_version, created_by=actor,
        correlation_id=f"gas_policy:{draft.scope}", now=now, trace_id=trace_id,
        memo=f"gas_mode {config.gas_mode} -> {draft.gas_mode}; bearer {draft.gas_bearer}")
    pending = {"gas_mode": draft.gas_mode, "gas_bearer": draft.gas_bearer,
               "scope": draft.scope, "intent_id": str(result["intent"]["intent_id"]),
               "signing_request_id": str(
                   result["signing_request"]["signing_request_id"]),
               "takes_effect": "next_batch"}
    payload = gas_policy_view(conn, config_provider=config_provider, now=now, pending=pending)
    payload["note"] = "本接口只 propose（POLICY_CHANGE 意图）；发布由 M10 决策，下一批生效"
    return {"policy": payload, "intent": result["intent"],
            "signing_request": result["signing_request"]}
