# SPDX-License-Identifier: Apache-2.0
"""M08 资金意图与签名六事件（M08 §3 / §8.2 / 产品 §19.5.2 / §19.11.4）。

边界：**只 propose，不持钥**。

* 本模块创建 treasury_intent（EIP-712 摘要字段）+ signing_request（2-of-3 门限），
  推送签名事件（signing.requested）；真正的签名发生在决策人设备 / HSM，本模块只**记录**
  六事件（requested → presented → signed → verified → co_signed → broadcast）；
* 不存私钥 / 助记词 / 完整签名：signature_hash 只存哈希，device_id 只存引用；
* 有效期：普通动作 ≤30 分钟，WALLET_PROVISION ≤24h（库层 CHECK + 本层判定双保险）；
* 2/3 判据：owner 签（signed）+ 复核人 / 公司签（co_signed）+ HSM 验签（verified）
  且签名人数 ≥ 门限；缺一不得进入下一阶段（INV-10）。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Mapping

from . import clock, events, facts, ids, models, policy, store
from .errors import BadRequest, Conflict, NotFound

__all__ = [
    "request_signature", "record_event", "require_signed", "signing_view", "intent_summary",
    "WALLET_SIGNER_SET",
]

#: 签名人集合引用（决策人 / 对账复核人 / 公司 HSM 三位；只存引用不存身份）
WALLET_SIGNER_SET = "signers:owner+reviewer+company"


def _digest(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def request_signature(conn: Any, *, kind: str, chain_id: str, asset: str,
                      total_amount_minor: int, item_count: int, recipients_hash: str | None,
                      policy_version: str, created_by: str, correlation_id: str | None,
                      now: datetime, trace_id: str | None = None,
                      signer_set_ref: str | None = None,
                      idempotency_key: str | None = None,
                      memo: str | None = None) -> dict[str, Any]:
    """创建资金意图 + 签名请求 + signing.requested（同一事务）。"""
    if kind not in facts.INTENT_KINDS:
        raise BadRequest(f"kind 必须是 {list(facts.INTENT_KINDS)} 之一", field="kind")
    moment = clock.as_utc(now)
    expires_at = policy.intent_expires_at(kind, moment)
    intent_id = str(ids.uuid7())
    memo_hash = _digest(memo) if memo else None
    intent = store.insert_intent(
        conn, intent_id=intent_id, kind=kind, chain_id=chain_id, asset=asset,
        total_amount_minor=int(total_amount_minor), item_count=int(item_count),
        recipients_hash=recipients_hash, status="signing", policy_version=policy_version,
        memo_hash=memo_hash, created_by=created_by, correlation_id=correlation_id,
        idempotency_key=idempotency_key, expires_at=expires_at, now=moment)
    signing_request_id = str(ids.uuid7())
    signing = store.insert_signing_request(
        conn, signing_request_id=signing_request_id, intent_id=intent_id, kind=kind,
        status="pending", signer_set_ref=signer_set_ref or WALLET_SIGNER_SET,
        threshold_n=facts.SIGNER_THRESHOLD, signer_count_n=facts.SIGNER_COUNT,
        policy_version=policy_version, requested_at=moment, expires_at=expires_at,
        created_by=created_by, idempotency_key=idempotency_key, now=moment)
    store.insert_signing_event(
        conn, signing_event_id=str(ids.uuid7()), signing_request_id=signing_request_id,
        event="requested", signer_type="owner", signer_ref=created_by,
        signature_hash=None, device_id=None, auth_hash=None, txid=None, error_code=None,
        occurred_at=moment)
    events.signing_requested(conn, intent=intent, signing_request_id=signing_request_id,
                             signer_type="owner", trace_id=trace_id)
    return {"intent": intent, "signing_request": signing}


def _apply_milestone(conn: Any, signing_request_id: str, event: str,
                     occurred_at: datetime, *, auth_hash: str | None,
                     txid: str | None) -> dict[str, Any]:
    """到达某个阶段时回填对应时间戳（presented/signed/verified/co_signed/broadcast）。"""
    field_by_event = {
        "presented": "presented_at", "signed": "signed_at", "verified": "verified_at",
        "co_signed": "co_signed_at", "broadcast": "broadcast_at",
    }
    fields: dict[str, Any] = {}
    name = field_by_event.get(event)
    if name is not None:
        fields[name] = occurred_at
    if auth_hash:
        fields["auth_hash"] = auth_hash
    if txid:
        fields["txid"] = txid
    if not fields:
        return store.get_signing_request(conn, signing_request_id) or {}
    return store.update_signing_request(conn, signing_request_id, **fields)


def record_event(conn: Any, signing_request_id: str, draft: models.SigningEventDraft,
                 *, actor: str | None = None, now: datetime | None = None,
                 trace_id: str | None = None) -> dict[str, Any]:
    """记录签名六事件（幂等 + 顺序 + 阶段推进）；返回 {request, event, complete}。"""
    moment = clock.as_utc(draft.occurred_at or now or clock.utcnow())
    request = store.get_signing_request(conn, signing_request_id, lock=True)
    if request is None:
        raise NotFound("签名请求不存在")
    if request["status"] in ("signed", "expired", "failed"):
        raise Conflict(f"签名请求已是终态：{request['status']}", reason="signing_closed")
    intent = store.get_intent(conn, str(request["intent_id"]))
    if intent is None:
        raise NotFound("资金意图不存在")
    policy.check_intent_alive(str(intent["kind"]), intent["created_at"],
                              intent["expires_at"], moment)
    last = store.last_signing_event(conn, signing_request_id)
    policy.ensure_stage_order(last["event"] if last else None, draft.event)

    event_row = store.insert_signing_event(
        conn, signing_event_id=str(ids.uuid7()), signing_request_id=str(signing_request_id),
        event=draft.event, signer_type=draft.signer_type, signer_ref=draft.signer_ref,
        signature_hash=draft.signature_hash, device_id=draft.device_id,
        auth_hash=draft.auth_hash, txid=draft.txid, error_code=draft.error_code,
        occurred_at=moment)
    _apply_milestone(conn, str(signing_request_id), draft.event, moment,
                     auth_hash=draft.auth_hash, txid=draft.txid)
    if draft.event in ("signed", "co_signed"):
        events.signing_signed(conn, intent=intent, signing_request_id=str(signing_request_id),
                              signer_type=draft.signer_type, signed_at=moment, trace_id=trace_id)
    all_events = store.list_signing_events(conn, signing_request_id)
    complete = policy.signing_complete(all_events)
    counts = store.signed_counts(conn, signing_request_id)
    signed_total = int(counts["signed"]) + int(counts["co_signed"])
    fields: dict[str, Any] = {"signed_count": min(signed_total, int(request["signer_count_n"]))}
    if complete:
        fields["status"] = "signed"
    request = store.update_signing_request(conn, str(signing_request_id), **fields)
    if intent["status"] == "proposed":
        store.update_intent(conn, str(intent["intent_id"]), status="signing")
    advanced = None
    if complete:
        advanced = _advance_owner(conn, intent, request, moment)
    return {"request": request, "event": event_row, "complete": complete,
            "signed_count": signed_total, "advanced": advanced}


def _advance_owner(conn: Any, intent: Mapping[str, Any], request: Mapping[str, Any],
                   moment: datetime) -> dict[str, Any] | None:
    """签齐后推进 Owner 聚合：PAYOUT 批次 → signed；WALLET_PROVISION 批次 → signed。"""
    kind = str(intent["kind"])
    if kind == "PAYOUT":
        batch = store.find_payout_by_intent(conn, str(intent["intent_id"]), lock=True)
        if batch is not None and batch["status"] == "checked":
            updated = store.update_payout_batch(
                conn, str(batch["batch_id"]), status="signed", signed_at=moment)
            return {"owner_type": "payout_batch", "batch_id": str(updated["batch_id"]),
                    "status": updated["status"]}
    if kind == "WALLET_PROVISION":
        batch = store.find_provision_by_signing_request(
            conn, str(request["signing_request_id"]), lock=True)
        if batch is not None and batch["status"] == "pending_sign":
            updated = store.update_provision_batch(
                conn, str(batch["batch_id"]), status="signed")
            return {"owner_type": "wallet_provision_batch",
                    "batch_id": str(updated["batch_id"]), "status": updated["status"]}
    return None


def require_signed(conn: Any, signing_request_id: str) -> dict[str, Any]:
    """INV-10：2/3 签名未齐 → 40919（不得激活 / 不得广播）。"""
    request = store.get_signing_request(conn, signing_request_id)
    if request is None:
        raise NotFound("签名请求不存在")
    all_events = store.list_signing_events(conn, signing_request_id)
    if not policy.signing_complete(all_events):
        raise Conflict("2/3 签名未齐（或缺 HSM 验签）：拒绝进入下一阶段（INV-10）",
                       reason="signature_incomplete")
    return request


def signing_view(conn: Any, signing_request_id: str) -> dict[str, Any]:
    request = store.get_signing_request(conn, signing_request_id)
    if request is None:
        raise NotFound("签名请求不存在")
    intent = store.get_intent(conn, str(request["intent_id"]))
    event_rows = store.list_signing_events(conn, signing_request_id)
    return {
        "signing_request": {
            "signing_request_id": str(request["signing_request_id"]),
            "intent_id": str(request["intent_id"]),
            "kind": request["kind"],
            "status": request["status"],
            "threshold": int(request["threshold_n"]),
            "signer_count": int(request["signer_count_n"]),
            "signed_count": int(request["signed_count"]),
            "expires_at": clock.iso(request["expires_at"]),
        },
        "intent": models.intent_payload(intent) if intent else None,
        "events": [models.signing_event_payload(item) for item in event_rows],
        "complete": policy.signing_complete(event_rows),
    }


def intent_summary(intent: Mapping[str, Any]) -> dict[str, Any]:
    return models.intent_payload(intent)
