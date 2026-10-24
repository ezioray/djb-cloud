# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08 事件生产（02-events §1/§2/§3/§5）：信封校验 + 本地事务内 outbox + 投递重试。

硬规则：

* **只生产 02-events 已登记的 9 个 M08 事件**，payload 键走白名单，未知键直接拒绝
  （防卡号 / 完整签名 / 原始报文 / PII 泄漏）；
* 业务写入与事件入队**同一连接 / 同一事务**（router 负责 transaction），不做跨库事务；
* 至少一次：m08_outbox.idempotency_key 唯一；重试 1s/5s/30s/5min/30min，8 次后进 dead
  （02-events §2），本模块不启动 publisher（合并期由 Lead 注入），测试直接读 outbox；
* 资金意图只**提案**：signing.requested / signing.signed 是事实通知，本模块绝不代签。
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Mapping

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import clock, facts, ids
from .errors import BadRequest

log = logging.getLogger("djb.treasury.events")

__all__ = [
    "build_event", "validate_payload", "enqueue", "pending", "published_events",
    "mark_published", "mark_failed", "payment_created", "payment_paid", "payment_failed",
    "wallet_switched", "sweep_completed", "payout_paid", "refund_completed",
    "signing_requested", "signing_signed", "MAX_ATTEMPTS",
]

#: 02-events §2 重试节奏（秒）
_BACKOFF_SECONDS: tuple[int, ...] = (1, 5, 30, 300, 1800, 1800, 1800, 1800)
MAX_ATTEMPTS = 8

#: payload 里绝对不允许出现的键（密钥 / 卡 / 签名原文 / 正文 / PII）
FORBIDDEN_PAYLOAD_KEYS: frozenset[str] = frozenset({
    "card", "card_no", "pan", "cvv", "secret", "private_key", "mnemonic", "seed",
    "signature", "raw_body", "prompt", "response", "email", "phone",
})


def validate_payload(event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """payload 白名单 + 零密钥 / 零正文 / 零 PII。"""
    if event_type not in facts.EVENT_PAYLOAD_FIELDS:
        raise BadRequest(f"未登记的事件类型：{event_type}", field="type")
    allowed = facts.EVENT_PAYLOAD_FIELDS[event_type]
    unknown = set(payload) - allowed
    if unknown:
        raise BadRequest(f"payload 含未登记字段：{sorted(unknown)}", field="payload")
    forbidden = {key for key in payload if str(key).lower() in FORBIDDEN_PAYLOAD_KEYS}
    if forbidden:
        raise BadRequest(f"payload 含禁止字段（密钥 / 卡 / 签名 / PII）：{sorted(forbidden)}",
                         field="payload")
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, (dict, list, tuple, set)):
            raise BadRequest(f"payload.{key} 只能是标量", field="payload")
        if isinstance(value, str):
            if len(value) > 256 or "@" in value:
                raise BadRequest(f"payload.{key} 形态非法（超长或含 PII）", field="payload")
        clean[key] = value
    return clean


def build_event(event_type: str, *, aggregate_type: str, aggregate_id: str,
                payload: Mapping[str, Any], occurred_at: datetime,
                idempotency_key: str, trace_id: str | None = None,
                correlation_id: str | None = None, causation_id: str | None = None,
                event_id: Any = None) -> dict[str, Any]:
    """构造 02-events §1 信封（字段齐全；payload 已白名单校验）。"""
    if not idempotency_key or len(idempotency_key) > 128:
        raise BadRequest("事件幂等键形态非法", field="idempotency_key")
    return {
        "event_id": str(event_id or ids.uuid7()),
        "type": event_type,
        "version": 1,
        "occurred_at": clock.as_utc(occurred_at),
        "producer": "M08",
        "aggregate_type": aggregate_type,
        "aggregate_id": str(aggregate_id),
        "correlation_id": correlation_id,
        "causation_id": causation_id,
        "trace_id": trace_id or ids.uuid7().hex,
        "idempotency_key": idempotency_key,
        "payload": validate_payload(event_type, payload),
    }


def enqueue(conn: Any, event: Mapping[str, Any]) -> str:
    """同事务入队；同 idempotency_key 重放 → 返回既有 event_id（不重复入队）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO m08_outbox (event_id, type, version, producer, aggregate_type,
                                    aggregate_id, correlation_id, causation_id, trace_id,
                                    idempotency_key, payload, occurred_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (idempotency_key) DO NOTHING
            RETURNING event_id
            """,
            (event["event_id"], event["type"], event["version"], event["producer"],
             event["aggregate_type"], event["aggregate_id"], event.get("correlation_id"),
             event.get("causation_id"), event["trace_id"], event["idempotency_key"],
             Jsonb(event["payload"]), event["occurred_at"]))
        row = cur.fetchone()
        if row is not None:
            return str(row["event_id"])
        cur.execute("SELECT event_id FROM m08_outbox WHERE idempotency_key = %s",
                    (event["idempotency_key"],))
        existing = cur.fetchone()
    if existing is None:                                  # pragma: no cover - 竞态兜底
        raise RuntimeError("outbox 入队失败：幂等键冲突但查不到既有事件")
    return str(existing["event_id"])


def pending(conn: Any, *, limit: int = 100) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT * FROM m08_outbox
             WHERE status = 'pending'
               AND (next_attempt_at IS NULL OR next_attempt_at <= now())
             ORDER BY id
             LIMIT %s
            """, (limit,))
        return list(cur.fetchall())


def published_events(conn: Any, *, aggregate_id: str | None = None) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        if aggregate_id is None:
            cur.execute("SELECT * FROM m08_outbox ORDER BY id")
        else:
            cur.execute("SELECT * FROM m08_outbox WHERE aggregate_id = %s ORDER BY id",
                        (aggregate_id,))
        return list(cur.fetchall())


def mark_published(conn: Any, event_id: str, *, at: datetime | None = None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE m08_outbox
               SET status = 'published', published_at = %s, last_error = NULL
             WHERE event_id = %s AND status = 'pending'
            """, (clock.as_utc(at or clock.utcnow()), event_id))


def mark_failed(conn: Any, event_id: str, error: str) -> str:
    """指数退避；第 8 次失败 → dead（人工重放，02-events §2）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT attempts FROM m08_outbox WHERE event_id = %s FOR UPDATE",
                    (event_id,))
        row = cur.fetchone()
        if row is None:
            raise BadRequest("事件不存在", field="event_id")
        attempts = int(row["attempts"]) + 1
        if attempts >= MAX_ATTEMPTS:
            cur.execute(
                "UPDATE m08_outbox SET attempts = %s, status = 'dead', last_error = %s"
                " WHERE event_id = %s", (attempts, error[:256], event_id))
            return "dead"
        delay = _BACKOFF_SECONDS[min(attempts - 1, len(_BACKOFF_SECONDS) - 1)]
        cur.execute(
            """
            UPDATE m08_outbox
               SET attempts = %s, last_error = %s,
                   next_attempt_at = now() + %s * interval '1 second'
             WHERE event_id = %s
            """, (attempts, error[:256], delay, event_id))
        return "retry"


# ───────────────────────────────────────────────────────────── 领域事件
def payment_created(conn: Any, order: Mapping[str, Any], *, trace_id: str | None = None) -> str:
    event = build_event(
        facts.EVENT_PAYMENT_CREATED, aggregate_type="payment_order",
        aggregate_id=str(order["order_id"]),
        payload={"order_no": order["order_no"], "amount_minor": int(order["amount_minor"]),
                 "method": order["method"], "currency": order["currency"]},
        occurred_at=order.get("created_at") or clock.utcnow(),
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_PAYMENT_CREATED]}:"
                        f"{order['order_id']}",
        trace_id=trace_id, correlation_id=order["order_no"])
    return enqueue(conn, event)


def payment_paid(conn: Any, order: Mapping[str, Any], *, provider_ref: str, paid_at: datetime,
                 trace_id: str | None = None) -> str:
    event = build_event(
        facts.EVENT_PAYMENT_PAID, aggregate_type="payment_order",
        aggregate_id=str(order["order_id"]),
        payload={"order_no": order["order_no"], "paid_at": clock.iso(paid_at),
                 "provider_ref": provider_ref, "amount_minor": int(order["amount_minor"])},
        occurred_at=paid_at,
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_PAYMENT_PAID]}:"
                        f"{order['order_id']}",
        trace_id=trace_id, correlation_id=order["order_no"])
    return enqueue(conn, event)


def payment_failed(conn: Any, order: Mapping[str, Any], *, error_code: int | str,
                   occurred_at: datetime | None = None, trace_id: str | None = None) -> str:
    event = build_event(
        facts.EVENT_PAYMENT_FAILED, aggregate_type="payment_order",
        aggregate_id=str(order["order_id"]),
        payload={"order_no": order["order_no"], "error_code": str(error_code)[:32]},
        occurred_at=occurred_at or clock.utcnow(),
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_PAYMENT_FAILED]}:"
                        f"{order['order_id']}",
        trace_id=trace_id, correlation_id=order["order_no"])
    return enqueue(conn, event)


def wallet_switched(conn: Any, *, pool_id: str, from_wallet: str, to_wallet: str, reason: str,
                    occurred_at: datetime | None = None, switch_id: str | None = None,
                    trace_id: str | None = None) -> str:
    moment = clock.as_utc(occurred_at or clock.utcnow())
    event = build_event(
        facts.EVENT_WALLET_SWITCHED, aggregate_type="wallet_pool", aggregate_id=pool_id,
        payload={"pool_id": pool_id, "from_wallet": from_wallet, "to_wallet": to_wallet,
                 "reason": reason},
        occurred_at=moment,
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_WALLET_SWITCHED]}:"
                        f"{switch_id or ids.uuid7()}",
        trace_id=trace_id, correlation_id=pool_id)
    return enqueue(conn, event)


def sweep_completed(conn: Any, *, batch_no: str, from_wallet: str, to_wallet: str,
                    amount_minor: int, txid: str, occurred_at: datetime | None = None,
                    transfer_id: str | None = None, trace_id: str | None = None) -> str:
    event = build_event(
        facts.EVENT_SWEEP_COMPLETED, aggregate_type="wallet_transfer",
        aggregate_id=str(transfer_id or batch_no),
        payload={"batch_no": batch_no, "from_wallet": from_wallet, "to_wallet": to_wallet,
                 "amount_minor": int(amount_minor), "txid": txid},
        occurred_at=occurred_at or clock.utcnow(),
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_SWEEP_COMPLETED]}:"
                        f"{transfer_id or batch_no}",
        trace_id=trace_id, correlation_id=batch_no)
    return enqueue(conn, event)


def payout_paid(conn: Any, batch: Mapping[str, Any], *, txid: str, settled_at: datetime,
                trace_id: str | None = None) -> str:
    event = build_event(
        facts.EVENT_PAYOUT_PAID, aggregate_type="payout_batch",
        aggregate_id=str(batch["batch_id"]),
        payload={"batch_no": batch["batch_no"], "item_count": int(batch["item_count"]),
                 "total_minor": int(batch["total_net_minor"]), "txid": txid},
        occurred_at=settled_at,
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_PAYOUT_PAID]}:"
                        f"{batch['batch_id']}",
        trace_id=trace_id, correlation_id=batch["batch_no"])
    return enqueue(conn, event)


def refund_completed(conn: Any, refund: Mapping[str, Any], *, succeeded_at: datetime,
                     trace_id: str | None = None) -> str:
    event = build_event(
        facts.EVENT_REFUND_COMPLETED, aggregate_type="refund_request",
        aggregate_id=str(refund["refund_request_id"]),
        payload={"refund_no": refund["refund_no"], "order_no": refund["order_no"],
                 "amount_minor": int(refund["amount_minor"]),
                 "method": refund.get("reason_code") or "original_route"},
        occurred_at=succeeded_at,
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_REFUND_COMPLETED]}:"
                        f"{refund['refund_request_id']}",
        trace_id=trace_id, correlation_id=refund["refund_no"])
    return enqueue(conn, event)


def signing_requested(conn: Any, *, intent: Mapping[str, Any], signing_request_id: str,
                      signer_type: str = "owner", trace_id: str | None = None) -> str:
    event = build_event(
        facts.EVENT_SIGNING_REQUESTED, aggregate_type="treasury_intent",
        aggregate_id=str(intent["intent_id"]),
        payload={"intent_id": str(intent["intent_id"]), "signer_type": signer_type,
                 "expires_at": clock.iso(intent["expires_at"]), "kind": str(intent["kind"])},
        occurred_at=clock.utcnow(),
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_SIGNING_REQUESTED]}:"
                        f"{signing_request_id}",
        trace_id=trace_id, correlation_id=str(intent.get("correlation_id") or intent["intent_id"]))
    return enqueue(conn, event)


def signing_signed(conn: Any, *, intent: Mapping[str, Any], signing_request_id: str,
                   signer_type: str, signed_at: datetime, trace_id: str | None = None) -> str:
    event = build_event(
        facts.EVENT_SIGNING_SIGNED, aggregate_type="treasury_intent",
        aggregate_id=str(intent["intent_id"]),
        payload={"intent_id": str(intent["intent_id"]), "signer_type": signer_type,
                 "signed_at": clock.iso(signed_at)},
        occurred_at=signed_at,
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_SIGNING_SIGNED]}:"
                        f"{signing_request_id}:{signer_type}",
        trace_id=trace_id, correlation_id=str(intent.get("correlation_id") or intent["intent_id"]))
    return enqueue(conn, event)
