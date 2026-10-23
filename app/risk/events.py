# SPDX-License-Identifier: Apache-2.0
"""M11 事件生产（02-events §1/§2/§3/§5）：信封校验 + 本地事务内 outbox + 投递重试。

硬规则：

* **只生产 02-events 已登记的 4 个事件**（``risk.case.opened`` / ``risk.case.closed`` /
  ``risk.limit.hit`` / ``risk.action.requested``），payload 键走白名单，未知键直接拒绝
  （防阈值 / 权重 / 名单 / PII 泄漏，INV-01 / INV-05）；
* 业务写入与事件入队**同一连接 / 同一事务**（router 负责 transaction），不做跨库事务；
* 至少一次：``risk_outbox.idempotency_key`` 唯一；重试 1s/5s/30s/5min/30min，8 次后进 dead
  （02-events §2），本模块**不启动** publisher（合并期由 Lead 注入），测试直接读 outbox；
* 处置只**提案**：``risk.action.requested`` 是给 M01 的事实，本模块绝不改 accounts 状态（INV-04）。
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Mapping

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import clock, facts, ids
from .errors import BadRequest

log = logging.getLogger("djb.risk.events")

__all__ = [
    "build_event", "validate_payload", "enqueue", "pending", "published_events",
    "mark_published", "mark_failed", "case_opened", "case_closed", "action_requested",
    "record_limit_hit",
]

#: 02-events §2 重试节奏（秒）
_BACKOFF_SECONDS: tuple[int, ...] = (1, 5, 30, 300, 1800, 1800, 1800, 1800)
MAX_ATTEMPTS = 8


def validate_payload(event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """payload 白名单 + 零阈值 + 零 PII（INV-01 / INV-05）。"""
    if event_type not in facts.EVENT_PAYLOAD_FIELDS:
        raise BadRequest(f"未登记的事件类型：{event_type}", field="type")
    allowed = facts.EVENT_PAYLOAD_FIELDS[event_type]
    unknown = set(payload) - allowed
    if unknown:
        raise BadRequest(f"payload 含未登记字段：{sorted(unknown)}", field="payload")
    forbidden = {key for key in payload if str(key).lower() in facts.FORBIDDEN_PAYLOAD_KEYS}
    if forbidden:
        raise BadRequest(f"payload 含禁止字段（阈值 / 名单 / PII）：{sorted(forbidden)}",
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
                correlation_id: str | None = None,
                causation_id: str | None = None,
                event_id: Any = None) -> dict[str, Any]:
    """构造 02-events §1 信封（字段齐全；payload 已白名单校验）。"""
    if not idempotency_key or len(idempotency_key) > 128:
        raise BadRequest("事件幂等键形态非法", field="idempotency_key")
    return {
        "event_id": str(event_id or ids.uuid7()),
        "type": event_type,
        "version": 1,
        "occurred_at": clock.as_utc(occurred_at),
        "producer": "M11",
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
            INSERT INTO risk_outbox (event_id, type, version, producer, aggregate_type,
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
        cur.execute("SELECT event_id FROM risk_outbox WHERE idempotency_key = %s",
                    (event["idempotency_key"],))
        existing = cur.fetchone()
    if existing is None:                                  # pragma: no cover - 竞态兜底
        raise RuntimeError("outbox 入队失败：幂等键冲突但查不到既有事件")
    return str(existing["event_id"])


def pending(conn: Any, *, limit: int = 100) -> list[dict[str, Any]]:
    """待投递事件（``next_attempt_at`` 已到期；``status='pending'``）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT * FROM risk_outbox
             WHERE status = 'pending'
               AND (next_attempt_at IS NULL OR next_attempt_at <= now())
             ORDER BY id
             LIMIT %s
            """, (limit,))
        return list(cur.fetchall())


def published_events(conn: Any, *, aggregate_id: str | None = None) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        if aggregate_id is None:
            cur.execute("SELECT * FROM risk_outbox ORDER BY id")
        else:
            cur.execute("SELECT * FROM risk_outbox WHERE aggregate_id = %s ORDER BY id",
                        (aggregate_id,))
        return list(cur.fetchall())


def mark_published(conn: Any, event_id: str, *, at: datetime | None = None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE risk_outbox
               SET status = 'published', published_at = %s, last_error = NULL
             WHERE event_id = %s AND status = 'pending'
            """, (clock.as_utc(at or clock.utcnow()), event_id))


def mark_failed(conn: Any, event_id: str, error: str) -> str:
    """指数退避；第 8 次失败 → dead（人工重放，02-events §2）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT attempts FROM risk_outbox WHERE event_id = %s FOR UPDATE",
                    (event_id,))
        row = cur.fetchone()
        if row is None:
            raise BadRequest("事件不存在", field="event_id")
        attempts = int(row["attempts"]) + 1
        if attempts >= MAX_ATTEMPTS:
            cur.execute(
                "UPDATE risk_outbox SET attempts = %s, status = 'dead', last_error = %s"
                " WHERE event_id = %s", (attempts, error[:256], event_id))
            return "dead"
        delay = _BACKOFF_SECONDS[min(attempts - 1, len(_BACKOFF_SECONDS) - 1)]
        cur.execute(
            """
            UPDATE risk_outbox
               SET attempts = %s, last_error = %s, next_attempt_at = now() + %s * interval '1 second'
             WHERE event_id = %s
            """, (attempts, error[:256], delay, event_id))
        return "retry"


# ───────────────────────────────────────────────────────────── 领域事件
def case_opened(conn: Any, case: Mapping[str, Any], *, trace_id: str | None = None) -> str:
    """risk.case.opened（02-events §3：case_id / subject_id / risk_type / severity / rule_version）。"""
    payload: dict[str, Any] = {
        "case_id": str(case["case_id"]),
        "subject_id": case["subject_hash"],
        "risk_type": case["risk_type"],
        "severity": case["severity"],
    }
    if case.get("rule_version") is not None:
        payload["rule_version"] = int(case["rule_version"])
    event = build_event(
        facts.EVENT_CASE_OPENED,
        aggregate_type="risk_case",
        aggregate_id=str(case["case_id"]),
        payload=payload,
        occurred_at=case.get("opened_at") or clock.utcnow(),
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_CASE_OPENED]}:"
                        f"{case['case_id']}",
        trace_id=trace_id)
    return enqueue(conn, event)


def case_closed(conn: Any, case: Mapping[str, Any], *, outcome: str,
                closed_at: datetime, trace_id: str | None = None) -> str:
    """risk.case.closed（含 merged / dismissed；outcome 用终态或裁决结果）。"""
    event = build_event(
        facts.EVENT_CASE_CLOSED,
        aggregate_type="risk_case",
        aggregate_id=str(case["case_id"]),
        payload={"case_id": str(case["case_id"]), "outcome": outcome,
                 "closed_at": clock.iso(closed_at)},
        occurred_at=closed_at,
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_CASE_CLOSED]}:"
                        f"{case['case_id']}:{outcome}",
        trace_id=trace_id)
    return enqueue(conn, event)


def action_requested(conn: Any, case: Mapping[str, Any], *, action: str, reason_code: str,
                     expires_at: datetime | None, sequence: int,
                     trace_id: str | None = None) -> str:
    """risk.action.requested（INV-04：只提案，不改账户状态；冻结必带期限）。

    返回 ``proposal_id``（= 事件 event_id），供 ``RiskDecision.proposal_id`` 回填。
    """
    payload = {
        "case_id": str(case["case_id"]),
        "subject_type": case.get("subject_type") or "account",
        "subject_id": case["subject_hash"],
        "action": action,
        "reason_code": reason_code,
        "expires_at": clock.iso(expires_at) if expires_at is not None else None,
    }
    event = build_event(
        facts.EVENT_ACTION_REQUESTED,
        aggregate_type="risk_case",
        aggregate_id=str(case["case_id"]),
        payload=payload,
        occurred_at=clock.utcnow(),
        idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_ACTION_REQUESTED]}:"
                        f"{case['case_id']}:{sequence}",
        trace_id=trace_id)
    return enqueue(conn, event)


def record_limit_hit(conn: Any, *, subject_hash: str, limit_type: str, value: int,
                     window_s: int, occurred_at: datetime,
                     signal_type: str = "limit_hit",
                     source_event_id: str | None = None, source_module: str | None = None,
                     cluster_id: str | None = None, amount_minor: int | None = None,
                     currency: str | None = None,
                     payload: Mapping[str, Any] | None = None,
                     trace_id: str | None = None) -> dict[str, Any]:
    """消费上游失败（48001 / 40312 等）→ 写 risk_events（幂等）→ 生产 risk.limit.hit。"""
    meta = dict(payload or {})
    forbidden = {key for key in meta if str(key).lower() in facts.FORBIDDEN_PAYLOAD_KEYS}
    if forbidden:
        raise BadRequest(f"signal payload 含禁止字段：{sorted(forbidden)}", field="payload")
    event_id = ids.uuid7()
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO risk_events (event_id, signal_type, subject_hash, cluster_id,
                                     amount_minor, currency, occurred_at, source_event_id,
                                     source_module, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (source_event_id) DO NOTHING
            RETURNING event_id
            """,
            (str(event_id), signal_type, subject_hash, cluster_id, amount_minor, currency,
             clock.as_utc(occurred_at), source_event_id, source_module, Jsonb(meta)))
        inserted = cur.fetchone()
        if inserted is None:                            # 重放：不重复落库、不重复发事件
            cur.execute("SELECT event_id FROM risk_events WHERE source_event_id = %s",
                        (source_event_id,))
            existing = cur.fetchone()
            return {"event_id": str(existing["event_id"]), "created": False}
        signal_id = str(inserted["event_id"])
        event = build_event(
            facts.EVENT_LIMIT_HIT,
            aggregate_type="risk_signal",
            aggregate_id=signal_id,
            payload={"subject_id": subject_hash, "limit_type": limit_type,
                     "value": int(value), "window_s": int(window_s)},
            occurred_at=occurred_at,
            idempotency_key=f"{facts.EVENT_IDEMPOTENCY_PREFIX[facts.EVENT_LIMIT_HIT]}:{signal_id}",
            trace_id=trace_id)
        enqueue(conn, event)
        return {"event_id": signal_id, "created": True}
