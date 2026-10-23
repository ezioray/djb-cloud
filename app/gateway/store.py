# SPDX-License-Identifier: Apache-2.0
"""本模块表读写（**只碰自己的表**：``api_request_log`` / ``m03_outbox`` / ``m03_idempotency``）。

铁律：

* **只加不改**：``api_request_log`` 只追加元数据（7 天保留），**不存正文 / 密钥 / PII**
  （INV-M03-02）；重复 ``request_id`` 走 ``ON CONFLICT DO NOTHING``（客户端复用同一
  ``X-Request-Id`` 时不产生第二行，也不让请求失败）；
* **同一本地事务**：``api_request_log`` + ``m03_outbox`` + ``m03_idempotency`` 由调用方
  传入同一个 ``c``（M03 §6「事务边界」），禁止跨模块事务；
* **无 ORM**：与 ``app.db`` 既有约定一致（psycopg3，成功提交 / 异常回滚由连接管理器负责）。
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Mapping

from . import models

__all__ = ["LOG_COLUMNS", "log_request", "fetch_request_log", "get_idempotency",
           "save_idempotency", "purge_idempotency", "insert_outbox", "pending_outbox",
           "mark_outbox_published", "mark_outbox_failed"]

LOG_COLUMNS: tuple[str, ...] = (
    "request_id", "trace_id", "account_id", "tenant_id", "api_key_id", "model",
    "service_tier", "stream", "status", "http_status", "error_code", "node_id",
    "latency_ms", "first_byte_ms", "tokens_in", "tokens_out", "usage_source", "batch_id",
    "created_at",
)
"""``api_request_log`` 列（与 ``migrations/301_api_request_log.sql`` 一致，顺序无关）。"""


# --------------------------------------------------------------------------- 请求日志
def log_request(c: Any, record: models.RequestRecord, *, now: datetime,
                record_id: str | None = None) -> bool:
    """写一行请求元数据；重复 ``request_id`` 不报错（返回 False）。"""
    payload = {
        "id": record_id or str(models.uuid7(int(now.timestamp() * 1_000_000))),
        "request_id": record.request_id,
        "trace_id": record.trace_id,
        "account_id": record.account_id,
        "tenant_id": record.tenant_id,
        "api_key_id": record.api_key_id,
        "model": record.model,
        "service_tier": record.service_tier,
        "stream": bool(record.stream),
        "status": record.status,
        "http_status": int(record.http_status),
        "error_code": record.error_code,
        "node_id": record.node_id,
        "latency_ms": record.latency_ms,
        "first_byte_ms": record.first_byte_ms,
        "tokens_in": record.tokens_in,
        "tokens_out": record.tokens_out,
        "usage_source": record.usage_source,
        "batch_id": record.batch_id,
        "created_at": now,
    }
    with c.cursor() as cur:
        cur.execute(
            """
            INSERT INTO api_request_log (
                id, request_id, trace_id, account_id, tenant_id, api_key_id, model,
                service_tier, stream, status, http_status, error_code, node_id,
                latency_ms, first_byte_ms, tokens_in, tokens_out, usage_source, batch_id,
                created_at
            ) VALUES (
                %(id)s, %(request_id)s, %(trace_id)s, %(account_id)s, %(tenant_id)s,
                %(api_key_id)s,
                %(model)s, %(service_tier)s, %(stream)s, %(status)s, %(http_status)s,
                %(error_code)s, %(node_id)s, %(latency_ms)s, %(first_byte_ms)s,
                %(tokens_in)s, %(tokens_out)s, %(usage_source)s, %(batch_id)s, %(created_at)s
            )
            ON CONFLICT (request_id) DO NOTHING
            """,
            payload,
        )
        return cur.rowcount == 1


def fetch_request_log(c: Any, request_id: str) -> dict[str, Any] | None:
    """按 ``request_id`` 取一行（排障 / 用例断言用）。"""
    with c.cursor() as cur:
        cur.execute(
            "SELECT request_id, account_id, api_key_id, model, service_tier, stream, status,"
            " http_status, error_code, node_id, latency_ms, first_byte_ms, tokens_in,"
            " tokens_out, usage_source, batch_id, created_at"
            " FROM api_request_log WHERE request_id = %s", (request_id,))
        row = cur.fetchone()
        if row is None:
            return None
        keys = [desc[0] for desc in cur.description]
    return dict(zip(keys, row))


# --------------------------------------------------------------------------- 幂等记录
def get_idempotency(c: Any, *, scope: str, key: str):
    """取一条幂等记录（``record`` 的模型层见 :mod:`app.gateway.idempotency`）。"""
    from . import idempotency                             # 同包；避免顶层循环 import

    with c.cursor() as cur:
        cur.execute(
            "SELECT scope, key, request_hash, status_code, response, created_at, expires_at"
            " FROM m03_idempotency WHERE scope = %s AND key = %s", (scope, key))
        row = cur.fetchone()
    if row is None:
        return None
    payload = row[4]
    if isinstance(payload, str):                          # jsonb 个别驱动配置返回文本
        payload = json.loads(payload)
    return idempotency.IdempotencyRecord(scope=row[0], key=row[1], request_hash=row[2],
                                         status_code=int(row[3]), payload=payload or {},
                                         created_at=row[5], expires_at=row[6])


def save_idempotency(c: Any, *, record_id: str, scope: str, key: str, request_hash: str,
                     status_code: int, payload: Mapping[str, Any], created_at: datetime,
                     expires_at: datetime) -> None:
    """同键覆盖写（已过期的旧记录被新结果替换；未过期由调用方先判 409）。"""
    with c.cursor() as cur:
        cur.execute(
            """
            INSERT INTO m03_idempotency (
                id, scope, key, request_hash, status_code, response, created_at, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
            ON CONFLICT (scope, key) DO UPDATE SET
                request_hash = EXCLUDED.request_hash,
                status_code = EXCLUDED.status_code,
                response = EXCLUDED.response,
                created_at = EXCLUDED.created_at,
                expires_at = EXCLUDED.expires_at
            """,
            (record_id, scope, key, request_hash, int(status_code),
             json.dumps(dict(payload), ensure_ascii=False), created_at, expires_at),
        )


def purge_idempotency(c: Any, *, now: datetime, limit: int = 200) -> int:
    """清理过期记录（小批量；不阻塞主链路）。"""
    with c.cursor() as cur:
        cur.execute(
            "DELETE FROM m03_idempotency WHERE id IN ("
            " SELECT id FROM m03_idempotency WHERE expires_at <= %s ORDER BY expires_at LIMIT %s)",
            (now, int(limit)))
        return int(cur.rowcount or 0)


# --------------------------------------------------------------------------- outbox
def insert_outbox(c: Any, envelope: Mapping[str, Any]) -> None:
    """把一个 02-events §1 信封写入 ``m03_outbox``（与业务同事务）。"""
    with c.cursor() as cur:
        cur.execute(
            """
            INSERT INTO m03_outbox (
                event_id, type, version, occurred_at, producer, aggregate_type,
                aggregate_id, correlation_id, causation_id, trace_id, idempotency_key,
                payload, attempts, next_attempt_at, created_at
            ) VALUES (
                %(event_id)s, %(type)s, %(version)s, %(occurred_at)s, %(producer)s,
                %(aggregate_type)s, %(aggregate_id)s, %(correlation_id)s, %(causation_id)s,
                %(trace_id)s, %(idempotency_key)s, %(payload)s::jsonb, 0, %(occurred_at)s,
                %(occurred_at)s
            )
            ON CONFLICT (idempotency_key) DO NOTHING
            """,
            {**dict(envelope),
             "payload": json.dumps(dict(envelope.get("payload") or {}), ensure_ascii=False)},
        )


def pending_outbox(c: Any, *, now: datetime, limit: int = 100) -> list[dict[str, Any]]:
    """取待投递事件（``FOR UPDATE SKIP LOCKED``：多进程不抢同一行）。"""
    with c.cursor() as cur:
        cur.execute(
            "SELECT event_id, type, payload, attempts, idempotency_key FROM m03_outbox"
            " WHERE published_at IS NULL AND next_attempt_at <= %s"
            " ORDER BY next_attempt_at LIMIT %s FOR UPDATE SKIP LOCKED", (now, int(limit)))
        rows = cur.fetchall()
    return [{"event_id": str(row[0]), "type": row[1], "payload": row[2],
             "attempts": int(row[3]), "idempotency_key": row[4]} for row in rows]


def mark_outbox_published(c: Any, *, event_id: str, now: datetime) -> None:
    with c.cursor() as cur:
        cur.execute("UPDATE m03_outbox SET published_at = %s, attempts = attempts + 1"
                    " WHERE event_id = %s", (now, event_id))


def mark_outbox_failed(c: Any, *, event_id: str, attempts: int, next_attempt_at: datetime,
                       error: str) -> None:
    """按 02-events §2.3 退避重试；8 次后留在表里等人工重放（DLQ 语义）。"""
    with c.cursor() as cur:
        cur.execute("UPDATE m03_outbox SET attempts = %s, next_attempt_at = %s, last_error = %s"
                    " WHERE event_id = %s",
                    (int(attempts), next_attempt_at, error[:200], event_id))

