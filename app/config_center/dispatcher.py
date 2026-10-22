# SPDX-License-Identifier: Apache-2.0
"""事件派发器（T4，02-events §2「至少一次投递」）。

职责边界：
  · 本模块只负责「把 outbox 里待投递的事件交给下游，并按结果标记 published / DLQ」；
  · 真正的传输（Kafka / HTTP / 内部总线）由 `publisher` 回调注入 —— 本层不选中间件；
  · 投递失败**不回滚业务事务**（业务已提交），指数退避与重试间隔由调度器决定；
    本层只累计次数，达到 :data:`MAX_ATTEMPTS`（02-events §2：8 次）后置死信并告警。

死信只能人工重放（02-events §2）：outbox 是只追加表，`dead_lettered_at` 不可撤销；
人工重放应基于原 payload **新增一条事件**（新的 event_id / 幂等键后缀），由 T5 的 CLI 做。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

import psycopg
from psycopg.types.json import Jsonb

from .errors import ValidationFailed

__all__ = [
    "MAX_ATTEMPTS",
    "BACKOFF_SECONDS",
    "dispatch_pending",
    "pending_count",
    "dead_letters",
    "requeue_dead_letter",
]

#: 02-events §2：指数退避 8 次后进 DLQ（内部算法常量，不是业务数字）
MAX_ATTEMPTS = 8
#: 02-events §2 的退避序列：1s / 5s / 30s / 5min / 30min（之后维持 30min）
BACKOFF_SECONDS: tuple[int, ...] = (1, 5, 30, 300, 1800)


def _rows(conn: psycopg.Connection, sql: str, params: Any = ()) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    columns = [desc.name for desc in cur.description or ()]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def _now(now: datetime | None) -> datetime:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValidationFailed("now 必须带时区（UTC）")
    return moment.astimezone(timezone.utc)


def pending_count(conn: psycopg.Connection) -> int:
    row = conn.execute(
        """SELECT count(*) FROM config_outbox
            WHERE published_at IS NULL AND dead_lettered_at IS NULL""").fetchone()
    return int(row[0])


def dispatch_pending(
    conn: psycopg.Connection,
    *,
    publisher: Callable[[Mapping[str, Any]], Any] | None = None,
    limit: int = 100,
    now: datetime | None = None,
    on_dead_letter: Callable[[Mapping[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    """投递一批待发事件。

    ``publisher``：收到事件行（dict），成功返回即视为投递成功；抛异常即失败。
    缺省 publisher 为 no-op（本地 / 测试的「直接成功」模式）。
    ``on_dead_letter``：事件进入死信时的告警回调（M12 / 值班）；缺省不告警。
    """
    if not 1 <= limit <= 1000:
        raise ValidationFailed(f"limit 越界 1..1000：{limit}")
    moment = _now(now)
    deliver = publisher or (lambda _event: None)
    rows = _rows(conn,
                 """SELECT * FROM config_outbox
                     WHERE published_at IS NULL AND dead_lettered_at IS NULL
                       AND (next_attempt_at IS NULL OR next_attempt_at <= %s)
                     ORDER BY created_at, event_id LIMIT %s""", (moment, limit))
    delivered: list[str] = []
    failed: list[str] = []
    dead: list[str] = []

    for row in rows:
        try:
            deliver(row)
        except Exception as exc:                       # noqa: BLE001 - 任何投递异常都按失败计
            attempts = int(row["delivery_attempts"]) + 1
            message = f"{type(exc).__name__}: {exc}"[:512]
            if attempts >= MAX_ATTEMPTS:
                conn.execute(
                    """UPDATE config_outbox
                          SET delivery_attempts = %s, last_error = %s, dead_lettered_at = %s,
                              last_attempt_at = %s, next_attempt_at = NULL
                        WHERE event_id = %s""",
                    (attempts, message, moment, moment, row["event_id"]))
                dead.append(str(row["event_id"]))
                if on_dead_letter is not None:
                    on_dead_letter({**row, "delivery_attempts": attempts, "last_error": message,
                                    "dead_lettered_at": moment})
            else:
                backoff = BACKOFF_SECONDS[min(attempts - 1, len(BACKOFF_SECONDS) - 1)]
                conn.execute(
                    """UPDATE config_outbox
                          SET delivery_attempts = %s, last_error = %s,
                              last_attempt_at = %s, next_attempt_at = %s
                        WHERE event_id = %s""",
                    (attempts, message, moment, moment + timedelta(seconds=backoff),
                     row["event_id"]))
                failed.append(str(row["event_id"]))
        else:
            conn.execute(
                "UPDATE config_outbox SET published_at = %s WHERE event_id = %s AND published_at IS NULL",
                (moment, row["event_id"]))
            delivered.append(str(row["event_id"]))

    return {"scanned": len(rows), "delivered": delivered, "failed": failed,
            "dead_lettered": dead, "pending": pending_count(conn)}


def dead_letters(conn: psycopg.Connection, *, limit: int = 50) -> list[dict[str, Any]]:
    """死信清单（人工重放入口；按进入时间倒序）。"""
    if not 1 <= limit <= 200:
        raise ValidationFailed(f"limit 越界 1..200：{limit}")
    return _rows(conn,
                 """SELECT * FROM config_outbox WHERE dead_lettered_at IS NOT NULL
                     ORDER BY dead_lettered_at DESC LIMIT %s""", (limit,))


def requeue_dead_letter(conn: psycopg.Connection, event_id: str, *,
                        now: datetime | None = None) -> dict[str, Any]:
    """人工重放死信：基于原 payload **新增一条事件**（outbox 只追加，原死信不可撤销）。

    新事件沿用原 type / payload / aggregate / trace，携带新的 event_id 与幂等键后缀，
    投递计数从 0 开始（02-events §2「死信只能人工重放」）。
    """
    moment = _now(now)
    row = conn.execute(
        """SELECT * FROM config_outbox WHERE event_id = %s AND dead_lettered_at IS NOT NULL""",
        (event_id,)).fetchone()
    if row is None:
        raise ValidationFailed(f"死信不存在或未进死信：{event_id}")
    columns = [desc.name for desc in conn.execute(
        "SELECT * FROM config_outbox LIMIT 0").description]
    original = dict(zip(columns, row))
    suffix = uuid.uuid4().hex[:8]
    new_id = uuid.uuid4()
    new_key = f"{original['idempotency_key']}:replay:{suffix}"
    conn.execute(
        """INSERT INTO config_outbox
             (event_id, type, version, occurred_at, producer, aggregate_type, aggregate_id,
              correlation_id, causation_id, trace_id, idempotency_key, payload, created_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (new_id, original["type"], original["version"], moment, original["producer"],
         original["aggregate_type"], original["aggregate_id"], original["correlation_id"],
         original["event_id"], original["trace_id"], new_key,
         Jsonb(original["payload"]), moment))
    new_row = conn.execute("SELECT * FROM config_outbox WHERE event_id = %s",
                           (new_id,)).fetchone()
    return dict(zip(columns, new_row))
