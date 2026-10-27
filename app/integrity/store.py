# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 冻结段持久化层（psycopg3，无 ORM，全部参数化 SQL）。

边界：

* 只读写 ``supplier_integrity_holds`` / ``supplier_integrity_events`` 两张表；
  **不 import 账本、不写 ledger_*、不改 account_balances**（M17 §6.1「不改账本」）；
* 写接口不提交：事务边界在 service / router（``app.db.conn`` 成功提交、异常回滚）；
* 「active」的业务判定 = ``state='active' AND (expires_at IS NULL OR expires_at > now)``，
  和 ``expire_due`` 的状态翻转一致（到期但还没扫到的行不再算冻结，也不会挡住新 hold 创建）。

``FOR UPDATE`` 只用于 create_or_escalate / release 的读-改-写路径，避免并发写出两条 active
（DB 侧另有部分唯一索引 uq_integrity_holds_active 兜底）。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import facts, models

__all__ = [
    "active_predicate", "get_hold", "find_active_hold", "insert_hold",
    "escalate_hold", "mark_released", "expire_due", "insert_event", "list_events",
    "list_holds", "frozen_total", "count_active", "lock_node_model",
    "insert_appeal", "get_appeal", "find_open_appeal", "resolve_appeal",
    "list_appeals", "expire_open_appeals",
]

ACTIVE_PREDICATE = "state = 'active' AND (expires_at IS NULL OR expires_at > %s)"


def active_predicate() -> str:
    return ACTIVE_PREDICATE


def get_hold(conn: Any, hold_id: uuid.UUID, *, for_update: bool = False
             ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.HOLD_COLUMNS} FROM supplier_integrity_holds"
            f" WHERE id = %s{suffix}", (hold_id,))
        return cur.fetchone()


def find_active_hold(conn: Any, node_id: str, model: str, *, now: datetime,
                     for_update: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.HOLD_COLUMNS} FROM supplier_integrity_holds"
            f" WHERE node_id = %s AND model = %s AND {ACTIVE_PREDICATE}{suffix}",
            (node_id, model, now))
        return cur.fetchone()


def lock_node_model(conn: Any, node_id: str, model: str) -> None:
    """按 (node_id, model) 做事务级 advisory lock：并发 create 串行化，避免唯一索引 500。

    用 hashtext 拼 64 位键（两个 int4），不依赖具体行是否存在（行还不存在也能加锁）。
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
            (f"m17.hold:{node_id}", f"m17.hold:{model}"))


def insert_hold(conn: Any, *, hold_id: uuid.UUID, node_id: str, upstream_id: str | None,
                model: str, level: str, ratio_bp: int, base_amount_micro: int,
                frozen_amount_micro: int, reason: str, evidence_ref: str,
                created_at: datetime, expires_at: datetime | None) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO supplier_integrity_holds
              (id, node_id, upstream_id, model, level, ratio_bp, base_amount_micro,
               frozen_amount_micro, state, reason, evidence_ref, created_at, expires_at,
               version, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', %s, %s, %s, %s, 1, %s)
            RETURNING {facts.HOLD_COLUMNS}
            """,
            (hold_id, node_id, upstream_id, model, level, ratio_bp, base_amount_micro,
             frozen_amount_micro, reason, evidence_ref, created_at, expires_at, created_at))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def escalate_hold(conn: Any, hold_id: uuid.UUID, *, level: str, ratio_bp: int,
                  base_amount_micro: int, frozen_amount_micro: int, reason: str,
                  evidence_ref: str, expires_at: datetime | None,
                  updated_at: datetime) -> dict[str, Any]:
    """只升不降的升级：改同一行（version+1），不新建第二条 active。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE supplier_integrity_holds
               SET level = %s, ratio_bp = %s, base_amount_micro = %s,
                   frozen_amount_micro = %s, reason = %s, evidence_ref = %s,
                   expires_at = %s, version = version + 1, updated_at = %s
             WHERE id = %s AND state = 'active'
            RETURNING {facts.HOLD_COLUMNS}
            """,
            (level, ratio_bp, base_amount_micro, frozen_amount_micro, reason, evidence_ref,
             expires_at, updated_at, hold_id))
        row = cur.fetchone()
    if row is None:                                       # pragma: no cover - FOR UPDATE 串行化后不应发生
        raise LookupError("hold 已不在 active 状态")
    return dict(row)


def mark_released(conn: Any, hold_id: uuid.UUID, *, reviewers: list[str], reason: str,
                  released_at: datetime) -> dict[str, Any]:
    reviewer_a = reviewers[0] if reviewers else None
    reviewer_b = reviewers[1] if len(reviewers) > 1 else None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE supplier_integrity_holds
               SET state = 'released', released_at = %s, release_reason = %s,
                   reviewer_a = %s, reviewer_b = %s,
                   version = version + 1, updated_at = %s
             WHERE id = %s AND state = 'active'
            RETURNING {facts.HOLD_COLUMNS}
            """,
            (released_at, reason, reviewer_a, reviewer_b, released_at, hold_id))
        row = cur.fetchone()
    if row is None:                                       # pragma: no cover - 调用方已校验 active
        raise LookupError("hold 已不在 active 状态")
    return dict(row)


def expire_due(conn: Any, now: datetime) -> list[dict[str, Any]]:
    """把到期的 I1 hold 翻成 expired（只改本表 + 追加事件；不碰账本）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE supplier_integrity_holds
               SET state = 'expired', version = version + 1, updated_at = %s
             WHERE state = 'active' AND expires_at IS NOT NULL AND expires_at <= %s
            RETURNING {facts.HOLD_COLUMNS}
            """,
            (now, now))
        return [dict(row) for row in cur.fetchall()]


def insert_event(conn: Any, *, event_id: uuid.UUID, hold_id: uuid.UUID | None,
                 node_id: str, model: str, event: str, from_level: str | None,
                 to_level: str | None, detail: dict[str, Any], actor: str,
                 created_at: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO supplier_integrity_events
              (event_id, hold_id, node_id, model, event, from_level, to_level, detail,
               actor, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {facts.EVENT_COLUMNS}
            """,
            (event_id, hold_id, node_id, model, event, from_level, to_level,
             Jsonb(detail), actor, created_at))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


# ───────────────────────────────────────────────────────── 申诉（1712）
def insert_appeal(conn: Any, *, appeal_id: uuid.UUID, hold_id: uuid.UUID, node_id: str,
                  model: str, reason: str, appellant: str, created_at: datetime,
                  deadline_at: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO supplier_integrity_appeals
              (id, hold_id, node_id, model, state, reason, appellant, created_at,
               deadline_at, version, updated_at)
            VALUES (%s, %s, %s, %s, 'open', %s, %s, %s, %s, 1, %s)
            RETURNING {facts.APPEAL_COLUMNS}
            """,
            (appeal_id, hold_id, node_id, model, reason, appellant, created_at,
             deadline_at, created_at))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_appeal(conn: Any, appeal_id: uuid.UUID, *, for_update: bool = False
               ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.APPEAL_COLUMNS} FROM supplier_integrity_appeals"
            f" WHERE id = %s{suffix}", (appeal_id,))
        return cur.fetchone()


def find_open_appeal(conn: Any, hold_id: uuid.UUID, *, for_update: bool = False
                     ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.APPEAL_COLUMNS} FROM supplier_integrity_appeals"
            f" WHERE hold_id = %s AND state = 'open'{suffix}", (hold_id,))
        return cur.fetchone()


def resolve_appeal(conn: Any, appeal_id: uuid.UUID, *, state: str, reviewers: list[str],
                   release_reason: str | None, resolved_at: datetime) -> dict[str, Any]:
    """终态落库：open → upheld / released / expired（version+1，触发器兜底）。"""
    reviewer_a = reviewers[0] if reviewers else None
    reviewer_b = reviewers[1] if len(reviewers) > 1 else None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE supplier_integrity_appeals
               SET state = %s, resolution = %s, resolved_at = %s, release_reason = %s,
                   reviewer_a = %s, reviewer_b = %s,
                   version = version + 1, updated_at = %s
             WHERE id = %s AND state = 'open'
            RETURNING {facts.APPEAL_COLUMNS}
            """,
            (state, state, resolved_at, release_reason, reviewer_a, reviewer_b,
             resolved_at, appeal_id))
        row = cur.fetchone()
    if row is None:                                      # pragma: no cover - 调用方已校验 open
        raise LookupError("申诉已不在 open 状态")
    return dict(row)


def list_appeals(conn: Any, *, hold_id: uuid.UUID | None = None,
                 node_id: str | None = None, state: str | None = None,
                 limit: int = 50) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if hold_id is not None:
        clauses.append("hold_id = %s")
        params.append(hold_id)
    if node_id is not None:
        clauses.append("node_id = %s")
        params.append(node_id)
    if state is not None:
        clauses.append("state = %s")
        params.append(state)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(int(limit), 200)))
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.APPEAL_COLUMNS} FROM supplier_integrity_appeals{where}"
            f" ORDER BY created_at DESC, id DESC LIMIT %s", params)
        return list(cur.fetchall())


def expire_open_appeals(conn: Any, now: datetime) -> list[dict[str, Any]]:
    """把窗口已过的 open 申诉翻成 expired（仍只改本表，不动 hold / 账本）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE supplier_integrity_appeals
               SET state = 'expired', resolution = 'expired', resolved_at = %s,
                   version = version + 1, updated_at = %s
             WHERE state = 'open' AND deadline_at <= %s
            RETURNING {facts.APPEAL_COLUMNS}
            """,
            (now, now, now))
        return list(cur.fetchall())


def list_events(conn: Any, hold_id: uuid.UUID, *, limit: int = 50) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.EVENT_COLUMNS} FROM supplier_integrity_events"
            " WHERE hold_id = %s ORDER BY created_at DESC, event_id DESC LIMIT %s",
            (hold_id, limit))
        return [dict(row) for row in cur.fetchall()]


def list_holds(conn: Any, *, state: str, node_id: str | None, model: str | None,
               level: str | None, limit: int, cursor: str | None, now: datetime
               ) -> tuple[list[dict[str, Any]], bool, str | None]:
    conditions: list[str] = []
    params: list[Any] = []
    if state == "active":
        conditions.append(f"({ACTIVE_PREDICATE})")
        params.append(now)
    elif state != "all":
        conditions.append("state = %s")
        params.append(state)
    if node_id:
        conditions.append("node_id = %s")
        params.append(node_id)
    if model:
        conditions.append("model = %s")
        params.append(model)
    if level:
        conditions.append("level = %s")
        params.append(level)
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment, identity = parsed
        conditions.append("(created_at < %s OR (created_at = %s AND id::text < %s))")
        params.extend([moment, moment, identity])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {facts.HOLD_COLUMNS} FROM supplier_integrity_holds{where}"
            " ORDER BY created_at DESC, id DESC LIMIT %s", tuple(params))
        rows = [dict(row) for row in cur.fetchall()]
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = models.encode_cursor(last["created_at"], str(last["id"]))
    return rows, has_more, next_cursor


def frozen_total(conn: Any, node_id: str, *, now: datetime) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COALESCE(SUM(frozen_amount_micro), 0) FROM supplier_integrity_holds"
            f" WHERE node_id = %s AND {ACTIVE_PREDICATE}", (node_id, now))
        return int(cur.fetchone()[0])


def count_active(conn: Any, node_id: str, *, now: datetime) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM supplier_integrity_holds"
            f" WHERE node_id = %s AND {ACTIVE_PREDICATE}", (node_id, now))
        return int(cur.fetchone()[0])
