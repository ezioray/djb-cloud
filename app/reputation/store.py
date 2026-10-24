# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 仓储层：评分当前态 / 指标事实 / 后台只读列表（**不含 COP 台账**，那个在 cop.py）。

边界：

* 只碰本模块的表（``reputation_scores`` / ``reputation_events``）与只读视图；
* ``reputation_scores`` 是当前态（覆盖写），``reputation_events`` 只追加（DB 触发器兜底）；
* 分页一律游标 keyset（00-conventions §5：不得用 offset）。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Iterable

from . import clock, errors
from .models import (
    ReputationEvent, ReputationScore, decode_cursor, decode_cursor_payload, encode_cursor,
    encode_cursor_payload, new_id,
)

__all__ = [
    "SCORE_COLUMNS", "get_score", "upsert_score", "score_page", "insert_event",
    "events_page", "latest_events",
]

SCORE_COLUMNS = """account_id, score, tier, quality_coef, stability_coef, window_days,
                   policy_version, computed_at, tier_since, prev_tier, manual_tier, reasons"""

MAX_PAGE_LIMIT = 200
DEFAULT_PAGE_LIMIT = 50


def _limit(raw: Any) -> int:
    if raw in (None, ""):
        return DEFAULT_PAGE_LIMIT
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument("limit 必须是整数") from exc
    if not 1 <= value <= MAX_PAGE_LIMIT:
        raise errors.InvalidArgument(f"limit 必须在 1..{MAX_PAGE_LIMIT}")
    return value


# --------------------------------------------------------------------------- 当前评分
def get_score(conn: Any, account_id: str) -> ReputationScore | None:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {SCORE_COLUMNS} FROM reputation_scores WHERE account_id = %s",
                    (account_id,))
        row = cur.fetchone()
    return ReputationScore.from_row(row) if row else None


def upsert_score(conn: Any, account_id: str, *, score: int, tier: str, quality_coef: Any,
                 stability_coef: Any, window_days: int, policy_version: str,
                 computed_at: datetime, tier_since: datetime, prev_tier: str | None,
                 manual_tier: bool, reasons: Iterable[str] = ()) -> ReputationScore:
    """写当前态（一个账户一行）；等级变化时 ``tier_since`` 由调用方给出新起点。"""
    if not account_id:
        raise errors.InvalidArgument("account_id 必填")
    with conn.cursor() as cur:
        cur.execute(
            f"""INSERT INTO reputation_scores ({SCORE_COLUMNS})
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (account_id) DO UPDATE
                   SET score = EXCLUDED.score, tier = EXCLUDED.tier,
                       quality_coef = EXCLUDED.quality_coef,
                       stability_coef = EXCLUDED.stability_coef,
                       window_days = EXCLUDED.window_days,
                       policy_version = EXCLUDED.policy_version,
                       computed_at = EXCLUDED.computed_at,
                       tier_since = EXCLUDED.tier_since,
                       prev_tier = EXCLUDED.prev_tier,
                       manual_tier = EXCLUDED.manual_tier,
                       reasons = EXCLUDED.reasons,
                       updated_at = now()
                RETURNING {SCORE_COLUMNS}""",
            (account_id, int(score), tier, quality_coef, stability_coef, int(window_days),
             policy_version, computed_at, tier_since, prev_tier, bool(manual_tier),
             list(reasons)))
        row = cur.fetchone()
    return ReputationScore.from_row(row)


def score_page(conn: Any, *, tier: str | None = None, min_score: Any = None,
               limit: Any = None, cursor: str | None = None
               ) -> tuple[list[ReputationScore], str | None]:
    """后台只读列表（spec ``ReputationScorePage``）：按 ``(score, account_id)`` 倒序游标。"""
    size = _limit(limit)
    params: list[Any] = []
    clauses: list[str] = []
    if tier:
        if tier not in ("L1", "L2", "L3", "L4", "L5"):
            raise errors.InvalidArgument("tier 只支持 L1..L5")
        clauses.append("tier = %s")
        params.append(tier)
    if min_score not in (None, ""):
        try:
            floor = int(min_score)
        except (TypeError, ValueError) as exc:
            raise errors.InvalidArgument("min_score 必须是整数") from exc
        if not 0 <= floor <= 1000:
            raise errors.InvalidArgument("min_score 必须在 0..1000")
        clauses.append("score >= %s")
        params.append(floor)
    if cursor:
        data = decode_cursor_payload(cursor)
        try:
            last_score = int(data["s"])
            last_account = str(data["i"])
        except (KeyError, TypeError, ValueError) as exc:
            raise errors.CursorInvalid("游标不合法（内容缺失）") from exc
        clauses.append("(score, account_id) < (%s, %s)")
        params.extend([last_score, last_account])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT {SCORE_COLUMNS} FROM reputation_scores{where}
                 ORDER BY score DESC, account_id DESC LIMIT %s""", (*params, size + 1))
        rows = cur.fetchall()
    items = [ReputationScore.from_row(row) for row in rows[:size]]
    next_cursor = None
    if len(rows) > size and items:
        last = items[-1]
        next_cursor = encode_cursor_payload({"s": last.score, "i": last.account_id})
    return items, next_cursor


# --------------------------------------------------------------------------- 指标事实
def insert_event(conn: Any, account_id: str, *, metric: str, value: Any, weight: int,
                 delta: Any, ref_id: str | None, occurred_at: datetime,
                 event_id: uuid.UUID | None = None) -> bool:
    """追加一条指标事实（幂等：同 ``(account_id, metric, ref_id)`` 已存在 → 返回 False）。"""
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO reputation_events
                 (id, account_id, metric, value, weight, delta, ref_id, occurred_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT DO NOTHING
               RETURNING id""",
            (event_id or new_id(), account_id, metric, value, int(weight), delta,
             ref_id, occurred_at))
        row = cur.fetchone()
    return row is not None


def events_page(conn: Any, account_id: str, *, occurred_from: datetime | None = None,
                occurred_to: datetime | None = None, limit: Any = None,
                cursor: str | None = None) -> tuple[list[ReputationEvent], str | None]:
    size = _limit(limit)
    params: list[Any] = [account_id]
    clauses = ["account_id = %s"]
    if occurred_from is not None:
        clauses.append("occurred_at >= %s")
        params.append(occurred_from)
    if occurred_to is not None:
        clauses.append("occurred_at <= %s")
        params.append(occurred_to)
    if cursor:
        moment, row_id = decode_cursor(cursor)
        clauses.append("(occurred_at, id) < (%s, %s)")
        params.extend([moment, row_id])
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT id, account_id, metric, value, weight, delta, ref_id, occurred_at
                  FROM reputation_events WHERE {' AND '.join(clauses)}
                 ORDER BY occurred_at DESC, id DESC LIMIT %s""", (*params, size + 1))
        rows = cur.fetchall()
    items = [ReputationEvent.from_row(row) for row in rows[:size]]
    next_cursor = None
    if len(rows) > size and items:
        next_cursor = encode_cursor(items[-1].occurred_at, items[-1].id)
    return items, next_cursor


def latest_events(conn: Any, account_id: str, *, limit: int = 50) -> list[ReputationEvent]:
    """最近指标事实（重算的输入；纯读取）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT id, account_id, metric, value, weight, delta, ref_id, occurred_at
                  FROM reputation_events WHERE account_id = %s
                 ORDER BY occurred_at DESC, id DESC LIMIT %s""", (account_id, int(limit)))
        rows = cur.fetchall()
    return [ReputationEvent.from_row(row) for row in rows]
