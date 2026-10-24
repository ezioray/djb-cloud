# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 人工授予 / 扣回（spec ``POST /api/v1/admin/reputation/grants`` / CR-5 / §7）。

规则（全部在写账之前判定）：

1. **step-up 必填**（424 / 42401）——由路由层校验头 ``X-Admin-Step-Up``；
2. **理由必填**（1–512 字符）→ 缺了是 400 / 40001；
3. **双人复核**：复核人必填且 ≠ 发起人 → 否则 409 / 40919；
4. **账户必须存在**（``points_account`` 有档案）→ 否则 404 / 40401（不泄露存在性）；
5. **扣回不得把余额扣成负数**（INV-01）→ 可用量不足 402 / 40201；
6. 幂等：``X-DJB-Idempotency-Key`` 24h；同键重复请求返回**第一次**的结果，不重复记财。

落账口径：金额以 COP 唯一账本（``points_*``）为准，本模块的 ``reward_grants`` 只存作业凭据
（谁发起、谁复核、为什么、关联哪条 journal），**不重复记账**。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app import points as cop_ledger

from . import clock, errors, outbox
from .cop import translate
from .models import GRANT_COLUMNS, Grant, new_id

__all__ = ["create", "list_grants", "MAX_REASON", "MAX_UNITS"]

MAX_REASON = 512
MAX_UNITS = 1_000_000


def _validate(*, account_id: Any, kind: Any, units: Any, reason: Any,
              actor: Any, approved_by: Any) -> tuple[str, str, int, str, str, str]:
    if not account_id or not isinstance(account_id, str):
        raise errors.InvalidArgument("account_id 必填")
    if kind not in ("grant", "clawback"):
        raise errors.InvalidArgument("kind 只支持 grant / clawback")
    try:
        amount = int(units)
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument("units 必须是正整数") from exc
    if amount <= 0 or amount > MAX_UNITS:
        raise errors.InvalidArgument("units 必须在 1..1000000")
    text = (reason or "").strip() if isinstance(reason, str) else ""
    if not text:
        raise errors.InvalidArgument("reason 必填（§4.1 必须带理由）")
    if len(text) > MAX_REASON:
        raise errors.InvalidArgument(f"reason 不得超过 {MAX_REASON} 字符")
    if not actor or not isinstance(actor, str):
        raise errors.Unauthorized("缺少发起人主体")
    if not approved_by or not isinstance(approved_by, str):
        raise errors.ReviewerConflict("必须提供复核人（双人复核）", reason="approver_missing")
    if approved_by == actor:
        raise errors.ReviewerConflict("复核人不得等于发起人（双人复核）",
                                      reason="approver_is_actor")
    return account_id, kind, amount, text, actor, approved_by


def create(conn: Any, *, account_id: Any, kind: Any, units: Any, reason: Any, actor: Any,
           approved_by: Any, approval_id: str | None = None, request_id: str | None = None,
           now: datetime | None = None) -> Grant:
    """人工授予（``grant``）/ 扣回（``clawback``）。"""
    moment = clock.as_utc(now)
    account_id, kind, amount, reason_text, actor, approved_by = _validate(
        account_id=account_id, kind=kind, units=units, reason=reason, actor=actor,
        approved_by=approved_by)

    replay = _replay(conn, request_id)
    if replay is not None:
        if replay.account_id != account_id or replay.kind != kind or replay.units != amount:
            raise errors.Conflict("幂等键已被不同载荷使用", reason="idempotency_conflict")
        return replay

    if _account_missing(conn, account_id):
        raise errors.NotFound("账户不存在")

    grant_id = new_id()
    signed = amount if kind == "grant" else -amount
    try:
        journal = cop_ledger.adjust(
            conn, account_id, signed,
            reason_code="manual_grant" if kind == "grant" else "manual_clawback",
            approved_by=approved_by, actor=actor, ref_id=str(grant_id), request_id=request_id)
    except cop_ledger.PointsError as exc:
        raise translate(exc, context="redeem") from exc

    with conn.cursor() as cur:
        cur.execute(
            f"""INSERT INTO reward_grants
                 (id, account_id, kind, amount, reason, actor, approved_by, approval_id,
                  journal_id, request_id, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               RETURNING {GRANT_COLUMNS}""",
            (grant_id, account_id, kind, amount, reason_text, actor, approved_by,
             approval_id, journal["journal_id"], request_id, moment))
        row = cur.fetchone()

    # 事件：授予 → cop.earned(reward)；扣回 → cop.spent(revoke)
    if kind == "grant":
        envelope = outbox.cop_earned(account_id=account_id, units=amount, source="reward",
                                     ref_id=str(grant_id), lock_until=None,
                                     occurred_at=moment,
                                     journal_id=str(journal["journal_id"]))
    else:
        envelope = outbox.cop_spent(account_id=account_id, units=amount, source="revoke",
                                    ref_id=str(grant_id), occurred_at=moment,
                                    journal_id=str(journal["journal_id"]))
    outbox.enqueue(conn, envelope)
    return Grant.from_row(row)


def list_grants(conn: Any, account_id: str, *, limit: int = 50) -> list[Grant]:
    """某账户的人工授予 / 扣回记录（后台排障只读；按时间倒序）。"""
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT {GRANT_COLUMNS} FROM reward_grants WHERE account_id = %s
                 ORDER BY created_at DESC, id DESC LIMIT %s""", (account_id, int(limit)))
        rows = cur.fetchall()
    return [Grant.from_row(row) for row in rows]


# --------------------------------------------------------------------------- 内部
def _account_missing(conn: Any, account_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM points_account WHERE account_id = %s", (account_id,))
        return cur.fetchone() is None


def _replay(conn: Any, request_id: str | None) -> Grant | None:
    if not request_id:
        return None
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT {GRANT_COLUMNS} FROM reward_grants WHERE request_id = %s""",
            (request_id,))
        row = cur.fetchone()
    return Grant.from_row(row) if row else None
