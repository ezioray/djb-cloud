# SPDX-License-Identifier: Apache-2.0
"""M07 单层邀请（INV-03 / INV-04 / §6.2）。

对外只有一条只读接口（spec ``GET /api/v1/user/cop/invites``）；**发码与绑定是内部函数**
（S1 由运营 / M14 触发，不新增用户侧路由——spec 没有对应端点，不得自造）。

不变量落地：

* **INV-03 只有一层**：领域层先判（给出 409 / 422 的干净错误码），DB 触发器兜底
  （``invites_single_layer``），两条路都拒绝二级链路；
* **INV-04 唯一**：``(inviter_id, invitee_id)`` 部分唯一 + 「一个被邀请人只绑一次」部分唯一；
* 反自邀 / 同设备簇 / 同支付方式簇：读 ``points_account`` 的风控簇字段（只读）。

奖励计提（§6.2）在 :mod:`app.reputation.events` 里做（每笔 ``usage.settled`` 按
``points.invite_bps`` 给邀请人计提到「绑定日 + ``points.invite_months``」为止）。
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any

from . import clock, errors, outbox
from .models import Invite, InviteOverview, decode_cursor, encode_cursor, new_id

__all__ = [
    "issue", "bind", "revoke", "expire_due", "list_overview", "bound_invite_of",
    "reward_window_end", "generate_code", "INVITE_CODE_ALPHABET",
]

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200
#: 邀请码字符集（去掉易混的 0/O/1/I）
INVITE_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 10
DEFAULT_EXPIRE_DAYS = 30


def generate_code() -> str:
    """生成邀请码（``secrets`` 取随机源；唯一性由 ``invites_code_uq`` 兜底）。"""
    return "".join(secrets.choice(INVITE_CODE_ALPHABET) for _ in range(CODE_LENGTH))


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


# --------------------------------------------------------------------------- 内部：发码
def issue(conn: Any, inviter_id: str, *, code: str | None = None,
          expire_at: datetime | None = None, issued_by: str = "self",
          now: datetime | None = None) -> Invite:
    """发放一张待绑定邀请（``status='sent'``）。同一邀请码不可复用（唯一索引兜底）。"""
    moment = clock.as_utc(now)
    if not inviter_id:
        raise errors.InvalidArgument("inviter_id 必填")
    expires = clock.as_utc(expire_at) if expire_at is not None \
        else moment + timedelta(days=DEFAULT_EXPIRE_DAYS)
    if expires <= moment:
        raise errors.InvalidArgument("expire_at 必须晚于当前时刻")
    record_id = new_id()
    attempts = 0
    while True:
        candidate = code or generate_code()
        attempts += 1
        row = None
        with conn.cursor() as cur:
            cur.execute("SAVEPOINT m07_invite_code")
            try:
                cur.execute(
                    """INSERT INTO invites (id, inviter_id, code, status, expire_at,
                                            created_at, issued_by)
                       VALUES (%s,%s,%s,'sent',%s,%s,%s)
                       RETURNING id, inviter_id, invitee_id, code, status, bound_at,
                                 expire_at, created_at""",
                    (record_id, inviter_id, candidate, expires, moment, issued_by))
                row = cur.fetchone()
                cur.execute("RELEASE SAVEPOINT m07_invite_code")
            except Exception as exc:                         # noqa: BLE001 - 唯一冲突重试
                cur.execute("ROLLBACK TO SAVEPOINT m07_invite_code")
                if code is not None or not _is_unique_violation(exc):
                    raise
                if attempts > 5:                             # pragma: no cover - 概率兜底
                    raise errors.Conflict("邀请码生成冲突，请重试",
                                          reason="code_collision") from exc
        if row is not None:
            return Invite.from_row((*row, 0))


# --------------------------------------------------------------------------- 内部：绑定
def bind(conn: Any, code: str, invitee_id: str, *, now: datetime | None = None,
         actor: str = "system:m07") -> Invite:
    """绑定邀请（§6.2）：单层 / 唯一 / 未过期 / 非自邀 / 非同一簇，全部通过才落库。"""
    moment = clock.as_utc(now)
    if not code or not invitee_id:
        raise errors.InvalidArgument("code 与 invitee_id 必填")
    with conn.cursor() as cur:
        cur.execute(
            """SELECT id, inviter_id, invitee_id, code, status, bound_at, expire_at, created_at
                 FROM invites WHERE code = %s""", (code,))
        row = cur.fetchone()
    if row is None:
        raise errors.NotFound("邀请不存在或已失效")
    invite = Invite.from_row((*row, 0))

    if invite.status == "bound":
        if invite.invitee_id == invitee_id:
            raise errors.InviteStateConflict("邀请已绑定", reason="already_bound")
        raise errors.InviteStateConflict("邀请已被他人绑定", reason="already_bound")
    if invite.status in ("expired", "revoked"):
        raise errors.InviteStateConflict(f"邀请状态 {invite.status} 不可绑定",
                                         reason=f"invite_{invite.status}")
    if invite.expire_at is not None and invite.expire_at <= moment:
        raise errors.InviteStateConflict("邀请已过期", reason="invite_expired")

    _assert_single_layer(conn, invite.inviter_id, invitee_id)
    _assert_not_same_cluster(conn, invite.inviter_id, invitee_id)

    with conn.cursor() as cur:
        cur.execute(
            """UPDATE invites SET status = 'bound', invitee_id = %s, bound_at = %s
                WHERE id = %s AND status = 'sent'
                RETURNING id, inviter_id, invitee_id, code, status, bound_at, expire_at,
                          created_at""", (invitee_id, moment, invite.id))
        updated = cur.fetchone()
    if updated is None:                                      # pragma: no cover - 并发兜底
        raise errors.InviteStateConflict("邀请状态已变化", reason="already_bound")
    bound = Invite.from_row((*updated, 0))
    # §6.2：invites(bound) 与 outbox 同一事务
    outbox.enqueue(conn, outbox.invite_bound(
        inviter_id=bound.inviter_id, invitee_id=str(bound.invitee_id), code=bound.code,
        occurred_at=bound.bound_at))
    return bound


def revoke(conn: Any, invite_id: Any, *, actor: str = "admin:m07",
           now: datetime | None = None) -> Invite:
    """撤销一张已绑定邀请（``bound→revoked``；已发放 COP 不回溯，§3 状态机）。"""
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE invites SET status = 'revoked'
                WHERE id = %s AND status = 'bound'
                RETURNING id, inviter_id, invitee_id, code, status, bound_at, expire_at,
                          created_at""", (invite_id,))
        row = cur.fetchone()
    if row is None:
        raise errors.InviteStateConflict("只有已绑定的邀请可撤销", reason="invite_state")
    return Invite.from_row((*row, 0))


def expire_due(conn: Any, *, now: datetime | None = None) -> list[str]:
    """到期结转 job（§4.3）：``sent`` 且已过期 → ``expired``。幂等（可重复执行）。"""
    moment = clock.as_utc(now)
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE invites SET status = 'expired'
                WHERE status = 'sent' AND expire_at IS NOT NULL AND expire_at <= %s
                RETURNING id""", (moment,))
        return [str(row[0]) for row in cur.fetchall()]


# --------------------------------------------------------------------------- 不变量
def _assert_single_layer(conn: Any, inviter_id: str, invitee_id: str) -> None:
    """INV-03：邀请人不得自己是被邀请人；被邀请人不得已经是邀请人。"""
    if inviter_id == invitee_id:
        raise errors.ValidationFailed("不可自邀（INV-04）", reason="self_invite")
    with conn.cursor() as cur:
        cur.execute(
            """SELECT inviter_id FROM invites
                WHERE invitee_id = %s AND status = 'bound' LIMIT 1""", (inviter_id,))
        parent = cur.fetchone()
        if parent is not None:
            raise errors.InviteStateConflict(
                "邀请只有一层（INV-03）：该账户已是被邀请人", reason="invite_layer")
        cur.execute("SELECT 1 FROM invites WHERE inviter_id = %s LIMIT 1", (invitee_id,))
        if cur.fetchone() is not None:
            raise errors.ValidationFailed(
                "被邀请人已是邀请人，绑定会形成二级链路（INV-03）", reason="invite_layer")


def _assert_not_same_cluster(conn: Any, inviter_id: str, invitee_id: str) -> None:
    """INV-04：同设备簇 / 同支付方式簇拒绝（读 ``points_account`` 的风控簇字段，只读）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT account_id, device_cluster, payment_cluster FROM points_account
                WHERE account_id IN (%s, %s)""", (inviter_id, invitee_id))
        rows = {row[0]: (row[1], row[2]) for row in cur.fetchall()}
    inviter = rows.get(inviter_id, (None, None))
    invitee = rows.get(invitee_id, (None, None))
    if inviter[0] and inviter[0] == invitee[0]:
        raise errors.ValidationFailed("不可绑定同一设备簇（INV-04）", reason="same_device_cluster")
    if inviter[1] and inviter[1] == invitee[1]:
        raise errors.ValidationFailed("不可绑定同一支付方式簇（INV-04）",
                                      reason="same_payment_cluster")


def _is_unique_violation(exc: Exception) -> bool:
    name = type(exc).__name__
    sqlstate = getattr(exc, "sqlstate", None) or getattr(getattr(exc, "diag", None), "sqlstate", None)
    return name == "UniqueViolation" or sqlstate == "23505"


# --------------------------------------------------------------------------- 读：概览
def list_overview(conn: Any, inviter_id: str, *, limit: Any = None,
                  cursor: str | None = None, invite_months: int = 12
                  ) -> InviteOverview:
    """我的邀请概览（spec ``InviteOverview``）：逐条状态 + 累计奖励 + 游标分页。"""
    size = _limit(limit)
    params: list[Any] = [int(invite_months), inviter_id]
    clause = ""
    if cursor:
        moment, row_id = decode_cursor(cursor)
        clause = " AND (i.created_at, i.id) < (%s, %s)"
        params.extend([moment, row_id])
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT i.id, i.inviter_id, i.invitee_id, i.code, i.status, i.bound_at,
                       i.expire_at, i.created_at,
                       CASE WHEN i.status = 'bound' THEN COALESCE((
                            SELECT SUM(l.amount) FROM v_m07_cop_ledger l
                             WHERE l.account_id = i.inviter_id AND l.source = 'invite'
                               AND l.direction = 'credit'
                               AND l.created_at >= i.bound_at
                               AND l.created_at < i.bound_at + make_interval(months => %s)
                       ), 0) ELSE 0 END AS earned_units
                  FROM invites i
                 WHERE i.inviter_id = %s{clause}
                 ORDER BY i.created_at DESC, i.id DESC LIMIT %s""", (*params, size + 1))
        rows = cur.fetchall()
        cur.execute(
            """SELECT COUNT(*) FILTER (WHERE status = 'bound'),
                      COUNT(*) FILTER (WHERE status = 'sent')
                 FROM invites WHERE inviter_id = %s""", (inviter_id,))
        bound, pending = (int(value) for value in cur.fetchone())
        cur.execute(
            """SELECT COALESCE(SUM(amount), 0) FROM v_m07_cop_ledger
                WHERE account_id = %s AND source = 'invite' AND direction = 'credit'""",
            (inviter_id,))
        earned = int(cur.fetchone()[0])
    items = [Invite.from_row(row) for row in rows[:size]]
    next_cursor = None
    if len(rows) > size and items:
        next_cursor = encode_cursor(items[-1].created_at, items[-1].id)
    return InviteOverview(items=items, bound=bound, pending=pending, earned_units=earned,
                          start_cursor=cursor, next_cursor=next_cursor)


def bound_invite_of(conn: Any, invitee_id: str) -> Invite | None:
    """该账户绑定的邀请（§6.2：奖励计提只对已绑定且未过窗口的被邀请人生效）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT id, inviter_id, invitee_id, code, status, bound_at, expire_at, created_at
                 FROM invites WHERE invitee_id = %s AND status = 'bound'
                 ORDER BY bound_at DESC LIMIT 1""", (invitee_id,))
        row = cur.fetchone()
    return Invite.from_row((*row, 0)) if row else None


def reward_window_end(bound_at: datetime, invite_months: int) -> datetime:
    """奖励计提窗口结束时刻 = 绑定日 + ``points.invite_months``（不追溯，§6.2）。"""
    return clock.as_utc(bound_at) + timedelta(days=30 * int(invite_months))
