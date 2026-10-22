# SPDX-License-Identifier: Apache-2.0
"""扫码登录中间态（M01 §6.1、§8.2：中间态 TTL ≤120 s，一次性）。

状态机（库层 ``identity_scan_tickets_shape_chk`` 同步约束）::

    created ──扫码──▶ scanned ──确认──▶ confirmed ──换取令牌──▶ consumed
       └───────────── 120 s 到期 / 主动作废 ──▶ expired

规则：
- 票据只存 ``sha256(ticket)``；明文只在二维码内容里出现一次（不落库、不落日志）。
- 一次性：``consume`` 之后任何再用 → 40905。
- 扫码与确认必须是**同一个账户**（否则 40905，防抢票）。
- 到期判定用服务端时钟（``clock.utcnow``），轮询时顺带把到期票据标 expired（可重放）。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from . import clock, credentials, errors, models

SCAN_TICKET_TTL_SECONDS = models.SCAN_TICKET_TTL_SECONDS

_COLS = ("id, ticket_hash, status, account_id, created_at, expires_at, scanned_at, "
         "confirmed_at, consumed_at")


@dataclass(frozen=True)
class Ticket:
    id: uuid.UUID
    status: str
    account_id: uuid.UUID | None
    created_at: datetime
    expires_at: datetime
    scanned_at: datetime | None
    confirmed_at: datetime | None
    consumed_at: datetime | None

    @property
    def live(self) -> bool:
        return self.status in ("created", "scanned", "confirmed")

    def retry_after_s(self, moment: datetime) -> int:
        """轮询建议间隔（客户端用；服务端不依赖它）。"""
        remaining = int((self.expires_at - moment).total_seconds())
        return max(1, min(5, remaining or 1))


def _now(now: datetime | None) -> datetime:
    return now.astimezone(clock.utcnow().tzinfo) if now else clock.utcnow()


def _row(c, *, ticket: str | None = None, ticket_id: uuid.UUID | None = None,
         for_update: bool = False) -> Ticket | None:
    sql = f"SELECT {_COLS} FROM identity_scan_tickets WHERE "
    params: tuple
    if ticket is not None:
        sql += "ticket_hash = %s"
        params = (credentials.token_hash(ticket),)
    else:
        sql += "id = %s"
        params = (ticket_id,)
    with c.cursor() as cur:
        cur.execute(sql + (" FOR UPDATE" if for_update else ""), params)
        row = models._one(cur)
    return models._make(Ticket, row) if row else None


def _expire_if_due(c, ticket: Ticket, moment: datetime) -> Ticket:
    """到期即标 expired（可重放；已 confirmed 的不再作废，交给 consume）。"""
    if ticket.live and ticket.status != "confirmed" and ticket.expires_at <= moment:
        with c.cursor() as cur:
            cur.execute(
                f"""UPDATE identity_scan_tickets SET status = 'expired'
                     WHERE id = %s AND status IN ('created', 'scanned') RETURNING {_COLS}""",
                (ticket.id,))
            row = models._one(cur)
        if row:
            return models._make(Ticket, row)
    return ticket


def create(c, *, now: datetime | None = None,
           ticket_id: uuid.UUID | None = None) -> tuple[Ticket, str]:
    """生成扫码票据：返回 (票据, 明文)。二维码里放明文，库里只有哈希。"""
    moment = _now(now)
    plaintext = credentials.new_token()[0]
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO identity_scan_tickets (id, ticket_hash, status, created_at, expires_at)
                VALUES (%s, %s, 'created', %s, %s)
                RETURNING {_COLS}""",
            (ticket_id or models.uuid7(), credentials.token_hash(plaintext), moment,
             moment + timedelta(seconds=SCAN_TICKET_TTL_SECONDS)),
        )
        return models._make(Ticket, models._one(cur)), plaintext


def scan(c, ticket: str, *, account_id: uuid.UUID, now: datetime | None = None) -> Ticket:
    """扫码：created → scanned（绑定扫码账户）。"""
    moment = _now(now)
    current = _row(c, ticket=ticket, for_update=True)
    if current is None:
        raise errors.ScanTicketInvalid("扫码票据无效")
    current = _expire_if_due(c, current, moment)
    if current.status != "created":
        raise errors.ScanTicketInvalid(f"票据当前状态不可扫码：{current.status}",
                                       status=current.status)
    models.get_account(c, account_id)                 # 账户不存在 → 40401
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE identity_scan_tickets
                   SET status = 'scanned', account_id = %s, scanned_at = %s
                 WHERE id = %s RETURNING {_COLS}""",
            (account_id, moment, current.id))
        return models._make(Ticket, models._one(cur))


def confirm(c, ticket: str, *, account_id: uuid.UUID, now: datetime | None = None) -> Ticket:
    """确认登录：scanned → confirmed（必须是扫码的那个账户）。"""
    moment = _now(now)
    current = _row(c, ticket=ticket, for_update=True)
    if current is None:
        raise errors.ScanTicketInvalid("扫码票据无效")
    current = _expire_if_due(c, current, moment)
    if current.status != "scanned":
        raise errors.ScanTicketInvalid(f"票据当前状态不可确认：{current.status}",
                                       status=current.status)
    if current.account_id != account_id:
        raise errors.ScanTicketInvalid("确认账户与扫码账户不一致", reason="ticket_owner_mismatch")
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE identity_scan_tickets
                   SET status = 'confirmed', confirmed_at = %s
                 WHERE id = %s RETURNING {_COLS}""",
            (moment, current.id))
        return models._make(Ticket, models._one(cur))


def poll(c, ticket: str, *, now: datetime | None = None) -> Ticket:
    """轮询状态（顺带把到期票据标 expired）；未知票据 40905。"""
    moment = _now(now)
    current = _row(c, ticket=ticket)
    if current is None:
        raise errors.ScanTicketInvalid("扫码票据无效")
    return _expire_if_due(c, current, moment)


def consume(c, ticket: str, *, now: datetime | None = None) -> Ticket:
    """换取令牌：confirmed → consumed（一次性）。"""
    moment = _now(now)
    current = _row(c, ticket=ticket, for_update=True)
    if current is None:
        raise errors.ScanTicketInvalid("扫码票据无效")
    current = _expire_if_due(c, current, moment)
    if current.status != "confirmed":
        raise errors.ScanTicketInvalid(f"票据当前状态不可换取令牌：{current.status}",
                                       status=current.status)
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE identity_scan_tickets SET status = 'consumed', consumed_at = %s
                 WHERE id = %s RETURNING {_COLS}""",
            (moment, current.id))
        return models._make(Ticket, models._one(cur))


def get(c, ticket_id: uuid.UUID) -> Ticket:
    found = _row(c, ticket_id=ticket_id)
    if found is None:
        raise errors.ScanTicketInvalid("扫码票据不存在")
    return found


__all__ = ["SCAN_TICKET_TTL_SECONDS", "Ticket", "create", "scan", "confirm", "poll",
           "consume", "get"]
