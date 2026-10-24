# SPDX-License-Identifier: AGPL-3.0-or-later
"""出价簿（M04 §3 Bid / §5 bids / spec ``BidRequest``）。

规则与报价簿同款（只追加 + 版本化 + 内容不变不升版本），差别只有两点：

* 版本号是 **``(tenant_id, model)`` 维度**的：一个租户的价格调整不会影响别的租户；
* 出价**不锁量**（spec：成交由 M04 决策产生，本表不承担成交锁）——锁在 ``bookings``。

区间语义（INV-01）：``min_price_minor`` = b_lo（缺省 0），``max_price_minor`` = b_hi
（缺省 = +∞），因此「只设下限」「只设上限」「两端都不设」都能退化成一维比较。
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from . import clock, facts, models
from .errors import InvalidArgument, NotFound

log = logging.getLogger("djb.scheduling.bids")

COLUMNS = ("id", "tenant_id", "model", "min_price_minor", "max_price_minor", "strategy",
           "currency", "state", "bid_version", "created_at", "expires_at")
SELECT_COLUMNS = ", ".join(COLUMNS)

LOCK_NAMESPACE = 4002
LOCK_BID_BOOK = 1


@dataclass(frozen=True)
class BidResult:
    bid: models.Bid
    created: bool


def _lock_book(c) -> None:
    with c.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s, %s)", (LOCK_NAMESPACE, LOCK_BID_BOOK))


def next_version(c, *, tenant_id: uuid.UUID, model: str) -> int:
    with c.cursor() as cur:
        cur.execute("SELECT COALESCE(max(bid_version), 0) FROM bids "
                    "WHERE tenant_id = %s AND model = %s", (tenant_id, model))
        row = cur.fetchone()
    return int(row[0]) + 1 if row else 1


def get(c, bid_id: str | uuid.UUID) -> models.Bid:
    try:
        identifier = bid_id if isinstance(bid_id, uuid.UUID) else uuid.UUID(str(bid_id))
    except (ValueError, AttributeError) as exc:
        raise NotFound("出价 ID 形态非法", reason="bid_not_found", object="bid") from exc
    with c.cursor() as cur:
        cur.execute(f"SELECT {SELECT_COLUMNS} FROM bids WHERE id = %s", (identifier,))
        row = cur.fetchone()
    if row is None:
        raise NotFound("出价不存在", reason="bid_not_found", object="bid")
    return models.Bid.from_row(row)


def latest_active(c, *, tenant_id: uuid.UUID, model: str,
                  now: datetime | None = None) -> models.Bid | None:
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {SELECT_COLUMNS} FROM bids
                 WHERE tenant_id = %s AND model = %s AND state = 'active' AND expires_at > %s
                 ORDER BY bid_version DESC LIMIT 1""",
            (tenant_id, model, moment))
        row = cur.fetchone()
    return models.Bid.from_row(row) if row else None


def register(c, *, tenant_id: uuid.UUID, model: str, min_price_minor: int = 0,
             max_price_minor: int | None = None, strategy: str | None = None,
             window_seconds: int | None = None, now: datetime | None = None,
             trace_id: str = "") -> BidResult:
    """写出一条出价（内容不变不升版本）。"""
    moment = now or clock.utcnow()
    if min_price_minor < 0 or min_price_minor > facts.MAX_PRICE_MINOR:
        raise InvalidArgument("min_price 超出允许范围", field="min_price")
    if max_price_minor is not None:
        if max_price_minor < 0 or max_price_minor > facts.MAX_PRICE_MINOR:
            raise InvalidArgument("max_price 超出允许范围", field="max_price")
        if max_price_minor < min_price_minor:
            raise InvalidArgument("max_price 必须 ≥ min_price（INV-01）", field="max_price")
    chosen_strategy = (strategy or facts.PRICE_STRATEGY_DEFAULT).strip().lower()
    if chosen_strategy not in facts.PRICE_STRATEGIES:
        raise InvalidArgument(f"strategy 必须是 {facts.PRICE_STRATEGIES} 之一",
                              field="strategy")
    window = window_seconds if window_seconds is not None else facts.DEFAULT_BID_WINDOW_S
    if not isinstance(window, int) or isinstance(window, bool) or not 1 <= window <= 2_592_000:
        raise InvalidArgument("window_seconds 必须是 1–2592000 的整数", field="window_seconds")

    expires_at = moment + timedelta(seconds=window)
    _lock_book(c)
    existing = latest_active(c, tenant_id=tenant_id, model=model, now=moment)
    if existing is not None and existing.signature() == (tenant_id, model, min_price_minor,
                                                         max_price_minor, chosen_strategy,
                                                         facts.CURRENCY):
        return BidResult(bid=existing, created=False)

    version = next_version(c, tenant_id=tenant_id, model=model)
    identifier = models.uuid7(int(moment.timestamp() * 1_000_000))
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO bids (id, tenant_id, model, min_price_minor, max_price_minor,
                                  strategy, currency, state, bid_version, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'active', %s, %s, %s)
                RETURNING {SELECT_COLUMNS}""",
            (identifier, tenant_id, model, min_price_minor, max_price_minor, chosen_strategy,
             facts.CURRENCY, version, moment, expires_at))
        bid = models.Bid.from_row(cur.fetchone())
    log.info("scheduling.bid.created", extra={"event": "bid.created", "bid_id": bid.bid_id,
                                              "bid_version": version})
    return BidResult(bid=bid, created=True)


def active_book(c, *, now: datetime | None = None, model: str | None = None,
                tenant_id: uuid.UUID | None = None) -> list[models.Bid]:
    moment = now or clock.utcnow()
    clauses = ["state = 'active'", "expires_at > %s"]
    params: list[Any] = [moment]
    if model is not None:
        clauses.append("model = %s")
        params.append(model)
    if tenant_id is not None:
        clauses.append("tenant_id = %s")
        params.append(tenant_id)
    where = " AND ".join(clauses)
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT DISTINCT ON (tenant_id, model) {SELECT_COLUMNS}
                  FROM bids WHERE {where}
                 ORDER BY tenant_id, model, bid_version DESC""", params)
        return [models.Bid.from_row(row) for row in cur.fetchall()]


def expire_due(c, *, now: datetime | None = None) -> list[models.Bid]:
    """过期清理：``active → expired``。出价过期不产生事件（02-events 无 bid.* 事件）。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE bids SET state = 'expired'
                 WHERE state = 'active' AND expires_at <= %s
                 RETURNING {SELECT_COLUMNS}""", (moment,))
        return [models.Bid.from_row(row) for row in cur.fetchall()]


__all__ = ["COLUMNS", "SELECT_COLUMNS", "BidResult", "next_version", "get", "latest_active",
           "register", "active_book", "expire_due", "LOCK_NAMESPACE"]
