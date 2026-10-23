# SPDX-License-Identifier: Apache-2.0
"""撮合与取价（M04 §6 流程 1 / INV-01 / INV-02 / §9 验收 ①③）。

纯函数在前、落库在后：

* :func:`intersection` —— INV-01 可成交判定：``a_lo ≤ b_hi ∧ b_lo ≤ a_hi``；
  未设端取 0 / +∞，单边设置退化为单边比较。
* :func:`take_price` —— INV-02 取价：成交价必须落在 ``[max(a_lo,b_lo), min(a_hi,b_hi)]``
  之内；mid（默认）/ floor（冷启动）/ ceiling（供给紧张）。
* :func:`plan` —— 在报价簿里挑一个成交对象（价低优先 + ``node_id`` 字典序，**确定性**）。
* :func:`create_booking` —— 同一事务里写 ``bookings(held)`` + ``quotes.state=consumed``
  + 发 ``booking.created``（M04 §6 流程 1）。
* :func:`expire_due` —— ``held → expired`` + 发 ``booking.expired``。

**无交集不产生 booking**（验收 ③）：返回 :class:`NoMatch`（价差 + 三个建议 + 价格带），
由调用方决定是拒绝还是改档，绝不静默。
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

from . import clock, facts, models
from .errors import InvalidArgument, NotFound, StateConflict

log = logging.getLogger("djb.scheduling.matching")

COLUMNS = ("id", "quote_id", "bid_id", "node_id", "tenant_id", "request_id", "price_minor",
           "strategy", "state", "created_at", "expires_at", "consumed_at")
SELECT_COLUMNS = ", ".join(COLUMNS)


# --------------------------------------------------------------------------- INV-01
def intersection(a_lo: int, a_hi: int | None, b_lo: int, b_hi: int | None) \
        -> tuple[int, int | None] | None:
    """区间交集；无交集返回 None（INV-01）。

    ``a_hi`` / ``b_hi`` 为 None 表示不设上限（+∞），此时成交上界取另一侧的上界。
    """
    if a_lo < 0 or b_lo < 0:
        raise InvalidArgument("区间下界不能为负（INV-13）")
    if a_hi is not None and a_hi < a_lo:
        raise InvalidArgument("供方区间非法：a_hi < a_lo（INV-01）")
    if b_hi is not None and b_hi < b_lo:
        raise InvalidArgument("用方区间非法：b_hi < b_lo（INV-01）")

    low = max(a_lo, b_lo)
    if a_hi is None:
        high = b_hi
    elif b_hi is None:
        high = a_hi
    else:
        high = min(a_hi, b_hi)

    if high is not None and low > high:
        return None
    return low, high


def matched(a_lo: int, a_hi: int | None, b_lo: int, b_hi: int | None) -> bool:
    return intersection(a_lo, a_hi, b_lo, b_hi) is not None


# --------------------------------------------------------------------------- INV-02
def take_price(strategy: str, low: int, high: int | None) -> int:
    """在交集 ``[low, high]`` 内取价（INV-02）。

    * ``floor``   取交集下界（冷启动：新节点靠低价拿到首批调度单元）
    * ``ceiling`` 取交集上界（供给紧张：按用方可接受的上限成交）
    * ``mid``     取中点（默认）；**上界缺省（+∞）时退化为下界**并打日志，
      因为无穷区间的中点在数学上无定义，不能拍一个数出来。
    """
    if strategy not in facts.PRICE_STRATEGIES:
        raise InvalidArgument(f"取价策略必须是 {facts.PRICE_STRATEGIES} 之一",
                              field="strategy")
    if low < 0:
        raise InvalidArgument("交集下界不能为负（INV-13）")
    if high is not None and high < low:
        raise InvalidArgument("交集非法：high < low（INV-02）")

    if strategy == "floor":
        return low
    if strategy == "ceiling":
        return high if high is not None else low
    if high is None:
        log.warning("scheduling.price.mid_unbounded",
                    extra={"event": "price.mid_unbounded", "low": low})
        return low
    return (low + high) // 2


# --------------------------------------------------------------------------- 撮合计划
@dataclass(frozen=True)
class MatchPlan:
    """一次可成交的撮合（尚未落库）。"""

    quote: models.Quote
    bid: models.Bid | None
    price_minor: int
    strategy: str
    interval_low: int
    interval_high: int | None

    def as_dict(self) -> dict[str, Any]:
        return {"quote_id": self.quote.quote_id, "node_id": self.quote.node_id,
                "bid_id": self.bid.bid_id if self.bid else None,
                "price_minor": self.price_minor, "strategy": self.strategy,
                "interval": [self.interval_low, self.interval_high]}


@dataclass(frozen=True)
class NoMatch:
    """无交集（验收 ③）：给价差 + 三个建议 + 当前价格带，不产生 booking。"""

    gap_minor: int | None
    suggestions: tuple[dict[str, str], ...]
    band: tuple[int, int] | None
    reason: str = "no_intersection"

    def as_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "gap_minor": self.gap_minor,
                "suggestions": list(self.suggestions),
                "band_minor": list(self.band) if self.band else None}


def plan(bid: models.Bid | None, quotes: Sequence[models.Quote], *,
         strategy: str | None = None, request_max_minor: int | None = None,
         unit: str | None = None) -> MatchPlan | NoMatch:
    """在候选报价里挑一个成交对象（确定性：价低 → ``node_id`` 字典序）。

    ``bid`` 为 None 表示「无出价」：区间退化为 ``[0, request_max]``，
    即只受请求侧上限约束（spec：min_price 缺省 0、max_price 缺省不设上限）。
    """
    chosen_strategy = (strategy or (bid.strategy if bid else facts.PRICE_STRATEGY_DEFAULT))
    b_lo = bid.min_price_minor if bid else 0
    b_hi = bid.max_price_minor if bid else None
    if bid is None and request_max_minor is not None:
        b_hi = request_max_minor
    elif bid is not None and request_max_minor is not None:
        b_hi = request_max_minor if b_hi is None else min(b_hi, request_max_minor)

    candidates: list[tuple[int, str, models.Quote, tuple[int, int | None]]] = []
    for quote in quotes:
        if unit is not None and quote.unit != unit:
            continue
        band = intersection(quote.a_lo, quote.a_hi, b_lo, b_hi)
        if band is None:
            continue
        price = take_price(chosen_strategy, band[0], band[1])
        candidates.append((price, quote.node_id, quote, band))

    if not candidates:
        return _no_match(quotes, b_lo, b_hi)

    price, _node, quote, band = min(candidates, key=lambda item: (item[0], item[1]))
    return MatchPlan(quote=quote, bid=bid, price_minor=price, strategy=chosen_strategy,
                     interval_low=band[0], interval_high=band[1])


def _no_match(quotes: Sequence[models.Quote], b_lo: int, b_hi: int | None) -> NoMatch:
    """诊断：价差 + 价格带 + 三个可执行建议（INV-06 的「下一步」）。"""
    gap: int | None = None
    band: tuple[int, int] | None = None
    if quotes:
        lows = [quote.a_lo for quote in quotes]
        highs = [quote.a_hi for quote in quotes if quote.a_hi is not None]
        band = (min(lows), max(highs) if highs else max(lows))
        if b_hi is not None and b_hi < band[0]:
            gap = band[0] - b_hi                      # 出价上限不够
        elif b_lo > band[1]:
            gap = b_lo - band[1]                      # 出价下限高于供给上限
    return NoMatch(gap_minor=gap, suggestions=facts.REJECT_ACTIONS, band=band)


# --------------------------------------------------------------------------- 落库
def create_booking(c, match: MatchPlan, *, tenant_id: uuid.UUID,
                   request_id: str | None = None, now: datetime | None = None,
                   trace_id: str = "", ttl_s: int = facts.BOOKING_TTL_S) -> models.Booking:
    """写成交锁（held）+ 消费报价（同事务）+ 发 ``booking.created``。

    ``tenant_id`` 由调用方从认证主体带入（出价可能为空，但**租户永远不能瞎猜**）。
    """
    moment = now or clock.utcnow()
    identifier = models.uuid7(int(moment.timestamp() * 1_000_000))
    expires_at = moment + timedelta(seconds=ttl_s)
    from . import quotes as quote_book                      # 同包内，避免循环 import

    quote_book.mark_consumed_by_booking(c, match.quote.id, now=moment)
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO bookings (id, quote_id, bid_id, node_id, tenant_id, request_id,
                                      price_minor, strategy, state, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'held', %s, %s)
                RETURNING {SELECT_COLUMNS}""",
            (identifier, match.quote.id, match.bid.id if match.bid else None,
             match.quote.node_id, tenant_id, request_id, match.price_minor,
             match.strategy, moment, expires_at))
        booking = models.Booking.from_row(cur.fetchone())
    log.info("scheduling.booking.created", extra={"event": "booking.created",
                                                  "booking_id": booking.booking_id,
                                                  "node_id": booking.node_id})
    from . import events

    events.booking_created(c, booking, trace_id=trace_id or booking.booking_id,
                          occurred_at=moment)
    return booking


def get(c, booking_id: str | uuid.UUID) -> models.Booking:
    try:
        identifier = booking_id if isinstance(booking_id, uuid.UUID) \
            else uuid.UUID(str(booking_id))
    except (ValueError, AttributeError) as exc:
        raise NotFound("成交锁 ID 形态非法", reason="booking_not_found",
                       object="booking") from exc
    with c.cursor() as cur:
        cur.execute(f"SELECT {SELECT_COLUMNS} FROM bookings WHERE id = %s", (identifier,))
        row = cur.fetchone()
    if row is None:
        raise NotFound("成交锁不存在", reason="booking_not_found", object="booking")
    return models.Booking.from_row(row)


def consume(c, booking_id: str | uuid.UUID, *, now: datetime | None = None) \
        -> models.Booking:
    """``held → consumed``（业务消费完成）。已终结的锁拒绝（40902）。"""
    moment = now or clock.utcnow()
    booking = get(c, booking_id)
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE bookings SET state = 'consumed', consumed_at = %s
                 WHERE id = %s AND state = 'held'
                 RETURNING {SELECT_COLUMNS}""", (moment, booking.id))
        row = cur.fetchone()
    if row is None:
        raise StateConflict("成交锁已终结，不能重复消费（只能新建）",
                            reason="booking_not_consumable", booking_id=booking.booking_id)
    return models.Booking.from_row(row)


def expire_due(c, *, now: datetime | None = None, trace_id: str = "") \
        -> list[models.Booking]:
    """``held → expired``（TTL 到期）+ 发 ``booking.expired``。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE bookings SET state = 'expired'
                 WHERE state = 'held' AND expires_at <= %s
                 RETURNING {SELECT_COLUMNS}""", (moment,))
        expired = [models.Booking.from_row(row) for row in cur.fetchall()]
    if expired:
        from . import events

        for booking in expired:
            events.booking_expired(c, booking, trace_id=trace_id or booking.booking_id,
                                   occurred_at=moment)
    return expired


def book_summary(quotes: Iterable[models.Quote]) -> dict[str, Any]:
    """报价簿汇总（公开快照 / 诊断用；只有价格与计数，没有节点身份细节）。"""
    items = list(quotes)
    lows = [item.a_lo for item in items]
    return {"quote_count": len(items),
            "min_ask_minor": min(lows) if lows else None,
            "max_ask_minor": max(lows) if lows else None,
            "models": sorted({item.model for item in items})}


__all__ = ["COLUMNS", "SELECT_COLUMNS", "intersection", "matched", "take_price", "MatchPlan",
           "NoMatch", "plan", "create_booking", "get", "consume", "expire_due", "book_summary"]
