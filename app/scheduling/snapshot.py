# SPDX-License-Identifier: Apache-2.0
"""公开快照（M04 §1 责任 / §4.1 ``GET /api/v1/schedule/snapshot/{period}``）。

**只发布输入**：报价区间、``quote_version``、计数与时间；不发布权重、阈值、ρ/κ 明细、
正文与凭据（M04 §1「发布只含输入的公开快照」/ INV-12）。

``period`` 三种取值：

* ``latest`` —— 当前有效报价簿；
* ``YYYY-MM-DD`` —— 该 UTC 日结束时刻的历史视图（按 ``created_at`` 与 ``expires_at``
  还原「当时有效的版本」，用于对账与事后解释）；
* 其它 → ``40401``（不猜测用户想要什么）。
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from . import clock, facts, matching, models, quotes
from .errors import InvalidArgument, NotFound

PERIOD_PATH_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _period_moment(period: str, now: datetime) -> datetime | None:
    """``latest`` → None；``YYYY-MM-DD`` → 该日 23:59:59.999999 UTC。"""
    if period == facts.SNAPSHOT_PERIOD_LATEST:
        return None
    if PERIOD_PATH_RE.match(period or ""):
        try:
            day = datetime.strptime(period, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise InvalidArgument("period 必须是 YYYY-MM-DD 或 latest", field="period") from exc
        if day > now:
            raise InvalidArgument("period 不能是未来日期", field="period")
        return day + timedelta(days=1) - timedelta(microseconds=1)
    raise NotFound("快照周期不存在", reason="snapshot_not_found", object="snapshot",
                   period=period)


def _book_at(c, moment: datetime, *, model: str | None = None) -> list[models.Quote]:
    """某一时刻的有效报价簿（每个 (node, access, model, unit) 取当时最高的版本）。"""
    clauses = ["state IN ('active', 'consumed', 'expired')", "created_at <= %s",
               "expires_at > %s"]
    params: list[Any] = [moment, moment]
    if model is not None:
        clauses.append("model = %s")
        params.append(model)
    where = " AND ".join(clauses)
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT DISTINCT ON (node_id, access, model, unit) {quotes.SELECT_COLUMNS}
                  FROM quotes WHERE {where}
                 ORDER BY node_id, access, model, unit, quote_version DESC""", params)
        return [models.Quote.from_row(row) for row in cur.fetchall()]


def build(c, *, period: str = facts.SNAPSHOT_PERIOD_LATEST, now: datetime | None = None,
          model: str | None = None) -> dict[str, Any]:
    """构造公开快照（只含输入 + ``quote_version``）。"""
    moment = now or clock.utcnow()
    at = _period_moment(period, moment)
    book = quotes.active_book(c, now=moment, model=model) if at is None \
        else _book_at(c, at, model=model)
    version = max((quote.quote_version for quote in book), default=0)
    return {
        "period": period,
        "generated_at": moment.isoformat(),
        "snapshot_ts": clock.truncate(at or moment).isoformat(),
        "quote_version": version,
        "quotes": [
            {"quote_id": quote.quote_id, "node_id": quote.node_id, "access": quote.access,
             "model": quote.model, "unit": quote.unit,
             "price_min": models.format_amount(quote.ask_price_minor, quote.unit),
             "price_max": (models.format_amount(quote.price_max_minor, quote.unit)
                           if quote.price_max_minor is not None else None),
             "quote_version": quote.quote_version,
             "expires_at": quote.expires_at.isoformat()}
            for quote in sorted(book, key=lambda item: (item.model, item.access, item.node_id))
        ],
        "summary": matching.book_summary(book),
    }


def version(c, *, now: datetime | None = None) -> int:
    """当前报价簿版本（快照 / 决策锚点共用）。"""
    return quotes.current_version(c)


__all__ = ["PERIOD_PATH_RE", "build", "version"]
