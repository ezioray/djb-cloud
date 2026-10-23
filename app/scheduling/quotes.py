# SPDX-License-Identifier: Apache-2.0
"""报价簿（M04 §3 Quote / §6 流程 1 前半 / §5 quotes）。

三条规则：

1. **只追加 + 版本化**：``quote_version`` 是**报价簿**的单调版本号（不是单节点版本）。
   同 ``(node_id, access, model, unit)`` 内容完全相同的重复报价**不升版本**、不写新行，
   直接复用当前 active 版本；内容变了才 ``max(quote_version)+1`` 追加一行。
2. **状态机**：``active → consumed``（成交）/ ``active → expired``（TTL）；禁止回退，
   只能新建（库层 ``m04_quotes_guard`` 兜底）。
3. **不 join 他人基表**：``node_id`` 的存在性只经 M02 的只读视图
   ``v_supply_node_snapshot`` 校验（01-ownership §2），DDL 层不建跨模块外键。

并发：报价写入用**事务级 advisory lock** 串行化「取版本号 + 追加」这一步，
避免两个并发报价拿到同一个 ``quote_version``（版本号是业务语义，不是自增序列）。
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from . import clock, facts, models
from .errors import InvalidArgument, NotFound, StateConflict

log = logging.getLogger("djb.scheduling.quotes")

#: SELECT 列顺序（与 :meth:`models.Quote.from_row` 严格一致）
COLUMNS = ("id", "node_id", "access", "model", "unit", "ask_price_minor", "price_max_minor",
           "currency", "ttl_s", "state", "quote_version", "created_at", "expires_at",
           "consumed_at")
SELECT_COLUMNS = ", ".join(COLUMNS)
RETURNING_COLUMNS = SELECT_COLUMNS

#: advisory lock 命名空间（M04 = 4001；键 1 = 报价簿版本分配）
LOCK_NAMESPACE = 4001
LOCK_QUOTE_BOOK = 1


@dataclass(frozen=True)
class QuoteResult:
    """写入结果：``created=False`` 表示内容未变、复用了既有版本（未升版本）。"""

    quote: models.Quote
    created: bool


def _lock_book(c) -> None:
    with c.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s, %s)", (LOCK_NAMESPACE, LOCK_QUOTE_BOOK))


def current_version(c) -> int:
    """报价簿当前版本（``max(quote_version)``；空簿 = 0）。"""
    with c.cursor() as cur:
        cur.execute("SELECT COALESCE(max(quote_version), 0) FROM quotes")
        row = cur.fetchone()
    return int(row[0]) if row else 0


def get(c, quote_id: str | uuid.UUID) -> models.Quote:
    with c.cursor() as cur:
        cur.execute(f"SELECT {SELECT_COLUMNS} FROM quotes WHERE id = %s", (_as_uuid(quote_id),))
        row = cur.fetchone()
    if row is None:
        raise NotFound("报价不存在", reason="quote_not_found", object="quote")
    return models.Quote.from_row(row)


def _as_uuid(value: str | uuid.UUID) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError) as exc:
        raise NotFound("报价 ID 形态非法", reason="quote_not_found", object="quote") from exc


def assert_node_exists(c, node_id: str) -> None:
    """节点存在性只经 M02 只读视图校验（不 join ``nodes`` 基表）。"""
    with c.cursor() as cur:
        cur.execute(f"SELECT 1 FROM {facts.NODE_SNAPSHOT_VIEW} WHERE node_id = %s", (node_id,))
        if cur.fetchone() is None:
            raise NotFound("节点不存在或不在只读快照里", reason="node_not_found", object="node")


def latest_active(c, *, node_id: str, access: str, model: str, unit: str,
                  now: datetime | None = None) -> models.Quote | None:
    """同一 (node, access, model, unit) 的最新 active 且未过期版本。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {SELECT_COLUMNS} FROM quotes
                 WHERE node_id = %s AND access = %s AND model = %s AND unit = %s
                   AND state = 'active' AND expires_at > %s
                 ORDER BY quote_version DESC LIMIT 1""",
            (node_id, access, model, unit, moment))
        row = cur.fetchone()
    return models.Quote.from_row(row) if row else None


def register(c, *, node_id: str, access: str, model: str, unit: str,
             ask_price_minor: int, price_max_minor: int | None, ttl_s: int,
             now: datetime | None = None, trace_id: str = "",
             check_node: bool = True) -> QuoteResult:
    """写入一条报价（内容不变不升版本）。

    ``ask_price_minor`` 是区间下界 a_lo，``price_max_minor`` 是上界 a_hi（None = +∞）。
    """
    moment = now or clock.utcnow()
    if access not in facts.ACCESS_TYPES:
        raise InvalidArgument(f"access 必须是 {facts.ACCESS_TYPES} 之一", field="access")
    if not isinstance(ttl_s, int) or isinstance(ttl_s, bool) or not 1 <= ttl_s <= 86_400:
        raise InvalidArgument("ttl_s 必须是 1–86400 的整数", field="ttl_s")
    if ask_price_minor < 0 or ask_price_minor > facts.MAX_PRICE_MINOR:
        raise InvalidArgument("报价超出允许范围", field="ask_price_minor")
    if price_max_minor is not None and price_max_minor < ask_price_minor:
        raise InvalidArgument("price_max 必须 ≥ price_min（INV-01）", field="price_max")

    if check_node:
        assert_node_exists(c, node_id)

    expires_at = moment + timedelta(seconds=ttl_s)
    _lock_book(c)
    existing = latest_active(c, node_id=node_id, access=access, model=model, unit=unit,
                             now=moment)
    if existing is not None and existing.signature() == (node_id, access, model, unit,
                                                         ask_price_minor, price_max_minor,
                                                         facts.CURRENCY, ttl_s):
        log.info("scheduling.quote.reused", extra={"event": "quote.reused",
                                                  "quote_id": existing.quote_id})
        return QuoteResult(quote=existing, created=False)

    version = current_version(c) + 1
    identifier = models.uuid7(int(moment.timestamp() * 1_000_000))
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO quotes (id, node_id, access, model, unit, ask_price_minor,
                                    price_max_minor, currency, ttl_s, state, quote_version,
                                    created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s, %s, %s)
                RETURNING {RETURNING_COLUMNS}""",
            (identifier, node_id, access, model, unit, ask_price_minor, price_max_minor,
             facts.CURRENCY, ttl_s, version, moment, expires_at))
        quote = models.Quote.from_row(cur.fetchone())
    log.info("scheduling.quote.created", extra={"event": "quote.created",
                                                "quote_id": quote.quote_id,
                                                "quote_version": version})
    from . import events                                    # 延迟导入：events 依赖 models

    events.quote_created(c, quote, trace_id=trace_id or identifier.hex, occurred_at=moment)
    return QuoteResult(quote=quote, created=True)


def active_book(c, *, now: datetime | None = None, model: str | None = None,
                access: str | None = None, unit: str | None = None,
                node_ids: Iterable[str] | None = None) -> list[models.Quote]:
    """有效报价簿：每个 (node, access, model, unit) 取版本最高的 active 未过期行。"""
    moment = now or clock.utcnow()
    clauses = ["state = 'active'", "expires_at > %s"]
    params: list[Any] = [moment]
    if model is not None:
        clauses.append("model = %s")
        params.append(model)
    if access is not None:
        clauses.append("access = %s")
        params.append(access)
    if unit is not None:
        clauses.append("unit = %s")
        params.append(unit)
    node_list = list(node_ids) if node_ids is not None else None
    if node_list is not None:
        if not node_list:
            return []
        clauses.append("node_id = ANY(%s)")
        params.append(node_list)
    where = " AND ".join(clauses)
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT DISTINCT ON (node_id, access, model, unit) {SELECT_COLUMNS}
                  FROM quotes WHERE {where}
                 ORDER BY node_id, access, model, unit, quote_version DESC""", params)
        return [models.Quote.from_row(row) for row in cur.fetchall()]


def consume(c, quote: models.Quote, *, now: datetime | None = None) -> models.Quote:
    """``active → consumed``（撮合成交，同事务）。已终结的报价拒绝（40902，禁止回退）。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE quotes SET state = 'consumed', consumed_at = %s
                 WHERE id = %s AND state = 'active' AND expires_at > %s
                 RETURNING {RETURNING_COLUMNS}""",
            (moment, quote.id, moment))
        row = cur.fetchone()
    if row is None:
        raise StateConflict("报价已成交或已过期，不能重复消费（只能新建报价）",
                            reason="quote_not_consumable", quote_id=quote.quote_id)
    return models.Quote.from_row(row)


def expire_due(c, *, now: datetime | None = None, trace_id: str = "") -> list[models.Quote]:
    """过期清理（M04 §4.1 定时作业 1 min）：``active → expired`` 并发 ``quote.expired``。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE quotes SET state = 'expired'
                 WHERE state = 'active' AND expires_at <= %s
                 RETURNING {RETURNING_COLUMNS}""", (moment,))
        expired = [models.Quote.from_row(row) for row in cur.fetchall()]
    if expired:
        from . import events

        for quote in expired:
            events.quote_expired(c, quote, trace_id=trace_id or quote.quote_id,
                                 occurred_at=moment)
    return expired


def mark_consumed_by_booking(c, quote_id: uuid.UUID, *, now: datetime | None = None) -> None:
    """撮合事务内的报价消费（幂等：已 consumed 视为成功，用于重放同一 booking）。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            "UPDATE quotes SET state = 'consumed', consumed_at = %s "
            "WHERE id = %s AND state = 'active'", (moment, quote_id))


def content_digest(quotes: Iterable[models.Quote]) -> str:
    """报价簿内容摘要（公开快照 / 排障用；**不含**任何凭据）。"""
    digest = hashlib.sha256()
    for quote in sorted(quotes, key=lambda item: (item.node_id, item.access, item.model,
                                                  item.unit, item.quote_version)):
        digest.update(f"{quote.quote_id}|{quote.node_id}|{quote.access}|{quote.model}|"
                      f"{quote.unit}|{quote.ask_price_minor}|{quote.price_max_minor}|"
                      f"{quote.quote_version};".encode("utf-8"))
    return digest.hexdigest()


__all__ = ["COLUMNS", "SELECT_COLUMNS", "QuoteResult", "current_version", "get",
           "assert_node_exists", "latest_active", "register", "active_book", "consume",
           "expire_due", "mark_consumed_by_booking", "content_digest", "LOCK_NAMESPACE"]
