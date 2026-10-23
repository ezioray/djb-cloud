# SPDX-License-Identifier: Apache-2.0
"""报价簿 / 出价簿 / 成交锁（M04 §3 状态机 / §5 表 / §6 流程 1）。

守的是四件事：**只追加 + 版本化**、**内容不变不升版本**、**状态机只能前进**、
**库层触发器兜底**（应用层写错了也改不动历史）。
"""
from __future__ import annotations

import uuid

import pytest

from app.scheduling import bids, matching, quotes
from app.scheduling.errors import NotFound, StateConflict


# --------------------------------------------------------------------------- 报价：版本化
def test_quote_version_increments_only_when_content_changes(factory, conn, now):
    first = factory.quote("n_001", low=800, high=1_000)
    assert first.created is True and first.quote.quote_version == 1

    again = factory.quote("n_001", low=800, high=1_000)
    assert again.created is False                       # 内容不变 → 复用
    assert again.quote.id == first.quote.id
    assert quotes.current_version(conn) == 1

    changed = factory.quote("n_001", low=820, high=1_000)
    assert changed.created is True
    assert changed.quote.quote_version == 2             # 内容变了 → 新版本
    assert quotes.current_version(conn) == 2


def test_new_version_shadows_old_one_in_the_book(factory, conn, now):
    factory.quote("n_001", low=800, high=1_000)
    factory.quote("n_001", low=700, high=900)
    book = quotes.active_book(conn, now=now)
    assert len(book) == 1
    assert book[0].ask_price_minor == 700
    assert book[0].quote_version == 2


def test_different_keys_get_independent_versions(factory, conn, now):
    factory.quote("n_001", low=800, high=1_000)
    factory.quote("n_002", low=810, high=1_000)
    factory.quote("n_001", access="B", low=820, high=1_000)
    assert quotes.current_version(conn) == 3
    book = quotes.active_book(conn, now=now)
    assert {(item.node_id, item.access) for item in book} == {("n_001", "A1"), ("n_002", "A1"),
                                                             ("n_001", "B")}


def test_register_rejects_invalid_arguments(factory, conn, now):
    with pytest.raises(Exception):
        quotes.register(conn, node_id="n_001", access="A9", model="m1", unit="token",
                        ask_price_minor=800, price_max_minor=None, ttl_s=60, now=now)
    with pytest.raises(Exception):
        quotes.register(conn, node_id="n_001", access="A1", model="m1", unit="token",
                        ask_price_minor=800, price_max_minor=700, ttl_s=60, now=now)
    with pytest.raises(Exception):
        quotes.register(conn, node_id="n_001", access="A1", model="m1", unit="token",
                        ask_price_minor=800, price_max_minor=None, ttl_s=0, now=now)


def test_register_checks_node_through_the_read_only_view(factory, conn, now):
    """节点必须存在于 M02 只读视图里（M04 不 join nodes 基表）。"""
    with pytest.raises(NotFound) as excinfo:
        quotes.register(conn, node_id="n_missing", access="A1", model="m1", unit="token",
                        ask_price_minor=800, price_max_minor=None, ttl_s=60, now=now)
    assert excinfo.value.reason == "node_not_found"

    node = factory.node("n_001")
    assert quotes.register(conn, node_id=node, access="A1", model="m1", unit="token",
                           ask_price_minor=800, price_max_minor=None, ttl_s=60,
                           now=now).created is True


# --------------------------------------------------------------------------- 报价：状态机
def test_quote_consume_is_one_way(factory, conn, now):
    result = factory.quote("n_001")
    consumed = quotes.consume(conn, result.quote, now=now)
    assert consumed.state == "consumed" and consumed.consumed_at == now
    with pytest.raises(StateConflict):
        quotes.consume(conn, consumed, now=now)


def test_consumed_quote_leaves_the_book_but_can_be_replaced(factory, conn, now):
    first = factory.quote("n_001", low=800, high=1_000)
    quotes.consume(conn, first.quote, now=now)
    assert quotes.active_book(conn, now=now) == []
    # 消费后同内容再报 → 因为 active 行已不在，必须新建版本（不能复活旧行）
    again = factory.quote("n_001", low=800, high=1_000)
    assert again.created is True
    assert again.quote.id != first.quote.id


def test_expire_due_flips_only_expired_active_quotes(factory, conn, now):
    from datetime import timedelta

    short = factory.quote("n_001", ttl_s=10)
    long = factory.quote("n_002", ttl_s=3_600)
    expired = quotes.expire_due(conn, now=now + timedelta(seconds=30))
    assert [item.id for item in expired] == [short.quote.id]
    assert quotes.get(conn, short.quote.id).state == "expired"
    assert quotes.get(conn, long.quote.id).state == "active"


def test_expired_quote_is_not_reusable_or_consumable(factory, conn, now):
    from datetime import timedelta

    result = factory.quote("n_001", ttl_s=10)
    later = now + timedelta(seconds=30)
    with pytest.raises(StateConflict):
        quotes.consume(conn, result.quote, now=later)
    assert quotes.latest_active(conn, node_id="n_001", access="A1", model="m1", unit="token",
                                now=later) is None


# --------------------------------------------------------------------------- 报价：库层兜底
def test_quotes_table_rejects_delete_and_immutable_updates(factory, conn, now):
    quote = factory.quote("n_001").quote
    with pytest.raises(Exception):
        conn.execute("DELETE FROM quotes WHERE id = %s", (quote.id,))
    with pytest.raises(Exception):
        conn.execute("UPDATE quotes SET ask_price_minor = 1 WHERE id = %s", (quote.id,))
    with pytest.raises(Exception):
        conn.execute("UPDATE quotes SET quote_version = 99 WHERE id = %s", (quote.id,))


def test_quotes_table_rejects_state_rollback(factory, conn, now):
    quote = factory.quote("n_001").quote
    quotes.consume(conn, quote, now=now)
    with pytest.raises(Exception):
        conn.execute("UPDATE quotes SET state = 'active', consumed_at = NULL WHERE id = %s",
                     (quote.id,))


def test_get_unknown_quote_is_404(factory, conn):
    with pytest.raises(NotFound):
        quotes.get(conn, str(uuid.uuid4()))
    with pytest.raises(NotFound):
        quotes.get(conn, "not-a-uuid")


def test_content_digest_is_stable_and_order_independent(factory, conn, now):
    factory.quote("n_001")
    factory.quote("n_002")
    book = quotes.active_book(conn, now=now)
    assert quotes.content_digest(book) == quotes.content_digest(list(reversed(book)))
    assert len(quotes.content_digest(book)) == 64


# --------------------------------------------------------------------------- 出价
def test_bid_version_is_per_tenant_and_model(factory, conn, now, tenant, other_tenant):
    first = factory.bid(tenant, low=600, high=950)
    assert first.created is True and first.bid.bid_version == 1

    same = factory.bid(tenant, low=600, high=950)
    assert same.created is False and same.bid.id == first.bid.id

    changed = factory.bid(tenant, low=650, high=950)
    assert changed.bid.bid_version == 2

    other = factory.bid(other_tenant, low=600, high=950)
    assert other.bid.bid_version == 1                  # 别的租户从 1 开始


def test_bid_validates_interval_and_strategy(factory, conn, now, tenant):
    with pytest.raises(Exception):
        factory.bid(tenant, low=950, high=600)
    with pytest.raises(Exception):
        factory.bid(tenant, low=0, high=1, strategy="auction")
    with pytest.raises(Exception):
        factory.bid(tenant, low=-1, high=None)


def test_bid_expiry_and_book(factory, conn, now, tenant):
    from datetime import timedelta

    result = factory.bid(tenant, window_s=10)
    assert bids.active_book(conn, now=now, model="m1")[0].id == result.bid.id
    expired = bids.expire_due(conn, now=now + timedelta(seconds=30))
    assert [item.id for item in expired] == [result.bid.id]
    assert bids.active_book(conn, now=now + timedelta(seconds=30)) == []


def test_bid_unknown_lookup_is_404(factory, conn):
    with pytest.raises(NotFound):
        bids.get(conn, str(uuid.uuid4()))
    with pytest.raises(NotFound):
        bids.get(conn, "bad-id")


def test_bids_table_rejects_delete(factory, conn, tenant):
    bid = factory.bid(tenant).bid
    with pytest.raises(Exception):
        conn.execute("DELETE FROM bids WHERE id = %s", (bid.id,))


# --------------------------------------------------------------------------- 成交锁
def test_match_creates_held_booking_and_consumes_the_quote(factory, conn, now, tenant):
    quote = factory.quote("n_001", low=800, high=1_000).quote
    bid = factory.bid(tenant, low=600, high=950).bid
    plan = matching.plan(bid, [quote])
    assert isinstance(plan, matching.MatchPlan)

    booking = matching.create_booking(conn, plan, tenant_id=tenant, request_id="req-1",
                                      now=now, trace_id="trace-1")
    assert booking.state == "held"
    assert booking.price_minor == 875                   # mid(800, 950)（验收 ①）
    assert booking.consumed_at is None
    assert quotes.get(conn, quote.id).state == "consumed"
    assert matching.get(conn, booking.id).id == booking.id


def test_booking_lifecycle_is_forward_only(factory, conn, now, tenant):
    quote = factory.quote("n_001").quote
    bid = factory.bid(tenant).bid
    booking = matching.create_booking(conn, matching.plan(bid, [quote]), tenant_id=tenant,
                                      request_id="req-1", now=now)
    consumed = matching.consume(conn, booking.id, now=now)
    assert consumed.state == "consumed" and consumed.consumed_at == now
    with pytest.raises(StateConflict):
        matching.consume(conn, booking.id, now=now)


def test_booking_expiry(factory, conn, now, tenant):
    from datetime import timedelta

    quote = factory.quote("n_001").quote
    bid = factory.bid(tenant).bid
    booking = matching.create_booking(conn, matching.plan(bid, [quote]), tenant_id=tenant,
                                      request_id="req-1", now=now, ttl_s=30)
    expired = matching.expire_due(conn, now=now + timedelta(seconds=60))
    assert [item.id for item in expired] == [booking.id]
    with pytest.raises(StateConflict):
        matching.consume(conn, booking.id, now=now + timedelta(seconds=60))


def test_bookings_table_rejects_price_mutation(factory, conn, now, tenant):
    quote = factory.quote("n_001").quote
    bid = factory.bid(tenant).bid
    booking = matching.create_booking(conn, matching.plan(bid, [quote]), tenant_id=tenant,
                                      request_id="req-1", now=now)
    with pytest.raises(Exception):
        conn.execute("UPDATE bookings SET price_minor = 1 WHERE id = %s", (booking.id,))
    with pytest.raises(Exception):
        conn.execute("DELETE FROM bookings WHERE id = %s", (booking.id,))


def test_no_intersection_creates_no_booking(factory, conn, now, tenant):
    """验收 ③：无交集 → 只有诊断，不落成交锁。"""
    quote = factory.quote("n_001", low=800, high=1_000).quote
    bid = factory.bid(tenant, low=600, high=700).bid
    result = matching.plan(bid, [quote])
    assert isinstance(result, matching.NoMatch)
    count = conn.execute("SELECT count(*) FROM bookings").fetchone()[0]
    assert count == 0
    assert result.gap_minor == 100
