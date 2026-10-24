# SPDX-License-Identifier: AGPL-3.0-or-later
"""仓储层测试：当前态 upsert、指标事件分页与时间过滤、后台评分分页、迁移 CLI。

这些用例覆盖「读路径」与「运维入口」（``python -m app.reputation.migrate``），
与 ``test_migrations.py``（DB 三跑 / 护栏）互补。
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.reputation import clock, migrate as m07_migrate, score, store
from repukit import NOW, connect, create_schema, drop_schema, scalar, seed_account_on


def test_get_score_returns_none_for_new_account(conn):
    account = seed_account_on(conn)
    assert store.get_score(conn, account) is None


def test_upsert_score_is_idempotent_and_updates(conn):
    account = seed_account_on(conn)
    first = store.upsert_score(
        conn, account, score=800, tier="L1", quality_coef="1.1", stability_coef="1.0",
        window_days=30, policy_version="rep-v1", computed_at=NOW, tier_since=NOW,
        prev_tier=None, manual_tier=False, reasons=("initial_assessment",))
    assert first.score == 800 and first.tier == "L1"
    second = store.upsert_score(
        conn, account, score=900, tier="L2", quality_coef="1.2", stability_coef="1.1",
        window_days=30, policy_version="rep-v1", computed_at=NOW, tier_since=NOW,
        prev_tier="L1", manual_tier=False, reasons=("tier_promoted",))
    assert (second.score, second.tier, second.prev_tier) == (900, "L2", "L1")
    assert second.reasons == ("tier_promoted",)
    assert int(scalar(conn, "SELECT count(*) FROM reputation_scores WHERE account_id = %s",
                      (account,))) == 1


def test_upsert_rejects_invalid_tier(conn):
    account = seed_account_on(conn)
    import psycopg

    with pytest.raises(psycopg.errors.CheckViolation):
        store.upsert_score(conn, account, score=10, tier="L9", quality_coef="1.0",
                           stability_coef="1.0", window_days=30, policy_version="rep-v1",
                           computed_at=NOW, tier_since=NOW, prev_tier=None,
                           manual_tier=False)
    conn.rollback()


def test_events_page_filters_by_time_and_paginates(conn):
    account = seed_account_on(conn)
    for index in range(5):
        store.insert_event(conn, account, metric="online_rate", value=900 - index, weight=2000,
                           delta=0, ref_id=f"evt-{index}", occurred_at=NOW + timedelta(hours=index))
    first, cursor = store.events_page(conn, account, limit=2)
    assert len(first) == 2 and cursor
    second, cursor2 = store.events_page(conn, account, limit=2, cursor=cursor)
    assert len(second) == 2 and cursor2
    ids = {item.id for item in first + second}
    assert len(ids) == 4

    # 时间窗过滤（含端点）
    filtered, _ = store.events_page(conn, account, occurred_from=NOW + timedelta(hours=4),
                                    occurred_to=NOW + timedelta(hours=4))
    assert len(filtered) == 1
    assert filtered[0].ref_id == "evt-4"

    with pytest.raises(Exception):
        store.events_page(conn, account, limit=0)


def test_insert_event_is_idempotent_per_fact(conn):
    account = seed_account_on(conn)
    assert store.insert_event(conn, account, metric="penalty", value=1, weight=0, delta=-200,
                              ref_id="case-1", occurred_at=NOW) is True
    assert store.insert_event(conn, account, metric="penalty", value=1, weight=0, delta=-200,
                              ref_id="case-1", occurred_at=NOW) is False
    assert int(scalar(conn, "SELECT count(*) FROM reputation_events WHERE account_id = %s",
                      (account,))) == 1


def test_score_page_filters_and_paginates(conn):
    with conn.cursor() as cur:                        # 本模块 schema 内只留本用例的三行
        cur.execute("DELETE FROM reputation_scores")
    for index in range(3):
        account = seed_account_on(conn)
        store.upsert_score(conn, account, score=900 - index * 100, tier="L2",
                           quality_coef="1.0", stability_coef="1.0", window_days=30,
                           policy_version="rep-v1", computed_at=NOW, tier_since=NOW,
                           prev_tier=None, manual_tier=False)
    page, cursor = store.score_page(conn, limit=2)
    assert len(page) == 2 and cursor
    rest, cursor2 = store.score_page(conn, limit=2, cursor=cursor)
    assert len(rest) == 1 and cursor2 is None
    assert {item.score for item in page + rest} == {900, 800, 700}

    filtered, _ = store.score_page(conn, tier="L2")
    assert len(filtered) == 3
    assert store.score_page(conn, tier="L4")[0] == []
    assert len(store.score_page(conn, min_score=850)[0]) == 1
    with pytest.raises(Exception):
        store.score_page(conn, tier="L9")
    with pytest.raises(Exception):
        store.score_page(conn, min_score=2000)


def test_latest_events_returns_recent_first(conn):
    account = seed_account_on(conn)
    for index in range(3):
        store.insert_event(conn, account, metric="success_rate", value=index, weight=0,
                           delta=0, ref_id=f"m-{index}", occurred_at=NOW + timedelta(minutes=index))
    rows = store.latest_events(conn, account, limit=2)
    assert [row.ref_id for row in rows] == ["m-2", "m-1"]


# --------------------------------------------------------------------------- 迁移 CLI
def test_migration_cli_up_status_fingerprint_down(schema):
    assert m07_migrate.main(["--schema", schema, "--status"]) == 0
    assert m07_migrate.main(["--schema", schema, "--up"]) == 0
    assert m07_migrate.main(["--schema", schema, "--status"]) == 0
    assert m07_migrate.main(["--schema", schema, "--fingerprint"]) == 0
    assert m07_migrate.main(["--schema", schema, "--down"]) == 0
    assert m07_migrate.main(["--schema", schema, "--down"]) == 0      # 可重复回滚
    conn = connect(schema)
    try:
        assert int(scalar(conn, """SELECT count(*) FROM information_schema.tables
                                    WHERE table_schema = current_schema()
                                      AND table_name = 'reputation_scores'""")) == 0
    finally:
        conn.close()


def test_migration_cli_requires_dsn(monkeypatch):
    monkeypatch.delenv("DJB_DSN", raising=False)
    assert m07_migrate.main(["--schema", "whatever", "--status"]) == 2


def test_clock_helpers():
    moment = clock.now()
    assert clock.as_utc(None) is not None
    assert clock.isoformat(None) is None
    assert clock.isoformat(moment).endswith("Z")
    assert clock.business_day(moment) >= moment.date().isoformat()   # UTC+4 不早于 UTC 日
    assert clock.parse_datetime(None) is None
    assert clock.parse_datetime("not-a-date") is None
    assert clock.parse_datetime("2026-10-23T04:00:00Z") == NOW
    # unaware 时间按 UTC 处理
    assert clock.as_utc(moment.replace(tzinfo=None)).tzinfo is not None


def test_score_constants_are_documented():
    """§8.2 常量集中在一处（模块内不散落数字）。"""
    from app.reputation import facts

    assert facts.DEFAULT_CONFIG.validated() is not None
    assert facts.ReputationConfig().validated().weights == dict(facts.WEIGHTS_BPS)
    assert facts.COEFFICIENT_BANDS[0][0] == 900
    assert score.coefficient_tenths(facts.SCORE_MAX) == facts.COEFF_MAX_TENTHS
