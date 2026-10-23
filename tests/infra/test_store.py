# SPDX-License-Identifier: Apache-2.0
"""追加/查询/锚点（需要 DJB_DSN）：幂等、串行化 seq、同事务 outbox、密钥 fail-closed。"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.audit import clock, errors, facts, merkle, models, store
from infrakit import (HASH_PATTERN, OTHER_KEY, TEST_KEY, apply_migrations, connect,
                      new_idempotency_key)

NOW = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)


def draft(**overrides):
    body = {"actor": "infra-seat", "actor_type": "agent", "role": "INFRA",
            "action": "read.report", "target": "nas/guard"}
    body.update(overrides)
    return models.draft_from_request(body, now=NOW)


def append(connection, key_provider, *, now=NOW, idempotency_key=None, **overrides):
    return store.append(connection, draft(**overrides), key_provider=key_provider, now=now,
                        trace_id="test-trace", idempotency_key=idempotency_key)


# --------------------------------------------------------------------------- 基本追加
def test_append_writes_entry_and_outbox(conn, key_provider):
    result = append(conn, key_provider)
    entry = result["entry"]
    assert result["duplicate"] is False
    assert entry["seq"] == 1
    assert entry["prev_hash"] == facts.GENESIS
    assert entry["alg"] == facts.ALG
    assert HASH_PATTERN.match(entry["hash"])
    assert entry["status"] == "recorded"
    assert entry["ts"] == NOW

    with conn.cursor() as cur:
        row = cur.execute(
            """SELECT seq, entry_id, ts, actor, action, alg, prev_hash, hash, idempotency_key
                 FROM audit_log WHERE seq = 1""").fetchone()
    assert row[0] == 1 and str(row[1]) == entry["entry_id"]
    assert row[6] == facts.GENESIS and row[7] == entry["hash"]

    with conn.cursor() as cur:
        event = cur.execute(
            """SELECT type, version, producer, aggregate_type, aggregate_id, idempotency_key,
                      payload
                 FROM m16_outbox WHERE aggregate_id = %s""", (entry["entry_id"],)).fetchone()
    assert event[0] == "audit.appended"
    assert event[1] == facts.EVENT_VERSION
    assert event[2] == "M16"
    assert event[3] == "audit_entry"
    assert event[5] == f"audit.appended:{entry['entry_id']}"
    assert set(event[6]) == set(facts.EVENT_PAYLOAD_KEYS)
    assert event[6]["audit_id"] == entry["entry_id"]
    assert event[6]["hash"] == entry["hash"]
    assert event[6]["seq"] == 1


def test_second_append_chains_prev_hash(conn, key_provider):
    first = append(conn, key_provider)["entry"]
    second = append(conn, key_provider, target="nas/guard-2")["entry"]
    assert second["seq"] == 2
    assert second["prev_hash"] == first["hash"]
    assert second["hash"] != first["hash"]


def test_entry_id_is_uuid7_like(conn, key_provider):
    entry = append(conn, key_provider)["entry"]
    assert len(entry["entry_id"]) == 36
    assert entry["entry_id"][14] == "7"              # 版本位 = 7


def test_high_risk_entry_round_trip(conn, key_provider):
    result = append(
        conn, key_provider, action="authorize.window", target="REL-0001",
        reason_code="R-OK", ticket="REL-0001", before={"window": "closed"},
        after={"window": "open"}, status="approved",
        approval_chain=[{"actor": "lead", "decision": "propose"},
                        {"actor": "release-manager", "decision": "approve"}],
        evidence="ops/audit/reports/REL-0001.txt")
    entry = result["entry"]
    fetched = store.fetch_all(conn)
    assert fetched[0]["before"] == {"window": "closed"}
    assert fetched[0]["after"] == {"window": "open"}
    assert fetched[0]["approval_chain"][0]["actor"] == "lead"
    assert fetched[0]["hash"] == entry["hash"]


# --------------------------------------------------------------------------- 幂等
def test_idempotency_key_returns_the_first_result(conn, key_provider):
    key = new_idempotency_key()
    first = append(conn, key_provider, idempotency_key=key)
    second = append(conn, key_provider, idempotency_key=key)
    assert first["duplicate"] is False and second["duplicate"] is True
    assert second["entry"]["seq"] == first["entry"]["seq"]
    assert second["entry"]["hash"] == first["entry"]["hash"]
    with conn.cursor() as cur:
        count = cur.execute("SELECT count(*) FROM audit_log").fetchone()[0]
    assert count == 1


def test_idempotency_key_reuse_with_different_content_is_conflict(conn, key_provider):
    key = new_idempotency_key()
    append(conn, key_provider, idempotency_key=key)
    with pytest.raises(errors.Conflict) as excinfo:
        append(conn, key_provider, idempotency_key=key, target="another/target")
    assert excinfo.value.code == "40901"
    assert excinfo.value.reason == "idempotency_key_reused"


# --------------------------------------------------------------------------- 密钥 fail-closed
def test_missing_key_refuses_to_write(conn, key_provider):
    from app.audit import StaticKeyProvider

    with pytest.raises(errors.ChainLocked) as excinfo:
        append(conn, StaticKeyProvider(None))
    assert excinfo.value.status_code == 423
    assert excinfo.value.code == "42301"
    with conn.cursor() as cur:
        assert cur.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0


def test_chain_only_verifies_with_the_key_that_signed_it(conn, key_provider):
    """链与密钥绑定：换成别的密钥复算必然不匹配（这也是"密钥泄露=可重算"的护栏）。"""
    from app.audit import chain

    append(conn, key_provider)
    entries = store.fetch_all(conn)
    assert chain.verify_entries(entries, key=TEST_KEY, now=NOW).ok
    rotated = chain.verify_entries(entries, key=OTHER_KEY, now=NOW)
    assert not rotated.ok and rotated.broken_seq == 1


# --------------------------------------------------------------------------- 查询与分页
def test_list_page_filters_and_cursor(conn, key_provider):
    append(conn, key_provider, target="a")
    append(conn, key_provider, target="b", action="write.report")
    append(conn, key_provider, target="a")

    page = store.list_page(conn)
    assert [item["seq"] for item in page["data"]] == [1, 2, 3]
    assert page["page"]["has_more"] is False
    assert page["page"]["next_cursor"] is None

    filtered = store.list_page(conn, action="write.report")
    assert [item["seq"] for item in filtered["data"]] == [2]

    by_target = store.list_page(conn, target="a")
    assert [item["seq"] for item in by_target["data"]] == [1, 3]

    first_page = store.list_page(conn, limit=2)
    assert [item["seq"] for item in first_page["data"]] == [1, 2]
    assert first_page["page"]["has_more"] is True
    assert first_page["page"]["next_cursor"] == "3"

    second_page = store.list_page(conn, from_seq=3, limit=2)
    assert [item["seq"] for item in second_page["data"]] == [3]
    assert second_page["page"]["has_more"] is False


@pytest.mark.parametrize("limit", [0, -1, facts.MAX_PAGE_SIZE + 1])
def test_list_page_rejects_bad_limit(conn, limit):
    with pytest.raises(errors.InvalidArgument):
        store.list_page(conn, limit=limit)


# --------------------------------------------------------------------------- 锚点
def test_insert_anchor_is_idempotent(conn):
    first, created = store.insert_anchor(conn, period="2026-10-23", merkle_root="a" * 64,
                                         sealed_at=NOW, entry_count=2, first_seq=1, last_seq=2)
    assert created is True
    assert first["merkle_root"] == "a" * 64
    assert first["entry_count"] == 2

    second, created_again = store.insert_anchor(
        conn, period="2026-10-23", merkle_root="b" * 64, sealed_at=NOW, entry_count=9)
    assert created_again is False
    assert second["merkle_root"] == "a" * 64           # 首次根为准，不被覆盖
    assert second["entry_count"] == 2
    assert store.get_anchor(conn, "2026-10-23")["merkle_root"] == "a" * 64
    assert store.get_anchor(conn, "2026-10-24") is None


def test_append_refuses_autocommit_connection(migrated, key_provider):
    """autocommit 连接会让 advisory xact lock 立刻失效 → 必须在入口拒绝。"""
    connection = connect(migrated, autocommit=True)
    try:
        with pytest.raises(errors.ServiceUnavailable) as excinfo:
            store.append(connection, draft(), key_provider=key_provider)
        assert excinfo.value.reason == "autocommit_not_allowed"
        assert connection.execute("SELECT count(*) FROM audit_log").fetchone()[0] == 0
    finally:
        connection.close()


# --------------------------------------------------------------------------- 并发
def test_concurrent_appends_are_serialized(schema, key_provider):
    """两个连接并发 append：seq 必须连续无洞，整链可验（证明 advisory lock 生效）。"""
    apply_migrations(schema)                          # 该用例要真提交，用自己的 schema
    failures: list[BaseException] = []

    def worker(tag: str) -> None:
        connection = connect(schema, autocommit=False)
        try:
            for index in range(5):
                store.append(connection, draft(target=f"{tag}-{index}"),
                             key_provider=key_provider, now=NOW,
                             trace_id=f"t-{tag}")
            connection.commit()
        except BaseException as exc:              # noqa: BLE001 - 线程里必须带回异常
            failures.append(exc)
            connection.rollback()
        finally:
            connection.close()

    threads = [threading.Thread(target=worker, args=(f"w{index}",), daemon=True)
               for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
        assert not thread.is_alive(), "并发 append 超时（锁没有释放？）"
    assert not failures, f"并发 append 失败：{failures!r}"

    with connect(schema, autocommit=True) as connection:
        entries = store.fetch_all(connection)
        assert [entry["seq"] for entry in entries] == list(range(1, 11))
        from app.audit import chain

        report = chain.verify_entries(entries, key=TEST_KEY, now=clock.utcnow())
        assert report.ok, report.all_problems()
        assert merkle.merkle_root([entry["hash"] for entry in entries])


def test_fetch_by_idempotency_returns_the_stored_entry(conn, key_provider):
    key = new_idempotency_key()
    first = append(conn, key_provider, idempotency_key=key)["entry"]
    with conn.cursor() as cur:
        stored = store.fetch_by_idempotency(cur, key)
        assert stored["hash"] == first["hash"]
        assert store.fetch_by_idempotency(cur, "idem-not-used-000000") is None
