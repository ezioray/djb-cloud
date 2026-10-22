# SPDX-License-Identifier: Apache-2.0
"""只追加护栏（INV-08）与冲正唯一迁移（INV-07）。

验收来源：DEV-M06-T1 验收 2「非法 UPDATE / DELETE 被触发器拒绝（有测试）」。
"""
from __future__ import annotations

import uuid

import pytest

from ledgerkit import (
    session,
    assert_db_error,
    connect,
    line,
    new_hash,
    post_journal,
    run_ok,
    simple_lines,
)


# ─────────────────────────────────────────────────────── journal_entry
def test_journal_entry_rejects_delete(shared: str) -> None:
    ids = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute("DELETE FROM journal_entry WHERE journal_id = %s",
                                     (ids["journal_id"],)))


def test_journal_entry_rejects_business_column_update(shared: str) -> None:
    ids = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    # 除 status 外的列一律不许改（哪怕只是 ts / policy_version）
    assert_db_error(
        shared, "only status may change",
        lambda c: c.cursor().execute("UPDATE journal_entry SET policy_version = 'v9' WHERE journal_id = %s",
                                     (ids["journal_id"],)))
    assert_db_error(
        shared, "only status may change",
        lambda c: c.cursor().execute("UPDATE journal_entry SET event_seq = event_seq + 1 WHERE journal_id = %s",
                                     (ids["journal_id"],)))


def test_journal_entry_status_is_one_way(shared: str) -> None:
    """冲正是唯一合法迁移：posted → voided；反向与重复都不允许。"""
    ids = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))

    run_ok(shared, lambda c: c.cursor().execute(
        "UPDATE journal_entry SET status = 'voided' WHERE journal_id = %s", (ids["journal_id"],)))

    assert_db_error(
        shared, "only allows posted -> voided",
        lambda c: c.cursor().execute("UPDATE journal_entry SET status = 'posted' WHERE journal_id = %s",
                                     (ids["journal_id"],)))
    assert_db_error(
        shared, "only allows posted -> voided",
        lambda c: c.cursor().execute("UPDATE journal_entry SET status = 'voided' WHERE journal_id = %s",
                                     (ids["journal_id"],)))


# ─────────────────────────────────────────────────────── journal_line
def test_journal_line_rejects_update_and_delete(shared: str) -> None:
    ids = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute("UPDATE journal_line SET amount_minor = 1 WHERE journal_id = %s",
                                     (ids["journal_id"],)))
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute("DELETE FROM journal_line WHERE journal_id = %s",
                                     (ids["journal_id"],)))


# ─────────────────────────────────────────────────────── ledger_entry
def test_ledger_entry_rejects_update_and_delete(shared: str) -> None:
    ids = run_ok(shared, lambda c: post_journal(c, simple_lines(100)))
    entry_id = ids["entry_ids"][0]
    assert_db_error(
        shared, "only status may change",
        lambda c: c.cursor().execute("UPDATE ledger_entry SET amount_minor = 1 WHERE entry_id = %s",
                                     (entry_id,)))
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute("DELETE FROM ledger_entry WHERE entry_id = %s", (entry_id,)))
    # 账本级两态：posted → voided 允许（冲正流程），反向拒绝
    run_ok(shared, lambda c: c.cursor().execute(
        "UPDATE ledger_entry SET status = 'voided' WHERE entry_id = %s", (entry_id,)))
    assert_db_error(
        shared, "only allows posted -> voided",
        lambda c: c.cursor().execute("UPDATE ledger_entry SET status = 'posted' WHERE entry_id = %s",
                                     (entry_id,)))


# ─────────────────────────────────────────────────────── 派生余额
def test_account_balances_rejects_update_and_delete(shared: str) -> None:
    def _write(c):
        with c.cursor() as cur:
            cur.execute(
                "INSERT INTO account_balances (account_id, unit_type, sub_account, version, balance_minor) "
                "VALUES ('coa:2101', 'USD', 'AVAILABLE', 1, -100)")

    run_ok(shared, _write)
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute(
            "UPDATE account_balances SET balance_minor = 0 WHERE account_id = 'coa:2101'"))
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute("DELETE FROM account_balances WHERE account_id = 'coa:2101'"))


# ─────────────────────────────────────────────────────── 期间根
def test_merkle_commitments_rejects_update_and_delete(shared: str) -> None:
    def _write(c):
        with c.cursor() as cur:
            cur.execute(
                "INSERT INTO merkle_commitments (period, kind, root, entry_count) "
                "VALUES (%s, 'journal', %s, 3)", ("2026-10", "a" * 64))

    run_ok(shared, _write)
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute("UPDATE merkle_commitments SET entry_count = 4"))
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute("DELETE FROM merkle_commitments"))


# ─────────────────────────────────────────────────────── 本地事件投递
def _outbox_row(**over) -> dict:
    row = {
        "event_id": str(uuid.uuid4()),
        "type": "journal.posted",
        "aggregate_type": "journal_entry",
        "aggregate_id": str(uuid.uuid4()),
        "trace_id": f"trace-{uuid.uuid4().hex[:8]}",
        "idempotency_key": f"journal.posted:{uuid.uuid4().hex}",
        "payload": '{"journal_id": "j-1", "event_type": "E6", "amount_minor": 100, "ref_id": "r-1"}',
    }
    row.update(over)
    return row


def _insert_outbox(cur, **over) -> str:
    row = _outbox_row(**over)
    cur.execute(
        """INSERT INTO m06_outbox (event_id, type, producer, aggregate_type, aggregate_id, trace_id,
                                   idempotency_key, payload)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)""",
        (row["event_id"], row["type"], row.get("producer", "M06"), row["aggregate_type"],
         row["aggregate_id"], row["trace_id"], row["idempotency_key"], row["payload"]))
    return row["event_id"]


def test_outbox_allows_only_publish_bookkeeping(shared: str) -> None:
    event_id = run_ok(shared, lambda c: _insert_outbox(c.cursor()))

    # 投递完成标记：published_at NULL → NOT NULL 唯一合法变化
    run_ok(shared, lambda c: c.cursor().execute(
        "UPDATE m06_outbox SET published_at = now() WHERE event_id = %s", (event_id,)))
    assert_db_error(
        shared, "only published_at",
        lambda c: c.cursor().execute(
            "UPDATE m06_outbox SET published_at = now() WHERE event_id = %s", (event_id,)))
    assert_db_error(
        shared, "only published_at may change",
        lambda c: c.cursor().execute(
            "UPDATE m06_outbox SET payload = '{\"journal_id\": \"x\"}'::jsonb WHERE event_id = %s",
            (event_id,)))
    assert_db_error(
        shared, "append-only",
        lambda c: c.cursor().execute("DELETE FROM m06_outbox WHERE event_id = %s", (event_id,)))


@pytest.mark.parametrize("table", ["journal_entry", "journal_line", "ledger_entry", "account_balances",
                                   "merkle_commitments", "m06_outbox"])
def test_every_m06_table_has_write_guard_trigger(shared: str, table: str) -> None:
    """六张表都必须挂护栏：BEFORE UPDATE OR DELETE（行级）+ BEFORE TRUNCATE（语句级）。"""
    with session(shared) as c, c.cursor() as cur:
        cur.execute(
            """SELECT tgname, pg_get_triggerdef(t.oid)
                 FROM pg_trigger t
                 JOIN pg_class cl ON cl.oid = t.tgrelid
                 JOIN pg_namespace n ON n.oid = cl.relnamespace
                WHERE n.nspname = current_schema() AND cl.relname = %s AND NOT t.tgisinternal""",
            (table,))
        defs = {name: d for name, d in cur.fetchall()}
    assert defs, f"{table} 没有触发器"
    joined = " ".join(defs.values()).upper()
    assert "UPDATE" in joined and "DELETE" in joined, (table, defs)
    assert "TRUNCATE" in joined, (table, defs)


@pytest.mark.parametrize("table", ["journal_entry", "journal_line", "ledger_entry", "account_balances",
                                   "merkle_commitments", "m06_outbox"])
def test_truncate_is_rejected(shared: str, table: str) -> None:
    """TRUNCATE 绕过行级触发器，必须单独拦住 —— 否则一条语句就能清空账本。

    被外键引用的表（journal_entry / ledger_entry）会先被 PG 的 FK 规则拦下，同样是拒绝；
    其它表由 BEFORE TRUNCATE 触发器拦下。
    """
    err = assert_db_error(shared, "truncate",
                          lambda c: c.cursor().execute(f"TRUNCATE {table}"))
    msg = str(err).lower()
    assert "truncate not allowed" in msg or "foreign key constraint" in msg, msg


def test_truncate_cascade_from_journal_entry_is_rejected(shared: str) -> None:
    """TRUNCATE ... CASCADE 也不能顺带把凭证行带走。"""
    assert_db_error(shared, "truncate not allowed",
                    lambda c: c.cursor().execute("TRUNCATE journal_entry CASCADE"))
