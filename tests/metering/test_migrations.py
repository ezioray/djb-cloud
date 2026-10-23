# SPDX-License-Identifier: Apache-2.0
"""迁移三跑（空库 / 升级 / 回滚）+ 只追加护栏 / 约束（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.metering import migrate
from meterkit import (
    M05_MIGRATIONS,
    M05_TABLES,
    NOW,
    apply_migrations,
    column_names,
    connect,
    create_schema,
    drop_schema,
    fingerprint,
    function_names,
    index_names,
    m05_migration_files,
    migration_files,
    migration_number,
    prerequisite_files,
    run_migrations,
    table_names,
    trigger_names,
)

UPSTREAM_TABLES = ("nodes", "user_accounts", "receipts", "node_receipts", "accounts", "api_keys",
                   "ledger_entries", "tenant_quotas")


def _sqlstate(exc: psycopg.Error) -> str:
    return exc.sqlstate or ""


# ─────────────────────────────────────────────────────── 空库 / 升级 / 回滚 三跑
def test_empty_schema_applies_every_migration_in_numeric_order(schema: str):
    """空库：001–1008 按**数字序**一次跑通（M05 段落在 409 与 600 之间）。"""
    result = run_migrations(migration_files(), schema)
    assert result.returncode == 0, result.stderr
    numbers = [migration_number(path) for path in migration_files()]
    assert numbers == sorted(numbers)
    tables = table_names(schema)
    for table in M05_TABLES:
        assert table in tables, table
    m05_numbers = [number for number in numbers if 500 <= number <= 599]
    assert m05_numbers == [501, 502, 503, 504, 505]


def test_numeric_order_is_not_lexicographic():
    numeric = [path.name for path in migration_files()]
    lexicographic = [path.name for path in migration_files("lexicographic")]
    assert numeric != lexicographic
    assert numeric.index("100_identity_core.sql") < numeric.index("1000_config_items.sql")
    assert numeric.index("505_loss_pool_entries.sql") < numeric.index("600_ledger_journal.sql")


def test_upgrade_from_prerequisites_keeps_upstream_objects_untouched(schema: str):
    """升级：只加不改——5xx 前后上游对象结构指纹必须完全一致。"""
    apply_migrations(schema, prerequisite_files())
    before = fingerprint(schema, UPSTREAM_TABLES)
    apply_migrations(schema, m05_migration_files())
    after = fingerprint(schema, UPSTREAM_TABLES)
    assert before == after, "5xx 迁移改动了上游对象（违反只加不改）"
    for table in M05_TABLES:
        assert table in table_names(schema)


def test_rollback_drops_only_m05_objects(schema: str):
    """回滚：逆序删 5xx，可重复执行；上游对象一个不动。"""
    apply_migrations(schema, migration_files())
    upstream_before = fingerprint(schema, UPSTREAM_TABLES)
    with connect(schema, autocommit=False) as conn:
        results = migrate.down(conn)
        assert [item["rc"] for item in results] == [0] * len(results)
        assert [item["name"] for item in results] == list(reversed(M05_MIGRATIONS))
        again = migrate.down(conn)                        # 可重复执行
        assert [item["rc"] for item in again] == [0] * len(again)
    tables = table_names(schema)
    for table in M05_TABLES:
        assert table not in tables, table
    for table in UPSTREAM_TABLES:
        assert table in tables, table
    assert fingerprint(schema, UPSTREAM_TABLES) == upstream_before
    functions = function_names(schema)
    for name in ("m05_forbid_mutation", "m05_forbid_truncate", "m05_usage_state_guard"):
        assert name not in functions


def test_m05_migrations_are_repeatable(schema: str):
    """重复执行：再跑一遍 501–505 仍是 exit 0（IF NOT EXISTS / OR REPLACE）。"""
    apply_migrations(schema, migration_files())
    result = run_migrations(m05_migration_files(), schema)
    assert result.returncode == 0, result.stderr


def test_status_reports_applied_after_up_and_missing_after_down(schema: str):
    apply_migrations(schema, prerequisite_files())
    with connect(schema, autocommit=False) as conn:
        missing = migrate.status(conn)
        assert all(not item["applied"] for item in missing)
        migrate.up(conn, files=m05_migration_files())
        applied = migrate.status(conn)
        assert all(item["applied"] for item in applied)
        assert [item["name"] for item in applied] == list(M05_MIGRATIONS)


# ─────────────────────────────────────────────────────── 结构（索引 / 触发器 / 函数）
def test_required_indexes_exist(migrated: str):
    indexes = index_names(migrated)
    for name in ("usage_records_request_attempt_uq", "usage_records_receipt_uq",
                 "usage_records_account_time_idx", "metering_receipts_accepted_uq",
                 "metering_receipts_usage_uq", "usage_corrections_bill_uq",
                 "loss_pool_request_attempt_uq"):
        assert name in indexes, name


def test_required_triggers_and_functions_exist(migrated: str):
    triggers = trigger_names(migrated)
    for name in ("usage_records_state_guard", "usage_records_insert_guard",
                 "usage_records_no_truncate", "metering_receipts_no_mutation",
                 "metering_receipts_no_truncate", "usage_corrections_guard",
                 "usage_corrections_insert_guard", "upstream_bills_guard",
                 "upstream_bills_insert_guard", "loss_pool_no_mutation"):
        assert name in triggers, name
    functions = function_names(migrated)
    for name in ("m05_forbid_mutation", "m05_forbid_truncate", "m05_usage_state_guard",
                 "m05_usage_insert_guard", "m05_correction_guard", "m05_bill_guard"):
        assert name in functions, name


def test_columns_match_m05_contract(migrated: str):
    usage = column_names(migrated, "usage_records")
    assert {"usage_id", "request_id", "attempt_no", "account_id", "node_id", "model", "access",
            "tokens_in", "tokens_out", "usage_amount", "usage_unit", "amount_minor",
            "usage_source", "state", "receipt_id", "correction_id", "recorded_at",
            "settled_at", "corrected_at"} <= usage
    receipt = column_names(migrated, "metering_receipts")
    assert {"receipt_id", "usage_id", "node_id", "task_id", "access", "usage_amount",
            "usage_unit", "price_amount", "price_minor", "sig_provider", "sig_consumer",
            "state", "rejected_code", "received_at", "reported_at"} <= receipt


def test_no_cross_module_foreign_keys(migrated: str):
    """跨模块只软引用：M05 表上不得有指向上游基表的外键。"""
    with connect(migrated) as conn:
        rows = conn.execute(
            """SELECT c.relname, confrelid::regclass::text
                 FROM pg_constraint con
                 JOIN pg_class c ON c.oid = con.conrelid
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND con.contype = 'f'""", (migrated,)).fetchall()
    foreign = {(table, target) for table, target in rows if table in M05_TABLES}
    assert foreign == set(), foreign


# ─────────────────────────────────────────────────────── 只追加护栏
def test_receipts_table_is_append_only(migrated: str):
    receipt_id = f"rcpt_{uuid.uuid4().hex[:10]}"
    with connect(migrated) as conn:
        conn.execute(
            """INSERT INTO metering_receipts
                 (submission_id, receipt_id, usage_id, node_id, task_id, access, usage_amount,
                  usage_unit, price_amount, price_minor, sig_provider, sig_consumer, state,
                  rejected_code, reject_reason, reported_at, received_at)
               VALUES (%s,%s,NULL,'n1','t1','A1','1','token','0.01',1,%s,%s,'rejected',
                       40001,'x',%s,%s)""",
            (uuid.uuid4(), receipt_id, "hmac-sha256:" + "0" * 64,
             "hmac-sha256:" + "0" * 64, NOW, NOW))
        with pytest.raises(psycopg.Error) as update_exc:
            conn.execute("UPDATE metering_receipts SET state='accepted' WHERE receipt_id=%s",
                         (receipt_id,))
        assert _sqlstate(update_exc.value) == "42501"
        with pytest.raises(psycopg.Error) as delete_exc:
            conn.execute("DELETE FROM metering_receipts WHERE receipt_id=%s", (receipt_id,))
        assert _sqlstate(delete_exc.value) == "42501"
        with pytest.raises(psycopg.Error) as truncate_exc:
            conn.execute("TRUNCATE metering_receipts")
        assert _sqlstate(truncate_exc.value) == "42501"


def test_loss_pool_is_append_only_and_deduplicated(migrated: str):
    request_id = f"req_{uuid.uuid4().hex[:10]}"
    with connect(migrated) as conn:
        conn.execute(
            """INSERT INTO loss_pool_entries (entry_id, request_id, attempt_no, amount_minor,
                                              reason, evidence_ref, recorded_at)
               VALUES (%s,%s,1,800,'fallback_switch','bill:1',%s)""",
            (uuid.uuid4(), request_id, NOW))
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(
                """INSERT INTO loss_pool_entries (entry_id, request_id, attempt_no, amount_minor,
                                                  reason, recorded_at)
                   VALUES (%s,%s,1,800,'stream_interrupt',%s)""",
                (uuid.uuid4(), request_id, NOW))
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                """INSERT INTO loss_pool_entries (entry_id, request_id, attempt_no, amount_minor,
                                                  reason, recorded_at)
                   VALUES (%s,%s,2,0,'fallback_switch',%s)""",
                (uuid.uuid4(), request_id, NOW))
        with pytest.raises(psycopg.Error) as exc:
            conn.execute("UPDATE loss_pool_entries SET amount_minor=1 WHERE request_id=%s",
                         (request_id,))
        assert _sqlstate(exc.value) == "42501"


def test_usage_records_reject_delete_and_column_rewrite(migrated: str):
    usage_id = uuid.uuid4()
    with connect(migrated) as conn:
        conn.execute(
            """INSERT INTO usage_records (usage_id, request_id, attempt_no, account_id, node_id,
                   model, access, tokens_in, tokens_out, usage_amount, usage_unit, amount_minor,
                   usage_source, state, receipt_id, recorded_at)
               VALUES (%s,%s,1,%s,'n1','m1','A1',10,5,'15','token',125,'dual','recorded',
                       %s,%s)""",
            (usage_id, f"req_{uuid.uuid4().hex[:8]}", uuid.uuid4(),
             f"rcpt_{uuid.uuid4().hex[:8]}", NOW))
        with pytest.raises(psycopg.Error) as amount_exc:
            conn.execute("UPDATE usage_records SET amount_minor=999 WHERE usage_id=%s",
                         (usage_id,))
        assert _sqlstate(amount_exc.value) == "42501"
        with pytest.raises(psycopg.Error) as delete_exc:
            conn.execute("DELETE FROM usage_records WHERE usage_id=%s", (usage_id,))
        assert _sqlstate(delete_exc.value) == "42501"


def test_usage_records_state_machine(migrated: str):
    usage_id = uuid.uuid4()
    with connect(migrated) as conn:
        # 新行必须是 recorded
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                """INSERT INTO usage_records (usage_id, request_id, attempt_no, account_id,
                       node_id, model, access, usage_amount, usage_unit, amount_minor,
                       usage_source, state, receipt_id, recorded_at)
                   VALUES (%s,%s,1,%s,'n1','m1','A1','1','token',1,'dual','settled',%s,%s)""",
                (uuid.uuid4(), f"req_{uuid.uuid4().hex[:8]}", uuid.uuid4(),
                 f"rcpt_{uuid.uuid4().hex[:8]}", NOW))
        conn.execute(
            """INSERT INTO usage_records (usage_id, request_id, attempt_no, account_id, node_id,
                   model, access, usage_amount, usage_unit, amount_minor, usage_source, state,
                   receipt_id, recorded_at)
               VALUES (%s,%s,1,%s,'n1','m1','A1','1','token',1,'dual','recorded',%s,%s)""",
            (usage_id, f"req_{uuid.uuid4().hex[:8]}", uuid.uuid4(),
             f"rcpt_{uuid.uuid4().hex[:8]}", NOW))
        # recorded → settled 合法
        conn.execute("UPDATE usage_records SET state='settled', settled_at=%s WHERE usage_id=%s",
                     (NOW, usage_id))
        # settled → corrected 非法（M05 §3 只允许 recorded 出发）
        with pytest.raises(psycopg.Error) as exc:
            conn.execute("UPDATE usage_records SET state='corrected', corrected_at=%s, "
                         "correction_id='c1' WHERE usage_id=%s", (NOW, usage_id))
        assert _sqlstate(exc.value) == "42501"


def test_usage_records_unique_billing_keys(migrated: str):
    request_id = f"req_{uuid.uuid4().hex[:10]}"
    receipt_id = f"rcpt_{uuid.uuid4().hex[:10]}"
    base = """INSERT INTO usage_records (usage_id, request_id, attempt_no, account_id, node_id,
                  model, access, usage_amount, usage_unit, amount_minor, usage_source, state,
                  receipt_id, recorded_at)
              VALUES (%s,%s,%s,%s,'n1','m1','A1','1','token',1,'dual','recorded',%s,%s)"""
    with connect(migrated) as conn:
        account = uuid.uuid4()
        conn.execute(base, (uuid.uuid4(), request_id, 1, account, receipt_id, NOW))
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(base, (uuid.uuid4(), request_id, 1, account,
                                f"rcpt_{uuid.uuid4().hex[:8]}", NOW))
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(base, (uuid.uuid4(), f"req_{uuid.uuid4().hex[:8]}", 1, account,
                                receipt_id, NOW))
        # 同请求的另一个尝试可以计费（INV-04 以最终成功尝试为准）
        conn.execute(base, (uuid.uuid4(), request_id, 2, account,
                            f"rcpt_{uuid.uuid4().hex[:8]}", NOW))


def test_metering_receipts_state_constraints(migrated: str):
    columns = """INSERT INTO metering_receipts (submission_id, receipt_id, usage_id, node_id,
                     task_id, access, usage_amount, usage_unit, price_amount, price_minor,
                     sig_provider, sig_consumer, state, rejected_code, reject_reason,
                     reported_at, received_at)
                 VALUES (%s,%s,%s,'n1','t1','A1','1','token','0.01',1,%s,%s,%s,%s,%s,%s,%s)"""
    good_sig = "hmac-sha256:" + "a" * 64
    with connect(migrated) as conn:
        # accepted 必须有 usage_id
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(columns, (uuid.uuid4(), f"rcpt_{uuid.uuid4().hex[:8]}", None,
                                   good_sig, good_sig, "accepted", None, None, NOW, NOW))
        # accepted 的签名必须是 hmac-sha256:<64hex>
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(columns, (uuid.uuid4(), f"rcpt_{uuid.uuid4().hex[:8]}", uuid.uuid4(),
                                   "bad", good_sig, "accepted", None, None, NOW, NOW))
        # rejected 必须有拒绝码
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(columns, (uuid.uuid4(), f"rcpt_{uuid.uuid4().hex[:8]}", None,
                                   good_sig, good_sig, "rejected", None, None, NOW, NOW))
        # 未上报时间的未来值受 reported_at <= received_at 约束
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(columns, (uuid.uuid4(), f"rcpt_{uuid.uuid4().hex[:8]}", None,
                                   good_sig, good_sig, "rejected", 46001, "x",
                                   NOW + timedelta(hours=1), NOW))
        # 同一个 receipt_id 只能有一条 accepted（INV-03）
        receipt_id = f"rcpt_{uuid.uuid4().hex[:8]}"
        conn.execute(columns, (uuid.uuid4(), receipt_id, uuid.uuid4(), good_sig, good_sig,
                               "accepted", None, None, NOW, NOW))
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(columns, (uuid.uuid4(), receipt_id, uuid.uuid4(), good_sig, good_sig,
                                   "accepted", None, None, NOW, NOW))
        # 被拒的同一个 receipt_id 仍可重提（部分唯一索引）
        conn.execute(columns, (uuid.uuid4(), receipt_id, None, good_sig, good_sig,
                               "rejected", 46001, "sig", NOW, NOW))


def test_corrections_constraints_and_state_machine(migrated: str):
    insert = """INSERT INTO usage_corrections (correction_id, usage_id, delta_minor, original_minor,
                    reason_code, upstream_bill_id, state, requested_by, second_approver,
                    created_at) VALUES (%s,%s,%s,%s,%s,%s,'proposed',%s,%s,%s)"""
    usage_id = uuid.uuid4()
    with connect(migrated) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):        # delta 不能为 0
            conn.execute(insert, (uuid.uuid4(), usage_id, 0, 100, "overbill", None, "ops", None,
                                  NOW))
        with pytest.raises(psycopg.errors.CheckViolation):        # 负向校正需复核人
            conn.execute(insert, (uuid.uuid4(), usage_id, -10, 100, "underbill", None, "ops",
                                  None, NOW))
        with pytest.raises(psycopg.errors.CheckViolation):        # reason 白名单
            conn.execute(insert, (uuid.uuid4(), usage_id, 10, 100, "guess", None, "ops", None,
                                  NOW))
        correction_id = uuid.uuid4()
        conn.execute(insert, (correction_id, usage_id, -10, 100, "underbill", None, "ops",
                              "reviewer", NOW))
        # proposed → applied 合法
        conn.execute("UPDATE usage_corrections SET state='applied', applied_at=%s "
                     "WHERE correction_id=%s", (NOW, correction_id))
        # applied → rejected 非法；业务列不可改
        with pytest.raises(psycopg.Error) as exc:
            conn.execute("UPDATE usage_corrections SET state='rejected', rejected_at=%s "
                         "WHERE correction_id=%s", (NOW, correction_id))
        assert _sqlstate(exc.value) == "42501"
        with pytest.raises(psycopg.Error) as amount_exc:
            conn.execute("UPDATE usage_corrections SET delta_minor=99 WHERE correction_id=%s",
                         (correction_id,))
        assert _sqlstate(amount_exc.value) == "42501"
        # 一次写入终态（applied）被插入护栏拦下
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                """INSERT INTO usage_corrections (correction_id, usage_id, delta_minor,
                       original_minor, reason_code, state, requested_by, created_at, applied_at)
                   VALUES (%s,%s,5,100,'overbill','applied','ops',%s,%s)""",
                (uuid.uuid4(), uuid.uuid4(), NOW, NOW))
        # 幂等键 (usage_id, upstream_bill_id) 唯一
        conn.execute(insert, (uuid.uuid4(), usage_id, 5, 100, "overbill", "bill-1", "ops", None,
                              NOW))
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(insert, (uuid.uuid4(), usage_id, 6, 100, "overbill", "bill-1", "ops",
                                  None, NOW))


def test_upstream_bills_constraints_and_state_machine(migrated: str):
    insert = """INSERT INTO upstream_bills (bill_id, provider, period, amount_minor, access, state,
                    imported_at, reconciled_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"""
    with connect(migrated) as conn:
        conn.execute(insert, ("bill-1", "openai", "2026-10", 800, "A1", "imported", NOW, None))
        conn.execute("UPDATE upstream_bills SET state='reconciled', reconciled_at=%s "
                     "WHERE bill_id='bill-1'", (NOW,))
        with pytest.raises(psycopg.Error) as exc:
            conn.execute("UPDATE upstream_bills SET amount_minor=1 WHERE bill_id='bill-1'")
        assert _sqlstate(exc.value) == "42501"
        with pytest.raises(psycopg.errors.CheckViolation):        # 周期形状
            conn.execute(insert, ("bill-2", "openai", "2026-13", 1, "A1", "imported", NOW, None))
        with pytest.raises(psycopg.errors.CheckViolation):        # 金额非负
            conn.execute(insert, ("bill-3", "openai", "2026-10", -1, "A1", "imported", NOW, None))
        with pytest.raises(psycopg.errors.CheckViolation):        # 直接写入 reconciled
            conn.execute(insert, ("bill-4", "openai", "2026-10", 1, "A1", "reconciled", NOW, NOW))
        with pytest.raises(psycopg.Error) as delete_exc:
            conn.execute("DELETE FROM upstream_bills WHERE bill_id='bill-1'")
        assert _sqlstate(delete_exc.value) == "42501"


# ─────────────────────────────────────────────────────── CLI（证据里三跑用的就是它）
def test_migrate_cli_up_status_down(schema: str, capsys):
    from meterkit import dsn

    assert migrate.main(["--schema", schema, "--dsn", dsn(), "--up"]) == 0
    out = capsys.readouterr().out
    for name in M05_MIGRATIONS:
        assert name in out
    assert migrate.main(["--schema", schema, "--dsn", dsn(), "--status"]) == 0
    status_out = capsys.readouterr().out
    assert status_out.count("APPLIED") == len(M05_MIGRATIONS)
    assert migrate.main(["--schema", schema, "--dsn", dsn(), "--down"]) == 0
    down_out = capsys.readouterr().out
    assert "down 501_usage_records.sql" in down_out


def test_migrate_cli_requires_dsn(monkeypatch, capsys):
    monkeypatch.delenv("DJB_DSN", raising=False)
    assert migrate.main(["--schema", "m05_noop", "--status"]) == 2
    assert "DJB_DSN" in capsys.readouterr().err
