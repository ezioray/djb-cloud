# SPDX-License-Identifier: AGPL-3.0-or-later
"""迁移 1301–1304：空库 / 幂等 / 回滚 / CLI 四跑 + 库层护栏（M14 §5 / §9）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import psycopg
import pytest

from admin_kit import (
    FIXED_NOW,
    M14_FUNCTIONS,
    M14_INDEXES,
    M14_TABLES,
    apply_m14_twice,
    apply_migrations,
    column_signature,
    constraint_signature,
    function_names,
    index_names,
    insert_audit,
    m14_migration_files,
    make_export,
    make_retention,
    outbox_rows,
    prerequisite_files,
    session,
    table_names,
    trigger_names,
)
from app.data_gov import events, ids, migrate, store


# ─────────────────────────────────────────────────────── 四跑：空库 / 幂等 / 回滚 / CLI
def test_empty_schema_applies_base_and_module(fresh: str) -> None:
    applied = apply_migrations(fresh)
    module_names = [path.name for path in m14_migration_files()]
    assert set(module_names) <= set(applied)
    # 数字序：1205 之后、1400 之前，13xx 段连续且顺序正确
    assert applied.index("1205_notification_preferences.sql") < applied.index(module_names[0])
    assert applied.index(module_names[-1]) < applied.index("1400_audit_log.sql")
    assert [name for name in applied if name in set(module_names)] == module_names
    tables = table_names(fresh)
    assert set(M14_TABLES) <= tables
    # 只加不改：前置模块的表仍在
    assert {"accounts", "usage_records", "notification_outbox", "audit_log"} <= tables


def test_module_migrations_are_idempotent(fresh: str) -> None:
    apply_migrations(fresh, prerequisite_files())
    apply_m14_twice(fresh)                                   # 1301–1304 连跑两遍
    apply_m14_twice(fresh)
    tables = table_names(fresh)
    assert set(M14_TABLES) <= tables
    with session(fresh) as connection, connection.cursor() as cur:
        cur.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n"
                    " ON n.oid = c.relnamespace WHERE n.nspname = %s"
                    " AND c.relname = ANY(%s)", (fresh, list(M14_TABLES)))
        assert cur.fetchone()[0] == len(M14_TABLES)
    assert set(M14_FUNCTIONS) <= function_names(fresh)
    repeated = [name for name in index_names(fresh) if name in M14_INDEXES]
    assert set(repeated) == set(M14_INDEXES)


def test_down_is_repeatable_and_leaves_base_untouched(fresh: str) -> None:
    apply_migrations(fresh)
    base_tables = table_names(fresh) - set(M14_TABLES)
    before_columns = column_signature(fresh, base_tables)
    before_constraints = constraint_signature(fresh, base_tables)

    for _ in range(2):
        with migrate.connect(fresh) as connection:
            assert migrate.down(connection) == [
                "1304_data_gov_outbox.sql", "1303_admin_saved_views.sql",
                "1302_retention_jobs.sql", "1301_data_export_requests.sql"]

    assert not (set(M14_TABLES) & table_names(fresh))
    assert not (set(M14_FUNCTIONS) & function_names(fresh))
    assert not {name for name in index_names(fresh) if name in M14_INDEXES}
    assert column_signature(fresh, base_tables) == before_columns
    assert constraint_signature(fresh, base_tables) == before_constraints

    with migrate.connect(fresh) as connection:               # 回滚后可再升级
        assert migrate.up(connection, with_base=False) == [
            "1301_data_export_requests.sql", "1302_retention_jobs.sql",
            "1303_admin_saved_views.sql", "1304_data_gov_outbox.sql"]
    assert set(M14_TABLES) <= table_names(fresh)


def test_migrate_cli_up_status_down(fresh: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert migrate.main(["--schema", fresh, "--up-only"]) == 0
    assert "applied 4 migrations" in capsys.readouterr().out
    assert migrate.main(["--schema", fresh, "--status"]) == 0
    out = capsys.readouterr().out
    assert "MISSING" not in out
    assert migrate.main(["--schema", fresh, "--down"]) == 0
    assert migrate.main(["--schema", fresh, "--status"]) == 0
    assert "MISSING" in capsys.readouterr().out


# ─────────────────────────────────────────────────────── 索引 / 触发器 / 函数
def test_required_indexes_triggers_functions(migrated: str) -> None:
    indexes = index_names(migrated)
    assert set(M14_INDEXES) <= indexes
    triggers = trigger_names(migrated)
    assert {
        "data_export_requests_guard", "data_export_requests_no_delete",
        "data_export_requests_no_truncate", "retention_jobs_guard",
        "retention_jobs_no_delete", "retention_jobs_no_truncate",
        "admin_saved_views_guard", "admin_saved_views_no_delete",
        "admin_saved_views_no_truncate", "data_gov_outbox_payload_guard",
        "data_gov_outbox_guard", "data_gov_outbox_no_delete",
        "data_gov_outbox_no_truncate",
    } <= triggers
    assert set(M14_FUNCTIONS) <= function_names(migrated)


# ─────────────────────────────────────────────────────── 导出表库层护栏（INV-04）
def test_export_state_machine_guard(conn: psycopg.Connection) -> None:
    row = make_export(conn, state="pending")
    export_id = str(row["export_id"])
    with conn.transaction():
        approved = store.update_export(conn, export_id, state="approved",
                                       approver="ops-approver", approved_at=FIXED_NOW)
    assert approved is not None and approved["state"] == "approved"
    with pytest.raises(psycopg.errors.CheckViolation):        # approved 不能直接 done
        with conn.transaction():
            store.update_export(conn, export_id, state="done", row_count=1,
                                finished_at=FIXED_NOW,
                                expires_at=FIXED_NOW + timedelta(days=7),
                                watermark="DJB-M14 TEST")
    with pytest.raises(psycopg.errors.CheckViolation):        # done 缺 watermark / expires_at
        with conn.transaction():
            store.update_export(conn, export_id, state="running", started_at=FIXED_NOW)
        with conn.transaction():
            store.update_export(conn, export_id, state="done", finished_at=FIXED_NOW)


def test_export_immutable_fields_and_no_delete(conn: psycopg.Connection) -> None:
    row = make_export(conn, state="pending")
    export_id = str(row["export_id"])
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("UPDATE data_export_requests SET requester = 'other'"
                         " WHERE export_id = %s::uuid", (export_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("DELETE FROM data_export_requests WHERE export_id = %s::uuid",
                         (export_id,))


def test_export_cancel_requires_trace(conn: psycopg.Connection) -> None:
    row = make_export(conn, state="pending")
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                "UPDATE data_export_requests SET state = 'failed',"
                " failure_reason = 'cancelled_by_requester', finished_at = now()"
                " WHERE export_id = %s::uuid", (str(row["export_id"]),))


def test_export_approver_cannot_be_requester(conn: psycopg.Connection) -> None:
    row = make_export(conn, state="pending", requester="same-person")
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            store.update_export(conn, str(row["export_id"]), state="approved",
                                approver="same-person", approved_at=FIXED_NOW)


# ─────────────────────────────────────────────────────── 保留任务库层护栏（INV-07）
def test_retention_object_cutoff_unique_for_real_execution(conn: psycopg.Connection) -> None:
    row = make_retention(conn, object_name="logs", policy_days=30)
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.transaction():
            store.insert_retention(
                conn, job_id=str(ids.uuid7()), job_no="RET-DUP-001", object_name="logs",
                policy_days=30, cutoff=row["cutoff"], dry_run=False,
                report_ref="report://retention/jobs/dup", requested_by="ops-admin",
                idempotency_key=None, sla_due_at=FIXED_NOW + timedelta(days=30),
                created_at=FIXED_NOW)
    # dry-run 不占名额
    store.insert_retention(
        conn, job_id=str(ids.uuid7()), job_no="RET-DRY-001", object_name="logs",
        policy_days=30, cutoff=row["cutoff"], dry_run=True,
        report_ref="report://retention/jobs/dry", requested_by="ops-admin",
        idempotency_key=None, sla_due_at=FIXED_NOW + timedelta(days=30),
        created_at=FIXED_NOW)


def test_retention_replay_requires_counter(conn: psycopg.Connection) -> None:
    row = make_retention(conn, state="failed")
    job_id = str(row["job_id"])
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            store.update_retention(conn, job_id, state="queued", failure_reason=None,
                                   started_at=None, finished_at=None)
    replayed = store.update_retention(
        conn, job_id, state="queued", failure_reason=None, started_at=None,
        finished_at=None, replay_count=1)
    assert replayed is not None and replayed["state"] == "queued"
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("DELETE FROM retention_jobs WHERE job_id = %s::uuid", (job_id,))


def test_retention_immutable_task_fields(conn: psycopg.Connection) -> None:
    row = make_retention(conn, object_name="backups", policy_days=35)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("UPDATE retention_jobs SET cutoff = now() WHERE job_id = %s::uuid",
                         (str(row["job_id"]),))


# ─────────────────────────────────────────────────────── 保存视图（1303）
def test_saved_views_soft_delete_only(conn: psycopg.Connection) -> None:
    view_id = str(ids.uuid7())
    store.insert_saved_view(conn, view_id=view_id, owner_id="ops-admin", domain="ledger",
                            name="大额分录", filters={"min_amount_minor": 100},
                            shared=True, created_at=FIXED_NOW)
    with conn.transaction():
        conn.execute("UPDATE admin_saved_views SET name = '大额分录（新）'"
                     " WHERE view_id = %s::uuid", (view_id,))
    with conn.transaction():
        deleted = store.soft_delete_saved_view(conn, view_id, "ops-admin")
    assert deleted is not None and deleted["state"] == "deleted"
    assert store.list_saved_views(conn, "ops-admin") == []
    with pytest.raises(psycopg.errors.CheckViolation):        # 软删除不可复活
        with conn.transaction():
            conn.execute("UPDATE admin_saved_views SET state = 'active'"
                         " WHERE view_id = %s::uuid", (view_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("DELETE FROM admin_saved_views WHERE view_id = %s::uuid",
                         (view_id,))


# ─────────────────────────────────────────────────────── outbox（1304 / 02-events）
def _envelope(**overrides):
    base = events.build_envelope(
        "data.export.completed",
        {"export_id": str(ids.uuid7()), "requester": "ops-admin", "rows": 3},
        aggregate_type="data_export_request", aggregate_id=str(ids.uuid7()),
        trace_id="trace-1", idempotency_key="data_export:test:completed",
        now=FIXED_NOW)
    base.update(overrides)
    return base


def test_outbox_payload_whitelist_and_immutability(conn: psycopg.Connection) -> None:
    envelope = _envelope()
    assert store.insert_outbox(conn, envelope) is not None
    assert store.insert_outbox(conn, envelope) is None          # event_id 幂等
    rows = outbox_rows(conn)
    assert len(rows) == 1 and rows[0]["state"] == "pending"

    bad_payload = dict(envelope, event_id=str(ids.uuid7()),
                       idempotency_key="data_export:test:other")
    bad_payload["payload"] = {"export_id": "x", "requester": "y", "rows": 1, "pii": "no"}
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            store.insert_outbox(conn, bad_payload)
    missing_key = dict(envelope, event_id=str(ids.uuid7()),
                       idempotency_key="data_export:test:missing")
    missing_key["payload"] = {"export_id": "x"}
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            store.insert_outbox(conn, missing_key)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("UPDATE data_gov_outbox SET payload = '{}'::jsonb"
                         " WHERE event_id = %s::uuid", (envelope["event_id"],))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with conn.transaction():
            conn.execute("DELETE FROM data_gov_outbox WHERE event_id = %s::uuid",
                         (envelope["event_id"],))


def test_outbox_publish_state_is_mutable(conn: psycopg.Connection) -> None:
    envelope = _envelope()
    store.insert_outbox(conn, envelope)
    events.mark_published(conn, envelope["event_id"], now=FIXED_NOW)
    row = store.get_outbox(conn, envelope["event_id"])
    assert row is not None and row["state"] == "published" and row["published_at"] is not None


def test_unregistered_event_type_rejected(conn: psycopg.Connection) -> None:
    envelope = _envelope(type="data.export.cancelled")
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            store.insert_outbox(conn, envelope)


# ─────────────────────────────────────────────────────── 审计链种子（只读面夹具自检）
def test_audit_seed_follows_chain_guards(conn: psycopg.Connection) -> None:
    first = insert_audit(conn, action="deploy.started", after={"window_start": "2026-10-24"})
    second = insert_audit(conn, action="deploy.completed", ts=FIXED_NOW + timedelta(minutes=5))
    assert second["seq"] == first["seq"] + 1
    assert second["prev_hash"] == first["hash"]
