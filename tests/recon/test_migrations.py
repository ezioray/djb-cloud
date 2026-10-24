# SPDX-License-Identifier: AGPL-3.0-or-later
"""迁移 901–905：空库 / 幂等 / 回滚三跑 + 库层护栏（不需要真提交的用例走事务回滚）。"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.recon import migrate
from reconkit import (
    BASE_TABLES,
    GUARD_DENIED,
    M09_TABLES,
    M09_VIEWS,
    apply_migrations,
    apply_m09_twice,
    column_signature,
    constraint_signature,
    index_names,
    m09_migration_files,
    prerequisite_files,
    session,
    table_names,
    trigger_names,
    view_names,
)

FIXED = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────── 三跑：空库 / 幂等 / 回滚
def test_empty_schema_applies_001_to_905(fresh: str) -> None:
    apply_migrations(fresh)                                  # 全部迁移，数字序
    tables = table_names(fresh)
    views = view_names(fresh)
    assert set(M09_TABLES) <= tables
    assert set(M09_VIEWS) <= views
    # 只加不改：存量表仍在
    assert set(BASE_TABLES) <= tables


def test_m09_migrations_are_idempotent(fresh: str) -> None:
    apply_migrations(fresh, prerequisite_files())
    apply_m09_twice(fresh)                                   # 9xx 连跑两遍
    with session(fresh) as connection:
        with connection.cursor() as cur:
            cur.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n"
                        " ON n.oid = c.relnamespace WHERE n.nspname = %s"
                        " AND c.relname = ANY(%s)", (fresh, list(M09_TABLES)))
            assert cur.fetchone()[0] == len(M09_TABLES)
    # 索引没有翻倍
    indexes = index_names(fresh)
    assert len([name for name in indexes if name.startswith("reconciliation_")]) == \
        len({name for name in indexes if name.startswith("reconciliation_")})


def test_down_is_repeatable_and_leaves_base_untouched(fresh: str) -> None:
    apply_migrations(fresh)
    base_before = column_signature(fresh, BASE_TABLES)
    constraints_before = constraint_signature(fresh, BASE_TABLES)

    for _ in range(2):                                       # 回滚两遍
        with migrate.connect(fresh) as connection:
            assert migrate.down(connection) == [
                "905_report_renders.sql", "904_por_snapshots.sql", "903_recon_attestations.sql",
                "902_recon_exceptions.sql", "901_recon_runs.sql"]

    tables = table_names(fresh)
    views = view_names(fresh)
    assert not (set(M09_TABLES) & tables)
    assert not (set(M09_VIEWS) & views)
    assert not {name for name in index_names(fresh) if name.startswith("reconciliation_")}
    assert not {name for name in trigger_names(fresh) if name.startswith("m09_") or
                name.startswith("reconciliation_") or name.startswith("por_") or
                name.startswith("report_renders")}
    # 存量表结构一格没动
    assert column_signature(fresh, BASE_TABLES) == base_before
    assert constraint_signature(fresh, BASE_TABLES) == constraints_before


def test_m09_does_not_touch_m05_m06_structure(fresh: str) -> None:
    apply_migrations(fresh, prerequisite_files())
    before = column_signature(fresh, BASE_TABLES)
    before_constraints = constraint_signature(fresh, BASE_TABLES)
    apply_migrations(fresh, m09_migration_files())
    assert column_signature(fresh, BASE_TABLES) == before
    assert constraint_signature(fresh, BASE_TABLES) == before_constraints


# ─────────────────────────────────────────────────────── 索引 / 视图（§5）
def test_required_indexes_exist(migrated: str) -> None:
    indexes = index_names(migrated)
    assert {
        "reconciliation_runs_unique",                     # INV-04
        "reconciliation_runs_trigger_uq",
        "reconciliation_runs_signoff_idem_uq",
        "reconciliation_exceptions_run_status_due_idx",   # §5 (run_id, status, sla_due)
        "reconciliation_attestations_valid_uq",           # INV-05 部分唯一
        "por_snapshots_granularity_cutoff_uq",
        "report_renders_version_uq",                      # INV-07
    } <= indexes


def test_views_are_queryable(migrated: str) -> None:
    with session(migrated) as connection:
        with connection.cursor() as cur:
            for view in M09_VIEWS:
                cur.execute(f"SELECT count(*) FROM {view}")
                cur.fetchone()


# ─────────────────────────────────────────────────────── 库层护栏（run / exception）
def _new_run(connection: psycopg.Connection, *, status: str = "running",
             scope: str = "receipt") -> str:
    run_id = str(uuid.uuid4())
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO reconciliation_runs
                 (run_id, scope, subject_ref, period_start, period_end, cutoff_at, status,
                  rule_version, book_minor, external_minor)
               VALUES (%s,%s,'m05',%s,%s,%s,%s,'m09-test',100,97)""",
            (run_id, scope, FIXED - timedelta(days=1), FIXED, FIXED, status))
    return run_id


def _new_exception(connection: psycopg.Connection, run_id: str, *, severity: str = "P2",
                   kind: str = "amount_mismatch", diff_minor: int = 3) -> str:
    exception_id = str(uuid.uuid4())
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO reconciliation_exceptions
                 (exception_id, run_id, scope, kind, severity, ref_type, ref_id, diff_minor,
                  sla_due, status)
               VALUES (%s,%s,'receipt',%s,%s,'task','t-1',%s,%s,'open')""",
            (exception_id, run_id, kind, severity, diff_minor, FIXED + timedelta(minutes=15)))
    return exception_id


def test_run_delete_and_illegal_transition_are_rejected(conn: psycopg.Connection) -> None:
    run_id = _new_run(conn)
    with pytest.raises(GUARD_DENIED):
        with conn.transaction():
            conn.execute("DELETE FROM reconciliation_runs WHERE run_id = %s", (run_id,))
    with pytest.raises(psycopg.errors.CheckViolation):       # 非法迁移（running -> signed_off）
        with conn.transaction():
            conn.execute(
                "UPDATE reconciliation_runs SET status='signed_off',"
                " signed_off_by='r', signed_off_at=now() WHERE run_id = %s", (run_id,))


def test_run_is_readonly_after_sign_off(conn: psycopg.Connection) -> None:
    run_id = _new_run(conn)
    with conn.transaction():
        conn.execute(
            "UPDATE reconciliation_runs SET status='matched' WHERE run_id = %s", (run_id,))
        conn.execute(
            "UPDATE reconciliation_runs SET status='signed_off', signed_off_by='reviewer',"
            " signed_off_at=%s WHERE run_id = %s", (FIXED, run_id))
    with pytest.raises(GUARD_DENIED):
        with conn.transaction():
            conn.execute("UPDATE reconciliation_runs SET diff_minor = 999 WHERE run_id = %s",
                         (run_id,))
    with pytest.raises(GUARD_DENIED):                        # 已签核不得回退状态
        with conn.transaction():
            conn.execute("UPDATE reconciliation_runs SET status='matched' WHERE run_id = %s",
                         (run_id,))
    with conn.transaction():                                 # signed_off -> closed 放行
        conn.execute("UPDATE reconciliation_runs SET status='closed' WHERE run_id = %s",
                     (run_id,))


def test_inv01_diff_is_maintained_by_trigger(conn: psycopg.Connection) -> None:
    run_id = _new_run(conn)
    exception_id = _new_exception(conn, run_id, diff_minor=3)
    with conn.cursor() as cur:
        cur.execute("SELECT diff_minor FROM reconciliation_runs WHERE run_id = %s", (run_id,))
        assert cur.fetchone()[0] == 3                        # 触发器同步
    with conn.transaction():
        conn.execute("UPDATE reconciliation_exceptions SET status='closed',"
                     " resolution_code='external_fix', closed_at=now(),"
                     " root_cause='ok' WHERE exception_id = %s", (exception_id,))
        with conn.cursor() as cur:
            cur.execute("SELECT diff_minor FROM reconciliation_runs WHERE run_id = %s", (run_id,))
            assert cur.fetchone()[0] == 0                    # 关完即归零（INV-01）


def test_exception_guards(conn: psycopg.Connection) -> None:
    run_id = _new_run(conn)
    exception_id = _new_exception(conn, run_id)

    with pytest.raises(GUARD_DENIED):                        # 差异不删
        with conn.transaction():
            conn.execute("DELETE FROM reconciliation_exceptions WHERE exception_id = %s",
                         (exception_id,))
    with pytest.raises(GUARD_DENIED):                        # kind 不可变（护栏先于 CHECK）
        with conn.transaction():
            conn.execute("UPDATE reconciliation_exceptions SET kind='signature_bad'"
                         " WHERE exception_id = %s", (exception_id,))
    with pytest.raises(psycopg.errors.CheckViolation):       # INV-02：结构性 kind 必须 P0
        with conn.transaction():
            _new_exception(conn, run_id, kind="signature_bad", severity="P2")
    with pytest.raises(psycopg.errors.CheckViolation):       # 关闭必须有处置码 + 时间
        with conn.transaction():
            conn.execute("UPDATE reconciliation_exceptions SET status='closed'"
                         " WHERE exception_id = %s", (exception_id,))
    with conn.transaction():                                 # 正常关闭
        conn.execute("UPDATE reconciliation_exceptions SET status='closed',"
                     " resolution_code='false_positive', root_cause='dup', closed_at=now()"
                     " WHERE exception_id = %s", (exception_id,))
    with pytest.raises(psycopg.errors.CheckViolation):       # closed 不可重开
        with conn.transaction():
            conn.execute("UPDATE reconciliation_exceptions SET status='open'"
                         " WHERE exception_id = %s", (exception_id,))


def test_exception_cannot_be_added_to_signed_off_run(conn: psycopg.Connection) -> None:
    run_id = _new_run(conn)
    with conn.transaction():
        conn.execute("UPDATE reconciliation_runs SET status='matched' WHERE run_id = %s",
                     (run_id,))
        conn.execute("UPDATE reconciliation_runs SET status='signed_off', signed_off_by='r',"
                     " signed_off_at=%s WHERE run_id = %s", (FIXED, run_id))
    with pytest.raises(GUARD_DENIED):
        with conn.transaction():
            _new_exception(conn, run_id)


def test_exception_scope_must_match_run(conn: psycopg.Connection) -> None:
    run_id = _new_run(conn, scope="daily_close")
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            _new_exception(conn, run_id)                     # 插入时 scope=receipt != run


# ─────────────────────────────────────────────────────── 库层护栏（attestation / por / render）
def _new_attestation(connection: psycopg.Connection, *, batch_hash: str = "b" * 32,
                     status: str = "valid") -> str:
    attestation_id = str(uuid.uuid4())
    with connection.cursor() as cur:
        cur.execute(
            """INSERT INTO reconciliation_attestations
                 (attestation_id, period_start, period_end, ledger_root, payable_total_minor,
                  batch_hash, signature_ref, status, reviewer_id, maker_id)
               VALUES (%s,%s,%s,%s,1000,%s,'hsm:k:1',%s,'reviewer-1','maker-1')""",
            (attestation_id, FIXED - timedelta(days=30), FIXED, "a" * 64, batch_hash, status))
    return attestation_id


def test_attestation_inv05_unique_valid_and_transitions(conn: psycopg.Connection) -> None:
    first = _new_attestation(conn)
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.transaction():
            _new_attestation(conn)                           # 同期间 + batch_hash 第二条 valid
    with conn.transaction():                                 # valid -> revoked
        conn.execute("UPDATE reconciliation_attestations SET status='revoked'"
                     " WHERE attestation_id = %s", (first,))
    with pytest.raises(GUARD_DENIED):                        # 凭证正文不可改
        with conn.transaction():
            conn.execute("UPDATE reconciliation_attestations SET payable_total_minor=1"
                         " WHERE attestation_id = %s", (first,))
    with pytest.raises(GUARD_DENIED):                        # 凭证不删
        with conn.transaction():
            conn.execute("DELETE FROM reconciliation_attestations WHERE attestation_id = %s",
                         (first,))
    _new_attestation(conn)                                   # revoke 后可提交新件


def test_dual_control_constraint_rejects_same_person(conn: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO reconciliation_attestations
                     (attestation_id, period_start, period_end, ledger_root,
                      payable_total_minor, batch_hash, signature_ref, reviewer_id, maker_id)
                   VALUES (%s,%s,%s,%s,1,%s,'sig','same','same')""",
                (str(uuid.uuid4()), FIXED - timedelta(days=1), FIXED, "a" * 64, "c" * 32))


def test_por_requires_full_coverage_to_publish(conn: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO por_snapshots
                     (snapshot_id, granularity, cutoff_at, coverage_bps, status, published_at)
                   VALUES (%s,'daily',%s,9900,'published',now())""",
                (str(uuid.uuid4()), FIXED))
    with conn.transaction():
        conn.execute(
            """INSERT INTO por_snapshots (snapshot_id, granularity, cutoff_at, coverage_bps)
               VALUES (%s,'daily',%s,10000)""", (str(uuid.uuid4()), FIXED))


def test_migrate_cli_status_and_usage(fresh: str) -> None:
    """CLI 的 ``--status`` 与「无参数打印帮助」两条分支（迁移三跑的脚本入口）。"""
    apply_migrations(fresh)
    with migrate.connect(fresh) as connection:
        state = migrate.status(connection)
    assert state["tables_missing"] == []
    assert state["views_missing"] == []
    assert state["runs"] == 0
    assert state["module_migrations"] == [
        "901_recon_runs.sql", "902_recon_exceptions.sql", "903_recon_attestations.sql",
        "904_por_snapshots.sql", "905_report_renders.sql"]
    with migrate.connect(fresh) as connection:
        assert migrate.up(connection, with_base=False) == list(migrate.MODULE_MIGRATIONS)
    assert migrate.main([]) == 2


def test_report_render_version_is_immutable(conn: psycopg.Connection) -> None:
    render_id = str(uuid.uuid4())
    with conn.transaction():
        conn.execute(
            """INSERT INTO report_renders
                 (render_id, report_id, period, cutoff_at, data_hash, report_version,
                  renderer_version, svg_object_key, status)
               VALUES (%s,'REP-01','2026-10',%s,%s,%s,'svg-v1','s3://x.svg','rendered')""",
            (render_id, FIXED, "d" * 64, "e" * 64))
    with pytest.raises(psycopg.errors.UniqueViolation):       # INV-07 同版本不可覆盖
        with conn.transaction():
            conn.execute(
                """INSERT INTO report_renders
                     (render_id, report_id, period, cutoff_at, data_hash, report_version,
                      renderer_version, svg_object_key, status)
                   VALUES (%s,'REP-01','2026-10',%s,%s,%s,'svg-v1','s3://y.svg','rendered')""",
                (str(uuid.uuid4()), FIXED, "d" * 64, "e" * 64))
    with pytest.raises(psycopg.errors.CheckViolation):       # 无对象 key 不得进 rendered
        with conn.transaction():
            conn.execute(
                """INSERT INTO report_renders
                     (render_id, report_id, period, cutoff_at, data_hash, report_version,
                      renderer_version, status)
                   VALUES (%s,'REP-02','2026-10',%s,%s,%s,'svg-v1','rendered')""",
                (str(uuid.uuid4()), FIXED, "f" * 64, "0" * 64))
