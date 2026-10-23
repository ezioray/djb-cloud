# SPDX-License-Identifier: Apache-2.0
"""迁移 1100–1104：空库 / 幂等 / 回滚三跑 + 索引视图 + 库层护栏。"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.risk import migrate
from riskkit import (
    FIXED_NOW,
    FORBIDDEN_KEY_RE,
    M11_TABLES,
    M11_VIEWS,
    apply_migrations,
    apply_m11_twice,
    column_signature,
    constraint_signature,
    index_names,
    m11_migration_files,
    prerequisite_files,
    session,
    table_columns,
    table_names,
    trigger_names,
    view_names,
)

FIXED = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────── 三跑：空库 / 幂等 / 回滚
def test_empty_schema_applies_001_to_1104(fresh: str) -> None:
    applied = apply_migrations(fresh)
    m11_names = [path.name for path in m11_migration_files()]
    assert set(m11_names) <= set(applied)
    # 数字序：1100 在 1008 之后、1201 之前（11xx 段连续且顺序正确）
    assert applied.index("1008_outbox_backoff.sql") < applied.index(m11_names[0])
    assert applied.index(m11_names[-1]) < applied.index("1201_notifications.sql")
    assert [name for name in applied if name in set(m11_names)] == m11_names
    tables = table_names(fresh)
    views = view_names(fresh)
    assert set(M11_TABLES) <= tables
    assert set(M11_VIEWS) <= views
    # 只加不改：前置模块的表仍在
    assert {"accounts", "usage_records", "notification_outbox"} <= tables


def test_m11_migrations_are_idempotent(fresh: str) -> None:
    apply_migrations(fresh, prerequisite_files())
    before = column_signature(fresh, M11_TABLES) if set(M11_TABLES) <= table_names(fresh) else {}
    apply_m11_twice(fresh)                                   # 11xx 连跑两遍
    after = column_signature(fresh, M11_TABLES)
    assert before == {} or before == after                    # 形状不变
    with session(fresh) as connection, connection.cursor() as cur:
        cur.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n"
                    " ON n.oid = c.relnamespace WHERE n.nspname = %s"
                    " AND c.relname = ANY(%s)", (fresh, list(M11_TABLES)))
        assert cur.fetchone()[0] == len(M11_TABLES)
    indexes = [name for name in index_names(fresh) if name.startswith("risk_")]
    assert len(indexes) == len(set(indexes))                  # 索引没有翻倍


def test_down_is_repeatable_and_leaves_base_untouched(fresh: str) -> None:
    apply_migrations(fresh)
    base_tables = table_names(fresh) - set(M11_TABLES)
    base_before = column_signature(fresh, base_tables)
    constraints_before = constraint_signature(fresh, base_tables)

    for _ in range(2):                                        # 回滚两遍
        with migrate.connect(fresh) as connection:
            assert migrate.down(connection) == [
                "1104_risk_events.sql", "1103_risk_appeals.sql", "1102_risk_cases.sql",
                "1101_risk_limits.sql", "1100_risk_rules.sql"]

    tables = table_names(fresh)
    views = view_names(fresh)
    assert not (set(M11_TABLES) & tables)
    assert not (set(M11_VIEWS) & views)
    assert not {name for name in index_names(fresh) if name.startswith("risk_")}
    assert not {name for name in trigger_names(fresh) if name.startswith("risk_")
                or name.startswith("m11_")}
    assert column_signature(fresh, base_tables) == base_before
    assert constraint_signature(fresh, base_tables) == constraints_before

    with migrate.connect(fresh) as connection:                # 回滚后可再升级
        assert migrate.up(connection, with_base=False) == [
            "1100_risk_rules.sql", "1101_risk_limits.sql", "1102_risk_cases.sql",
            "1103_risk_appeals.sql", "1104_risk_events.sql"]
    assert set(M11_TABLES) <= table_names(fresh)
    assert set(M11_VIEWS) <= view_names(fresh)


# ─────────────────────────────────────────────────────── 索引 / 视图（§5）
def test_required_indexes_exist(migrated: str) -> None:
    indexes = index_names(migrated)
    assert {
        "uq_cases_open",                     # INV-06
        "idx_cases_status",
        "idx_appeals_sla",
        "idx_events_subject",
        "uq_appeals_open",                   # 重复申诉 48003
        "risk_rules_idem_uq",
        "risk_limits_idem_uq",
        "risk_outbox_pending_idx",
    } <= indexes


def test_views_are_queryable(migrated: str) -> None:
    with session(migrated) as connection, connection.cursor() as cur:
        for view in M11_VIEWS:
            cur.execute(f"SELECT count(*) FROM {view}")       # noqa: S608 - 固定视图名
            cur.fetchone()
        cur.execute("SELECT count(*) FROM v_risk_case_summary WHERE case_count >= 0")
        cur.fetchone()


def test_v_risk_limits_only_returns_active(migrated: str) -> None:
    tenant = "tenant-" + uuid.uuid4().hex[:8]
    with session(migrated) as connection, connection.cursor() as cur:
        for subject, expires in (("active-subject", None),
                                 ("expired-subject", FIXED - timedelta(days=1))):
            cur.execute(
                "INSERT INTO risk_limits (tenant_id, subject_type, subject_id, limit_type,"
                " value, window_s, expires_at, set_by) VALUES (%s, 'account', %s, 'qps',"
                " 100, 60, %s, 'tester')", (tenant, subject, expires))
        cur.execute("SELECT subject_id FROM v_risk_limits WHERE tenant_id = %s"
                    " ORDER BY subject_id", (tenant,))
        assert [row[0] for row in cur.fetchall()] == ["active-subject"]


# ─────────────────────────────────────────────────────── INV-01 库层兜底
def test_inv01_no_threshold_columns_anywhere(migrated: str) -> None:
    """库表里 0 处阈值 / 权重 / 名单列（INV-01）。"""
    hits = [(row["table_name"], row["column_name"]) for row in table_columns(migrated)
            if FORBIDDEN_KEY_RE.search(row["column_name"])]
    assert hits == []
    columns = {(row["table_name"], row["column_name"]) for row in table_columns(migrated)}
    # 规则表只有元数据 + config_ref（没有阈值 / 权重 / 名单列）
    assert {
        ("risk_rules", "rule_key"), ("risk_rules", "version"), ("risk_rules", "enabled"),
        ("risk_rules", "severity"), ("risk_rules", "action_class"),
        ("risk_rules", "config_ref"),
    } <= columns
    assert not {name for _, name in columns
                if name in ("threshold", "weight", "blocklist", "score")}


# ─────────────────────────────────────────────────────── 库层护栏
def test_inv03_case_requires_evidence(conn: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction(), conn.cursor() as cur:
            cur.execute(
                "INSERT INTO risk_cases (case_id, tenant_id, subject_hash, risk_type, severity,"
                " status, evidence_refs, opened_by, opened_at) VALUES (%s, 'tenant-a',"
                " %s, 'self_trade', 'P2', 'opened', '{}', 'maker', now())",
                (str(uuid.uuid4()), "sha256:" + "b" * 64))


def test_inv06_open_case_unique(conn: psycopg.Connection) -> None:
    subject = "sha256:" + "c" * 64
    with conn.transaction(), conn.cursor() as cur:
        for _ in range(2):
            case_id = str(uuid.uuid4())
            params = (case_id, "tenant-a", subject, "self_trade", "P2", ["evt-1"], "maker")
            if _ == 0:
                cur.execute(
                    "INSERT INTO risk_cases (case_id, tenant_id, subject_hash, risk_type,"
                    " severity, status, evidence_refs, opened_by, opened_at)"
                    " VALUES (%s, %s, %s, %s, %s, 'opened', %s, %s, now())", params)
        with pytest.raises(psycopg.errors.UniqueViolation):
            with conn.transaction():
                with conn.cursor() as inner:
                    inner.execute(
                        "INSERT INTO risk_cases (case_id, tenant_id, subject_hash, risk_type,"
                        " severity, status, evidence_refs, opened_by, opened_at)"
                        " VALUES (%s, 'tenant-a', %s, 'self_trade', 'P2', 'opened',"
                        " ARRAY['evt-2'], 'maker', now())", (str(uuid.uuid4()), subject))


def test_rules_are_append_only_and_immutable(conn: psycopg.Connection) -> None:
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            "INSERT INTO risk_rules (rule_key, version, enabled, severity, action_class,"
            " config_ref, created_by) VALUES ('self_trade.ratio', 1, true, 'P2', 'observe',"
            " 'risk.case.auto_action', 'tester')")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                with conn.cursor() as inner:
                    inner.execute("UPDATE risk_rules SET severity = 'P0'"
                                  " WHERE rule_key = 'self_trade.ratio'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                with conn.cursor() as inner:
                    inner.execute("DELETE FROM risk_rules WHERE rule_key = 'self_trade.ratio'")


def test_cases_are_append_only_and_terminal_locked(conn: psycopg.Connection) -> None:
    case_id = str(uuid.uuid4())
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            "INSERT INTO risk_cases (case_id, tenant_id, subject_hash, risk_type, severity,"
            " status, evidence_refs, opened_by, opened_at, closed_at)"
            " VALUES (%s, 'tenant-a', %s, 'sybil', 'P2', 'closed', ARRAY['evt-1'], 'maker',"
            " now(), now())", (case_id, "sha256:" + uuid.uuid4().hex + uuid.uuid4().hex))
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.transaction():
                with conn.cursor() as inner:
                    inner.execute("UPDATE risk_cases SET status = 'actioned'"
                                  " WHERE case_id = %s", (case_id,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                with conn.cursor() as inner:
                    inner.execute("DELETE FROM risk_cases WHERE case_id = %s", (case_id,))


def test_inv05_subject_hash_rejects_plaintext_pii(conn: psycopg.Connection) -> None:
    for subject in ("user@example.com", "192.168.1.10", "13800138000"):
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.transaction(), conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO risk_cases (case_id, tenant_id, subject_hash, risk_type,"
                    " severity, status, evidence_refs, opened_by, opened_at)"
                    " VALUES (%s, 'tenant-a', %s, 'key_leak', 'P1', 'opened',"
                    " ARRAY['evt-1'], 'maker', now())", (str(uuid.uuid4()), subject))


# ─────────────────────────────────────────────────────── 迁移 CLI
def test_migrate_cli_up_status_down(fresh: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert migrate.main(["--schema", fresh, "--up-only"]) == 0
    assert "applied 5 migrations" in capsys.readouterr().out
    assert migrate.main(["--schema", fresh, "--status"]) == 0
    out = capsys.readouterr().out
    assert "MISSING" not in out
    assert migrate.main(["--schema", fresh, "--down"]) == 0
    assert migrate.main(["--schema", fresh, "--status"]) == 0
    assert "MISSING" in capsys.readouterr().out
