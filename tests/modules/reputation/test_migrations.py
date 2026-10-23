# SPDX-License-Identifier: Apache-2.0
"""M07 迁移验收：空库 001→707、7xx 重复执行幂等、回滚两次干净、``points_*`` 结构不变、DB 护栏。

对应任务卡验收 1：空库全通过 / 7xx 连跑两遍幂等 / 回滚两次干净 / points_* 结构指纹前后一致。

性能约定：**前置段很重**（≈55 个文件），所以只有迁移三跑用完整空库升级；
护栏用例复用 ``migrated``（模块级已升级 schema）。
"""
from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg.types.json import Jsonb

from app.reputation import migrate as m07_migrate
from repukit import (
    FINGERPRINT_TABLES,
    M07_MIGRATIONS,
    M07_TABLES,
    M07_VIEWS,
    NOW,
    apply_file,
    apply_migrations,
    connect,
    m07_migration_files,
    prerequisite_files,
    scalar,
    structure_fingerprint,
    table_names,
)


def test_segment_is_owned_and_ordered():
    numbers = [int(name.split("_", 1)[0]) for name in M07_MIGRATIONS]
    assert numbers == [701, 702, 704, 705, 706, 707]
    assert all(700 <= number <= 799 for number in numbers)
    assert m07_migrate.MODULE_MIGRATIONS == M07_MIGRATIONS
    assert not [path for path in prerequisite_files() if 700 <= int(path.name.split("_")[0]) <= 799]
    assert m07_migrate.DOWN_SQL[0][0].startswith("707")


def test_cop_ledger_table_is_not_created():
    """Lead 裁决：COP 唯一账本是既有 points_*；**不得**出现 cop_ledger（703）。"""
    assert not [name for name in M07_MIGRATIONS if name.startswith("703")]
    assert not [name for name in M07_TABLES if name == "cop_ledger"]


def test_empty_database_upgrades_to_707(schema):
    applied = apply_migrations(schema)
    assert applied[-6:] == list(M07_MIGRATIONS)
    names = table_names(schema)
    assert set(M07_TABLES) <= names
    assert set(M07_VIEWS) <= names
    # 前置段对象仍在（M07 不删不改别人的东西）
    assert {"points_ledger", "points_journal", "ledger_entry", "config_items"} <= names
    assert not [item for item in _status(schema) if not item["applied"]]


def test_migrations_are_idempotent_when_repeated(schema):
    apply_migrations(schema)
    for _ in range(2):                                   # 连跑两遍（单文件级幂等）
        for path in m07_migration_files():
            apply_file(schema, path)
    names = table_names(schema)
    assert set(M07_TABLES) <= names
    assert set(M07_VIEWS) <= names
    _assert_key_objects(schema)


def test_rollback_twice_is_clean_and_reversible(schema):
    apply_migrations(schema)
    for _ in range(2):                                   # 回滚两次都要成功
        results = _down(schema)
        assert [item["rc"] for item in results] == [0] * 6
    names = table_names(schema)
    assert not set(M07_TABLES) & names
    assert not set(M07_VIEWS) & names
    assert {"points_ledger", "points_journal", "ledger_entry"} <= names   # 前置对象未删
    # 回滚后再升级仍然通过（可重复执行）
    apply_migrations(schema, files=list(m07_migration_files()))
    assert set(M07_TABLES) <= table_names(schema)


def test_status_reports_missing_before_and_after(schema):
    apply_migrations(schema, files=prerequisite_files())   # 707 的视图依赖 points_*（006）
    assert [item["applied"] for item in _status(schema)] == [False] * 6
    apply_migrations(schema, files=list(m07_migration_files()))
    assert [item["applied"] for item in _status(schema)] == [True] * 6
    assert m07_migrate.migration_files()[-6:] == tuple(m07_migration_files())


def test_points_structure_fingerprint_is_unchanged(schema):
    """验收 1：7xx 前后 ``points_*`` 结构指纹必须一致（M07 不碰 COP 台账的表结构）。"""
    apply_migrations(schema, files=prerequisite_files())
    before = structure_fingerprint(schema)
    assert set(before["tables"]) == set(FINGERPRINT_TABLES)
    apply_migrations(schema, files=list(m07_migration_files()))
    after = structure_fingerprint(schema)
    assert before == after
    assert before["digest"] == after["digest"]


# --------------------------------------------------------------------------- DB 护栏
def test_reputation_events_are_append_only(migrated):
    conn = connect(migrated)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO reputation_events (id, account_id, metric, value, weight, delta,
                                                  ref_id, occurred_at)
                   VALUES (%s,'user:guard','online_rate',900,2000,180,'ref-1',%s)""",
                (uuid.uuid4(), NOW))
            conn.commit()                                  # 行必须先落库，否则 0 行不触发 ROW 级触发器
        for statement in ("UPDATE reputation_events SET value = 1",
                          "DELETE FROM reputation_events",
                          "TRUNCATE reputation_events"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.cursor() as cur:
                    cur.execute(statement)
            conn.rollback()
    finally:
        conn.close()


def test_reward_grants_are_append_only(migrated):
    conn = connect(migrated)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO reward_grants (id, account_id, kind, amount, reason, actor,
                                              approved_by)
                   VALUES (%s,'user:guard','grant',100,'测试授予','admin:a','admin:b')""",
                (uuid.uuid4(),))
            conn.commit()
        for statement in ("UPDATE reward_grants SET amount = 1",
                          "DELETE FROM reward_grants",
                          "TRUNCATE reward_grants"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.cursor() as cur:
                    cur.execute(statement)
            conn.rollback()
    finally:
        conn.close()


def test_reward_grants_reject_self_approval(migrated):
    conn = connect(migrated)
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO reward_grants (id, account_id, kind, amount, reason, actor,
                                                  approved_by)
                       VALUES (%s,'user:guard','grant',1,'自批','admin:a','admin:a')""",
                    (uuid.uuid4(),))
        conn.rollback()
    finally:
        conn.close()


def test_invite_single_layer_is_enforced_by_db(migrated):
    """INV-03：库里不存在二级链路（触发器兜底，哪怕领域层被绕过）。"""
    conn = connect(migrated)
    inviter, invitee, third = f"user:l1-{uuid.uuid4().hex[:6]}", \
        f"user:l2-{uuid.uuid4().hex[:6]}", f"user:l3-{uuid.uuid4().hex[:6]}"
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO invites (id, inviter_id, invitee_id, code, status, bound_at)
                   VALUES (%s,%s,%s,%s,'bound',now())""",
                (uuid.uuid4(), inviter, invitee, f"C{uuid.uuid4().hex[:8].upper()}"))
        conn.commit()
        # ① invitee 自己再邀请别人 → 会形成二级链路，拒绝
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO invites (id, inviter_id, invitee_id, code, status, bound_at)
                       VALUES (%s,%s,%s,%s,'bound',now())""",
                    (uuid.uuid4(), invitee, third, f"C{uuid.uuid4().hex[:8].upper()}"))
        conn.rollback()
        # ② 已有上级的人再被绑给另一个上级 → 拒绝（唯一索引与单层触发器都会拦）
        with pytest.raises(psycopg.errors.IntegrityError):
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO invites (id, inviter_id, invitee_id, code, status, bound_at)
                       VALUES (%s,%s,%s,%s,'bound',now())""",
                    (uuid.uuid4(), third, invitee, f"C{uuid.uuid4().hex[:8].upper()}"))
        conn.rollback()
    finally:
        conn.close()


def test_invite_code_and_pair_are_unique(migrated):
    conn = connect(migrated)
    inviter, invitee = f"user:u1-{uuid.uuid4().hex[:6]}", f"user:u2-{uuid.uuid4().hex[:6]}"
    code = f"C{uuid.uuid4().hex[:8].upper()}"
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO invites (id, inviter_id, invitee_id, code, status, bound_at)
                   VALUES (%s,%s,%s,%s,'bound',now())""",
                (uuid.uuid4(), inviter, invitee, code))
        conn.commit()
        # INV-04：同一 (inviter, invitee) 不能有第二条
        with pytest.raises(psycopg.errors.UniqueViolation):
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO invites (id, inviter_id, invitee_id, code, status, bound_at)
                       VALUES (%s,%s,%s,%s,'bound',now())""",
                    (uuid.uuid4(), inviter, invitee, f"C{uuid.uuid4().hex[:8].upper()}"))
        conn.rollback()
        # code 唯一
        with pytest.raises(psycopg.errors.UniqueViolation):
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO invites (id, inviter_id, invitee_id, code, status, bound_at)
                       VALUES (%s,%s,%s,%s,'bound',now())""",
                    (uuid.uuid4(), f"user:x-{uuid.uuid4().hex[:6]}",
                     f"user:y-{uuid.uuid4().hex[:6]}", code))
        conn.rollback()
    finally:
        conn.close()


def test_invite_state_machine_rejects_illegal_transitions(migrated):
    conn = connect(migrated)
    inviter = f"user:sm-{uuid.uuid4().hex[:6]}"
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO invites (id, inviter_id, code, status, expire_at)
                   VALUES (%s,%s,%s,'sent',now() + interval '1 day')""",
                (uuid.uuid4(), inviter, f"C{uuid.uuid4().hex[:8].upper()}"))
        conn.commit()
        # sent → revoked 未登记（§3 只允许 sent→bound / sent→expired / bound→revoked）
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute("""UPDATE invites SET status = 'revoked'
                                WHERE inviter_id = %s AND status = 'sent'""", (inviter,))
        conn.rollback()
        # bound 但没 bound_at → 违反状态一致性
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute("""UPDATE invites SET status = 'bound'
                                WHERE inviter_id = %s AND status = 'sent'""", (inviter,))
        conn.rollback()
    finally:
        conn.close()


def test_outbox_envelope_is_immutable(migrated):
    conn = connect(migrated)
    row_id = uuid.uuid4()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO reputation_outbox
                     (id, event_id, type, occurred_at, aggregate_type, aggregate_id, trace_id,
                      idempotency_key, payload)
                   VALUES (%s,%s,'cop.earned',%s,'account','user:o','trace','k1',%s)""",
                (row_id, uuid.uuid4(), NOW, Jsonb({"amount": 1})))
        conn.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("UPDATE reputation_outbox SET payload = %s WHERE id = %s",
                            (Jsonb({"amount": 999}), row_id))
        conn.rollback()
        # 未发布的行不得删除（保留 30 天）
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("DELETE FROM reputation_outbox WHERE id = %s", (row_id,))
        conn.rollback()
        # 投递列可以改
        with conn.cursor() as cur:
            cur.execute("UPDATE reputation_outbox SET published_at = now() WHERE id = %s", (row_id,))
        conn.commit()
        assert scalar(conn, "SELECT published_at IS NOT NULL FROM reputation_outbox WHERE id = %s",
                      (row_id,)) is True
    finally:
        conn.close()


def test_reputation_scores_rejects_rate_columns(migrated):
    """INV-08 的结构保证：评分表不得出现费率 / 折扣列。"""
    conn = connect(migrated)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT column_name FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name = 'reputation_scores'
                      AND column_name ~ '(rate|discount|fee|price)'""")
            assert cur.fetchall() == []
    finally:
        conn.close()


def test_cop_ledger_view_maps_points_tables(migrated):
    """707 的只读视图必须只读：不能 INSERT / UPDATE。"""
    conn = connect(migrated)
    try:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            with conn.cursor() as cur:
                cur.execute("INSERT INTO v_m07_cop_ledger (id) VALUES (%s)", (uuid.uuid4(),))
        conn.rollback()
    finally:
        conn.close()


# --------------------------------------------------------------------------- 工具
def _status(schema: str) -> list[dict]:
    conn = connect(schema)
    try:
        return m07_migrate.status(conn)
    finally:
        conn.close()


def _down(schema: str) -> list[dict]:
    conn = connect(schema)
    try:
        try:
            return m07_migrate.down(conn)
        except Exception:                                  # pragma: no cover - 失败即停
            conn.rollback()
            raise
    finally:
        conn.close()


def _assert_key_objects(schema: str) -> None:
    conn = connect(schema)
    try:
        for index in ("invites_code_uq", "invites_inviter_invitee_uq", "invites_invitee_bound_uq",
                      "reputation_events_fact_uq", "reward_grants_request_uq",
                      "reputation_outbox_event_uq", "reputation_outbox_dedupe_uq"):
            assert scalar(
                conn,
                """SELECT count(*) FROM pg_indexes
                    WHERE schemaname = current_schema() AND indexname = %s""", (index,)) == 1, index
        for trigger, table in (
                ("reputation_events_no_mutation", "reputation_events"),
                ("reward_grants_no_mutation", "reward_grants"),
                ("invites_single_layer", "invites"),
                ("invites_state_machine", "invites"),
                ("reputation_outbox_guard", "reputation_outbox")):
            assert scalar(
                conn,
                """SELECT count(*) FROM pg_trigger
                    WHERE tgname = %s AND tgrelid = %s::regclass""",
                (trigger, table)) == 1, trigger
    finally:
        conn.close()
