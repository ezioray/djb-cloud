# SPDX-License-Identifier: AGPL-3.0-or-later
"""1730 迁移用例：对象 / 只加不改 / 回滚可重复 / 承诺与状态护栏 / 抽检唯一 / 账本 diff=0。

DDL 在 PostgreSQL 是事务性的：升级与回滚演练都在一个事务里做完再回滚。
1730 依赖 1720 的 attestation_challenges（FK），因此先在事务内应用 1720 再应用 1730。
"""
from __future__ import annotations

import psycopg
import pytest

from app.integrity import facts, migrate

from kit import (connect, function_names_on, index_names_on, ledger_snapshot,
                 m17_migration_files, relation_fingerprint_on, strip_transaction,
                 table_names_on)


def _apply(conn, *numbers: str) -> list[str]:
    applied: list[str] = []
    for path in m17_migration_files():
        if path.name.split("_", 1)[0] in numbers:
            conn.execute(strip_transaction(path.read_text(encoding="utf-8")))
            applied.append(path.name)
    return applied


def _down(conn, name: str) -> None:
    conn.execute(strip_transaction(dict(migrate.DOWN_SQL)[name]))


def test_1730_objects_exist_in_migrated_schema(migrated):
    tables = table_names_on(connect(migrated), migrated)
    assert {"sampling_epochs", "sampling_draws", "sampling_events"} <= tables
    indexes = index_names_on(connect(migrated), migrated)
    assert {"uq_sampling_draws_epoch_node_model", "idx_sampling_events_epoch"} <= indexes
    functions = function_names_on(connect(migrated), migrated)
    assert {"m17_sampling_epoch_guard", "m17_sampling_draw_guard",
            "m17_sampling_event_guard"} <= functions


def test_1730_upgrade_only_adds_its_objects(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1720")                                  # 先满足 FK 依赖
        before_tables = table_names_on(conn, base_schema)
        before_indexes = index_names_on(conn, base_schema)
        before_functions = function_names_on(conn, base_schema)
        before_fingerprint = relation_fingerprint_on(conn, base_schema, sorted(before_tables))

        _apply(conn, "1730")

        after_tables = table_names_on(conn, base_schema)
        assert after_tables - before_tables == {
            "sampling_epochs", "sampling_draws", "sampling_events"}
        assert relation_fingerprint_on(conn, base_schema, sorted(before_tables)) == \
            before_fingerprint
        assert index_names_on(conn, base_schema) - before_indexes == {
            "idx_sampling_epochs_state", "idx_sampling_draws_epoch",
            "idx_sampling_draws_node", "idx_sampling_draws_challenge",
            "idx_sampling_events_epoch", "idx_sampling_events_draw",
            "uq_sampling_draws_epoch_node_model", "sampling_epochs_pkey",
            "sampling_epochs_epoch_no_key", "sampling_draws_pkey", "sampling_events_pkey"}
        assert function_names_on(conn, base_schema) - before_functions == {
            "m17_sampling_epoch_guard", "m17_sampling_draw_guard",
            "m17_sampling_event_guard", "m17_sampling_forbid_truncate"}
        conn.rollback()


def test_1730_rollback_is_clean_and_repeatable(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1720", "1730")
        assert {"sampling_epochs", "sampling_draws"} <= table_names_on(conn, base_schema)
        _down(conn, "1730_sampling.sql")
        assert not ({"sampling_epochs", "sampling_draws", "sampling_events"}
                    & table_names_on(conn, base_schema))
        _down(conn, "1730_sampling.sql")                      # 再回滚一次：可重复
        _apply(conn, "1730")                                  # 回滚后还能再升级
        assert {"sampling_epochs", "sampling_events"} <= table_names_on(conn, base_schema)
        conn.rollback()


def test_epoch_commit_guard_and_lifecycle(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1720", "1730")
        conn.execute(
            """
            INSERT INTO sampling_epochs
              (id, epoch_no, seed_commit, seed_reveal, contributions, state,
               committed_at, revealed_at, draw_count, created_at)
            VALUES (gen_random_uuid(), 1, repeat('a', 64), NULL,
                    '[{"node_id": "n1", "model": "m1", "weight": 10}]'::jsonb,
                    'committed', now(), NULL, 1, now())
            """)
        with pytest.raises(psycopg.Error):                    # 承诺不可改
            with conn.transaction():
                conn.execute("UPDATE sampling_epochs SET seed_commit = repeat('b', 64)")
        with pytest.raises(psycopg.Error):                    # 抽样框快照不可改
            with conn.transaction():
                conn.execute("UPDATE sampling_epochs SET contributions = '[]'::jsonb")
        with pytest.raises(psycopg.Error):                    # committed 阶段不得带 seed
            with conn.transaction():
                conn.execute("UPDATE sampling_epochs SET seed_reveal = repeat('c', 64),"
                             " state = 'revealed'")           # 缺 revealed_at
        with conn.transaction():
            conn.execute("UPDATE sampling_epochs SET seed_reveal = repeat('c', 64),"
                         " state = 'revealed', revealed_at = now()")
        with pytest.raises(psycopg.Error) as excinfo:         # seed 只能揭示一次
            with conn.transaction():
                conn.execute("UPDATE sampling_epochs SET seed_reveal = repeat('d', 64)")
        assert "不可改写" in str(excinfo.value)
        with pytest.raises(psycopg.Error):                    # 终态不可回写
            with conn.transaction():
                conn.execute("UPDATE sampling_epochs SET state = 'committed'")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM sampling_epochs")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("TRUNCATE sampling_epochs")
        conn.rollback()


def test_draw_guard_uniqueness_and_detail_hygiene(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1720", "1730")
        conn.execute(
            """
            INSERT INTO sampling_epochs
              (id, epoch_no, seed_commit, contributions, state, committed_at, draw_count,
               created_at)
            VALUES ('00000000-0000-7000-8000-0000000000e1', 9, repeat('a', 64),
                    '[]'::jsonb, 'committed', now(), 0, now())
            """)
        insert = """
            INSERT INTO sampling_draws
              (id, epoch_id, node_id, model, weight, rank, challenge_id, status, level,
               detail, created_at, resolved_at)
            VALUES (gen_random_uuid(), '00000000-0000-7000-8000-0000000000e1', %s, %s, 10,
                    %s, NULL, 'pending', NULL, %s, now(), NULL)
        """
        with conn.transaction():
            conn.execute(insert, ("n1", "m1", 1, "{}"))
        with pytest.raises(psycopg.errors.UniqueViolation):   # 同轮同 (node,model) 唯一
            with conn.transaction():
                conn.execute(insert, ("n1", "m1", 2, "{}"))
        with pytest.raises(psycopg.errors.CheckViolation):    # detail 不得带正文类键
            with conn.transaction():
                conn.execute(insert, ("n2", "m1", 3, '{"prompt": "x"}'))
        with pytest.raises(psycopg.Error):                    # 抽签字段不可变
            with conn.transaction():
                conn.execute("UPDATE sampling_draws SET rank = 5")
        with conn.transaction():                              # pending → passed 允许
            conn.execute("UPDATE sampling_draws SET status = 'passed', level = 'L3',"
                         " resolved_at = now()")
        with pytest.raises(psycopg.Error) as excinfo:         # 终态不可改
            with conn.transaction():
                conn.execute("UPDATE sampling_draws SET status = 'missed'")
        assert "不可再改" in str(excinfo.value)
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM sampling_draws")
        conn.rollback()


def test_events_append_only(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1720", "1730")
        conn.execute(
            """
            INSERT INTO sampling_events (event_id, epoch_id, draw_id, event, detail, actor,
                                         created_at)
            VALUES (gen_random_uuid(), NULL, NULL, 'committed',
                    '{"epoch_no": 1}'::jsonb, 'system:sampling', now())
            """)
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("UPDATE sampling_events SET actor = 'tamper'")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM sampling_events")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("TRUNCATE sampling_events")
        with pytest.raises(psycopg.errors.CheckViolation):    # seed 不得进事件 detail
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO sampling_events (event_id, event, detail, actor, created_at)
                    VALUES (gen_random_uuid(), 'committed', '{"seed": "abc"}'::jsonb,
                            'system:sampling', now())
                    """)
        conn.rollback()


def test_ledger_unchanged_by_1730(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        conn.execute(
            """
            INSERT INTO loss_pool_entries
              (entry_id, request_id, attempt_no, amount_minor, reason, evidence_ref,
               recorded_at)
            VALUES (gen_random_uuid(), 'req-c14b-ledger-1', 1, 900000, 'upstream_consumed',
                    'bill-c14b', now())
            """)
        before_rows = ledger_snapshot(conn, facts.LEDGER_TABLES)
        before_structure = relation_fingerprint_on(conn, base_schema,
                                                  sorted(facts.LEDGER_TABLES))
        _apply(conn, "1720", "1730")
        assert ledger_snapshot(conn, facts.LEDGER_TABLES) == before_rows
        assert relation_fingerprint_on(conn, base_schema, sorted(facts.LEDGER_TABLES)) == \
            before_structure
        assert before_rows["loss_pool_entries"]["count"] == 1
        conn.rollback()
