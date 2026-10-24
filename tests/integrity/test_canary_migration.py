# SPDX-License-Identifier: AGPL-3.0-or-later
"""1740 迁移用例：对象 / 内置题面 / 只加不改 / 回滚可重复 / 题面与运行护栏 / 账本 diff=0。

DDL 在 PostgreSQL 是事务性的：升级与回滚演练都在一个事务里做完再回滚。
1740 只依赖自身（FK 无跨迁移依赖），可以在 ``base_schema`` 上单独应用。
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


def test_1740_objects_and_builtin_prompts(migrated):
    tables = table_names_on(connect(migrated), migrated)
    assert {"canary_prompts", "canary_runs", "canary_events"} <= tables
    indexes = index_names_on(connect(migrated), migrated)
    assert {"uq_canary_runs_issued", "idx_canary_runs_status"} <= indexes
    functions = function_names_on(connect(migrated), migrated)
    assert {"m17_canary_prompt_guard", "m17_canary_run_guard",
            "m17_canary_event_guard"} <= functions
    with connect(migrated) as conn:
        rows = conn.execute(
            "SELECT prompt_key, expected_kind, state FROM canary_prompts"
            " ORDER BY prompt_key").fetchall()
    assert [row[0] for row in rows] == sorted(facts.CANARY_PROMPT_KEYS)
    assert {row[1] for row in rows} == {"exact", "contains", "regex"}
    assert all(row[2] == "active" for row in rows)


def test_1740_upgrade_only_adds_its_objects(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        before_tables = table_names_on(conn, base_schema)
        before_indexes = index_names_on(conn, base_schema)
        before_functions = function_names_on(conn, base_schema)
        before_fingerprint = relation_fingerprint_on(conn, base_schema, sorted(before_tables))

        _apply(conn, "1740")

        after_tables = table_names_on(conn, base_schema)
        assert after_tables - before_tables == {
            "canary_prompts", "canary_runs", "canary_events"}
        assert relation_fingerprint_on(conn, base_schema, sorted(before_tables)) == \
            before_fingerprint
        assert index_names_on(conn, base_schema) - before_indexes == {
            "idx_canary_prompts_state", "uq_canary_runs_issued", "idx_canary_runs_node",
            "idx_canary_runs_status", "idx_canary_runs_prompt", "idx_canary_events_run",
            "canary_prompts_pkey", "canary_prompts_prompt_key_key", "canary_runs_pkey",
            "canary_events_pkey"}
        assert function_names_on(conn, base_schema) - before_functions == {
            "m17_canary_prompt_guard", "m17_canary_run_guard", "m17_canary_event_guard",
            "m17_canary_forbid_truncate"}
        assert conn.execute("SELECT COUNT(*) FROM canary_prompts").fetchone()[0] == 5
        conn.rollback()


def test_1740_rollback_repeatable_and_reseeds(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1740")
        _down(conn, "1740_canary.sql")
        assert not ({"canary_prompts", "canary_runs", "canary_events"}
                    & table_names_on(conn, base_schema))
        _down(conn, "1740_canary.sql")                        # 再回滚一次：可重复
        _apply(conn, "1740")                                  # 回滚后还能再升级
        assert {"canary_prompts", "canary_runs"} <= table_names_on(conn, base_schema)
        assert conn.execute("SELECT COUNT(*) FROM canary_prompts").fetchone()[0] == 5
        conn.rollback()


def test_prompt_guard_immutable_and_retire_only(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1740")
        with pytest.raises(psycopg.Error):                    # 题面不可改
            with conn.transaction():
                conn.execute("UPDATE canary_prompts SET expected_value = 'x'")
        with pytest.raises(psycopg.Error):                    # max_tokens 不可改
            with conn.transaction():
                conn.execute("UPDATE canary_prompts SET max_tokens = 99")
        with conn.transaction():                              # active → retired 允许
            conn.execute("UPDATE canary_prompts SET state = 'retired'"
                         " WHERE prompt_key = 'arith.2plus2'")
        with pytest.raises(psycopg.Error) as excinfo:         # retired 不可回写
            with conn.transaction():
                conn.execute("UPDATE canary_prompts SET state = 'active'"
                             " WHERE prompt_key = 'arith.2plus2'")
        assert "不可回写" in str(excinfo.value)
        with pytest.raises(psycopg.Error):                    # 禁止 DELETE
            with conn.transaction():
                conn.execute("DELETE FROM canary_prompts WHERE prompt_key = 'arith.2plus2'")
        with pytest.raises(psycopg.Error):                    # 禁止 TRUNCATE
            with conn.transaction():
                conn.execute("TRUNCATE canary_prompts")
        conn.rollback()


def test_run_guard_state_and_hash(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1740")
        conn.execute(
            """
            INSERT INTO canary_runs
              (id, node_id, upstream_id, model, prompt_id, nonce, status, response_hash,
               score, detail, created_at, deadline_at, resolved_at)
            VALUES (gen_random_uuid(), 'node-1', NULL, 'openai/gpt-4o',
                    '00000000-0000-7400-8000-000000000001', 'aabbccdd11223344', 'issued',
                    NULL, NULL, '{}'::jsonb, now(), now() + interval '120 seconds', NULL)
            """)
        with pytest.raises(psycopg.errors.UniqueViolation):   # 同 node/model 只 1 条 issued
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO canary_runs
                      (id, node_id, upstream_id, model, prompt_id, nonce, status,
                       created_at, deadline_at)
                    VALUES (gen_random_uuid(), 'node-1', NULL, 'openai/gpt-4o',
                            '00000000-0000-7400-8000-000000000002', 'aabbccdd11223355',
                            'issued', now(), now() + interval '120 seconds')
                    """)
        with pytest.raises(psycopg.Error):                    # 身份字段不可变
            with conn.transaction():
                conn.execute("UPDATE canary_runs SET node_id = 'node-2'")
        with conn.transaction():                              # issued → passed 允许
            conn.execute("UPDATE canary_runs SET status = 'passed',"
                         " response_hash = repeat('a', 64), score = 1.0,"
                         " resolved_at = now()")
        with pytest.raises(psycopg.Error) as excinfo:         # 终态不可改
            with conn.transaction():
                conn.execute("UPDATE canary_runs SET status = 'failed'")
        assert "不可再改" in str(excinfo.value)
        with pytest.raises(psycopg.Error):                    # 结果 hash 不可翻案
            with conn.transaction():
                conn.execute("UPDATE canary_runs SET response_hash = repeat('b', 64)")
        with pytest.raises(psycopg.errors.CheckViolation):    # detail 不得带正文类键
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO canary_runs
                      (id, node_id, upstream_id, model, prompt_id, nonce, status, detail,
                       created_at, deadline_at)
                    VALUES (gen_random_uuid(), 'node-3', NULL, 'openai/gpt-4o',
                            '00000000-0000-7400-8000-000000000001', 'aabbccdd11223366',
                            'issued', '{"response": "x"}'::jsonb, now(),
                            now() + interval '120 seconds')
                    """)
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM canary_runs")
        conn.rollback()


def test_events_append_only(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, "1740")
        conn.execute(
            """
            INSERT INTO canary_runs
              (id, node_id, upstream_id, model, prompt_id, nonce, status, detail,
               created_at, deadline_at)
            VALUES ('00000000-0000-7400-8000-0000000000a1', 'node-1', NULL,
                    'openai/gpt-4o', '00000000-0000-7400-8000-000000000001',
                    'aabbccdd11223377', 'issued', '{}'::jsonb, now(),
                    now() + interval '120 seconds')
            """)
        conn.execute(
            """
            INSERT INTO canary_events (event_id, run_id, event, detail, created_at)
            VALUES (gen_random_uuid(), '00000000-0000-7400-8000-0000000000a1', 'issued',
                    '{"prompt_key": "arith.2plus2"}'::jsonb, now())
            """)
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("UPDATE canary_events SET event = 'passed'")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM canary_events")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("TRUNCATE canary_events")
        conn.rollback()


def test_ledger_unchanged_by_1740(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        conn.execute(
            """
            INSERT INTO loss_pool_entries
              (entry_id, request_id, attempt_no, amount_minor, reason, evidence_ref,
               recorded_at)
            VALUES (gen_random_uuid(), 'req-c13-ledger-1', 1, 700000, 'upstream_consumed',
                    'bill-c13', now())
            """)
        before_rows = ledger_snapshot(conn, facts.LEDGER_TABLES)
        before_structure = relation_fingerprint_on(conn, base_schema,
                                                  sorted(facts.LEDGER_TABLES))
        _apply(conn, "1740")
        assert ledger_snapshot(conn, facts.LEDGER_TABLES) == before_rows
        assert relation_fingerprint_on(conn, base_schema, sorted(facts.LEDGER_TABLES)) == \
            before_structure
        assert before_rows["loss_pool_entries"]["count"] == 1
        conn.rollback()
