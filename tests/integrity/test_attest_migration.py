# SPDX-License-Identifier: AGPL-3.0-or-later
"""1720 迁移用例：对象 / 只加不改 / 回滚可重复 / 一次性挑战 / 只升不降 / 账本 diff=0。

DDL 在 PostgreSQL 是事务性的：升级与回滚演练都在一个事务里做完再回滚，
共享 ``base_schema`` 保持原状（NAS 上只跑一次基线迁移）。
"""
from __future__ import annotations

import psycopg
import pytest

from app.integrity import facts, migrate

from kit import (apply_m17_in_transaction, connect, function_names_on, index_names_on,
                 ledger_snapshot, m17_migration_files, relation_fingerprint_on,
                 strip_transaction, table_names_on)


def _apply(conn, *, names: tuple[str, ...]) -> list[str]:
    applied: list[str] = []
    for path in m17_migration_files():
        number = path.name.split("_", 1)[0]
        if number in names:
            conn.execute(strip_transaction(path.read_text(encoding="utf-8")))
            applied.append(path.name)
    return applied


def _down(conn, name: str) -> None:
    conn.execute(strip_transaction(dict(migrate.DOWN_SQL)[name]))


def test_1720_objects_exist_in_migrated_schema(migrated):
    tables = table_names_on(connect(migrated), migrated)
    assert {"model_attestations", "attestation_challenges", "attestation_events"} <= tables
    indexes = index_names_on(connect(migrated), migrated)
    assert {"uq_attestations_active", "idx_challenges_node",
            "idx_attestation_events_node"} <= indexes
    functions = function_names_on(connect(migrated), migrated)
    assert {"m17_attestation_guard", "m17_challenge_guard",
            "m17_attest_event_guard"} <= functions


def test_1720_upgrade_only_adds_its_objects(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        before_tables = table_names_on(conn, base_schema)
        before_indexes = index_names_on(conn, base_schema)
        before_functions = function_names_on(conn, base_schema)
        before_fingerprint = relation_fingerprint_on(conn, base_schema, sorted(before_tables))

        _apply(conn, names=("1720",))

        after_tables = table_names_on(conn, base_schema)
        assert after_tables - before_tables == {
            "model_attestations", "attestation_challenges", "attestation_events"}
        assert relation_fingerprint_on(conn, base_schema, sorted(before_tables)) == \
            before_fingerprint
        assert index_names_on(conn, base_schema) - before_indexes == {
            "uq_attestations_active", "idx_attestations_node", "idx_attestations_level",
            "idx_attestations_expiry", "idx_challenges_node", "idx_challenges_expiry",
            "idx_attestation_events_attestation", "idx_attestation_events_challenge",
            "idx_attestation_events_node", "model_attestations_pkey",
            "attestation_challenges_pkey", "attestation_challenges_nonce_key",
            "attestation_events_pkey"}
        assert function_names_on(conn, base_schema) - before_functions == {
            "m17_attestation_guard", "m17_challenge_guard", "m17_attest_event_guard",
            "m17_attest_forbid_truncate"}
        conn.rollback()


def test_1720_rollback_is_clean_and_repeatable(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, names=("1720",))
        assert {"model_attestations", "attestation_challenges",
                "attestation_events"} <= table_names_on(conn, base_schema)
        _down(conn, "1720_model_attestations.sql")
        assert not ({"model_attestations", "attestation_challenges", "attestation_events"}
                    & table_names_on(conn, base_schema))
        _down(conn, "1720_model_attestations.sql")            # 再回滚一次：可重复
        _apply(conn, names=("1720",))                         # 回滚后还能再升级
        assert {"model_attestations", "attestation_challenges"} <= table_names_on(
            conn, base_schema)
        conn.rollback()


def test_full_module_up_down_up_is_clean(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        apply_m17_in_transaction(conn)
        for name, _sql in migrate.DOWN_SQL:
            _down(conn, name)
        assert not (set(migrate.M17_TABLES) & table_names_on(conn, base_schema))
        assert not (set(migrate.M17_FUNCTIONS) & function_names_on(conn, base_schema))
        views = {row[0] for row in conn.execute(
            "SELECT viewname FROM pg_views WHERE schemaname = %s", (base_schema,))}
        assert not (set(migrate.M17_VIEWS) & views)
        apply_m17_in_transaction(conn)
        assert set(migrate.M17_TABLES) <= table_names_on(conn, base_schema)
        conn.rollback()


def test_challenge_is_single_use_and_immutable(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, names=("1720",))
        conn.execute(
            """
            INSERT INTO attestation_challenges
              (id, node_id, upstream_id, model, prompt, prompt_tokens, nonce, state,
               expires_at, created_at)
            VALUES (gen_random_uuid(), 'node-1', NULL, 'openai/gpt-4o',
                    repeat('synthetic probe ', 4), 40, 'aabbccdd11223344', 'issued',
                    now() + interval '5 minutes', now())
            """)
        with pytest.raises(psycopg.Error):                     # 内容不可变
            with conn.transaction():
                conn.execute("UPDATE attestation_challenges SET prompt = 'tampered'")
        with pytest.raises(psycopg.Error):                     # 不能跳过消费直接置回 issued
            with conn.transaction():
                conn.execute("UPDATE attestation_challenges SET state = 'issued'")
        with conn.transaction():
            conn.execute("UPDATE attestation_challenges"
                         " SET state = 'consumed', consumed_at = now()")
        with pytest.raises(psycopg.Error) as excinfo:          # 二次消费（重放）拒绝
            with conn.transaction():
                conn.execute("UPDATE attestation_challenges SET state = 'consumed'")
        assert "重放" in str(excinfo.value)
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM attestation_challenges")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("TRUNCATE attestation_challenges")
        conn.rollback()


def test_attestation_level_only_goes_up(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, names=("1720",))
        conn.execute(
            """
            INSERT INTO model_attestations
              (id, node_id, upstream_id, model, level, state, source, tokenizer_version,
               evidence_ref, verified_at, expires_at, created_at)
            VALUES (gen_random_uuid(), 'node-1', NULL, 'openai/gpt-4o', 'L2', 'active',
                    'server_challenge', 'fake-1', 'challenge:x', now(),
                    now() + interval '24 hours', now())
            """)
        with pytest.raises(psycopg.Error) as excinfo:          # 降级拒绝
            with conn.transaction():
                conn.execute("UPDATE model_attestations SET level = 'L1'")
        assert "只升不降" in str(excinfo.value)
        with conn.transaction():                                # 升级允许
            conn.execute("UPDATE model_attestations SET level = 'L3',"
                         " expires_at = now() + interval '7 days'")
        with pytest.raises(psycopg.Error):                      # 身份字段不可变
            with conn.transaction():
                conn.execute("UPDATE model_attestations SET node_id = 'node-2'")
        with pytest.raises(psycopg.Error):                      # L0 不允许带 verified
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO model_attestations
                      (id, node_id, upstream_id, model, level, state, source, evidence_ref,
                       verified_at, expires_at, created_at)
                    VALUES (gen_random_uuid(), 'node-3', NULL, 'openai/gpt-4o', 'L0',
                            'active', 'server_challenge', 'challenge:y', now(),
                            now() + interval '1 hour', now())
                    """)
        conn.rollback()


def test_events_append_only_and_detail_hygiene(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        _apply(conn, names=("1720",))
        conn.execute(
            """
            INSERT INTO attestation_events
              (event_id, attestation_id, challenge_id, node_id, model, event, level,
               detail, actor, created_at)
            VALUES (gen_random_uuid(), NULL, NULL, 'node-1', 'openai/gpt-4o',
                    'challenge_issued', NULL, '{"prompt_tokens": 40}'::jsonb,
                    'node:node-1', now())
            """)
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("UPDATE attestation_events SET actor = 'tamper'")
        with pytest.raises(psycopg.Error):
            with conn.transaction():
                conn.execute("DELETE FROM attestation_events")
        with pytest.raises(psycopg.errors.CheckViolation):      # 正文类键写不进来
            with conn.transaction():
                conn.execute(
                    """
                    INSERT INTO attestation_events
                      (event_id, node_id, model, event, level, detail, actor, created_at)
                    VALUES (gen_random_uuid(), 'node-1', 'openai/gpt-4o',
                            'evidence_submitted', 'L3', '{"prompt": "用户正文"}'::jsonb,
                            'node:node-1', now())
                    """)
        conn.rollback()


def test_ledger_unchanged_by_1720(base_schema):
    with connect(base_schema, autocommit=False) as conn:
        conn.execute(
            """
            INSERT INTO loss_pool_entries
              (entry_id, request_id, attempt_no, amount_minor, reason, evidence_ref,
               recorded_at)
            VALUES (gen_random_uuid(), 'req-c12-ledger-1', 1, 1200000, 'upstream_consumed',
                    'bill-c12', now())
            """)
        before_rows = ledger_snapshot(conn, facts.LEDGER_TABLES)
        before_structure = relation_fingerprint_on(conn, base_schema,
                                                  sorted(facts.LEDGER_TABLES))
        _apply(conn, names=("1720",))
        assert ledger_snapshot(conn, facts.LEDGER_TABLES) == before_rows
        assert relation_fingerprint_on(conn, base_schema, sorted(facts.LEDGER_TABLES)) == \
            before_structure
        assert before_rows["loss_pool_entries"]["count"] == 1
        conn.rollback()
