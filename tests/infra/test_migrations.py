# SPDX-License-Identifier: AGPL-3.0-or-later
"""迁移三跑（空库 / 升级 / 回滚）+ 只追加护栏 + 约束（需要 DJB_DSN）。

对应验收：1400–1403 空库跑通、单文件重复执行幂等、回滚干净、不触碰其它模块表。

性能取舍：NAS 上一次全量迁移约 20s，所以"读 + 事务内写"的用例都跑在 session 级共享
schema 上（``conn`` 回滚隔离），只有必须"真 DDL 态"的三跑用全新 schema。
"""
from __future__ import annotations

import hashlib

import pytest
from psycopg.types.json import Jsonb

from app.audit import facts, migrate
from infrakit import (
    HASH_PATTERN,
    apply_migrations,
    assert_db_error,
    base_table_names,
    column_names,
    connect,
    fingerprint,
    function_names,
    index_names,
    m16_migration_files,
    migration_files,
    migration_number,
    prerequisite_files,
    run_migrations,
    scalar,
    table_names,
    trigger_names,
)

M16_TABLES = ("audit_log", "audit_anchors", "m16_outbox")


def entry_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def insert_entry(connection, *, seq: int = 1, prev_hash: str = facts.GENESIS,
                 hash_value: str | None = None, entry_id: str | None = None,
                 alg: str = facts.ALG, status: str = "recorded",
                 actor_type: str = "agent", **overrides) -> None:
    params = {
        "seq": seq,
        "entry_id": entry_id or f"018f4d0e-0000-7000-8000-0000000000{seq:02d}",
        "actor": "infra-seat",
        "actor_type": actor_type,
        "role": "INFRA",
        "action": "read.report",
        "target": "nas/guard",
        "status": status,
        "alg": alg,
        "prev_hash": prev_hash,
        "hash": hash_value or entry_hash(f"seq-{seq}"),
    }
    params.update(overrides)
    connection.execute(
        """INSERT INTO audit_log
               (seq, entry_id, ts, actor, actor_type, role, action, target, before, after,
                reason_code, ticket, evidence, approval_chain, status, alg, prev_hash, hash,
                idempotency_key)
           VALUES (%(seq)s, %(entry_id)s, now(), %(actor)s, %(actor_type)s, %(role)s,
                   %(action)s, %(target)s, NULL, NULL, NULL, NULL, NULL, '[]'::jsonb,
                   %(status)s, %(alg)s, %(prev_hash)s, %(hash)s, NULL)""", params)


def insert_outbox(connection, *, aggregate_id: str, payload: dict | None = None,
                  type_: str = "audit.appended", key: str = "k-0123456789abcdef") -> None:
    connection.execute(
        """INSERT INTO m16_outbox (type, aggregate_type, aggregate_id, trace_id,
                                   idempotency_key, payload)
           VALUES (%s, 'audit_entry', %s, 'trace', %s, %s)""",
        (type_, aggregate_id, key,
         Jsonb(payload if payload is not None else {"audit_id": aggregate_id, "actor": "a",
                                                    "action": "b", "hash": "h", "seq": 1})))


# --------------------------------------------------------------------------- 空库 / 升级 / 回滚（真 DDL 态）
def test_empty_schema_applies_every_migration_in_numeric_order(schema: str):
    """空库：001→1403 按数字序一次跑通。"""
    result = run_migrations(migration_files(), schema)
    assert result.returncode == 0, result.stderr

    numbers = [migration_number(path) for path in migration_files()]
    assert numbers == sorted(numbers)
    assert [number for number in numbers if 1400 <= number <= 1499] == [1400, 1401, 1402, 1403]

    tables = table_names(schema)
    for table in M16_TABLES:
        assert table in tables, table


def test_upgrade_only_adds_m16_objects(schema: str):
    """升级：只加不改 —— 14xx 前后上游对象结构指纹必须完全一致。"""
    apply_migrations(schema, prerequisite_files())
    before_tables = table_names(schema)
    upstream = sorted(base_table_names() & before_tables)
    before_fingerprint = fingerprint(schema, upstream)

    apply_migrations(schema, m16_migration_files())

    after_tables = table_names(schema)
    assert before_fingerprint == fingerprint(schema, upstream), "14xx 迁移改动了上游对象"
    assert set(M16_TABLES).issubset(after_tables)
    # 只多了 3 张本模块表，零张别人的表
    assert after_tables - before_tables == set(M16_TABLES)


def test_rollback_is_clean_and_repeatable(schema: str):
    """回滚：逆序删 14xx，上游零改动；可重复执行；回滚后还能再升级。"""
    apply_migrations(schema)
    upstream = sorted(base_table_names() & table_names(schema))
    upstream_before = fingerprint(schema, upstream)

    with connect(schema, autocommit=False) as connection:
        results = migrate.down(connection)
        assert results == [name for name, _ in migrate.DOWN_SQL]
        connection.commit()
        again = migrate.down(connection)              # 可重复执行
        connection.commit()
        assert again == results

    tables = table_names(schema)
    for table in M16_TABLES:
        assert table not in tables, table
    assert fingerprint(schema, upstream) == upstream_before

    functions = function_names(schema)
    for name in ("m16_audit_forbid_mutation", "m16_forbid_truncate", "m16_outbox_guard",
                 "m16_audit_chain_guard", "m16_outbox_audit_ref_guard"):
        assert name not in functions, name
    triggers = trigger_names(schema)
    for name in ("audit_log_no_mutation", "audit_anchors_no_mutation", "m16_outbox_guard"):
        assert name not in triggers, name

    with connect(schema, autocommit=True) as connection:
        assert migrate.up(connection, with_base=False) == list(migrate.MODULE_MIGRATIONS)
        info = migrate.status(connection)
    assert set(info["tables"]) == set(M16_TABLES)
    assert list(info["migrations"]) == list(migrate.MODULE_MIGRATIONS)
    assert info["audit_entries"] == 0
    assert info["anchors"] == 0
    assert "audit_log_no_mutation" in info["triggers"]

    with connect(schema, autocommit=True) as connection:
        migrate.down(connection)
        empty = migrate.status(connection)
    assert empty["tables"] == []
    assert empty["audit_entries"] is None
    assert empty["anchors"] is None


def test_migrations_are_numbered_in_order_and_not_lexicographic():
    """字典序会把 1008 排到 600 前面 —— 所以迁移必须按数字前缀跑。"""
    numeric = [path.name for path in migration_files()]
    lexicographic = [path.name for path in migration_files("lexicographic")]
    assert numeric.index("600_ledger_journal.sql") < numeric.index("1008_outbox_backoff.sql")
    assert lexicographic.index("1008_outbox_backoff.sql") < lexicographic.index(
        "600_ledger_journal.sql")
    assert numeric.index("1008_outbox_backoff.sql") < numeric.index("1400_audit_log.sql")
    assert [path.name for path in m16_migration_files()] == [
        "1400_audit_log.sql", "1401_audit_anchors.sql", "1402_m16_outbox.sql",
        "1403_audit_chain_guards.sql"]


# --------------------------------------------------------------------------- 重复执行（幂等）
def test_m16_migrations_are_repeatable(migrated: str):
    """单文件重复执行幂等：在已迁移 schema 上再跑一遍 1400–1403 仍是 exit 0。

    （共享 schema 上跑，省掉一次 20s 的全量迁移；DDL 全为 IF NOT EXISTS / OR REPLACE。）
    """
    result = run_migrations(m16_migration_files(), migrated)
    assert result.returncode == 0, result.stderr
    again = run_migrations(m16_migration_files(), migrated)
    assert again.returncode == 0, again.stderr


# --------------------------------------------------------------------------- 结构（索引 / 函数 / 触发器）
def test_required_indexes_exist(migrated: str):
    indexes = index_names(migrated)
    for name in ("audit_log_entry_id_uq", "audit_log_hash_uq", "audit_log_idempotency_uq",
                 "audit_log_action_target_ts_idx", "audit_anchors_period_uq",
                 "m16_outbox_idempotency_uq"):
        assert name in indexes, name


def test_required_functions_and_triggers_exist(migrated: str):
    functions = function_names(migrated)
    for name in ("m16_audit_forbid_mutation", "m16_forbid_truncate", "m16_outbox_guard",
                 "m16_audit_chain_guard", "m16_outbox_audit_ref_guard"):
        assert name in functions, name
    triggers = trigger_names(migrated)
    for name in ("audit_log_no_mutation", "audit_log_no_truncate", "audit_log_chain_guard",
                 "audit_anchors_no_mutation", "audit_anchors_no_truncate", "m16_outbox_guard",
                 "m16_outbox_no_truncate", "m16_outbox_audit_ref_guard"):
        assert name in triggers, name


# --------------------------------------------------------------------------- 只追加护栏
def test_update_is_rejected(conn):
    insert_entry(conn)
    exc = assert_db_error(conn, "append-only",
                          lambda c: c.execute("UPDATE audit_log SET target = 'x' WHERE seq = 1"))
    assert exc.sqlstate == "42501"


def test_delete_is_rejected(conn):
    insert_entry(conn)
    exc = assert_db_error(conn, "append-only",
                          lambda c: c.execute("DELETE FROM audit_log WHERE seq = 1"))
    assert exc.sqlstate == "42501"


def test_truncate_is_rejected(conn):
    assert_db_error(conn, "append-only", lambda c: c.execute("TRUNCATE audit_log"))


def test_anchors_are_append_only(conn):
    conn.execute("""INSERT INTO audit_anchors (period, merkle_root, entry_count)
                    VALUES ('2026-10-23', %s, 0)""", (entry_hash("root"),))
    assert_db_error(conn, "append-only", lambda c: c.execute(
        "UPDATE audit_anchors SET merkle_root = 'x' WHERE period = '2026-10-23'"))
    assert_db_error(conn, "append-only", lambda c: c.execute(
        "DELETE FROM audit_anchors WHERE period = '2026-10-23'"))


# --------------------------------------------------------------------------- 约束
@pytest.mark.parametrize("overrides,match", [
    ({"alg": "sha256"}, "audit_log_alg_ck"),
    ({"status": "done"}, "audit_log_status_ck"),
    ({"actor_type": "robot"}, "audit_log_actor_type_ck"),
    ({"hash_value": "not-a-hash"}, "audit_log_hash_ck"),
    ({"hash_value": "A" * 64}, "audit_log_hash_ck"),
])
def test_check_constraints_reject_bad_rows(conn, overrides, match):
    assert_db_error(conn, match, lambda c: insert_entry(c, **overrides))


def test_prev_hash_shape_is_guarded_structurally(migrated: str):
    """prev_hash 的形状由链护栏先挡（必须等于上一条 hash），约束只做库层兜底 —— 这里验后者存在。"""
    with connect(migrated, autocommit=True) as connection:
        definition = scalar(connection,
                            """SELECT pg_get_constraintdef(oid) FROM pg_constraint
                                WHERE conname = 'audit_log_hash_ck'""")
    assert "prev_hash" in definition and "GENESIS" in definition


def test_unique_indexes(conn):
    insert_entry(conn, seq=1)
    head = entry_hash("seq-1")
    assert_db_error(conn, "audit_log_entry_id_uq", lambda c: insert_entry(
        c, seq=2, prev_hash=head, entry_id="018f4d0e-0000-7000-8000-000000000001"))
    assert_db_error(conn, "audit_log_hash_uq", lambda c: insert_entry(
        c, seq=2, prev_hash=head, hash_value=head))


def test_anchor_period_is_unique(conn):
    conn.execute("INSERT INTO audit_anchors (period, merkle_root) VALUES (%s, %s)",
                 ("2026-10-23", entry_hash("a")))
    assert_db_error(conn, "audit_anchors_period_uq", lambda c: c.execute(
        "INSERT INTO audit_anchors (period, merkle_root) VALUES (%s, %s)",
        ("2026-10-23", entry_hash("b"))))


# --------------------------------------------------------------------------- 链护栏
def test_chain_guard_requires_seq_one_and_genesis(conn):
    assert_db_error(conn, "first entry must be seq=1", lambda c: insert_entry(c, seq=2))
    assert_db_error(conn, "prev_hash must be GENESIS",
                    lambda c: insert_entry(c, seq=1, prev_hash=entry_hash("x")))


def test_chain_guard_requires_contiguous_seq_and_matching_prev_hash(conn):
    insert_entry(conn, seq=1)
    head = entry_hash("seq-1")
    assert_db_error(conn, "seq must continue at 2",
                    lambda c: insert_entry(c, seq=3, prev_hash=head))
    assert_db_error(conn, "prev_hash does not match",
                    lambda c: insert_entry(c, seq=2, prev_hash=entry_hash("other")))
    insert_entry(conn, seq=2, prev_hash=head)          # 正确的一条能进
    assert scalar(conn, "SELECT count(*) FROM audit_log") == 2


# --------------------------------------------------------------------------- outbox
def test_outbox_rejects_unknown_event_type(conn):
    insert_entry(conn)
    assert_db_error(conn, "m16_outbox_type_ck", lambda c: insert_outbox(
        c, aggregate_id="018f4d0e-0000-7000-8000-000000000001", type_="deploy.completed"))


def test_outbox_payload_must_carry_required_keys(conn):
    insert_entry(conn)
    assert_db_error(conn, "m16_outbox_payload_ck", lambda c: insert_outbox(
        c, aggregate_id="018f4d0e-0000-7000-8000-000000000001", payload={"audit_id": "x"}))


def test_outbox_must_reference_an_existing_entry(conn):
    assert_db_error(conn, "must reference an existing audit entry", lambda c: insert_outbox(
        c, aggregate_id="018f4d0e-0000-7000-8000-000000000099"))


def test_outbox_is_append_only(conn):
    insert_entry(conn)
    insert_outbox(conn, aggregate_id="018f4d0e-0000-7000-8000-000000000001")
    assert_db_error(conn, "immutable",
                    lambda c: c.execute("UPDATE m16_outbox SET trace_id = 'other'"))
    # 唯一允许的变化：published_at 置为投递完成时刻
    conn.execute("UPDATE m16_outbox SET published_at = now()")
    assert scalar(conn, "SELECT count(*) FROM m16_outbox WHERE published_at IS NOT NULL") == 1
    assert_db_error(conn, "append-only", lambda c: c.execute("DELETE FROM m16_outbox"))


# --------------------------------------------------------------------------- CLI（--status / --up-only）
def test_migrate_cli_status_and_up_only(migrated: str, capsys):
    """``python -m app.audit.migrate`` 的两条只读/幂等分支（--down 只在专用 schema 跑）。"""
    assert migrate.main(["--schema", migrated, "--status"]) == 0
    output = capsys.readouterr().out
    assert "audit_log" in output and "1400_audit_log.sql" in output

    assert migrate.main(["--schema", migrated, "--up-only"]) == 0
    output = capsys.readouterr().out
    assert "up   1400_audit_log.sql" in output


def test_migrate_dsn_requires_environment(monkeypatch):
    monkeypatch.delenv("DJB_DSN", raising=False)
    with pytest.raises(SystemExit):
        migrate.dsn()
    # main() 的 --up 分支依赖 dsn()；缺环境时必须显式失败，而不是猜一个库
    with pytest.raises(SystemExit):
        migrate.main(["--up"])


# --------------------------------------------------------------------------- 数据边界
def test_audit_tables_have_no_business_or_secret_columns(migrated: str):
    """审计表不得承载正文 / 金额 / 凭据（M16 §1「不做」/ INV-M16-10）。"""
    forbidden = {"prompt", "response", "prompt_text", "response_text", "card_number", "id_card",
                 "mnemonic", "private_key", "secret", "api_key", "amount_minor", "balance_minor"}
    for table in M16_TABLES:
        columns = set(column_names(migrated, table))
        assert columns & forbidden == set(), f"{table} 出现业务/凭据列：{columns & forbidden}"
    assert {"seq", "entry_id", "ts", "actor", "actor_type", "role", "action", "target",
            "before", "after", "reason_code", "ticket", "evidence", "approval_chain", "status",
            "alg", "prev_hash", "hash"} <= set(column_names(migrated, "audit_log"))


def test_audit_log_columns_are_text_for_hashes(migrated: str):
    with connect(migrated, autocommit=True) as connection:
        for column in ("hash", "prev_hash"):
            assert scalar(
                connection,
                """SELECT data_type FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name = 'audit_log'
                      AND column_name = %s""", (column,)) == "text"
    assert HASH_PATTERN.match(entry_hash("anything"))


def test_jsonb_columns_are_jsonb(migrated: str):
    with connect(migrated, autocommit=True) as connection:
        for column in ("before", "after", "approval_chain"):
            assert scalar(
                connection,
                """SELECT data_type FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name = 'audit_log'
                      AND column_name = %s""", (column,)) == "jsonb"
