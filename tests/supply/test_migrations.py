# SPDX-License-Identifier: AGPL-3.0-or-later
"""迁移验收：空库 001–299（数字序 / 字典序）/ 升级（只加不改）/ 回滚（可重复）/ 约束与触发器。

三跑语义与 M01 / M06 / M10 同款：

* 空库：全新 schema 顺序跑 ``migrations/*.sql``（与 CI 一致，含 ``sort -V``）；
* 升级：先跑基线（不含 2xx），种一条**存量节点**，再只跑 200–207；
  存量列结构指纹逐项不变、存量数据不丢，``lifecycle_state`` 生成列与 ``state`` 同步；
* 回滚：``migrate.down()`` 逆序删本模块对象，存量表零改动、可重复执行、回滚后能再升级。
"""
from __future__ import annotations

import pytest

from supplykit import (
    BASE_TABLES,
    M02_FUNCTIONS,
    M02_MIGRATIONS,
    M02_TABLES,
    apply_migrations,
    base_migration_files,
    column_names,
    fingerprint,
    function_names,
    m02_migration_files,
    migration_files,
    run_migration,
    table_names,
)

from app.supply import migrate

LEGACY_NODE_COLUMNS = (
    "id", "platform", "hardware_fingerprint", "client_version", "protocol_version",
    "state", "key_prefix", "key_hash", "created_at", "last_seen_at",
)


# --------------------------------------------------------------------------- 空库
def test_empty_database_applies_001_to_299_in_numeric_order(schema: str) -> None:
    outputs = apply_migrations(schema)
    assert [item["name"] for item in outputs] == [path.name for path in migration_files()]
    assert [item["name"] for item in outputs
            if item["name"].startswith("2")][:len(M02_MIGRATIONS)] == list(M02_MIGRATIONS)
    assert all(item["rc"] == 0 for item in outputs)

    tables = table_names(schema)
    for name in M02_TABLES:
        assert name in tables, f"缺表 {name}"
    # 存量表仍在（不重建、不改名；视图另计）
    assert set(BASE_TABLES) - {"v_identity_accounts"} <= tables

    functions = function_names(schema)
    for name in M02_FUNCTIONS:
        assert name in functions, f"缺函数 {name}"


def test_empty_database_applies_in_glob_order_too(schema: str) -> None:
    """CI 用 ``sort -V``，但字典序（1000 会排在 200 之后）也必须能跑。

    M02 迁移只依赖 003 的 ``nodes``，所以两种顺序都必须 rc=0——这里显式钉住，
    避免下一位接线人误以为「必须先跑 100 再跑 200」。
    """
    outputs = apply_migrations(schema, files=migration_files(order="lexicographic"))
    assert all(item["rc"] == 0 for item in outputs)
    assert set(M02_TABLES) <= table_names(schema)


def test_module_migrations_are_the_expected_files() -> None:
    assert migrate.MODULE_MIGRATIONS == M02_MIGRATIONS
    assert list(M02_MIGRATIONS) == sorted(M02_MIGRATIONS, key=lambda n: int(n.split("_")[0]))


def test_each_migration_is_idempotent_on_rerun(schema: str) -> None:
    """单文件重复执行幂等（``IF NOT EXISTS`` / ``DO $$`` 守卫）。"""
    apply_migrations(schema)
    for path in m02_migration_files():
        result = run_migration(path, schema)
        assert result.returncode == 0, f"{path.name} 重跑失败：{result.stderr}"


# --------------------------------------------------------------------------- 升级（只加不改）
def test_upgrade_adds_columns_without_touching_legacy_ones(schema: str) -> None:
    apply_migrations(schema, files=base_migration_files())
    before_tables = table_names(schema)
    before = fingerprint(schema, tables=("nodes",))
    assert before["columns"], "基线 nodes 应有列定义"

    # 种一条「存量」节点（003 时代的写法，状态列直接 active）
    from supplykit import session

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_legacy', 'linux', %s, '0.9.0', '1.0.0', 'active', 'abcdefgh',
                       %s)""",
            ("fp-legacy-0001-aaaa", "0" * 64))

    for item in apply_migrations(schema, files=m02_migration_files()):
        assert item["rc"] == 0

    after = fingerprint(schema, tables=("nodes",))
    before_columns = {row.split(".")[1].split(":")[0]: row for row in before["columns"]}
    after_columns = {row.split(".")[1].split(":")[0]: row for row in after["columns"]}
    # 存量列定义逐字节不变（只加不改）
    for name in LEGACY_NODE_COLUMNS:
        assert name in after_columns, f"存量列丢失：{name}"
        assert after_columns[name] == before_columns[name], f"存量列被改：{name}"
    # 新增列都在，且 lifecycle_state 是生成列
    added = set(after_columns) - set(before_columns)
    assert {"lifecycle_state", "account_id", "policy_version", "bound_account_id"} <= added
    assert after_columns["lifecycle_state"].endswith(":ALWAYS"), after_columns["lifecycle_state"]
    # 存量表没被重建
    assert set(before_tables) <= table_names(schema)

    with session(schema) as conn:
        row = conn.execute(
            "SELECT state, lifecycle_state, policy_version, access_modes "
            "FROM nodes WHERE id = 'n_legacy'").fetchone()
    assert row[0] == "active"
    assert row[1] == "active"                  # 生成列与 state 同步
    assert row[2] == "0"                       # 默认策略版本：未下发
    assert row[3] == []


def test_upgrade_keeps_legacy_rows_and_adds_unique_fingerprint_index(schema: str) -> None:
    apply_migrations(schema, files=base_migration_files())
    from supplykit import session
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_legacy2', 'linux', %s, '0.9.0', '1.0.0', 'active', 'abcdefgh',
                       %s)""", ("fp-legacy-0002-aaaa", "1" * 64))
    apply_migrations(schema, files=m02_migration_files())

    import psycopg

    with pytest.raises(psycopg.errors.UniqueViolation):
        with session(schema) as conn:
            conn.execute(
                """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                      protocol_version, state, key_prefix, key_hash)
                   VALUES ('n_dup', 'linux', %s, '0.9.0', '1.0.0', 'pending', 'abcdefgh',
                           %s)""", ("fp-legacy-0002-aaaa", "2" * 64))


# --------------------------------------------------------------------------- 回滚
def test_rollback_removes_module_objects_and_keeps_baseline(schema: str) -> None:
    apply_migrations(schema)
    from supplykit import connect, session
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_keep', 'linux', %s, '1.0.0', '1.0.0', 'pending', 'abcdefgh',
                       %s)""", ("fp-keep-0001-aaaa", "3" * 64))

    conn = connect(schema, autocommit=False)
    try:
        results = migrate.down(conn)
    finally:
        conn.close()
    assert [item["rc"] for item in results] == [0] * len(M02_MIGRATIONS)

    tables = table_names(schema)
    for name in M02_TABLES:
        if name == "nodes":
            continue                                  # nodes 是存量表，不删
        assert name not in tables, f"回滚后仍存在：{name}"
    assert set(BASE_TABLES) - {"v_identity_accounts"} <= tables
    columns = column_names(schema, "nodes")
    assert set(LEGACY_NODE_COLUMNS) <= columns
    assert "lifecycle_state" not in columns
    assert "bound_account_id" not in columns
    assert not (set(M02_FUNCTIONS) & function_names(schema))

    with session(schema) as check:
        row = check.execute("SELECT state FROM nodes WHERE id = 'n_keep'").fetchone()
    assert row[0] == "pending"                       # 存量数据不丢

    # 可重复执行
    conn = connect(schema, autocommit=False)
    try:
        again = migrate.down(conn)
    finally:
        conn.close()
    assert [item["rc"] for item in again] == [0] * len(M02_MIGRATIONS)

    # 回滚后能再升级
    for item in apply_migrations(schema, files=m02_migration_files()):
        assert item["rc"] == 0
    assert "lifecycle_state" in column_names(schema, "nodes")


def test_status_reports_missing_then_applied(schema: str) -> None:
    from supplykit import connect

    conn = connect(schema, autocommit=False)
    try:
        assert all(item["applied"] is False for item in migrate.status(conn))
    finally:
        conn.close()
    apply_migrations(schema)
    conn = connect(schema, autocommit=False)
    try:
        assert all(item["applied"] is True for item in migrate.status(conn))
    finally:
        conn.close()


# --------------------------------------------------------------------------- 约束与触发器
def _node_row(**overrides):
    row = {"id": "n_x", "platform": "linux", "hardware_fingerprint": "fp-x",
           "client_version": "1.0.0", "protocol_version": "1.0.0", "state": "pending",
           "key_prefix": "abcdefgh", "key_hash": "a" * 64}
    row.update(overrides)
    return row


def test_nodes_constraints_reject_bad_values(schema: str) -> None:
    import psycopg

    apply_migrations(schema)
    from supplykit import session

    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:
            conn.execute(
                """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                      protocol_version, state, key_prefix, key_hash, access_modes)
                   VALUES ('n_bad', 'linux', 'fp-bad', '1.0.0', '1.0.0', 'pending',
                           'abcdefgh', %s, '{Z9}')""", ("b" * 64,))

    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:
            conn.execute(
                """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                      protocol_version, state, key_prefix, key_hash,
                                      bound_account_id)
                   VALUES ('n_bad2', 'linux', 'fp-bad2', '1.0.0', '1.0.0', 'pending',
                           'abcdefgh', %s, gen_random_uuid())""", ("c" * 64,))

    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:            # retired 必须有 retired_at
            conn.execute(
                """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                      protocol_version, state, key_prefix, key_hash)
                   VALUES ('n_retired', 'linux', 'fp-ret', '1.0.0', '1.0.0', 'retired',
                           'abcdefgh', %s)""", ("d" * 64,))


def test_lifecycle_state_is_generated_and_read_only(schema: str) -> None:
    import psycopg

    apply_migrations(schema)
    from supplykit import session

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_gen', 'linux', 'fp-gen', '1.0.0', '1.0.0', 'pending',
                       'abcdefgh', %s)""", ("e" * 64,))
    with pytest.raises(psycopg.errors.Error) as excinfo:
        with session(schema) as conn:
            conn.execute("UPDATE nodes SET lifecycle_state = 'active' WHERE id = 'n_gen'")
    assert "generated" in str(excinfo.value).lower()


def test_node_events_is_append_only(schema: str) -> None:
    import psycopg

    apply_migrations(schema)
    from supplykit import session

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_ev', 'linux', 'fp-ev', '1.0.0', '1.0.0', 'pending', 'abcdefgh',
                       %s)""", ("f" * 64,))
        conn.execute(
            """INSERT INTO node_events (node_id, kind, from_state, to_state)
               VALUES ('n_ev', 'registered', NULL, 'pending')""")
    for statement in ("UPDATE node_events SET kind = 'tampered'",
                      "DELETE FROM node_events"):
        with pytest.raises(psycopg.errors.RaiseException):
            with session(schema) as conn:
                conn.execute(statement)


def test_node_policies_are_immutable_except_status_superseded(schema: str) -> None:
    import psycopg

    apply_migrations(schema)
    from supplykit import session

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO node_policies (policy_version, node_id, protocol_version,
                                          effective_at, digest, doc)
               VALUES ('1', NULL, '1.0.0', now(), %s,
                       '{"quotas": [], "directives": []}'::jsonb)""", ("1" * 64,))
    with session(schema) as conn:                 # 允许 active → superseded
        conn.execute("UPDATE node_policies SET status = 'superseded' WHERE policy_version = '1'")
    with pytest.raises(psycopg.errors.RaiseException):
        with session(schema) as conn:             # 内容不可改
            conn.execute(
                "UPDATE node_policies SET digest = %s WHERE policy_version = '1'", ("2" * 64,))
    with pytest.raises(psycopg.errors.RaiseException):
        with session(schema) as conn:
            conn.execute("DELETE FROM node_policies")


def test_capacity_announcements_are_append_only_and_seq_unique(schema: str) -> None:
    import psycopg

    apply_migrations(schema)
    from supplykit import session

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_cap', 'linux', 'fp-cap', '1.0.0', '1.0.0', 'active', 'abcdefgh',
                       %s)""", ("9" * 64,))
        conn.execute(
            """INSERT INTO capacity_announcements (node_id, seq, expires_at, capabilities)
               VALUES ('n_cap', 1, now() + interval '60 s', '[]'::jsonb)""")
    with pytest.raises(psycopg.errors.UniqueViolation):
        with session(schema) as conn:
            conn.execute(
                """INSERT INTO capacity_announcements (node_id, seq, expires_at)
                   VALUES ('n_cap', 1, now() + interval '60 s')""")
    with pytest.raises(psycopg.errors.RaiseException):
        with session(schema) as conn:
            conn.execute("UPDATE capacity_announcements SET seq = 2")


def test_supply_outbox_only_allows_publish_marker(schema: str) -> None:
    import psycopg

    apply_migrations(schema)
    from supplykit import session

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO supply_outbox (type, aggregate_id, trace_id, idempotency_key, payload)
               VALUES ('node.registered', 'n_out', 'trace', 'node.registered:n_out',
                       '{"node_id": "n_out", "account_id": null, "protocols": ["1.0.0"],
                         "region": null}'::jsonb)""")
    with session(schema) as conn:
        conn.execute("UPDATE supply_outbox SET published_at = now()")
    for statement in ("UPDATE supply_outbox SET payload = '{\"node_id\": \"x\"}'::jsonb",
                      "UPDATE supply_outbox SET published_at = NULL",
                      "DELETE FROM supply_outbox"):
        with pytest.raises(psycopg.errors.RaiseException):
            with session(schema) as conn:
                conn.execute(statement)

    # 缺业务键的事件写不进去（02-events §3 契约兜底）
    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:
            conn.execute(
                """INSERT INTO supply_outbox (type, aggregate_id, trace_id, idempotency_key,
                                              payload)
                   VALUES ('node.registered', 'n_out2', 'trace', 'k2',
                           '{"node_id": "n_out2"}'::jsonb)""")
    # 未登记的事件类型写不进去
    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:
            conn.execute(
                """INSERT INTO supply_outbox (type, aggregate_id, trace_id, idempotency_key,
                                              payload)
                   VALUES ('node.invented', 'n_out3', 'trace', 'k3', '{}'::jsonb)""")


def test_upstream_constraints_reject_userinfo_and_bad_models(schema: str) -> None:
    import psycopg

    apply_migrations(schema)
    from supplykit import session

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_up', 'linux', 'fp-up', '1.0.0', '1.0.0', 'active', 'abcdefgh',
                       %s)""", ("8" * 64,))
    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:          # userinfo 禁止（M02 §6.3）
            conn.execute(
                """INSERT INTO node_upstreams (node_id, access_type, base_url, models)
                   VALUES ('n_up', 'A1', 'https://user:pass@up.example/v1', '["m1"]')""")
    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:          # models 不能为空
            conn.execute(
                """INSERT INTO node_upstreams (node_id, access_type, base_url, models)
                   VALUES ('n_up', 'A1', 'https://up.example/v1', '[]')""")
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO node_upstreams (node_id, access_type, base_url, models,
                                           credential_handle)
               VALUES ('n_up', 'A2', 'http://127.0.0.1:8080/v1', '["m1"]',
                       'keychain:djb-upstream')""")
    with pytest.raises(psycopg.errors.UniqueViolation):
        with session(schema) as conn:          # 幂等键 (node, access_type, base_url)
            conn.execute(
                """INSERT INTO node_upstreams (node_id, access_type, base_url, models)
                   VALUES ('n_up', 'A2', 'http://127.0.0.1:8080/v1', '["m2"]')""")


def test_idempotency_and_binding_code_constraints(schema: str) -> None:
    import psycopg

    apply_migrations(schema)
    from supplykit import session

    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:          # TTL 必须为正
            conn.execute(
                """INSERT INTO supply_idempotency (scope, idem_key, request_hash, status_code,
                                                   response, expires_at)
                   VALUES ('POST /x', 'k', 'h', 200, '{}'::jsonb, now() - interval '1 s')""")
    with session(schema) as conn:
        conn.execute(
            """INSERT INTO supply_idempotency (scope, idem_key, request_hash, status_code,
                                               response, expires_at)
               VALUES ('POST /x', 'k', 'h', 200, '{}'::jsonb, now() + interval '24 h')""")
    with pytest.raises(psycopg.errors.UniqueViolation):
        with session(schema) as conn:
            conn.execute(
                """INSERT INTO supply_idempotency (scope, idem_key, request_hash, status_code,
                                                   response, expires_at)
                   VALUES ('POST /x', 'k', 'other', 200, '{}'::jsonb, now() + interval '24 h')""")

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_code', 'linux', 'fp-code', '1.0.0', '1.0.0', 'active', 'abcdefgh',
                       %s)""", ("7" * 64,))
    with pytest.raises(psycopg.errors.CheckViolation):
        with session(schema) as conn:          # 绑定码时效 ≤1 h
            conn.execute(
                """INSERT INTO node_binding_codes (node_id, account_id, code_hash, expires_at)
                   VALUES ('n_code', gen_random_uuid(), %s, now() + interval '2 h')""",
                ("5" * 64,))


def test_cli_three_runs_return_zero(schema: str, capsys) -> None:
    """CLI 三跑（--status / --up / --down / 再 --up）exit=0 —— 证据文件里同一条命令的冒烟。"""
    assert migrate.main(["--schema", schema, "--status"]) == 0
    assert migrate.main(["--schema", schema, "--up"]) == 0
    assert migrate.main(["--schema", schema, "--status"]) == 0
    out = capsys.readouterr().out
    assert "applied 207_supply_binding_codes.sql" in out

    assert migrate.main(["--schema", schema, "--down"]) == 0
    assert migrate.main(["--schema", schema, "--down"]) == 0        # 可重复
    assert migrate.main(["--schema", schema, "--up"]) == 0
    assert "up   200_supply_nodes.sql" in capsys.readouterr().out


def test_cli_requires_dsn(monkeypatch, capsys) -> None:
    monkeypatch.delenv("DJB_DSN", raising=False)
    assert migrate.main(["--schema", "m02_cli_noop", "--status"]) == 2
    assert "缺 DJB_DSN" in capsys.readouterr().err


def test_node_events_seq_is_monotonic(schema: str) -> None:
    """插入序单调：同毫秒 / 同 ts 的多条留痕也能稳定排序（node_events.seq）。"""
    apply_migrations(schema)
    from supplykit import session

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_seq', 'linux', 'fp-seq-0001-aaaa', '1.0.0', '1.0.0', 'pending',
                       'abcdefgh', %s)""", ("6" * 64,))
        for kind in ("registered", "re_registered", "key_rotated"):
            conn.execute("INSERT INTO node_events (node_id, kind) VALUES ('n_seq', %s)",
                         (kind,))
        rows = conn.execute("SELECT seq, kind FROM node_events WHERE node_id = 'n_seq' "
                            "ORDER BY seq").fetchall()
    assert [row[1] for row in rows] == ["registered", "re_registered", "key_rotated"]
    assert [row[0] for row in rows] == sorted(row[0] for row in rows)
