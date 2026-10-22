# SPDX-License-Identifier: Apache-2.0
"""迁移验收（T2）：空库 001–1004 / 升级（只加不改）/ 回滚（可重复）/ 单文件重复执行幂等。

三跑语义与 M01/M06 同款：
* 空库：全新 schema 顺序跑 ``migrations/*.sql``（与 CI 一致）；
* 升级：先跑 001–604，再只跑 1000–1004；存量 19 个迁移的表结构指纹逐项不变；
* 回滚：``migrate.down()`` 逆序删本模块对象，存量表零改动，可重复执行，回滚后能再升级。
"""
from __future__ import annotations

import pytest

from configkit import (
    BASE_TABLES,
    M10_FUNCTIONS,
    M10_MIGRATIONS,
    M10_TABLES,
    apply_migrations,
    base_migration_files,
    fingerprint,
    function_names,
    m10_migration_files,
    migration_files,
    run_migration,
    table_names,
)

from app.config_center import migrate


def test_empty_database_applies_001_to_1004(schema: str) -> None:
    outputs = apply_migrations(schema)
    assert [item["name"] for item in outputs] == [path.name for path in migration_files()]
    assert [item["name"] for item in outputs][-7:] == list(M10_MIGRATIONS)
    assert all(item["rc"] == 0 for item in outputs), [o for o in outputs if o["rc"]]

    tables = table_names(schema)
    for name in M10_TABLES:
        assert name in tables, f"缺表 {name}"
    # 存量表仍在（不重建、不改名）
    assert {"journal_entry", "ledger_entry", "user_accounts", "api_keys"} <= tables

    functions = function_names(schema)
    for name in M10_FUNCTIONS:
        assert name in functions, f"缺函数 {name}"


def test_empty_database_applies_in_glob_order_too(schema: str) -> None:
    """CI 的 ``for f in migrations/*.sql`` 是字典序（1000 会排在 100/600 之前）。

    M10 迁移不依赖 M01/M06 的表，所以两种顺序都必须 rc=0——这里显式验证，避免下一位
    接线人误以为「必须先跑 600 再跑 1000」。
    """
    outputs = apply_migrations(schema, files=migration_files(order="lexicographic"))
    assert all(item["rc"] == 0 for item in outputs)
    assert set(M10_TABLES) <= table_names(schema)


def test_module_migrations_are_the_seven_expected_files() -> None:
    assert migrate.MODULE_MIGRATIONS == M10_MIGRATIONS
    assert [path.name for path in m10_migration_files()] == list(M10_MIGRATIONS)
    assert len(migrate.BASE_MIGRATIONS) == 19
    assert [path.name for path in base_migration_files()] == list(migrate.BASE_MIGRATIONS)


def test_single_file_rerun_is_idempotent(schema: str) -> None:
    apply_migrations(schema)
    before = fingerprint(schema)
    for _ in range(2):
        for path in m10_migration_files():
            result = run_migration(path, schema)
            assert result.returncode == 0, f"{path.name} 重跑失败：{result.stderr}\n{result.stdout}"
    after = fingerprint(schema)
    assert after == before, {
        key: (set(before[key]) ^ set(after[key])) for key in before if before[key] != after[key]
    }


def test_upgrade_adds_module_tables_without_touching_base(schema: str) -> None:
    apply_migrations(schema, files=base_migration_files())
    base_tables = table_names(schema)
    assert not set(M10_TABLES) & base_tables
    before = fingerprint(schema, tables=BASE_TABLES)

    apply_migrations(schema, files=m10_migration_files())
    after = fingerprint(schema, tables=BASE_TABLES)
    assert after == before, {
        key: (set(before[key]) ^ set(after[key])) for key in before if before[key] != after[key]
    }
    assert set(M10_TABLES) <= table_names(schema)


def test_down_rolls_back_only_module_objects_and_is_repeatable(schema: str) -> None:
    apply_migrations(schema)
    base_before = fingerprint(schema, tables=BASE_TABLES)

    with migrate.connect(schema) as conn:
        assert migrate.down(conn) == [name for name, _ in migrate.DOWN_SQL]
        assert migrate.down(conn) == [name for name, _ in migrate.DOWN_SQL]   # 可重复执行

    tables = table_names(schema)
    assert not set(M10_TABLES) & tables
    assert {"journal_entry", "ledger_entry", "user_accounts", "api_keys"} <= tables
    assert not set(M10_FUNCTIONS) & function_names(schema)
    assert fingerprint(schema, tables=BASE_TABLES) == base_before

    # 回滚后能再升级（演练路径）
    apply_migrations(schema, files=m10_migration_files())
    assert set(M10_TABLES) <= table_names(schema)


def test_status_lists_module_objects(schema: str) -> None:
    apply_migrations(schema)
    with migrate.connect(schema) as conn:
        info = migrate.status(conn)
    for name in M10_TABLES:
        assert name in info["tables"]
    assert set(M10_FUNCTIONS) <= set(info["functions"])


def test_constraints_and_indexes_exist(schema: str) -> None:
    apply_migrations(schema)
    fp = fingerprint(schema, tables=M10_TABLES)
    constraints = "\n".join(fp["constraints"])
    indexes = "\n".join(fp["indexes"])
    triggers = "\n".join(fp["triggers"])

    # §5 的唯一约束与索引
    assert "config_items_pk" in constraints
    assert "config_versions_key_scope_version_uq" in constraints
    assert "config_versions_idem_uq" in indexes
    assert "config_versions_one_active_uq" in indexes
    assert "config_publish_requests_status_idx" in indexes
    assert "config_drifts_detected_idx" in indexes
    assert "config_publish_requests_inflight_uq" in indexes   # INV-07
    assert "config_outbox_pending_idx" in indexes
    # 只追加 / 状态机 / 敏感值护栏都在
    assert "config_items_guard" in triggers
    assert "config_versions_guard" in triggers
    assert "config_versions_monotonic" in triggers
    assert "config_versions_secret" in triggers
    assert "config_snapshots_no_mutation" in triggers
    assert "config_drifts_guard" in triggers
    assert "config_outbox_no_mutation" in triggers
    assert "config_publish_requests_guard" in triggers
    # INV-08：policy_version 是生成列（information_schema 里 is_generated = ALWAYS）
    policy_columns = [line for line in fp["columns"]
                      if line.startswith("config_snapshots.policy_version:")]
    assert policy_columns, "缺 config_snapshots.policy_version"
    assert policy_columns[0].endswith(":ALWAYS")


def test_cli_up_status_down_roundtrip(schema: str, capsys) -> None:
    """迁移执行器 CLI（T3/T4 演练会用）：up → status → down → up-only。"""
    assert migrate.main(["--schema", schema, "--up"]) == 0
    out = capsys.readouterr().out
    assert "up   1000_config_items.sql" in out and "up   001_init.sql" in out

    assert migrate.main(["--schema", schema, "--status"]) == 0
    status_out = capsys.readouterr().out
    assert "config_versions" in status_out and "m10_versions_guard" in status_out

    assert migrate.main(["--schema", schema, "--down"]) == 0
    down_out = capsys.readouterr().out
    assert "down 1004_config_drifts.sql" in down_out
    assert not set(M10_TABLES) & table_names(schema)

    assert migrate.main(["--schema", schema, "--up-only"]) == 0
    assert "up   1000_config_items.sql" in capsys.readouterr().out
    assert set(M10_TABLES) <= table_names(schema)


def test_cli_requires_dsn(monkeypatch) -> None:
    monkeypatch.delenv("DJB_DSN", raising=False)
    with pytest.raises(SystemExit):
        migrate.dsn()


def test_migration_number_segment() -> None:
    for name in M10_MIGRATIONS:
        number = int(name.split("_", 1)[0])
        assert 1000 <= number <= 1099, name
    assert [int(name.split("_", 1)[0]) for name in M10_MIGRATIONS] == list(range(1000, 1007))
