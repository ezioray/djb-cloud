# SPDX-License-Identifier: AGPL-3.0-or-later
"""迁移验收（DEV-M01-T1 验收 1）：空库 / 升级 / 回滚三跑 + 对象与约束清单。

三跑的语义：
- **空库**：全新 schema 里按文件名顺序跑 ``migrations/*.sql``（与 CI 的
  ``for f in migrations/*.sql`` 一致），证明 M01 段与存量段能共处。
- **升级**：存量 schema（只有 001/002 与老式三列 Key）上跑 1xx，证明「只加不改」——
  老数据不丢、老写法仍能插入、新列对老行为默认空。
- **回滚**：``migrate.down()`` 逆序删本模块新增对象；存量 api_keys 只删新增列与约束，
  老数据与老列原样保留，且可重复执行。
"""
from __future__ import annotations

import uuid

import psycopg
import pytest

from app.identity import migrate

from identitykit import (
    IDENTITY_TABLES,
    MIGRATIONS_DIR,
    apply_files,
    rows,
    scalar,
    scratch_schema,
)

ALL_MIGRATIONS = sorted(p.name for p in MIGRATIONS_DIR.glob("*.sql"))


# --------------------------------------------------------------------------- 空库
def test_empty_db_applies_every_migration(db, schema_name):
    with scratch_schema(schema_name, "empty") as (conn, name):
        apply_files(conn, ALL_MIGRATIONS)              # 与 CI 的 for f in migrations/*.sql 等价

        tables = {r["table_name"] for r in rows(
            conn, "SELECT table_name FROM information_schema.tables"
                  " WHERE table_schema = current_schema()")}
        views = {r["table_name"] for r in rows(
            conn, "SELECT table_name FROM information_schema.views"
                  " WHERE table_schema = current_schema()")}

        # 8 张身份表 + 本模块自有 outbox（01-ownership §2）
        assert set(IDENTITY_TABLES) <= tables
        assert {"v_identity_accounts", "v_identity_api_keys"} <= views
        # 只建一套：不存在第二套后台用户表
        assert not {t for t in tables if t.startswith(("admin_user", "backstage", "console_user"))}
        print(f"[empty-db] schema={name} tables={len(tables)} views={len(views)}")


def test_module_migrations_are_in_the_1xx_segment():
    # 00-conventions §7.1：一个迁移只属于一个模块。M01 段 = 100–199；
    # 文件名以 "1" 开头不等于 1xx（1000_config_* / 1100_risk_* / 13xx / 14xx 都是别的模块）。
    def _segment(name: str) -> int:
        head = name.split("_", 1)[0]
        return int(head) if head.isdigit() else -1

    files = sorted(p.name for p in MIGRATIONS_DIR.glob("*.sql")
                   if 100 <= _segment(p.name) <= 199)
    assert files == list(migrate.MODULE_MIGRATIONS)
    for name in files:
        assert name[:3].isdigit() and name[0] == "1", f"{name} 不在 M01 的 1xx 段"
        assert 100 <= int(name[:3]) <= 199, f"{name} 不在 100–199"


def test_up_is_idempotent(conn):
    """重复执行不报错（CI 与本地演练会重复跑）。"""
    assert migrate.up(conn) == list(migrate.BASE_MIGRATIONS) + list(migrate.MODULE_MIGRATIONS)
    migrate.up(conn)                       # 第二次
    migrate.up(conn)                       # 第三次
    assert scalar(conn, "SELECT count(*) FROM information_schema.tables"
                        " WHERE table_schema = current_schema() AND table_name = 'identity_outbox'") == 1


# --------------------------------------------------------------------------- 升级
def test_upgrade_preserves_legacy_data(db, schema_name):
    """存量 001/002 + 老式三列 Key → 跑 1xx：数据不丢、老写法仍可插入。"""
    with scratch_schema(schema_name, "upgrade") as (conn, _name):
        apply_files(conn, migrate.BASE_MIGRATIONS)
        legacy_hash = "a" * 64
        conn.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s, %s, %s)",
                     ("user:legacy", "legacyab", legacy_hash))

        migrate.up(conn, with_base=False)

        legacy = rows(conn, "SELECT * FROM api_keys WHERE key_hash = %s", (legacy_hash,))
        assert len(legacy) == 1
        assert legacy[0]["account_id"] is None and legacy[0]["tenant_id"] is None
        # 老写法（不带新列）仍然可用：不破坏 app/api.py、scripts/mint_key.py 与既有测试
        conn.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s, %s, %s)",
                     ("user:legacy2", "legacycd", "b" * 64))
        assert scalar(conn, "SELECT count(*) FROM api_keys") == 2
        # 新列存在且可写入
        cols = {r["column_name"] for r in rows(
            conn, "SELECT column_name FROM information_schema.columns"
                  " WHERE table_schema = current_schema() AND table_name = 'api_keys'")}
        assert {"account_id", "tenant_id", "qps", "daily_usd_minor", "rotated_from",
                "revoked_reason"} <= cols


# --------------------------------------------------------------------------- 回滚
def test_rollback_removes_only_new_objects(db, schema_name):
    with scratch_schema(schema_name, "rollback") as (conn, _name):
        migrate.up(conn)
        # 造一条 1xx 之后的数据 + 一条老式 Key
        user_id = uuid.uuid4()
        account_id = uuid.uuid4()
        conn.execute("INSERT INTO users (id, email_hash) VALUES (%s, %s)", (user_id, "c" * 64))
        conn.execute("""INSERT INTO user_accounts (id, user_id, type, state, tenant_id)
                        VALUES (%s, %s, 'personal', 'normal', %s)""",
                     (account_id, user_id, account_id))
        conn.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s, %s, %s)",
                     ("user:legacy", "legacyab", "d" * 64))

        assert migrate.down(conn) == [name for name, _ in migrate.DOWN_SQL]

        tables = {r["table_name"] for r in rows(
            conn, "SELECT table_name FROM information_schema.tables"
                  " WHERE table_schema = current_schema()")}
        for name in ("users", "user_accounts", "orgs", "org_members", "sessions",
                     "role_bindings", "tenant_quotas", "identity_outbox"):
            assert name not in tables
        # 存量表与存量数据仍在，且回到三列形态
        cols = {r["column_name"] for r in rows(
            conn, "SELECT column_name FROM information_schema.columns"
                  " WHERE table_schema = current_schema() AND table_name = 'api_keys'")}
        assert cols == {"id", "user_id", "key_prefix", "key_hash", "created_at", "revoked_at"}
        assert scalar(conn, "SELECT count(*) FROM api_keys") == 1
        assert not rows(conn, "SELECT 1 FROM information_schema.views"
                              " WHERE table_schema = current_schema()")

        migrate.down(conn)                 # 可重复执行
        assert "api_keys" in {r["table_name"] for r in rows(
            conn, "SELECT table_name FROM information_schema.tables"
                  " WHERE table_schema = current_schema()")}


# --------------------------------------------------------------------------- 对象清单
def test_expected_constraints_and_indexes(conn):
    names = {r["conname"] for r in rows(
        conn, "SELECT conname FROM pg_constraint"
              " WHERE connamespace = current_schema()::regnamespace")}
    assert {
        "user_accounts_id_tenant_uq", "user_accounts_tenant_src_chk",
        "user_accounts_frozen_chk", "user_accounts_closing_chk",
        "org_members_account_fk", "orgs_owner_account_fk",
        "api_keys_account_tenant_fk", "api_keys_hash_shape_chk",
        "sessions_account_tenant_fk", "role_bindings_role_chk",
        "role_bindings_dual_control_chk", "tenant_quotas_kind_chk",
        "identity_outbox_type_chk",
    } <= names

    indexes = {r["indexname"] for r in rows(
        conn, "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")}
    assert {
        "users_email_hash_uq", "users_phone_hash_uq", "orgs_tenant_uq",
        "org_members_owner_uq", "sessions_account_epoch_idx",
        "role_bindings_live_uq", "tenant_quotas_tenant_uq", "tenant_quotas_key_uq",
        "identity_outbox_unpublished_idx",
    } <= indexes


def test_only_owner_module_tables_are_new(conn):
    """不建第二套后台用户表：身份侧只有 users（登录身份）与 user_accounts（账户）。"""
    tables = {r["table_name"] for r in rows(
        conn, "SELECT table_name FROM information_schema.tables"
              " WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'")}
    assert "users" in tables and "user_accounts" in tables
    assert not any(t in tables for t in ("admin_users", "backstage_users", "user", "accounts_v2"))


def test_outbox_rejects_unregistered_event_type(conn):
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("""INSERT INTO identity_outbox
                            (event_id, type, aggregate_type, aggregate_id, trace_id,
                             idempotency_key, payload)
                        VALUES (gen_random_uuid(), 'account.exploded', 'account', 'x', 't',
                                'k1', '{}'::jsonb)""")


# --------------------------------------------------------------------------- 命令行
def test_cli_up_status_down(db, schema_name, capsys):
    """``python -m app.identity.migrate`` 三档都要能跑（证据文件里的迁移输出就靠它）。"""
    with scratch_schema(schema_name, "cli") as (_conn, name):
        assert migrate.main(["--schema", name, "--up"]) == 0
        up_out = capsys.readouterr().out
        assert "up   100_identity_core.sql" in up_out and "identity_outbox" in up_out

        assert migrate.main(["--schema", name, "--status"]) == 0
        status_out = capsys.readouterr().out
        assert "tenant_quotas" in status_out and "api_keys_columns" in status_out

        assert migrate.main(["--schema", name, "--down"]) == 0
        down_out = capsys.readouterr().out
        assert "down 100_identity_core.sql" in down_out
        # 回滚后只剩存量表
        assert "'api_keys'" in down_out and "'user_accounts'" not in down_out


def test_cli_requires_dsn(monkeypatch):
    monkeypatch.delenv("DJB_DSN", raising=False)
    with pytest.raises(SystemExit):
        migrate.dsn()
