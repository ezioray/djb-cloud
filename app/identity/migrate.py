# SPDX-License-Identifier: Apache-2.0
"""M01 迁移执行器：1xx 正向升级 + 可执行回滚（DEV-M01-T1 验收 1「空库 + 升级 + 回滚」）。

为什么回滚 SQL 放在 Python 里而不是 ``migrations/1xx_*_down.sql``：
CI 的执行方式是 ``for f in migrations/*.sql``（见 .github/workflows/ci.yml），
放在 ``migrations/`` 下的任何 ``*.sql`` 都会被当成**正向迁移**执行。
因此回滚 DDL 由本模块持有，正向文件末尾用注释保留同等人可读版本。

用法（工作树 PYTHONPATH + 独立 schema）::

    python -m app.identity.migrate --schema m01_t1_x --up
    python -m app.identity.migrate --schema m01_t1_x --down
    python -m app.identity.migrate --schema m01_t1_x --status

``--up`` 会先应用存量基线 001/002（api_keys 原型由 002 建立，1xx 在其上只加列）。
1xx 段：100–104（T1 模型）+ 105（T2 会话令牌 / MFA 因子 / 扫码票据 / 幂等键）
        + 106（T3 Key 生命周期的 scopes / expires_at）。
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

import psycopg

MODULE_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = MODULE_DIR.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

# 一次正向迁移只属于一个模块（00-conventions §7.1）：M01 段 = 1xx
BASE_MIGRATIONS = ("001_init.sql", "002_api_keys.sql")
MODULE_MIGRATIONS = tuple(sorted(p.name for p in MIGRATIONS_DIR.glob("1*.sql")))

# 回滚：逆序删除本模块新增对象；**存量对象只删新增列**，不删表、不改类型（00-conventions §7.2）
DOWN_SQL: tuple[tuple[str, str], ...] = (
    ("106_identity_api_keys_lifecycle.sql", """
        DROP INDEX IF EXISTS api_keys_expiry_idx;
        DROP INDEX IF EXISTS api_keys_revoked_after_idx;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_scopes_chk;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_expires_chk;
        ALTER TABLE IF EXISTS api_keys DROP COLUMN IF EXISTS scopes;
        ALTER TABLE IF EXISTS api_keys DROP COLUMN IF EXISTS expires_at;
    """),
    ("105_identity_auth.sql", """
        DROP TABLE IF EXISTS identity_idempotency;
        DROP TABLE IF EXISTS identity_scan_tickets;
        ALTER TABLE IF EXISTS users DROP CONSTRAINT IF EXISTS users_mfa_factor_chk;
        ALTER TABLE IF EXISTS users DROP CONSTRAINT IF EXISTS users_password_shape_chk;
        ALTER TABLE IF EXISTS users DROP CONSTRAINT IF EXISTS users_login_lock_chk;
        ALTER TABLE IF EXISTS users DROP COLUMN IF EXISTS password_hash;
        ALTER TABLE IF EXISTS users DROP COLUMN IF EXISTS password_updated_at;
        ALTER TABLE IF EXISTS users DROP COLUMN IF EXISTS mfa_secret_hash;
        ALTER TABLE IF EXISTS users DROP COLUMN IF EXISTS mfa_salt;
        ALTER TABLE IF EXISTS users DROP COLUMN IF EXISTS mfa_enabled_at;
        ALTER TABLE IF EXISTS users DROP COLUMN IF EXISTS failed_login_count;
        ALTER TABLE IF EXISTS users DROP COLUMN IF EXISTS login_locked_until;
        ALTER TABLE IF EXISTS users DROP COLUMN IF EXISTS last_login_at;
        DROP INDEX IF EXISTS sessions_access_uq;
        DROP INDEX IF EXISTS sessions_refresh_uq;
        ALTER TABLE IF EXISTS sessions DROP CONSTRAINT IF EXISTS sessions_token_hash_chk;
        ALTER TABLE IF EXISTS sessions DROP CONSTRAINT IF EXISTS sessions_absolute_chk;
        -- kind 收回两值：用 NOT VALID 保留存量行（回退应用后不会再有新 kind）
        ALTER TABLE IF EXISTS sessions DROP CONSTRAINT IF EXISTS sessions_kind_chk;
        ALTER TABLE IF EXISTS sessions ADD CONSTRAINT sessions_kind_chk
          CHECK (kind IN ('user', 'admin')) NOT VALID;
        ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS access_hash;
        ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS refresh_hash;
        ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS absolute_expires_at;
        ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS rotated_at;
        ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS idle_expires_at;
        ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS step_up_until;
        ALTER TABLE IF EXISTS sessions DROP COLUMN IF EXISTS client_ip_hash;
    """),
    ("104_identity_outbox.sql", """
        DROP TABLE IF EXISTS identity_outbox;
    """),
    ("103_identity_quotas.sql", """
        DROP TABLE IF EXISTS tenant_quotas;
    """),
    ("102_identity_sessions_roles.sql", """
        DROP TABLE IF EXISTS role_bindings;
        DROP TABLE IF EXISTS sessions;
        DROP FUNCTION IF EXISTS role_bindings_svc_guard();
    """),
    ("101_identity_api_keys.sql", """
        DROP VIEW IF EXISTS v_identity_api_keys;
        DROP INDEX IF EXISTS api_keys_account_live_idx;
        DROP INDEX IF EXISTS api_keys_tenant_idx;
        DROP INDEX IF EXISTS api_keys_id_tenant_uq;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_account_tenant_fk;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_rotated_from_fk;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_qps_chk;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_daily_usd_chk;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_hash_shape_chk;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_prefix_shape_chk;
        ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_revoke_chk;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS account_id;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS tenant_id;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS qps;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS daily_usd_minor;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS label;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS rotated_from;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS last_used_at;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS created_by;
        ALTER TABLE api_keys DROP COLUMN IF EXISTS revoked_reason;
    """),
    ("100_identity_core.sql", """
        DROP VIEW IF EXISTS v_identity_accounts;
        DROP TABLE IF EXISTS org_members;
        ALTER TABLE IF EXISTS orgs DROP CONSTRAINT IF EXISTS orgs_owner_account_fk;
        -- CASCADE：连带清掉仍指向 user_accounts 的约束（orgs.owner_account_id 等）
        DROP TABLE IF EXISTS user_accounts CASCADE;
        DROP TABLE IF EXISTS orgs;
        DROP TABLE IF EXISTS users;
        DROP FUNCTION IF EXISTS identity_touch_updated_at();
    """),
)


def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库）")
    return value


def connect(schema: str | None = None) -> psycopg.Connection:
    """连接开发库；``schema`` 给定时把 search_path 固定到该 schema（测试 / 演练用）。"""
    options = f"-c search_path={schema}" if schema else None
    return psycopg.connect(dsn(), autocommit=True, options=options)


def _apply(conn: psycopg.Connection, files, *, direction: str) -> list[str]:
    applied: list[str] = []
    for name in files:
        if direction == "up":
            sql = (MIGRATIONS_DIR / name).read_text(encoding="utf-8")
        else:
            sql = dict(DOWN_SQL)[name]
        conn.execute(sql)
        applied.append(name)
    return applied


def up(conn: psycopg.Connection, *, with_base: bool = True) -> list[str]:
    """正向升级：001/002（基线）+ 1xx（本模块）。可重复执行（全部 IF NOT EXISTS / 幂等）。"""
    applied: list[str] = []
    if with_base:
        applied += _apply(conn, BASE_MIGRATIONS, direction="up")
    applied += _apply(conn, MODULE_MIGRATIONS, direction="up")
    return applied


def down(conn: psycopg.Connection) -> list[str]:
    """回滚：逆序删除 1xx 新增对象；存量 api_keys 只删新增列。"""
    return _apply(conn, [name for name, _ in DOWN_SQL], direction="down")


def status(conn: psycopg.Connection) -> dict[str, list[str]]:
    """区分「本模块对象」与「存量对象」，供证据文件引用。"""
    tables = [r[0] for r in conn.execute(
        """SELECT table_name FROM information_schema.tables
            WHERE table_schema = current_schema() ORDER BY 1""").fetchall()]
    views = [r[0] for r in conn.execute(
        """SELECT table_name FROM information_schema.views
            WHERE table_schema = current_schema() ORDER BY 1""").fetchall()]
    columns = [r[0] for r in conn.execute(
        """SELECT column_name FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'api_keys'
            ORDER BY ordinal_position""").fetchall()]
    return {"tables": tables, "views": views, "api_keys_columns": columns}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M01 identity 迁移（up / down / status）")
    parser.add_argument("--schema", default=None, help="目标 schema（缺省用连接默认）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--up", action="store_true", help="正向升级（含 001/002 基线）")
    group.add_argument("--down", action="store_true", help="回滚 1xx 新增对象")
    group.add_argument("--status", action="store_true", help="列出当前 schema 的表 / 视图 / 列")
    args = parser.parse_args(argv)

    with connect(args.schema) as conn:
        if args.up:
            for name in up(conn):
                print(f"up   {name}")
        elif args.down:
            for name in down(conn):
                print(f"down {name}")
        print(conn.execute("SELECT current_schema()").fetchone()[0])
        for key, values in status(conn).items():
            print(f"{key}: {values}")
    return 0


if __name__ == "__main__":                                   # pragma: no cover - CLI
    sys.exit(main())
