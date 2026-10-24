# SPDX-License-Identifier: AGPL-3.0-or-later
"""迁移验收：空库 001–499（数字序 / 字典序）/ 升级（只加不改）/ 回滚（可重复）/ 约束与触发器。

三跑语义与 M01 / M02 / M06 / M10 同款：

* **空库**：全新 schema 顺序跑 ``migrations/*.sql``（与 CI 一致，含 ``sort -V``）；
* **升级**：先跑基线（不含 4xx），种一条存量节点 + 存量报价簿以外的前置数据，
  再只跑 401–406；前置对象结构指纹逐项不变、存量数据不丢；
* **回滚**：``migrate.down()`` 逆序删本模块对象，前置对象零改动、可重复执行、回滚后能再升级。
"""
from __future__ import annotations

import pytest

from schedulingkit import (
    BASE_TABLES,
    M04_FUNCTIONS,
    M04_MIGRATIONS,
    M04_TABLES,
    SUPPLY_VIEWS,
    apply_migrations,
    base_migration_files,
    column_names,
    fingerprint,
    function_names,
    m04_migration_files,
    migration_files,
    prerequisite_files,
    run_migration,
    session,
    table_names,
    view_names,
)

from app.scheduling import migrate


# --------------------------------------------------------------------------- 空库
def test_empty_database_applies_001_to_499_in_numeric_order(schema: str) -> None:
    files = prerequisite_files(499)
    outputs = apply_migrations(schema, files=files)
    assert [item["name"] for item in outputs] == [path.name for path in files]
    assert all(item["rc"] == 0 for item in outputs)

    tables = table_names(schema)
    for name in M04_TABLES:
        assert name in tables, f"缺表 {name}"
    # 前置对象仍在（不重建、不改名）
    assert set(BASE_TABLES) <= tables
    assert set(SUPPLY_VIEWS) <= view_names(schema)

    functions = function_names(schema)
    for name in M04_FUNCTIONS:
        assert name in functions, f"缺函数 {name}"


def test_empty_database_applies_in_glob_order_too(schema: str) -> None:
    """CI 用 ``sort -V``，但字典序（1000 排在 100 之后）也必须能跑。

    M04 迁移只依赖 003 ``nodes`` 与 208 的视图，所以两种顺序都必须 rc=0。
    """
    outputs = apply_migrations(schema, files=migration_files(order="lexicographic"))
    assert all(item["rc"] == 0 for item in outputs)
    assert set(M04_TABLES) <= table_names(schema)


def test_module_migrations_are_the_expected_files() -> None:
    assert migrate.MODULE_MIGRATIONS == M04_MIGRATIONS
    assert list(M04_MIGRATIONS) == sorted(M04_MIGRATIONS, key=lambda n: int(n.split("_")[0]))
    assert migrate.PREREQUISITE_MIGRATIONS == tuple(
        path.name for path in prerequisite_files(499)
        if not path.name.startswith("4"))


def test_each_migration_is_idempotent_on_rerun(schema: str) -> None:
    """单文件重复执行幂等（``IF NOT EXISTS`` / ``DO $$`` 守卫）。"""
    apply_migrations(schema, files=prerequisite_files(499))
    for path in m04_migration_files():
        result = run_migration(path, schema)
        assert result.returncode == 0, f"{path.name} 重跑失败：{result.stderr}"


# --------------------------------------------------------------------------- 升级（只加不改）
def test_upgrade_leaves_upstream_objects_untouched(schema: str) -> None:
    apply_migrations(schema, files=base_migration_files())
    watched = ("nodes", "capacity_announcements", "user_accounts", "tenant_quotas")
    before = fingerprint(schema, tables=watched)
    assert before["columns"], "基线应有列定义"

    with session(schema) as conn:
        conn.execute(
            """INSERT INTO nodes (id, platform, hardware_fingerprint, client_version,
                                  protocol_version, state, key_prefix, key_hash)
               VALUES ('n_legacy', 'linux', 'fp-legacy-0001-aaaa', '0.9.0', '1.0.0', 'active',
                       'abcdefgh', %s)""", ("0" * 64,))

    for item in apply_migrations(schema, files=m04_migration_files()):
        assert item["rc"] == 0

    after = fingerprint(schema, tables=watched)
    for key in ("columns", "constraints", "indexes", "triggers"):
        assert after[key] == before[key], f"前置对象被改动：{key}"

    with session(schema) as conn:
        row = conn.execute("SELECT state, lifecycle_state FROM nodes WHERE id = 'n_legacy'").fetchone()
    assert row[0] == "active" and row[1] == "active"


# --------------------------------------------------------------------------- 回滚
def test_rollback_drops_only_m04_objects_and_is_repeatable(schema: str) -> None:
    apply_migrations(schema, files=prerequisite_files(499))
    upstream_before = fingerprint(schema, tables=("nodes", "capacity_announcements"))

    import psycopg

    from schedulingkit import dsn

    conn = psycopg.connect(dsn(), autocommit=False, options=f"-c search_path={schema}")
    try:
        results = migrate.down(conn)
        assert all(item["rc"] == 0 for item in results)
        assert [item["name"] for item in results] == list(reversed(M04_MIGRATIONS))
        # 可重复执行
        assert all(item["rc"] == 0 for item in migrate.down(conn))
    finally:
        conn.close()

    assert not (set(M04_TABLES) & table_names(schema))
    assert set(SUPPLY_VIEWS) <= view_names(schema)
    assert not (set(M04_FUNCTIONS) & function_names(schema))
    assert fingerprint(schema, tables=("nodes", "capacity_announcements")) == upstream_before

    # 回滚后能再升级
    for item in apply_migrations(schema, files=m04_migration_files()):
        assert item["rc"] == 0
    assert set(M04_TABLES) <= table_names(schema)


def test_status_reports_each_migration(schema: str) -> None:
    import psycopg

    from schedulingkit import dsn

    apply_migrations(schema, files=prerequisite_files(499))
    conn = psycopg.connect(dsn(), autocommit=True, options=f"-c search_path={schema}")
    try:
        report = {item["name"]: item["applied"] for item in migrate.status(conn)}
    finally:
        conn.close()
    assert set(report) == set(M04_MIGRATIONS)
    assert all(report.values())


# --------------------------------------------------------------------------- 表结构
def test_m04_tables_expose_the_section_5_columns(schema: str) -> None:
    apply_migrations(schema, files=prerequisite_files(499))
    expected = {
        "quotes": {"node_id", "access", "model", "unit", "ask_price_minor", "ttl_s", "state",
                   "quote_version", "price_max_minor", "currency", "expires_at"},
        "bids": {"tenant_id", "model", "min_price_minor", "max_price_minor", "strategy", "state",
                 "bid_version", "currency", "expires_at"},
        "bookings": {"quote_id", "bid_id", "node_id", "tenant_id", "price_minor", "expires_at",
                     "state", "request_id", "strategy"},
        "routing_decisions": {"decision_id", "snapshot_ts", "quote_version", "policy_version",
                              "request_digest", "candidates", "eliminated", "score_breakdown",
                              "chosen", "tie_break", "preempt_plan", "outcome", "fallback_used",
                              "trace_id", "attempt_no", "reason_codes", "eta_seconds",
                              "price_minor", "decided_at"},
        "quota_usage": {"tenant_id", "model", "window_kind", "window_start", "concurrent",
                        "daily_spend_minor", "share_pct_bps"},
        "model_catalog": {"model", "vendor", "unit", "price_version", "state"},
    }
    for table, columns in expected.items():
        assert columns <= column_names(schema, table), table


def test_quotes_reject_wrong_currency_and_inverted_interval(schema: str) -> None:
    apply_migrations(schema, files=prerequisite_files(499))
    with session(schema) as conn:
        # 非 USD（INV-13）
        with pytest.raises(Exception):
            conn.execute(
                """INSERT INTO quotes (node_id, access, model, unit, ask_price_minor,
                                       currency, ttl_s, quote_version, expires_at)
                   VALUES ('n1', 'A1', 'm1', 'token', 800, 'USDT', 60, 1, now() + interval '1 h')""")
        # 上界 < 下界（INV-01）
        with pytest.raises(Exception):
            conn.execute(
                """INSERT INTO quotes (node_id, access, model, unit, ask_price_minor,
                                       price_max_minor, ttl_s, quote_version, expires_at)
                   VALUES ('n1', 'A1', 'm1', 'token', 1000, 900, 60, 1, now() + interval '1 h')""")
        # 非法 access
        with pytest.raises(Exception):
            conn.execute(
                """INSERT INTO quotes (node_id, access, model, unit, ask_price_minor, ttl_s,
                                       quote_version, expires_at)
                   VALUES ('n1', 'A9', 'm1', 'token', 800, 60, 1, now() + interval '1 h')""")


# --------------------------------------------------------------------------- CLI（migrate.py）
def test_cli_up_status_down_round_trip(schema: str) -> None:
    """``python -m app.scheduling.migrate`` 的三种模式都能在隔离 schema 里跑通。"""
    assert migrate.main(["--schema", schema, "--up"]) == 0
    assert set(M04_TABLES) <= table_names(schema)
    assert migrate.main(["--schema", schema, "--status"]) == 0
    assert migrate.main(["--schema", schema, "--down"]) == 0
    assert not (set(M04_TABLES) & table_names(schema))


def test_cli_requires_a_dsn(monkeypatch) -> None:
    monkeypatch.delenv("DJB_DSN", raising=False)
    assert migrate.main(["--schema", "m04_cli_no_dsn", "--status"]) == 2


def test_migrate_module_exports_the_rollback_map() -> None:
    """回滚 SQL 由 Python 持有（``migrations/`` 下不能放 *_down.sql，会被当正向执行）。"""
    assert len(migrate.DOWN_SQL) == len(M04_MIGRATIONS)
    assert [name for name, _sql in migrate.DOWN_SQL] == list(reversed(M04_MIGRATIONS))
    for name, script in migrate.DOWN_SQL:
        # 建表类迁移删表；只加列的迁移（如 409）删列/索引即可
        assert "DROP TABLE IF EXISTS" in script or "DROP COLUMN IF EXISTS" in script, name
