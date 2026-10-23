# SPDX-License-Identifier: Apache-2.0
"""架构门禁（00-conventions §1 / §7.1 / 04-api-contracts §4 architecture）。

静态检查，不需要 DB：

* **禁止跨模块 import**：``app/scheduling/**`` 只能 import 标准库 / ``psycopg`` / ``fastapi``
  与基础设施 ``app.db``；
* **禁止直读非本模块表**：SQL 里出现的表名必须属于 M04 的表清单，跨模块只能用
  00-conventions §7.4 允许的只读视图（``v_supply_*``）；
* **不碰 legacy adapter**：不 import / 不修改 ``app/pricing.py``、``app/api.py`` 等；
* 迁移编号段只属于 M04（400–499），且不动任何前置对象。
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

from schedulingkit import M04_MIGRATIONS, M04_TABLES, ROOT, SUPPLY_VIEWS

MODULE_DIR = ROOT / "app" / "scheduling"
ALLOWED_THIRD_PARTY = {"psycopg", "fastapi", "pydantic", "starlette"}
ALLOWED_APP_PREFIXES = ("app.scheduling", "app.db")

#: 允许读的**只读视图**（00-conventions §7.4：v_<module>_<object>）
ALLOWED_FOREIGN_OBJECTS = set(SUPPLY_VIEWS)
#: SQL 关键字组合里的非表名 token
SQL_NON_TABLE_TOKENS = {"skip", "set", "only", "where", "select", "lateral"}

SQL_TABLE_RE = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN)\s+([a-z_][a-z0-9_]*)", re.IGNORECASE)


def _module_files() -> list[pathlib.Path]:
    return sorted(MODULE_DIR.glob("*.py"))


def test_module_has_the_expected_layers():
    names = {path.name for path in _module_files()}
    assert {"__init__.py", "facts.py", "errors.py", "clock.py", "config_source.py",
            "features.py", "models.py", "quotes.py", "bids.py", "matching.py", "events.py",
            "outbox.py", "idempotency.py", "candidates.py", "scoring.py", "quota.py",
            "fairness.py", "preempt.py", "backpressure.py", "circuit.py", "pipeline.py",
            "decisions.py", "replay.py", "snapshot.py", "migrate.py", "router.py",
            "cli.py"} <= names


def test_no_cross_module_imports():
    offenders: list[str] = []
    for path in _module_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    offenders += _check_import(path, alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level:                                   # 相对 import：包内
                    continue
                offenders += _check_import(path, node.module or "")
    assert offenders == [], f"跨模块 import：{offenders}"


def _check_import(path: pathlib.Path, name: str) -> list[str]:
    if not name:
        return []
    root = name.split(".")[0]
    if root in ALLOWED_THIRD_PARTY:
        return []
    if name == "app" or name.startswith("app."):
        return [] if name.startswith(ALLOWED_APP_PREFIXES) else [f"{path.name}: {name}"]
    import sys

    if root in sys.stdlib_module_names:
        return []
    return [f"{path.name}: {name}"] if not _is_local(root) else []


def _is_local(root: str) -> bool:
    return (MODULE_DIR / f"{root}.py").exists() or (MODULE_DIR / root).is_dir()


def _string_literals(path: pathlib.Path) -> list[str]:
    """只扫字符串常量里的 SQL（源码里的 Python import 也含 ``from ...``，会误报）。"""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)]


def test_sql_only_touches_own_tables_and_allowed_views():
    extra = {"information_schema", "pg_constraint", "pg_proc", "pg_namespace", "pg_class",
             "pg_trigger", "pg_indexes", "pg_tables"}
    allowed = set(M04_TABLES) | ALLOWED_FOREIGN_OBJECTS | extra
    offenders: list[str] = []
    for path in _module_files():
        for literal in _string_literals(path):
            for match in SQL_TABLE_RE.finditer(literal):
                table = match.group(1).lower()
                if table in allowed or table in SQL_NON_TABLE_TOKENS:
                    continue
                offenders.append(f"{path.name}: {table}")
    assert offenders == [], f"读了非本模块对象：{offenders}"


def test_sql_never_reads_upstream_base_tables():
    """跨模块只读依赖必须走视图（01-ownership §2 / 00-conventions §7.4）。"""
    forbidden = ("FROM nodes", "JOIN nodes", "FROM capacity_announcements",
                 "JOIN capacity_announcements", "FROM tenant_quotas", "JOIN tenant_quotas",
                 "FROM user_accounts", "JOIN user_accounts", "FROM config_items")
    for path in _module_files():
        for literal in _string_literals(path):
            for token in forbidden:
                assert token not in literal, f"{path.name}: 直读上游基表（{token}）"


def test_migrations_create_only_m04_tables():
    created: set[str] = set()
    for name in M04_MIGRATIONS:
        sql = (ROOT / "migrations" / name).read_text(encoding="utf-8")
        for match in re.finditer(r"CREATE TABLE IF NOT EXISTS ([a-z_][a-z0-9_]*)", sql):
            created.add(match.group(1))
    assert created == set(M04_TABLES), created


def test_migration_numbers_stay_in_the_m04_segment():
    for name in M04_MIGRATIONS:
        number = int(name.split("_", 1)[0])
        assert 400 <= number <= 499, name


def test_migrations_never_recreate_upstream_tables():
    for name in M04_MIGRATIONS:
        sql = (ROOT / "migrations" / name).read_text(encoding="utf-8")
        for table in ("nodes", "capacity_announcements", "user_accounts", "tenant_quotas",
                      "config_items", "ledger_entry"):
            assert f"CREATE TABLE IF NOT EXISTS {table}" not in sql, (name, table)
            assert f"DROP TABLE IF EXISTS {table}" not in sql, (name, table)


def test_migrations_only_add_to_upstream_objects():
    """只加不改（00-conventions §7.2）：4xx 里不允许 ALTER 上游表。"""
    for name in M04_MIGRATIONS:
        sql = (ROOT / "migrations" / name).read_text(encoding="utf-8")
        assert "ALTER TABLE nodes" not in sql, name
        assert "ALTER TABLE capacity_announcements" not in sql, name
        assert "ALTER TABLE user_accounts" not in sql, name


@pytest.mark.parametrize("forbidden", ["app.identity", "app.supply", "app.config_center",
                                       "app.ledger", "app.api", "app.nodes", "app.admin",
                                       "app.pricing", "app.receipt", "app.upstream"])
def test_forbidden_imports_are_absent(forbidden):
    for path in _module_files():
        source = path.read_text(encoding="utf-8")
        assert f"import {forbidden}" not in source, path.name
        assert f"from {forbidden}" not in source, path.name


def test_legacy_pricing_adapter_is_untouched():
    """``app/pricing.py`` 是 legacy adapter（只读引用），M04 不 import、不改它。"""
    legacy = ROOT / "app" / "pricing.py"
    assert legacy.exists()
    for path in _module_files():
        source = path.read_text(encoding="utf-8")
        assert "pricing import" not in source, path.name
        assert "from ..pricing" not in source, path.name


def test_no_hardcoded_fact_literals_in_module():
    """facts 不得硬编码：模块里不出现「源码级」业务字面量（抽查关键阈值）。"""
    suspicious = ("1500", "0.35", "20000")           # 平台费率 / 基尼 / 决策时延 ms
    for path in _module_files():
        if path.name == "facts.py":
            continue
        source = path.read_text(encoding="utf-8")
        for token in suspicious:
            assert f"= {token}" not in source, f"{path.name}: 疑似硬编码 {token}"


def test_api_module_is_not_wired_here():
    """不接 app/api.py：本包不注册任何全局路由副作用。"""
    source = (MODULE_DIR / "router.py").read_text(encoding="utf-8")
    assert "include_router" not in source
    assert "app.api" not in source
