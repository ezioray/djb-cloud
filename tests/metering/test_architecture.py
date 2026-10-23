# SPDX-License-Identifier: Apache-2.0
"""架构门禁（00-conventions §1 / §7.1 / 04-api-contracts §4 architecture）。不需要 DB。

静态检查：

* **禁止跨模块 import**：``app/metering/**`` 只能 import 标准库 / ``psycopg`` / ``fastapi``
  与基础设施 ``app.db``；
* **禁止直读非本模块表**：SQL 里出现的表名必须属于 M05 的表清单，跨模块只用
  00-conventions §7.4 允许的只读视图（``v_supply_*`` / ``v_identity_*``）；
* **不碰 legacy adapter**：不 import / 不修改 ``app/receipt.py``、``app/api.py`` 等；
* 迁移编号段只属于 M05（500–599），且不动任何前置对象。
"""
from __future__ import annotations

import ast
import re

import pytest

from meterkit import (
    IDENTITY_VIEWS,
    M05_MIGRATIONS,
    M05_TABLES,
    ROOT,
    SUPPLY_VIEWS,
    UPSTREAM_BASE_TABLES,
)

MODULE_DIR = ROOT / "app" / "metering"
ALLOWED_THIRD_PARTY = {"psycopg", "fastapi", "starlette", "pydantic"}
ALLOWED_APP_PREFIXES = ("app.metering", "app.db")

#: 允许读的**只读视图**（00-conventions §7.4：v_<module>_<object>）
ALLOWED_FOREIGN_OBJECTS = set(SUPPLY_VIEWS) | set(IDENTITY_VIEWS)
SQL_NON_TABLE_TOKENS = {"skip", "set", "only", "where", "select", "lateral"}

SQL_TABLE_RE = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN)\s+([a-z_][a-z0-9_]*)", re.IGNORECASE)


def _module_files() -> list:
    return sorted(MODULE_DIR.glob("*.py"))


def test_module_has_the_expected_layers():
    names = {path.name for path in _module_files()}
    assert {"__init__.py", "facts.py", "errors.py", "clock.py", "config_source.py",
            "features.py", "amounts.py", "signing.py", "models.py", "events.py",
            "receipts.py", "usage.py", "router.py", "migrate.py"} <= names


def _check_import(path, name: str) -> list[str]:
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


def test_rollback_sql_only_drops_m05_objects():
    """回滚 SQL 在 migrate.py 里：只允许 DROP 本模块对象，不得 ALTER / DROP 上游表。"""
    from app.metering import migrate

    for name, script in migrate.DOWN_SQL:
        for match in re.finditer(r"DROP TABLE IF EXISTS\s+([a-z_][a-z0-9_]*)", script):
            assert match.group(1) in M05_TABLES, (name, match.group(1))
        for table in UPSTREAM_BASE_TABLES:
            assert f"ALTER TABLE {table}" not in script, (name, table)
            assert f"DROP TABLE IF EXISTS {table}" not in script, (name, table)


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


def _string_literals(path) -> list[str]:
    """只扫字符串常量里的 SQL（源码里的 Python import 也含 ``from ...``，会误报）。"""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)]


def test_sql_only_touches_own_tables_and_allowed_views():
    extra = {"information_schema", "pg_constraint", "pg_proc", "pg_namespace", "pg_class",
             "pg_trigger", "pg_indexes", "pg_attrdef", "pg_type", "pg_depend"}
    allowed = set(M05_TABLES) | ALLOWED_FOREIGN_OBJECTS | extra
    offenders: list[str] = []
    for path in _module_files():
        if path.name == "migrate.py":
            continue                      # 回滚 DDL 由 test_migrations + DOWN_SQL 专项检查
        for literal in _string_literals(path):
            for match in SQL_TABLE_RE.finditer(literal):
                table = match.group(1).lower()
                if table in allowed or table in SQL_NON_TABLE_TOKENS:
                    continue
                offenders.append(f"{path.name}: {table}")
    assert offenders == [], f"读了非本模块对象：{offenders}"


def test_sql_never_reads_upstream_base_tables():
    """跨模块只读依赖必须走视图（01-ownership §2 / 00-conventions §7.4）。"""
    for path in _module_files():
        for literal in _string_literals(path):
            for table in UPSTREAM_BASE_TABLES:
                for keyword in ("FROM", "JOIN", "INTO", "UPDATE"):
                    assert f"{keyword} {table}" not in literal, (path.name, keyword, table)


def test_legacy_adapters_are_not_imported_or_modified():
    for path in _module_files():
        source = path.read_text(encoding="utf-8")
        for legacy in ("app.receipt", "app.api", "app.nodes", "app.pricing", "app.upstream",
                       "app.reconcile", "app.ledger", "app.points", "app.wallet_pool"):
            assert f"import {legacy}" not in source, (path.name, legacy)
            assert f"from {legacy}" not in source, (path.name, legacy)
            assert f"from {legacy.split('.')[-1]} import" not in source, (path.name, legacy)


def test_router_is_not_wired_into_the_global_app():
    """不接 app/api.py：本包不注册任何全局路由副作用（由 Lead 合并时 include）。"""
    source = (MODULE_DIR / "router.py").read_text(encoding="utf-8")
    assert "include_router" not in source
    assert "app.api" not in source


def test_migrations_create_only_m05_tables():
    created: set[str] = set()
    for name in M05_MIGRATIONS:
        sql = (ROOT / "migrations" / name).read_text(encoding="utf-8")
        for match in re.finditer(r"CREATE TABLE IF NOT EXISTS ([a-z_][a-z0-9_]*)", sql):
            created.add(match.group(1))
    assert created == set(M05_TABLES), created


def test_migration_numbers_stay_in_the_m05_segment():
    for name in M05_MIGRATIONS:
        number = int(name.split("_", 1)[0])
        assert 500 <= number <= 599, name


def test_migrations_never_recreate_or_alter_upstream_objects():
    """只加不改（00-conventions §7.2）：5xx 里不允许 CREATE / ALTER / DROP 上游对象。"""
    for name in M05_MIGRATIONS:
        sql = (ROOT / "migrations" / name).read_text(encoding="utf-8")
        for table in UPSTREAM_BASE_TABLES:
            assert f"CREATE TABLE IF NOT EXISTS {table}" not in sql, (name, table)
            assert f"DROP TABLE IF EXISTS {table}" not in sql, (name, table)
            assert f"ALTER TABLE {table} " not in sql, (name, table)
            assert f"ALTER TABLE {table}\n" not in sql, (name, table)


def test_no_ddl_inside_module_code():
    """DDL 只在 migrations/：模块代码里不得出现 CREATE TABLE / ALTER TABLE / DROP TABLE。

    例外：``migrate.py`` 按 M02/M04/M06 同款做法持有**回滚 SQL**（放 migrations/ 下的
    ``*_down.sql`` 会被 ``sort -V`` 当正向迁移执行），因此它允许 DROP / ALTER。
    """
    for path in _module_files():
        if path.name == "migrate.py":
            continue
        for literal in _string_literals(path):
            upper = literal.upper()
            for token in ("CREATE TABLE", "ALTER TABLE", "DROP TABLE"):
                assert token not in upper, (path.name, token)


def test_no_hardcoded_business_constants_outside_facts():
    """facts 不得硬编码：业务数值只能来自 facts.py / 配置注入（用 AST 只扫**数字字面量**）。

    文档字符串里的举例（如 ``"0.0005"``）不算硬编码；真正危险的是代码里出现
    「平台费率 1500」「一天 86400」「默认窗口 24」这类数值。
    """
    # 0 / 1 是结构性字面量（下标、布尔式），不在此列
    suspicious_numbers = {24, 50, 1500, 10000, 86400, 41200, 1.0, 24.0, 50.0, 0.0005}
    offenders: list[str] = []
    for path in _module_files():
        if path.name == "facts.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and not isinstance(node.value, bool):
                value = node.value
                if not isinstance(value, (int, float)):
                    continue
                if isinstance(value, int) and value in (0, 1):
                    continue
                if float(value) in suspicious_numbers:
                    offenders.append(f"{path.name}:{node.lineno}={value!r}")
    assert offenders == [], f"疑似硬编码业务数值（应放 facts.py / 配置注入）：{offenders}"


def _docstring_ids(tree: ast.AST) -> set[int]:
    """收集文档字符串节点的 id（文档里引用配置键名是允许的，代码里不允许）。"""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and \
                    isinstance(body[0].value, ast.Constant) and \
                    isinstance(body[0].value.value, str):
                ids.add(id(body[0].value))
    return ids


def test_business_config_keys_are_only_read_through_config_source():
    """``metering.*`` 配置键只在 facts.py 登记、由 config_source 解析（文档字符串除外）。"""
    for path in _module_files():
        if path.name in ("facts.py", "config_source.py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        skip = _docstring_ids(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if id(node) in skip:
                continue
            assert "metering.receipt_late_h" not in node.value, (path.name, node.lineno)
            assert "metering.overbill_tolerance_pct" not in node.value, (path.name, node.lineno)


@pytest.mark.parametrize("forbidden", ["app.identity", "app.supply", "app.scheduling",
                                       "app.config_center", "app.admin", "app.chain"])
def test_forbidden_imports_are_absent(forbidden):
    for path in _module_files():
        source = path.read_text(encoding="utf-8")
        assert f"import {forbidden}" not in source, path.name
        assert f"from {forbidden}" not in source, path.name


def test_events_payload_keys_live_in_facts_only():
    """事件 payload 必含字段只在 facts.py 登记（业务代码只能经 ``facts.EVENT_PAYLOAD_KEYS`` 读）。"""
    for path in _module_files():
        if path.name == "facts.py":
            continue
        source = path.read_text(encoding="utf-8")
        assert source.count("EVENT_PAYLOAD_KEYS") == source.count("facts.EVENT_PAYLOAD_KEYS")
