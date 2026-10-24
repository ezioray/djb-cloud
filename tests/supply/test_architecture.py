# SPDX-License-Identifier: Apache-2.0
"""架构门禁（00-conventions §1 / §7.1 / 04-api-contracts §4 architecture）。

静态检查，不需要 DB：

* **禁止跨模块 import**：``app/supply/**`` 只能 import 标准库 / ``psycopg`` / ``fastapi``
  与基础设施 ``app.db``；
* **禁止直读非本模块表**：SQL 里出现的表名必须属于 M02 的表清单（``v_identity_accounts``
  是 00-conventions §7.4 允许的跨模块只读视图）；
* **不建第二套身份表**：2xx 迁移只创建 M02 的表；
* 迁移编号段只属于 M02（200–299），且不动 003 的存量定义。
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

from supplykit import M02_MIGRATIONS, M02_TABLES, ROOT

MODULE_DIR = ROOT / "app" / "supply"
ALLOWED_THIRD_PARTY = {"psycopg", "fastapi", "pydantic", "starlette"}
ALLOWED_APP_PREFIXES = ("app.supply", "app.db")

#: 允许读的**只读视图**（00-conventions §7.4：v_<module>_<object>）
ALLOWED_FOREIGN_OBJECTS = {"v_identity_accounts"}
#: M02 自己建的只读视图（供 M04 读；属于本模块对象）
OWN_VIEWS = {"v_supply_capacity_latest", "v_supply_node_snapshot",
             "v_supply_upstream_verified"}
#: 形如 "UPDATE SKIP LOCKED" / "CROSS JOIN LATERAL ..." 的 SQL 关键字组合不是表名
SQL_NON_TABLE_TOKENS = {"skip", "set", "only", "where", "select", "lateral"}

SQL_TABLE_RE = re.compile(
    r"\b(?:FROM|INTO|UPDATE|JOIN)\s+([a-z_][a-z0-9_]*)", re.IGNORECASE)


def _module_files() -> list[pathlib.Path]:
    return sorted(MODULE_DIR.glob("*.py"))


def test_module_has_the_expected_layers():
    names = {path.name for path in _module_files()}
    assert {"__init__.py", "facts.py", "state.py", "protocol.py", "security.py", "events.py",
            "models.py", "idempotency.py", "features.py", "migrate.py", "router.py",
            "errors.py", "clock.py", "config_source.py", "capacity.py", "heartbeat.py",
            "upstream.py", "policy.py", "jobs.py", "audit.py"} <= names


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
    # 标准库：用 sys.stdlib_module_names 判定（Python 3.10+）
    import sys

    if root in sys.stdlib_module_names:
        return []
    if root in {"app"}:                                          # pragma: no cover - 兜底
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
    allowed = (set(M02_TABLES) | ALLOWED_FOREIGN_OBJECTS | OWN_VIEWS
               | {"information_schema", "pg_constraint", "pg_proc", "pg_namespace",
                  "pg_class", "pg_trigger"})
    offenders: list[str] = []
    for path in _module_files():
        for literal in _string_literals(path):
            for match in SQL_TABLE_RE.finditer(literal):
                table = match.group(1).lower()
                if table in allowed or table in SQL_NON_TABLE_TOKENS:
                    continue
                offenders.append(f"{path.name}: {table}")
    assert offenders == [], f"读了非本模块对象：{offenders}"


def test_sql_reads_accounts_only_through_the_read_only_view():
    source = (MODULE_DIR / "models.py").read_text(encoding="utf-8")
    assert "v_identity_accounts" in source
    assert "FROM user_accounts" not in source
    assert "JOIN user_accounts" not in source


def test_migrations_create_only_m02_tables():
    created: set[str] = set()
    for name in M02_MIGRATIONS:
        sql = (ROOT / "migrations" / name).read_text(encoding="utf-8")
        for match in re.finditer(r"CREATE TABLE IF NOT EXISTS ([a-z_][a-z0-9_]*)", sql):
            created.add(match.group(1))
    assert created == set(M02_TABLES) - {"nodes"}, created


def test_migration_numbers_stay_in_the_m02_segment():
    for name in M02_MIGRATIONS:
        number = int(name.split("_", 1)[0])
        assert 200 <= number <= 299, name


def test_migrations_never_recreate_the_legacy_nodes_table():
    for name in M02_MIGRATIONS:
        sql = (ROOT / "migrations" / name).read_text(encoding="utf-8")
        assert "CREATE TABLE IF NOT EXISTS nodes" not in sql, name
        assert "DROP TABLE IF EXISTS nodes" not in sql, name


def test_legacy_adapter_is_not_imported_or_modified_by_the_module():
    for path in _module_files():
        source = path.read_text(encoding="utf-8")
        assert "app.nodes" not in source and "from ..nodes" not in source, path.name
        assert "from ..api" not in source and "app.api" not in source, path.name


@pytest.mark.parametrize("forbidden", ["app.identity", "app.config_center", "app.ledger",
                                       "app.api", "app.nodes", "app.admin"])
def test_forbidden_imports_are_absent(forbidden):
    for path in _module_files():
        source = path.read_text(encoding="utf-8")
        assert f"import {forbidden}" not in source, path.name
        assert f"from {forbidden}" not in source, path.name
