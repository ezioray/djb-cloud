# SPDX-License-Identifier: AGPL-3.0-or-later
"""架构门禁（00-conventions §1 / §7 / 04-api-contracts §4 architecture）。不需要 DB。

* **禁止跨模块 import**：``app/gateway/**`` 只能 import 标准库 / ``psycopg`` / ``fastapi``
  与基础设施 ``app.db``；
* **禁止直读非本模块表**：SQL 里出现的表名必须属于 M03 的表清单（跨模块只走注入 provider）；
* **不碰 legacy / 路由层**：不 import ``app.api``、不在本包 include router；
* **迁移编号段只属于 M03（300–399）**，且不动任何前置对象；
* **特性开关三字段 + 默认关闭**；**facts 不硬编码**。
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

import pytest

from app.gateway import features, providers
from gatewaykit import M03_MIGRATIONS, M03_TABLES, ROOT

MODULE_DIR = ROOT / "app" / "gateway"
ALLOWED_THIRD_PARTY = {"psycopg", "fastapi", "pydantic", "starlette"}
ALLOWED_APP_PREFIXES = ("app.gateway", "app.db")

SQL_TABLE_RE = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN)\s+([a-z_][a-z0-9_]*)", re.IGNORECASE)
#: SQL 关键字 / plpgsql 行变量（不是表名）
SQL_NON_TABLE_TOKENS = {"skip", "set", "only", "where", "select", "lateral", "old", "new"}
#: 允许在 SQL 里读的系统视图（结构与排障查询）
SYSTEM_OBJECTS = {"information_schema", "pg_constraint", "pg_proc", "pg_namespace", "pg_class",
                  "pg_indexes", "pg_tables", "pg_trigger"}


def _module_files() -> list[pathlib.Path]:
    return sorted(MODULE_DIR.glob("*.py"))


def test_module_has_the_expected_layers():
    names = {path.name for path in _module_files()}
    assert {"__init__.py", "auth.py", "chat.py", "clock.py", "config_source.py", "dispatch.py",
            "errors.py", "events.py", "facts.py", "features.py", "idempotency.py", "migrate.py",
            "models.py", "outbox.py", "providers.py", "quota.py", "ratelimit.py", "router.py",
            "store.py", "validation.py"} <= names


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
    if root in sys.stdlib_module_names:
        return []
    return [f"{path.name}: {name}"] if not _is_local(root) else []


def _is_local(root: str) -> bool:
    return (MODULE_DIR / f"{root}.py").exists() or (MODULE_DIR / root).is_dir()


@pytest.mark.parametrize("forbidden", ["app.identity", "app.supply", "app.scheduling",
                                       "app.metering", "app.ledger", "app.config_center",
                                       "app.api", "app.nodes", "app.admin", "app.pricing",
                                       "app.receipt", "app.upstream"])
def test_forbidden_imports_are_absent(forbidden):
    for path in _module_files():
        source = path.read_text(encoding="utf-8")
        assert f"import {forbidden}" not in source, path.name
        assert f"from {forbidden}" not in source, path.name


def _string_literals(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)]


def test_sql_only_touches_own_tables():
    allowed = set(M03_TABLES) | SYSTEM_OBJECTS
    offenders: list[str] = []
    for path in _module_files():
        for literal in _string_literals(path):
            for match in SQL_TABLE_RE.finditer(literal):
                table = match.group(1).lower()
                if table in allowed or table in SQL_NON_TABLE_TOKENS:
                    continue
                offenders.append(f"{path.name}: {table}")
    assert offenders == [], f"读了非本模块对象：{offenders}"


def test_api_module_is_not_wired_here():
    source = (MODULE_DIR / "router.py").read_text(encoding="utf-8")
    assert "include_router" not in source
    assert "app.api" not in source


def test_router_paths_are_only_v1_gateway_owned():
    from app.gateway import router as router_module

    paths = {route.path for route in router_module.router.routes}
    assert paths <= {"/v1/chat/completions", "/v1/models", "/v1/batches",
                     "/v1/batches/{id}", "/v1/batches/{id}/cancel"}
    assert "/api/v1/protocol" not in paths                  # 后台接口归 M02


def test_providers_default_to_fail_closed():
    providers.reset_providers()
    assert providers.current() == {"auth": False, "route": False, "node": False,
                                   "stream": False, "usage": False, "model_catalog": False,
                                   "webhook_sender": False, "webhook_secret": False,
                                   "result_signer": False}


def test_feature_switches_have_three_fields_and_off_default():
    for switch in features.switches():
        assert switch.owner and switch.expire_at and switch.rollback_rule
        assert switch.default is False
    assert features.WRITE_SURFACE == ()


def test_no_hardcoded_business_constants_in_code():
    """§8.2 常量只允许出现在 facts.py；业务阈值不得散落在别处。"""
    suspicious = ("86400", "1048576", "900", "0.35")
    for path in _module_files():
        if path.name in {"facts.py", "migrate.py"}:          # migrate 有 SQL 文本
            continue
        source = path.read_text(encoding="utf-8")
        for token in suspicious:
            assert f"= {token}" not in source, f"{path.name}: 疑似硬编码 {token}"


def test_no_secrets_or_env_business_config():
    for path in _module_files():
        source = path.read_text(encoding="utf-8")
        assert "os.environ" not in source or path.name in {"migrate.py"}, path.name
        assert "password" not in source.lower(), path.name


def test_migrations_segment_and_upstream_safety():
    root = ROOT / "migrations"
    for name in M03_MIGRATIONS:
        number = int(name.split("_", 1)[0])
        assert 300 <= number <= 399, name
        sql = (root / name).read_text(encoding="utf-8")
        assert "DROP TABLE IF EXISTS api_keys" not in sql
        assert "ALTER TABLE nodes" not in sql


def test_module_documents_wiring_points():
    wiring = MODULE_DIR / "WIRING.md"
    assert wiring.exists()
    text = wiring.read_text(encoding="utf-8")
    for provider in ("set_auth_provider", "set_route_provider", "set_node_client",
                     "set_usage_provider", "set_model_catalog_provider", "set_provider"):
        assert provider in text, provider
