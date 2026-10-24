# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/model_sync 夹具（M18 C17）。

隔离：

* ``migrated``（session 级共享）：全量迁移一次，读写用例共用；每个用例在自己的事务里跑，
  结束回滚（``conn`` 夹具）——不污染共享 schema；
* ``base_schema``（session 级）：只跑到 1800 段之前，供「升级 / 回滚 / 账本 diff」演练
  （DDL 在 PG 里是事务性的，用例里应用 1800 后回滚即可复原）；
* 缺 ``DJB_DSN`` 时整体 skip（纯函数用例仍跑）。
"""
from __future__ import annotations

import os
import pathlib
import sys
import uuid

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for _path in (str(_HERE), str(_REPO_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from kit import (                                     # noqa: E402
    ADMIN_PRINCIPAL,
    FIXED_NOW,
    NODE_PRINCIPAL,
    apply_migrations,
    base_migration_files,
    build_client,
    connect,
    create_schema,
    drop_schema,
    reset_authenticators,
)

SCHEMA_ENV = "M18_SCHEMA"


@pytest.fixture(scope="session")
def db() -> str:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return dsn


@pytest.fixture(scope="session")
def schema_prefix(db: str) -> str:                    # noqa: ARG001
    return os.environ.get(SCHEMA_ENV) or f"m18_t_{os.getpid()}_{uuid.uuid4().hex[:6]}"


@pytest.fixture(scope="session")
def migrated(db: str, schema_prefix: str) -> str:     # noqa: ARG001
    """全量迁移（001…1800）一次，session 内共享。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture(scope="session")
def base_schema(db: str, schema_prefix: str) -> str:  # noqa: ARG001
    """只到 1800 段之前（升级 / 回滚 / 账本 diff 的前置基线）。"""
    name = f"{schema_prefix}_base_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name, base_migration_files())
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """事务型连接：用例结束回滚（不改共享 schema 的数据）。"""
    connection = connect(migrated, autocommit=False)
    connection.execute("SELECT 1")          # 显式开启外层事务：之后只允许 SAVEPOINT
    try:
        yield connection
    finally:
        connection.rollback()
        connection.close()


@pytest.fixture
def base_conn(base_schema: str):
    """事务型连接（基线 schema，用于迁移演练）。"""
    connection = connect(base_schema, autocommit=False)
    connection.execute("SELECT 1")
    try:
        yield connection
    finally:
        connection.rollback()
        connection.close()


@pytest.fixture
def now():
    return FIXED_NOW


@pytest.fixture(autouse=True)
def _reset_hooks():
    """每个用例后清空鉴权钩子（模块级全局状态，防串场）。"""
    yield
    reset_authenticators()


@pytest.fixture
def client(conn, monkeypatch, now):
    """节点 + 管理面都已接线的客户端（开关打开、测试假密钥）。"""
    return build_client(conn, monkeypatch, node=NODE_PRINCIPAL, admin=ADMIN_PRINCIPAL, now=now)


@pytest.fixture
def anon_client(conn, monkeypatch, now):
    """未接线任何鉴权的客户端（验 fail-closed）。"""
    return build_client(conn, monkeypatch, node=None, admin=None, now=now)
