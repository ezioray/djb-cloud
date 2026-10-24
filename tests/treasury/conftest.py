# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/treasury 测试脚手架（DEV-M08）。

隔离与两套 schema（复用一个全量迁移 schema 省时间）：

* migrated（session 级共享）：读 + 事务内写用例共用，靠**事务回滚 / SAVEPOINT** 隔离；
* fresh（用例级全新）：空库 / 升级 / 回滚 / 幂等 / CLI 用例（必须真 DDL）。

覆盖率（M08_COVERAGE=1）必须在导入 app.treasury **之前**启动 → 放在本文件顶部。
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

from coverkit import maybe_start, write_report       # noqa: E402

_COVERAGE = maybe_start()

from m08kit import (                                 # noqa: E402
    FIXED_NOW,
    apply_migrations,
    build_client,
    connect,
    create_schema,
    drop_schema,
)

SCHEMA_ENV = "M08_SCHEMA"


@pytest.fixture(scope="session")
def db() -> str:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return dsn


@pytest.fixture(scope="session")
def schema_prefix(db: str) -> str:
    return os.environ.get(SCHEMA_ENV) or f"m08_t_{os.getpid()}_{uuid.uuid4().hex[:6]}"


@pytest.fixture
def fresh(db: str, schema_prefix: str) -> str:
    """空 schema（未跑任何迁移）—— 空库 / 升级 / 回滚 / 幂等用例用。"""
    name = f"{schema_prefix}_{uuid.uuid4().hex[:6]}"
    create_schema(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture(scope="session")
def migrated(db: str, schema_prefix: str) -> str:
    """session 级共享 schema：001→805 只跑一次。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """事务型连接：退出回滚（业务表多数只追加，用事务隔离最干净）。"""
    connection = connect(migrated, autocommit=False)
    connection.execute("SELECT 1")
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


@pytest.fixture
def savepoint_conn(migrated: str):
    """外层事务 + 内层 SAVEPOINT：HTTP 用例的 handler 提交只释放保存点。"""
    connection = connect(migrated, autocommit=False)
    connection.execute("SELECT 1")
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


@pytest.fixture
def now():
    return FIXED_NOW


def pytest_sessionfinish(session, exitstatus):       # noqa: ARG001
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M08_COVERAGE_OUT")
    report = write_report(_COVERAGE, out) if out else _COVERAGE.report()
    print(f"\n[M08 coverage] app/treasury = {report['percent']}% "
          f"({report['total_hit']}/{report['total_executable']} lines)"
          + (f" -> {out}" if out else ""))


# ─────────────────────────────────────────────────── HTTP 客户端夹具
# 客户端构造器与 principals 在 m08kit.py（测试文件也从那里导入）。
@pytest.fixture
def client(savepoint_conn):
    with build_client(savepoint_conn) as test_client:
        yield test_client


@pytest.fixture
def unauth_client(savepoint_conn):
    """鉴权钩子未接线 → 所有端点必须 401（fail-closed）。"""
    with build_client(savepoint_conn, user=None, provider=None, admin=None) as test_client:
        yield test_client
