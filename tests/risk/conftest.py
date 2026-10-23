# SPDX-License-Identifier: Apache-2.0
"""tests/risk 测试脚手架（DEV-M11）。

隔离与两套 schema（NAS 上一次全量迁移 ~20s，能省就省）：

* ``migrated``（session 级共享）：读 + 事务内写用例共用，靠**事务回滚 / SAVEPOINT** 隔离；
* ``fresh``（用例级全新）：空库 / 迁移幂等 / 回滚 / CLI 用例（必须真 DDL）。

覆盖率（``M11_COVERAGE=1``）必须在导入 ``app.risk`` **之前**启动 → 放在本文件顶部。
"""
from __future__ import annotations

import os
import pathlib
import sys
import uuid
from contextlib import contextmanager

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for _path in (str(_HERE), str(_REPO_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from coverkit import maybe_start, write_report       # noqa: E402

_COVERAGE = maybe_start()

from riskkit import (                                # noqa: E402
    FIXED_NOW,
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
)

SCHEMA_ENV = "M11_SCHEMA"


@pytest.fixture(scope="session")
def db() -> str:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return dsn


@pytest.fixture(scope="session")
def schema_prefix(db: str) -> str:
    return os.environ.get(SCHEMA_ENV) or f"m11_t_{os.getpid()}_{uuid.uuid4().hex[:6]}"


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
    """session 级共享 schema：001→1104 只跑一次。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """事务型连接：退出回滚（案件 / 事件表追加型，用事务隔离最干净）。"""
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


def savepoint_factory(connection):
    @contextmanager
    def factory():
        with connection.transaction():
            yield connection

    return factory


@pytest.fixture
def now():
    return FIXED_NOW


def pytest_sessionfinish(session, exitstatus):       # noqa: ARG001
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M11_COVERAGE_OUT")
    report = write_report(_COVERAGE, out) if out else _COVERAGE.report()
    print(f"\n[M11 coverage] app/risk = {report['percent']}% "
          f"({report['total_hit']}/{report['total_executable']} lines)"
          + (f" → {out}" if out else ""))


# ─────────────────────────────────────────────────────── M11 HTTP 客户端夹具
ADMIN_PRINCIPAL = {"admin_id": "disposer", "tenant_id": "tenant-a",
                   "scopes": ["risk.read", "risk.write"]}
READONLY_PRINCIPAL = {"admin_id": "auditor", "tenant_id": "tenant-a", "scopes": ["risk.read"]}
OTHER_TENANT_PRINCIPAL = {"admin_id": "disposer-b", "tenant_id": "tenant-b",
                          "scopes": ["risk.read", "risk.write"]}


def build_client(connection, *, admin=ADMIN_PRINCIPAL, step_up=True, now=None,
                 config_provider=None, audit_sink=None):
    """构造带 M11 路由的 ASGI 客户端（请求级 SAVEPOINT，不真提交）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.risk.router import create_router
    from riskkit import FIXED_NOW

    moment = now or FIXED_NOW
    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(connection),
        admin_resolver=(lambda request: dict(admin)) if admin is not None else None,
        step_up_verifier=(lambda request: step_up) if step_up is not None else None,
        now_provider=lambda: moment,
        config_provider=(lambda: config_provider) if config_provider is not None else None,
        audit_sink=audit_sink,
    ))
    return TestClient(app)


@pytest.fixture
def client(savepoint_conn):
    with build_client(savepoint_conn) as test_client:
        yield test_client


@pytest.fixture
def unauth_client(savepoint_conn):
    """鉴权钩子未接线 → 所有端点必须 401（fail-closed）。"""
    with build_client(savepoint_conn, admin=None) as test_client:
        yield test_client
