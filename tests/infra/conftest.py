# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/infra 测试脚手架（DEV-M16）。

隔离约定：
* 每个测试进程独立 schema 前缀（``m16_t_<pid>_<hex>``，``M16_SCHEMA`` 可覆盖），结束 DROP；
* 迁移用 ``psql -f`` 逐文件执行（与 CI / 生产同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑；
* 覆盖率（``M16_COVERAGE=1``）必须在导入 ``app.audit`` **之前**启动，所以放在本文件顶部。

两套 schema（NAS 上一次全量迁移 ~20s，能省就省）：
* ``migrated``（**session 级**共享）：所有"读 + 事务内写"的用例共用，靠 **事务回滚** 隔离；
* ``schema``（用例级全新）：只给"必须真提交 / 必须 DDL 态"的用例（空库、升级、回滚、并发）。
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

from infrakit import (                              # noqa: E402
    TEST_KEY,
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
    savepoint_factory,
)

SCHEMA_ENV = "M16_SCHEMA"


@pytest.fixture(scope="session")
def db() -> str:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return dsn


@pytest.fixture(scope="session")
def schema_prefix(db: str) -> str:
    return os.environ.get(SCHEMA_ENV) or f"m16_t_{os.getpid()}_{uuid.uuid4().hex[:6]}"


@pytest.fixture
def schema(db: str, schema_prefix: str) -> str:
    """空 schema（未跑任何迁移）—— 空库 / 升级 / 回滚 / 并发用例用。"""
    name = f"{schema_prefix}_{uuid.uuid4().hex[:6]}"
    create_schema(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture(scope="session")
def migrated(db: str, schema_prefix: str) -> str:
    """session 级共享 schema：001→1403 只跑一次（NAS 上全量迁移约 20s）。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """事务型连接：退出回滚（审计表 append-only 不能 TRUNCATE，用事务隔离最干净）。"""
    connection = connect(migrated, autocommit=False)
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


@pytest.fixture
def savepoint_conn(migrated: str):
    """外层事务 + 内层 SAVEPOINT 的连接：给 HTTP 用例用，handler 的提交只释放保存点。"""
    connection = connect(migrated, autocommit=False)
    connection.execute("SELECT 1")                   # 显式开启外层事务
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


@pytest.fixture
def key_provider():
    from app.audit import StaticKeyProvider

    return StaticKeyProvider(TEST_KEY)


@pytest.fixture
def unauth_client(savepoint_conn, key_provider):
    """未接线鉴权的客户端（fail-closed 用例：必须 401）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.audit import create_router

    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(savepoint_conn),
        principal_resolver=None,
        key_provider=key_provider,
    ))
    with TestClient(app) as client:
        yield client


@pytest.fixture
def health_client(savepoint_conn, key_provider):
    """/healthz 客户端（health router 单独 include，等价于 Lead 接线方式）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.audit import create_health_router

    app = FastAPI()
    app.include_router(create_health_router(
        connection_factory=savepoint_factory(savepoint_conn),
        key_provider=key_provider,
    ))
    with TestClient(app) as client:
        yield client


def pytest_sessionfinish(session, exitstatus):       # noqa: ARG001
    """覆盖率落盘（``M16_COVERAGE_OUT``）。"""
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M16_COVERAGE_OUT")
    report = write_report(_COVERAGE, out) if out else _COVERAGE.report()
    print(f"\n[M16 coverage] app/audit = {report['percent']}% "
          f"({report['total_hit']}/{report['total_executable']} lines)"
          + (f" → {out}" if out else ""))
