# SPDX-License-Identifier: Apache-2.0
"""tests/recon 测试脚手架（DEV-M09 T1–T3）。

隔离约定：
* 每个测试进程独立 schema 前缀（``m09_t_<pid>_<hex>``，``M09_SCHEMA`` 可覆盖），结束 DROP；
* 迁移用 ``psql -f`` 逐文件执行（与 CI / 生产同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑；
* 覆盖率（``M09_COVERAGE=1``）必须在导入 ``app.recon`` **之前**启动，所以放在本文件顶部。

两套 schema（NAS 上一次全量迁移 ~20s，能省就省）：
* ``migrated``（**session 级**共享）：所有「读 + 事务内写」的用例共用，靠**事务回滚**隔离
  （M09 的表是追加型，DELETE 会被护栏拒绝，事务隔离比删数据干净）；
* ``fresh``（用例级全新）：只给「必须真提交 / 必须 DDL 态」的用例（空库、升级、回滚、幂等）。
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

from reconkit import (                               # noqa: E402
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
)

SCHEMA_ENV = "M09_SCHEMA"


@pytest.fixture(scope="session")
def db() -> str:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return dsn


@pytest.fixture(scope="session")
def schema_prefix(db: str) -> str:
    return os.environ.get(SCHEMA_ENV) or f"m09_t_{os.getpid()}_{uuid.uuid4().hex[:6]}"


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
    """session 级共享 schema：001→905 只跑一次。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """事务型连接：退出回滚（M09 表追加型，用事务隔离最干净）。"""
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
    """外层事务 + 内层 SAVEPOINT 的连接：给 HTTP 用例用，handler 的提交只释放保存点。"""
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
    """把一条连接包成 handler 需要的「请求级连接」（内层 SAVEPOINT，不真提交）。"""

    @contextmanager
    def factory():
        with connection.transaction():
            yield connection

    return factory


@pytest.fixture
def now():
    """固定时钟（分级 / SLA / 报表口径都靠它，避免 now() 抖动）。"""
    from reconkit import FIXED_NOW

    return FIXED_NOW


def pytest_sessionfinish(session, exitstatus):       # noqa: ARG001
    """覆盖率落盘（``M09_COVERAGE_OUT``）。"""
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M09_COVERAGE_OUT")
    report = write_report(_COVERAGE, out) if out else _COVERAGE.report()
    print(f"\n[M09 coverage] app/recon = {report['percent']}% "
          f"({report['total_hit']}/{report['total_executable']} lines)"
          + (f" → {out}" if out else ""))


# ─────────────────────────────────────────────────────── M09 HTTP 客户端夹具
ADMIN_PRINCIPAL = {"admin_id": "admin-maker", "tenant_id": "tenant-a",
                   "scopes": ["recon.read", "recon.write"]}
SERVICE_PRINCIPAL = {"service_id": "M08-payout", "scopes": ["recon.attestation.validate"]}


def build_client(connection, *, admin=ADMIN_PRINCIPAL, service=SERVICE_PRINCIPAL,
                 step_up=True, now=None, engine_deps=None):
    """构造带 M09 路由的 ASGI 客户端（请求级 SAVEPOINT，不真提交）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.recon.router import create_router
    from reconkit import FIXED_NOW

    moment = now or FIXED_NOW
    app = FastAPI()
    app.include_router(create_router(
        connection_factory=savepoint_factory(connection),
        admin_resolver=(lambda request: dict(admin)) if admin is not None else None,
        service_resolver=(lambda request: dict(service)) if service is not None else None,
        step_up_verifier=(lambda request: step_up) if step_up is not None else None,
        now_provider=lambda: moment,
        engine_deps=engine_deps,
    ))
    return TestClient(app)


@pytest.fixture
def client(savepoint_conn):
    with build_client(savepoint_conn) as test_client:
        yield test_client


@pytest.fixture
def unauth_client(savepoint_conn):
    """两个鉴权钩子都没接线 → 所有端点必须 401（fail-closed）。"""
    with build_client(savepoint_conn, admin=None, service=None) as test_client:
        yield test_client
