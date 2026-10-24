# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/admin 测试脚手架（DEV-M14）。

两套 schema（NAS 上一次全量迁移 ~20s，能省就省）：

* ``migrated``（session 级共享）：读 + 事务内写用例共用，靠**事务回滚 / SAVEPOINT** 隔离；
* ``fresh``（用例级全新）：空库 / 迁移幂等 / 回滚 / CLI 用例（必须真 DDL）。

覆盖率（``M14_COVERAGE=1``）必须在导入 ``app.data_gov`` **之前**启动 → 放在本文件顶部。
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

from admin_kit import (                              # noqa: E402
    ADMIN_PRINCIPAL,
    AUDITOR_PRINCIPAL,
    FIXED_NOW,
    NON_ADMIN_PRINCIPAL,
    OTHER_TENANT_PRINCIPAL,
    SECOND_ADMIN,
    RecordingSink,
    apply_migrations,
    build_client,
    connect,
    create_schema,
    drop_schema,
)

SCHEMA_ENV = "M14_SCHEMA"


@pytest.fixture(scope="session")
def db() -> str:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return dsn


@pytest.fixture(scope="session")
def schema_prefix(db: str) -> str:
    return os.environ.get(SCHEMA_ENV) or f"m14_t_{os.getpid()}_{uuid.uuid4().hex[:6]}"


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
    """session 级共享 schema：001→1304 只跑一次。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
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


@pytest.fixture
def sink() -> RecordingSink:
    return RecordingSink()


@pytest.fixture
def client(savepoint_conn):
    with build_client(savepoint_conn, principal=ADMIN_PRINCIPAL) as test_client:
        yield test_client


@pytest.fixture
def readonly_client(savepoint_conn):
    with build_client(savepoint_conn, principal=AUDITOR_PRINCIPAL) as test_client:
        yield test_client


@pytest.fixture
def nonadmin_client(savepoint_conn):
    with build_client(savepoint_conn, principal=NON_ADMIN_PRINCIPAL) as test_client:
        yield test_client


@pytest.fixture
def unauth_client(savepoint_conn):
    """鉴权钩子未接线 → 所有端点必须 401（fail-closed）。"""
    with build_client(savepoint_conn, principal=False) as test_client:
        yield test_client


@pytest.fixture
def no_stepup_client(savepoint_conn):
    with build_client(savepoint_conn, principal=ADMIN_PRINCIPAL, step_up=False) as test_client:
        yield test_client


@pytest.fixture
def second_client(savepoint_conn):
    with build_client(savepoint_conn, principal=SECOND_ADMIN) as test_client:
        yield test_client


@pytest.fixture
def other_tenant_client(savepoint_conn):
    with build_client(savepoint_conn, principal=OTHER_TENANT_PRINCIPAL) as test_client:
        yield test_client


def pytest_sessionfinish(session, exitstatus):       # noqa: ARG001
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M14_COVERAGE_OUT")
    report = write_report(_COVERAGE, out) if out else _COVERAGE.report()
    print(f"\n[M14 coverage] app/data_gov = {report['percent']}% "
          f"({report['total_hit']}/{report['total_executable']} lines)"
          + (f" → {out}" if out else ""))
    if os.environ.get("M14_COVERAGE_GATE") == "1" and report["percent"] < 80.0:
        print(f"[M14 coverage] GATE FAIL：{report['percent']}% < 80%")
        session.exitstatus = 1
