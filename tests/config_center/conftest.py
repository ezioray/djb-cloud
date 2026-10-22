# SPDX-License-Identifier: Apache-2.0
"""tests/config_center 测试脚手架（DEV-M10 T1+T2）。

隔离约定：
* 每个测试进程独立 schema（``m10_t12_<pid>_<hex>``，``M10_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不污染 public，也不复用他人 schema；
* 迁移用 ``psql -f`` 逐文件执行（与 CI / 生产同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑（本地不阻断）；
* 覆盖率（``M10_COVERAGE=1``）必须在导入 ``app.config_center`` 之前启动，
  所以放在本文件顶部（pytest 先导入 conftest，再导入测试模块）。
"""
from __future__ import annotations

import os
import pathlib
import sys
import uuid

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for path in (str(_HERE), str(_REPO_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from coverkit import maybe_start, write_report   # noqa: E402  (必须在 app.* 之前)

_COVERAGE = maybe_start()

from configkit import (                        # noqa: E402
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
)

SCHEMA_ENV = "M10_T12_SCHEMA"


@pytest.fixture(scope="session")
def db() -> str:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return dsn


@pytest.fixture(scope="session")
def schema_prefix(db: str) -> str:
    return os.environ.get(SCHEMA_ENV) or f"m10_t12_{os.getpid()}_{uuid.uuid4().hex[:6]}"


@pytest.fixture
def schema(db: str, schema_prefix: str) -> str:
    """空 schema（未跑任何迁移）—— 空库 / 升级 / 回滚三跑用。"""
    name = f"{schema_prefix}_{uuid.uuid4().hex[:6]}"
    create_schema(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture(scope="module")
def migrated(db: str, schema_prefix: str) -> str:
    """模块级共享 schema：迁移只跑一次（60+ 用例不重复建库，避免拖慢 NAS）。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """事务型连接：退出回滚（append-only 表不能 TRUNCATE，用事务隔离最干净）。"""
    connection = connect(migrated, autocommit=False)
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


def pytest_sessionfinish(session, exitstatus):   # noqa: ARG001
    """覆盖率落盘（``M10_COVERAGE_OUT``）。"""
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M10_COVERAGE_OUT")
    report = write_report(_COVERAGE, out) if out else _COVERAGE.report()
    print(f"\n[M10 coverage] app/config_center = {report['percent']}% "
          f"({report['total_hit']}/{report['total_executable']} lines)"
          + (f" → {out}" if out else ""))
