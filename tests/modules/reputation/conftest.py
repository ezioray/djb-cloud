# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/modules/reputation 测试脚手架（DEV-M07）。

隔离约定（W1-EXECUTION-PLAN §3）：

* 每个测试进程独立 schema（``m07_t5_<pid>_<hex>``，``M07_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不污染 public，也不复用他人 schema；
* 迁移按数字序逐文件执行（与 CI / 生产同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑（本地不阻断）；
* 覆盖率（``M07_COVERAGE=1``）必须在导入 ``app.reputation`` **之前**启动；
* 固定时钟：用例用 ``NOW`` 常量 + 显式 ``now=`` 参数，不依赖墙上时间（00-conventions §10）。
"""
from __future__ import annotations

import os
import pathlib
import sys
import uuid

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[2]
for path in (str(_HERE), str(_REPO_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from coverkit import maybe_start, write_report            # noqa: E402  (必须在 app.* 之前)

_COVERAGE = maybe_start()

from repukit import (                                     # noqa: E402
    NOW,
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
)

SCHEMA_ENV = "M07_SCHEMA"


def pytest_sessionfinish(session, exitstatus):            # noqa: ARG001
    """覆盖率落盘（``M07_COVERAGE_OUT`` 指定路径；缺省不写）。"""
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M07_COVERAGE_OUT")
    if out:
        write_report(_COVERAGE, out)


@pytest.fixture(scope="session")
def db() -> dict:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return {"dsn": dsn}


@pytest.fixture(scope="session")
def schema_prefix(db: dict) -> str:                       # noqa: ARG001
    return os.environ.get(SCHEMA_ENV) or f"m07_t5_{os.getpid()}_{uuid.uuid4().hex[:6]}"


@pytest.fixture
def schema(db: dict, schema_prefix: str) -> str:          # noqa: ARG001
    """空 schema（未跑任何迁移）—— 空库 / 升级 / 回滚三跑用。"""
    name = f"{schema_prefix}_{uuid.uuid4().hex[:6]}"
    create_schema(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture(scope="module")
def migrated(db: dict, schema_prefix: str) -> str:         # noqa: ARG001
    """模块级共享 schema：迁移只跑一次（用例之间用随机账户隔离，避免拖慢 NAS）。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """非 autocommit 连接：与生产同款（成功提交、异常回滚）。"""
    connection = connect(migrated)
    try:
        yield connection
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


@pytest.fixture
def connection_factory(migrated: str):
    """路由注入用的连接工厂：每次调用返回一个独立连接（``with`` 退出即提交）。"""
    created: list = []

    def factory():
        connection = connect(migrated)
        created.append(connection)
        return connection

    try:
        yield factory
    finally:
        for connection in created:
            try:
                connection.close()
            except Exception:                             # pragma: no cover - 清理容错
                pass


@pytest.fixture
def now():
    return NOW
