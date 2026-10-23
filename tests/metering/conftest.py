# SPDX-License-Identifier: Apache-2.0
"""tests/metering 测试脚手架（DEV-M05 T1+T2）。

隔离约定（W1-EXECUTION-PLAN §3）：

* 每个测试进程独立 schema（``m05_t12_<pid>_<hex>``，``M05_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不污染 public，也不复用他人 schema；
* 迁移用 ``psql -f`` 逐文件执行（与 CI / 生产同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑（本地不阻断）；
* 覆盖率（``M05_COVERAGE=1``）必须在导入 ``app.metering`` **之前**启动；
* 固定时钟：用例用 ``NOW`` 常量 + 显式 ``now=`` 参数，不依赖墙上时间（00-conventions §10）。
"""
from __future__ import annotations

import os
import pathlib
import sys
import uuid
from datetime import datetime

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for path in (str(_HERE), str(_REPO_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from coverkit import maybe_start, write_report            # noqa: E402  (必须在 app.* 之前)

_COVERAGE = maybe_start()

from meterkit import (                                    # noqa: E402
    NOW,
    TEST_CONSUMER_KEY,
    TEST_PROVIDER_KEY,
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
    seed_account,
    seed_node,
)

from app.metering import clock, config_source, receipts, signing   # noqa: E402

SCHEMA_ENV = "M05_T12_SCHEMA"


def pytest_sessionfinish(session, exitstatus):            # noqa: ARG001
    """覆盖率落盘（``M05_COVERAGE_OUT`` 指定路径；缺省不写）。"""
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M05_COVERAGE_OUT")
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
    return os.environ.get(SCHEMA_ENV) or f"m05_t12_{os.getpid()}_{uuid.uuid4().hex[:6]}"


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
    """模块级共享 schema：迁移只跑一次（用例之间用随机 id 隔离，避免拖慢 NAS）。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """autocommit 连接：逐条提交（受理路径本身用保存点，语义与生产一致）。"""
    connection = connect(migrated, autocommit=True)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    """默认把双签密钥钉在测试夹具上（用例要坏密钥就显式传参）。"""
    keys = signing.SignatureKeys(TEST_PROVIDER_KEY, TEST_CONSUMER_KEY)
    monkeypatch.setattr(signing, "_keys_provider", lambda: keys, raising=False)
    return keys


@pytest.fixture(autouse=True)
def _config(monkeypatch):
    """默认配置用 §8.1 默认值（不接 M10），24h 窗口生效。"""
    monkeypatch.setattr(config_source, "_config_provider", None, raising=False)
    return config_source.snapshot()


@pytest.fixture(autouse=True)
def _price_provider(monkeypatch):
    """默认不注入成交价（T3 才接 M04）；用例要校验金额时显式 set。"""
    monkeypatch.setattr(receipts, "_price_provider", None, raising=False)


@pytest.fixture
def now() -> datetime:
    return NOW


@pytest.fixture
def account(migrated: str) -> uuid.UUID:
    """一个 M01 需方账户（M05 只经注入 / 软引用使用）。"""
    return seed_account(migrated)


@pytest.fixture
def node(migrated: str) -> str:
    """一个 M02 在线节点（M05 只经 ``v_supply_node_snapshot`` 只读校验）。"""
    return seed_node(migrated)


@pytest.fixture(scope="module")
def api_schema(db: dict, schema_prefix: str) -> str:      # noqa: ARG001
    """路由级用例专用 schema（HTTP 路径会真提交，与域用例分开最干净）。

    模块级：迁移只跑一次（每个用例用**独立账户 / 独立节点**做隔离，绝不复用他人数据）。
    """
    name = f"{schema_prefix}_api_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def client(api_schema: str):
    """TestClient + 把 router 的 ``_connection`` 指到隔离 schema。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.metering import router as router_module

    app = FastAPI()
    app.include_router(router_module.router)

    def _connection():
        return connect(api_schema, autocommit=True)

    original = router_module._connection
    router_module._connection = _connection
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        router_module._connection = original
        router_module.set_node_authenticator(None)
        router_module.set_user_authenticator(None)
        router_module.set_admin_authenticator(None)


@pytest.fixture
def api_account(api_schema: str) -> uuid.UUID:
    """每个用例一个独立账户：汇总 / 明细按 account_id 天然隔离。"""
    return seed_account(api_schema)


@pytest.fixture
def api_node(api_schema: str) -> str:
    """每个用例一个独立节点（随机 id，避免跨用例串味）。"""
    return seed_node(api_schema, f"n_api_{uuid.uuid4().hex[:10]}")


@pytest.fixture
def auth(client, api_account, api_node, api_schema):      # noqa: ARG001
    """注入两个鉴权钩子（默认 fail-closed，用例里显式接线）。"""
    from app.metering import router as router_module

    router_module.set_node_authenticator(
        lambda request: {"node_id": request.headers.get("X-Client-Key", api_node)})
    router_module.set_user_authenticator(
        lambda request: {"account_id": str(api_account), "tenant_id": str(api_account)})
    router_module.set_admin_authenticator(
        lambda request: {"admin_id": "ops-1",
                         "step_up": bool(request.headers.get("X-Admin-Step-Up"))})
    return {"account_id": api_account, "node_id": api_node, "schema": api_schema}


__all__ = ["NOW"]
