# SPDX-License-Identifier: Apache-2.0
"""tests/gateway 测试脚手架（DEV-M03 T1+T2）。

隔离约定（W1-EXECUTION-PLAN §3）：

* 每个测试进程独立 schema（``m03_t12_<pid>_<hex>``，``M03_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不污染 public，也不复用他人 schema；
* 迁移用 ``psql -f`` 逐文件执行（与 CI / 生产同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑（本地不阻断）；
* 覆盖率（``M03_COVERAGE=1``）必须在导入 ``app.gateway`` **之前**启动；
* 固定时钟：用例用 ``NOW`` 常量 + 显式 ``now=`` 参数，不依赖墙上时间（00-conventions §10）；
* 上游模块一律用假 provider（``gatewaykit.Fake*``），测试不 import 其它业务模块。
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

from coverkit import maybe_start, write_report            # noqa: E402  (必须在 app.* 之前)

_COVERAGE = maybe_start()

from gatewaykit import (                                  # noqa: E402
    NOW,
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
)

from app.gateway import clock, config_source, models, providers, ratelimit   # noqa: E402

SCHEMA_ENV = "M03_T12_SCHEMA"


def pytest_sessionfinish(session, exitstatus):            # noqa: ARG001
    """覆盖率落盘（``M03_COVERAGE_OUT`` 指定路径；缺省不写）。"""
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M03_COVERAGE_OUT")
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
    return os.environ.get(SCHEMA_ENV) or f"m03_t12_{os.getpid()}_{uuid.uuid4().hex[:6]}"


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
    """模块级共享 schema：迁移只跑一次（用例不重复建库，避免拖慢 NAS）。"""
    name = f"{schema_prefix}_shared_{uuid.uuid4().hex[:4]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@pytest.fixture
def conn(migrated: str):
    """事务型连接：退出回滚（本模块表有只追加护栏，用事务隔离最干净）。"""
    connection = connect(migrated, autocommit=False)
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


@pytest.fixture
def now():
    return NOW


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch):
    """默认把模块时钟钉在 ``NOW``（用例要别的时刻就显式传 ``now=``）。"""
    monkeypatch.setattr(clock, "utcnow", lambda: NOW)
    return NOW


@pytest.fixture(autouse=True)
def _clean_wiring():
    """每个用例前后复位注入点与限流窗口（默认 fail-closed）。"""
    providers.reset_providers()
    config_source.set_provider(None)
    ratelimit.LIMITER.reset()
    yield
    providers.reset_providers()
    config_source.set_provider(None)
    ratelimit.LIMITER.reset()


@pytest.fixture
def principal() -> models.Principal:
    """一个可用的调用主体（不接 M01，直接构造）。"""
    return models.coerce_principal({
        "account_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()),
        "api_key_id": 7, "account_state": "normal", "policy_version": "pv-1",
        "quotas": {"policy_version": "pv-1", "effective": {"qps": 5}},
    })


@pytest.fixture
def wired(principal):
    """把三个必需 provider 接上（鉴权 / 路由 / 上游），返回可检查的假实现。"""
    from gatewaykit import FakeAuth, FakeNode, FakeRoute, FakeUsage

    auth = FakeAuth(account_id=uuid.UUID(principal.account_id),
                    tenant_id=uuid.UUID(principal.tenant_id), api_key_id=principal.api_key_id)
    route = FakeRoute()
    node = FakeNode()
    usage = FakeUsage()
    providers.set_auth_provider(auth)
    providers.set_route_provider(route)
    providers.set_node_client(node)
    providers.set_usage_provider(usage)
    return {"auth": auth, "route": route, "node": node, "usage": usage}
