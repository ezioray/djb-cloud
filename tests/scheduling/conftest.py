# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/scheduling 测试脚手架（DEV-M04 T1+T2）。

隔离约定（W1-EXECUTION-PLAN §3）：

* 每个测试进程独立 schema（``m04_t12_<pid>_<hex>``，``M04_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不污染 public，也不复用他人 schema；
* 迁移用 ``psql -f`` 逐文件执行（与 CI / 生产同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑（本地不阻断）；
* 覆盖率（``M04_COVERAGE=1``）必须在导入 ``app.scheduling`` **之前**启动；
* 固定时钟：用例用 ``NOW`` 常量 + 显式 ``now=`` 参数，不依赖墙上时间（00-conventions §10）。
"""
from __future__ import annotations

import os
import pathlib
import sys
import uuid
from datetime import datetime, timezone

import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for path in (str(_HERE), str(_REPO_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from coverkit import maybe_start, write_report            # noqa: E402  (必须在 app.* 之前)

_COVERAGE = maybe_start()

from schedulingkit import (                               # noqa: E402
    NOW,
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
    seed_capacity,
    seed_node,
    seed_tenant,
)

from app.scheduling import clock                          # noqa: E402

SCHEMA_ENV = "M04_T12_SCHEMA"


def pytest_sessionfinish(session, exitstatus):            # noqa: ARG001
    """覆盖率落盘（``M04_COVERAGE_OUT`` 指定路径；缺省不写）。"""
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M04_COVERAGE_OUT")
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
    return os.environ.get(SCHEMA_ENV) or f"m04_t12_{os.getpid()}_{uuid.uuid4().hex[:6]}"


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
    """事务型连接：退出回滚（只追加表不能 TRUNCATE，用事务隔离最干净）。"""
    connection = connect(migrated, autocommit=False)
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


@pytest.fixture
def schema_conn(migrated: str):                            # noqa: ARG001
    """autocommit 连接（需要种夹具 / 断言表内容时用）。"""
    connection = connect(migrated, autocommit=True)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def now() -> datetime:
    return NOW


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch):
    """默认把模块时钟钉在 ``NOW``（用例要别的时刻就显式传 ``now=``）。"""
    monkeypatch.setattr(clock, "utcnow", lambda: NOW)
    return NOW


@pytest.fixture
def tenant(migrated: str) -> uuid.UUID:
    """一个租户（M01 表；M04 只经注入 provider 使用）。"""
    return seed_tenant(migrated)


@pytest.fixture
def other_tenant(migrated: str) -> uuid.UUID:
    return seed_tenant(migrated)


class Factory:
    """测试构造器：显式 ``now=``，不依赖墙上时间。"""

    def __init__(self, connection, moment: datetime, schema: str) -> None:
        self.conn = connection
        self.schema = schema
        self.moment = moment
        self._seq = 0

    # ------------------------------------------------------------------ 上游夹具
    def node(self, node_id: str | None = None, *, state: str = "active",
             last_seen_at: datetime | None = None, account_id: uuid.UUID | None = None,
             tenant_id: uuid.UUID | None = None, region: str = "cn-east") -> str:
        self._seq += 1
        identifier = node_id or f"n_{self._seq:03d}_{uuid.uuid4().hex[:6]}"
        seed_node(self.schema, identifier, account_id=account_id, tenant_id=tenant_id,
                  state=state, region=region, last_seen_at=last_seen_at or self.moment)
        return identifier

    def capacity(self, node_id: str, **kwargs) -> None:
        seed_capacity(self.schema, node_id, announced_at=self.moment, **kwargs)

    # ------------------------------------------------------------------ 报价 / 出价
    def quote(self, node_id: str, *, access: str = "A1", model: str = "m1",
              unit: str = "token", low: int = 800, high: int | None = 1_000,
              ttl_s: int = 600, now: datetime | None = None, trace_id: str = "trace-test",
              ensure_node: bool = True):
        """写一条报价；``ensure_node=True`` 时先确保节点在 M02 只读视图里存在。"""
        from app.scheduling import quotes

        if ensure_node:
            self.node(node_id)
        return quotes.register(self.conn, node_id=node_id, access=access, model=model,
                               unit=unit, ask_price_minor=low, price_max_minor=high,
                               ttl_s=ttl_s, now=now or self.moment, trace_id=trace_id)

    def bid(self, tenant_id: uuid.UUID, *, model: str = "m1", low: int = 600,
            high: int | None = 950, strategy: str | None = None, window_s: int = 3_600,
            now: datetime | None = None):
        from app.scheduling import bids

        return bids.register(self.conn, tenant_id=tenant_id, model=model,
                             min_price_minor=low, max_price_minor=high, strategy=strategy,
                             window_seconds=window_s, now=now or self.moment,
                             trace_id="trace-test")

    def route(self, tenant_id: uuid.UUID, *, model: str = "m1", kind: str = "realtime",
              max_price_minor: int | None = None, trace_id: str = "trace-1",
              attempt_no: int = 1, required_access: tuple[str, ...] = ()):
        from app.scheduling import candidates

        return candidates.RouteInput(model=model, kind=kind, tenant_id=tenant_id,
                                     trace_id=trace_id, attempt_no=attempt_no,
                                     max_price_minor=max_price_minor,
                                     required_access=required_access)


@pytest.fixture
def factory(conn, now, migrated) -> Factory:
    return Factory(conn, now, migrated)


@pytest.fixture(scope="module")
def api_schema(db: dict, schema_prefix: str) -> str:       # noqa: ARG001
    """路由级用例专用 schema（HTTP 路径会真提交，与「事务回滚」域用例分开最干净）。"""
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

    from app.scheduling import router as router_module

    app = FastAPI()
    app.include_router(router_module.router)

    def _connection():
        return connect(api_schema, autocommit=False)

    original = router_module._connection
    router_module._connection = _connection
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        router_module._connection = original
        for name in ("node", "user", "internal", "admin"):
            getattr(router_module, f"set_{name}_authenticator")(None)


@pytest.fixture
def api_tenant(api_schema: str) -> uuid.UUID:
    return seed_tenant(api_schema, uuid.uuid4())


@pytest.fixture
def auth(client, api_tenant, api_schema):
    """注入四个鉴权钩子（默认 fail-closed，用例里显式接线）。"""
    from app.scheduling import router as router_module

    node_id = "n_api_001"
    seed_node(api_schema, node_id, tenant_id=api_tenant, account_id=uuid.uuid4())
    seed_capacity(api_schema, node_id, announced_at=NOW)

    router_module.set_node_authenticator(
        lambda request: {"node_id": request.headers.get("X-Client-Key", node_id)})
    router_module.set_user_authenticator(
        lambda request: {"tenant_id": api_tenant, "account_id": str(uuid.uuid4())})
    router_module.set_internal_authenticator(
        lambda request: {"caller": "M03", "tenant_id": api_tenant,
                         "platform_concurrency": 8, "terminal_concurrency": 4})
    router_module.set_admin_authenticator(
        lambda request: {"admin_id": "admin-1",
                         "step_up": bool(request.headers.get("X-Admin-Step-Up"))})
    return {"tenant_id": api_tenant, "node_id": node_id, "schema": api_schema}


__all__ = ["NOW", "Factory"]
