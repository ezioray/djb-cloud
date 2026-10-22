# SPDX-License-Identifier: Apache-2.0
"""tests/supply 测试脚手架（DEV-M02 T1+T2）。

隔离约定（W1-EXECUTION-PLAN §3）：

* 每个测试进程独立 schema（``m02_t12_<pid>_<hex>``，``M02_T12_SCHEMA`` 可覆盖），
  结束 ``DROP SCHEMA ... CASCADE``；不污染 public，也不复用他人 schema；
* 迁移用 ``psql -f`` 逐文件执行（与 CI / 生产同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑（本地不阻断）；
* 覆盖率（``M02_COVERAGE=1``）必须在导入 ``app.supply`` **之前**启动，
  所以放在本文件顶部（pytest 先导入 conftest，再导入测试模块）；
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

from supplykit import (                                   # noqa: E402
    apply_migrations,
    connect,
    create_schema,
    drop_schema,
    seed_account,
)

from app.supply import clock                              # noqa: E402

SCHEMA_ENV = "M02_T12_SCHEMA"
NOW = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)


def pytest_sessionfinish(session, exitstatus):            # noqa: ARG001
    """覆盖率落盘（``M02_COVERAGE_OUT`` 指定路径；缺省写到会话临时目录）。"""
    if _COVERAGE is None:
        return
    _COVERAGE.stop()
    out = os.environ.get("M02_COVERAGE_OUT")
    write_report(_COVERAGE, out) if out else None


@pytest.fixture(scope="session")
def db() -> dict:
    dsn = os.environ.get("DJB_DSN")
    if not dsn:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）")
    return {"dsn": dsn}


@pytest.fixture(scope="session")
def schema_prefix(db: dict) -> str:                       # noqa: ARG001
    return os.environ.get(SCHEMA_ENV) or f"m02_t12_{os.getpid()}_{uuid.uuid4().hex[:6]}"


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
    """事务型连接：退出回滚（append-only 表不能 TRUNCATE，用事务隔离最干净）。"""
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
    """带 schema 名的连接（需要种夹具 / 断言表内容时用）。"""
    connection = connect(migrated, autocommit=True)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def now() -> datetime:
    return NOW


@pytest.fixture
def account(migrated: str) -> uuid.UUID:
    """一个可绑定的账户（种在 M01 表里；M02 只读 ``v_identity_accounts`` 视图）。"""
    return seed_account(migrated)


@pytest.fixture
def other_account(migrated: str) -> uuid.UUID:
    return seed_account(migrated)


@pytest.fixture
def frozen_account(migrated: str) -> uuid.UUID:
    return seed_account(migrated, state="frozen")


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch):
    """默认把模块时钟钉在 ``NOW``（用例要别的时刻就显式传 ``now=``）。"""
    monkeypatch.setattr(clock, "utcnow", lambda: NOW)
    return NOW


class Factory:
    """测试构造器：显式 ``now=``，不依赖墙上时间。"""

    def __init__(self, connection, moment: datetime) -> None:
        self.conn = connection
        self.moment = moment
        self._seq = 0

    def _fingerprint(self) -> str:
        self._seq += 1
        return f"fp-{self._seq:04d}-{'a' * 24}-{uuid.uuid4().hex[:8]}"

    def register(self, **overrides):
        from app.supply import models

        params = {
            "platform": "linux",
            "hardware_fingerprint": overrides.pop("hardware_fingerprint", self._fingerprint()),
            "client_version": "1.4.0",
            "protocol_version": "1.0.0",
            "capabilities": ["capacity_announcement"],
            "access_modes": ["A1"],
            "region": "cn-east",
            "now": self.moment,
            "trace_id": "trace-test",
        }
        params.update(overrides)
        return models.register(self.conn, **params)

    def active_node(self, *, account_id: uuid.UUID | None = None, **overrides):
        """注册 + 审核通过（+ 可选绑定）→ 一个可用节点。"""
        from app.supply import models

        result = self.register(**overrides)
        node = models.review(self.conn, node_id=result.node.id, decision="approve",
                             reason="测试准入", actor="admin-1", now=self.moment,
                             trace_id="trace-test")
        if account_id is not None:
            code = models.issue_binding_code(self.conn, node_id=node.id,
                                             account_id=account_id, now=self.moment)
            binding, node = models.bind(self.conn, node_id=node.id, code=code.code,
                                        now=self.moment, trace_id="trace-test")
        return node, result.client_key


@pytest.fixture
def factory(conn, now) -> Factory:
    return Factory(conn, now)


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
def api(api_schema: str, monkeypatch, now):
    """构造一个「路由级」测试客户端：连接指向隔离 schema，时钟钉死。

    ``router._connection`` 被替换成指向测试 schema 的连接工厂（app.db 的 deploy 期接线
    在 CI 里没有 DSN，所以测试必须替换它——与 M01 的做法一致）。
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.supply import router as router_module

    def _connection():
        return connect(api_schema, autocommit=False)

    monkeypatch.setattr(router_module, "_connection", _connection)
    monkeypatch.setattr(router_module.clock, "utcnow", lambda: now)

    app = FastAPI()
    app.include_router(router_module.router)
    client = TestClient(app)
    client.schema = api_schema                                # type: ignore[attr-defined]
    client.router = router_module                             # type: ignore[attr-defined]
    yield client
    router_module.set_admin_authenticator(None)


@pytest.fixture
def api_account(api_schema: str) -> uuid.UUID:
    return seed_account(api_schema)


@pytest.fixture
def admin_hook(api):
    """默认管理面主体（step-up 已通过）；用例可覆盖。"""
    from app.supply import router as router_module

    principal = {"admin_id": "admin-1", "step_up": True}

    def _authenticator(request):                              # noqa: ARG001
        if not request.headers.get("X-Admin-Step-Up"):
            return {"admin_id": "admin-1", "step_up": False}
        return principal

    router_module.set_admin_authenticator(_authenticator)
    return principal
