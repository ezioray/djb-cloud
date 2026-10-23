# SPDX-License-Identifier: Apache-2.0
"""tests/identity 测试脚手架（M01）：**只留 pytest fixture**。

helper / 构造器 / 断言工具已移到同目录 ``identitykit.py``（DEV-TESTINFRA）：
单进程全量 pytest 时多个目录的 ``conftest`` 会互相覆盖，测试文件不得再 ``from conftest import ...``。

隔离约定（W1-EXECUTION-PLAN §3）：
- 每个测试进程用**独立 schema**（默认 ``m01_t1_<pid>``，可用 ``M01_T1_SCHEMA`` 覆盖），
  结束时 ``DROP SCHEMA ... CASCADE``；不污染 public，也不复用他人 schema。
- 缺 ``DJB_DSN`` 或库不可达时整个目录 skip（本地不阻断），CI 由 workflow 注入。
- 每个用例跑在**一个事务**里，结束即回滚（快、且天然隔离）：预期失败的断言用
  ``with pytest.raises(...), conn.transaction():`` —— psycopg3 的嵌套事务即 SAVEPOINT，
  失败后连接仍可用。
- 固定时钟：用例用 ``NOW`` 常量 + 显式 ``now=`` 参数，不依赖墙上时间（00-conventions §10）。
"""
from __future__ import annotations

import os
import pathlib
import sys

import psycopg
import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for _path in (str(_HERE), str(_REPO_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from identitykit import (                        # noqa: E402
    NOW,
    SCHEMA_ENV,
    Factory,
    Timeline,
    _connect,
    _create_schema,
    _drop_schema,
    _dsn,
)

from app.identity import clock, migrate          # noqa: E402


@pytest.fixture(scope="session")
def schema_name() -> str:
    return os.environ.get(SCHEMA_ENV) or f"m01_t1_{os.getpid()}"


@pytest.fixture(scope="session")
def db(schema_name: str):
    """会话级：建 schema + 迁移 001/002 + 1xx，结束后 DROP SCHEMA。"""
    try:
        admin = _connect()
    except psycopg.OperationalError as exc:                # pragma: no cover - 环境缺库
        pytest.skip(f"开发库不可达：{exc}")
    try:
        _create_schema(admin, schema_name)
        scoped = _connect(schema_name)
        try:
            migrate.up(scoped)
        finally:
            scoped.close()
        yield {"dsn": _dsn(), "schema": schema_name}
    finally:
        _drop_schema(admin, schema_name)
        admin.close()


@pytest.fixture()
def conn(db):
    """函数级连接：整个用例一个事务，teardown 回滚 → 下个用例仍是空表（无需 TRUNCATE）。"""
    c = _connect(db["schema"], autocommit=False)
    try:
        yield c
    finally:
        try:
            c.rollback()
        finally:
            c.close()


@pytest.fixture()
def now():
    return NOW


@pytest.fixture()
def f(conn, now) -> Factory:
    return Factory(conn, now)


@pytest.fixture(autouse=True)
def clock_now(monkeypatch, now):
    """固定时钟，避免墙钟漂移（00-conventions §10：测试必须确定性）。

    把 app.identity.clock.utcnow 钉到测试时刻 NOW：HTTP 用例与断言（f.moment）共用同一时钟。
    历史上 api 用例走真实墙钟，跨日后扫码 120s TTL / revoke 立即失效 / rotate 的
    revoked_at <= NOW 全部变红；timeline 依赖本 fixture，并在其后用可推进时钟覆盖。
    """
    monkeypatch.setattr(clock, "utcnow", lambda: now)
    return now


@pytest.fixture()
def timeline(monkeypatch, now, clock_now) -> Timeline:
    line = Timeline(now)
    monkeypatch.setattr(clock, "utcnow", line)
    return line


@pytest.fixture()
def api(conn, monkeypatch, clock_now):
    """FastAPI TestClient：把 router 的 ``_connection`` 指向本用例事务连接。

    这样路由里的写操作都落在**同一测试事务**里，teardown 回滚即清空；
    也不需要 app/api.py 参与（T2 不接线，由 Lead 合并时 include）。
    """
    from contextlib import contextmanager

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.identity import router as router_module

    @contextmanager
    def _conn():
        yield conn

    @contextmanager
    def _sink():
        yield conn

    monkeypatch.setattr(router_module, "_connection", _conn)
    monkeypatch.setattr(router_module, "_failure_sink", _sink)
    app = FastAPI()
    app.include_router(router_module.router)
    with TestClient(app) as client:
        yield client
