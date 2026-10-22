# SPDX-License-Identifier: Apache-2.0
"""tests/identity 测试脚手架（DEV-M01-T1）。

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

import contextlib
import os
import pathlib
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.identity import clock, migrate, models, state

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "migrations"
SCHEMA_ENV = "M01_T1_SCHEMA"
NOW = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)

IDENTITY_TABLES = (
    "identity_outbox", "tenant_quotas", "role_bindings", "sessions",
    "org_members", "user_accounts", "orgs", "users", "api_keys",
)


def _dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        pytest.skip("缺 DJB_DSN：开发库未注入（CI 会提供）", allow_module_level=False)
    return value


def _connect(schema: str | None = None, *, autocommit: bool = True) -> psycopg.Connection:
    """测试专用连接：固定 search_path + 关掉 synchronous_commit（NAS 盘 fsync 很慢）。

    ``synchronous_commit=off`` 只影响本测试会话的持久性保证（崩溃可能丢最后几条提交），
    测试 schema 内可接受；不写 public，也不改服务器配置。
    """
    opts = ["-c synchronous_commit=off"]
    if schema:
        opts.append(f"-c search_path={schema}")
    return psycopg.connect(_dsn(), autocommit=autocommit, options=" ".join(opts))


def _create_schema(conn: psycopg.Connection, schema: str) -> None:
    conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    conn.execute(f"CREATE SCHEMA {schema}")


def _drop_schema(conn: psycopg.Connection, schema: str) -> None:
    conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")


@pytest.fixture(scope="session")
def schema_name() -> str:
    return os.environ.get(SCHEMA_ENV) or f"m01_t1_{os.getpid()}"


@pytest.fixture(scope="session")
def db(schema_name: str):
    """会话级：建 schema + 迁移 001/002 + 1xx，结束后 DROP SCHEMA。"""
    try:
        admin = _connect()
    except psycopg.OperationalError as exc:                   # pragma: no cover - 环境缺库
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
def now() -> datetime:
    return NOW


# --------------------------------------------------------------------------- 构造器
class Factory:
    """测试用构造器：显式 ``now=``，不依赖墙上时间。"""

    def __init__(self, conn: psycopg.Connection, moment: datetime) -> None:
        self.conn = conn
        self.moment = moment
        self._seq = 0

    def user(self, *, email: str | None = None, phone: str | None = None,
             display_name: str | None = None) -> models.User:
        self._seq += 1
        if email is None and phone is None:
            email = f"u{self._seq}@example.com"
        return models.create_user(self.conn, email=email, phone=phone,
                                  display_name=display_name, now=self.moment)

    def org(self, *, type: str = "team", seats_limit: int | None = None,
            name: str | None = None) -> models.Org:
        self._seq += 1
        return models.create_org(self.conn, type=type, seats_limit=seats_limit,
                                 name=name or f"org-{self._seq}", now=self.moment)

    def account(self, *, type: str = "personal", org: models.Org | None = None,
                user: models.User | None = None,
                policy_version: str | None = "v4.0") -> models.Account:
        user = user or self.user()
        return models.create_account(self.conn, user_id=user.id, type=type,
                                     org_id=org.id if org else None,
                                     policy_version=policy_version, now=self.moment)

    def normal(self, **kwargs) -> models.Account:
        """直接建到 ``normal``（跳过验证）——只用于非「注册验证」类用例。"""
        account = self.account(**kwargs)
        return state.verify(self.conn, account.id, now=self.moment)

    def login_ready(self, *, password: str = "S3cret!", email: str | None = None,
                    policy_version: str | None = "v4.0") -> tuple[models.User, models.Account]:
        """建一个可登录账户：user（带口令）+ personal 账户（normal）。"""
        self._seq += 1
        user = models.create_user(self.conn, email=email or f"login{self._seq}@example.com",
                                  password=password, now=self.moment)
        account = models.create_account(self.conn, user_id=user.id,
                                        policy_version=policy_version, now=self.moment)
        state.verify(self.conn, account.id, now=self.moment)
        return user, account

    def key(self, account: models.Account, **kwargs) -> tuple[models.ApiKey, str]:
        return models.create_api_key(self.conn, account_id=account.id, now=self.moment, **kwargs)

    def session(self, account: models.Account, **kwargs) -> models.Session:
        return models.create_session(self.conn, account_id=account.id, now=self.moment, **kwargs)

    def freeze(self, account: models.Account, *, days: int = 7, **kwargs) -> models.Account:
        return state.freeze(
            self.conn, account.id, until=self.moment + timedelta(days=days),
            reason=kwargs.pop("reason", "risk_case_1"),
            approval_chain=kwargs.pop("approval_chain", [{"approver": "risk-1", "at": "t0"}]),
            actor_id=kwargs.pop("actor_id", uuid.uuid4()), now=self.moment, **kwargs)


@pytest.fixture()
def f(conn, now) -> Factory:
    return Factory(conn, now)


# --------------------------------------------------------------------------- 工具
def rows(conn: psycopg.Connection, sql: str, params=()) -> list[dict]:
    cur = conn.execute(sql, params)
    names = [d.name for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def scalar(conn: psycopg.Connection, sql: str, params=()):
    return conn.execute(sql, params).fetchone()[0]


def state_events(conn: psycopg.Connection, account_id: uuid.UUID) -> list[dict]:
    return rows(conn,
                "SELECT type, payload, idempotency_key FROM identity_outbox "
                "WHERE type = 'account.state.changed' AND aggregate_id = %s ORDER BY seq",
                (str(account_id),))


def all_events(conn: psycopg.Connection) -> list[dict]:
    return rows(conn, "SELECT type, aggregate_id, payload, idempotency_key "
                      "FROM identity_outbox ORDER BY seq")


def account_state(conn: psycopg.Connection, account_id: uuid.UUID) -> str:
    return scalar(conn, "SELECT state FROM user_accounts WHERE id = %s", (account_id,))


def backdate_account(conn: psycopg.Connection, account_id: uuid.UUID,
                     *, days: int) -> None:
    """把 created_at 拨回（模拟 7 天未验证的存量数据）。"""
    conn.execute("UPDATE user_accounts SET created_at = created_at - make_interval(days => %s)"
                 " WHERE id = %s", (days, account_id))


@contextlib.contextmanager
def scratch_schema(base: str, suffix: str):
    """独立 schema 上下文（空库 / 升级 / 回滚三跑用），结束即 DROP。"""
    name = f"{base}_{suffix}"
    admin = _connect()
    try:
        _create_schema(admin, name)
        scoped = _connect(name)
        try:
            yield scoped, name
        finally:
            scoped.close()
    finally:
        _drop_schema(admin, name)
        admin.close()


def apply_files(conn: psycopg.Connection, names) -> list[str]:
    for name in names:
        conn.execute((MIGRATIONS_DIR / name).read_text(encoding="utf-8"))
    return list(names)


# --------------------------------------------------------------------------- T2：时钟与 HTTP
class Timeline:
    """可推进的测试时钟（替换 ``clock.utcnow``，保持测试确定性）。"""

    def __init__(self, moment: datetime) -> None:
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, **kwargs) -> datetime:
        self.moment = self.moment + timedelta(**kwargs)
        return self.moment


@pytest.fixture()
def timeline(monkeypatch, now) -> Timeline:
    line = Timeline(now)
    monkeypatch.setattr(clock, "utcnow", line)
    return line


@pytest.fixture()
def api(conn, monkeypatch):
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


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def error_of(response) -> dict:
    body = response.json()
    assert set(body) == {"error"}, body
    return body["error"]
