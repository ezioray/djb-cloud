# SPDX-License-Identifier: AGPL-3.0-or-later
"""tests/identity 的**唯一 helper 模块**（M01 测试工具；conftest 只留 pytest fixture）。

背景（DEV-TESTINFRA）：测试文件不得再 ``from conftest import ...`` —— 单进程全量 pytest 时，
多个目录的 ``conftest`` 会互相覆盖（sys.modules 里只有一个 conftest），跨目录收集必 ImportError。
因此纯 helper / 构造器 / HTTP 客户端 / 常量都集中到本模块，conftest 与测试文件各自从这里导入。

内容：
* 常量：REPO_ROOT / MIGRATIONS_DIR / SCHEMA_ENV / NOW / IDENTITY_TABLES；
* 连接与 schema 工具：_dsn / _connect / _create_schema / _drop_schema / scratch_schema；
* 构造器：Factory（用户 / 组织 / 账户 / Key / 会话 / 冻结）、Timeline（可推进时钟）；
* 断言小工具：rows / scalar / state_events / all_events / account_state / backdate_account；
* HTTP：bearer / error_of（客户端本体是 conftest 的 ``api`` fixture，需要 conn 与 monkeypatch）。

约定：本模块**不 import conftest**（防循环）；缺 ``DJB_DSN`` 时由 conftest 的 fixture 统一 skip。
"""
from __future__ import annotations

import contextlib
import os
import pathlib
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.identity import clock, models, state

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "migrations"
SCHEMA_ENV = "M01_T1_SCHEMA"
NOW = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)

IDENTITY_TABLES = (
    "identity_outbox", "tenant_quotas", "role_bindings", "sessions",
    "org_members", "user_accounts", "orgs", "users", "api_keys",
)


# --------------------------------------------------------------------------- 连接
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


class Timeline:
    """可推进的测试时钟（替换 ``clock.utcnow``，保持测试确定性）。"""

    def __init__(self, moment: datetime) -> None:
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, **kwargs) -> datetime:
        self.moment = self.moment + timedelta(**kwargs)
        return self.moment


# --------------------------------------------------------------------------- 断言小工具
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


# --------------------------------------------------------------------------- HTTP
def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def error_of(response) -> dict:
    body = response.json()
    assert set(body) == {"error"}, body
    return body["error"]


__all__ = [
    "REPO_ROOT", "MIGRATIONS_DIR", "SCHEMA_ENV", "NOW", "IDENTITY_TABLES",
    "_dsn", "_connect", "_create_schema", "_drop_schema", "scratch_schema", "apply_files",
    "Factory", "Timeline",
    "rows", "scalar", "state_events", "all_events", "account_state", "backdate_account",
    "bearer", "error_of", "clock",
]
