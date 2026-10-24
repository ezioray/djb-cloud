# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-M07 测试工具：迁移执行、schema 隔离、账户夹具、路由客户端、结构指纹。

只读契约（本文件不改实现代码）：

* 迁移文件是唯一 DDL 来源，测试只按数字序执行 ``migrations/*.sql``，**不在 Python 里手写建表**；
* 每个 schema 独立（``m07_t5_<pid>_<hex>``），结束 ``DROP SCHEMA ... CASCADE``；
  不读写 public，也不碰别人的 schema；
* COP 账户一律用**既有** ``app.points.open_account`` 建（不绕过唯一账本自造账户档案）；
* 固定时钟：``NOW`` 常量 + 显式 ``now=`` 参数，不依赖墙上时间（00-conventions §10）；
* 结构指纹只比 ``information_schema`` / ``pg_indexes`` / ``pg_constraint``，与数据无关。
"""
from __future__ import annotations

import os
import pathlib
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg

ROOT = pathlib.Path(__file__).resolve().parents[3]
MIGRATIONS_DIR = ROOT / "migrations"

M07_MIGRATIONS = (
    "701_reputation_scores.sql",
    "702_reputation_events.sql",
    "704_invites.sql",
    "705_reward_grants.sql",
    "706_reputation_outbox.sql",
    "707_m07_cop_ledger_view.sql",
)
M07_TABLES = ("reputation_scores", "reputation_events", "invites", "reward_grants",
              "reputation_outbox")
M07_VIEWS = ("v_m07_cop_ledger", "v_m07_cop_status")
#: 只读依赖、**不允许** M07 写的上游基表（架构门禁反例清单）
UPSTREAM_BASE_TABLES = ("accounts", "journal_entry", "ledger_entry", "usage_records",
                        "config_items", "users", "user_accounts")
#: 验收 1：7xx 前后结构必须逐字节一致的表
FINGERPRINT_TABLES = ("points_account", "points_policy", "points_journal", "points_ledger",
                      "points_transfer")

#: 固定时钟（UTC 04:00，避开日界）
NOW = datetime(2026, 10, 23, 4, 0, 0, tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────── 连接与迁移
def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（见 product/v4/modules/W1-EXECUTION-PLAN.md §3）")
    return value


def _admin_connect() -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m07-t5-tests")


def connect(schema: str, autocommit: bool = False) -> psycopg.Connection:
    quoted = '"' + schema.replace('"', '""') + '"'          # 防大小写折叠
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m07-t5-tests",
                           options=f"-c search_path={quoted} -c synchronous_commit=off")


def create_schema(name: str) -> None:
    conn = _admin_connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '10s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
            cur.execute(f'CREATE SCHEMA "{name}"')
    finally:
        conn.close()


def drop_schema(name: str) -> None:
    conn = _admin_connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off")
            cur.execute("SET lock_timeout = '15s'")
            cur.execute("SET statement_timeout = '180s'")
            cur.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
    finally:
        conn.close()


def migration_number(path: pathlib.Path) -> int:
    return int(path.name.split("_", 1)[0])


def migration_files() -> list[pathlib.Path]:
    files = list(MIGRATIONS_DIR.glob("*.sql"))
    return sorted(files, key=migration_number)


def in_m07_segment(path: pathlib.Path) -> bool:
    """是否属于 M07 独占段 700–799（注意：1xxx / 9xx 是**别的模块**，不是 M07 的前置/后继）。"""
    return 700 <= migration_number(path) <= 799


def prerequisite_files() -> list[pathlib.Path]:
    """前置段：除 700–799 之外的全部迁移（含 COP 台账 006 与 M01–M06 / M09–M16）。"""
    return [path for path in migration_files() if not in_m07_segment(path)]


def m07_migration_files() -> list[pathlib.Path]:
    return [MIGRATIONS_DIR / name for name in M07_MIGRATIONS]


def apply_file(schema: str, path: pathlib.Path) -> None:
    """执行单个迁移文件（文件自身带 BEGIN/COMMIT；失败抛异常并停）。"""
    script = path.read_text(encoding="utf-8")
    conn = connect(schema, autocommit=False)
    try:
        with conn.cursor() as cur:
            cur.execute(script)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def apply_migrations(schema: str, *, files: list[pathlib.Path] | None = None) -> list[str]:
    applied: list[str] = []
    for path in (files if files is not None else prerequisite_files() + m07_migration_files()):
        apply_file(schema, path)
        applied.append(path.name)
    return applied


# ─────────────────────────────────────────────────────── 夹具
def seed_account(schema: str, account_id: str | None = None, *, verified: bool = True,
                 state: str = "normal", device_cluster: str | None = None,
                 payment_cluster: str | None = None) -> str:
    """用**既有** ``app.points.open_account`` 建 COP 账户档案（不自造账户表）。"""
    from app import points

    account = account_id or f"user:{uuid.uuid4().hex[:12]}"
    conn = connect(schema)
    try:
        points.open_account(conn, account, verified=verified, state=state,
                            device_cluster=device_cluster, payment_cluster=payment_cluster)
        conn.commit()
    finally:
        conn.close()
    return account


def seed_account_on(conn: Any, account_id: str | None = None, *, verified: bool = True,
                    state: str = "normal", device_cluster: str | None = None,
                    payment_cluster: str | None = None) -> str:
    """在**已有连接**上建 COP 账户档案（与用例同一事务；路由用 ``seed_account`` 落库版）。"""
    from app import points

    account = account_id or f"user:{uuid.uuid4().hex[:12]}"
    points.open_account(conn, account, verified=verified, state=state,
                        device_cluster=device_cluster, payment_cluster=payment_cluster)
    return account


def account_id() -> str:
    return f"user:{uuid.uuid4().hex[:12]}"


def event(event_type: str, *, account_id: str | None, occurred_at: datetime = NOW,
          event_id: uuid.UUID | None = None, **payload: Any) -> dict[str, Any]:
    """构造 02-events 信封（event_id 随机；需要固定时显式传 ``event_id``）。"""
    body: dict[str, Any] = {"event_id": str(event_id or uuid.uuid4()), "type": event_type,
                            "version": 1, "occurred_at": occurred_at.isoformat(),
                            "producer": "M05" if event_type.startswith("usage.") else "M01",
                            "aggregate_type": "account",
                            "aggregate_id": account_id or "",
                            "trace_id": "trace-m07-tests",
                            "idempotency_key": f"{event_type}:{uuid.uuid4().hex[:8]}",
                            "payload": dict(payload)}
    if account_id is not None:
        body["payload"].setdefault("account_id", account_id)
    return body


def table_names(schema: str) -> set[str]:
    conn = connect(schema, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT table_name FROM information_schema.tables
                    WHERE table_schema = current_schema()
                   UNION
                   SELECT table_name FROM information_schema.views
                    WHERE table_schema = current_schema()""")
            return {row[0] for row in cur.fetchall()}
    finally:
        conn.close()


def scalar(conn: Any, sql: str, params: tuple = ()) -> Any:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
    return row[0] if row else None


def count(conn: Any, table: str, where: str = "", params: tuple = ()) -> int:
    clause = f" WHERE {where}" if where else ""
    return int(scalar(conn, f"SELECT count(*) FROM {table}{clause}", params))


def structure_fingerprint(schema: str, tables: tuple[str, ...] = FINGERPRINT_TABLES) -> dict:
    """复用实现里的指纹函数（``app.reputation.migrate.structure_fingerprint``）。"""
    from app.reputation import migrate

    conn = connect(schema)
    try:
        return migrate.structure_fingerprint(conn, tables)
    finally:
        conn.close()


# ─────────────────────────────────────────────────────── 路由客户端
def make_client(schema: str, *, principal: str | None = "auto", admin_actor: str = "admin:1",
                roles: tuple[str, ...] = ("admin",), step_up: str | None = "ok",
                step_up_valid: bool = True, now: datetime = NOW,
                config: Any = None, with_principal: bool = True,
                with_admin: bool = True):
    """构造注入依赖的 TestClient（默认全部接线；缺省注入即 fail-closed 用例）。

    ``principal='auto'`` 表示「每个请求用 ``account_id`` 头指定账户」，便于一个客户端
    测多账户隔离；也接受固定账户字符串。
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.reputation.router import create_router

    def _principal(request):
        if principal == "auto":
            return {"account_id": request.headers.get("X-Test-Account", "user:anon")}
        return {"account_id": principal}

    app = FastAPI()
    app.include_router(create_router(
        connection_factory=lambda: connect(schema),
        principal_resolver=_principal if with_principal else None,
        admin_resolver=(
            (lambda request: {"actor": admin_actor, "roles": list(roles)})
            if with_admin else None),
        step_up_verifier=((lambda request: step_up_valid) if step_up is not None else None),
        config_provider=(lambda: config) if config is not None else None,
        now_provider=lambda: now))
    return TestClient(app, raise_server_exceptions=False)


def as_account(account: str) -> dict[str, str]:
    """``make_client(principal='auto')`` 下指定主体的请求头。"""
    return {"X-Test-Account": account}
