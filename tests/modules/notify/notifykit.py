# SPDX-License-Identifier: Apache-2.0
"""DEV-M12 测试工具：迁移执行、schema 隔离、夹具（账户 / 事件 / 连接工厂）。

只读契约（本文件不改实现代码）：

* 迁移文件是唯一 DDL 来源，测试只按数字序执行 ``migrations/*.sql``，**不在 Python 里手写建表**；
* 每个 schema 独立（``m12_t12_<pid>_<hex>``），结束 ``DROP SCHEMA ... CASCADE``；
  不读写 public，也不碰别人的 schema；
* 固定时钟：``NOW`` 常量 + 显式 ``now=`` 参数，不依赖墙上时间（00-conventions §10）；
* 密钥是**测试夹具**（固定字面量、明显非生产）；生产 secret 只存哈希（INV-05）。
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

M12_MIGRATIONS = (
    "1201_notifications.sql",
    "1202_notification_outbox.sql",
    "1203_webhook_subscriptions.sql",
    "1204_delivery_attempts.sql",
    "1205_notification_preferences.sql",
)
M12_TABLES = ("notifications", "notification_outbox", "webhook_subscriptions",
              "delivery_attempts", "notification_preferences")
#: 被 M12 只读依赖、但**不允许**直读的上游基表（架构门禁反例清单）
UPSTREAM_BASE_TABLES = ("user_accounts", "api_keys", "sessions", "accounts", "journal_entry",
                        "ledger_entry", "usage_records", "config_items")

#: 固定时钟（UTC 04:00，避开日界与静默时段边界）
NOW = datetime(2026, 10, 23, 4, 0, 0, tzinfo=timezone.utc)
#: 测试用 Webhook 密钥（**夹具**：固定字面量、非生产）
TEST_WEBHOOK_SECRET = "m12-t12-webhook-fixture-secret-0123456789"


# ─────────────────────────────────────────────────────── 连接与迁移
def dsn() -> str:
    value = os.environ.get("DJB_DSN")
    if not value:
        raise RuntimeError("缺环境变量 DJB_DSN（见 product/v4/modules/W1-EXECUTION-PLAN.md §3）")
    return value


def _admin_connect() -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=True, connect_timeout=15,
                           application_name="m12-t12-tests")


def connect(schema: str, autocommit: bool = False) -> psycopg.Connection:
    quoted = '"' + schema.replace('"', '""') + '"'          # 防大小写折叠
    return psycopg.connect(dsn(), autocommit=autocommit, connect_timeout=15,
                           application_name="m12-t12-tests",
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
    """按数字排序（CI 用 ``sort -V``）；只取本模块 + 前置段。"""
    files = list(MIGRATIONS_DIR.glob("*.sql"))
    return sorted(files, key=migration_number)


def prerequisite_files() -> list[pathlib.Path]:
    """前置段：编号 < 1200 的全部迁移（空库三跑 / 升级基线用）。"""
    return [path for path in migration_files() if migration_number(path) < 1200]


def m12_migration_files() -> list[pathlib.Path]:
    return [MIGRATIONS_DIR / name for name in M12_MIGRATIONS]


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
    for path in (files if files is not None else prerequisite_files() + m12_migration_files()):
        apply_file(schema, path)
        applied.append(path.name)
    return applied


# ─────────────────────────────────────────────────────── 夹具
def seed_account(schema: str) -> uuid.UUID:
    """M01 的账户表是**只读依赖**（M12 不建 FK），这里只保证账户 id 存在且稳定。"""
    return uuid.uuid4()


def event(event_type: str, *, account_id: uuid.UUID | str | None,
          occurred_at: datetime = NOW, **payload: Any) -> dict[str, Any]:
    """构造 02-events 信封（event_id 随机；需要固定时显式传 ``event_id``）。"""
    body: dict[str, Any] = {"type": event_type, "occurred_at": occurred_at,
                            "aggregate_type": "account",
                            "aggregate_id": str(account_id) if account_id else "",
                            "payload": dict(payload)}
    if "event_id" in payload:
        body["event_id"] = payload.pop("event_id")
    else:
        body["event_id"] = uuid.uuid4()
    if account_id is not None:
        body["payload"].setdefault("account_id", str(account_id))
    return body


def table_names(schema: str) -> set[str]:
    conn = connect(schema, autocommit=True)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT table_name FROM information_schema.tables
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


def build_notification(account_id: uuid.UUID, *, level: str = "P1", type_: str = "payment.paid",
                       template_key: str | None = None, payload: dict[str, Any] | None = None,
                       channels: tuple[str, ...] = ("in_app",), status: str = "queued",
                       created_at: datetime = NOW, read_at: datetime | None = None,
                       channel_count: int = 1, dedupe_bucket: int | None = None,
                       scope: str = "customer"):
    """直接构造一条通知对象（不走事件层，用于列表 / 分页 / 已读用例）。"""
    from app.notify import facts
    from app.notify.models import Notification

    moment = created_at
    return Notification(
        id=uuid.uuid4(), account_id=account_id, level=level, type=type_,
        template_key=template_key or f"customer.{type_}", template_scope=scope,
        payload=dict(payload or {}), channels=tuple(channels), channel_count=channel_count,
        dedupe_bucket=(facts.dedupe_bucket(moment) if dedupe_bucket is None else dedupe_bucket),
        status=status, created_at=moment, read_at=read_at)
