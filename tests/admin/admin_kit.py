# SPDX-License-Identifier: Apache-2.0
"""tests/admin 脚手架：schema 隔离 / 迁移四跑 / 审计链种子 / 行夹具 / 假端口。

隔离约定（与 tests/risk 同款）：

* 每个测试进程独立 schema 前缀（``m14_t_<pid>_<hex>``，``M14_SCHEMA`` 可覆盖），结束 DROP；
* 迁移用 psycopg 逐文件执行（与 ``python -m app.data_gov.migrate`` 同一路径），DSN 由 ``DJB_DSN`` 注入；
* 缺 ``DJB_DSN`` 时 DB 用例整体 skip，纯函数用例照跑；
* 审计链种子（``insert_audit``）按 M16 1403 护栏顺序追加：seq 连续 + prev_hash 指向上一条 hash。
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

import psycopg
from psycopg.rows import dict_row

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
MIGRATIONS_DIR = REPO_ROOT / "migrations"

M14_TABLES: tuple[str, ...] = (
    "data_export_requests", "retention_jobs", "admin_saved_views", "data_gov_outbox",
)
M14_FUNCTIONS: tuple[str, ...] = (
    "m14_export_requests_guard", "m14_retention_jobs_guard", "m14_admin_saved_views_guard",
    "m14_outbox_payload_guard", "m14_outbox_guard", "m14_forbid_delete", "m14_forbid_truncate",
)
M14_INDEXES: tuple[str, ...] = (
    "uq_export_requests_idem", "idx_export_requests_requester_created",
    "idx_export_requests_state_created", "idx_export_requests_large",
    "uq_retention_jobs_object_cutoff", "idx_retention_jobs_object_created",
    "idx_retention_jobs_state_created", "idx_admin_saved_views_owner_domain",
    "uq_admin_saved_views_active_name", "uq_data_gov_outbox_event_id",
    "uq_data_gov_outbox_idempotency", "idx_data_gov_outbox_pending",
    "idx_data_gov_outbox_aggregate",
)

FIXED_NOW = datetime(2026, 10, 24, 3, 0, tzinfo=timezone.utc)
LINK_SECRET = b"m14-test-link-secret"
STEP_UP_HEADERS = {"X-Admin-Step-Up": "step-up-token"}

ADMIN_PRINCIPAL: dict[str, Any] = {
    "admin_id": "ops-admin", "tenant_id": "tenant-a",
    "scopes": ["data.read", "data.write", "data.approve", "ops.read", "ops.write"],
}
SECOND_ADMIN: dict[str, Any] = {
    "admin_id": "ops-admin-b", "tenant_id": "tenant-a",
    "scopes": ["data.read", "data.write", "data.approve", "ops.read", "ops.write"],
}
AUDITOR_PRINCIPAL: dict[str, Any] = {
    "admin_id": "auditor", "tenant_id": "tenant-a", "roles": ["AUDIT"],
}
NON_ADMIN_PRINCIPAL: dict[str, Any] = {
    "admin_id": "finance", "tenant_id": "tenant-a", "roles": ["FIN"],
}
OTHER_TENANT_PRINCIPAL: dict[str, Any] = {
    "admin_id": "ops-admin-c", "tenant_id": "tenant-b", "scopes": ["*"],
}


# ───────────────────────────────────────────────────────────── 连接 / schema
def dsn() -> str:
    from tests.pgdsn import safe_dsn
    value = os.environ.get("DJB_DSN")
    if not value:
        raise SystemExit("缺环境变量 DJB_DSN（凭据只注入环境，不入库 / 不入提交）")
    return safe_dsn(value)


def connect(schema: str, *, autocommit: bool = True) -> psycopg.Connection:
    return psycopg.connect(dsn(), autocommit=autocommit,
                           options=f"-c search_path={schema}", connect_timeout=15,
                           application_name="m14-admin-tests")


@contextmanager
def session(schema: str):
    connection = connect(schema)
    try:
        yield connection
    finally:
        connection.close()


def create_schema(schema: str) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')


def drop_schema(schema: str) -> None:
    with psycopg.connect(dsn(), autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


@contextmanager
def savepoint_factory(connection: psycopg.Connection):
    """请求级 SAVEPOINT（HTTP handler 的提交只释放保存点，用例结束整体回滚）。"""
    with connection.transaction():
        yield connection


# ───────────────────────────────────────────────────────────── 迁移
def _number(name: str) -> int:
    head = name.split("_", 1)[0]
    return int(head) if head.isdigit() else -1


def _sorted(files: Iterable[pathlib.Path]) -> list[pathlib.Path]:
    return sorted(files, key=lambda path: (_number(path.name), path.name))


def all_migration_files() -> list[pathlib.Path]:
    return _sorted(MIGRATIONS_DIR.glob("*.sql"))


def m14_migration_files() -> list[pathlib.Path]:
    return [path for path in all_migration_files() if 1300 <= _number(path.name) <= 1399]


def prerequisite_files() -> list[pathlib.Path]:
    return [path for path in all_migration_files() if _number(path.name) < 1300]


def apply_migrations(schema: str, files: Iterable[pathlib.Path] | None = None) -> list[str]:
    applied: list[str] = []
    with connect(schema) as conn:
        for path in (files if files is not None else all_migration_files()):
            conn.execute(path.read_text(encoding="utf-8"))
            applied.append(path.name)
    return applied


def apply_m14_twice(schema: str) -> None:
    for _ in range(2):
        apply_migrations(schema, m14_migration_files())


# ───────────────────────────────────────────────────────────── 结构读取
def table_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = %s", (schema,))
        return {row[0] for row in cur.fetchall()}


def view_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT viewname FROM pg_views WHERE schemaname = %s", (schema,))
        return {row[0] for row in cur.fetchall()}


def index_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname = %s", (schema,))
        return {row[0] for row in cur.fetchall()}


def trigger_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
            " JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = %s AND NOT t.tgisinternal", (schema,))
        return {row[0] for row in cur.fetchall()}


def function_names(schema: str) -> set[str]:
    with session(schema) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = %s AND p.proname LIKE 'm14%%'", (schema,))
        return {row[0] for row in cur.fetchall()}


def column_signature(schema: str, tables: Iterable[str] | None = None) -> dict[str, Any]:
    names = sorted(tables) if tables is not None else sorted(table_names(schema))
    signature: dict[str, Any] = {}
    with session(schema) as conn, conn.cursor(row_factory=dict_row) as cur:
        for table in names:
            cur.execute(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns"
                " WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (schema, table))
            signature[table] = [dict(row) for row in cur.fetchall()]
    return signature


def constraint_signature(schema: str, tables: Iterable[str] | None = None) -> dict[str, Any]:
    names = sorted(tables) if tables is not None else sorted(table_names(schema))
    signature: dict[str, Any] = {}
    with session(schema) as conn, conn.cursor(row_factory=dict_row) as cur:
        for table in names:
            cur.execute(
                "SELECT conname, contype FROM pg_constraint c"
                " JOIN pg_class r ON r.oid = c.conrelid"
                " JOIN pg_namespace n ON n.oid = r.relnamespace"
                " WHERE n.nspname = %s AND r.relname = %s ORDER BY conname",
                (schema, table))
            signature[table] = [dict(row) for row in cur.fetchall()]
    return signature


# ───────────────────────────────────────────────────────────── 审计链种子
def insert_audit(connection: psycopg.Connection, *, action: str,
                 actor: str = "ops-actor", target: str = "svc/ops",
                 ts: datetime | None = None, after: Mapping[str, Any] | None = None,
                 reason_code: str | None = None, ticket: str | None = None,
                 evidence: str | None = None, role: str = "OPS") -> dict[str, Any]:
    """按 M16 1403 链护栏顺序追加一条形状合法的审计条目（只用于只读面测试）。"""
    moment = ts or FIXED_NOW
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        tail = cur.fetchone()
        seq = int(tail["seq"]) + 1 if tail else 1
        prev_hash = tail["hash"] if tail else "GENESIS"
        digest = hashlib.sha256(f"{seq}:{action}:{actor}".encode("utf-8")).hexdigest()
        cur.execute(
            """
            INSERT INTO audit_log (seq, entry_id, ts, actor, actor_type, role, action,
                                   target, before, after, reason_code, ticket, evidence,
                                   approval_chain, status, alg, prev_hash, hash, created_at)
            VALUES (%s, %s::uuid, %s, %s, 'human', %s, %s, %s, NULL, %s::jsonb, %s, %s, %s,
                    '[]'::jsonb, 'recorded', 'hmac-sha256', %s, %s, now())
            RETURNING *
            """,
            (seq, str(uuid.uuid4()), moment, actor, role, action, target,
             json.dumps(dict(after)) if after is not None else None,
             reason_code, ticket, evidence, prev_hash, digest))
        return dict(cur.fetchone())


class AuditLogSink:
    """把 M14 审计记录追加进 audit_log 的测试适配器（模拟 M16 audit.append 接线）。"""

    def __init__(self, connection: psycopg.Connection) -> None:
        self.connection = connection
        self.records: list[dict[str, Any]] = []

    def __call__(self, record: Mapping[str, Any]) -> None:
        self.records.append(dict(record))
        moment = record.get("occurred_at")
        if isinstance(moment, str):
            moment = datetime.fromisoformat(moment.replace("Z", "+00:00"))
        insert_audit(self.connection, action=str(record["action"]),
                     actor=str(record["actor"]), target=str(record["object_id"]),
                     ts=moment, after={key: value for key, value in record.items()
                                       if key not in ("action", "actor", "object_id")})


class RecordingSink:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def __call__(self, record: Mapping[str, Any]) -> None:
        self.records.append(dict(record))

    def actions(self) -> list[str]:
        return [str(record.get("action")) for record in self.records]


# ───────────────────────────────────────────────────────────── 行夹具
def _unique_no(prefix: str) -> str:
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"


def make_export(connection: psycopg.Connection, *, state: str = "pending",
                requester: str = "ops-admin", tenant_id: str = "tenant-a",
                object_name: str = "usage", reason: str = "审计抽查",
                estimated_rows: int = 0, contains_personal_data: bool = False,
                approval_required: bool | None = None, export_no: str | None = None,
                created_at: datetime | None = None,
                idempotency_key: str | None = None) -> dict[str, Any]:
    from app.data_gov import ids, store

    moment = created_at or FIXED_NOW
    approval = (contains_personal_data or estimated_rows > 1000
                if approval_required is None else approval_required)
    row = store.insert_export(
        connection, export_id=str(ids.uuid7()), export_no=export_no or _unique_no("EXP"),
        requester=requester, tenant_id=tenant_id, scope={"object": object_name},
        fmt=["json", "csv"], reason=reason, estimated_rows=estimated_rows,
        contains_personal_data=contains_personal_data, approval_required=approval,
        idempotency_key=idempotency_key, created_at=moment)
    if state == "pending":
        return row
    fields: dict[str, Any] = {"state": "approved", "approver": "ops-approver",
                              "approved_at": moment}
    row = store.update_export(connection, str(row["export_id"]), **fields) or row
    if state == "approved":
        return row
    row = store.update_export(connection, str(row["export_id"]), state="running",
                              started_at=moment) or row
    if state == "running":
        return row
    if state == "failed":
        return store.update_export(connection, str(row["export_id"]), state="failed",
                                   failure_reason="boom", finished_at=moment) or row
    row = store.update_export(
        connection, str(row["export_id"]), state="done", row_count=7, finished_at=moment,
        expires_at=moment + timedelta(days=7), watermark="DJB-M14 TEST") or row
    if state == "done":
        return row
    return store.update_export(connection, str(row["export_id"]), state="expired") or row


def make_retention(connection: psycopg.Connection, *, state: str = "queued",
                   object_name: str = "logs", policy_days: int = 30,
                   cutoff: datetime | None = None, dry_run: bool = False,
                   requested_by: str = "ops-admin") -> dict[str, Any]:
    from app.data_gov import ids, store

    moment = cutoff or FIXED_NOW - timedelta(days=policy_days)
    row = store.insert_retention(
        connection, job_id=str(ids.uuid7()), job_no=_unique_no("RET"),
        object_name=object_name, policy_days=policy_days, cutoff=moment, dry_run=dry_run,
        report_ref="report://retention/jobs/test", requested_by=requested_by,
        idempotency_key=None, sla_due_at=FIXED_NOW + timedelta(days=30),
        created_at=FIXED_NOW)
    if state == "queued":
        return row
    row = store.update_retention(connection, str(row["job_id"]), state="running",
                                 started_at=FIXED_NOW) or row
    if state == "running":
        return row
    if state == "failed":
        return store.update_retention(connection, str(row["job_id"]), state="failed",
                                      failure_reason="boom", finished_at=FIXED_NOW) or row
    report = {"object": object_name, "cutoff": None, "policy_days": policy_days,
              "dry_run": dry_run, "deleted_count": 3, "retained_count": 1,
              "retained": [{"reason": "legal_hold"}], "latest_clear_dates": {},
              "method": "test", "sampling": {"after_days": 40, "target_hits": 0},
              "generated_at": None}
    return store.update_retention(
        connection, str(row["job_id"]), state="done", finished_at=FIXED_NOW,
        deleted_count=3, retained_count=1, report=report) or row


# ───────────────────────────────────────────────────────────── 假端口
class FakeRetentionExecutor:
    def __init__(self, result: Mapping[str, Any] | None = None,
                 error: BaseException | None = None) -> None:
        self.result = dict(result) if result is not None else {
            "candidates": 12, "deleted": 10, "retained": 2,
            "retained_reasons": ["legal_hold", "ledger_link_only"],
            "latest_clear_dates": {"backups": "2026-11-28", "logs": "2026-11-23"},
            "method": "owner_api", "hold": True,
        }
        self.error = error
        self.calls: list[tuple[str, datetime, bool]] = []

    def __call__(self, object_name: str, cutoff: datetime, dry_run: bool):
        self.calls.append((object_name, cutoff, dry_run))
        if self.error is not None:
            raise self.error
        return dict(self.result)


class FakeBatchExecutor:
    def __init__(self, fail_ids: Iterable[str] = (),
                 error: BaseException | None = None) -> None:
        self.fail_ids = set(fail_ids)
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def __call__(self, action_type: str, item: str, target: Mapping[str, Any]):
        self.calls.append((action_type, item))
        if self.error is not None:
            raise self.error
        if item in self.fail_ids:
            return {"status": "failed", "error_code": "40901"}
        return {"status": "succeeded"}


class FakeBatchProbe:
    def __init__(self, ids_list: Iterable[str] | None = None) -> None:
        self.ids = list(ids_list or ["acct-1", "acct-2", "acct-3"])
        self.calls: list[Mapping[str, Any]] = []

    def __call__(self, target: Mapping[str, Any]):
        self.calls.append(dict(target))
        return list(self.ids)


def outbox_rows(connection: psycopg.Connection) -> list[dict[str, Any]]:
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM data_gov_outbox ORDER BY id")
        return [dict(row) for row in cur.fetchall()]


def idempotency_key(tag: str = "a") -> str:
    text = f"m14-idem-{tag}"
    return text.ljust(16, "0")[:128]

# ───────────────────────────────────────────────────────────── HTTP 客户端
def build_client(connection: psycopg.Connection, *, principal: Mapping[str, Any] | None = None,
                 step_up: bool | None = True, now: datetime | None = None,
                 config: Mapping[str, Any] | None = None, audit_sink: Any = None,
                 retention_executor: Any = None, health_probes: Any = None,
                 batch_store: Any = None, batch_probe: Any = None,
                 batch_executor: Any = None, batch_undoer: Any = None,
                 link_base_url: str = "https://admin.test"):
    """构造带 M14 路由的 ASGI 客户端（请求级 SAVEPOINT，不真提交）。"""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.data_gov.router import create_router

    chosen: dict[str, Any] | None
    if principal is None:
        chosen = dict(ADMIN_PRINCIPAL)
    elif principal is False:
        chosen = None
    else:
        chosen = dict(principal)
    app = FastAPI()
    app.include_router(create_router(
        connection_factory=lambda: savepoint_factory(connection),
        admin_resolver=(lambda request: dict(chosen)) if chosen is not None else None,
        step_up_verifier=(lambda request: bool(step_up)) if step_up is not None else None,
        now_provider=lambda: now or FIXED_NOW,
        config_provider=(lambda: dict(config)) if config is not None else None,
        audit_sink=audit_sink,
        retention_executor=retention_executor,
        health_probes=health_probes,
        batch_store=batch_store,
        batch_probe=batch_probe,
        batch_executor=batch_executor,
        batch_undoer=batch_undoer,
        link_secret=LINK_SECRET,
        link_base_url=link_base_url,
    ))
    return TestClient(app)


def write_headers(tag: str = "a", *, step_up: bool = True) -> dict[str, str]:
    headers = {"X-DJB-Idempotency-Key": idempotency_key(tag)}
    if step_up:
        headers["X-Admin-Step-Up"] = "step-up-token"
    return headers
