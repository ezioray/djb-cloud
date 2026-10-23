# SPDX-License-Identifier: Apache-2.0
"""M14 数据访问层：自有 3 表 + outbox 的 SQL；只读视图 / audit_log 适配。

边界（INV-01 / 01-ownership §6）：

* **写**只发生在本模块自有表（``data_export_requests`` / ``retention_jobs`` /
  ``admin_saved_views`` / ``data_gov_outbox``）；
* **读**其它模块只允许只读视图 ``v_<module>_*``（本仓既有 ``v_m09_run_diff``、
  ``chain_tx_state``、``account_balances_latest`` 等）与 M16 的 ``audit_log``；
  不 join 任何他域基表，不做写。

所有列表按 ``(created_at, id)`` / ``(ts, seq)`` 游标翻页（禁止 offset）。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import clock, errors, facts, models

__all__ = [
    "EXPORT_TABLE", "RETENTION_TABLE", "SAVED_VIEW_TABLE", "OUTBOX_TABLE", "M14_TABLES",
    "insert_export", "get_export", "find_export_by_idempotency", "count_large_exports",
    "list_exports", "update_export", "expire_due_exports",
    "insert_retention", "get_retention", "find_retention_by_idempotency",
    "find_retention_execution", "find_retention_preview", "list_retentions",
    "update_retention",
    "insert_saved_view", "list_saved_views", "soft_delete_saved_view",
    "insert_outbox", "get_outbox", "list_outbox", "update_outbox", "count_outbox_pending",
    "relation_exists", "audit_log_available", "latest_audit_change", "list_audit_entries",
    "list_audit_changes", "retention_candidates", "latest_balance_ts", "count_stuck_chain_tx",
    "latest_recon_run",
]

EXPORT_TABLE = "data_export_requests"
RETENTION_TABLE = "retention_jobs"
SAVED_VIEW_TABLE = "admin_saved_views"
OUTBOX_TABLE = "data_gov_outbox"
M14_TABLES: tuple[str, ...] = (EXPORT_TABLE, RETENTION_TABLE, SAVED_VIEW_TABLE, OUTBOX_TABLE)

#: 可变列白名单（状态机字段；其余列由库层触发器锁死）
_EXPORT_MUTABLE = frozenset({
    "state", "approver", "approved_at", "started_at", "finished_at", "expires_at",
    "watermark", "failure_reason", "cancelled_at", "cancelled_by", "link_jti",
    "link_consumed_at", "row_count",
})
_RETENTION_MUTABLE = frozenset({
    "state", "started_at", "finished_at", "deleted_count", "retained_count", "report",
    "report_ref", "failure_reason", "replay_count",
})
_OUTBOX_MUTABLE = frozenset({
    "state", "attempts", "next_attempt_at", "last_error", "published_at",
})


def _fetch_one(connection: Any, sql: str, params: Mapping[str, Any] | Sequence[Any]) -> dict | None:
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row is not None else None


def _fetch_all(connection: Any, sql: str,
               params: Mapping[str, Any] | Sequence[Any]) -> list[dict]:
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]


# ═══════════════════════════════════════════════════════════════ 导出申请（1301）
def insert_export(connection: Any, *, export_id: str, export_no: str, requester: str,
                  tenant_id: str, scope: Mapping[str, Any], fmt: Sequence[str],
                  reason: str, estimated_rows: int, contains_personal_data: bool,
                  approval_required: bool, idempotency_key: str | None,
                  created_at: datetime, expires_at: datetime | None = None) -> dict:
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO data_export_requests (
                export_id, export_no, requester, requester_tenant, scope, "format", reason,
                state, estimated_rows, contains_personal_data, approval_required,
                expires_at, idempotency_key, created_at, updated_at)
            VALUES (%(export_id)s::uuid, %(export_no)s, %(requester)s, %(tenant)s,
                    %(scope)s::jsonb, %(fmt)s::jsonb, %(reason)s, 'pending',
                    %(estimated)s, %(pii)s, %(approval)s, %(expires)s, %(idem)s,
                    %(created)s, %(created)s)
            RETURNING *
            """,
            {"export_id": export_id, "export_no": export_no, "requester": requester,
             "tenant": tenant_id, "scope": Jsonb(dict(scope)), "fmt": Jsonb(list(fmt)),
             "reason": reason, "estimated": estimated_rows, "pii": contains_personal_data,
             "approval": approval_required, "expires": expires_at,
             "idem": idempotency_key, "created": created_at})
        return dict(cur.fetchone())


def get_export(connection: Any, export_id: str) -> dict | None:
    return _fetch_one(connection, "SELECT * FROM data_export_requests"
                                 " WHERE export_id = %(id)s::uuid", {"id": export_id})


def find_export_by_idempotency(connection: Any, requester: str,
                               key: str | None) -> dict | None:
    if not key:
        return None
    return _fetch_one(
        connection,
        "SELECT * FROM data_export_requests"
        " WHERE requester = %(requester)s AND idempotency_key = %(key)s",
        {"requester": requester, "key": key})


def count_large_exports(connection: Any, requester: str, since: datetime) -> int:
    row = _fetch_one(
        connection,
        "SELECT count(*) AS n FROM data_export_requests"
        " WHERE requester = %(requester)s AND approval_required"
        "   AND state IN ('pending','approved','running','done')"
        "   AND created_at >= %(since)s",
        {"requester": requester, "since": since})
    return int(row["n"]) if row else 0


def list_exports(connection: Any, *, state: str | None = None, object_name: str | None = None,
                 requester: str | None = None, from_at: datetime | None = None,
                 to_at: datetime | None = None, cursor: str | None = None,
                 limit: int = facts.DEFAULT_PAGE_SIZE,
                 visible_to: str | None = None) -> tuple[list[dict], bool, str | None]:
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}
    if visible_to:
        # spec：申请人 / 复核人之外不可见（越权统一 404）
        where.append("(requester = %(visible)s OR approver = %(visible)s)")
        params["visible"] = visible_to
    if state:
        where.append("state = %(state)s")
        params["state"] = state
    if object_name:
        where.append("scope->>'object' = %(object_name)s")
        params["object_name"] = object_name
    if requester:
        where.append("requester = %(requester)s")
        params["requester"] = requester
    if from_at:
        where.append("created_at >= %(from_at)s")
        params["from_at"] = from_at
    if to_at:
        where.append("created_at <= %(to_at)s")
        params["to_at"] = to_at
    decoded = models.decode_cursor(cursor)
    if decoded is not None:
        params["cts"], params["cid"] = decoded
        where.append("(created_at < %(cts)s OR"
                     " (created_at = %(cts)s AND export_id < %(cid)s::uuid))")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = _fetch_all(
        connection,
        "SELECT * FROM data_export_requests" + clause +
        " ORDER BY created_at DESC, export_id DESC LIMIT %(limit)s", params)
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = (models.encode_cursor(rows[-1]["created_at"], str(rows[-1]["export_id"]))
                   if has_more and rows else None)
    return rows, has_more, next_cursor


def update_export(connection: Any, export_id: str, **fields: Any) -> dict | None:
    payload = {key: value for key, value in fields.items() if key in _EXPORT_MUTABLE}
    unknown = set(fields) - set(payload)
    if unknown:
        raise ValueError(f"不可写列：{sorted(unknown)}")
    if not payload:
        return get_export(connection, export_id)
    assignments = ", ".join(f'"{name}" = %({name})s' for name in payload)
    params: dict[str, Any] = dict(payload)
    params["id"] = export_id
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE data_export_requests SET {assignments}, updated_at = now()"
            " WHERE export_id = %(id)s::uuid RETURNING *", params)
        row = cur.fetchone()
        return dict(row) if row is not None else None


def expire_due_exports(connection: Any, now: datetime) -> list[dict]:
    """done 且文件 7 天到期 → expired（过期不自动续期，INV-04）。"""
    return _fetch_all(
        connection,
        "UPDATE data_export_requests SET state = 'expired', updated_at = now()"
        " WHERE state = 'done' AND expires_at IS NOT NULL AND expires_at <= %(now)s"
        " RETURNING export_id, export_no, requester",
        {"now": now})


# ═══════════════════════════════════════════════════════════════ 保留任务（1302）
def insert_retention(connection: Any, *, job_id: str, job_no: str, object_name: str,
                     policy_days: int, cutoff: datetime, dry_run: bool, report_ref: str,
                     requested_by: str, idempotency_key: str | None, sla_due_at: datetime,
                     created_at: datetime) -> dict:
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO retention_jobs (
                job_id, job_no, object, policy_days, cutoff, state, dry_run,
                report_ref, requested_by, idempotency_key, sla_due_at, created_at, updated_at)
            VALUES (%(job_id)s::uuid, %(job_no)s, %(object)s, %(days)s, %(cutoff)s, 'queued',
                    %(dry)s, %(ref)s, %(by)s, %(idem)s, %(due)s, %(created)s, %(created)s)
            RETURNING *
            """,
            {"job_id": job_id, "job_no": job_no, "object": object_name, "days": policy_days,
             "cutoff": cutoff, "dry": dry_run, "ref": report_ref, "by": requested_by,
             "idem": idempotency_key, "due": sla_due_at, "created": created_at})
        return dict(cur.fetchone())


def get_retention(connection: Any, job_id: str) -> dict | None:
    return _fetch_one(connection, "SELECT * FROM retention_jobs WHERE job_id = %(id)s::uuid",
                      {"id": job_id})


def find_retention_by_idempotency(connection: Any, requested_by: str,
                                  key: str | None) -> dict | None:
    if not key:
        return None
    return _fetch_one(
        connection,
        "SELECT * FROM retention_jobs"
        " WHERE requested_by = %(by)s AND idempotency_key = %(key)s",
        {"by": requested_by, "key": key})


def find_retention_execution(connection: Any, object_name: str,
                             cutoff: datetime) -> dict | None:
    """同一 (object, cutoff) 的**真实执行**只允许一条（INV-07 幂等）。"""
    return _fetch_one(
        connection,
        "SELECT * FROM retention_jobs"
        " WHERE object = %(object)s AND cutoff = %(cutoff)s AND dry_run = false"
        "   AND state <> 'failed' ORDER BY created_at DESC LIMIT 1",
        {"object": object_name, "cutoff": cutoff})


def find_retention_preview(connection: Any, object_name: str,
                           cutoff: datetime) -> dict | None:
    """同一 (object, cutoff) 的 dry-run 预览可复用（不重复执行）。"""
    return _fetch_one(
        connection,
        "SELECT * FROM retention_jobs"
        " WHERE object = %(object)s AND cutoff = %(cutoff)s AND dry_run = true"
        " ORDER BY created_at DESC LIMIT 1",
        {"object": object_name, "cutoff": cutoff})


def list_retentions(connection: Any, *, object_name: str | None = None,
                    state: str | None = None, dry_run: bool | None = None,
                    cursor: str | None = None,
                    limit: int = facts.DEFAULT_PAGE_SIZE) -> tuple[list[dict], bool, str | None]:
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}
    if object_name:
        where.append('"object" = %(object)s')
        params["object"] = object_name
    if state:
        where.append("state = %(state)s")
        params["state"] = state
    if dry_run is not None:
        where.append("dry_run = %(dry)s")
        params["dry"] = dry_run
    decoded = models.decode_cursor(cursor)
    if decoded is not None:
        params["cts"], params["cid"] = decoded
        where.append("(created_at < %(cts)s OR"
                     " (created_at = %(cts)s AND job_id < %(cid)s::uuid))")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = _fetch_all(
        connection,
        "SELECT * FROM retention_jobs" + clause +
        " ORDER BY created_at DESC, job_id DESC LIMIT %(limit)s", params)
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = (models.encode_cursor(rows[-1]["created_at"], str(rows[-1]["job_id"]))
                   if has_more and rows else None)
    return rows, has_more, next_cursor


def update_retention(connection: Any, job_id: str, **fields: Any) -> dict | None:
    payload = {key: value for key, value in fields.items() if key in _RETENTION_MUTABLE}
    unknown = set(fields) - set(payload)
    if unknown:
        raise ValueError(f"不可写列：{sorted(unknown)}")
    if not payload:
        return get_retention(connection, job_id)
    assignments = ", ".join(f'"{name}" = %({name})s' for name in payload)
    params: dict[str, Any] = dict(payload)
    if "report" in params and params["report"] is not None:
        params["report"] = Jsonb(dict(params["report"]))
    params["id"] = job_id
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE retention_jobs SET {assignments}, updated_at = now()"
            " WHERE job_id = %(id)s::uuid RETURNING *", params)
        row = cur.fetchone()
        return dict(row) if row is not None else None


# ═══════════════════════════════════════════════════════════════ 保存视图（1303）
def insert_saved_view(connection: Any, *, view_id: str, owner_id: str, domain: str,
                      name: str, filters: Mapping[str, Any], shared: bool,
                      created_at: datetime) -> dict:
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO admin_saved_views (view_id, owner_id, domain, name, filters, shared,
                                           state, created_at, updated_at)
            VALUES (%(id)s::uuid, %(owner)s, %(domain)s, %(name)s, %(filters)s::jsonb,
                    %(shared)s, 'active', %(created)s, %(created)s)
            RETURNING *
            """,
            {"id": view_id, "owner": owner_id, "domain": domain, "name": name,
             "filters": Jsonb(dict(filters)), "shared": shared, "created": created_at})
        return dict(cur.fetchone())


def list_saved_views(connection: Any, owner_id: str,
                     domain: str | None = None) -> list[dict]:
    return _fetch_all(
        connection,
        "SELECT * FROM admin_saved_views WHERE owner_id = %(owner)s"
        " AND state = 'active'"
        " AND (%(domain)s::text IS NULL OR domain = %(domain)s::text)"
        " ORDER BY domain, name",
        {"owner": owner_id, "domain": domain})


def soft_delete_saved_view(connection: Any, view_id: str, owner_id: str) -> dict | None:
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "UPDATE admin_saved_views SET state = 'deleted', updated_at = now()"
            " WHERE view_id = %(id)s::uuid AND owner_id = %(owner)s AND state = 'active'"
            " RETURNING *",
            {"id": view_id, "owner": owner_id})
        row = cur.fetchone()
        return dict(row) if row is not None else None


# ═══════════════════════════════════════════════════════════════ outbox（1304）
def insert_outbox(connection: Any, envelope: Mapping[str, Any]) -> dict | None:
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO data_gov_outbox (
                event_id, type, version, occurred_at, producer, aggregate_type,
                aggregate_id, correlation_id, causation_id, trace_id, idempotency_key,
                payload, state, attempts, next_attempt_at, created_at)
            VALUES (%(event_id)s::uuid, %(type)s, %(version)s, %(occurred)s, %(producer)s,
                    %(aggregate_type)s, %(aggregate_id)s, %(correlation)s, %(causation)s,
                    %(trace)s, %(idem)s, %(payload)s::jsonb, 'pending', 0, %(occurred)s,
                    now())
            ON CONFLICT DO NOTHING
            RETURNING *
            """,
            {"event_id": envelope["event_id"], "type": envelope["type"],
             "version": int(envelope.get("version", 1)),
             "occurred": clock.parse_datetime(envelope["occurred_at"], field="occurred_at"),
             "producer": envelope.get("producer", facts.PRODUCER),
             "aggregate_type": envelope["aggregate_type"],
             "aggregate_id": envelope["aggregate_id"],
             "correlation": envelope.get("correlation_id"),
             "causation": envelope.get("causation_id"),
             "trace": envelope["trace_id"],
             "idem": envelope["idempotency_key"],
             "payload": Jsonb(dict(envelope["payload"]))})
        row = cur.fetchone()
        return dict(row) if row is not None else None


def get_outbox(connection: Any, event_id: str) -> dict | None:
    return _fetch_one(connection, "SELECT * FROM data_gov_outbox"
                                 " WHERE event_id = %(id)s::uuid", {"id": event_id})


def list_outbox(connection: Any, *, trace_id: str | None = None,
                event_type: str | None = None, from_at: datetime | None = None,
                to_at: datetime | None = None, cursor: str | None = None,
                limit: int = facts.DEFAULT_PAGE_SIZE) -> tuple[list[dict], bool, str | None]:
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}
    if trace_id:
        where.append("trace_id = %(trace)s")
        params["trace"] = trace_id
    if event_type:
        where.append("type = %(type)s")
        params["type"] = event_type
    if from_at:
        where.append("occurred_at >= %(from_at)s")
        params["from_at"] = from_at
    if to_at:
        where.append("occurred_at <= %(to_at)s")
        params["to_at"] = to_at
    decoded = models.decode_cursor(cursor)
    if decoded is not None:
        params["cts"], params["cid"] = decoded
        where.append("(occurred_at < %(cts)s OR"
                     " (occurred_at = %(cts)s AND id < %(cid)s::bigint))")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = _fetch_all(
        connection,
        "SELECT * FROM data_gov_outbox" + clause +
        " ORDER BY occurred_at DESC, id DESC LIMIT %(limit)s", params)
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = (models.encode_cursor(rows[-1]["occurred_at"], str(rows[-1]["id"]))
                   if has_more and rows else None)
    return rows, has_more, next_cursor


def update_outbox(connection: Any, event_id: str, **fields: Any) -> dict | None:
    payload = {key: value for key, value in fields.items() if key in _OUTBOX_MUTABLE}
    unknown = set(fields) - set(payload)
    if unknown:
        raise ValueError(f"不可写列：{sorted(unknown)}")
    if not payload:
        return get_outbox(connection, event_id)
    assignments = ", ".join(f'"{name}" = %({name})s' for name in payload)
    params: dict[str, Any] = dict(payload)
    params["id"] = event_id
    with connection.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE data_gov_outbox SET {assignments}"
            " WHERE event_id = %(id)s::uuid RETURNING *", params)
        row = cur.fetchone()
        return dict(row) if row is not None else None


def count_outbox_pending(connection: Any) -> int:
    row = _fetch_one(connection, "SELECT count(*) AS n FROM data_gov_outbox"
                                " WHERE state = 'pending'", {})
    return int(row["n"]) if row else 0


# ═══════════════════════════════════════════════════════════════ 只读适配（他域）
def relation_exists(connection: Any, name: str) -> bool:
    row = _fetch_one(connection, "SELECT to_regclass(%(name)s) IS NOT NULL AS ok",
                     {"name": name})
    return bool(row and row["ok"])


def audit_log_available(connection: Any) -> bool:
    return relation_exists(connection, "audit_log")


def latest_audit_change(connection: Any, patterns: Iterable[str]) -> dict | None:
    """每块"最近变更"：audit_log 动作前缀匹配（M16 审计链唯一权威）。"""
    if not patterns or not audit_log_available(connection):
        return None
    like = [f"{prefix}%" for prefix in patterns]
    return _fetch_one(
        connection,
        "SELECT ts, actor, action, target FROM audit_log"
        " WHERE action LIKE ANY(%(like)s) ORDER BY ts DESC, seq DESC LIMIT 1",
        {"like": like})


def list_audit_entries(connection: Any, *, actor: str | None = None,
                       action_prefix: str | None = None,
                       from_at: datetime | None = None, to_at: datetime | None = None,
                       cursor: str | None = None,
                       limit: int = facts.DEFAULT_PAGE_SIZE
                       ) -> tuple[list[dict], bool, str | None]:
    if not audit_log_available(connection):
        return [], False, None
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}
    if actor:
        where.append("actor = %(actor)s")
        params["actor"] = actor
    if action_prefix:
        where.append("action LIKE %(action_like)s")
        params["action_like"] = f"{action_prefix}%"
    if from_at:
        where.append("ts >= %(from_at)s")
        params["from_at"] = from_at
    if to_at:
        where.append("ts <= %(to_at)s")
        params["to_at"] = to_at
    decoded = models.decode_cursor(cursor)
    if decoded is not None:
        params["cts"], params["cid"] = decoded
        params["cid_int"] = int(params["cid"])
        where.append("(ts < %(cts)s OR (ts = %(cts)s AND seq < %(cid_int)s))")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    rows = _fetch_all(
        connection,
        "SELECT seq, entry_id, ts, actor, action, target, reason_code, evidence, after"
        " FROM audit_log" + clause +
        " ORDER BY ts DESC, seq DESC LIMIT %(limit)s", params)
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = (models.encode_cursor(rows[-1]["ts"], str(rows[-1]["seq"]))
                   if has_more and rows else None)
    return rows, has_more, next_cursor


def list_audit_changes(connection: Any, *, from_at: datetime | None = None,
                       to_at: datetime | None = None, cursor: str | None = None,
                       limit: int = facts.DEFAULT_PAGE_SIZE
                       ) -> tuple[list[dict], bool, str | None]:
    if not audit_log_available(connection):
        return [], False, None
    where: list[str] = ["action LIKE ANY(%(like)s)"]
    params: dict[str, Any] = {
        "limit": limit + 1,
        "like": [f"{prefix}%" for prefix in facts.CHANGE_ACTION_PATTERNS],
    }
    if from_at:
        where.append("ts >= %(from_at)s")
        params["from_at"] = from_at
    if to_at:
        where.append("ts <= %(to_at)s")
        params["to_at"] = to_at
    decoded = models.decode_cursor(cursor)
    if decoded is not None:
        params["cts"], params["cid"] = decoded
        params["cid_int"] = int(params["cid"])
        where.append("(ts < %(cts)s OR (ts = %(cts)s AND seq < %(cid_int)s))")
    rows = _fetch_all(
        connection,
        "SELECT seq, entry_id, ts, actor, action, target, reason_code, ticket, evidence, after"
        " FROM audit_log WHERE " + " AND ".join(where) +
        " ORDER BY ts DESC, seq DESC LIMIT %(limit)s", params)
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = (models.encode_cursor(rows[-1]["ts"], str(rows[-1]["seq"]))
                   if has_more and rows else None)
    return rows, has_more, next_cursor


def retention_candidates(connection: Any, object_name: str,
                         cutoff: datetime) -> int | None:
    """候选行数：只读 Owner 视图；视图未接线 → None（报告标 unknown，绝不直删）。"""
    source = facts.RETENTION_SOURCES.get(object_name)
    if source is None:
        return None
    _owner, view, time_column = source
    if not relation_exists(connection, view):
        return None
    row = _fetch_one(
        connection,
        f"SELECT count(*) AS n FROM {view} WHERE {time_column} < %(cutoff)s",   # noqa: S608
        {"cutoff": cutoff})
    return int(row["n"]) if row else None


def latest_balance_ts(connection: Any) -> datetime | None:
    if not relation_exists(connection, "account_balances_latest"):
        return None
    row = _fetch_one(connection, "SELECT max(created_at) AS last FROM account_balances_latest",
                     {})
    return row["last"] if row else None


def count_stuck_chain_tx(connection: Any, minutes: int) -> int | None:
    if not relation_exists(connection, "chain_tx_state"):
        return None
    row = _fetch_one(
        connection,
        "SELECT count(*) AS n FROM chain_tx_state"
        " WHERE status IN ('detected', 'held')"
        "   AND detected_at < now() - make_interval(mins => %(mins)s)",
        {"mins": int(minutes)})
    return int(row["n"]) if row else None


def latest_recon_run(connection: Any) -> dict | None:
    if not relation_exists(connection, "v_m09_run_diff"):
        return None
    return _fetch_one(
        connection,
        "SELECT run_id, scope, status, open_count, pending_p0_p1, open_p0, open_p1, open_p2"
        " FROM v_m09_run_diff ORDER BY run_id DESC LIMIT 1", {})


# ═══════════════════════════════════════════════════════════════ 操作回放（只读合并）
def audit_entries_for_replay(connection: Any, *, actor: str | None = None,
                             action_prefix: str | None = None,
                             from_at: datetime | None = None,
                             to_at: datetime | None = None,
                             cursor_ts: datetime | None = None,
                             cursor_rank: int | None = None,
                             cursor_id: int | None = None,
                             limit: int = facts.DEFAULT_PAGE_SIZE) -> list[dict]:
    """audit_log 侧时间线（rank=0）；游标 (ts desc, rank asc, id desc)。"""
    if not audit_log_available(connection):
        return []
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit}
    if actor:
        where.append("actor = %(actor)s")
        params["actor"] = actor
    if action_prefix:
        where.append("action LIKE %(action_like)s")
        params["action_like"] = f"{action_prefix}%"
    if from_at:
        where.append("ts >= %(from_at)s")
        params["from_at"] = from_at
    if to_at:
        where.append("ts <= %(to_at)s")
        params["to_at"] = to_at
    if cursor_ts is not None and cursor_rank is not None and cursor_id is not None:
        params["cts"] = cursor_ts
        params["cid"] = int(cursor_id)
        tail = "seq < %(cid)s" if cursor_rank == 0 else "FALSE"
        where.append(f"(ts < %(cts)s OR (ts = %(cts)s AND {tail}))")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    return _fetch_all(
        connection,
        "SELECT seq, entry_id, ts, actor, action, target, reason_code, evidence, after"
        " FROM audit_log" + clause +
        " ORDER BY ts DESC, seq DESC LIMIT %(limit)s", params)


def outbox_events_for_replay(connection: Any, *, trace_id: str | None = None,
                             event_type_prefix: str | None = None,
                             from_at: datetime | None = None,
                             to_at: datetime | None = None,
                             cursor_ts: datetime | None = None,
                             cursor_rank: int | None = None,
                             cursor_id: int | None = None,
                             limit: int = facts.DEFAULT_PAGE_SIZE) -> list[dict]:
    """本模块 outbox 侧时间线（rank=1）；只读本模块自有表。"""
    where: list[str] = []
    params: dict[str, Any] = {"limit": limit}
    if trace_id:
        where.append("trace_id = %(trace)s")
        params["trace"] = trace_id
    if event_type_prefix:
        where.append("type LIKE %(type_like)s")
        params["type_like"] = f"{event_type_prefix}%"
    if from_at:
        where.append("occurred_at >= %(from_at)s")
        params["from_at"] = from_at
    if to_at:
        where.append("occurred_at <= %(to_at)s")
        params["to_at"] = to_at
    if cursor_ts is not None and cursor_rank is not None and cursor_id is not None:
        params["cts"] = cursor_ts
        params["cid"] = int(cursor_id)
        tail = "id < %(cid)s" if cursor_rank == 1 else "TRUE"
        where.append(f"(occurred_at < %(cts)s OR (occurred_at = %(cts)s AND {tail}))")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    return _fetch_all(
        connection,
        "SELECT id, event_id, type, occurred_at, trace_id, aggregate_type, aggregate_id,"
        " payload, state FROM data_gov_outbox" + clause +
        " ORDER BY occurred_at DESC, id DESC LIMIT %(limit)s", params)
