# SPDX-License-Identifier: AGPL-3.0-or-later
"""M09 存储层（psycopg3，无 ORM）：对账批次 / 差异 / 凭证的读写。

边界纪律：
* 只读写 M09 自己的 5 张表；对 M05（usage_records / metering_receipts）与 M06
  （journal_entry / journal_line / account_balances）**只读**，读写分离在 :mod:`engine`；
* 事务边界由调用方给（``with conn.transaction():``）：run + 差异 + 幂等键同事务（M09 §6.1 第 5 步）；
* 行一律以 dict 返回（``dict_row``），字段名与迁移列名一致，payload 转换在 :mod:`models`。

INV-01（diff_minor = 未关闭差异之和）由库层触发器维护（902），本层**不写** diff_minor。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

import uuid

import psycopg
from psycopg.rows import dict_row

from . import clock, facts, models
from .errors import Conflict, ExceptionStateConflict, RunNotFound

__all__ = [
    "RUN_COLUMNS", "EXCEPTION_COLUMNS", "ATTESTATION_COLUMNS",
    "insert_run", "find_run_by_key", "find_run_by_trigger", "get_run", "require_run", "list_runs", "update_run",
    "diff_summary", "pending_p0_p1",
    "insert_exception", "get_exception", "list_exceptions", "resolve_exception_row",
    "insert_attestation", "get_attestation", "find_valid_attestation",
    "find_attestation_by_idempotency", "transition_attestation",
]

RUN_COLUMNS = (
    "run_id, scope, subject_ref, period_start, period_end, cutoff_at, block_height, book_minor, "
    "external_minor, diff_minor, matched_count, unmatched_count, status, rule_version, "
    "policy_version, trigger_event_id, report_ref, metrics, tenant_id, created_by, "
    "signed_off_by, signed_off_at, reviewer_note, signoff_idempotency_key, created_at, updated_at"
)

EXCEPTION_COLUMNS = (
    "exception_id, run_id, scope, kind, severity, ref_type, ref_id, diff_minor, owner, sla_due, "
    "status, resolution_code, resolution_journal_id, root_cause, evidence_ref, resolved_by, "
    "resolve_idempotency_key, closed_at, created_at, updated_at"
)

ATTESTATION_COLUMNS = (
    "attestation_id, period_start, period_end, ledger_root, chain_snapshot_ref, "
    "bank_snapshot_ref, balances_ref, payable_total_minor, batch_hash, reviewer_id, "
    "reviewer_pubkey_ref, maker_id, signature_ref, hsm_verified_at, status, tenant_id, "
    "idempotency_key, created_at, updated_at"
)


def _uuid_text(value: Any) -> str | None:
    """把 id 规整成 UUID 文本；非法形态直接返回 None（按「不存在」处理，不打库）。

    为什么不在 SQL 里靠类型转换报错：一条 ``InvalidTextRepresentation`` 会把所在事务打成
    aborted，后续错误信封都发不出去（M09 的读接口都跑在请求级 SAVEPOINT 里）。
    """
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


# ───────────────────────────────────────────────────────────── 批次
def _jsonify(row: Mapping[str, Any]) -> dict[str, Any]:
    """JSONB 列需要 Json wrapper（psycopg3 不会自动把 dict 当 jsonb）。"""
    from psycopg.types.json import Json

    return {key: (Json(value) if key == "metrics" else value) for key, value in row.items()}


def insert_run(conn: psycopg.Connection, spec: models.RunSpec, *, book_minor: int = 0,
               external_minor: int = 0, matched_count: int = 0, unmatched_count: int = 0,
               status: str = "running", report_ref: str | None = None,
               metrics: Mapping[str, Any] | None = None,
               now: datetime | None = None) -> dict[str, Any]:
    """插入一条 run（调用方负责事务与 INV-04 冲突处理）。"""
    moment = clock.as_utc(now or clock.utcnow())
    row = {
        "run_id": models.uuid7(moment),
        "scope": spec.scope,
        "subject_ref": spec.subject_ref,
        "period_start": spec.period_start,
        "period_end": spec.period_end,
        "cutoff_at": spec.cutoff_at,
        "block_height": spec.block_height,
        "book_minor": int(book_minor),
        "external_minor": int(external_minor),
        "diff_minor": 0,
        "matched_count": int(matched_count),
        "unmatched_count": int(unmatched_count),
        "status": status,
        "rule_version": spec.rule_version,
        "policy_version": spec.policy_version,
        "trigger_event_id": spec.trigger_event_id,
        "report_ref": report_ref,
        "metrics": dict(metrics or {}),
        "tenant_id": spec.tenant_id,
        "created_by": spec.created_by,
        "signed_off_by": None,
        "signed_off_at": None,
        "reviewer_note": None,
        "signoff_idempotency_key": None,
        "created_at": moment,
        "updated_at": moment,
    }
    columns = ", ".join(row)
    placeholders = ", ".join(f"%({name})s" for name in row)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"INSERT INTO reconciliation_runs ({columns}) VALUES ({placeholders}) RETURNING {RUN_COLUMNS}",
            _jsonify(row))
        return cur.fetchone()


def find_run_by_key(conn: psycopg.Connection, spec: models.RunSpec) -> dict[str, Any] | None:
    """INV-04 唯一键查既有 run（同键重放返回原批次）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""SELECT {RUN_COLUMNS} FROM reconciliation_runs
                 WHERE scope = %s AND COALESCE(subject_ref, '') = %s
                   AND period_start = %s AND period_end = %s AND cutoff_at = %s""",
            (spec.scope, spec.subject_ref or "", spec.period_start, spec.period_end,
             spec.cutoff_at))
        return cur.fetchone()


def find_run_by_trigger(conn: psycopg.Connection,
                        trigger_event_id: str | None) -> dict[str, Any] | None:
    """按 ``trigger_event_id`` 找既有 run（事件重放幂等；§5「trigger_event_id 唯一」）。"""
    if not trigger_event_id:
        return None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {RUN_COLUMNS} FROM reconciliation_runs WHERE trigger_event_id = %s",
                    (trigger_event_id,))
        return cur.fetchone()


def get_run(conn: psycopg.Connection, run_id: str, *, tenant_id: str | None = None,
            lock: bool = False) -> dict[str, Any] | None:
    """按 id 取 run。

    租户口径（M09 是内部资金台，批次多数是**平台级**）：
    ``tenant_id IS NULL``（平台级）对所有管理主体可见；带 tenant 的批次只对本租户可见，
    跨租户按「不存在」处理（404，不泄露存在性）。
    """
    clause = "run_id = %s"
    params: list[Any] = [run_id]
    if tenant_id is not None:
        clause += " AND (tenant_id IS NULL OR tenant_id = %s)"
        params.append(tenant_id)
    sql = f"SELECT {RUN_COLUMNS} FROM reconciliation_runs WHERE {clause}"
    if lock:
        sql += " FOR UPDATE"
    key = _uuid_text(run_id)
    if key is None:
        return None
    params[0] = key
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def require_run(conn: psycopg.Connection, run_id: str, *, tenant_id: str | None = None,
                lock: bool = False) -> dict[str, Any]:
    row = get_run(conn, run_id, tenant_id=tenant_id, lock=lock)
    if row is None:
        raise RunNotFound("对账批次不存在")
    return row


def list_runs(conn: psycopg.Connection, *, scope: str | None = None, status: str | None = None,
              from_ts: datetime | None = None, to_ts: datetime | None = None,
              tenant_id: str | None = None, cursor: str | None = None,
              limit: int = facts.DEFAULT_PAGE_SIZE) -> tuple[list[dict], bool, str | None]:
    """按 ``cutoff_at DESC, run_id DESC`` 游标分页（spec `Cursor`）。"""
    clauses: list[str] = []
    params: list[Any] = []
    if scope:
        clauses.append("scope = %s")
        params.append(scope)
    if status:
        clauses.append("status = %s")
        params.append(status)
    if from_ts is not None:
        clauses.append("cutoff_at >= %s")
        params.append(from_ts)
    if to_ts is not None:
        clauses.append("cutoff_at <= %s")
        params.append(to_ts)
    if tenant_id is not None:
        clauses.append("(tenant_id IS NULL OR tenant_id = %s)")
        params.append(tenant_id)
    decoded = models.decode_cursor(cursor)
    if decoded is not None:
        moment, identity = decoded
        clauses.append("(cutoff_at, run_id) < (%s, %s::uuid)")
        params.extend([moment, identity])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(int(limit) + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {RUN_COLUMNS} FROM reconciliation_runs {where} "
            "ORDER BY cutoff_at DESC, run_id DESC LIMIT %s", params)
        rows = cur.fetchall()
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = (models.encode_cursor(page[-1]["cutoff_at"], str(page[-1]["run_id"]))
                   if has_more and page else None)
    return page, has_more, next_cursor


def update_run(conn: psycopg.Connection, run_id: str, *, now: datetime | None = None,
               **fields: Any) -> dict[str, Any]:
    """更新 run 可变列（库层护栏会拒绝非法迁移 / 签核后改动）。"""
    if not fields:
        raise ValueError("update_run 至少需要一个字段")
    allowed = {"status", "diff_minor", "matched_count", "unmatched_count", "report_ref",
               "signed_off_at", "signed_off_by", "reviewer_note", "signoff_idempotency_key"}
    unknown = set(fields) - allowed
    if unknown:
        raise ValueError(f"update_run 不允许改的列：{sorted(unknown)}")
    moment = clock.as_utc(now or clock.utcnow())
    assignments = ", ".join(f"{name} = %({name})s" for name in fields)
    payload = dict(fields)
    payload["updated_at"] = moment
    payload["run_id"] = run_id
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE reconciliation_runs SET {assignments}, updated_at = %(updated_at)s "
            f"WHERE run_id = %(run_id)s RETURNING {RUN_COLUMNS}", payload)
        row = cur.fetchone()
    if row is None:
        raise RunNotFound("对账批次不存在")
    return row


def diff_summary(conn: psycopg.Connection, run_id: str) -> dict[str, Any]:
    """ReconDiffSummary（spec）：未结 P0/P1 + 按严重度 / 状态计数。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """SELECT count(*) FILTER (WHERE status <> 'closed' AND severity IN ('P0','P1'))
                      AS pending_p0_p1,
                      count(*) FILTER (WHERE status <> 'closed' AND severity = 'P0') AS p0,
                      count(*) FILTER (WHERE status <> 'closed' AND severity = 'P1') AS p1,
                      count(*) FILTER (WHERE status <> 'closed' AND severity = 'P2') AS p2,
                      count(*) FILTER (WHERE status = 'open') AS st_open,
                      count(*) FILTER (WHERE status = 'investigating') AS st_investigating,
                      count(*) FILTER (WHERE status = 'escalated') AS st_escalated,
                      count(*) FILTER (WHERE status = 'resolved') AS st_resolved,
                      count(*) FILTER (WHERE status = 'accepted') AS st_accepted,
                      count(*) FILTER (WHERE status = 'closed') AS st_closed
                 FROM reconciliation_exceptions WHERE run_id = %s""", (run_id,))
        row = cur.fetchone()
    return {
        "pending_p0_p1": int(row["pending_p0_p1"]),
        "by_severity": {"P0": int(row["p0"]), "P1": int(row["p1"]), "P2": int(row["p2"])},
        "by_status": {
            "open": int(row["st_open"]),
            "investigating": int(row["st_investigating"]),
            "escalated": int(row["st_escalated"]),
            "resolved": int(row["st_resolved"]),
            "accepted": int(row["st_accepted"]),
            "closed": int(row["st_closed"]),
        },
    }


def pending_p0_p1(conn: psycopg.Connection, run_id: str) -> dict[str, Any]:
    """INV-03 的判定输入：未结 P0/P1 数量（不读缓存，直接数差异表）。"""
    summary = diff_summary(conn, run_id)
    return {"pending": summary["pending_p0_p1"], "by_severity": summary["by_severity"]}


# ───────────────────────────────────────────────────────────── 差异
def insert_exception(conn: psycopg.Connection, *, run_id: str, scope: str,
                     draft: models.ExceptionDraft, now: datetime | None = None) -> dict[str, Any]:
    moment = clock.as_utc(now or clock.utcnow())
    row = {
        "exception_id": models.uuid7(moment),
        "run_id": run_id,
        "scope": scope,
        "kind": draft.kind,
        "severity": draft.severity,
        "ref_type": draft.ref_type,
        "ref_id": draft.ref_id,
        "diff_minor": int(draft.diff_minor),
        "owner": draft.owner,
        "sla_due": draft.sla_due,
        "status": "open",
        "resolution_code": None,
        "resolution_journal_id": None,
        "root_cause": draft.root_cause,
        "evidence_ref": draft.evidence_ref,
        "resolved_by": None,
        "resolve_idempotency_key": None,
        "closed_at": None,
        "created_at": moment,
        "updated_at": moment,
    }
    columns = ", ".join(row)
    placeholders = ", ".join(f"%({name})s" for name in row)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"INSERT INTO reconciliation_exceptions ({columns}) VALUES ({placeholders}) "
            f"RETURNING {EXCEPTION_COLUMNS}", row)
        return cur.fetchone()


def get_exception(conn: psycopg.Connection, exception_id: str, *,
                  lock: bool = False) -> dict[str, Any] | None:
    sql = f"SELECT {EXCEPTION_COLUMNS} FROM reconciliation_exceptions WHERE exception_id = %s"
    if lock:
        sql += " FOR UPDATE"
    key = _uuid_text(exception_id)
    if key is None:
        return None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, (key,))
        return cur.fetchone()


def list_exceptions(conn: psycopg.Connection, *, run_id: str | None = None,
                    severity: str | None = None, status: str | None = None,
                    owner: str | None = None, scope: str | None = None,
                    tenant_id: str | None = None, cursor: str | None = None,
                    limit: int = facts.DEFAULT_PAGE_SIZE) -> tuple[list[dict], bool, str | None]:
    """按 ``sla_due ASC, exception_id ASC`` 游标分页（最紧急的先出）。"""
    clauses: list[str] = []
    params: list[Any] = []
    if tenant_id is not None:
        clauses.append("e.run_id IN (SELECT run_id FROM reconciliation_runs"
                       " WHERE tenant_id IS NULL OR tenant_id = %s)")
        params.append(tenant_id)
    if run_id:
        clauses.append("e.run_id = %s::uuid")
        params.append(run_id)
    if severity:
        clauses.append("e.severity = %s")
        params.append(severity)
    if status:
        clauses.append("e.status = %s")
        params.append(status)
    if owner:
        clauses.append("e.owner = %s")
        params.append(owner)
    if scope:
        clauses.append("e.scope = %s")
        params.append(scope)
    decoded = models.decode_cursor(cursor)
    if decoded is not None:
        moment, identity = decoded
        clauses.append("(e.sla_due, e.exception_id) > (%s, %s::uuid)")
        params.extend([moment, identity])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(int(limit) + 1)
    columns = ", ".join(f"e.{name.strip()}" for name in EXCEPTION_COLUMNS.split(","))
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {columns} FROM reconciliation_exceptions e {where} "
            "ORDER BY e.sla_due ASC, e.exception_id ASC LIMIT %s", params)
        rows = cur.fetchall()
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = (models.encode_cursor(page[-1]["sla_due"], str(page[-1]["exception_id"]))
                   if has_more and page else None)
    return page, has_more, next_cursor


def resolve_exception_row(conn: psycopg.Connection, row: Mapping[str, Any],
                          request: models.ResolveRequest, *, actor: str | None,
                          idempotency_key: str | None, now: datetime | None = None) -> dict[str, Any]:
    """把差异置 closed（状态机由库层再校验一次）。"""
    if row["status"] == facts.EXCEPTION_CLOSED:
        raise ExceptionStateConflict("差异已关闭：不可重开（M09 §3.2）",
                                     reason="exception_already_closed")
    if row["status"] not in facts.EXCEPTION_OPEN_STATUSES + ("resolved", "accepted"):
        raise ExceptionStateConflict("差异当前状态不允许处置",
                                     reason="exception_state_not_resolvable")
    if (request.resolution_code in facts.RESOLUTION_REQUIRES_JOURNAL
            and not request.resolution_journal_id):
        raise ExceptionStateConflict(
            "resolution_code=adjust_journal 必须带已入账的 resolution_journal_id（M09 §6.2）",
            reason="journal_id_required")
    if (request.resolution_code in facts.RESOLUTION_REQUIRES_CAUSE and not request.root_cause):
        raise ExceptionStateConflict(
            f"resolution_code={request.resolution_code} 必须带 root_cause（M09 §6.2）",
            reason="root_cause_required")
    moment = clock.as_utc(now or clock.utcnow())
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""UPDATE reconciliation_exceptions
                   SET status = 'closed', resolution_code = %(code)s,
                       resolution_journal_id = %(journal)s, root_cause = COALESCE(%(cause)s, root_cause),
                       evidence_ref = COALESCE(%(evidence)s, evidence_ref),
                       resolved_by = %(actor)s, resolve_idempotency_key = COALESCE(%(key)s, resolve_idempotency_key),
                       closed_at = %(moment)s, updated_at = %(moment)s
                 WHERE exception_id = %(exception_id)s RETURNING {EXCEPTION_COLUMNS}""",
            {"code": request.resolution_code, "journal": request.resolution_journal_id,
             "cause": request.root_cause, "evidence": request.evidence_ref, "actor": actor,
             "key": idempotency_key, "moment": moment,
             "exception_id": str(row["exception_id"])})
        return cur.fetchone()



# ───────────────────────────────────────────────────────────── 复核凭证
def insert_attestation(conn: psycopg.Connection, draft: models.AttestationDraft, *,
                       reviewer_id: str | None, now: datetime | None = None,
                       balances_ref: str | None = None) -> dict[str, Any]:
    moment = clock.as_utc(now or clock.utcnow())
    row = {
        "attestation_id": models.uuid7(moment),
        "period_start": draft.period_start,
        "period_end": draft.period_end,
        "ledger_root": draft.ledger_root,
        "chain_snapshot_ref": draft.chain_snapshot_ref,
        "bank_snapshot_ref": draft.bank_snapshot_ref,
        "balances_ref": balances_ref,
        "payable_total_minor": int(draft.payable_total_minor),
        "batch_hash": draft.batch_hash,
        "reviewer_id": reviewer_id,
        "reviewer_pubkey_ref": None,
        "maker_id": draft.maker_id,
        "signature_ref": draft.signature_ref,
        "hsm_verified_at": None,
        "status": "valid",
        "tenant_id": draft.tenant_id,
        "idempotency_key": draft.idempotency_key,
        "created_at": moment,
        "updated_at": moment,
    }
    columns = ", ".join(row)
    placeholders = ", ".join(f"%({name})s" for name in row)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"INSERT INTO reconciliation_attestations ({columns}) VALUES ({placeholders}) "
            f"RETURNING {ATTESTATION_COLUMNS}", row)
        return cur.fetchone()


def get_attestation(conn: psycopg.Connection, attestation_id: str, *,
                    lock: bool = False) -> dict[str, Any] | None:
    sql = f"SELECT {ATTESTATION_COLUMNS} FROM reconciliation_attestations WHERE attestation_id = %s"
    if lock:
        sql += " FOR UPDATE"
    key = _uuid_text(attestation_id)
    if key is None:
        return None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, (key,))
        return cur.fetchone()


def find_valid_attestation(conn: psycopg.Connection, draft: models.AttestationDraft) -> dict[str, Any] | None:
    """INV-05 查询：同 (period_start, period_end, batch_hash) 的 valid 凭证。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""SELECT {ATTESTATION_COLUMNS} FROM reconciliation_attestations
                 WHERE period_start = %s AND period_end = %s AND batch_hash = %s
                   AND status = 'valid'""",
            (draft.period_start, draft.period_end, draft.batch_hash))
        return cur.fetchone()


def find_attestation_by_idempotency(conn: psycopg.Connection,
                                    key: str | None) -> dict[str, Any] | None:
    if not key:
        return None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {ATTESTATION_COLUMNS} FROM reconciliation_attestations "
            "WHERE idempotency_key = %s", (key,))
        return cur.fetchone()


def transition_attestation(conn: psycopg.Connection, attestation_id: str, *, to_status: str,
                           now: datetime | None = None) -> dict[str, Any]:
    """valid -> superseded / revoked（唯一合法流转，库层也会再校验）。"""
    if to_status not in facts.ATTESTATION_STATUSES[1:]:
        raise ValueError(f"不能流转到 {to_status!r}")
    moment = clock.as_utc(now or clock.utcnow())
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""UPDATE reconciliation_attestations SET status = %s, updated_at = %s
                 WHERE attestation_id = %s RETURNING {ATTESTATION_COLUMNS}""",
            (to_status, moment, attestation_id))
        row = cur.fetchone()
    if row is None:                                 # pragma: no cover - 调用方已锁行
        raise Conflict("凭证不存在或不可流转", reason="attestation_transition_failed")
    return row
