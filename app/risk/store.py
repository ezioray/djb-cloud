# SPDX-License-Identifier: AGPL-3.0-or-later
"""M11 持久化层（psycopg3，无 ORM）。

隔离与安全：

* 案件 / 申诉 / 限额的读一律带 ``tenant_id``（跨租户 = 不存在 → 404，不泄露存在性）；
* 规则是平台级元数据（无租户维度）；
* 所有 SQL 参数化；JSONB 只放白名单键（阈值 / PII 在 events / migrations 双处兜底）；
* 写接口不 ``commit``：事务边界在 router / service（业务写入 + outbox 同事务）。
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Iterable, Mapping

from psycopg.rows import dict_row

from . import clock, facts, models
from .errors import BadRequest, CaseExists, NotFound

__all__ = [
    "get_latest_rule", "get_rule", "list_rules", "insert_rule", "find_rule_by_idempotency",
    "get_limit", "list_limits", "upsert_limit", "find_limit_by_idempotency",
    "insert_case", "get_case", "find_open_case", "list_cases", "append_decision",
    "append_evidence", "set_case_status", "case_decisions",
    "insert_appeal", "get_appeal", "find_open_appeal", "list_appeals_for_case",
    "decide_appeal", "escalate_overdue_appeals", "overdue_appeals",
]

RULE_COLUMNS = ("rule_key, version, enabled, severity, action_class, config_ref, created_at")
LIMIT_COLUMNS = ("tenant_id, subject_type, subject_id, limit_type, value, window_s, expires_at,"
                 " revision, updated_at")
CASE_COLUMNS = ("case_id, case_no, tenant_id, subject_type, subject_hash, risk_type, severity,"
                " status, rule_key, rule_version, config_ref, evidence_refs, decision, decisions,"
                " decided_by, decided_at, proposal_id, merged_into, opened_by, opened_at,"
                " closed_at, updated_at")
APPEAL_COLUMNS = ("appeal_id, case_id, tenant_id, status, reason, submitted_at, sla_due,"
                  " escalated_at, outcome, decision_reason, decided_by, decided_at, closed_at,"
                  " idempotency_key")


# ───────────────────────────────────────────────────────────────── 规则
def get_rule(conn: Any, rule_key: str, version: int | None = None) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        if version is None:
            cur.execute(
                f"SELECT {RULE_COLUMNS} FROM risk_rules WHERE rule_key = %s"
                " ORDER BY version DESC LIMIT 1", (rule_key,))
        else:
            cur.execute(
                f"SELECT {RULE_COLUMNS} FROM risk_rules WHERE rule_key = %s AND version = %s",
                (rule_key, version))
        return cur.fetchone()


def get_latest_rule(conn: Any, rule_key: str) -> dict[str, Any] | None:
    return get_rule(conn, rule_key)


def find_rule_by_idempotency(conn: Any, key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {RULE_COLUMNS} FROM risk_rules WHERE idempotency_key = %s", (key,))
        return cur.fetchone()


def list_rules(conn: Any, *, enabled: bool | None = None, cursor: str | None = None,
               limit: int = facts.DEFAULT_PAGE_SIZE) -> tuple[list[dict[str, Any]], bool, str | None]:
    conditions: list[str] = []
    params: list[Any] = []
    if enabled is not None:
        conditions.append("enabled = %s")
        params.append(bool(enabled))
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment, identity = parsed
        rule_key, _, version = identity.rpartition("#")
        # 排序是 created_at DESC, rule_key DESC, version DESC → 游标用同向的「严格更小」
        conditions.append(
            "(created_at < %s OR (created_at = %s AND (rule_key < %s"
            " OR (rule_key = %s AND version < %s))))")
        params.extend([moment, moment, rule_key, rule_key, int(version or 0)])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {RULE_COLUMNS} FROM risk_rules{where}"
            " ORDER BY created_at DESC, rule_key DESC, version DESC LIMIT %s", tuple(params))
        rows = list(cur.fetchall())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = models.encode_cursor(last["created_at"],
                                           f"{last['rule_key']}#{last['version']}")
    return rows, has_more, next_cursor


def insert_rule(conn: Any, draft: models.RuleDraft, *, version: int, created_by: str,
                idempotency_key: str | None) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO risk_rules (rule_key, version, enabled, severity, action_class,
                                    config_ref, created_by, idempotency_key)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {RULE_COLUMNS}
            """,
            (draft.rule_key, version, draft.enabled, draft.severity, draft.action_class,
             draft.config_ref, created_by, idempotency_key))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


# ───────────────────────────────────────────────────────────────── 限额
def get_limit(conn: Any, *, tenant_id: str, subject_type: str, subject_id: str,
              limit_type: str, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {LIMIT_COLUMNS} FROM risk_limits"
            " WHERE tenant_id = %s AND subject_type = %s AND subject_id = %s"
            f" AND limit_type = %s{suffix}",
            (tenant_id, subject_type, subject_id, limit_type))
        return cur.fetchone()


def find_limit_by_idempotency(conn: Any, key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {LIMIT_COLUMNS} FROM risk_limits WHERE idempotency_key = %s",
                    (key,))
        return cur.fetchone()


def list_limits(conn: Any, *, tenant_id: str, subject_type: str | None = None,
                subject_id: str | None = None, cursor: str | None = None,
                limit: int = facts.DEFAULT_PAGE_SIZE
                ) -> tuple[list[dict[str, Any]], bool, str | None]:
    conditions = ["tenant_id = %s"]
    params: list[Any] = [tenant_id]
    if subject_type is not None:
        conditions.append("subject_type = %s")
        params.append(subject_type)
    if subject_id is not None:
        conditions.append("subject_id = %s")
        params.append(subject_id)
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        _, identity = parsed
        st, sid, lt = identity.split("|", 2)
        conditions.append("(subject_type, subject_id, limit_type) > (%s, %s, %s)")
        params.extend([st, sid, lt])
    params.append(limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {LIMIT_COLUMNS} FROM v_risk_limits WHERE " + " AND ".join(conditions) +
            " ORDER BY subject_type, subject_id, limit_type LIMIT %s", tuple(params))
        rows = list(cur.fetchall())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = models.encode_cursor(
            last["updated_at"] or clock.utcnow(),
            f"{last['subject_type']}|{last['subject_id']}|{last['limit_type']}")
    return rows, has_more, next_cursor


def upsert_limit(conn: Any, draft: models.LimitDraft, *, tenant_id: str, set_by: str,
                 idempotency_key: str | None, now: datetime) -> tuple[dict[str, Any], bool]:
    """新增 / 调整限额；返回 ``(row, created)``。版本冲突由调用方先校验。"""
    existing = get_limit(conn, tenant_id=tenant_id, subject_type=draft.subject_type,
                         subject_id=draft.subject_id, limit_type=draft.limit_type, lock=True)
    if existing is None:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                f"""
                INSERT INTO risk_limits (tenant_id, subject_type, subject_id, limit_type, value,
                                         window_s, expires_at, revision, set_by,
                                         idempotency_key, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s, %s, %s, %s)
                RETURNING {LIMIT_COLUMNS}
                """,
                (tenant_id, draft.subject_type, draft.subject_id, draft.limit_type,
                 draft.value, draft.window_s, draft.expires_at, set_by, idempotency_key,
                 now, now))
            row = cur.fetchone()
        assert row is not None
        return dict(row), True
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE risk_limits
               SET value = %s, window_s = %s, expires_at = %s,
                   revision = revision + 1, set_by = %s,
                   idempotency_key = COALESCE(%s, idempotency_key), updated_at = %s
             WHERE tenant_id = %s AND subject_type = %s AND subject_id = %s AND limit_type = %s
             RETURNING {LIMIT_COLUMNS}
            """,
            (draft.value, draft.window_s, draft.expires_at, set_by, idempotency_key, now,
             tenant_id, draft.subject_type, draft.subject_id, draft.limit_type))
        row = cur.fetchone()
    assert row is not None
    return dict(row), False


# ───────────────────────────────────────────────────────────────── 案件
def insert_case(conn: Any, draft: models.CaseDraft) -> dict[str, Any]:
    from . import ids

    case_id = ids.uuid7()
    with conn.cursor(row_factory=dict_row) as cur:
        try:
            cur.execute(
                f"""
                INSERT INTO risk_cases (case_id, tenant_id, subject_type, subject_hash,
                                        risk_type, severity, status, rule_key, rule_version,
                                        config_ref, evidence_refs, decisions, opened_by,
                                        opened_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'opened', %s, %s, %s, %s, '[]'::jsonb, %s, %s)
                RETURNING {CASE_COLUMNS}
                """,
                (str(case_id), draft.tenant_id, draft.subject_type, draft.subject_hash,
                 draft.risk_type, draft.severity, draft.rule_key, draft.rule_version,
                 draft.config_ref, draft.evidence_refs, draft.opened_by, draft.opened_at))
        except Exception as exc:  # noqa: BLE001 - 唯一约束 → 48002（INV-06）
            import psycopg

            if isinstance(exc, psycopg.errors.UniqueViolation):
                raise CaseExists("同主体同类型已有未结案件（INV-06）") from exc
            raise
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def find_open_case(conn: Any, subject_hash: str, risk_type: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {CASE_COLUMNS} FROM risk_cases"
            " WHERE subject_hash = %s AND risk_type = %s"
            " AND status NOT IN ('closed', 'merged', 'dismissed')"
            " ORDER BY opened_at DESC LIMIT 1", (subject_hash, risk_type))
        return cur.fetchone()


def get_case(conn: Any, case_id: str, *, tenant_id: str | None = None,
             lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    params: list[Any] = [case_id]
    tenant_clause = ""
    if tenant_id is not None:
        tenant_clause = " AND tenant_id = %s"
        params.append(tenant_id)
    with conn.cursor(row_factory=dict_row) as cur:
        try:
            cur.execute(
                f"SELECT {CASE_COLUMNS} FROM risk_cases WHERE case_id = %s{tenant_clause}{suffix}",
                tuple(params))
        except Exception as exc:  # noqa: BLE001 - 非法 uuid → 不存在（404，不泄露）
            import psycopg

            if isinstance(exc, psycopg.errors.InvalidTextRepresentation):
                return None
            raise
        return cur.fetchone()


def list_cases(conn: Any, *, tenant_id: str, status: str | None = None,
               subject: str | None = None, cursor: str | None = None,
               limit: int = facts.DEFAULT_PAGE_SIZE
               ) -> tuple[list[dict[str, Any]], bool, str | None]:
    conditions = ["tenant_id = %s"]
    params: list[Any] = [tenant_id]
    if status is not None:
        conditions.append("status = %s")
        params.append(status)
    if subject is not None:
        conditions.append("subject_hash = %s")
        params.append(subject)
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment, case_id = parsed
        conditions.append("(opened_at, case_id) < (%s, %s)")
        params.extend([moment, case_id])
    params.append(limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {CASE_COLUMNS} FROM risk_cases WHERE " + " AND ".join(conditions) +
            " ORDER BY opened_at DESC, case_id DESC LIMIT %s", tuple(params))
        rows = list(cur.fetchall())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = models.encode_cursor(last["opened_at"], str(last["case_id"]))
    return rows, has_more, next_cursor


def case_decisions(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = row.get("decisions") or []
    if isinstance(raw, str):
        raw = json.loads(raw)
    return list(raw)


def append_decision(conn: Any, case_id: str, entry: Mapping[str, Any], *,
                    status: str, decision: str, decided_by: str, decided_at: datetime,
                    proposal_id: str | None, closed_at: datetime | None,
                    merged_into: str | None, evidence_refs: Iterable[str] | None = None
                    ) -> dict[str, Any]:
    """追加一条处置记录 + 推进状态（同一 UPDATE；触发器保证只追加）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE risk_cases
               SET status = %s,
                   decision = %s,
                   decided_by = %s,
                   decided_at = %s,
                   proposal_id = COALESCE(%s, proposal_id),
                   closed_at = COALESCE(%s, closed_at),
                   merged_into = COALESCE(%s, merged_into),
                   evidence_refs = CASE WHEN %s::text[] IS NULL THEN evidence_refs
                                        ELSE evidence_refs || %s::text[] END,
                   decisions = decisions || %s::jsonb
             WHERE case_id = %s
             RETURNING {CASE_COLUMNS}
            """,
            (status, decision, decided_by, decided_at, proposal_id, closed_at, merged_into,
             list(evidence_refs) if evidence_refs is not None else None,
             list(evidence_refs) if evidence_refs is not None else None,
             json.dumps([dict(entry)], ensure_ascii=False), case_id))
        row = cur.fetchone()
    if row is None:
        raise NotFound("案件不存在")
    return dict(row)


def append_evidence(conn: Any, case_id: str, refs: Iterable[str]) -> dict[str, Any]:
    values = [ref for ref in refs]
    if not values:
        return get_case(conn, case_id) or {}
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE risk_cases SET evidence_refs = evidence_refs || %s::text[]"
            f" WHERE case_id = %s RETURNING {CASE_COLUMNS}", (values, case_id))
        row = cur.fetchone()
    if row is None:
        raise NotFound("案件不存在")
    return dict(row)


def set_case_status(conn: Any, case_id: str, *, status: str,
                    closed_at: datetime | None = None) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE risk_cases SET status = %s, closed_at = COALESCE(%s, closed_at)"
            f" WHERE case_id = %s RETURNING {CASE_COLUMNS}", (status, closed_at, case_id))
        row = cur.fetchone()
    if row is None:
        raise NotFound("案件不存在")
    return dict(row)


# ───────────────────────────────────────────────────────────────── 申诉
def insert_appeal(conn: Any, *, appeal_id: str, case_id: str, tenant_id: str, reason: str,
                  submitted_at: datetime, sla_due: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO risk_appeals (appeal_id, case_id, tenant_id, status, reason,
                                      submitted_at, sla_due)
            VALUES (%s, %s, %s, 'submitted', %s, %s, %s)
            RETURNING {APPEAL_COLUMNS}
            """,
            (appeal_id, case_id, tenant_id, reason, submitted_at, sla_due))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_appeal(conn: Any, appeal_id: str, *, tenant_id: str | None = None,
               lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    params: list[Any] = [appeal_id]
    tenant_clause = ""
    if tenant_id is not None:
        tenant_clause = " AND tenant_id = %s"
        params.append(tenant_id)
    with conn.cursor(row_factory=dict_row) as cur:
        try:
            cur.execute(
                f"SELECT {APPEAL_COLUMNS} FROM risk_appeals WHERE appeal_id = %s"
                f"{tenant_clause}{suffix}", tuple(params))
        except Exception as exc:  # noqa: BLE001
            import psycopg

            if isinstance(exc, psycopg.errors.InvalidTextRepresentation):
                return None
            raise
        return cur.fetchone()


def find_open_appeal(conn: Any, case_id: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {APPEAL_COLUMNS} FROM risk_appeals"
            " WHERE case_id = %s AND status IN ('submitted', 'in_review')"
            " ORDER BY submitted_at DESC LIMIT 1", (case_id,))
        return cur.fetchone()


def list_appeals_for_case(conn: Any, case_id: str) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {APPEAL_COLUMNS} FROM risk_appeals WHERE case_id = %s"
                    " ORDER BY submitted_at ASC", (case_id,))
        return list(cur.fetchall())


def decide_appeal(conn: Any, appeal_id: str, *, outcome: str, reason: str, decided_by: str,
                  decided_at: datetime, idempotency_key: str | None = None) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE risk_appeals
               SET status = %s, outcome = %s, decision_reason = %s, decided_by = %s,
                   decided_at = %s, closed_at = %s, escalated_at = escalated_at,
                   idempotency_key = COALESCE(%s, idempotency_key)
             WHERE appeal_id = %s AND status IN ('submitted', 'in_review')
             RETURNING {APPEAL_COLUMNS}
            """,
            (outcome, outcome, reason, decided_by, decided_at, decided_at, idempotency_key,
             appeal_id))
        row = cur.fetchone()
    if row is None:
        raise NotFound("申诉不存在或已裁决")
    return dict(row)


def overdue_appeals(conn: Any, now: datetime) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {APPEAL_COLUMNS} FROM risk_appeals"
            " WHERE status IN ('submitted', 'in_review') AND sla_due < %s"
            " ORDER BY sla_due ASC", (now,))
        return list(cur.fetchall())


def escalate_overdue_appeals(conn: Any, now: datetime) -> list[dict[str, Any]]:
    """SLA 超期自动升级（P1）：打 ``escalated_at``；幂等（只打一次）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE risk_appeals
               SET escalated_at = %s
             WHERE status IN ('submitted', 'in_review') AND sla_due < %s
               AND escalated_at IS NULL
             RETURNING {APPEAL_COLUMNS}
            """, (now, now))
        return list(cur.fetchall())
