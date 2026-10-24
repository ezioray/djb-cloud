# SPDX-License-Identifier: AGPL-3.0-or-later
"""保留任务：矩阵 / dry-run / 删除报告 / (object, cutoff) 幂等 / 失败重放。

INV-05：删除先查争议保全（hold 由 Owner 执行器给出）→ 执行 → 删除报告
（已删 / 部分保留及原因 / 各最迟清除日 / 方式）→ 30 天内办结。
INV-07：同一 (object, cutoff) 只执行一次；失败不静默丢弃，可幂等重放。

**M14 永不 DELETE 业务表**：真正删除由 Owner 执行器（注入的 API 适配器 / M16 备份元数据）
完成，本模块只记录任务、报告与事件。
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping

from . import audit as audit_hook
from . import clock, errors, events, facts, ids, models, policy, store

__all__ = [
    "RetentionExecutor", "create_job", "replay_job", "list_jobs", "get_job",
    "build_report",
]

#: Owner 侧执行器契约：``(object, cutoff, dry_run) -> {candidates, deleted, retained,
#: retained_reasons, latest_clear_dates, method, hold}``。未接线返回 None。
RetentionExecutor = Callable[[str, datetime, bool], Mapping[str, Any] | None]

Config = Mapping[str, Any] | None


def _job_no(now: datetime) -> str:
    stamp = clock.as_utc(now).strftime("%Y%m%d%H%M%S")
    return f"RET-{stamp}-{secrets.token_hex(3).upper()}"[:32]


def _audit(sink: audit_hook.AuditSink | None, *, action: str, job_id: str, actor: str,
           reason: str, now: datetime, **details: Any) -> None:
    audit_hook.emit(sink, audit_hook.AuditRecord(
        action=action, object_type="retention_job", object_id=job_id,
        actor=actor, reason=reason, occurred_at=now, details=details))


def build_report(*, object_name: str, cutoff: datetime, policy_days: int, dry_run: bool,
                 result: Mapping[str, Any] | None, now: datetime,
                 note: str | None = None) -> dict[str, Any]:
    payload = dict(result or {})
    candidates = payload.get("candidates")
    deleted = int(payload.get("deleted") or 0)
    retained = int(payload.get("retained") or 0)
    reasons = payload.get("retained_reasons") or []
    if isinstance(reasons, Mapping):
        retained_items = [{"reason": key, "count": int(value)}
                          for key, value in reasons.items()]
    else:
        retained_items = [{"reason": str(item)} for item in reasons]
    latest = payload.get("latest_clear_dates") or {}
    report = {
        "object": object_name,
        "cutoff": clock.iso(cutoff),
        "policy_days": int(policy_days),
        "dry_run": bool(dry_run),
        "candidates": None if candidates is None else int(candidates),
        "deleted_count": deleted,
        "retained_count": retained,
        "retained": retained_items,
        "latest_clear_dates": dict(latest) if isinstance(latest, Mapping) else {},
        "method": str(payload.get("method") or "unwired"),
        "hold": bool(payload.get("hold", False)),
        "sampling": {"after_days": facts.RETENTION_SAMPLE_DAYS, "target_hits": 0,
                     "scheduled": not dry_run},
        "generated_at": clock.iso(now),
    }
    if dry_run:
        report["would_delete"] = None if candidates is None else int(candidates)
        report["deleted_count"] = 0
    if note:
        report["note"] = note
    return report


def _finish(connection: Any, row: Mapping[str, Any], *, now: datetime, trace_id: str,
            audit_sink: audit_hook.AuditSink | None,
            executor: RetentionExecutor | None) -> dict:
    job_id = str(row["job_id"])
    policy.assert_transition("retention", row["state"], "running")
    running = store.update_retention(connection, job_id, state="running", started_at=now)
    object_name = str(row["object"])
    cutoff = row["cutoff"]
    dry_run = bool(row["dry_run"])
    if executor is None:
        if dry_run:
            report = build_report(
                object_name=object_name, cutoff=cutoff, policy_days=int(row["policy_days"]),
                dry_run=True, result=None, now=now,
                note="Owner 只读 API / 视图未接线：候选数未知，未执行任何删除")
            return store.update_retention(
                connection, job_id, state="done", finished_at=now, deleted_count=0,
                retained_count=0, report=report) or running
        updated = store.update_retention(
            connection, job_id, state="failed", finished_at=now,
            failure_reason="owner_executor_unavailable",
            report=build_report(object_name=object_name, cutoff=cutoff,
                                policy_days=int(row["policy_days"]), dry_run=False,
                                result=None, now=now,
                                note="Owner 执行器未接线：fail-closed，不静默跳过"))
        _audit(audit_sink, action=facts.AUDIT_RETENTION_FAILED, job_id=job_id,
               actor=str(row["requested_by"]), reason="owner_executor_unavailable",
               now=now, object=object_name, trace_id=trace_id)
        return updated or running
    try:
        result = executor(object_name, cutoff, dry_run)
    except Exception as exc:                     # noqa: BLE001 - 失败必须留痕，不静默
        updated = store.update_retention(
            connection, job_id, state="failed", finished_at=now,
            failure_reason="owner_executor_error",
            report=build_report(object_name=object_name, cutoff=cutoff,
                                policy_days=int(row["policy_days"]), dry_run=dry_run,
                                result=None, now=now, note=f"执行器异常：{type(exc).__name__}"))
        _audit(audit_sink, action=facts.AUDIT_RETENTION_FAILED, job_id=job_id,
               actor=str(row["requested_by"]), reason="owner_executor_error", now=now,
               object=object_name, error_class=type(exc).__name__, trace_id=trace_id)
        return updated or running
    report = build_report(object_name=object_name, cutoff=cutoff,
                          policy_days=int(row["policy_days"]), dry_run=dry_run,
                          result=result, now=now)
    deleted = int(report["deleted_count"])
    retained = int(report["retained_count"])
    updated = store.update_retention(
        connection, job_id, state="done", finished_at=now, deleted_count=deleted,
        retained_count=retained, report=report)
    if not dry_run:
        envelope = events.build_envelope(
            facts.EVENT_RETENTION_EXECUTED,
            {"job_id": job_id, "object": object_name, "deleted_count": deleted},
            aggregate_type="retention_job", aggregate_id=job_id,
            trace_id=trace_id or f"m14-retention-{job_id}",
            idempotency_key=f"retention:{job_id}:executed", now=now,
            correlation_id=str(row["job_no"]))
        events.enqueue(connection, envelope)
    _audit(audit_sink, action=facts.AUDIT_RETENTION_COMPLETED, job_id=job_id,
           actor=str(row["requested_by"]), reason="保留任务完成", now=now,
           object=object_name, deleted_count=deleted, retained_count=retained,
           dry_run=dry_run, trace_id=trace_id)
    return updated or running


def create_job(connection: Any, *, requested_by: str, body: Mapping[str, Any],
               now: datetime, idempotency_key: str | None, trace_id: str = "",
               audit_sink: audit_hook.AuditSink | None = None,
               executor: RetentionExecutor | None = None) -> dict:
    draft = models.parse_retention_create(body, now=now)
    if idempotency_key:
        replay = store.find_retention_by_idempotency(connection, requested_by,
                                                     idempotency_key)
        if replay is not None:
            if (replay["object"] != draft.object or int(replay["policy_days"]) != draft.policy_days
                    or clock.as_utc(replay["cutoff"]) != clock.as_utc(draft.cutoff)
                    or bool(replay["dry_run"]) != draft.dry_run):
                raise errors.Conflict("幂等键已用于不同载荷（保留任务）",
                                      reason="idempotency_key_reused")
            return replay
    if draft.dry_run:
        preview = store.find_retention_preview(connection, draft.object, draft.cutoff)
        if preview is not None:
            return preview
    else:
        existing = store.find_retention_execution(connection, draft.object, draft.cutoff)
        if existing is not None:
            raise errors.Conflict(
                f"同一 (object, cutoff) 已执行（job_id={existing['job_id']}）：换 cutoff 或看报告",
                reason="retention_already_executed", job_id=str(existing["job_id"]))
    job_id = str(ids.uuid7())
    job_no = _job_no(now)
    row = store.insert_retention(
        connection, job_id=job_id, job_no=job_no, object_name=draft.object,
        policy_days=draft.policy_days, cutoff=draft.cutoff, dry_run=draft.dry_run,
        report_ref=f"report://retention/jobs/{job_no}", requested_by=requested_by,
        idempotency_key=idempotency_key,
        sla_due_at=clock.as_utc(now) + timedelta(days=facts.RETENTION_SLA_DAYS),
        created_at=now)
    _audit(audit_sink, action=facts.AUDIT_RETENTION_CREATED, job_id=job_id,
           actor=requested_by,
           reason=draft.reason or f"触发保留任务（dry_run={draft.dry_run}）",
           now=now, object=draft.object, cutoff=clock.iso(draft.cutoff),
           policy_days=draft.policy_days, trace_id=trace_id)
    return _finish(connection, row, now=now, trace_id=trace_id, audit_sink=audit_sink,
                   executor=executor)


def replay_job(connection: Any, job_id: str, *, now: datetime, trace_id: str = "",
               audit_sink: audit_hook.AuditSink | None = None,
               executor: RetentionExecutor | None = None) -> dict:
    row = store.get_retention(connection, job_id)
    if row is None:
        raise errors.NotFound("保留任务不存在")
    if row["state"] != "failed":
        raise errors.Conflict(f"只有 failed 任务可重放（当前 {row['state']}）",
                              reason="illegal_transition")
    policy.assert_transition("retention", "failed", "queued")
    queued = store.update_retention(
        connection, job_id, state="queued", failure_reason=None, started_at=None,
        finished_at=None, replay_count=int(row.get("replay_count") or 0) + 1)
    _audit(audit_sink, action=facts.AUDIT_RETENTION_REPLAYED, job_id=job_id,
           actor=str(row["requested_by"]), reason="失败任务幂等重放（不跳期）", now=now,
           object=str(row["object"]), trace_id=trace_id)
    return _finish(connection, queued or row, now=now, trace_id=trace_id,
                   audit_sink=audit_sink, executor=executor)


def get_job(connection: Any, job_id: str) -> dict:
    row = store.get_retention(connection, job_id)
    if row is None:
        raise errors.NotFound("保留任务不存在")
    return row


def list_jobs(connection: Any, *, object_name: str | None = None,
              state: str | None = None, dry_run: bool | None = None,
              cursor: str | None = None, limit: int = facts.DEFAULT_PAGE_SIZE
              ) -> tuple[list[dict], bool, str | None]:
    return store.list_retentions(connection, object_name=object_name, state=state,
                                 dry_run=dry_run, cursor=cursor, limit=limit)
