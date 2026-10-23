# SPDX-License-Identifier: Apache-2.0
"""导出闭环：申请 → 审批（双人）→ 执行 → 完成（水印 + 签名链接）→ 取消 / 过期。

INV-04 落地：范围白名单 + 行数上限（``49001``）+ 大导出双人复核（>1,000 行或含个人信息）
+ 同一人 24h ≤1 次大导出 + 链接 TTL ≤15 分钟 + 一次性 + 水印 + 全程审计。

事务边界：本模块自有表本地事务；携带的数据由 Owner API 拉取，M14 不读写任何业务表。
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping

from . import audit as audit_hook
from . import clock, errors, events, facts, ids, models, policy, store

__all__ = [
    "create_request", "approve_request", "start_request", "complete_request",
    "fail_request", "cancel_request", "list_requests", "get_request", "mint_link",
    "consume_link", "expire_due",
]

Config = Mapping[str, Any] | None


def _config(config: Config, key: str, default: Any = None) -> Any:
    if not isinstance(config, Mapping):
        return default
    return config.get(key, default)


def _export_no(now: datetime) -> str:
    stamp = clock.as_utc(now).strftime("%Y%m%d%H%M%S")
    return f"EXP-{stamp}-{secrets.token_hex(3).upper()}"[:32]


def _requester_tenant(row: Mapping[str, Any]) -> str:
    return str(row["requester_tenant"])


def _same_draft(row: Mapping[str, Any], draft: models.ExportDraft) -> bool:
    return (dict(row["scope"]) == dict(draft.scope)
            and [str(item) for item in row["format"]] == list(draft.format)
            and row["reason"] == draft.reason
            and int(row["estimated_rows"]) == draft.estimated_rows
            and bool(row["contains_personal_data"]) == draft.contains_personal_data)


def _audit(sink: audit_hook.AuditSink | None, *, action: str, object_id: str,
           actor: str, reason: str, now: datetime, **details: Any) -> None:
    audit_hook.emit(sink, audit_hook.AuditRecord(
        action=action, object_type="data_export_request", object_id=object_id,
        actor=actor, reason=reason, occurred_at=now, details=details))


# ═══════════════════════════════════════════════════════════ 申请 / 审批
def create_request(connection: Any, *, requester: str, tenant_id: str,
                   body: Mapping[str, Any], now: datetime, idempotency_key: str | None,
                   trace_id: str, audit_sink: audit_hook.AuditSink | None = None,
                   config: Config = None) -> dict:
    draft = models.parse_export_create(body, now=now)
    max_rows = policy.resolve_export_max_rows(_config(config, "data.export_max_rows"))
    if draft.estimated_rows > max_rows:
        raise errors.ExportTooLarge(
            f"预估行数 {draft.estimated_rows} 超过上限 {max_rows}：请拆小范围后重新申请",
            max_rows=max_rows)
    approval_required = policy.dual_review_required(draft.estimated_rows,
                                                    draft.contains_personal_data)
    if idempotency_key:
        replay = store.find_export_by_idempotency(connection, requester, idempotency_key)
        if replay is not None:
            if not _same_draft(replay, draft):
                raise errors.Conflict("幂等键已用于不同载荷（导出申请）",
                                      reason="idempotency_key_reused")
            return replay
    if approval_required:
        since = now - timedelta(seconds=facts.EXPORT_DAILY_WINDOW_S)
        used = store.count_large_exports(connection, requester, since)
        if used >= facts.EXPORT_DAILY_LARGE_LIMIT:
            raise errors.Conflict(
                "同一人 24h 内最多 1 次大导出：请等待窗口结束或拆小范围",
                reason="large_export_daily_limit")
    export_id = str(ids.uuid7())
    row = store.insert_export(
        connection, export_id=export_id, export_no=_export_no(now), requester=requester,
        tenant_id=tenant_id, scope=draft.scope, fmt=draft.format, reason=draft.reason,
        estimated_rows=draft.estimated_rows,
        contains_personal_data=draft.contains_personal_data,
        approval_required=approval_required, idempotency_key=idempotency_key,
        created_at=now,
        expires_at=clock.as_utc(now) + timedelta(days=facts.EXPORT_FILE_TTL_D))
    _audit(audit_sink, action=facts.AUDIT_EXPORT_REQUESTED, object_id=export_id,
           actor=requester, reason=draft.reason, now=now,
           scope_object=draft.scope["object"], format=list(draft.format),
           estimated_rows=draft.estimated_rows, approval_required=approval_required,
           trace_id=trace_id)
    return row


def approve_request(connection: Any, export_id: str, *, approver: str, tenant_id: str,
                    now: datetime, audit_sink: audit_hook.AuditSink | None = None,
                    trace_id: str = "") -> dict:
    row = store.get_export(connection, export_id)
    if row is None or _requester_tenant(row) != tenant_id:
        raise errors.NotFound("导出申请不存在")
    if row["state"] == "approved":
        if row["approver"] == approver:
            return row                                   # 幂等：同一审批人重放
        raise errors.Conflict("该申请已由他人审批", reason="already_approved")
    if row["state"] != "pending":
        raise errors.Conflict(
            f"当前状态 {row['state']} 不可审批", reason="illegal_transition")
    if approver == row["requester"]:
        raise errors.Forbidden("审批人不得与申请人相同（双人复核）",
                               reason="separation_of_duty")
    policy.assert_transition("export", row["state"], "approved")
    updated = store.update_export(connection, export_id, state="approved",
                                  approver=approver, approved_at=now)
    _audit(audit_sink, action=facts.AUDIT_EXPORT_APPROVED, object_id=export_id,
           actor=approver, reason="双人复核通过", now=now, requester=row["requester"],
           trace_id=trace_id)
    return updated or row


def start_request(connection: Any, export_id: str, *, now: datetime,
                  audit_sink: audit_hook.AuditSink | None = None,
                  trace_id: str = "") -> dict:
    row = store.get_export(connection, export_id)
    if row is None:
        raise errors.NotFound("导出申请不存在")
    policy.assert_transition("export", row["state"], "running")
    updated = store.update_export(connection, export_id, state="running", started_at=now)
    _audit(audit_sink, action=facts.AUDIT_EXPORT_STARTED, object_id=export_id,
           actor=str(row["requester"]), reason="打包作业开始", now=now, trace_id=trace_id)
    return updated or row


def complete_request(connection: Any, export_id: str, *, row_count: int, now: datetime,
                     trace_id: str = "", audit_sink: audit_hook.AuditSink | None = None,
                     config: Config = None) -> dict:
    row = store.get_export(connection, export_id)
    if row is None:
        raise errors.NotFound("导出申请不存在")
    policy.assert_transition("export", row["state"], "done")
    max_rows = policy.resolve_export_max_rows(_config(config, "data.export_max_rows"))
    if row_count < 0:
        raise errors.BadRequest("row_count 不得为负", field="row_count")
    if row_count > max_rows:
        failed = fail_request(connection, export_id, reason="row_limit_exceeded",
                              now=now, audit_sink=audit_sink, trace_id=trace_id)
        return failed
    watermark = policy.make_watermark(str(row["export_no"]), str(row["requester"]), now)
    expires_at = clock.as_utc(now) + timedelta(days=facts.EXPORT_FILE_TTL_D)
    updated = store.update_export(
        connection, export_id, state="done", row_count=int(row_count), finished_at=now,
        expires_at=expires_at, watermark=watermark)
    envelope = events.build_envelope(
        facts.EVENT_EXPORT_COMPLETED,
        {"export_id": export_id, "requester": str(row["requester"]), "rows": int(row_count)},
        aggregate_type="data_export_request", aggregate_id=export_id,
        trace_id=trace_id or f"m14-export-{export_id}",
        idempotency_key=f"data_export:{export_id}:completed", now=now,
        correlation_id=str(row["export_no"]))
    events.enqueue(connection, envelope)
    _audit(audit_sink, action=facts.AUDIT_EXPORT_COMPLETED, object_id=export_id,
           actor=str(row["requester"]), reason="导出打包完成", now=now,
           rows=int(row_count), watermark=watermark, trace_id=trace_id,
           file_expires_at=clock.iso(expires_at))
    return updated or row


def fail_request(connection: Any, export_id: str, *, reason: str, now: datetime,
                 audit_sink: audit_hook.AuditSink | None = None,
                 trace_id: str = "") -> dict:
    row = store.get_export(connection, export_id)
    if row is None:
        raise errors.NotFound("导出申请不存在")
    if row["state"] not in ("pending", "approved", "running"):
        raise errors.Conflict(f"当前状态 {row['state']} 不可失败关闭",
                              reason="illegal_transition")
    failure = models.require_text(reason, field="failure_reason", max_len=64)
    updated = store.update_export(connection, export_id, state="failed",
                                  failure_reason=failure, finished_at=now)
    _audit(audit_sink, action=facts.AUDIT_EXPORT_FAILED, object_id=export_id,
           actor=str(row["requester"]), reason=failure, now=now, trace_id=trace_id)
    return updated or row


def cancel_request(connection: Any, export_id: str, *, actor: str, now: datetime,
                   audit_sink: audit_hook.AuditSink | None = None,
                   trace_id: str = "") -> dict:
    row = store.get_export(connection, export_id)
    if row is None:
        raise errors.NotFound("导出申请不存在")
    if row["state"] == "failed" and row.get("failure_reason") == "cancelled_by_requester":
        return row                                  # 幂等：已取消的再取消直接回放
    if row["state"] not in facts.EXPORT_CANCELLABLE_STATES:
        raise errors.Conflict(
            f"取消只对未执行申请生效（当前 state={row['state']}）",
            reason="cancel_not_allowed")
    updated = store.update_export(
        connection, export_id, state="failed",
        failure_reason="cancelled_by_requester", cancelled_at=now, cancelled_by=actor,
        finished_at=now)
    _audit(audit_sink, action=facts.AUDIT_EXPORT_CANCELLED, object_id=export_id,
           actor=actor, reason="申请人取消（未执行）", now=now, trace_id=trace_id,
           previous_state=str(row["state"]))
    return updated or row


# ═══════════════════════════════════════════════════════════ 查询 / 过期
def expire_due(connection: Any, *, now: datetime,
               audit_sink: audit_hook.AuditSink | None = None,
               trace_id: str = "") -> int:
    rows = store.expire_due_exports(connection, now)
    for row in rows:
        _audit(audit_sink, action=facts.AUDIT_EXPORT_EXPIRED,
               object_id=str(row["export_id"]), actor="m14-system",
               reason="文件 7 天到期失效（过期不自动续期）", now=now,
               export_no=row["export_no"], requester=row["requester"], trace_id=trace_id)
    return len(rows)


def list_requests(connection: Any, *, state: str | None = None,
                  object_name: str | None = None, requester: str | None = None,
                  from_at: datetime | None = None, to_at: datetime | None = None,
                  cursor: str | None = None, limit: int = facts.DEFAULT_PAGE_SIZE,
                  now: datetime | None = None,
                  audit_sink: audit_hook.AuditSink | None = None,
                  trace_id: str = "", visible_to: str | None = None
                  ) -> tuple[list[dict], bool, str | None]:
    if now is not None:
        expire_due(connection, now=now, audit_sink=audit_sink, trace_id=trace_id)
    return store.list_exports(connection, state=state, object_name=object_name,
                              requester=requester, from_at=from_at, to_at=to_at,
                              cursor=cursor, limit=limit, visible_to=visible_to)


def mint_link(row: Mapping[str, Any], *, now: datetime, config: Config,
              secret: bytes, base_url: str) -> dict:
    ttl_s = policy.link_ttl_seconds(_config(config, "data.export_link_ttl_min"))
    token, expires_at, jti = policy.mint_download_token(
        str(row["export_id"]), now=now, ttl_s=ttl_s, secret=secret)
    url = (f"{base_url.rstrip('/')}/files/{row['export_no']}?token={token}")
    return {"available": True, "url": url, "expires_at": clock.iso(expires_at),
            "ttl_s": ttl_s, "one_time": True, "watermark": row.get("watermark"),
            "jti": jti}


def get_request(connection: Any, export_id: str, *, now: datetime, config: Config,
                secret: bytes, base_url: str,
                actor: str = "m14-system",
                audit_sink: audit_hook.AuditSink | None = None,
                trace_id: str = "", is_super: bool = False) -> tuple[dict, dict]:
    """返回 (row, payload)；done 且未消费时附带一次性签名链接（≤15 分钟）。

    spec：申请人 / 复核人之外不可见（越权统一 404 + 40401）；super 角色（scopes=*）例外。
    """
    expire_due(connection, now=now, audit_sink=audit_sink, trace_id=trace_id)
    row = store.get_export(connection, export_id)
    if row is None:
        raise errors.NotFound("导出申请不存在")
    if not is_super and actor not in (str(row["requester"]), str(row.get("approver") or "")):
        raise errors.NotFound("导出申请不存在")
    payload = models.export_payload(row)
    file_expired = (row.get("expires_at") is not None
                    and clock.as_utc(row["expires_at"]) <= clock.as_utc(now))
    if row["state"] != "done":
        payload["download"] = {"available": False, "reason": f"state_{row['state']}"}
    elif file_expired:
        payload["download"] = {"available": False, "reason": "file_expired"}
    elif row.get("link_consumed_at") is not None:
        payload["download"] = {"available": False, "reason": "already_downloaded"}
    else:
        link = mint_link(row, now=now, config=config, secret=secret, base_url=base_url)
        store.update_export(connection, export_id, link_jti=link["jti"])
        payload["download"] = {key: value for key, value in link.items() if key != "jti"}
        _audit(audit_sink, action=facts.AUDIT_EXPORT_LINK_MINTED, object_id=export_id,
               actor=actor, reason="签发一次性下载链接（≤15 分钟）", now=now,
               jti=link["jti"], ttl_s=link["ttl_s"], trace_id=trace_id)
    return row, payload


def consume_link(connection: Any, token: str, *, secret: bytes, now: datetime,
                 actor: str = "m14-system",
                 audit_sink: audit_hook.AuditSink | None = None,
                 trace_id: str = "") -> dict:
    """下载网关消费签名链接：一次性（第二次 40901）、文件 7 天到期后不可用。"""
    claims = policy.verify_download_token(token, secret=secret, now=now)
    row = store.get_export(connection, claims["export_id"])
    if row is None:
        raise errors.NotFound("导出申请不存在")
    if row["state"] != "done":
        raise errors.Conflict("文件不可用：导出未完成或已失效", reason="link_invalid")
    if row.get("link_consumed_at") is not None:
        raise errors.Conflict("下载链接已被使用（一次性）", reason="link_already_consumed")
    if row.get("link_jti") and row["link_jti"] != claims["jti"]:
        raise errors.Conflict("下载链接已失效（已签发新链接）", reason="link_superseded")
    expires_at = row.get("expires_at")
    if expires_at is not None and clock.as_utc(expires_at) <= clock.as_utc(now):
        raise errors.Conflict("文件已过 7 天失效期", reason="file_expired")
    store.update_export(connection, claims["export_id"], link_consumed_at=now)
    _audit(audit_sink, action=facts.AUDIT_EXPORT_LINK_CONSUMED,
           object_id=claims["export_id"], actor=actor, reason="一次性链接已消费", now=now,
           jti=claims["jti"], trace_id=trace_id)
    return {"export_id": claims["export_id"], "export_no": row["export_no"],
            "rows": int(row["row_count"]), "watermark": row.get("watermark"),
            "consumed_at": clock.iso(now), "one_time": True}
