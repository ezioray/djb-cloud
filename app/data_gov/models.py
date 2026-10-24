# SPDX-License-Identifier: AGPL-3.0-or-later
"""M14 请求解析 / 行映射 / 游标（S3：拒绝未知字段、枚举与长度前置校验）。

列表信封沿用本仓内部 API 习惯：``{"data": [...], "page": {cursor, has_more, next_cursor}}``
（spec ``Page`` 的 ``has_more`` 必填；游标不透明，``offset`` 翻页禁止）。
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping, Sequence

from . import clock, errors, facts

__all__ = [
    "ExportDraft", "RetentionDraft", "require_text", "optional_text", "require_bool",
    "require_int", "require_enum", "require_uuid", "require_idempotency_key",
    "parse_export_create", "parse_retention_create", "encode_cursor", "decode_cursor",
    "page_payload", "export_payload", "retention_payload", "saved_view_payload",
]

ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
ACTION_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
EXPORT_NO_RE = re.compile(r"^[A-Z0-9-]{1,32}$")


# ───────────────────────────────────────────────────────────── 基础校验
def require_text(value: Any, *, field: str, min_len: int = 1,
                 max_len: int = facts.MAX_REASON_LEN) -> str:
    if not isinstance(value, str) or not value.strip():
        raise errors.BadRequest(f"{field} 必填且必须是非空字符串", field=field)
    text = value.strip()
    if not (min_len <= len(text) <= max_len):
        raise errors.BadRequest(
            f"{field} 长度必须在 {min_len}..{max_len} 之间", field=field)
    return text


def optional_text(value: Any, *, field: str, max_len: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise errors.BadRequest(f"{field} 必须是字符串", field=field)
    text = value.strip()
    if not text:
        return None
    if len(text) > max_len:
        raise errors.BadRequest(f"{field} 长度不得超过 {max_len}", field=field)
    return text


def require_bool(value: Any, *, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise errors.BadRequest(f"{field} 必须是布尔值", field=field)


def require_int(value: Any, *, field: str, minimum: int, maximum: int,
                default: int | None = None) -> int:
    if value is None:
        if default is None:
            raise errors.BadRequest(f"{field} 必填", field=field)
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise errors.BadRequest(f"{field} 必须是整数", field=field)
    if not (minimum <= value <= maximum):
        raise errors.BadRequest(
            f"{field} 必须在 {minimum}..{maximum} 之间", field=field)
    return value


def require_enum(value: Any, *, field: str, allowed: Iterable[str]) -> str:
    options = tuple(allowed)
    if not isinstance(value, str) or value not in options:
        raise errors.BadRequest(f"{field} 必须是 {list(options)} 之一", field=field)
    return value


def require_uuid(value: Any, *, field: str = "id") -> str:
    if not isinstance(value, str) or not ID_RE.match(value.strip()):
        raise errors.NotFound(f"{field} 不存在")          # 统一 404，避免枚举
    return value.strip().lower()


def require_idempotency_key(raw: Any) -> str | None:
    """写接口必带 X-DJB-Idempotency-Key（16..128）；只读接口忽略。"""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    text = str(raw).strip()
    if not (facts.MIN_IDEMPOTENCY_LEN <= len(text) <= facts.MAX_IDEMPOTENCY_LEN):
        raise errors.BadRequest(
            f"X-DJB-Idempotency-Key 长度必须在 {facts.MIN_IDEMPOTENCY_LEN}.."
            f"{facts.MAX_IDEMPOTENCY_LEN}", field="X-DJB-Idempotency-Key")
    return text


def require_action(value: Any, *, field: str, max_len: int = 64) -> str:
    if not isinstance(value, str) or not ACTION_RE.match(value.strip()):
        raise errors.BadRequest(f"{field} 必须是点分动作名（≤{max_len}）", field=field)
    return value.strip()


def _reject_unknown(body: Mapping[str, Any], allowed: Iterable[str]) -> None:
    unknown = sorted(set(body) - set(allowed))
    if unknown:
        raise errors.BadRequest(f"未知字段：{unknown}", fields=unknown)


# ───────────────────────────────────────────────────────────── 导出申请
@dataclass(frozen=True)
class ExportDraft:
    scope: dict[str, Any]
    format: list[str]
    reason: str
    estimated_rows: int
    contains_personal_data: bool


def _parse_scope(raw: Any, *, now: datetime) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise errors.BadRequest("scope 必须是对象", field="scope")
    _reject_unknown(raw, facts.EXPORT_SCOPE_FIELDS)
    scope: dict[str, Any] = {
        "object": require_enum(raw.get("object"), field="scope.object",
                               allowed=facts.EXPORT_OBJECTS),
    }
    from_at = raw.get("from")
    to_at = raw.get("to")
    if from_at is not None:
        scope["from"] = clock.iso(clock.parse_datetime(from_at, field="scope.from"))
    if to_at is not None:
        scope["to"] = clock.iso(clock.parse_datetime(to_at, field="scope.to"))
    if "from" in scope and "to" in scope:
        start = clock.parse_datetime(scope["from"], field="scope.from")
        end = clock.parse_datetime(scope["to"], field="scope.to")
        if start >= end:
            raise errors.BadRequest("scope.from 必须早于 scope.to", field="scope")
    if "to" in scope:
        end = clock.parse_datetime(scope["to"], field="scope.to")
        if end > now:
            raise errors.BadRequest("scope.to 不得晚于当前时间", field="scope.to")
    tenant = raw.get("tenant_id")
    if tenant is not None:
        scope["tenant_id"] = require_text(tenant, field="scope.tenant_id",
                                          max_len=facts.MAX_ACTOR_LEN)
    return scope


def _parse_format(raw: Any) -> list[str]:
    if raw is None:
        return list(facts.EXPORT_FORMATS)              # 规格默认 JSON + CSV
    items: list[str]
    if isinstance(raw, str):
        items = [item.strip().lower() for item in raw.split("+") if item.strip()]
    elif isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray)):
        items = []
        for item in raw:
            if not isinstance(item, str):
                raise errors.BadRequest("format 数组元素必须是字符串", field="format")
            items.append(item.strip().lower())
    else:
        raise errors.BadRequest("format 必须是字符串或字符串数组", field="format")
    if not items:
        raise errors.BadRequest("format 至少要有 json / csv 之一", field="format")
    for item in items:
        if item == "both":
            items = list(facts.EXPORT_FORMATS)
            break
        if item not in facts.EXPORT_FORMATS:
            raise errors.BadRequest("format 只能是 json / csv / json+csv", field="format")
    deduped: list[str] = []
    for item in items:
        if item not in deduped:
            deduped.append(item)
    return deduped


def parse_export_create(body: Mapping[str, Any], *, now: datetime) -> ExportDraft:
    _reject_unknown(body, {"scope", "format", "reason", "estimated_rows",
                           "contains_personal_data"})
    scope = _parse_scope(body.get("scope"), now=now)
    reason = require_text(body.get("reason"), field="reason", max_len=facts.MAX_REASON_LEN)
    estimated = require_int(body.get("estimated_rows"), field="estimated_rows",
                            minimum=0, maximum=facts.EXPORT_MAX_ROWS_MAX, default=0)
    pii = require_bool(body.get("contains_personal_data"),
                       field="contains_personal_data")
    return ExportDraft(scope=scope, format=_parse_format(body.get("format")),
                       reason=reason, estimated_rows=estimated,
                       contains_personal_data=pii)


# ───────────────────────────────────────────────────────────── 保留任务
@dataclass(frozen=True)
class RetentionDraft:
    object: str
    policy_days: int
    cutoff: datetime
    dry_run: bool
    reason: str | None = None


def parse_retention_create(body: Mapping[str, Any], *, now: datetime) -> RetentionDraft:
    _reject_unknown(body, {"object", "policy_days", "cutoff", "dry_run", "reason"})
    object_name = require_enum(body.get("object"), field="object",
                               allowed=facts.RETENTION_OBJECTS)
    dry_run = require_bool(body.get("dry_run"), field="dry_run")
    raw_cutoff = body.get("cutoff")
    raw_days = body.get("policy_days")
    if raw_cutoff is None and raw_days is None:
        days = facts.RETENTION_POLICY_DAYS[object_name]
        cutoff = clock.start_of_utc_day(now - _days(days))
    elif raw_cutoff is not None and raw_days is not None:
        days = require_int(raw_days, field="policy_days",
                           minimum=facts.RETENTION_POLICY_MIN_DAYS,
                           maximum=facts.RETENTION_POLICY_MAX_DAYS)
        cutoff = clock.start_of_utc_day(clock.parse_datetime(
            raw_cutoff, field="cutoff"))
        age_days = (now - cutoff).days
        if age_days != days:
            raise errors.BadRequest(
                "cutoff 与 policy_days 不一致（cutoff 必须等于 now - policy_days 的 UTC 日界）",
                field="cutoff")
    elif raw_cutoff is not None:
        cutoff = clock.start_of_utc_day(clock.parse_datetime(
            raw_cutoff, field="cutoff"))
        age_days = (now - cutoff).days
        if not (facts.RETENTION_POLICY_MIN_DAYS <= age_days
                <= facts.RETENTION_POLICY_MAX_DAYS):
            raise errors.BadRequest(
                f"cutoff 距今必须在 {facts.RETENTION_POLICY_MIN_DAYS}.."
                f"{facts.RETENTION_POLICY_MAX_DAYS} 天之间", field="cutoff")
        days = age_days
    else:
        days = require_int(raw_days, field="policy_days",
                           minimum=facts.RETENTION_POLICY_MIN_DAYS,
                           maximum=facts.RETENTION_POLICY_MAX_DAYS)
        cutoff = clock.start_of_utc_day(now - _days(days))
    if cutoff > now:
        raise errors.BadRequest("cutoff 不得晚于当前时间", field="cutoff")
    reason = optional_text(body.get("reason"), field="reason",
                           max_len=facts.MAX_REASON_LEN)
    return RetentionDraft(object=object_name, policy_days=days, cutoff=cutoff,
                          dry_run=dry_run, reason=reason)


def _days(days: int) -> timedelta:
    return timedelta(days=days)


# ───────────────────────────────────────────────────────────── 游标 / 信封
def encode_cursor(created_at: datetime, identifier: str) -> str:
    payload = {"ts": clock.iso_micros(created_at), "id": identifier}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(raw: Any) -> tuple[datetime, str] | None:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    if not isinstance(raw, str):
        raise errors.BadRequest("cursor 不合法", field="cursor")
    text = raw.strip()
    padding = "=" * (-len(text) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(text + padding).decode("utf-8"))
        created_at = clock.parse_datetime(payload["ts"], field="cursor")
        identifier = str(payload["id"])
    except (ValueError, KeyError, TypeError, binascii.Error, UnicodeDecodeError):
        raise errors.BadRequest("cursor 不合法", field="cursor") from None
    if not identifier:
        raise errors.BadRequest("cursor 不合法", field="cursor")
    return created_at, identifier


def page_payload(*, cursor: str | None, has_more: bool,
                 next_cursor: str | None) -> dict[str, Any]:
    return {"cursor": cursor or None, "has_more": bool(has_more),
            "next_cursor": next_cursor if has_more else None}


# ───────────────────────────────────────────────────────────── 行 → 契约 payload
def export_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "export_id": str(row["export_id"]),
        "export_no": row["export_no"],
        "requester": row["requester"],
        "scope": row["scope"],
        "format": row["format"],
        "reason": row["reason"],
        "state": row["state"],
        "rows": int(row["row_count"]),
        "estimated_rows": int(row["estimated_rows"]),
        "contains_personal_data": bool(row["contains_personal_data"]),
        "approval_required": bool(row["approval_required"]),
        "approver": row.get("approver"),
        "created_at": clock.iso(row.get("created_at")),
        "approved_at": clock.iso(row.get("approved_at")),
        "started_at": clock.iso(row.get("started_at")),
        "finished_at": clock.iso(row.get("finished_at")),
        "expires_at": clock.iso(row.get("expires_at")),
        "watermark": row.get("watermark"),
        "failure_reason": row.get("failure_reason"),
        "cancelled_at": clock.iso(row.get("cancelled_at")),
        "cancelled_by": row.get("cancelled_by"),
    }


def retention_payload(row: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    finished = row.get("finished_at") or row.get("created_at")
    due = row.get("sla_due_at")
    overdue = bool(due is not None and finished is not None and finished > due)
    return {
        "job_id": str(row["job_id"]),
        "job_no": row["job_no"],
        "object": row["object"],
        "policy_days": int(row["policy_days"]),
        "cutoff": clock.iso(row["cutoff"]),
        "state": row["state"],
        "dry_run": bool(row["dry_run"]),
        "deleted_count": int(row["deleted_count"]),
        "retained_count": int(row["retained_count"]),
        "report": row.get("report"),
        "report_ref": row["report_ref"],
        "failure_reason": row.get("failure_reason"),
        "replay_count": int(row.get("replay_count") or 0),
        "requested_by": row["requested_by"],
        "created_at": clock.iso(row.get("created_at")),
        "started_at": clock.iso(row.get("started_at")),
        "finished_at": clock.iso(row.get("finished_at")),
        "sla": {
            "due_at": clock.iso(due),
            "overdue": overdue,
            "window_days": facts.RETENTION_SLA_DAYS,
            "sampling_days": facts.RETENTION_SAMPLE_DAYS,
        },
    }


def saved_view_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "view_id": str(row["view_id"]),
        "owner_id": row["owner_id"],
        "domain": row["domain"],
        "name": row["name"],
        "filters": row["filters"],
        "shared": bool(row["shared"]),
        "state": row["state"],
        "created_at": clock.iso(row.get("created_at")),
    }
