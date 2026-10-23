# SPDX-License-Identifier: Apache-2.0
"""M09 领域模型：请求解析、行 → 契约 payload、游标、幂等指纹（纯函数，无 DB）。

三条纪律：
1. **入口校验自己写**，不依赖框架 422（错误信封统一 400/40001，见 ``errors``）；
2. 金额只接受整数最小单位（``bool`` 不是整数，显式排除）；浮点一律拒绝（INV-08）；
3. payload 只输出 spec 字段 + 明确登记的追加字段（``additionalProperties: true`` 允许只加不改）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from . import clock, facts
from .errors import BadRequest

__all__ = [
    "uuid7", "RunSpec", "ExceptionDraft", "SignOffRequest", "ResolveRequest", "AttestationDraft",
    "parse_run_spec", "parse_sign_off", "parse_resolve", "parse_attestation",
    "run_payload", "exception_payload", "attestation_payload", "page_payload",
    "encode_cursor", "decode_cursor", "fingerprint", "require_text", "require_int",
    "require_enum", "require_object", "require_idempotency_key", "require_hex", "as_int",
]


# ───────────────────────────────────────────────────────────────────── 标识
def uuid7(moment: datetime | None = None) -> uuid.UUID:
    """UUIDv7（时间有序，00-conventions §2）：48 bit 毫秒 + 版本/变体 + 80 bit 随机。"""
    epoch_ms = int(clock.as_utc(moment or clock.utcnow()).timestamp() * 1_000) & ((1 << 48) - 1)
    random_bits = int.from_bytes(os.urandom(10), "big")
    value = (epoch_ms << 80) | (0x7 << 76)
    value |= ((random_bits >> 68) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= random_bits & ((1 << 62) - 1)
    return uuid.UUID(int=value)


# ───────────────────────────────────────────────────────────────────── 基础校验
def require_object(body: Any) -> dict[str, Any]:
    if not isinstance(body, Mapping):
        raise BadRequest("请求体必须是 JSON 对象")
    return dict(body)


def require_text(value: Any, *, field: str, max_len: int, min_len: int = 1,
                 required: bool = True) -> str | None:
    if value is None:
        if required:
            raise BadRequest(f"缺 {field}（必填）", field=field)
        return None
    if not isinstance(value, str):
        raise BadRequest(f"{field} 必须是字符串", field=field)
    text = value.strip()
    if not text:
        if required:
            raise BadRequest(f"{field} 不能为空", field=field)
        return None
    if len(text) > max_len:
        raise BadRequest(f"{field} 超长（≤{max_len}）", field=field)
    if len(text) < min_len:
        raise BadRequest(f"{field} 过短（≥{min_len}）", field=field)
    return text


def as_int(value: Any, *, field: str) -> int:
    """严格整数（拒绝 bool / float / 带小数的字符串）。"""
    if isinstance(value, bool):
        raise BadRequest(f"{field} 必须是整数最小单位", field=field)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise BadRequest(f"{field} 不接受浮点（金额一律整数最小单位）", field=field)
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]+", value.strip()):
        return int(value.strip())
    raise BadRequest(f"{field} 必须是整数最小单位", field=field)


def require_int(value: Any, *, field: str, minimum: int | None = None,
                maximum: int | None = None, required: bool = True) -> int | None:
    if value is None:
        if required:
            raise BadRequest(f"缺 {field}（必填）", field=field)
        return None
    number = as_int(value, field=field)
    if minimum is not None and number < minimum:
        raise BadRequest(f"{field} 不得小于 {minimum}", field=field)
    if maximum is not None and number > maximum:
        raise BadRequest(f"{field} 不得大于 {maximum}", field=field)
    return number


def require_enum(value: Any, *, field: str, allowed: tuple[str, ...]) -> str:
    text = require_text(value, field=field, max_len=64)
    assert text is not None
    if text not in allowed:
        raise BadRequest(f"{field} 必须是 {list(allowed)} 之一", field=field)
    return text


def require_hex(value: Any, *, field: str, pattern: str) -> str:
    text = require_text(value, field=field, max_len=128)
    assert text is not None
    if not re.fullmatch(pattern, text):
        raise BadRequest(f"{field} 形态非法", field=field)
    return text


def require_idempotency_key(value: Any) -> str | None:
    """``X-DJB-Idempotency-Key``：16..128 字符；缺省返回 None（由调用方按指纹去重）。"""
    if value is None:
        return None
    if not isinstance(value, str):
        raise BadRequest("幂等键必须是字符串", field="Idempotency-Key")
    text = value.strip()
    if not text:
        return None
    if not (facts.MIN_IDEMPOTENCY_LEN <= len(text) <= facts.MAX_IDEMPOTENCY_LEN):
        raise BadRequest(
            f"幂等键长度必须是 {facts.MIN_IDEMPOTENCY_LEN}..{facts.MAX_IDEMPOTENCY_LEN}",
            field="Idempotency-Key")
    return text


def fingerprint(body: Mapping[str, Any], *, now: datetime | None = None,
                bucket_seconds: int = 300) -> str:
    """请求体指纹（缺省幂等键时按 300s 窗口去重：00-conventions §5）。"""
    moment = clock.as_utc(now or clock.utcnow())
    bucket = int(moment.timestamp()) // bucket_seconds
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                           default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"fp:{bucket}:{digest[:48]}"


# ───────────────────────────────────────────────────────────────────── 对账批次
@dataclass(frozen=True)
class RunSpec:
    """一次对账的输入（M09 §3.1 reconciliation_run）。"""

    scope: str
    period_start: datetime
    period_end: datetime
    cutoff_at: datetime
    subject_ref: str | None = None
    block_height: int | None = None
    trigger_event_id: str | None = None
    tenant_id: str | None = None
    created_by: str | None = None
    grace_seconds: int = facts.DEFAULT_GRACE_SECONDS
    rule_version: str = facts.RULE_VERSION
    policy_version: str = facts.POLICY_VERSION

    def key(self) -> tuple[str, str, datetime, datetime, datetime]:
        """INV-04 唯一键（subject_ref 归一成空串，NULL 语义与唯一索引保持一致）。"""
        return (self.scope, self.subject_ref or "", self.period_start, self.period_end,
                self.cutoff_at)


def parse_run_spec(body: Mapping[str, Any], *, now: datetime | None = None) -> RunSpec:
    """解析触发对账的请求（CLI / 内部调用 / 测试共用）。"""
    payload = require_object(body)
    scope = require_enum(payload.get("scope"), field="scope", allowed=facts.SCOPES)
    period_start = clock.parse_datetime(payload.get("period_start"), field="period_start")
    period_end = clock.parse_datetime(payload.get("period_end"), field="period_end")
    cutoff_at = (clock.parse_datetime(payload.get("cutoff_at"), field="cutoff_at")
                 if payload.get("cutoff_at") is not None else (now or clock.utcnow()))
    if period_end <= period_start:
        raise BadRequest("period_end 必须晚于 period_start", field="period_end")
    if cutoff_at < period_start:
        raise BadRequest("cutoff_at 不得早于 period_start", field="cutoff_at")
    grace = require_int(payload.get("grace_seconds"), field="grace_seconds", minimum=0,
                        maximum=facts.MAX_GRACE_SECONDS, required=False)
    return RunSpec(
        scope=scope,
        period_start=period_start,
        period_end=period_end,
        cutoff_at=cutoff_at,
        subject_ref=require_text(payload.get("subject_ref"), field="subject_ref",
                                 max_len=128, required=False),
        block_height=require_int(payload.get("block_height"), field="block_height",
                                 minimum=0, required=False),
        trigger_event_id=require_text(payload.get("trigger_event_id"),
                                     field="trigger_event_id", max_len=128, required=False),
        tenant_id=require_text(payload.get("tenant_id"), field="tenant_id", max_len=128,
                               required=False),
        created_by=require_text(payload.get("created_by"), field="created_by", max_len=128,
                                required=False),
        grace_seconds=(facts.DEFAULT_GRACE_SECONDS if grace is None else grace),
    )


# ───────────────────────────────────────────────────────────────────── 差异
@dataclass(frozen=True)
class ExceptionDraft:
    """一条待落库的差异（引擎产出；``sla_due`` 由分级模块算）。"""

    kind: str
    severity: str
    ref_type: str | None
    ref_id: str | None
    diff_minor: int
    sla_due: datetime
    scope: str
    owner: str | None = None
    root_cause: str | None = None
    evidence_ref: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


# ───────────────────────────────────────────────────────────────────── 签核 / 处置
@dataclass(frozen=True)
class SignOffRequest:
    reviewer_note: str | None
    attestation_id: str | None


def parse_sign_off(body: Mapping[str, Any] | None) -> SignOffRequest:
    payload = require_object(body or {})
    return SignOffRequest(
        reviewer_note=require_text(payload.get("reviewer_note"), field="reviewer_note",
                                  max_len=512, required=False),
        attestation_id=require_text(payload.get("attestation_id"), field="attestation_id",
                                    max_len=64, required=False),
    )


@dataclass(frozen=True)
class ResolveRequest:
    resolution_code: str
    root_cause: str | None
    resolution_journal_id: str | None
    evidence_ref: str | None


def parse_resolve(body: Mapping[str, Any] | None) -> ResolveRequest:
    payload = require_object(body or {})
    code = require_enum(payload.get("resolution_code"), field="resolution_code",
                        allowed=facts.RESOLUTION_CODES)
    return ResolveRequest(
        resolution_code=code,
        root_cause=require_text(payload.get("root_cause"), field="root_cause", max_len=512,
                               required=False),
        resolution_journal_id=require_text(payload.get("resolution_journal_id"),
                                          field="resolution_journal_id", max_len=64,
                                          required=False),
        evidence_ref=require_text(payload.get("evidence_ref"), field="evidence_ref",
                                 max_len=256, required=False),
    )


# ───────────────────────────────────────────────────────────────────── 复核凭证
@dataclass(frozen=True)
class AttestationDraft:
    period_start: datetime
    period_end: datetime
    ledger_root: str
    batch_hash: str
    payable_total_minor: int
    signature_ref: str
    chain_snapshot_ref: str | None
    bank_snapshot_ref: str | None
    maker_id: str | None
    tenant_id: str | None
    idempotency_key: str | None


def parse_attestation(body: Mapping[str, Any] | None, *,
                      idempotency_key: str | None = None) -> AttestationDraft:
    payload = require_object(body or {})
    period_start = clock.parse_datetime(payload.get("period_start"), field="period_start")
    period_end = clock.parse_datetime(payload.get("period_end"), field="period_end")
    if period_end <= period_start:
        raise BadRequest("period_end 必须晚于 period_start", field="period_end")
    return AttestationDraft(
        period_start=period_start,
        period_end=period_end,
        ledger_root=require_hex(payload.get("ledger_root"), field="ledger_root",
                                pattern=facts.LEDGER_ROOT_PATTERN),
        batch_hash=require_hex(payload.get("batch_hash"), field="batch_hash",
                              pattern=facts.BATCH_HASH_PATTERN),
        payable_total_minor=require_int(payload.get("payable_total_minor"),
                                        field="payable_total_minor", minimum=0),
        signature_ref=require_text(payload.get("signature_ref"), field="signature_ref",
                                   max_len=256),
        chain_snapshot_ref=require_text(payload.get("chain_snapshot_ref"),
                                        field="chain_snapshot_ref", max_len=256,
                                        required=False),
        bank_snapshot_ref=require_text(payload.get("bank_snapshot_ref"),
                                       field="bank_snapshot_ref", max_len=256, required=False),
        maker_id=require_text(payload.get("maker_id"), field="maker_id", max_len=128,
                              required=False),
        tenant_id=require_text(payload.get("tenant_id"), field="tenant_id", max_len=128,
                               required=False),
        idempotency_key=idempotency_key,
    )


# ───────────────────────────────────────────────────────────────────── 行 → payload
def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return clock.iso_micros(value)
    return str(value)


def run_payload(row: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
    """ReconRun（spec）/ 追加字段只加不改。"""
    payload = {
        "run_id": str(row["run_id"]),
        "scope": row["scope"],
        "subject_ref": row.get("subject_ref"),
        "period_start": _iso(row["period_start"]),
        "period_end": _iso(row["period_end"]),
        "cutoff_at": _iso(row["cutoff_at"]),
        "block_height": row.get("block_height"),
        "book_minor": int(row.get("book_minor") or 0),
        "external_minor": int(row.get("external_minor") or 0),
        "diff_minor": int(row.get("diff_minor") or 0),
        "matched_count": int(row.get("matched_count") or 0),
        "unmatched_count": int(row.get("unmatched_count") or 0),
        "status": row["status"],
        "rule_version": row.get("rule_version") or facts.RULE_VERSION,
        "policy_version": row.get("policy_version"),
        "report_ref": row.get("report_ref"),
        "signed_off_at": _iso(row.get("signed_off_at")),
        "created_at": _iso(row.get("created_at")),
        # 追加字段（spec additionalProperties: true）
        "metrics": row.get("metrics") or {},
        "tenant_id": row.get("tenant_id"),
        "created_by": row.get("created_by"),
        "signed_off_by": row.get("signed_off_by"),
        "reviewer_note": row.get("reviewer_note"),
    }
    payload.update(extra)
    return payload


def exception_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "exception_id": str(row["exception_id"]),
        "run_id": str(row["run_id"]),
        "scope": row["scope"],
        "kind": row["kind"],
        "severity": row["severity"],
        "ref_type": row.get("ref_type"),
        "ref_id": row.get("ref_id"),
        "diff_minor": int(row.get("diff_minor") or 0),
        "owner": row.get("owner"),
        "sla_due": _iso(row["sla_due"]),
        "status": row["status"],
        "resolution_code": row.get("resolution_code"),
        "resolution_journal_id": row.get("resolution_journal_id"),
        "root_cause": row.get("root_cause"),
        "evidence_ref": row.get("evidence_ref"),
        "created_at": _iso(row.get("created_at")),
        "closed_at": _iso(row.get("closed_at")),
        # 追加字段
        "resolved_by": row.get("resolved_by"),
    }


def attestation_payload(row: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
    payload = {
        "attestation_id": str(row["attestation_id"]),
        "period_start": _iso(row["period_start"]),
        "period_end": _iso(row["period_end"]),
        "ledger_root": row["ledger_root"],
        "chain_snapshot_ref": row.get("chain_snapshot_ref"),
        "bank_snapshot_ref": row.get("bank_snapshot_ref"),
        "payable_total_minor": int(row.get("payable_total_minor") or 0),
        "batch_hash": row["batch_hash"],
        "reviewer_id": row.get("reviewer_id"),
        "reviewer_pubkey_ref": row.get("reviewer_pubkey_ref"),
        "signature_ref": row["signature_ref"],
        "hsm_verified_at": _iso(row.get("hsm_verified_at")),
        "status": row["status"],
        "created_at": _iso(row.get("created_at")),
        # 追加字段
        "maker_id": row.get("maker_id"),
    }
    payload.update(extra)
    return payload


def page_payload(rows: list[Mapping[str, Any]], *, cursor: str | None, has_more: bool,
                 next_cursor: str | None) -> dict[str, Any]:
    """spec ``Page``：``{cursor, has_more, next_cursor}``（``cursor`` 首页为空串）。"""
    return {"cursor": cursor or "", "has_more": bool(has_more),
            "next_cursor": None if not has_more else next_cursor}


# ───────────────────────────────────────────────────────────────────── 游标
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def encode_cursor(moment: datetime, identity: str) -> str:
    """游标 = base64url(``<UTC iso>|<id>``)；服务端生成，不加密、不可猜。"""
    return _b64encode(f"{clock.iso_micros(moment)}|{identity}".encode("utf-8"))


def decode_cursor(cursor: str | None) -> tuple[datetime, str] | None:
    """解析游标；非法 / 超长 / 结构不对 → 400/40001（不泄露内部字段名）。"""
    if cursor is None or cursor == "":
        return None
    if not isinstance(cursor, str) or len(cursor) > 512:
        raise BadRequest("cursor 非法", field="cursor")
    try:
        raw = _b64decode(cursor).decode("utf-8")
    except Exception as exc:                        # noqa: BLE001 - base64 各种错法都归 400
        raise BadRequest("cursor 非法", field="cursor") from exc
    head, _, tail = raw.partition("|")
    if not tail:
        raise BadRequest("cursor 结构非法", field="cursor")
    moment = clock.parse_datetime(head, field="cursor")
    return moment, tail

