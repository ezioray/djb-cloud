# SPDX-License-Identifier: Apache-2.0
"""M11 请求解析 / 行映射 / 对客序列化。

红线（INV-01 / INV-02 / INV-05）：

* 对客 payload 只从白名单键构造（``facts.*_PUBLIC_FIELDS``）——行里即便多出列，
  也不会被带进响应；
* 请求体校验自己做（不依赖框架 422）：不合法一律 400/40001；
* 证据引用只做「引用」校验（形态 + 数量），不存正文；
* 主体标识只接受不透明哈希 / 簇 ID，拒绝邮箱 / IPv4 / 手机号明文（INV-05）。
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from . import clock, facts
from .errors import BadRequest, EvidenceMissing

__all__ = [
    "RuleDraft", "LimitDraft", "DecisionDraft", "AppealDraft", "AppealDecisionDraft",
    "CaseDraft", "parse_rule", "parse_limit", "parse_decision", "parse_appeal",
    "parse_appeal_decision", "require_idempotency_key", "require_subject_hash",
    "rule_payload", "limit_payload", "case_payload", "decision_payload", "appeal_payload",
    "page_payload", "encode_cursor", "decode_cursor",
]

_PII_EMAIL = re.compile(r"@")
_PII_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PII_PHONE = re.compile(r"^1[3-9]\d{9}$")
_REF_FORBIDDEN = re.compile(r"[\s@]")


# ───────────────────────────────────────────────────────────── 基础校验
def _text(value: Any, *, field_name: str, min_len: int = 1, max_len: int = 128,
          required: bool = True) -> str | None:
    if value is None:
        if required:
            raise BadRequest(f"{field_name} 必填", field=field_name)
        return None
    if not isinstance(value, str):
        raise BadRequest(f"{field_name} 必须是字符串", field=field_name)
    text = value.strip()
    if not text:
        if required:
            raise BadRequest(f"{field_name} 不能为空", field=field_name)
        return None
    if not (min_len <= len(text) <= max_len):
        raise BadRequest(f"{field_name} 长度必须是 {min_len}..{max_len}", field=field_name)
    return text


def _int(value: Any, *, field_name: str, minimum: int = 0, maximum: int | None = None,
         required: bool = True, default: int | None = None) -> int | None:
    if value is None:
        if required:
            raise BadRequest(f"{field_name} 必填", field=field_name)
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRequest(f"{field_name} 必须是整数", field=field_name)
    if value < minimum or (maximum is not None and value > maximum):
        raise BadRequest(f"{field_name} 超出允许范围", field=field_name)
    return value


def _bool(value: Any, *, field_name: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise BadRequest(f"{field_name} 必须是布尔值", field=field_name)
    return value


def require_idempotency_key(value: Any) -> str | None:
    """``X-DJB-Idempotency-Key``：16..128 字符；缺省返回 None（不做跨请求猜测重放）。"""
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


def require_subject_hash(value: Any, *, field_name: str = "subject_hash") -> str:
    """主体哈希 / 簇 ID：不透明标识；拒绝明文邮箱 / IPv4 / 手机号（INV-05）。"""
    text = _text(value, field_name=field_name, min_len=3, max_len=128)
    assert text is not None
    if _PII_EMAIL.search(text) or _PII_IPV4.match(text) or _PII_PHONE.match(text):
        raise BadRequest(f"{field_name} 必须是哈希或簇 ID（不接受明文 PII）", field=field_name)
    return text


def _evidence_refs(value: Any) -> list[str]:
    """INV-03：至少 1 条证据引用（事件 id / 收据 id / 交易号 / 举报单）。"""
    if value is None:
        raise EvidenceMissing("证据缺失：必须至少提供 1 条 evidence_refs（INV-03）")
    if not isinstance(value, list):
        raise BadRequest("evidence_refs 必须是数组", field="evidence_refs")
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise EvidenceMissing("证据引用非法：必须是非空字符串（INV-03）",
                                  field="evidence_refs")
        text = item.strip()
        if len(text) > 128 or _REF_FORBIDDEN.search(text):
            raise BadRequest("证据引用形态非法（不得含空白 / 邮箱）", field="evidence_refs")
        refs.append(text)
    if not refs:
        raise EvidenceMissing("证据缺失：evidence_refs 不能为空（INV-03）")
    if len(refs) > facts.MAX_EVIDENCE_REFS:
        raise BadRequest(f"evidence_refs 最多 {facts.MAX_EVIDENCE_REFS} 条",
                         field="evidence_refs")
    return refs


# ───────────────────────────────────────────────────────────── 请求对象
@dataclass(frozen=True)
class RuleDraft:
    rule_key: str
    severity: str
    action_class: str
    enabled: bool = True
    config_ref: str | None = None
    expected_version: int | None = None


@dataclass(frozen=True)
class LimitDraft:
    subject_type: str
    subject_id: str
    limit_type: str
    value: int
    window_s: int
    expires_at: datetime | None = None
    expected_version: int | None = None


@dataclass(frozen=True)
class DecisionDraft:
    action: str
    reason: str
    evidence_refs: list[str]
    expires_at: datetime | None = None
    merge_into: str | None = None


@dataclass(frozen=True)
class AppealDraft:
    case_id: str
    reason: str


@dataclass(frozen=True)
class AppealDecisionDraft:
    outcome: str
    reason: str


@dataclass(frozen=True)
class CaseDraft:
    """开案入参（内部入口：事件消费 / 规则引擎调用，不对客暴露创建端点）。"""

    subject_type: str
    subject_hash: str
    risk_type: str
    severity: str
    evidence_refs: list[str]
    tenant_id: str
    opened_by: str
    opened_at: datetime
    rule_key: str | None = None
    rule_version: int | None = None
    config_ref: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def parse_rule(body: Mapping[str, Any]) -> RuleDraft:
    rule_key = _text(body.get("rule_key"), field_name="rule_key", min_len=1, max_len=128)
    severity = _text(body.get("severity"), field_name="severity")
    if severity not in facts.SEVERITIES:
        raise BadRequest(f"severity 必须是 {list(facts.SEVERITIES)} 之一", field="severity")
    action_class = _text(body.get("action_class"), field_name="action_class")
    if action_class not in facts.ACTION_CLASSES:
        raise BadRequest(f"action_class 必须是 {list(facts.ACTION_CLASSES)} 之一",
                         field="action_class")
    config_ref = _text(body.get("config_ref"), field_name="config_ref", min_len=1,
                       max_len=128, required=False)
    if config_ref is not None and not config_ref.startswith("risk."):
        raise BadRequest("config_ref 必须是 M10 的 risk.* 配置键（阈值不入库，INV-01）",
                         field="config_ref")
    return RuleDraft(
        rule_key=rule_key or "",
        severity=severity or "",
        action_class=action_class or "",
        enabled=_bool(body.get("enabled"), field_name="enabled", default=True),
        config_ref=config_ref,
        expected_version=_int(body.get("expected_version"), field_name="expected_version",
                              minimum=1, required=False),
    )


def parse_limit(body: Mapping[str, Any]) -> LimitDraft:
    subject_type = _text(body.get("subject_type"), field_name="subject_type")
    if subject_type not in facts.SUBJECT_TYPES:
        raise BadRequest(f"subject_type 必须是 {list(facts.SUBJECT_TYPES)} 之一",
                         field="subject_type")
    subject_id = _text(body.get("subject_id"), field_name="subject_id", min_len=1, max_len=128)
    limit_type = _text(body.get("limit_type"), field_name="limit_type", min_len=1, max_len=64)
    value = _int(body.get("value"), field_name="value", minimum=0)
    window_s = _int(body.get("window_s"), field_name="window_s", minimum=0)
    expires_at = (clock.parse_datetime(body["expires_at"], field="expires_at")
                  if body.get("expires_at") is not None else None)
    return LimitDraft(
        subject_type=subject_type or "",
        subject_id=subject_id or "",
        limit_type=limit_type or "",
        value=value if value is not None else 0,
        window_s=window_s if window_s is not None else 0,
        expires_at=expires_at,
        expected_version=_int(body.get("expected_version"), field_name="expected_version",
                              minimum=1, required=False),
    )


def parse_decision(body: Mapping[str, Any]) -> DecisionDraft:
    action = _text(body.get("action"), field_name="action")
    if action not in facts.DECISION_ACTIONS:
        raise BadRequest(f"action 必须是 {list(facts.DECISION_ACTIONS)} 之一", field="action")
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_REASON_LEN)
    evidence_refs = _evidence_refs(body.get("evidence_refs"))
    expires_at = (clock.parse_datetime(body["expires_at"], field="expires_at")
                  if body.get("expires_at") is not None else None)
    merge_into = _text(body.get("merge_into"), field_name="merge_into", min_len=1,
                       max_len=64, required=False)
    return DecisionDraft(action=action or "", reason=reason or "",
                         evidence_refs=evidence_refs, expires_at=expires_at,
                         merge_into=merge_into)


def parse_appeal(body: Mapping[str, Any]) -> AppealDraft:
    case_id = _text(body.get("case_id"), field_name="case_id", min_len=1, max_len=64)
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_REASON_LEN)
    return AppealDraft(case_id=case_id or "", reason=reason or "")


def parse_appeal_decision(body: Mapping[str, Any]) -> AppealDecisionDraft:
    outcome = _text(body.get("outcome"), field_name="outcome")
    if outcome not in facts.APPEAL_OUTCOMES:
        raise BadRequest(f"outcome 必须是 {list(facts.APPEAL_OUTCOMES)} 之一", field="outcome")
    reason = _text(body.get("reason"), field_name="reason", min_len=1,
                   max_len=facts.MAX_REASON_LEN)
    return AppealDecisionDraft(outcome=outcome or "", reason=reason or "")


# ───────────────────────────────────────────────────────────── 行 → 对客 payload
def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return clock.iso(value)
    return str(value)


def _pick(row: Mapping[str, Any], allowed: frozenset[str], *, iso_fields: tuple[str, ...]) -> dict:
    payload: dict[str, Any] = {}
    for key in sorted(allowed):
        if key not in row:
            continue
        value = row[key]
        payload[key] = _iso(value) if key in iso_fields else value
    return payload


def rule_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """RiskRule（spec）：只暴露元数据，**绝无**阈值 / 权重 / 名单。"""
    return _pick(row, facts.RULE_PUBLIC_FIELDS, iso_fields=("created_at",))


def limit_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = _pick(row, facts.LIMIT_PUBLIC_FIELDS, iso_fields=("expires_at",))
    payload["value"] = int(payload.get("value") or 0)
    payload["window_s"] = int(payload.get("window_s") or 0)
    return payload


def case_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """RiskCase（spec）：主体只出哈希；不含证据正文 / 处置理由 / 阈值。"""
    payload = _pick(row, facts.CASE_PUBLIC_FIELDS, iso_fields=("opened_at", "closed_at"))
    payload["case_id"] = str(payload.get("case_id"))
    return payload


def decision_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = _pick(row, facts.DECISION_PUBLIC_FIELDS, iso_fields=("decided_at",))
    if payload.get("proposal_id") is not None:
        payload["proposal_id"] = str(payload["proposal_id"])
    return payload


def appeal_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = _pick(row, facts.APPEAL_PUBLIC_FIELDS, iso_fields=("submitted_at", "sla_due"))
    payload["appeal_id"] = str(payload.get("appeal_id"))
    payload["case_id"] = str(payload.get("case_id"))
    return payload


def page_payload(*, cursor: str | None, has_more: bool, next_cursor: str | None) -> dict[str, Any]:
    """spec ``Page``：``{cursor, has_more, next_cursor}``（首页 cursor 为空串）。"""
    return {"cursor": cursor or "", "has_more": bool(has_more),
            "next_cursor": None if not has_more else next_cursor}


# ───────────────────────────────────────────────────────────── 游标
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def encode_cursor(moment: datetime, identity: str) -> str:
    """游标 = base64url(``<UTC iso>|<id>``)；服务端生成，不可猜。"""
    return _b64encode(f"{clock.iso_micros(moment)}|{identity}".encode("utf-8"))


def decode_cursor(cursor: str | None) -> tuple[datetime, str] | None:
    """解析游标；非法 / 超长 / 结构不对 → 400/40001（不泄露内部字段名）。"""
    if cursor is None or cursor == "":
        return None
    if not isinstance(cursor, str) or len(cursor) > 512:
        raise BadRequest("cursor 非法", field="cursor")
    try:
        raw = _b64decode(cursor).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - base64 各种错法都归 400
        raise BadRequest("cursor 非法", field="cursor") from exc
    head, _, tail = raw.partition("|")
    if not tail:
        raise BadRequest("cursor 结构非法", field="cursor")
    moment = clock.parse_datetime(head, field="cursor")
    return moment, tail
