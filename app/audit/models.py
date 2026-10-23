# SPDX-License-Identifier: Apache-2.0
"""审计条目的形态层：UUIDv7、请求体解析、审批链结构校验、幂等指纹。

这里只做**纯函数**（无 DB、无网络、无时钟副作用）：把 ``AuditAppendRequest`` 变成一份
"待上链的草稿"，并做一切形态 / 枚举 / 长度 / 审批链结构校验。策略判定在
:mod:`app.audit.policy`，哈希与链校验在 :mod:`app.audit.canonical` / :mod:`app.audit.chain`。

形状约定（spec-1.2.2 ``AuditAppendRequest`` / ``AuditEntry``）：

* 必填 5 个：``actor`` / ``actor_type`` / ``role`` / ``action`` / ``target``；
* ``before`` / ``after`` 是 JSON **对象**（只放运维事实，不放正文 / 凭据）；
* ``evidence`` 是**字符串**（证据引用路径，不是正文；spec AuditEntry.evidence: string）；
* ``approval_chain`` 是对象数组，每项至少 ``actor`` + ``decision``（propose/approve/execute/reject）；
* ``status`` 缺省 ``recorded``；``alg`` 只接受 ``hmac-sha256``（拒绝算法降级）。
"""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import date, datetime, timezone
from typing import Any, Mapping

from . import clock, errors, facts


# ───────────────────────────────────────────────────────────────────── UUIDv7
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
def require_text(value: Any, *, field: str, max_len: int, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise errors.InvalidArgument(f"缺 {field}（必填）", field=field)
        return None
    if not isinstance(value, str):
        raise errors.InvalidArgument(f"{field} 必须是字符串", field=field)
    text = value.strip()
    if not text or len(text) > max_len:
        raise errors.InvalidArgument(f"{field} 长度必须是 1..{max_len}", field=field)
    return text


def require_enum(value: Any, *, field: str, allowed: tuple[str, ...],
                 default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str):
        raise errors.InvalidArgument(f"{field} 必须是字符串", field=field, allowed=list(allowed))
    text = value.strip()
    if text not in allowed:
        raise errors.InvalidArgument(f"{field} 取值非法：{text!r}", field=field,
                                     allowed=list(allowed))
    return text


def require_object(value: Any, *, field: str) -> dict[str, Any] | None:
    """JSON 对象或 null（数组 / 标量一律拒绝：before/after 只放结构化运维事实）。"""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise errors.InvalidArgument(f"{field} 必须是 JSON 对象", field=field)
    return dict(value)


def require_approval_chain(value: Any) -> list[dict[str, Any]]:
    """审批链结构校验（INV-M16-02）：数组、每人一项、decision 枚举、actor 非空。"""
    if value is None:
        return []
    if not isinstance(value, list):
        raise errors.InvalidArgument("approval_chain 必须是数组", field="approval_chain")
    if len(value) > facts.MAX_CHAIN_ITEMS:
        raise errors.InvalidArgument(
            f"approval_chain 最多 {facts.MAX_CHAIN_ITEMS} 项", field="approval_chain")
    chain: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise errors.InvalidArgument(f"approval_chain[{index}] 必须是对象",
                                          field="approval_chain")
        actor = require_text(item.get("actor"), field=f"approval_chain[{index}].actor",
                             max_len=facts.MAX_ACTOR_LEN)
        decision = require_enum(item.get("decision"), field=f"approval_chain[{index}].decision",
                                allowed=facts.DECISIONS)
        entry: dict[str, Any] = {"actor": actor, "decision": decision}
        role = item.get("role")
        if role is not None:
            entry["role"] = require_text(role, field=f"approval_chain[{index}].role",
                                         max_len=facts.MAX_ROLE_LEN)
        at = item.get("at")
        if at is not None:
            entry["at"] = require_text(at, field=f"approval_chain[{index}].at",
                                       max_len=facts.MAX_EVIDENCE_LEN)
        chain.append(entry)
    return chain


def parse_period(value: Any, *, default_day: str) -> str:
    """``period`` = UTC 日 ``YYYY-MM-DD``（缺省当日）；不接受时间戳与时区偏移。"""
    if value is None or (isinstance(value, str) and not value.strip()):
        return default_day
    if not isinstance(value, str):
        raise errors.InvalidArgument("period 必须是 YYYY-MM-DD（UTC 日）", field="period")
    text = value.strip()
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise errors.InvalidArgument("period 必须是 YYYY-MM-DD（UTC 日）", field="period") from exc
    if parsed.isoformat() != text:
        raise errors.InvalidArgument("period 必须是 YYYY-MM-DD（UTC 日）", field="period")
    return text


# ───────────────────────────────────────────────────────────────────── 请求 → 草稿
def draft_from_request(body: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """把 ``AuditAppendRequest`` 解析成待上链草稿（链字段由 store 赋值）。"""
    if not isinstance(body, Mapping):
        raise errors.InvalidArgument("请求体必须是 JSON 对象", reason="malformed_json")

    draft: dict[str, Any] = {
        "actor": require_text(body.get("actor"), field="actor", max_len=facts.MAX_ACTOR_LEN),
        "actor_type": require_enum(body.get("actor_type"), field="actor_type",
                                   allowed=facts.ACTOR_TYPES),
        "role": require_text(body.get("role"), field="role", max_len=facts.MAX_ROLE_LEN),
        "action": require_text(body.get("action"), field="action", max_len=facts.MAX_ACTION_LEN),
        "target": require_text(body.get("target"), field="target", max_len=facts.MAX_TARGET_LEN),
        "before": require_object(body.get("before"), field="before"),
        "after": require_object(body.get("after"), field="after"),
        "reason_code": require_text(body.get("reason_code"), field="reason_code",
                                    max_len=facts.MAX_REASON_LEN, required=False),
        "ticket": require_text(body.get("ticket"), field="ticket",
                               max_len=facts.MAX_TICKET_LEN, required=False),
        "evidence": require_text(body.get("evidence"), field="evidence",
                                 max_len=facts.MAX_EVIDENCE_LEN, required=False),
        "approval_chain": require_approval_chain(body.get("approval_chain")),
        "status": require_enum(body.get("status"), field="status", allowed=facts.STATUSES,
                               default=facts.DEFAULT_STATUS),
        "alg": require_enum(body.get("alg"), field="alg", allowed=(facts.ALG,),
                            default=facts.ALG),
    }
    return draft


# ───────────────────────────────────────────────────────────────────── 幂等
def request_core(entry: Mapping[str, Any]) -> dict[str, Any]:
    """幂等比对用的"业务内容"（不含链字段 / 时间 / 幂等键本身）。

    同一个幂等键重复提交时，业务内容必须一致；不一致一律 409（不许拿旧键换新事实）。
    """
    return {
        "actor": entry.get("actor"),
        "actor_type": entry.get("actor_type"),
        "role": entry.get("role"),
        "action": entry.get("action"),
        "target": entry.get("target"),
        "before": entry.get("before"),
        "after": entry.get("after"),
        "reason_code": entry.get("reason_code"),
        "ticket": entry.get("ticket"),
        "evidence": entry.get("evidence"),
        "approval_chain": entry.get("approval_chain") or [],
        "status": entry.get("status"),
    }


def fingerprint_request(body: Any, *, now: datetime | None = None) -> str:
    """请求体指纹（缺省幂等键时用，00-conventions §5：300s 窗口去重）。

    窗口按 UTC 秒整除分桶：同一桶内重复提交同一请求体 → 命中幂等；跨桶视为新请求。
    """
    from . import canonical                          # 局部导入：避免模块级循环

    digest = hashlib.sha256(canonical.canonical_json(body).encode("utf-8")).hexdigest()
    moment = clock.as_utc(now or clock.utcnow())
    bucket = int(moment.timestamp()) // facts.FINGERPRINT_WINDOW_S
    return f"fp:{digest[:40]}:{bucket}"


def utc_from_epoch(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


__all__ = [
    "uuid7",
    "require_text",
    "require_enum",
    "require_object",
    "require_approval_chain",
    "parse_period",
    "draft_from_request",
    "request_core",
    "fingerprint_request",
    "utc_from_epoch",
]
