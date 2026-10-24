# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 冻结段：入参校验、行 → API 载荷、分页游标（无 ORM、无 PII）。

三件事：

1. **入参归一**：等级 / 金额 / 文本 / 复核人列表在 service 与 router 共用一份校验；
2. **载荷白名单**：只输出 §7 已登记字段（id / 节点 / 模型 / 等级 / 比例 / 金额 / 状态 /
   时间 / 复核人 / version），不含账本明细、不含正文、不含阈值；
3. **游标**：base64url(``<UTC iso>|<id>``)，服务端生成、不可猜；非法即 400/40001。
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime
from typing import Any, Iterable, Mapping

from . import clock, facts
from .errors import BadRequest

__all__ = [
    "hold_payload", "event_payload", "encode_cursor", "decode_cursor",
    "normalize_level", "level_rank", "validate_amount", "normalize_text",
    "normalize_actor", "normalize_reviewers", "validate_reason", "validate_evidence_ref",
    "validate_node_id", "validate_model", "parse_hold_id", "page_limit",
]


# ───────────────────────────────────────────────────────── 行 → 载荷
def _uuid_text(value: Any) -> str:
    if isinstance(value, uuid.UUID):
        return str(value)
    return str(value)


def hold_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """冻结记录对外形状（只列白名单字段；时间统一 UTC ISO）。"""
    return {
        "id": _uuid_text(row["id"]),
        "node_id": row["node_id"],
        "upstream_id": row.get("upstream_id"),
        "model": row["model"],
        "level": row["level"],
        "ratio_bp": int(row["ratio_bp"]),
        "base_amount_micro": int(row["base_amount_micro"]),
        "frozen_amount_micro": int(row["frozen_amount_micro"]),
        "state": row["state"],
        "reason": row["reason"],
        "evidence_ref": row["evidence_ref"],
        "created_at": clock.iso(row["created_at"]),
        "expires_at": clock.iso(row.get("expires_at")),
        "released_at": clock.iso(row.get("released_at")),
        "release_reason": row.get("release_reason"),
        "reviewer_a": row.get("reviewer_a"),
        "reviewer_b": row.get("reviewer_b"),
        "version": int(row["version"]),
        "updated_at": clock.iso(row.get("updated_at")),
    }


def event_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_id": _uuid_text(row["event_id"]),
        "hold_id": _uuid_text(row["hold_id"]) if row.get("hold_id") else None,
        "node_id": row["node_id"],
        "model": row["model"],
        "event": row["event"],
        "from_level": row.get("from_level"),
        "to_level": row.get("to_level"),
        "detail": dict(row.get("detail") or {}),
        "actor": row["actor"],
        "created_at": clock.iso(row["created_at"]),
    }


# ───────────────────────────────────────────────────────── 游标
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_cursor(moment: datetime, identity: str) -> str:
    return _b64encode(f"{clock.iso_micros(moment)}|{identity}".encode("utf-8"))


def decode_cursor(cursor: str | None) -> tuple[datetime, str] | None:
    if cursor is None or cursor == "":
        return None
    if not isinstance(cursor, str) or len(cursor) > facts.CURSOR_MAX_LEN:
        raise BadRequest("cursor 非法", field="cursor")
    try:
        raw = _b64decode(cursor).decode("utf-8")
    except Exception as exc:                            # noqa: BLE001 - 各种错法都归 400
        raise BadRequest("cursor 非法", field="cursor") from exc
    head, _, tail = raw.partition("|")
    if not tail:
        raise BadRequest("cursor 结构非法", field="cursor")
    return clock.parse_datetime(head, field="cursor"), tail


# ───────────────────────────────────────────────────────── 入参校验
def normalize_level(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text not in facts.LEVELS:
        raise BadRequest("level 必须是 I0–I4 之一", field="level")
    return text


def level_rank(level: Any) -> int:
    return facts.LEVEL_RANK[normalize_level(level)]


def validate_amount(value: Any, *, field: str = "base_amount_micro") -> int:
    if isinstance(value, bool) or value is None:
        raise BadRequest(f"{field} 必须是非负整数（micro）", field=field)
    if isinstance(value, str):
        text = value.strip()
        if not text.isdigit():
            raise BadRequest(f"{field} 必须是非负整数（micro）", field=field)
        number = int(text)
    elif isinstance(value, int):
        number = value
    else:
        raise BadRequest(f"{field} 必须是非负整数（micro）", field=field)
    if number < 0:
        raise BadRequest(f"{field} 不能为负", field=field)
    if number > facts.BASE_AMOUNT_MAX_MICRO:
        raise BadRequest(f"{field} 超出上限", field=field)
    return number


def normalize_text(value: Any, *, field: str, max_len: int, required: bool = True) -> str | None:
    if value is None:
        if required:
            raise BadRequest(f"{field} 必填", field=field)
        return None
    if not isinstance(value, str):
        raise BadRequest(f"{field} 必须是字符串", field=field)
    text = value.strip()
    if not text and required:
        raise BadRequest(f"{field} 必填", field=field)
    if not text:
        return None
    if len(text) > max_len:
        raise BadRequest(f"{field} 过长（≤{max_len}）", field=field)
    if any(char in text for char in "\r\n\t"):
        raise BadRequest(f"{field} 不得包含换行 / 制表符", field=field)
    return text


def validate_node_id(value: Any) -> str:
    text = normalize_text(value, field="node_id", max_len=facts.NODE_MAX_LEN)
    assert text is not None
    return text


def validate_model(value: Any) -> str:
    text = normalize_text(value, field="model", max_len=facts.MODEL_MAX_LEN)
    assert text is not None
    return text


def normalize_actor(value: Any) -> str:
    text = normalize_text(value, field="actor", max_len=facts.ACTOR_MAX_LEN)
    assert text is not None
    return text


def validate_reason(value: Any) -> str:
    text = normalize_text(value, field="reason", max_len=facts.REASON_MAX_LEN)
    assert text is not None
    return text


def validate_evidence_ref(value: Any) -> str:
    text = normalize_text(value, field="evidence_ref", max_len=facts.EVIDENCE_MAX_LEN)
    assert text is not None
    return text


def normalize_reviewers(value: Any) -> list[str]:
    """复核人列表：1..MAX_REVIEWERS 个非空、去重后仍满足数量（重复直接 400）。"""
    if value is None:
        return []
    if isinstance(value, str):
        items: Iterable[Any] = [value]
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        raise BadRequest("reviewers 必须是字符串数组", field="reviewers")
    out: list[str] = []
    for item in items:
        text = normalize_text(item, field="reviewers", max_len=facts.ACTOR_MAX_LEN)
        if text is not None:
            out.append(text)
    if len(out) > facts.MAX_REVIEWERS:
        raise BadRequest(f"reviewers 最多 {facts.MAX_REVIEWERS} 人", field="reviewers")
    if len(set(out)) != len(out):
        raise BadRequest("reviewers 不得重复（双人复核必须是两个不同主体）", field="reviewers")
    return out


def parse_hold_id(value: Any) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise BadRequest("hold id 非法", field="id") from exc


def page_limit(value: Any) -> int:
    if value is None:
        return facts.DEFAULT_PAGE_SIZE
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise BadRequest("limit 必须是整数", field="limit") from exc
    if number < 1 or number > facts.MAX_PAGE_SIZE:
        raise BadRequest(f"limit 必须在 1–{facts.MAX_PAGE_SIZE}", field="limit")
    return number
