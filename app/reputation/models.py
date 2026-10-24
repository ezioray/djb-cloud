# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 领域对象与对外 payload（spec 1.2.4 的 schema 一一对应）。

原则：

* **payload 只由这里产出**：字段名 / 可空性 / 枚举值跟 spec 对齐，路由层不做拼装；
* 时间一律 ISO-8601 带 Z（00-conventions §4.1）；金额一律整数 COP 单位（§3.1 的积分等价口径）；
* ``reasons`` 只放人类可读短句，**不含阈值**（spec ``ReputationProfile.reasons`` 描述）；
* 游标是 ``(created_at, id)`` 的不透明 keyset，带校验位（00-conventions §5「不得用 offset」）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Iterable, Mapping, Sequence

from . import clock, errors

__all__ = [
    "as_uuid", "new_id", "encode_cursor", "decode_cursor",
    "encode_cursor_payload", "decode_cursor_payload", "page_block",
    "ReputationScore", "ReputationEvent", "CopLedgerEntry", "CopBalance", "Redemption",
    "Transfer", "Invite", "InviteOverview", "Grant", "GRANT_COLUMNS", "profile_payload",
]

_CURSOR_SEPARATOR = "."


# --------------------------------------------------------------------------- id / 游标
def as_uuid(value: Any) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise errors.InvalidArgument("id 必须是 UUID") from exc


def new_id() -> uuid.UUID:
    """UUIDv7（时间有序；00-conventions §2）。失败时退化为 uuid4（同一接口，不改变契约）。"""
    factory = getattr(uuid, "uuid7", None)
    if factory is not None:                                   # pragma: no cover - 3.14+
        return factory()
    # Python 3.11/3.12 没有 uuid7：用时间戳高位手工拼一个 RFC 9562 形状的 v7
    millis = int(clock.now().timestamp() * 1000)
    raw = bytearray(uuid.uuid4().bytes)
    raw[0:6] = millis.to_bytes(6, "big")
    raw[6] = (raw[6] & 0x0F) | 0x70                           # version 7
    raw[8] = (raw[8] & 0x3F) | 0x80                           # variant RFC 4122
    return uuid.UUID(bytes=bytes(raw))


def encode_cursor_payload(payload: Mapping[str, Any]) -> str:
    """不透明游标：base64url(JSON) + "." + 校验位（00-conventions §5：不得自行构造）。"""
    raw = json.dumps(dict(payload), separators=(",", ":"), sort_keys=True).encode("utf-8")
    checksum = hashlib.sha256(raw).hexdigest()[:8]
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{token}{_CURSOR_SEPARATOR}{checksum}"


def decode_cursor_payload(cursor: str) -> dict[str, Any]:
    """解析游标；任何异常都翻成 ``40001 cursor_invalid``（不回显内部结构）。"""
    if not isinstance(cursor, str) or not cursor or len(cursor) > 512 \
            or _CURSOR_SEPARATOR not in cursor:
        raise errors.CursorInvalid("游标不合法（首次请求不要传 cursor）")
    token, _, checksum = cursor.rpartition(_CURSOR_SEPARATOR)
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:                                    # noqa: BLE001
        raise errors.CursorInvalid("游标不合法（无法解码）") from exc
    if hashlib.sha256(raw).hexdigest()[:8] != checksum:
        raise errors.CursorInvalid("游标不合法（校验位不匹配）")
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:                                    # noqa: BLE001
        raise errors.CursorInvalid("游标不合法（内容缺失）") from exc
    if not isinstance(data, dict):
        raise errors.CursorInvalid("游标不合法（内容缺失）")
    return data


def encode_cursor(moment: datetime, row_id: Any) -> str:
    """``(created_at, id)`` keyset 游标（台账 / 事件列表用）。"""
    return encode_cursor_payload({"t": clock.isoformat(moment), "i": str(row_id)})


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    """解析 ``(created_at, id)`` 游标。"""
    data = decode_cursor_payload(cursor)
    moment = clock.parse_datetime(data.get("t"))
    row_id = str(data.get("i") or "")
    if moment is None or not row_id:
        raise errors.CursorInvalid("游标不合法（内容缺失）")
    return moment, row_id


def page_block(*, start_cursor: str | None, next_cursor: str | None) -> dict[str, Any]:
    """spec ``Page``：``{cursor, has_more, next_cursor}``（``has_more=false`` 时游标为 null）。"""
    return {"cursor": start_cursor, "has_more": next_cursor is not None,
            "next_cursor": next_cursor}


def _num(value: Any) -> float | int:
    """NUMERIC → JSON 数字（整数值给 int，其余给 float；spec 用 ``type: number``）。"""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, (int, float)):
        return value
    return int(value)


# --------------------------------------------------------------------------- 评分
@dataclass(frozen=True)
class ReputationScore:
    account_id: str
    score: int
    tier: str
    quality_coef: Decimal
    stability_coef: Decimal
    window_days: int
    policy_version: str
    computed_at: datetime
    tier_since: datetime | None = None
    prev_tier: str | None = None
    manual_tier: bool = False
    reasons: tuple[str, ...] = ()

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> "ReputationScore":
        return cls(account_id=row[0], score=int(row[1]), tier=row[2],
                   quality_coef=Decimal(str(row[3])), stability_coef=Decimal(str(row[4])),
                   window_days=int(row[5]), policy_version=row[6],
                   computed_at=row[7], tier_since=row[8], prev_tier=row[9],
                   manual_tier=bool(row[10]), reasons=tuple(row[11] or ()))

    def as_dict(self, *, reasons: Iterable[str] | None = None) -> dict[str, Any]:
        """spec ``ReputationProfile``（required 字段全在；reasons 是扩展字段）。"""
        return {"account_id": self.account_id, "score": self.score, "tier": self.tier,
                "quality_coef": float(self.quality_coef),
                "stability_coef": float(self.stability_coef),
                "window_days": self.window_days, "policy_version": self.policy_version,
                "computed_at": clock.isoformat(self.computed_at),
                "reasons": list(self.reasons if reasons is None else reasons)}

    def as_admin_row(self) -> dict[str, Any]:
        """spec ``ReputationScoreRow``（后台只读列表）。"""
        return {"account_id": self.account_id, "score": self.score, "tier": self.tier,
                "computed_at": clock.isoformat(self.computed_at)}


def profile_payload(score: ReputationScore,
                    reasons: Iterable[str] | None = None) -> dict[str, Any]:
    return score.as_dict(reasons=reasons)


# --------------------------------------------------------------------------- 指标事件
@dataclass(frozen=True)
class ReputationEvent:
    id: uuid.UUID
    account_id: str
    metric: str
    value: Decimal
    weight: int
    delta: Decimal
    ref_id: str | None
    occurred_at: datetime

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> "ReputationEvent":
        return cls(id=row[0], account_id=row[1], metric=row[2], value=Decimal(str(row[3])),
                   weight=int(row[4]), delta=Decimal(str(row[5])), ref_id=row[6],
                   occurred_at=row[7])

    def as_dict(self) -> dict[str, Any]:
        """spec ``ReputationEvent``（required: id/metric/value/weight/delta/occurred_at）。"""
        return {"id": str(self.id), "metric": self.metric, "value": _num(self.value),
                "weight": self.weight, "delta": _num(self.delta), "ref_id": self.ref_id,
                "occurred_at": clock.isoformat(self.occurred_at)}


# --------------------------------------------------------------------------- COP
@dataclass(frozen=True)
class CopBalance:
    available: int
    locked: int
    total_earned: int
    redeemable: bool
    transferable: bool
    updated_at: datetime

    def as_dict(self) -> dict[str, Any]:
        """spec ``CopBalance``（INV-01：available + locked = total，全部 ≥0）。"""
        return {"available": self.available, "locked": self.locked,
                "total": self.available + self.locked,
                "total_earned": self.total_earned, "unit": "COP",
                "redeemable": self.redeemable, "transferable": self.transferable,
                "updated_at": clock.isoformat(self.updated_at)}


@dataclass(frozen=True)
class CopLedgerEntry:
    id: uuid.UUID
    account_id: str
    direction: str
    amount: int
    source: str
    ref_id: str
    status: str
    lock_until: datetime | None
    created_at: datetime

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> "CopLedgerEntry":
        return cls(id=row[0], account_id=row[1], direction=row[2], amount=int(row[3]),
                   source=row[4], ref_id=row[5], status=row[6], lock_until=row[7],
                   created_at=row[8])

    def as_dict(self) -> dict[str, Any]:
        """spec ``CopLedgerEntry``（required: id/direction/amount/source/status/created_at）。"""
        return {"id": str(self.id), "direction": self.direction, "amount": self.amount,
                "source": self.source, "ref_id": self.ref_id, "status": self.status,
                "lock_until": clock.isoformat(self.lock_until),
                "created_at": clock.isoformat(self.created_at)}


@dataclass(frozen=True)
class Redemption:
    """兑换单：**没有独立表**——兑换是 COP 账本的一条 ``redeem`` journal（spec §5 无此表）。"""

    redemption_id: uuid.UUID
    units: int
    state: str
    created_at: datetime

    def as_dict(self) -> dict[str, Any]:
        """spec ``CopRedemption``（state ∈ requested/posted/rejected/expired）。"""
        return {"redemption_id": str(self.redemption_id), "units": self.units,
                "state": self.state, "created_at": clock.isoformat(self.created_at)}


@dataclass(frozen=True)
class Transfer:
    transfer_id: uuid.UUID
    units: int
    state: str
    created_at: datetime
    from_account_id: str | None = None
    to_account_id: str | None = None
    locked_until: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        """spec ``CopTransfer``（state ∈ posted/rejected；收款方所得入 locked）。"""
        return {"transfer_id": str(self.transfer_id), "units": self.units,
                "state": self.state, "created_at": clock.isoformat(self.created_at),
                "from_account_id": self.from_account_id,
                "to_account_id": self.to_account_id,
                "locked_until": clock.isoformat(self.locked_until)}


# --------------------------------------------------------------------------- 邀请
@dataclass(frozen=True)
class Invite:
    id: uuid.UUID
    inviter_id: str
    invitee_id: str | None
    code: str
    status: str
    bound_at: datetime | None
    expire_at: datetime | None
    created_at: datetime
    earned_units: int = 0

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> "Invite":
        return cls(id=row[0], inviter_id=row[1], invitee_id=row[2], code=row[3], status=row[4],
                   bound_at=row[5], expire_at=row[6], created_at=row[7],
                   earned_units=int(row[8] or 0))

    def as_dict(self) -> dict[str, Any]:
        """spec ``InviteRecord``（required: invite_id/status）。"""
        return {"invite_id": str(self.id), "invitee_id": self.invitee_id, "code": self.code,
                "status": self.status, "bound_at": clock.isoformat(self.bound_at),
                "expire_at": clock.isoformat(self.expire_at),
                "earned_units": self.earned_units}


@dataclass(frozen=True)
class InviteOverview:
    items: Sequence[Invite]
    bound: int
    pending: int
    earned_units: int
    start_cursor: str | None
    next_cursor: str | None

    def as_dict(self) -> dict[str, Any]:
        """spec ``InviteOverview``（required: data/totals/page）。"""
        return {"data": [item.as_dict() for item in self.items],
                "totals": {"bound": self.bound, "pending": self.pending,
                           "earned_units": self.earned_units},
                "page": page_block(start_cursor=self.start_cursor,
                                   next_cursor=self.next_cursor)}


# --------------------------------------------------------------------------- 人工授予
#: ``reward_grants`` 的读取列序（grants.py 的 SELECT 与 :meth:`Grant.from_row` 共用）
GRANT_COLUMNS = ("id, account_id, kind, amount, reason, approval_id, created_at, "
                 "actor, approved_by")


@dataclass(frozen=True)
class Grant:
    id: uuid.UUID
    account_id: str
    kind: str
    units: int
    reason: str
    approval_id: str | None
    created_at: datetime
    actor: str | None = None
    approved_by: str | None = None

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> "Grant":
        return cls(id=row[0], account_id=row[1], kind=row[2], units=int(row[3]),
                   reason=row[4], approval_id=row[5], created_at=row[6], actor=row[7],
                   approved_by=row[8])

    def as_dict(self) -> dict[str, Any]:
        """spec ``ReputationGrant``（required: grant_id/account_id/kind/units/reason/created_at）。"""
        return {"grant_id": str(self.id), "account_id": self.account_id, "kind": self.kind,
                "units": self.units, "reason": self.reason, "approval_id": self.approval_id,
                "created_at": clock.isoformat(self.created_at),
                "actor": self.actor, "approved_by": self.approved_by}
