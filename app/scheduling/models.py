# SPDX-License-Identifier: AGPL-3.0-or-later
"""M04 领域模型：金额换算、UUIDv7、聚合数据类与行映射。

三条铁律：

* **金额一律整数最小单位**（USD 分）：``Amount`` 只是 API 的十进制字符串载体，
  进门立刻转 ``*_minor``；超精度**直接拒绝**、不四舍五入（INV-13 / 00-conventions §3.4）。
* **比例一律整数**：ρ / κ 用 milli（×1000），占比用 bps（×10000），λ 用微分（1e-6 分）。
  任何排序 / 比较都不出现 float，保证 INV-03 的复算一致。
* **ID**：报价 / 出价 / 成交锁用 UUIDv7（时间有序）；``decision_id`` 用 **UUIDv5**
  （由四元锚点确定性派生，INV-03 的要求压过「时间有序」的一般约定，见 ``decisions``）。
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from . import facts
from .errors import AmountPrecisionRejected, IntervalInvalid, InvalidArgument, UnsupportedCurrency

__all__ = [
    "uuid7", "parse_amount", "format_amount", "normalize_model", "parse_price_pair",
    "Quote", "Bid", "Booking", "Decision", "Candidate", "Score",
    "AMOUNT_PATTERN",
]

AMOUNT_PATTERN = re.compile(r"^-?[0-9]+(\.[0-9]+)?$")


# --------------------------------------------------------------------------- ID
def uuid7(now_us: int | None = None) -> uuid.UUID:
    """UUIDv7（时间有序）：48 bit 毫秒时间戳 + 版本位 + 随机后缀（00-conventions §2）。"""
    if now_us is None:
        now_us = int(datetime.now().timestamp() * 1_000_000)
    millis = now_us // 1_000
    rand = uuid.uuid4().int
    value = (millis & 0xFFFF_FFFF_FFFF) << 80                   # 48 bit unix_ts_ms
    value |= 0x7 << 76                                          # version = 7
    value |= ((rand >> 64) & 0xFFF) << 64                       # 12 bit rand_a
    value |= 0b10 << 62                                         # variant = RFC 4122
    value |= rand & 0x3FFF_FFFF_FFFF_FFFF                       # 62 bit rand_b
    return uuid.UUID(int=value)


# --------------------------------------------------------------------------- 金额
def _minor_from_text(text: str, *, field_name: str) -> int:
    raw = text.strip()
    if not AMOUNT_PATTERN.match(raw):
        raise InvalidArgument(f"{field_name} 必须是十进制数字字符串（spec Amount）",
                              field=field_name)
    negative = raw.startswith("-")
    body = raw[1:] if negative else raw
    whole, _, frac = body.partition(".")
    if len(frac) > 2:
        raise AmountPrecisionRejected(
            f"{field_name} 超过 USD 精度（最多 2 位小数），直接拒绝不四舍五入",
            field=field_name, precision=len(frac))
    minor = int(whole) * facts.AMOUNT_SCALE + int((frac or "0").ljust(2, "0"))
    if negative:
        raise InvalidArgument(f"{field_name} 不能为负数", field=field_name)
    if minor > facts.MAX_PRICE_MINOR:
        raise InvalidArgument(f"{field_name} 超过上限（{facts.MAX_PRICE_MINOR} 分）",
                              field=field_name, max_minor=facts.MAX_PRICE_MINOR)
    return minor


def parse_amount(value: Any, *, field_name: str = "amount") -> int:
    """把 spec ``Amount``（``{"amount": "8.75", "unit": "token"}``）转成整数分。

    容忍三种写法（都要求十进制字符串，**不接受 float**）::

        {"amount": "8.75", "unit": "token"}   → 875
        "8.75"                                → 875
        875                                   → 875（已经是分）

    超精度 / 负数 / 超上限 / 非字符串浮点 → 直接拒绝（INV-13）。
    """
    unit: str | None = None
    if isinstance(value, dict):
        if "amount" not in value:
            raise InvalidArgument(f"{field_name} 缺少 amount 字段（spec Amount）",
                                  field=field_name)
        unit = value.get("unit")
        raw = value["amount"]
    else:
        raw = value

    if isinstance(value, bool) or isinstance(raw, bool):
        raise InvalidArgument(f"{field_name} 不能是布尔值", field=field_name)
    if isinstance(raw, float):
        raise InvalidArgument(f"{field_name} 不接受浮点（客户端必须传十进制字符串）",
                              field=field_name)
    if isinstance(raw, int):
        minor = raw
        if minor < 0:
            raise InvalidArgument(f"{field_name} 不能为负数", field=field_name)
        if minor > facts.MAX_PRICE_MINOR:
            raise InvalidArgument(f"{field_name} 超过上限（{facts.MAX_PRICE_MINOR} 分）",
                                  field=field_name, max_minor=facts.MAX_PRICE_MINOR)
    elif isinstance(raw, (str, Decimal)):
        minor = _minor_from_text(str(raw), field_name=field_name)
    else:
        raise InvalidArgument(f"{field_name} 类型不支持：{type(raw).__name__}", field=field_name)

    if unit is not None and not isinstance(unit, str):
        raise InvalidArgument(f"{field_name}.unit 必须是字符串", field=field_name)
    return minor


def format_amount(minor: int, unit: str) -> dict[str, str]:
    """整数分 → spec ``Amount``（展示用；不做业务计算）。"""
    sign = "-" if minor < 0 else ""
    absolute = abs(int(minor))
    whole, frac = divmod(absolute, facts.AMOUNT_SCALE)
    return {"amount": f"{sign}{whole}.{frac:02d}", "unit": unit}


def parse_price_pair(payload: dict[str, Any], *, low_key: str, high_key: str,
                     low_default: int = 0) -> tuple[int, int | None]:
    """解析区间（``low ≤ high``）；上界缺省 = 不设上限（None）。"""
    low = parse_amount(payload[low_key], field_name=low_key) if payload.get(low_key) is not None \
        else low_default
    high = parse_amount(payload[high_key], field_name=high_key) \
        if payload.get(high_key) is not None else None
    if high is not None and high < low:
        raise IntervalInvalid(f"{high_key} 必须 ≥ {low_key}（INV-01）",
                              low_minor=low, high_minor=high)
    return low, high


def normalize_model(model: str) -> str:
    """模型 slug 归一（M04 §6 F1「归一后比较」）：小写 + 去首尾空白 + 折叠内部空白。"""
    if not isinstance(model, str):
        raise InvalidArgument("model 必须是字符串", field="model")
    text = " ".join(model.strip().lower().split())
    if not text or len(text) > 200:
        raise InvalidArgument("model 长度必须在 1–200", field="model")
    return text


def check_currency(payload: dict[str, Any], *, field_name: str = "currency") -> str:
    value = payload.get(field_name, facts.CURRENCY)
    if not isinstance(value, str) or value.strip().upper() != facts.CURRENCY:
        raise UnsupportedCurrency(f"S1 仅支持 {facts.CURRENCY}（INV-13）",
                                  field=field_name)
    return facts.CURRENCY


# --------------------------------------------------------------------------- 聚合
@dataclass(frozen=True)
class Quote:
    """供方报价（M04 §3）。``ask_price_minor`` = 区间下界 a_lo，``price_max_minor`` = a_hi。"""

    id: uuid.UUID
    node_id: str
    access: str
    model: str
    unit: str
    ask_price_minor: int
    price_max_minor: int | None
    currency: str
    ttl_s: int
    state: str
    quote_version: int
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None

    @property
    def a_lo(self) -> int:
        return self.ask_price_minor

    @property
    def a_hi(self) -> int | None:
        return self.price_max_minor

    @property
    def quote_id(self) -> str:
        return str(self.id)

    def active_at(self, moment: datetime) -> bool:
        return self.state == "active" and self.expires_at > moment

    def signature(self) -> tuple:
        """内容指纹：用于「内容不变不升版本」。"""
        return (self.node_id, self.access, self.model, self.unit,
                self.ask_price_minor, self.price_max_minor, self.currency, self.ttl_s)

    @classmethod
    def from_row(cls, row: tuple) -> "Quote":
        return cls(*row)


@dataclass(frozen=True)
class Bid:
    """用方出价（M04 §3）：``min_price_minor`` = b_lo，``max_price_minor`` = b_hi（NULL = +∞）。"""

    id: uuid.UUID
    tenant_id: uuid.UUID
    model: str
    min_price_minor: int
    max_price_minor: int | None
    strategy: str
    currency: str
    state: str
    bid_version: int
    created_at: datetime
    expires_at: datetime

    @property
    def b_lo(self) -> int:
        return self.min_price_minor

    @property
    def b_hi(self) -> int | None:
        return self.max_price_minor

    @property
    def bid_id(self) -> str:
        return str(self.id)

    def active_at(self, moment: datetime) -> bool:
        return self.state == "active" and self.expires_at > moment

    def signature(self) -> tuple:
        return (self.tenant_id, self.model, self.min_price_minor, self.max_price_minor,
                self.strategy, self.currency)

    @classmethod
    def from_row(cls, row: tuple) -> "Bid":
        return cls(*row)


@dataclass(frozen=True)
class Booking:
    """成交锁（M04 §3）：held → consumed / expired。"""

    id: uuid.UUID
    quote_id: uuid.UUID
    bid_id: uuid.UUID | None
    node_id: str
    tenant_id: uuid.UUID
    request_id: str | None
    price_minor: int
    strategy: str
    state: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None

    @property
    def booking_id(self) -> str:
        return str(self.id)

    @classmethod
    def from_row(cls, row: tuple) -> "Booking":
        return cls(*row)


@dataclass(frozen=True)
class Candidate:
    """候选节点的一次**输入快照**（P1 产出、P2 打分、P3 约束都只读它）。

    只放输入，不放评分结论——复算回放靠它就是靠「同一份输入」（INV-03）。
    """

    node_id: str
    access: str
    model: str
    unit: str
    ask_price_minor: int
    price_max_minor: int | None = None
    max_qps: int | None = None
    resource_level: str | None = None
    region: str | None = None
    last_seen_at: datetime | None = None
    announced_at: datetime | None = None
    rho_milli: int = facts.RHO_MISSING_MILLI
    kappa_milli: int = facts.KAPPA_MISSING_MILLI
    affinity_hit: bool = False
    physical_host_id: str | None = None
    quote_id: str | None = None
    quote_version: int = 0
    quote_created_at: datetime | None = None
    account_id: str | None = None
    tenant_id: str | None = None
    rep_missing: bool = True
    load_missing: bool = True

    @property
    def a_lo(self) -> int:
        return self.ask_price_minor

    @property
    def a_hi(self) -> int | None:
        return self.price_max_minor

    def as_input(self) -> dict[str, Any]:
        """落库形态（routing_decisions.candidates）：只含输入，时间为 ISO 串。"""
        return {
            "node_id": self.node_id,
            "access": self.access,
            "model": self.model,
            "unit": self.unit,
            "ask_price_minor": self.ask_price_minor,
            "price_max_minor": self.price_max_minor,
            "max_qps": self.max_qps,
            "resource_level": self.resource_level,
            "region": self.region,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "announced_at": self.announced_at.isoformat() if self.announced_at else None,
            "rho_milli": self.rho_milli,
            "kappa_milli": self.kappa_milli,
            "affinity_hit": self.affinity_hit,
            "physical_host_id": self.physical_host_id,
            "quote_id": self.quote_id,
            "quote_version": self.quote_version,
            "quote_created_at": (self.quote_created_at.isoformat()
                                 if self.quote_created_at else None),
            "rep_missing": self.rep_missing,
            "load_missing": self.load_missing,
        }

    @classmethod
    def from_input(cls, payload: dict[str, Any]) -> "Candidate":
        def _dt(key: str) -> datetime | None:
            value = payload.get(key)
            return datetime.fromisoformat(value) if value else None

        return cls(
            node_id=payload["node_id"], access=payload["access"], model=payload["model"],
            unit=payload.get("unit", "token"),
            ask_price_minor=int(payload["ask_price_minor"]),
            price_max_minor=(int(payload["price_max_minor"])
                             if payload.get("price_max_minor") is not None else None),
            max_qps=(int(payload["max_qps"]) if payload.get("max_qps") is not None else None),
            resource_level=payload.get("resource_level"), region=payload.get("region"),
            last_seen_at=_dt("last_seen_at"), announced_at=_dt("announced_at"),
            rho_milli=int(payload.get("rho_milli", facts.RHO_MISSING_MILLI)),
            kappa_milli=int(payload.get("kappa_milli", facts.KAPPA_MISSING_MILLI)),
            affinity_hit=bool(payload.get("affinity_hit", False)),
            physical_host_id=payload.get("physical_host_id"),
            quote_id=payload.get("quote_id"),
            quote_version=int(payload.get("quote_version", 0)),
            quote_created_at=_dt("quote_created_at"),
            rep_missing=bool(payload.get("rep_missing", True)),
            load_missing=bool(payload.get("load_missing", True)),
        )


@dataclass(frozen=True)
class Score:
    """P2 打分结果（分项全整数，单位：1e-6 分）。"""

    node_id: str
    ask_price_minor: int
    rho_milli: int
    kappa_milli: int
    lambda_micro: int
    cost_micro: int
    affinity_hit: bool = False
    rep_missing: bool = False
    load_missing: bool = False

    def as_breakdown(self) -> dict[str, Any]:
        return {"node_id": self.node_id, "ask_price_minor": self.ask_price_minor,
                "rho_milli": self.rho_milli, "kappa_milli": self.kappa_milli,
                "lambda_micro": self.lambda_micro, "cost_micro": self.cost_micro,
                "affinity_hit": self.affinity_hit, "rep_missing": self.rep_missing,
                "load_missing": self.load_missing}


@dataclass
class Decision:
    """决策记录（M04 §3 RoutingDecision；只追加）。"""

    decision_id: uuid.UUID
    trace_id: str
    attempt_no: int
    snapshot_ts: datetime
    quote_version: int
    policy_version: str
    request_digest: str
    candidates: list[dict[str, Any]] = field(default_factory=list)
    eliminated: list[dict[str, Any]] = field(default_factory=list)
    score_breakdown: list[dict[str, Any]] = field(default_factory=list)
    chosen: dict[str, Any] | None = None
    tie_break: str | None = None
    preempt_plan: list[dict[str, Any]] = field(default_factory=list)
    fallbacks: list[dict[str, Any]] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    eta_seconds: int | None = None
    price_minor: int | None = None
    outcome: str = "rejected"
    fallback_used: bool = False
    decided_at: datetime | None = None

    @property
    def chosen_node_id(self) -> str | None:
        return (self.chosen or {}).get("node_id")

    @classmethod
    def from_row(cls, row: tuple) -> "Decision":
        (decision_id, trace_id, attempt_no, snapshot_ts, quote_version, policy_version,
         request_digest, candidates, eliminated, score_breakdown, chosen, tie_break,
         preempt_plan, fallbacks, reason_codes, eta_seconds, price_minor, outcome,
         fallback_used, decided_at) = row
        return cls(decision_id=decision_id, trace_id=trace_id, attempt_no=int(attempt_no),
                   snapshot_ts=snapshot_ts, quote_version=int(quote_version),
                   policy_version=policy_version, request_digest=request_digest,
                   candidates=list(candidates or []), eliminated=list(eliminated or []),
                   score_breakdown=list(score_breakdown or []), chosen=chosen,
                   tie_break=tie_break, preempt_plan=list(preempt_plan or []),
                   fallbacks=list(fallbacks or []), reason_codes=list(reason_codes or []),
                   eta_seconds=eta_seconds, price_minor=price_minor, outcome=outcome,
                   fallback_used=bool(fallback_used), decided_at=decided_at)

    def as_dict(self) -> dict[str, Any]:
        """spec ``RouteDecision`` 形态（不含评分权重与阈值）。"""
        return {
            "decision_id": str(self.decision_id),
            "chosen": self.chosen,
            "eta_seconds": self.eta_seconds,
            "price": (format_amount(self.price_minor, (self.chosen or {}).get("unit", "token"))
                      if self.price_minor is not None else None),
            "quote_version": str(self.quote_version),
            "policy_version": self.policy_version,
            "snapshot_ts": self.snapshot_ts.isoformat(),
            "tie_break": self.tie_break,
            "fallback_used": self.fallback_used,
            "fallbacks": self.fallbacks,
            "eliminated": self.eliminated,
            "outcome": self.outcome,
            "reason_codes": self.reason_codes,
            "decided_at": (self.decided_at or self.snapshot_ts).isoformat(),
        }
