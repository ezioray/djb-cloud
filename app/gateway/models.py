# SPDX-License-Identifier: Apache-2.0
"""M03 领域模型：UUIDv7、跨模块 provider 的入参 / 出参、请求元数据记录。

三条口径：

* **ID**：``request_id`` / ``usage_id`` / ``batch_id`` 用 UUIDv7（时间有序，00-conventions §2）；
  客户端给的 ``X-Request-Id`` 若是合法 UUID 就**原样回显并作为 request_id**（spec
  ``RequestId`` 参数「服务端原样回显」），非法形态则服务端生成并在头部回显生成值。
* **金额**：``Amount`` 只做十进制字符串 ↔ 整数最小单位（USD 分）的转换；超精度
  **直接拒绝**、不四舍五入（00-conventions §3.4）。
* **跨模块出参一律**先 :func:`coerce_*` **规整成 dataclass**：注入的 provider 可以返回
  dataclass、Mapping 或带属性的对象（M01 ``AuthContext`` / M04 ``Decision`` 都能直接吃），
  网关内部只认 dataclass，避免把别人的内部结构带进判定。
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence

from . import clock, facts

__all__ = [
    "uuid7", "AMOUNT_PATTERN", "format_amount_minor", "parse_amount_minor", "parse_request_id",
    "ip_allowed", "Principal", "coerce_principal", "ChosenNode", "RouteRequest", "RouteDecision",
    "coerce_route_decision", "NodeCall", "NodeResult", "UsageDraft", "UsageReceipt",
    "RequestRecord", "pick_value", "str_or_none", "int_or_none",
]

AMOUNT_PATTERN = re.compile(r"^-?[0-9]+(\.[0-9]+)?$")


# --------------------------------------------------------------------------- ID
def uuid7(now_us: int | None = None) -> uuid.UUID:
    """UUIDv7（时间有序）：48 bit 毫秒时间戳 + 版本位 + 随机后缀（00-conventions §2）。"""
    if now_us is None:
        now_us = int(clock.utcnow().timestamp() * 1_000_000)
    millis = int(now_us) // 1_000
    rand = uuid.uuid4().int
    value = (millis & 0xFFFF_FFFF_FFFF) << 80
    value |= 0x7 << 76
    value |= ((rand >> 64) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= rand & 0x3FFF_FFFF_FFFF_FFFF
    return uuid.UUID(int=value)


def parse_request_id(raw: str | None, *, now: datetime | None = None) -> str:
    """``X-Request-Id`` 归一：合法 UUID → 原样（小写）；否则生成 UUIDv7。

    spec ``RequestId`` 声明的格式是 ``uuid``；客户端给非 UUID 时**不失败**
    （容错读取 INV-M03-07），服务端生成一个并在响应头回显**生成值**，
    避免非 UUID 值污染 ``api_request_log.request_id`` 的唯一性与排障口径。
    """
    text = (raw or "").strip()
    if text:
        try:
            return str(uuid.UUID(text))
        except (ValueError, AttributeError, TypeError):
            pass
    moment = clock.as_utc(now) if now else clock.utcnow()
    return str(uuid7(int(moment.timestamp() * 1_000_000)))


# --------------------------------------------------------------------------- 金额
def format_amount_minor(amount_minor: int) -> str:
    """整数分 → spec ``Amount.amount`` 十进制字符串（``125`` → ``"1.25"``）。"""
    value = int(amount_minor)
    sign = "-" if value < 0 else ""
    value = abs(value)
    return f"{sign}{value // 100}.{value % 100:02d}"


def parse_amount_minor(text: Any, *, field_name: str = "amount") -> int:
    """spec ``Amount.amount`` → 整数分；超过 2 位小数直接拒绝（不四舍五入）。"""
    if not isinstance(text, str) or not AMOUNT_PATTERN.match(text.strip()):
        raise ValueError(f"{field_name} 必须是十进制数字字符串（spec Amount）")
    raw = text.strip()
    try:
        value = Decimal(raw)
    except InvalidOperation as exc:                             # pragma: no cover - 正则已挡
        raise ValueError(f"{field_name} 不是合法十进制数") from exc
    scaled = value * 100
    if scaled != scaled.to_integral_value():
        raise ValueError(f"{field_name} 超过 USD 精度（最多 2 位小数），直接拒绝")
    return int(scaled)


# --------------------------------------------------------------------------- IP 白名单
def ip_allowed(client_ip: str | None, allowlist: Sequence[str] | None) -> bool:
    """Key 级 IP 白名单（空 / 未设置 = 不限制）。支持单 IP 与 CIDR。"""
    entries = [entry.strip() for entry in (allowlist or []) if str(entry).strip()]
    if not entries:
        return True
    if not client_ip:
        return False
    try:
        address = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return False
    for entry in entries:
        try:
            if "/" in entry:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            elif address == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------- 主体（M01）
@dataclass(frozen=True)
class Principal:
    """调用方身份（M01 ``AuthContext`` 的网关侧投影）；**只读**。"""

    account_id: str
    tenant_id: str
    api_key_id: int | None = None
    api_key_prefix: str | None = None
    account_state: str = "normal"
    quotas: Mapping[str, Any] = field(default_factory=dict)
    ip_allowlist: tuple[str, ...] = ()
    policy_version: str | None = None
    key_overlap: bool = False
    scopes: tuple[str, ...] = ()

    @property
    def writable(self) -> bool:
        """只有 ``normal`` 可写（M01 §3 五态；frozen / closing → 40304）。"""
        return self.account_state == "normal"


def pick_value(source: Any, *names: str, default: Any = None) -> Any:
    if isinstance(source, Mapping):
        for name in names:
            if name in source:
                return source[name]
        return default
    for name in names:
        value = getattr(source, name, None)
        if value is not None:
            return value
    return default


def coerce_principal(value: Any) -> Principal:
    """把 M01 的 ``AuthContext`` / Mapping 规整成 :class:`Principal`（失败即 401）。"""
    if isinstance(value, Principal):
        return value
    if value is None:
        raise ValueError("auth provider 返回 None（fail-closed）")
    account = pick_value(value, "account")
    account_id = pick_value(value, "account_id")
    if account_id is None and account is not None:
        account_id = pick_value(account, "id")
    tenant_id = pick_value(value, "tenant_id")
    if tenant_id is None and account is not None:
        tenant_id = pick_value(account, "tenant_id")
    if account_id is None or tenant_id is None:
        raise ValueError("auth provider 返回的主体缺 account_id / tenant_id（fail-closed）")
    state = pick_value(value, "account_state", "state")
    if state is None and account is not None:
        state = pick_value(account, "state")
    quotas = pick_value(value, "quotas", default={}) or {}
    if not isinstance(quotas, Mapping):
        quotas = {}
    allowlist = pick_value(value, "ip_allowlist", default=()) or ()
    if isinstance(allowlist, str):
        allowlist = tuple(part.strip() for part in allowlist.split(",") if part.strip())
    scopes = pick_value(value, "scopes", default=()) or ()
    if isinstance(scopes, str):
        scopes = tuple(part.strip() for part in scopes.split(",") if part.strip())
    policy_version = pick_value(value, "policy_version")
    if policy_version is None and isinstance(quotas, Mapping):
        policy_version = quotas.get("policy_version")
    return Principal(
        account_id=str(account_id),
        tenant_id=str(tenant_id),
        api_key_id=int_or_none(pick_value(value, "api_key_id")),
        api_key_prefix=pick_value(value, "api_key_prefix"),
        account_state=str(state or "normal"),
        quotas=dict(quotas),
        ip_allowlist=tuple(str(entry) for entry in allowlist),
        policy_version=None if policy_version is None else str(policy_version),
        key_overlap=bool(pick_value(value, "key_overlap", default=False)),
        scopes=tuple(str(entry) for entry in scopes),
    )


def int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- 路由（M04）
@dataclass(frozen=True)
class RouteRequest:
    """发给 M04 的 ``RouteRequest``（spec 1.2.x）；``kind`` 只有 realtime / batch。"""

    model: str
    kind: str
    tenant_id: str
    account_id: str
    request_id: str
    trace_id: str
    attempt_no: int = 1
    requested_tokens: int | None = None
    deadline_seconds: int | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"model": self.model, "kind": self.kind,
                                   "tenant_id": self.tenant_id,
                                   "attempt_no": self.attempt_no}
        if self.requested_tokens is not None:
            payload["requested_tokens"] = int(self.requested_tokens)
        if self.deadline_seconds is not None:
            payload["deadline_seconds"] = int(self.deadline_seconds)
        return payload


@dataclass(frozen=True)
class ChosenNode:
    node_id: str
    upstream_id: str | None = None
    access: str | None = None
    model: str | None = None


@dataclass(frozen=True)
class RouteDecision:
    """M04 决策的网关侧投影（``decision_id`` + ``chosen`` 必有；其余可选）。"""

    decision_id: str
    chosen: ChosenNode
    quote_version: str | None = None
    policy_version: str | None = None
    eta_seconds: int | None = None
    price_minor: int | None = None
    node_qps: int | None = None
    fallback_used: bool = False

    @property
    def node_id(self) -> str:
        return self.chosen.node_id


def coerce_route_decision(value: Any) -> RouteDecision:
    """把 M04 的 ``Decision`` / Mapping 规整成 :class:`RouteDecision`。"""
    if isinstance(value, RouteDecision):
        return value
    if value is None:
        raise ValueError("route provider 返回 None（fail-closed）")
    chosen_raw = pick_value(value, "chosen")
    if chosen_raw is None:
        raise ValueError("route provider 返回缺 chosen")
    node_id = pick_value(chosen_raw, "node_id")
    if not node_id:
        raise ValueError("route provider 的 chosen 缺 node_id")
    chosen = ChosenNode(node_id=str(node_id),
                        upstream_id=str_or_none(pick_value(chosen_raw, "upstream_id")),
                        access=str_or_none(pick_value(chosen_raw, "access")),
                        model=str_or_none(pick_value(chosen_raw, "model")))
    decision_id = pick_value(value, "decision_id")
    price_minor = pick_value(value, "price_minor")
    if price_minor is None:
        price = pick_value(value, "price")
        if isinstance(price, Mapping) and "amount" in price:
            try:
                price_minor = parse_amount_minor(price["amount"], field_name="price")
            except ValueError:
                price_minor = None
        elif isinstance(price, (int, float)) and not isinstance(price, bool):
            price_minor = int(round(float(price) * 100))
    return RouteDecision(
        decision_id=str(decision_id) if decision_id else "",
        chosen=chosen,
        quote_version=str_or_none(pick_value(value, "quote_version")),
        policy_version=str_or_none(pick_value(value, "policy_version")),
        eta_seconds=int_or_none(pick_value(value, "eta_seconds")),
        price_minor=int_or_none(price_minor),
        node_qps=int_or_none(pick_value(value, "node_qps", "max_qps")),
        fallback_used=bool(pick_value(value, "fallback_used", default=False)),
    )


def str_or_none(value: Any) -> str | None:
    return None if value is None else str(value)


# --------------------------------------------------------------------------- 上游节点（M02 承载）
@dataclass(frozen=True)
class NodeCall:
    """发往上游节点的调用（**不含**持久化；正文只在内存里过一手）。"""

    node_id: str
    upstream_id: str | None
    access: str | None
    model: str
    messages: tuple[Mapping[str, Any], ...]
    request_id: str
    trace_id: str
    attempt_no: int
    max_tokens: int | None = None
    temperature: float | None = None
    stop: tuple[str, ...] = ()
    timeout_s: int | None = None


@dataclass(frozen=True)
class NodeResult:
    """上游返回的**元数据 + 正文**（正文只在响应里回给调用方，不入库、不进事件）。"""

    content: str
    finish_reason: str = "stop"
    model: str | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    usage_source: str = "actual"
    latency_ms: int | None = None
    first_byte_ms: int | None = None
    upstream_request_id: str | None = None
    raw_choice_index: int = 0


# --------------------------------------------------------------------------- 计量（M05）
@dataclass(frozen=True)
class UsageDraft:
    """交给 M05 的用量事实（按 ``request_id`` 幂等；**只含元数据与金额**）。"""

    request_id: str
    attempt_no: int
    account_id: str
    tenant_id: str
    api_key_id: int | None
    node_id: str
    model: str
    access: str | None
    tokens_in: int
    tokens_out: int
    usage_source: str
    amount_minor: int | None
    policy_version: str | None
    trace_id: str
    occurred_at: datetime


@dataclass(frozen=True)
class UsageReceipt:
    """M05 回执（最小面：``usage_id`` / ``amount_minor``）。"""

    usage_id: str | None = None
    amount_minor: int | None = None


# --------------------------------------------------------------------------- 请求日志（本模块表）
@dataclass
class RequestRecord:
    """``api_request_log`` 一行（**只有元数据**：不存正文 / 密钥 / PII，INV-M03-02）。"""

    request_id: str
    status: str
    http_status: int
    service_tier: str = "realtime"
    stream: bool = False
    account_id: str | None = None
    tenant_id: str | None = None
    api_key_id: int | None = None
    model: str | None = None
    error_code: int | None = None
    node_id: str | None = None
    latency_ms: int | None = None
    first_byte_ms: int | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    usage_source: str | None = None
    batch_id: str | None = None
    trace_id: str | None = None

    def __post_init__(self) -> None:
        if self.status not in facts.REQUEST_STATUSES:
            raise ValueError(f"status 必须是 {facts.REQUEST_STATUSES}：{self.status!r}")
        if self.service_tier not in facts.SERVICE_TIERS:
            raise ValueError(f"service_tier 必须是 {facts.SERVICE_TIERS}：{self.service_tier!r}")
        if self.usage_source is not None and self.usage_source not in facts.USAGE_SOURCES:
            raise ValueError(f"usage_source 必须是 {facts.USAGE_SOURCES}：{self.usage_source!r}")
