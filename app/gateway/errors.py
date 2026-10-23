# SPDX-License-Identifier: Apache-2.0
"""M03 错误模型：M03 §4.4 错误映射表 + spec ``Error`` 信封（唯一出口）。

口径：

* **信封** ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**，
  ``type`` 取 spec 枚举（00-conventions §5 / spec ``Error``）；
  ``reason`` 只给粗粒度原因码（``rate_limited`` / ``quota_exceeded`` /
  ``account_restricted`` / ``policy_blocked``），**不含**规则、阈值、名单（INV-M03-05）。
* **只返回已登记码**：spec ``Error.code`` 明确「未登记的码一律不返回」。本表的
  ``registered`` 字段标注该码是否已在 ``spec/openapi.yaml`` 登记；未登记的码
  （``42901/42902/50901/50902/50903/44101/45201/45202/45203/45001`` 等）已在
  **M03 §4.4 本模块登记**，但 spec 码段表尚未收录 → 交付证据里作为 CR 上报 Lead
  （``PENDING_SPEC_CODES``），不在此处静默吞掉。
* **429 / 503 必须带 Retry-After**（INV-M03-05）；403 / 429 只给粗粒度原因。
* **42901 vs 40103 口径冲突**（M03 §4.4 把 40103 给「IP 不在白名单」，spec 1.2.1 已把
  40103 登记为 M01「刷新令牌无效/已轮换/过期」）→ 本模块**不返回 40103**，Key 层策略
  拒绝（含 IP 白名单）统一 ``403 / 40102``，理由写 ``policy_blocked``。已在证据登记待 Lead 裁决。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("djb.gateway.errors")

__all__ = [
    "ErrorSpec", "ERROR_SPECS", "PENDING_SPEC_CODES", "GatewayError", "spec", "error_body",
    "server_error", "M03_SPEC_SECTION",
]

M03_SPEC_SECTION = "M03 §4.4"
"""错误映射表出处（product/v4/modules/M03-gateway-protocol.md §4.4）。"""


@dataclass(frozen=True)
class ErrorSpec:
    """一条对外错误口径（HTTP / 数字码 / spec type / 粗粒度 reason / 计费后果）。"""

    key: str
    http: int
    code: int
    type: str
    reason: str | None
    billing: str
    registered: bool
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"key": self.key, "http": self.http, "code": self.code, "type": self.type,
                "reason": self.reason, "billing": self.billing,
                "registered": self.registered, "note": self.note}


#: spec ``Error.type`` 枚举（只加不改）
ERROR_TYPES: tuple[str, ...] = ("invalid_request_error", "authentication_error",
                               "permission_error", "rate_limit_error", "not_found_error",
                               "conflict_error", "protocol_error", "server_error",
                               "upstream_error")


def _spec(key: str, http: int, code: int, type_: str, reason: str | None, billing: str,
          *, registered: bool, note: str = "") -> ErrorSpec:
    if type_ not in ERROR_TYPES:
        raise ValueError(f"{key}: type 不在 spec 枚举内：{type_!r}")
    return ErrorSpec(key=key, http=http, code=code, type=type_, reason=reason,
                     billing=billing, registered=registered, note=note)


#: M03 §4.4 错误映射（顺序与规格表一致；「计费」列 = 是否计费）
ERROR_SPECS: dict[str, ErrorSpec] = {item.key: item for item in (
    # ---- Key 缺失 / 无效 / 禁用过期 / IP 不在白名单（401 / 403）
    _spec("key_missing", 401, 40101, "authentication_error", None, "不计",
          registered=True, note="Authorization 缺失或不是 Bearer 形态（M01 ApiKeyInvalid 同码）"),
    _spec("key_invalid", 401, 40101, "authentication_error", None, "不计",
          registered=True, note="Key 哈希未命中 / 撤销 / 过期（M01 verify_api_key）"),
    _spec("key_policy_denied", 403, 40102, "permission_error", "policy_blocked", "不计",
          registered=True, note="Key 层策略拒绝：停用 / IP 不在白名单。"
                                "M03 §4.4 原写 40103，与 spec 1.2.1（M01 刷新令牌）冲突 → 不返回 40103"),
    # ---- 余额不足 / 内容拦截 / 特性未开放 / 账户只读（402 / 403）
    _spec("insufficient_balance", 402, 40201, "permission_error", "quota_exceeded", "不计",
          registered=True, note="spec 1.2.0 新增 402 PaymentRequired"),
    _spec("content_blocked", 403, 40302, "permission_error", "policy_blocked", "不计",
          registered=False, note="内容拦截（M03 §4.4；spec 码段表待补）"),
    _spec("feature_disabled", 403, 40303, "permission_error", "policy_blocked", "不计",
          registered=False, note="特性未开放（M03 §4.4；spec 码段表待补）"),
    _spec("account_readonly", 403, 40304, "permission_error", "account_restricted", "不计",
          registered=True, note="frozen / closing 只读（M01 AccountReadOnly 同码）"),
    # ---- 参数 / 请求体超限（400 / 413）
    _spec("bad_request", 400, 40001, "invalid_request_error", None, "不计",
          registered=False, note="参数不合法（M03 §4.4；40001 属通用码，spec 正文以 400 响应表达）"),
    _spec("payload_too_large", 413, 40013, "invalid_request_error", None, "不计",
          registered=True, note="spec 1.2.0：HTTP 413 专用码 40013"),
    # ---- 状态冲突（409）
    _spec("conflict", 409, 40919, "conflict_error", None, "不计",
          registered=True, note="spec 1.2.0：HTTP 409 通用码 40919（幂等键同键不同载荷）"),
    # ---- 无可用节点 / 上游超时 / 上游异常（503 / 504 / 502）
    _spec("no_node", 503, 50901, "upstream_error", None, "不计",
          registered=False, note="M04 决策为空（M03 §4.4；spec 码段表待补 509xx）"),
    _spec("upstream_timeout", 504, 50902, "upstream_error", None, "不计",
          registered=False, note="上游超时（首字节前 ≤2 次尝试）"),
    _spec("upstream_error", 502, 50903, "upstream_error", None, "不计",
          registered=False, note="上游异常 / 5xx"),
    # ---- QPS / 每日花费上限（429）
    _spec("rate_limited", 429, 42901, "rate_limit_error", "rate_limited", "不计",
          registered=False, note="单 Key QPS 超限（带 Retry-After + X-DJB-RateLimit-*）"),
    _spec("daily_spend_cap", 429, 42902, "rate_limit_error", "quota_exceeded", "不计",
          registered=False, note="每日花费上限（M03 §4.4 / M04 quota 同码）"),
    # ---- 流式中断（441，T3）
    _spec("stream_interrupted", 441, 44101, "upstream_error", None, "按上游实际",
          registered=False, note="SSE 中断：usage_source=estimated（T3 使用）"),
    # ---- 慢任务（408 / 202 / 403，T4）
    _spec("eta_exceeded", 408, 45201, "upstream_error", None, "不计",
          registered=False, note="慢任务超 ETA（T4）"),
    _spec("cost_confirm_required", 202, 45202, "conflict_error", None, "确认后计",
          registered=False, note="预估成本 >10 USD 先确认（T4；语义是 202 非错误）"),
    _spec("group_admission", 403, 45203, "permission_error", "policy_blocked", "不计",
          registered=False, note="组网准入不足（T4）"),
    # ---- 兜底（500 / 503）
    _spec("error_model_fallback", 500, 45001, "server_error", None, "不计",
          registered=False, note="统一错误模型自检失败兜底（M03 §4.4；spec 码段表待补 45001）"),
    _spec("service_unavailable", 503, 45001, "server_error", None, "不计",
          registered=False, note="依赖不可用 fail-closed（M03 §7「M01 鉴权超时 → 503」；"
                                "M03 §4.4 未给专用码 → 复用兜底 45001 + reason=unavailable"),
)}

PENDING_SPEC_CODES: tuple[int, ...] = tuple(sorted(
    {item.code for item in ERROR_SPECS.values() if not item.registered}))
"""已在 M03 §4.4 登记、但 spec 码段表尚未收录的码（交付证据里作为 CR 上报）。"""


def spec(key: str) -> ErrorSpec:
    """按 key 取错误口径；未登记 key 直接抛（防止实现里出现「事实上的契约」）。"""
    try:
        return ERROR_SPECS[key]
    except KeyError as exc:                                   # pragma: no cover - 编程错误
        raise KeyError(f"未登记的错误 key：{key!r}（先补 M03 §4.4 与 errors.ERROR_SPECS）") \
            from exc


class GatewayError(Exception):
    """对外错误（HTTP 状态 + 数字码 + 信封字段），由 router 统一转成 ``Error`` 响应。

    ``message`` 只供人类阅读，不含内部堆栈 / SQL / 规则细节 / 凭据（00-conventions §9）。
    """

    def __init__(self, key: str, message: str, *, reason: str | None = None,
                 retry_after_s: int | None = None, details: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None,
                 upstream_error_class: str | None = None) -> None:
        self.spec = spec(key)
        super().__init__(message)
        self.key = key
        self.message = message
        self.reason = reason if reason is not None else self.spec.reason
        self.retry_after_s = retry_after_s
        self.details = dict(details or {})
        self.headers = {key_: str(value) for key_, value in (headers or {}).items()}
        self.upstream_error_class = upstream_error_class

    # ---- 便捷只读属性
    @property
    def http_status(self) -> int:
        return self.spec.http

    @property
    def code(self) -> int:
        return self.spec.code

    @property
    def type(self) -> str:
        return self.spec.type

    def with_headers(self, **headers: str) -> "GatewayError":
        """补挂响应头（限流三件套 / Retry-After），返回自身便于链式抛出。"""
        for key_, value in headers.items():
            if value is not None:
                self.headers[key_] = str(value)
        return self

    def __repr__(self) -> str:                                # pragma: no cover - 调试
        return f"GatewayError({self.key}, http={self.http_status}, code={self.code})"


def error_body(exc: GatewayError, request_id: str) -> dict[str, Any]:
    """构造 spec ``Error`` 信封（``type`` / ``code`` / ``message`` / ``request_id`` 必填）。"""
    error: dict[str, Any] = {
        "type": exc.type,
        "code": int(exc.code),
        "message": exc.message,
        "request_id": request_id,
    }
    if exc.reason:
        error["reason"] = exc.reason
    if exc.retry_after_s is not None:
        error["retry_after"] = int(exc.retry_after_s)
    # details 只放已核过的对外字段（attempts / limit_kind / …），不塞内部结构
    for key_, value in exc.details.items():
        if key_ in {"reason", "retry_after"}:
            continue
        error[key_] = value
    return {"error": error}


def server_error(request_id: str, *, detail: str | None = None) -> GatewayError:
    """未预期异常 → 500 / 45001（兜底）；detail 只进日志，不进响应。"""
    if detail:
        log.error("gateway.unexpected", extra={"request_id": request_id, "detail": detail})
    return GatewayError("error_model_fallback", "服务暂时不可用，请稍后重试")
