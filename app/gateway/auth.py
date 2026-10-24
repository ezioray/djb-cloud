# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bearer Key 鉴权编排（M03 §6 流程 1 的第 2 步）。

分工：

* **本模块**只管「从请求里取 Key → 交给 M01 provider → 归一成 Principal → Key 层策略
  （IP 白名单 / 账户可写）→ 404 化越权」这些**网关侧**动作；
* **Key 校验本体**（哈希、状态、过期、轮换重叠、配额快照）由 M01 ``verify_api_key``
  负责，经 :func:`app.gateway.providers.authenticate` 注入；**网关不复制**哈希逻辑。

错误口径（M03 §4.4 + spec）：

| 情形 | HTTP | 码 |
| --- | --- | --- |
| ``Authorization`` 缺失 / 不是 ``Bearer <token>`` | 401 | 40101 |
| Key 哈希未命中 / 撤销 / 过期（M01 抛出） | 401 | 40101 |
| 账户 frozen / closing（只读） | 403 | 40304 |
| Key 停用 / IP 不在白名单 | 403 | 40102（口径收敛见 :mod:`app.gateway.errors`） |
| 鉴权依赖不可用 | 503 | 45001 + ``Retry-After``（fail-closed） |

``X-Request-Id`` / ``X-Forwarded-For`` 只做**透传与日志**；客户端 IP 默认取
``request.client.host``，只有当部署层明确给出受信代理时才由 Lead 注入 ``X-Forwarded-For``
解析（见 ``WIRING.md``），避免伪造来源绕过白名单。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from . import errors, facts, models, providers

__all__ = ["extract_bearer", "header_value", "principal_from_headers", "authenticate_request",
           "assert_ip_allowed", "assert_writable"]


def header_value(headers: Mapping[str, str], name: str) -> str | None:
    """大小写无关地取头（Starlette / dict 两种容器都吃；HTTP 头本身不区分大小写）。"""
    if name in headers:
        return headers[name]
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return value
    return None


def extract_bearer(header_value: str | None) -> str:
    """从 ``Authorization`` 取 Key；缺失 / 形态不对 → 401 / 40101（不回显任何内容）。"""
    raw = (header_value or "").strip()
    if not raw:
        raise errors.GatewayError("key_missing", "缺少 Authorization: Bearer <API Key>")
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != facts.BEARER_SCHEME.lower():
        raise errors.GatewayError("key_missing", "Authorization 必须是 Bearer 形态")
    token = token.strip()
    if not token:
        raise errors.GatewayError("key_missing", "Authorization 缺少 Key")
    if len(token) < 8 or len(token) > 512:
        # 长度异常按无效处理：不回显、不提示格式细节（防探测）
        raise errors.GatewayError("key_invalid", "Key 无效")
    return token


def assert_ip_allowed(principal: models.Principal, client_ip: str | None) -> None:
    """Key 级 IP 白名单（空 = 不限制）；不在名单 → 403 / 40102。"""
    if models.ip_allowed(client_ip, principal.ip_allowlist):
        return
    raise errors.GatewayError("key_policy_denied", "来源地址不在该 Key 的允许范围内",
                              reason="policy_blocked")


def assert_writable(principal: models.Principal) -> None:
    """账户五态闸门（M01 §3）：frozen / closing → 40304；其余非 normal → 40001。"""
    if principal.writable:
        return
    if principal.account_state in {"frozen", "closing"}:
        raise errors.GatewayError("account_readonly", "账户当前只读，无法发起计费调用",
                                  reason="account_restricted")
    raise errors.GatewayError("bad_request", f"账户状态为 {principal.account_state}，禁止调用",
                              reason="account_not_verified")


def authenticate_request(header_value: str | None, *, now: datetime | None,
                         client_ip: str | None, trace_id: str,
                         provider: Any = None) -> models.Principal:
    """完整鉴权链：取 Key → M01 校验（注入）→ IP 白名单 → 账户可写。

    ``provider`` 只给测试注入用；缺省走 :mod:`app.gateway.providers` 的全局接线。
    """
    raw_key = extract_bearer(header_value)
    if provider is None:
        principal = providers.authenticate(raw_key, now=now, client_ip=client_ip,
                                           trace_id=trace_id)
    else:
        principal = models.coerce_principal(
            provider(raw_key, now=now, client_ip=client_ip, trace_id=trace_id))
    assert_ip_allowed(principal, client_ip)
    assert_writable(principal)
    return principal


def principal_from_headers(headers: Mapping[str, str], *, now: datetime | None = None,
                          client_ip: str | None = None, trace_id: str = "",
                          provider: Any = None) -> models.Principal:
    """便捷入口（HTTP 头 → Principal），router 与测试共用。"""
    return authenticate_request(header_value(headers, facts.AUTH_HEADER), now=now,
                                client_ip=client_ip, trace_id=trace_id, provider=provider)
