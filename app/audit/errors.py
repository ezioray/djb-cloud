# SPDX-License-Identifier: AGPL-3.0-or-later
"""M16 审计链错误码（M16 §4.1 / 00-conventions §5 码段 / spec 1.2.2 ``Error``）。

约定（与 M02/M04/M05/M10 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``type`` 取 spec 枚举（见 :func:`error_type_for`）；
* ``message`` 只供人类阅读：不含密钥 / 正文 / 内部拓扑；
* 未登记的码一律不返回，下表每个码都有出处。

===  ======  ================================================================
码     HTTP    语义 / 出处
===  ======  ================================================================
40001   400    请求不合法（M16 §4.1 audit append / verify：字段缺失、枚举非法、未知算法）
40101   401    未认证 / 鉴权未接线（M16 §4.1「内部接口 mTLS + 服务令牌」；本模块默认 fail-closed）
40301   403    服务身份无权写审计（M16 §4.1 audit append 40301；模块审计追加只验服务身份）
40901   409    断链 / 幂等冲突 / 自批自核（M16 §4.1「40901 锁定」+ INV-M16-02）
42301   423    审计链锁定：HMAC 密钥缺失 / 未激活 → 拒绝写入（M16 §4.1 42301，fail-closed）
50001   503    依赖不可用（数据库 / 密钥服务）：服务端未就绪，不降级放行
===  ======  ================================================================
"""
from __future__ import annotations

from typing import Any

_ERROR_TYPES: dict[int, str] = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    422: "invalid_request_error",
    423: "locked_error",
    424: "step_up_required",
    429: "rate_limit_error",
    500: "server_error",
    503: "server_error",
}


def error_type_for(status_code: int) -> str:
    """spec ``Error.error.type`` 枚举映射（未知状态按 server_error）。"""
    return _ERROR_TYPES.get(status_code, "server_error")


class AuditError(Exception):
    """领域错误基类：``status_code`` / ``code`` / ``reason`` 直接进错误信封。"""

    status_code = 400
    code = "40001"
    reason = "invalid_request"

    def __init__(self, message: str, *, reason: str | None = None, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        if reason is not None:
            self.reason = reason
        self.details = details

    def as_dict(self, request_id: str | None = None) -> dict[str, Any]:
        payload = {"type": error_type_for(self.status_code), "code": int(self.code),
                   "message": self.message, "reason": self.reason}
        if request_id:
            payload["request_id"] = request_id
        for key, value in self.details.items():
            if key != "reason":
                payload[key] = value
        return payload

    def __repr__(self) -> str:                      # pragma: no cover - 排障用
        return f"{type(self).__name__}(status={self.status_code}, code={self.code}, reason={self.reason})"


# --------------------------------------------------------------------------- 400xx
class InvalidArgument(AuditError):
    """参数 / 语义校验失败（40001）：缺字段、枚举非法、算法降级、幂等键形态。"""

    status_code = 400
    code = "40001"
    reason = "invalid_argument"


# --------------------------------------------------------------------------- 401xx
class Unauthorized(AuditError):
    """未认证 / 鉴权未接线（40101）：内部接口必须带服务身份，默认 fail-closed。"""

    status_code = 401
    code = "40101"
    reason = "unauthenticated"


# --------------------------------------------------------------------------- 403xx
class Forbidden(AuditError):
    """服务身份无权写审计（40301）。"""

    status_code = 403
    code = "40301"
    reason = "forbidden"


# --------------------------------------------------------------------------- 409xx
class Conflict(AuditError):
    """断链 / 幂等冲突 / 自批自核（40901）。"""

    status_code = 409
    code = "40901"
    reason = "conflict"


# --------------------------------------------------------------------------- 423
class ChainLocked(AuditError):
    """审计链锁定（42301）：HMAC 密钥缺失 / 未激活 / 校验进行中 → 拒绝写入（fail-closed）。"""

    status_code = 423
    code = "42301"
    reason = "audit_chain_locked"


# --------------------------------------------------------------------------- 5xx
class ServiceUnavailable(AuditError):
    """依赖不可用（503 / 50001）：数据库或密钥服务不可用，不降级放行。"""

    status_code = 503
    code = "50001"
    reason = "service_unavailable"


__all__ = [
    "AuditError",
    "InvalidArgument",
    "Unauthorized",
    "Forbidden",
    "Conflict",
    "ChainLocked",
    "ServiceUnavailable",
    "error_type_for",
]
