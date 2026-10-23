# SPDX-License-Identifier: Apache-2.0
"""M12 错误码（规格 §4.1 / 00-conventions §5 码段 / spec 1.2.3 ``Error``）。

约定（与 M02/M04/M05/M16 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``type`` 取 spec 枚举（见 :func:`error_type_for`）；
* ``message`` 只供人类阅读，不含内部阈值 / 堆栈 / **密钥 / 签名原文 / URL 查询串**；
* 未登记的码一律不返回：下表每个码都有出处。

===  ======  ================================================================
码     HTTP    语义 / 出处
===  ======  ================================================================
40001   400    请求不合法（M12 §4.1：URL / events / 偏好字段 / 游标形态）
40101   401    未认证 / 鉴权未接线（M12 §4.1；本模块默认 fail-closed）
40401   404    通知不存在 / 跨账户不可见（M12 §4.1；不泄露存在性）
40902   409    状态冲突（M12 §4.1）：P0 不可退订 / 订阅重复 / 幂等键冲突 / 订阅数超限
50001   503    依赖不可用（库未接线 / 意料之外的持久化失败）：fail-closed，不降级放行
              —— 与 M04/M05/M16 共用同一工程兜底码，不是 M12 §4.1 的契约码
===  ======  ================================================================

``reason`` 是给客户端与日志用的**短码**（机器可判），不进 spec 的必填字段但属于
``Error.error.additionalProperties`` 允许的扩展；``message`` 永不含具体策略细节。
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "NotifyError", "InvalidArgument", "AuthUnavailable", "Unauthorized", "NotFound",
    "Conflict", "P0OptOutRejected", "DuplicateSubscription", "WebhookLimitReached",
    "IdempotencyConflict", "StoreUnavailable", "error_type_for",
]


class NotifyError(Exception):
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

    def as_dict(self) -> dict[str, Any]:
        return {"type": type(self).__name__, "code": int(self.code), "message": self.message,
                "reason": self.reason, **self.details}


# --------------------------------------------------------------------------- 400xx
class InvalidArgument(NotifyError):
    """参数 / 语义校验失败（40001）。"""

    status_code = 400
    code = "40001"
    reason = "invalid_argument"


class CursorInvalid(InvalidArgument):
    """游标不可解析（00-conventions §5：不得猜测或自行构造）。"""

    reason = "cursor_invalid"


class UrlRejected(InvalidArgument):
    """Webhook URL 不合格：非 https / 私网 / 回环 / link-local / 带凭据（§6.3）。"""

    reason = "url_rejected"


# --------------------------------------------------------------------------- 401xx
class AuthUnavailable(NotifyError):
    """鉴权未接线（合并期由 Lead 注入）：**fail-closed**，不静默放行。"""

    status_code = 401
    code = "40101"
    reason = "auth_unavailable"


class Unauthorized(NotifyError):
    status_code = 401
    code = "40101"
    reason = "unauthorized"


# --------------------------------------------------------------------------- 404xx
class NotFound(NotifyError):
    """通知 / 订阅不存在，或不属于当前账户（越权统一 404，避免枚举）。"""

    status_code = 404
    code = "40401"
    reason = "not_found"


# --------------------------------------------------------------------------- 409xx
class Conflict(NotifyError):
    """状态冲突（40902）。"""

    status_code = 409
    code = "40902"
    reason = "state_conflict"


class P0OptOutRejected(Conflict):
    """INV-01：P0 通知不可退订（写入 ``p0_opt_out=true``）。"""

    reason = "p0_opt_out_rejected"


class DuplicateSubscription(Conflict):
    """同一账户同一 URL 已有订阅（§3 UNIQUE(account_id, url)）。"""

    reason = "duplicate_subscription"


class WebhookLimitReached(Conflict):
    """订阅数超过 ``notify.webhook_max_per_account``（§8.1）。"""

    reason = "webhook_limit_reached"


class IdempotencyConflict(Conflict):
    """幂等键：同键不同载荷，或回放时无法再次给出 secret（只存哈希，INV-05）。"""

    reason = "idempotency_conflict"


# --------------------------------------------------------------------------- 5xx
class StoreUnavailable(NotifyError):
    """库未接线 / 意料之外的持久化失败（不把内部细节回给调用方）。"""

    status_code = 503
    code = "50001"
    reason = "store_unavailable"


_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    413: "invalid_request_error",
    422: "invalid_request_error",
    429: "rate_limit_error",
    500: "server_error",
    503: "server_error",
}


def error_type_for(status_code: int) -> str:
    """spec ``Error.error.type`` 枚举映射（未知状态按 server_error）。"""
    return _ERROR_TYPES.get(status_code, "server_error")
