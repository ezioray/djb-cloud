# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 冻结段错误码（不发明新码：全部取自 spec 1.2.x 已登记通用码 / 仓库既有口径）。

===  ======  ==============================================================
码     HTTP    语义 / 出处
===  ======  ==============================================================
40001   400    请求不合法（字段缺失 / 形态非法 / 枚举越界 / 金额超限）
40101   401    未认证 / 鉴权未接线（fail-closed）
40301   403    权限不足（缺 scope；I3/I4 解除需要 integrity:release:high）
40401   404    资源不存在（hold id 查不到；跨节点不区分，避免枚举）
40919   409    状态冲突（降级 / 同级重复 / 已过期不可释放 / 复核人数不足）
50001   503    开关关闭 / 依赖不可用（fail-closed；**不复用 50903**——那是 spec 的 502 upstream_error）
===  ======  ==============================================================

约定（00-conventions §5 / spec ``Error``）：

* 信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``message`` 只供人类阅读，不含阈值 / 名单 / PII / 堆栈；``reason`` 是机器可判短码；
* 冻结是**风控处置**：拒绝时只给粗粒度原因，不回显内部字段。
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "IntegrityError", "BadRequest", "Unauthorized", "Forbidden", "NotFound", "Conflict",
    "FeatureUnavailable", "ServerError", "error_type_for",
]

TYPE_FOR_STATUS: dict[int, str] = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    503: "server_error",
}


def error_type_for(status_code: int) -> str:
    return TYPE_FOR_STATUS.get(int(status_code), "server_error")


class IntegrityError(Exception):
    """领域错误基类：``status_code`` / ``code`` / ``error_type`` 直接进错误信封。"""

    status_code = 400
    code = 40001
    error_type = "invalid_request_error"
    reason: str | None = None

    def __init__(self, message: str, *, reason: str | None = None, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        if reason is not None:
            self.reason = reason
        self.details = {key: value for key, value in details.items() if value is not None}

    def as_envelope(self, request_id: str) -> dict[str, Any]:
        error: dict[str, Any] = {
            "type": self.error_type,
            "code": self.code,
            "message": self.message,
            "request_id": request_id,
        }
        if self.reason:
            error["reason"] = self.reason
        if self.details:
            error["details"] = dict(self.details)
        return {"error": error}

    def __repr__(self) -> str:  # pragma: no cover - 便于排查
        return f"<{type(self).__name__} {self.status_code}/{self.code}: {self.message}>"


class BadRequest(IntegrityError):
    status_code = 400
    code = 40001
    error_type = "invalid_request_error"
    reason = "invalid_argument"


class Unauthorized(IntegrityError):
    status_code = 401
    code = 40101
    error_type = "authentication_error"
    reason = "unauthorized"


class Forbidden(IntegrityError):
    status_code = 403
    code = 40301
    error_type = "permission_error"
    reason = "forbidden"


class NotFound(IntegrityError):
    status_code = 404
    code = 40401
    error_type = "not_found_error"
    reason = "not_found"


class Conflict(IntegrityError):
    """状态冲突（40919）：降级 / 同级重复 / 已过期释放 / 复核人数不足。"""

    status_code = 409
    code = 40919
    error_type = "conflict_error"
    reason = "conflict"


class FeatureUnavailable(IntegrityError):
    """开关关闭或依赖不可用（503 / 50001）——fail-closed，不静默放行。"""

    status_code = 503
    code = 50001
    error_type = "server_error"
    reason = "feature_disabled"


class ServerError(IntegrityError):
    """兜底（500 / 50001）：不把内部细节回给调用方。"""

    status_code = 500
    code = 50001
    error_type = "server_error"
    reason = "server_error"
