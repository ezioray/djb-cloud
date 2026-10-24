# SPDX-License-Identifier: AGPL-3.0-or-later
"""M14 错误码（只用 00-conventions §5 / spec 已登记码，不新造）。

===  ======  ================================================================
码     HTTP    语义 / 出处
===  ======  ================================================================
40001   400    请求不合法（字段 / 枚举 / 范围 / 幂等键形态 / 未知字段）
40101   401    未认证 / 鉴权未接线（fail-closed）
40301   403    权限不足 / 职责分离（审批人 = 申请人、只读角色写操作）
40401   404    资源不存在（跨租户统一 404，避免枚举）
40901   409    状态冲突 / 幂等键复用 / 同一 (object, cutoff) 已执行
42401   424    step-up 缺失或过期（≤5 分钟）
49001   400/413 导出过大（行数超上限 / 大导出配额），提示拆范围
45001   500    统一错误模型兜底（spec 已登记）
===  ======  ================================================================

错误信封 ``{"error": {type, code, message, request_id}}``；``code`` 为整数，
``message`` 不含范围数值之外的个人信息 / 签名 / 凭据。
"""
from __future__ import annotations

from typing import Any, Final

__all__ = [
    "M14Error", "BadRequest", "Unauthorized", "Forbidden", "NotFound", "Conflict",
    "StepUpRequired", "ExportTooLarge", "ServerError", "REGISTERED_CODES", "error_type_for",
]


class M14Error(Exception):
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
        for key, value in self.details.items():
            error.setdefault(key, value)
        return {"error": error}

    def __repr__(self) -> str:                       # pragma: no cover - 排查用
        return f"<{type(self).__name__} {self.status_code}/{self.code}: {self.message}>"


class BadRequest(M14Error):
    status_code = 400
    code = 40001
    error_type = "invalid_request_error"


class Unauthorized(M14Error):
    status_code = 401
    code = 40101
    error_type = "authentication_error"


class Forbidden(M14Error):
    status_code = 403
    code = 40301
    error_type = "permission_error"


class NotFound(M14Error):
    status_code = 404
    code = 40401
    error_type = "not_found_error"


class Conflict(M14Error):
    """40901：非法状态迁移 / 幂等键复用 / 同一 (object, cutoff) 已执行 / Owner 未接线。"""

    status_code = 409
    code = 40901
    error_type = "conflict_error"


class StepUpRequired(M14Error):
    status_code = 424
    code = 42401
    error_type = "authentication_error"

    def __init__(self, message: str = "敏感操作需要 5 分钟内的二次认证（step-up）") -> None:
        super().__init__(message, reason="step_up_required")


class ExportTooLarge(M14Error):
    """49001：导出 / 批量过大（Lead 裁决：统一 HTTP 400，不用 413）。"""

    status_code = 400
    code = 49001
    error_type = "invalid_request_error"

    def __init__(self, message: str, *, reason: str = "export_too_large",
                 **details: Any) -> None:
        super().__init__(message, reason=reason, **details)


class ServerError(M14Error):
    status_code = 500
    code = 45001
    error_type = "server_error"
    reason = "server_error"


#: 本模块会返回的码 → 出处（契约测试逐条反查，禁止出现未登记码）
REGISTERED_CODES: Final[dict[int, str]] = {
    40001: "00-conventions §5 400xx 通用请求错误",
    40101: "00-conventions §5 401xx 身份 / 认证",
    40301: "spec Error.code 已核实：管理接口签名 / 权限不足",
    40401: "00-conventions §5 409xx 资源不存在（M11/M14 同款 40401）",
    40901: "spec 1.2.4 已登记：并发 / 状态冲突（复算唯一作业同款）",
    42401: "spec StepUpRequired（424 / 42401，M10 CR-3 已裁决）",
    49001: "00-conventions §5 49xxx 后台 / 数据：导出过大",
    45001: "spec 1.2.2 已登记：统一错误模型兜底",
}

ERROR_TYPE_BY_STATUS: Final[dict[int, str]] = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    413: "invalid_request_error",
    424: "authentication_error",
    429: "rate_limit_error",
    500: "server_error",
}


def error_type_for(status_code: int) -> str:
    return ERROR_TYPE_BY_STATUS.get(status_code, "server_error")
