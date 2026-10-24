# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 model-sync 错误码（不发明新码：全部取自 spec 已登记通用码 / 仓库既有口径）。

===  ======  ==============================================================
码     HTTP    语义 / 出处
===  ======  ==============================================================
40001   400    请求不合法（字段缺失 / 形态非法 / 枚举越界 / 数值超限）
40101   401    未认证 / 鉴权未接线（fail-closed）
40301   403    权限不足（缺 scope ``model_sync.read`` / ``model_sync.write``）
40401   404    资源不存在（bundle id / version 查不到，不区分存在性）
40919   409    状态冲突（非 draft 不可发布 / 已回滚 / 版本回退）
50001   500    内部错误
50001   503    开关关闭 / 签名密钥缺失 / 依赖不可用（fail-closed）
===  ======  ==============================================================

约定（00-conventions §5 / spec ``Error``）：

* 信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``message`` 只供人类阅读，**不含密钥 / payload 正文 / 堆栈**；``reason`` 是机器可判短码；
* 签名失败只回 ``signature_invalid``，不回显期望值（防签名预言机）。
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "ModelSyncError", "BadRequest", "Unauthorized", "Forbidden", "NotFound", "Conflict",
    "FeatureUnavailable", "ServerError", "error_type_for",
]

TYPE_FOR_STATUS: dict[int, str] = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    500: "server_error",
    503: "server_error",
}


def error_type_for(status_code: int) -> str:
    return TYPE_FOR_STATUS.get(int(status_code), "server_error")


class ModelSyncError(Exception):
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
            "code": int(self.code),
            "message": self.message,
            "request_id": request_id,
        }
        if self.reason is not None:
            error["reason"] = self.reason
        error.update(self.details)
        return {"error": error}


class BadRequest(ModelSyncError):
    status_code = 400
    code = 40001
    error_type = "invalid_request_error"


class Unauthorized(ModelSyncError):
    """未认证 / 鉴权钩子未接线（fail-closed：默认拒绝，不静默放行）。"""

    status_code = 401
    code = 40101
    error_type = "authentication_error"


class Forbidden(ModelSyncError):
    """主体已认证但缺 scope。"""

    status_code = 403
    code = 40301
    error_type = "permission_error"


class NotFound(ModelSyncError):
    status_code = 404
    code = 40401
    error_type = "not_found_error"


class Conflict(ModelSyncError):
    status_code = 409
    code = 40919
    error_type = "conflict_error"


class FeatureUnavailable(ModelSyncError):
    """开关关闭 / 签名密钥缺失 / 依赖不可用（503 + 50001，fail-closed）。"""

    status_code = 503
    code = 50001
    error_type = "server_error"


class ServerError(ModelSyncError):
    status_code = 500
    code = 50001
    error_type = "server_error"
