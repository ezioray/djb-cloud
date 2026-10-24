# SPDX-License-Identifier: AGPL-3.0-or-later
"""M09 错误码（spec 1.2.3 已登记码 · 00-conventions §5 · M09 §4.1）。

约定（与 M05/M10/M16 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``type`` 取 spec ``Error`` 枚举；``message`` 只供人类阅读，不含内部阈值 / 堆栈 / 凭据；
* **未登记的码一律不返回**：下表每个码都能在 spec 1.2.3 或 04 码段里找到出处。

===  ======  ================================================================
码     HTTP    语义 / 出处
===  ======  ================================================================
40001   400    请求不合法（字段缺失 / 形态非法 / 幂等键形态）
40101   401    未认证 / 鉴权未接线（fail-closed）
47010   403    角色或 scope 不足（spec 1.2.2 登记：M10「角色不足 / 越权」）
49206   403    出款前凭证校验不可用（M09 §4.1 / §7：fail-closed，M08 必须拒付）
40401   404    资源不存在（spec 1.2.2 通用码；差异台账等无更细码时）
49201   404    对账批次不存在（M09 §4.1）
49210   404    报表周期非法或无数据（M09 §4.1）
49211   404    渲染件不存在（M09 §4.1；T4 落地，码先登记）
49212   404    凭证不存在（M09 §4.1）
40902   ——     （M12 专用，本模块不用）
40919   409    状态冲突（spec `Conflict`：无更细码时用通用 40919）
49202   409    存在未结 P0/P1 不得签核（INV-03 / I-17）
49203   409    批次已签核或已关闭
49204   409    差异状态不允许该处置
49205   409    同一期间 + batch_hash 已有 valid 凭证
42401   424    二次认证（step-up）缺失或过期
45001   500    统一错误模型兜底（spec 1.2.2 登记）
===  ======  ================================================================

**产品文档与冻结 spec 的一处口径差异（已上报 Lead，见证据「遗留」）**：
M09 §9 A6 写「复核人 = 制单人时提交 **49212** 拒绝」，但 spec 1.2.3 把 ``49212`` 登记为
「凭证不存在（404）」。契约优先 → 复核人 = 制单人返回 ``409 + 40919``（状态冲突），
``49212`` 只用于凭证不存在。
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "ReconError", "BadRequest", "Unauthorized", "Forbidden", "StepUpRequired",
    "NotFound", "RunNotFound", "AttestationNotFound", "ReportUnavailable", "RenderNotFound",
    "Conflict", "PendingDifferencesBlockSignOff", "AlreadySignedOff", "ExceptionStateConflict",
    "AttestationConflict", "AttestationValidationUnavailable", "ServiceUnavailable",
    "ERROR_TYPE_BY_STATUS",
]


class ReconError(Exception):
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
        # details：结构化提示（如 pending / by_severity / field），只放非敏感信息
        for key, value in self.details.items():
            error.setdefault(key, value)
        return {"error": error}

    def __repr__(self) -> str:  # pragma: no cover - 便于排查
        return f"<{type(self).__name__} {self.status_code}/{self.code}: {self.message}>"


# ───────────────────────────────────────────────────────────── 4xx（请求 / 身份）
class BadRequest(ReconError):
    status_code = 400
    code = 40001
    error_type = "invalid_request_error"


class Unauthorized(ReconError):
    status_code = 401
    code = 40101
    error_type = "authentication_error"


class Forbidden(ReconError):
    status_code = 403
    code = 47010
    error_type = "permission_error"


class StepUpRequired(ReconError):
    """step-up 缺失 / 过期（spec `StepUpRequired`：424 + 42401）。"""

    status_code = 424
    code = 42401
    error_type = "authentication_error"

    def __init__(self, message: str = "敏感操作需要 5 分钟内的二次认证（step-up）") -> None:
        super().__init__(message, reason="step_up_required")


class NotFound(ReconError):
    status_code = 404
    code = 40401
    error_type = "not_found_error"


class RunNotFound(ReconError):
    """对账批次不存在（跨租户同样按不存在处理，不泄露存在性）。"""

    status_code = 404
    code = 49201
    error_type = "not_found_error"


class AttestationNotFound(ReconError):
    status_code = 404
    code = 49212
    error_type = "not_found_error"


class ReportUnavailable(ReconError):
    """报表周期非法或无数据（spec 1.2.3：49210 / 404）。"""

    status_code = 404
    code = 49210
    error_type = "not_found_error"


class RenderNotFound(ReconError):
    """渲染件不存在（T4 落地；码先登记，避免 T4 再改契约）。"""

    status_code = 404
    code = 49211
    error_type = "not_found_error"


class Conflict(ReconError):
    status_code = 409
    code = 40919
    error_type = "conflict_error"


class PendingDifferencesBlockSignOff(ReconError):
    """存在未结 P0/P1（INV-03 / I-17）：不得签核。"""

    status_code = 409
    code = 49202
    error_type = "conflict_error"

    def __init__(self, message: str, *, pending: int, by_severity: dict[str, int]) -> None:
        super().__init__(message, reason="pending_p0_p1", pending=pending,
                         by_severity=by_severity)


class AlreadySignedOff(ReconError):
    """批次已签核或已关闭：签核后只读，拒绝再次签核（M09 §3.2 / spec 49203）。"""

    status_code = 409
    code = 49203
    error_type = "conflict_error"


class ExceptionStateConflict(ReconError):
    """差异状态不允许该处置（已关闭不可重开 / 缺 journal_id / 缺原因码）。"""

    status_code = 409
    code = 49204
    error_type = "conflict_error"


class AttestationConflict(ReconError):
    """同一 (period_start, period_end, batch_hash) 已有 valid 凭证（INV-05）。"""

    status_code = 409
    code = 49205
    error_type = "conflict_error"


class AttestationValidationUnavailable(ReconError):
    """出款前校验不可用（服务主体 scope 不足 / 依赖不可用）：fail-closed，M08 必须拒付。"""

    status_code = 403
    code = 49206
    error_type = "permission_error"

    def __init__(self, message: str = "出款前凭证校验不可用（fail-closed）：拒绝出款",
                 *, reason: str = "attestation_validation_unavailable") -> None:
        super().__init__(message, reason=reason)


class ServiceUnavailable(ReconError):
    """数据库 / 依赖不可用（spec 登记 45001 兜底）。"""

    status_code = 500
    code = 45001
    error_type = "server_error"


#: 兜底映射（异常没有自带码时按 HTTP 状态挑一个**已登记**的通用码）
ERROR_TYPE_BY_STATUS: dict[int, str] = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    424: "authentication_error",
    500: "server_error",
}
