# SPDX-License-Identifier: Apache-2.0
"""M04 错误码（M04 §4.1 / §7 失败矩阵 / 00-conventions §5 码段）。

约定（00-conventions §5 + spec ``Error``）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``type`` 取 spec 枚举（见 :func:`error_type_for`）；
* ``message`` 只供人类阅读，不含内部权重 / 阈值 / 堆栈 / 凭据；
* **未登记的码一律不返回**：本文件出现的码都有出处（逐条标注）。

===  ======  ==========================================================
码     HTTP    语义 / 出处
===  ======  ==========================================================
40001  400     请求不合法（M04 §4.1；含金额超精度 INV-13、幂等键形态）
40101  401     未认证 / 鉴权未接线（M02/M01 同族；本模块默认 fail-closed）
40303  403     通道关闭 / 无权（M04 §4.1 route 的 40303）
40401  404     对象不存在 / 跨租户不可见（M04 §4.1；不泄露存在性）
40901  409     复算作业并发冲突（spec ReplayRequest「并发 1，重复提交 40901」）
40902  409     前置状态不满足（quote / booking 已 consumed 或已 expired）
40919  409     幂等冲突：同键不同载荷（00-conventions §6.1 / spec 1.2.0）
42901  429     限流（M04 §4.1；报价 / 出价写入过频）
42902  429     每日花费上限（M04 §4.1 / product §6.3）
45001  503     无可用节点（M04 §4.1 / §7；必须带原因 + 三个可选动作，INV-06）
50001  503     决策日志不可写 → 熔断新决策（INV-11；503 由 §7 规定）
===  ======  ==========================================================

**未使用 422xx 的原因**：M04 §4.1 为 quotes / bids 预留了 ``422xx`` 段，但 04-api-contracts
的码段表尚未登记具体码值；按「未登记不得返回」的硬规则，T1/T2 的参数校验统一用 ``40001``
（与 M02 同款），422xx 待 04 登记后再启用（已在证据文件「未做项」登记）。
"""
from __future__ import annotations

from typing import Any


class SchedulingError(Exception):
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
class InvalidArgument(SchedulingError):
    """参数 / 语义校验失败（40001）。"""

    status_code = 400
    code = "40001"
    reason = "invalid_argument"


class AmountPrecisionRejected(InvalidArgument):
    """金额超过币种精度（INV-13：超精度直接拒绝，不四舍五入）。"""

    reason = "amount_precision"


class IntervalInvalid(InvalidArgument):
    """区间非法（INV-01：上界 < 下界）。"""

    reason = "interval_invalid"


class UnsupportedCurrency(InvalidArgument):
    """S1 仅 USD（INV-13）。"""

    reason = "unsupported_currency"


# --------------------------------------------------------------------------- 401xx / 403xx
class AuthUnavailable(SchedulingError):
    """鉴权未接线（合并期由 Lead 注入）：**fail-closed**，不静默放行。"""

    status_code = 401
    code = "40101"
    reason = "auth_unavailable"


class Unauthorized(SchedulingError):
    status_code = 401
    code = "40101"
    reason = "unauthorized"


class Forbidden(SchedulingError):
    """通道关闭 / 无权访问该资源（40303；M04 §4.1）。"""

    status_code = 403
    code = "40303"
    reason = "forbidden"


class StepUpRequired(SchedulingError):
    """管理面高危动作二次认证缺失或过期（424 / 42401）。"""

    status_code = 424
    code = "42401"
    reason = "step_up_required"


# --------------------------------------------------------------------------- 404xx
class NotFound(SchedulingError):
    status_code = 404
    code = "40401"
    reason = "not_found"


# --------------------------------------------------------------------------- 409xx
class ReplayBusy(SchedulingError):
    """复算作业并发 1（spec ReplayRequest：重复提交 409 + 40901）。"""

    status_code = 409
    code = "40901"
    reason = "replay_busy"


class StateConflict(SchedulingError):
    """前置状态不满足（40902）：quote / booking 已 consumed / expired，不可回退（M04 §3）。"""

    status_code = 409
    code = "40902"
    reason = "state_conflict"


class IdempotencyConflict(SchedulingError):
    """同键不同载荷（40919）。"""

    status_code = 409
    code = "40919"
    reason = "idempotency_conflict"


# --------------------------------------------------------------------------- 429xx
class RateLimited(SchedulingError):
    """报价 / 出价写入过频（42901；附 ``retry_after_s``）。"""

    status_code = 429
    code = "42901"
    reason = "rate_limited"


class SpendCapExceeded(SchedulingError):
    """每日花费上限（42902；M04 §4.1 / product §6.3）。"""

    status_code = 429
    code = "42902"
    reason = "spend_cap_exceeded"


# --------------------------------------------------------------------------- 45xxx
class NoRoute(SchedulingError):
    """无可用节点（45001，503）：必须带原因 + 三个可选动作（INV-06）。

    ``details`` 固定包含 ``reason_codes``、``actions``（三个）、``eliminated``（粗粒度）。
    """

    status_code = 503
    code = "45001"
    reason = "no_route"


# --------------------------------------------------------------------------- 5xx
class DecisionLogUnavailable(SchedulingError):
    """决策日志写失败 → **熔断新决策**并 P0（INV-11 / §7；禁止「不记录继续」）。"""

    status_code = 503
    code = "50001"
    reason = "decision_log_unavailable"


_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    422: "invalid_request_error",
    424: "permission_error",
    426: "protocol_error",
    429: "rate_limit_error",
    500: "server_error",
    503: "service_unavailable",
}


def error_type_for(status_code: int) -> str:
    """spec ``Error.error.type`` 枚举映射（未知状态按 server_error）。"""
    return _ERROR_TYPES.get(status_code, "server_error")


__all__ = [
    "SchedulingError", "InvalidArgument", "AmountPrecisionRejected", "IntervalInvalid",
    "UnsupportedCurrency", "AuthUnavailable", "Unauthorized", "Forbidden", "StepUpRequired",
    "NotFound", "ReplayBusy", "StateConflict", "IdempotencyConflict", "RateLimited",
    "SpendCapExceeded", "NoRoute", "DecisionLogUnavailable", "error_type_for",
]
