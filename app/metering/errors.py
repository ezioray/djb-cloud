# SPDX-License-Identifier: Apache-2.0
"""M05 错误码（M05 §4.1 / §7 失败矩阵 / 00-conventions §5 码段 / spec 1.2.0 ``Error``）。

约定（与 M02/M04 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``type`` 取 spec 枚举（见 :func:`error_type_for`）；
* ``message`` 只供人类阅读，不含内部阈值 / 堆栈 / **密钥 / 签名原文**；
* 未登记的码一律不返回：下表每个码都有出处。

===  ======  ================================================================
码     HTTP    语义 / 出处
===  ======  ================================================================
40001   400    请求不合法（M05 §4.1：字段缺失 / 金额超精度 / 幂等键形态 / 未知节点）
40013   413    请求体超上限（HTTP 413 专用码；spec 1.2.0 登记；收据批 ≤500 条/次）
40101   401    未认证 / 鉴权未接线（M05 §4.1「401xx」；本模块默认 fail-closed）
40303   403    无权代表该节点提交（00-conventions §5 的 403xx 段；M04 §4.1 同码）
40401   404    收据不存在 / 跨节点不可见（M05 §4.1；不泄露存在性）
46001   422    收据签名不匹配（M05 §4.1 / 00-conventions §5「46xxx 计量收据」；spec 已登记）
50001   500    服务端未就绪（签名密钥未接线 / 两侧密钥相同）：fail-closed，不降级放行
===  ======  ================================================================

**逐条受理的拒收码**（写进 ``receipts.rejected_code``，不进 HTTP 信封）：
签名为 46001；字段 / 金额 / 窗口 / 重复请求等契约问题为 40001（M05 §7）。
"""
from __future__ import annotations

from typing import Any


class MeteringError(Exception):
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
class InvalidArgument(MeteringError):
    """参数 / 语义校验失败（40001）。"""

    status_code = 400
    code = "40001"
    reason = "invalid_argument"


class AmountPrecisionRejected(InvalidArgument):
    """金额 / 单价超过币种精度（INV-05：直接拒绝，不四舍五入）。"""

    reason = "amount_precision"


class UnsupportedCurrency(InvalidArgument):
    """S1 只收 USD 计价（00-conventions §3 / 03-facts §6）。"""

    reason = "unsupported_currency"


class BatchTooLarge(InvalidArgument):
    """批量超过 500 条（M05 §8.2 / spec ``maxItems``）→ HTTP 413 + 40013。"""

    status_code = 413
    code = "40013"
    reason = "batch_too_large"


class ReceiptWindowExceeded(InvalidArgument):
    """收据超出受理窗口（M05 §8.1 ``metering.receipt_late_h``，默认 24h）。"""

    reason = "receipt_window_exceeded"


class DuplicateRequestAttempt(InvalidArgument):
    """同一 (request_id, attempt_no) 已有计费用量（INV-04：一次请求只计费一次）。"""

    reason = "duplicate_request_attempt"


class AmountMismatch(InvalidArgument):
    """按成交价复算的金额与收据 price_amount 不一致（INV-05，T3 接 M04 成交价后启用）。"""

    reason = "amount_mismatch"


# --------------------------------------------------------------------------- 401xx / 403xx
class AuthUnavailable(MeteringError):
    """鉴权未接线（合并期由 Lead 注入）：**fail-closed**，不静默放行。"""

    status_code = 401
    code = "40101"
    reason = "auth_unavailable"


class Unauthorized(MeteringError):
    status_code = 401
    code = "40101"
    reason = "unauthorized"


class Forbidden(MeteringError):
    """无权代表该节点提交收据（40303；per-row 版本见 ``NodeIdentityMismatch``）。"""

    status_code = 403
    code = "40303"
    reason = "forbidden"


class NodeIdentityMismatch(InvalidArgument):
    """收据声明的 node_id 与鉴权主体不一致：该条拒收（不泄露他人节点是否存在）。"""

    reason = "node_identity_mismatch"


# --------------------------------------------------------------------------- 404xx
class NotFound(MeteringError):
    status_code = 404
    code = "40401"
    reason = "not_found"


# --------------------------------------------------------------------------- 46xxx
class SignatureMismatch(MeteringError):
    """收据签名不匹配 / 双签缺一 / 算法不符（46001，HTTP 422；M05 §4.1 / INV-01）。"""

    status_code = 422
    code = "46001"
    reason = "signature_mismatch"


# --------------------------------------------------------------------------- 5xx
class KeysUnavailable(MeteringError):
    """签名密钥未接线 / 两侧密钥相同：**禁止降级放行**（INV-01，fail-closed）。"""

    status_code = 500
    code = "50001"
    reason = "keys_unavailable"


class StoreUnavailable(MeteringError):
    """库不可用 / 意料之外的持久化失败（不把内部细节回给节点）。"""

    status_code = 500
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
    424: "permission_error",
    429: "rate_limit_error",
    500: "server_error",
}


def error_type_for(status_code: int) -> str:
    """spec ``Error.error.type`` 枚举映射（未知状态按 server_error）。"""
    return _ERROR_TYPES.get(status_code, "server_error")


__all__ = [
    "MeteringError", "InvalidArgument", "AmountPrecisionRejected", "UnsupportedCurrency",
    "BatchTooLarge", "ReceiptWindowExceeded", "DuplicateRequestAttempt", "AmountMismatch",
    "AuthUnavailable", "Unauthorized", "Forbidden", "NodeIdentityMismatch", "NotFound",
    "SignatureMismatch", "KeysUnavailable", "StoreUnavailable", "error_type_for",
]
