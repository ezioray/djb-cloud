# SPDX-License-Identifier: Apache-2.0
"""M07 错误码（规格 §4.1 / 00-conventions §5 码段 / spec 1.2.4 ``Error``）。

约定（与 M05 / M09 / M12 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``type`` 取 spec ``Error.error.type`` 枚举（见 :func:`error_type_for`）；
* ``message`` 只供人类阅读，不含内部阈值 / 堆栈 / SQL / 口令；
* **只返回下表登记的码**，每个码都有 spec 出处（spec 1.2.4 ``Error.code`` 说明）。

===  ======  ==============================================================
码     HTTP    语义 / 出处
===  ======  ==============================================================
40001   400    请求不合法（M07 §4.1：结构 / 枚举 / 大小 / 游标形态）
40101   401    未认证 / 鉴权未接线（本模块默认 fail-closed）
40201   402    余额不足（COP 可用量 < 本次兑换 / 扣回；spec 1.2.0 已登记）
40401   404    资源不存在 / 越权统一 404（不泄露存在性；spec 1.2.0 已登记）
40902   409    状态冲突（转让开关关闭 / 账户不可用 / 邀请状态机非法迁移）
40919   409    双人复核：复核人 = 发起人 / 复核人缺失（spec 1.2.0 通用冲突码）
42240   422    兑换 / 转让校验失败（锁定期、限额、自转；spec 1.2.4 登记）
42401   424    缺 step-up（spec 1.2.0 登记；本模块 **直接** 用 424，不退回 403）
50001   503    依赖不可用（库未接线 / 意料之外的持久化失败）：fail-closed，不降级放行
              —— 与 M04/M05/M12/M16 共用同一工程兜底码，不是 M07 §4.1 的契约码
===  ======  ==============================================================

``reason`` 是给客户端与日志用的**短码**（机器可判），进 ``Error.error`` 的扩展字段
（spec ``additionalProperties: true`` 允许），不进必填字段。
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "ReputationError", "InvalidArgument", "CursorInvalid", "AuthUnavailable", "Unauthorized",
    "NotFound", "Conflict", "TransferDisabled", "AccountUnavailable", "InviteStateConflict",
    "ReviewerConflict", "StepUpRequired", "ValidationFailed", "InsufficientBalance",
    "StoreUnavailable", "error_type_for",
]


class ReputationError(Exception):
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
        return {"code": int(self.code), "message": self.message, "reason": self.reason,
                **self.details}


# --------------------------------------------------------------------------- 400xx
class InvalidArgument(ReputationError):
    """参数 / 语义校验失败（40001）。"""

    status_code = 400
    code = "40001"
    reason = "invalid_argument"


class CursorInvalid(InvalidArgument):
    """游标不可解析（00-conventions §5：不得猜测或自行构造）。"""

    reason = "cursor_invalid"


# --------------------------------------------------------------------------- 401xx
class AuthUnavailable(ReputationError):
    """鉴权未接线（合并期由 Lead 注入）：**fail-closed**，不静默放行。"""

    status_code = 401
    code = "40101"
    reason = "auth_unavailable"


class Unauthorized(ReputationError):
    status_code = 401
    code = "40101"
    reason = "unauthorized"


# --------------------------------------------------------------------------- 402xx
class InsufficientBalance(ReputationError):
    """COP 可用量不足（402 / 40201）：只比较 ``available``，``locked`` 不可用。"""

    status_code = 402
    code = "40201"
    reason = "insufficient_cop"


# --------------------------------------------------------------------------- 404xx
class NotFound(ReputationError):
    """账户 / 兑换单 / 评分记录不存在，或不属于当前主体（越权统一 404，避免枚举）。"""

    status_code = 404
    code = "40401"
    reason = "not_found"


# --------------------------------------------------------------------------- 409xx
class Conflict(ReputationError):
    """状态冲突（40902）。"""

    status_code = 409
    code = "40902"
    reason = "state_conflict"


class TransferDisabled(Conflict):
    """K4 / INV-06：``points.transfer_enabled=false`` 时转让一律 409 / 40902。"""

    reason = "transfer_disabled"


class AccountUnavailable(Conflict):
    """账户状态不是 normal（frozen / closing / closed）：拒绝兑换与转让（已得 COP 保留）。"""

    reason = "account_unavailable"


class InviteStateConflict(Conflict):
    """邀请状态机非法迁移 / 已绑定 / 已过期。"""

    reason = "invite_state_conflict"


class ReviewerConflict(ReputationError):
    """双人复核失败（409 / 40919）：复核人缺失或等于发起人。"""

    status_code = 409
    code = "40919"
    reason = "reviewer_conflict"


# --------------------------------------------------------------------------- 422xx
class ValidationFailed(ReputationError):
    """兑换 / 转让校验失败（422 / 42240）：锁定期未到、超单笔 / 单日限额、自转等。"""

    status_code = 422
    code = "42240"
    reason = "validation_failed"


# --------------------------------------------------------------------------- 424xx
class StepUpRequired(ReputationError):
    """缺二次认证（424 / 42401）：管理面写操作必须带 ``X-Admin-Step-Up``。"""

    status_code = 424
    code = "42401"
    reason = "step_up_required"


# --------------------------------------------------------------------------- 5xx
class StoreUnavailable(ReputationError):
    """库未接线 / 意料之外的持久化失败（不把内部细节回给调用方）。"""

    status_code = 503
    code = "50001"
    reason = "store_unavailable"


_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    402: "permission_error",          # 与 M03 网关同口径（spec 1.2.0 PaymentRequired）
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    413: "invalid_request_error",
    422: "invalid_request_error",
    424: "authentication_error",      # 与 M09 recon 同口径（step-up）
    429: "rate_limit_error",
    500: "server_error",
    503: "server_error",
}


def error_type_for(status_code: int) -> str:
    """spec ``Error.error.type`` 枚举映射（未知状态按 server_error）。"""
    return _ERROR_TYPES.get(status_code, "server_error")
