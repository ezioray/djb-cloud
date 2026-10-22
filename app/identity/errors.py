# SPDX-License-Identifier: Apache-2.0
"""T2 认证域错误码（M01 §4.1 / spec 1.2.0 已登记项）。

沿用 T1 的 ``models.IdentityError``（``status_code`` + 字符串 ``code`` + ``as_dict``），
T2 只补认证相关码，并在 :func:`error_type_for` 里按 HTTP 状态映射到 spec 的
``Error.error.type`` 枚举（invalid_request_error / authentication_error / ...）。
"""
from __future__ import annotations

from .models import (
    AccountClosed,
    AccountReadOnly,
    ClosureBlocked,
    IdentityError,
    IllegalTransition,
    InvalidArgument,
    InviteInvalid,
    NotFound,
    QuotaSnapshotMissing,
    SessionInvalid,
    StateConflict,
)


class LoginCredentialError(IdentityError):
    """凭据错误：**不区分**「账号不存在」与「口令/MFA 错误」（防枚举，spec login 描述）。"""

    status_code = 401
    code = "40110"
    reason = "invalid_credentials"


class RefreshTokenRejected(IdentityError):
    """刷新令牌无效 / 已轮换 / 已撤销（重放旧令牌）。spec：按 40103 处理并要求重新登录。"""

    status_code = 401
    code = "40103"
    reason = "refresh_token_rejected"


class LoginThrottled(IdentityError):
    """连续失败触发账号锁定（M01 §8.2：5 次 / 15 分钟）。只给粗粒度原因与 Retry-After。"""

    status_code = 429
    code = "42901"
    reason = "login_locked"


class AuthMethodUnavailable(IdentityError):
    """登录方式在 S1 未接入（短信通道归 M12、外部 OAuth 未接入）。"""

    status_code = 403
    code = "40303"
    reason = "auth_method_unavailable"


class ScanTicketInvalid(IdentityError):
    """扫码票据无效 / 过期 / 已用（一次性令牌家族，与邀请令牌同码 40905）。"""

    status_code = 409
    code = "40905"
    reason = "scan_ticket_invalid"


class IdempotencyConflict(IdentityError):
    """同一幂等键携带不同载荷（00-conventions §6.1）。"""

    status_code = 409
    code = "40919"
    reason = "idempotency_conflict"


class StepUpRequired(IdentityError):
    """高危动作需要二次认证（spec 424 / 42401）。"""

    status_code = 424
    code = "42401"
    reason = "step_up_required"


class MfaNotEnabled(IdentityError):
    """账户未启用 MFA，却要求 MFA 动作（step-up / 关闭）。"""

    status_code = 409
    code = "40902"
    reason = "mfa_not_enabled"


_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    422: "invalid_request_error",
    429: "rate_limit_error",
    500: "server_error",
}


def error_type_for(status_code: int) -> str:
    """spec ``Error.error.type`` 枚举映射（未知状态按 server_error）。"""
    return _ERROR_TYPES.get(status_code, "server_error")


__all__ = [
    "LoginCredentialError", "RefreshTokenRejected", "LoginThrottled", "AuthMethodUnavailable",
    "ScanTicketInvalid", "IdempotencyConflict", "MfaNotEnabled", "StepUpRequired",
    "error_type_for",
    # 复用 T1 的错误类型，便于路由层一处 catch
    "IdentityError", "InvalidArgument", "NotFound", "StateConflict", "AccountClosed",
    "AccountReadOnly", "SessionInvalid", "IllegalTransition", "InviteInvalid",
    "ClosureBlocked", "QuotaSnapshotMissing",
]
