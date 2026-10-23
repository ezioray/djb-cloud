# SPDX-License-Identifier: Apache-2.0
"""M02 错误码（M02 §4.1 / §7 失败矩阵 / 04-api-contracts §5 码段）。

约定（00-conventions §5 + spec ``Error``）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``type`` 取 spec 枚举（见 :func:`error_type_for`）；
* ``message`` 只供人类阅读，不含内部堆栈 / 规则阈值 / 凭据；
* **未登记的码一律不返回**：本文件出现的码都有出处（逐条标注）。

本模块用到的码（全部在 M02 §4.1 / 04 已登记段内）：

===  ======  ====================================================
码     HTTP    语义
===  ======  ====================================================
40001  400     请求不合法（含 INV-03/04 指纹与疑似凭据字段）
40101  401     节点密钥缺失 / 未知（``key_hash`` 未命中）
40102  401     节点密钥已撤销 / 轮换重叠期已过（客户端应换钥并换绑）
40401  404     对象不存在 / 跨账户不可见（不泄露存在性）
40305  403     节点状态不允许该动作（pending / frozen / retired，CR-7 登记）
40903  409     冲突：指纹已被占用 / 已绑定其它账户 / 密钥状态冲突（INV-01 / INV-08）
40902  409     不可逆或需要前置条件（retired 不可逆、在途未完成，INV-09 / INV-10）
40905  409     一次性令牌失效（绑定码已用 / 过期；spec 1.2.1 登记的一次性令牌家族）
40907  409     策略版本回退 / 摘要不符（INV-06，T5 使用）
40919  409     幂等键冲突：同键不同载荷（00-conventions §6.1 / spec 1.2.0）
42401  424     需要 step-up（管理面高危动作）
42601  426     协议版本不兼容（INV-05，附 ``min_supported_version``）
42901  429     限流（心跳过快；T3）
===  ======  ====================================================
"""
from __future__ import annotations

from typing import Any


class SupplyError(Exception):
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
class InvalidArgument(SupplyError):
    """参数 / 语义校验失败（40001）。"""

    status_code = 400
    code = "40001"
    reason = "invalid_argument"


class CredentialFieldRejected(InvalidArgument):
    """请求疑似带凭据本体（INV-04）：丢弃字段、不落值、400 + 告警。

    ``details["fields"]`` 只放**字段名**（如 ``upstream.api_key``），绝不放值。
    """

    reason = "credential_field_rejected"


# --------------------------------------------------------------------------- 401xx
class NodeKeyMissing(SupplyError):
    status_code = 401
    code = "40101"
    reason = "missing_client_key"


class NodeKeyInvalid(SupplyError):
    """密钥未知（``key_hash`` 未命中）。"""

    status_code = 401
    code = "40101"
    reason = "invalid_client_key"


class NodeKeyRevoked(SupplyError):
    """密钥已撤销 / 轮换重叠期已过（40102，客户端应重新 pair）。"""

    status_code = 401
    code = "40102"
    reason = "client_key_revoked"


class AdminAuthUnavailable(SupplyError):
    """管理面鉴权未接线（合并期由 Lead 注入）：**fail-closed**，不静默放行。"""

    status_code = 401
    code = "40101"
    reason = "admin_auth_unavailable"


# --------------------------------------------------------------------------- 403xx
class NodeStateForbidden(SupplyError):
    """节点状态不允许该动作（40305，CR-7）。details 带当前状态与可做动作。"""

    status_code = 403
    code = "40305"
    reason = "node_state_forbidden"


# --------------------------------------------------------------------------- 404xx
class NodeNotFound(SupplyError):
    status_code = 404
    code = "40401"
    reason = "node_not_found"


class UpstreamNotFound(SupplyError):
    """上游申报不存在 / 不属于该节点（40401；不泄露他人节点存在性）。"""

    status_code = 404
    code = "40401"
    reason = "upstream_not_found"


class AccountNotFound(SupplyError):
    """绑定目标的账户在 M01 只读视图里不存在（40401；不泄露存在性细节）。"""

    status_code = 404
    code = "40401"
    reason = "account_not_found"


# --------------------------------------------------------------------------- 409xx
class FingerprintConflict(SupplyError):
    """同指纹已注册且不可被本次请求接管（INV-01 / §7「不同账户抢同指纹」）。"""

    status_code = 409
    code = "40903"
    reason = "fingerprint_conflict"


class BindingConflict(SupplyError):
    """节点已有另一条有效绑定（INV-08）。"""

    status_code = 409
    code = "40903"
    reason = "binding_conflict"


class KeyStateConflict(SupplyError):
    """密钥状态冲突（例如重叠窗口参数与请求矛盾）。"""

    status_code = 409
    code = "40903"
    reason = "key_state_conflict"


class RetireIrreversible(SupplyError):
    """``retired`` 不可逆 / 在途未完成（INV-09）。"""

    status_code = 409
    code = "40902"
    reason = "retire_irreversible"


class BindingCodeInvalid(SupplyError):
    """一次性绑定码已用 / 过期 / 不匹配（40905：spec 1.2.1 一次性令牌家族）。"""

    status_code = 409
    code = "40905"
    reason = "binding_code_invalid"


class IdempotencyConflict(SupplyError):
    """同键不同载荷（40919）。"""

    status_code = 409
    code = "40919"
    reason = "idempotency_conflict"


class PolicyVersionRegression(SupplyError):
    """策略版本回退 / digest 不符（INV-06，T5 使用）。"""

    status_code = 409
    code = "40907"
    reason = "policy_version_regression"


# --------------------------------------------------------------------------- 424xx / 426xx / 429xx
class StepUpRequired(SupplyError):
    """管理面高危动作二次认证缺失或过期（424 / 42401）。"""

    status_code = 424
    code = "42401"
    reason = "step_up_required"


class ProtocolIncompatible(SupplyError):
    """协议 MAJOR 越界（INV-05）：42601 + ``min_supported_version`` + 升级指引。"""

    status_code = 426
    code = "42601"
    reason = "protocol_incompatible"


class HeartbeatTooFast(SupplyError):
    """心跳过快（§7 心跳限流：每节点 5 s 一次，T3 使用）。"""

    status_code = 429
    code = "42901"
    reason = "heartbeat_too_fast"


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
    502: "upstream_error",
}


def error_type_for(status_code: int) -> str:
    """spec ``Error.error.type`` 枚举映射（未知状态按 server_error）。"""
    return _ERROR_TYPES.get(status_code, "server_error")


__all__ = [
    "SupplyError", "InvalidArgument", "CredentialFieldRejected",
    "NodeKeyMissing", "NodeKeyInvalid", "NodeKeyRevoked", "AdminAuthUnavailable",
    "NodeStateForbidden", "NodeNotFound", "AccountNotFound", "UpstreamNotFound",
    "FingerprintConflict", "BindingConflict", "KeyStateConflict", "RetireIrreversible",
    "BindingCodeInvalid", "IdempotencyConflict", "PolicyVersionRegression",
    "StepUpRequired", "ProtocolIncompatible", "HeartbeatTooFast",
    "error_type_for",
]
