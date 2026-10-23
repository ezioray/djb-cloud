# SPDX-License-Identifier: Apache-2.0
"""M08 错误码（spec 已登记码 · 00-conventions §5 · M08 §4.1 / §7 · 产品 §19.10.4）。

约定（与 M05 / M06 / M09 / M11 / M12 同款）：

* 错误信封 {"error": {type, code, message, request_id}}，code 是**整数**；
* type 取 spec Error 枚举；message 只供人类阅读，**不含**卡号 / 渠道原文 / 内部规则 / 堆栈；
* **不发明新码**：下表每个码都能在 spec 1.2.x 或 M08 §4.1 已登记段内找到出处。

===  ======  ==================================================================
码     HTTP    语义 / 出处
===  ======  ==================================================================
40001   400    请求不合法（字段缺失 / 形态非法 / 幂等键形态 / 枚举越界 / 验签失败）
40101   401    未认证 / 鉴权未接线（fail-closed）
40301   403    管理面签名 / 角色不足（spec 通用码；本模块用于 scope 不足）
40310   403    支付通道未开启（§19.10.4；该支付方式 / PSP 未开放）
40311   403    该地区不支持该支付方式（§19.10.4）
40312   403    入金 / 白名单需完成风控升级（§19.10.4）
40401   404    资源不存在（spec 1.2.2 已登记通用码；无更细码时）
40910   409    订单已支付 / 重复回调（幂等返回成功，不重复入账）
40911   409    金额与订单不符（少付 / 多付；挂账，入账前不计）
40912   409    确认数不足 / 充值未到账（只对链上收款；PSP 路径不用）
40913   409    地址 / 链 / 资产不支持（一期仅 Polygon USDT）
40914   409    扩容批次已过期（TTL 24h）
40915   409    钱包地址冲突（整批不激活）
40916   409    缺 recon_attestation（不得出款 / 不得退休）
40917   409    退款处理中（原路退回排队中）
40918   409    退款失败（原地址或卡不可用，转人工）
40919   409    状态冲突通用码（非法状态迁移 / 幂等键复用 / 冷却未到；无更细码时）
42210   422    出款主体未通过准入（白名单 / 所有权验证未完成）
42211   422    风控 / 地址风险拒绝
42401   424    step-up 二次认证缺失或过期（≤5 分钟）
45001   500    统一错误模型兜底（spec 1.2.2 已登记，不是本模块新码）
===  ======  ==================================================================

注：40910 在 M08 §7 同时用于「回调验签失败 / 金额不符」的拒绝路径；本模块把 40910 严格用于
「重复回调（幂等）」，验签失败走 40001（spec 通用请求错误），金额不符走 40911。差异已登记
证据「遗留 / CR-P7」，等 Lead 在 spec §4.1 明确。
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "TreasuryError", "BadRequest", "Unauthorized", "Forbidden", "NotFound", "Conflict",
    "StepUpRequired", "PaymentMethodClosed", "RegionUnsupported", "RiskLevelRequired",
    "DuplicateCallback", "AmountMismatch", "ConfirmationsPending", "ChainUnsupported",
    "ProvisionBatchExpired", "AddressConflict", "AttestationMissing", "RefundInProgress",
    "RefundFailed", "PayeeNotEligible", "AddressRiskRejected", "LedgerUnavailable",
    "ServerError", "error_type_for", "ERROR_TYPE_BY_STATUS",
]


class TreasuryError(Exception):
    """领域错误基类：status_code / code / error_type 直接进错误信封。"""

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

    def __repr__(self) -> str:  # pragma: no cover - 便于排查
        return f"<{type(self).__name__} {self.status_code}/{self.code}: {self.message}>"


# ───────────────────────────────────────────────────────────── 4xx（请求 / 身份）
class BadRequest(TreasuryError):
    status_code = 400
    code = 40001
    error_type = "invalid_request_error"


class Unauthorized(TreasuryError):
    status_code = 401
    code = 40101
    error_type = "authentication_error"


class Forbidden(TreasuryError):
    status_code = 403
    code = 40301
    error_type = "permission_error"


class NotFound(TreasuryError):
    status_code = 404
    code = 40401
    error_type = "not_found_error"


class Conflict(TreasuryError):
    """状态冲突（通用码 40919）：非法迁移 / 幂等键复用 / 冷却未到 / 窗口已过。"""

    status_code = 409
    code = 40919
    error_type = "conflict_error"


class StepUpRequired(TreasuryError):
    status_code = 424
    code = 42401
    error_type = "authentication_error"

    def __init__(self, message: str = "敏感操作需要 5 分钟内的二次认证（step-up）") -> None:
        super().__init__(message, reason="step_up_required")


# ───────────────────────────────────────────────────────────── 40xxx（资金段）
class PaymentMethodClosed(TreasuryError):
    status_code = 403
    code = 40310
    error_type = "permission_error"
    reason = "payment_method_closed"


class RegionUnsupported(TreasuryError):
    status_code = 403
    code = 40311
    error_type = "permission_error"
    reason = "region_unsupported"


class RiskLevelRequired(TreasuryError):
    status_code = 403
    code = 40312
    error_type = "permission_error"
    reason = "risk_level_required"


class DuplicateCallback(TreasuryError):
    """40910：订单已支付 / 重复回调 → 幂等返回首次结果，不重复入账。"""

    status_code = 409
    code = 40910
    error_type = "conflict_error"
    reason = "duplicate_callback"


class AmountMismatch(TreasuryError):
    """40911：到账金额与订单不符（少付 / 多付）→ 挂账，入账前不计。"""

    status_code = 409
    code = 40911
    error_type = "conflict_error"
    reason = "amount_mismatch"


class ConfirmationsPending(TreasuryError):
    """40912：确认数不足 / 充值未到账（链上路径；PSP 路径不使用）。"""

    status_code = 409
    code = 40912
    error_type = "conflict_error"
    reason = "confirmations_pending"


class ChainUnsupported(TreasuryError):
    """40913：地址 / 链 / 资产不支持（一期仅 Polygon USDT）。"""

    status_code = 409
    code = 40913
    error_type = "conflict_error"
    reason = "chain_unsupported"


class ProvisionBatchExpired(TreasuryError):
    """40914：扩容批次已过期（TTL 24h）→ 重新生成描述符再签。"""

    status_code = 409
    code = 40914
    error_type = "conflict_error"
    reason = "provision_batch_expired"


class AddressConflict(TreasuryError):
    """40915：钱包地址冲突（整批不激活）。"""

    status_code = 409
    code = 40915
    error_type = "conflict_error"
    reason = "address_conflict"


class AttestationMissing(TreasuryError):
    """40916：缺 recon_attestation（不得出款 / 不得退休）。"""

    status_code = 409
    code = 40916
    error_type = "conflict_error"
    reason = "attestation_missing"


class RefundInProgress(TreasuryError):
    """40917：退款处理中（原路退回排队中）。"""

    status_code = 409
    code = 40917
    error_type = "conflict_error"
    reason = "refund_in_progress"


class RefundFailed(TreasuryError):
    """40918：退款失败（原地址或卡不可用，转人工）。"""

    status_code = 409
    code = 40918
    error_type = "conflict_error"
    reason = "refund_failed"


class PayeeNotEligible(TreasuryError):
    """42210：出款主体未通过准入（白名单 / 所有权验证）。"""

    status_code = 422
    code = 42210
    error_type = "invalid_request_error"
    reason = "payee_not_eligible"


class AddressRiskRejected(TreasuryError):
    """42211：风控 / 地址风险拒绝。"""

    status_code = 422
    code = 42211
    error_type = "invalid_request_error"
    reason = "address_risk_rejected"


class LedgerUnavailable(TreasuryError):
    """M06 记账未接线 / 不可用：资金写不自动重试（00-conventions §6.3），fail-closed。"""

    status_code = 500
    code = 45001
    error_type = "server_error"
    reason = "ledger_unavailable"


class ServerError(TreasuryError):
    """500 兜底（45001 为 spec 已登记的统一错误码，不是本模块新码）。"""

    status_code = 500
    code = 45001
    error_type = "server_error"
    reason = "server_error"


#: HTTP 状态 → spec Error.type（框架级 422/405 之类走这里）
ERROR_TYPE_BY_STATUS: dict[int, str] = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    422: "invalid_request_error",
    424: "authentication_error",
    429: "rate_limit_error",
    500: "server_error",
}


def error_type_for(status_code: int) -> str:
    return ERROR_TYPE_BY_STATUS.get(status_code, "server_error")
