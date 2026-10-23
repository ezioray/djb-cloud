# SPDX-License-Identifier: Apache-2.0
"""M11 错误码（spec 1.2.4 已登记码 · 00-conventions §5 · M11 §4.1）。

约定（与 M05 / M09 / M10 / M12 / M16 同款）：

* 错误信封 ``{"error": {type, code, message, request_id}}``，``code`` 是**整数**；
* ``type`` 取 spec ``Error`` 枚举；``message`` 只供人类阅读，**不含**阈值 / 权重 / 名单 /
  规则命中细节 / PII / 堆栈；
* **不发明新码**：下表每个码都能在 spec 1.2.4 或已登记的通用码里找到出处。

===  ======  ================================================================
码     HTTP    语义 / 出处（M11 §4.1 / spec 1.2.4）
===  ======  ================================================================
40001   400    请求不合法（字段缺失 / 形态非法 / 幂等键形态 / 枚举越界）
40101   401    未认证 / 鉴权未接线（fail-closed）
40301   403    管理面签名 / 角色不足（spec 通用码；本模块用于 scope 不足）
40401   404    资源不存在（含跨租户统一 404，避免枚举）
40919   409    状态冲突通用码（非法状态迁移 / 幂等键复用 / 库层护栏）
42401   424    step-up 二次认证缺失或过期（≤5 分钟）
48001   429    限额命中（**对外只给粗粒度 reason**；由 M03/M04/M08 返回，本模块消费 48001 事件）
48002   409    同主体同类型已有未结案件（INV-06；重复触发并入既有案件）
48003   409    申诉超期 / 重复（同一案件已有未结申诉，或已过 30 天窗口）
48004   400    证据缺失（INV-03：evidence_refs 为空 / 非法）
48005   409    规则或限额版本冲突（expected_version 与当前版本不一致）
48006   403    处置越权 / 违反 SoD（裁决人 = 原处置人；开案人自行终局处置）
45001   500    统一错误模型兜底（spec 1.2.2 已登记，不是本模块新码；仅用于未预期异常）
===  ======  ================================================================

INV-02：对外错误只给 4 个粗粒度 reason（``facts.COARSE_REASONS``），**不含**规则名 / 阈值 /
命中条目。``reason`` 是给客户端与日志的短码（机器可判），不进 spec 必填字段。
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "RiskError", "BadRequest", "Unauthorized", "Forbidden", "StepUpRequired", "NotFound",
    "Conflict", "CaseExists", "AppealConflict", "EvidenceMissing", "RuleVersionConflict",
    "SeparationOfDuty", "LimitHit", "ServerError", "error_type_for",
]


class RiskError(Exception):
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

    def __repr__(self) -> str:  # pragma: no cover - 便于排查
        return f"<{type(self).__name__} {self.status_code}/{self.code}: {self.message}>"


# ───────────────────────────────────────────────────────────── 4xx（请求 / 身份）
class BadRequest(RiskError):
    status_code = 400
    code = 40001
    error_type = "invalid_request_error"


class Unauthorized(RiskError):
    status_code = 401
    code = 40101
    error_type = "authentication_error"


class Forbidden(RiskError):
    status_code = 403
    code = 40301
    error_type = "permission_error"


class StepUpRequired(RiskError):
    """step-up 缺失 / 过期（spec `StepUpRequired`：424 + 42401）。"""

    status_code = 424
    code = 42401
    error_type = "authentication_error"

    def __init__(self, message: str = "敏感操作需要 5 分钟内的二次认证（step-up）") -> None:
        super().__init__(message, reason="step_up_required")


class NotFound(RiskError):
    status_code = 404
    code = 40401
    error_type = "not_found_error"


class Conflict(RiskError):
    """状态冲突（通用码 40919）：非法状态迁移 / 幂等键复用 / 库层护栏。"""

    status_code = 409
    code = 40919
    error_type = "conflict_error"


# ───────────────────────────────────────────────────────────── 48xxx（风控段）
class LimitHit(RiskError):
    """48001 限额命中。

    **本模块不返回这个 HTTP 错误**：M11 §4.3 / §6 流程 1 规定限额由 M03 / M04 / M08
    读 ``v_risk_limits`` 本地判定并返回 48001（对外只给粗粒度 reason）；本模块只消费
    该失败事件（``record_limit_hit``）并生产 ``risk.limit.hit``。
    """

    status_code = 429
    code = 48001
    error_type = "rate_limit_error"
    reason = "rate_limited"


class CaseExists(RiskError):
    """48002：同 subject + risk_type 已有未结案件（INV-06）。"""

    status_code = 409
    code = 48002
    error_type = "conflict_error"
    reason = "case_exists"


class AppealConflict(RiskError):
    """48003：申诉重复（同案件已有未结申诉）或已超 30 天提交窗口。"""

    status_code = 409
    code = 48003
    error_type = "conflict_error"
    reason = "appeal_conflict"


class EvidenceMissing(RiskError):
    """48004：证据缺失（INV-03：无证据不得开案 / 不得终局处置）。"""

    status_code = 400
    code = 48004
    error_type = "invalid_request_error"
    reason = "evidence_required"


class RuleVersionConflict(RiskError):
    """48005：规则 / 限额版本冲突（expected_version 与当前版本不一致）。"""

    status_code = 409
    code = 48005
    error_type = "conflict_error"
    reason = "version_conflict"


class SeparationOfDuty(RiskError):
    """48006：处置越权 / 违反职责分离（裁决人 = 原处置人）。"""

    status_code = 403
    code = 48006
    error_type = "permission_error"
    reason = "separation_of_duty"


class ServerError(RiskError):
    """500 兜底（45001 为 spec 已登记的统一错误码，不是本模块新码）。"""

    status_code = 500
    code = 45001
    error_type = "server_error"
    reason = "server_error"


#: HTTP 状态 → spec ``Error.type``（框架级 422/405 之类走这里）
ERROR_TYPE_BY_STATUS: dict[int, str] = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    409: "conflict_error",
    424: "authentication_error",
    429: "rate_limit_error",
    500: "server_error",
}


def error_type_for(status_code: int) -> str:
    return ERROR_TYPE_BY_STATUS.get(status_code, "server_error")
