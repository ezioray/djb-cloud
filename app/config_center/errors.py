# SPDX-License-Identifier: Apache-2.0
"""M10 配置中心的错误码（47xxx 段，本模块独占）。

码值来源（只登记，不新造）：
  · ``product/v4/modules/M10-config-center.md`` §4.1 注（47001–47009）；
  · ``spec/openapi.yaml`` 1.2.0 Error.code 说明（47001–47009 + 40013 + 40919 + 42401）；
  · ``product/v4/modules/00-conventions.md`` §5 码段表（47xxx 归配置中心）。

分层纪律：本模块只抛**领域错误**（带 code / http_status），不依赖 FastAPI、不渲染响应体；
HTTP 包装由 T3 的管理面路由做（``/api/v1/admin/config/*``）。这样 T1/T2 的纯函数与存储层
可以被单测直接断言「哪种情况返回哪个码」，不需要起服务。

CR-3（step-up 424）现状：spec 1.2.0 已登记 424 / 42401，但过渡口径仍是「403 + 47009」；
本模块在 ``StepUpRequired`` 上同时携带两种口径（``http_status=403`` / ``spec_http_status=424``），
由 T3 的路由层按开关取用，避免现在就改动对外行为。
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "ERROR_CODES",
    "ConfigCenterError",
    "ValidationFailed",
    "UnknownKey",
    "TypeMismatch",
    "UnitViolation",
    "RangeViolation",
    "CrossFieldViolation",
    "SecretShapeForbidden",
    "DangerousKeyForbidden",
    "KeyLocked",
    "CooldownActive",
    "VersionNotFound",
    "GrayPlanInvalid",
    "OutsidePublishWindow",
    "StepUpRequired",
    "SelfApprovalForbidden",
    "IdempotencyConflict",
    "FactsError",
]

#: 47xxx 段登记表：码 → 语义。测试与证据文件直接引用本表，禁止在别处写裸数字。
ERROR_CODES: dict[int, str] = {
    47001: "校验失败（schema / 单位 / 范围 / 枚举 / 跨字段 / 未知键）",
    47002: "复核人 = 发起人（自批自核）",
    47003: "键被未完结发布单锁定",
    47004: "危险键禁改",
    47005: "冷却期未到（P0 24h / P1 60min）",
    47006: "目标版本不存在",
    47007: "灰度计划 / 观测窗非法",
    47008: "发布窗口外（工作日 10:00–17:00 UTC+8）",
    47009: "需要 step-up 二次认证",
    40919: "状态冲突通用码（幂等键同键不同载荷，HTTP 409）",
    42401: "需要 step-up（spec 1.2.0 登记；过渡期用 403 + 47009）",
}


class ConfigCenterError(Exception):
    """领域错误基类：``code`` 必须是 :data:`ERROR_CODES` 已登记值。"""

    code: int = 47001
    http_status: int = 400

    def __init__(
        self,
        message: str,
        *,
        details: list[dict[str, Any]] | None = None,
        key: str | None = None,
    ) -> None:
        super().__init__(message)
        if self.code not in ERROR_CODES:  # 防御：新增子类忘登记就导入期炸掉
            raise AssertionError(f"未登记的错误码：{self.code}")
        self.message = message
        self.details = list(details or ())
        self.key = key

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "http": self.http_status,
            "message": self.message,
            "key": self.key,
            "details": self.details,
        }


# ───────────────────────────────────────────────────────────── 47001 家族
class ValidationFailed(ConfigCenterError):
    """schema / 单位 / 范围 / 枚举 / 跨字段校验失败（47001, HTTP 400）。"""

    code = 47001
    http_status = 400


class UnknownKey(ValidationFailed):
    """未注册的配置键：一律拒绝，不做「未知键放行」（§21.3.4 第①道）。"""


class TypeMismatch(ValidationFailed):
    """value_type 与值不匹配（例如 integer 键收到字符串 / 布尔）。"""


class UnitViolation(ValidationFailed):
    """单位量纲违规（§21.3.2：bps > 10000、pct > 100、无单位小数、浮点金额…）。"""


class RangeViolation(ValidationFailed):
    """minimum / maximum / multipleOf / 长度 / 枚举越界。"""


class CrossFieldViolation(ValidationFailed):
    """注册式跨字段断言失败（求和 / 承诺上限 / 依赖必填 / 互斥）。"""


class SecretShapeForbidden(ValidationFailed):
    """值出现密钥形态（INV-05）：私钥 / AK-SK / 助记词 / 口令片段一律拒绝。"""


# ───────────────────────────────────────────────────────────── 其余 47xxx
class SelfApprovalForbidden(ConfigCenterError):
    """INV-03：P0/P1 复核人必填且 ≠ 发起人（47002, HTTP 403）。"""

    code = 47002
    http_status = 403


class KeyLocked(ConfigCenterError):
    """INV-07：同 key 同时只允许一个未完结发布单（47003, HTTP 409）。"""

    code = 47003
    http_status = 409


class DangerousKeyForbidden(ConfigCenterError):
    """INV-06：dangerous=true 的键不可经 API 修改（47004, HTTP 403）。"""

    code = 47004
    http_status = 403


class CooldownActive(ConfigCenterError):
    """INV-04：P0 键冷却窗内不得二次发布，只允许回滚（47005, HTTP 409）。"""

    code = 47005
    http_status = 409


class VersionNotFound(ConfigCenterError):
    """目标版本不存在 / 不属于本 key（47006, HTTP 404）。"""

    code = 47006
    http_status = 404


class GrayPlanInvalid(ConfigCenterError):
    """灰度计划或观测窗非法（47007, HTTP 400）。"""

    code = 47007
    http_status = 400


class OutsidePublishWindow(ConfigCenterError):
    """发布窗口外（47008, HTTP 409）。回滚 / kill switch 不受此限（§21.1.2）。"""

    code = 47008
    http_status = 409


class StepUpRequired(ConfigCenterError):
    """缺 step-up（过渡口径 403 + 47009；spec 1.2.0 目标口径 424 + 42401，CR-3）。"""

    code = 47009
    http_status = 403
    spec_http_status = 424
    spec_code = 42401


class IdempotencyConflict(ConfigCenterError):
    """同幂等键不同载荷（409 + 40919，spec 1.2.0 登记的通用冲突码）。"""

    code = 40919
    http_status = 409


class FactsError(RuntimeError):
    """facts.yaml 缺失 / 形状不符 / 关键事实读不出来（不是 HTTP 错误，属部署错误）。"""
