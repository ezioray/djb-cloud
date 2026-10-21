# SPDX-License-Identifier: Apache-2.0
"""管理后台域（§22.21 管理后台运维中心 · §21.12 配置中心）。

本包只放**管理面服务层**逻辑，不注册任何 HTTP 路由（路由接线见
``docs/DEV-0004-ops-center.md`` §6；本单红线：不新增未进 spec 的端点）。

目录
====
``ops_center.py``
    运维中心 + 配置中心的服务层：8 个配置操作的唯一实现入口、三源漂移、
    发布单状态机、审计哈希链、幂等、值班只读视图（健康 / SLO / 告警 / 冻结窗）。

契约（spec 唯一真源）
=====================
本包自始至终只使用 `spec/openapi.yaml` 里已定稿的 8 个 ``operationId``，
不新造、不改名、不合并。登记表见 ``OPERATIONS``；``ops_center.py`` 的每个
函数用 ``@operation(...)`` 声明自己实现哪一条，测试会拿 spec 反查（缺一条 / 多一条都红）。

======================  ======  ==========================================================  =========================
operationId              方法    路径                                                        权限点
======================  ======  ==========================================================  =========================
``listConfigItems``       GET     ``/api/v1/admin/config/items``                              ``config.item.read``
``listConfigDrifts``      GET     ``/api/v1/admin/config/drifts``                             ``config.item.read``
``getConfigItem``         GET     ``/api/v1/admin/config/{key}``                              ``config.item.read``
``createConfigDraft``     POST    ``/api/v1/admin/config/{key}``                              ``config.item.publish``
``publishConfigItem``     POST    ``/api/v1/admin/config/{key}/publish``                      ``config.item.publish``
``approveConfigPublish``  POST    ``/api/v1/admin/config/publish-requests/{id}/approve``      ``config.item.approve``
``rollbackConfigItem``    POST    ``/api/v1/admin/config/{key}/rollback``                     ``config.item.rollback``
``killSwitchConfigItem``  POST    ``/api/v1/admin/config/{key}/kill-switch``                  ``config.item.emergency``
======================  ======  ==========================================================  =========================

特性开关（§B.5 / §21.6.4；三字段 owner / expire_at / rollback_rule 必填，默认关闭）
====================================================================================

===================  ======  =========  ==========  ====================================================
flag                 默认    owner      expire_at   rollback_rule
===================  ======  =========  ==========  ====================================================
``admin_ops_center`` **off**  web-dev   2026-12-31  关闭后只保留只读视图（列表 / 详情 / 漂移 / 健康 /
                                                     SLO / 告警 / 审计检索），4 个写入口一律 **404**
                                                     （不是 403：关闭态下不暴露"这里本来能写"）；
                                                     已生效的配置值不回滚、不删除，审计链只追加不缩短
===================  ======  =========  ==========  ====================================================

打开方式：``DJB_FF_ADMIN_OPS_CENTER=1``；缺省 / ``0`` / ``off`` 均为关闭。
``expire_at`` 到期后**强制为关**（fail-closed），续期必须重新评审改日期，不允许静默续期。

红线
====
1. 管理面**不公网可达**：内网 / 加密专线 + 强 MFA + step-up（≤5 分钟）。本包只做鉴权入参校验，
   传输面与网络准入由网关负责，代码里不出现任何"公网可达"假设。
2. 不直接改账、不直接签名；写动作只落配置，资金动作仍走 §19。
3. 敏感项**绝不出现明文**：库里不存（CHECK 约束）、渲染不出来、审计里也脱敏。
"""
from __future__ import annotations

import os
from datetime import date

__all__ = [
    "FEATURE_FLAGS",
    "REQUIRED_FLAG_FIELDS",
    "OPERATIONS",
    "OPERATION_IDS",
    "PERMISSIONS",
    "APPROVER_ROLES_P0",
    "flag_spec",
    "flag_expired",
    "flag_enabled",
    "writes_enabled",
    "require_writes_enabled",
    "OpsCenterError",
    "FeatureDisabled",
    "BadRequest",
    "Unauthorized",
    "Forbidden",
    "NotFound",
    "Conflict",
    "StepUpRequired",
    "BreakGlassReadOnly",
]

# --------------------------------------------------------------------------- 开关
REQUIRED_FLAG_FIELDS = ("owner", "expire_at", "rollback_rule")

FEATURE_FLAGS: dict[str, dict] = {
    "admin_ops_center": {
        "default": False,
        "owner": "web-dev",
        "expire_at": "2026-12-31",
        "rollback_rule": (
            "关闭后只保留只读视图（配置项列表 / 详情 / 漂移 / 健康总览 / SLO / 告警 / 审计检索），"
            "4 个写入口（createConfigDraft / publishConfigItem / approveConfigPublish / "
            "rollbackConfigItem / killSwitchConfigItem）返回 404，不暴露可写能力；"
            "已生效配置值不回滚、不删除，审计链只追加不缩短；紧急止损改走运维手工流程 + kill-switch 前置演练"
        ),
        "summary": "管理后台运维中心（值班视图 + 配置中心 8 操作的服务层）",
    },
}

_ENV_PREFIX = "DJB_FF_"
_TRUTHY = {"1", "true", "yes", "on", "y", "t"}


def flag_spec(name: str) -> dict:
    """返回开关定义（含三字段）。缺字段直接报错，不允许「裸开关」上线。"""
    try:
        spec = dict(FEATURE_FLAGS[name])
    except KeyError:
        raise KeyError(f"未登记的特性开关: {name}") from None
    missing = [f for f in REQUIRED_FLAG_FIELDS if not spec.get(f)]
    if missing:
        raise ValueError(f"特性开关 {name} 缺三字段中的 {missing}（owner / expire_at / rollback_rule 必填）")
    return spec


def flag_expired(name: str, *, today: date | None = None) -> bool:
    """开关是否已过 expire_at（到期即强制为关）。"""
    spec = flag_spec(name)
    today = today or date.today()
    return today > date.fromisoformat(spec["expire_at"])


def flag_enabled(name: str, *, override: bool | None = None, today: date | None = None) -> bool:
    """读开关。优先级：显式 override（测试用）> 环境变量 > 默认值；到期一律 False。"""
    spec = flag_spec(name)
    if flag_expired(name, today=today):
        return False
    if override is not None:
        return bool(override)
    raw = os.environ.get(_ENV_PREFIX + name.upper())
    if raw is None or raw.strip() == "":
        return bool(spec["default"])
    return raw.strip().lower() in _TRUTHY


OPS_CENTER_FLAG = "admin_ops_center"


def writes_enabled(*, override: bool | None = None, today: date | None = None) -> bool:
    """写入口是否开启（读路径永远可用）。"""
    return flag_enabled(OPS_CENTER_FLAG, override=override, today=today)


def require_writes_enabled(*, override: bool | None = None, today: date | None = None) -> None:
    """写入口闸门：关闭态抛 404（rollback_rule 要求"写入口 404"，不是 403）。"""
    if not writes_enabled(override=override, today=today):
        raise FeatureDisabled(
            "管理后台运维中心写入口已关闭（admin_ops_center=false）；"
            "读视图仍可用，开写需按 §21.6.4 重新评审开关"
        )


# --------------------------------------------------------------------------- 契约常量
#: 8 个 operationId → 元数据。与 `spec/openapi.yaml` 一一对应（测试反查 spec）。
OPERATIONS: dict[str, dict] = {
    "listConfigItems": {
        "method": "GET", "path": "/api/v1/admin/config/items",
        "permission": "config.item.read", "step_up": False, "write": False,
    },
    "listConfigDrifts": {
        "method": "GET", "path": "/api/v1/admin/config/drifts",
        "permission": "config.item.read", "step_up": False, "write": False,
    },
    "getConfigItem": {
        "method": "GET", "path": "/api/v1/admin/config/{key}",
        "permission": "config.item.read", "step_up": False, "write": False,
    },
    "createConfigDraft": {
        "method": "POST", "path": "/api/v1/admin/config/{key}",
        "permission": "config.item.publish", "step_up": False, "write": True,
    },
    "publishConfigItem": {
        "method": "POST", "path": "/api/v1/admin/config/{key}/publish",
        "permission": "config.item.publish", "step_up": True, "write": True,
    },
    "approveConfigPublish": {
        "method": "POST", "path": "/api/v1/admin/config/publish-requests/{id}/approve",
        "permission": "config.item.approve", "step_up": True, "write": True,
    },
    "rollbackConfigItem": {
        "method": "POST", "path": "/api/v1/admin/config/{key}/rollback",
        "permission": "config.item.rollback", "step_up": True, "write": True,
    },
    "killSwitchConfigItem": {
        "method": "POST", "path": "/api/v1/admin/config/{key}/kill-switch",
        "permission": "config.item.emergency", "step_up": True, "write": True,
    },
}
OPERATION_IDS = tuple(OPERATIONS)

#: 权限点（§21.7.2 / OPS-09：与既有细粒度点并存，本期不改名）
PERMISSIONS = frozenset({
    "config.item.read",
    "config.item.publish",
    "config.item.approve",
    "config.item.rollback",
    "config.item.emergency",
    "config.item.secret.read",      # 明文查看（§21.12.5 #6），非 spec 独立端点
    "config.audit.export",          # 审计导出（AUDIT 专属）
})

#: P0 审批人必须来自 FIN 或 AUDIT（§21.4.3）
APPROVER_ROLES_P0 = frozenset({"FIN", "AUDIT"})


# --------------------------------------------------------------------------- 异常
class OpsCenterError(RuntimeError):
    """管理面统一异常。``http_status`` / ``code`` 直接映射 §21.12.4 错误码表。

    错误码一律复用 §6.3b 已登记值，**不新造**（OPS-08：不开 42202）。
    """

    http_status = 400
    code = 40001
    type = "invalid_request_error"

    def __init__(self, message: str, *, details: list[dict] | None = None, code: int | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or []
        if code is not None:
            self.code = code

    def envelope(self, request_id: str | None = None) -> dict:
        """统一错误信封（spec `Error`）。"""
        err = {
            "type": self.type,
            "code": self.code,
            "message": self.message,          # 不含内部堆栈 / 规则细节 / 凭据
            "request_id": request_id or "",
        }
        if self.details:
            err["details"] = self.details
        return {"error": err}

    def __str__(self) -> str:                 # pragma: no cover - 便于日志
        return f"[{self.http_status}/{self.code}] {self.message}"


class FeatureDisabled(OpsCenterError):
    """开关关闭。404 而非 403：不暴露"这里本来能写"。"""

    http_status = 404
    code = 40401
    type = "not_found_error"


class BadRequest(OpsCenterError):
    http_status = 400
    code = 40001
    type = "invalid_request_error"


class Unauthorized(OpsCenterError):
    http_status = 401
    code = 40101
    type = "authentication_error"


class Forbidden(OpsCenterError):
    http_status = 403
    code = 40301
    type = "permission_error"


class NotFound(OpsCenterError):
    """对象不存在；越权访问配置项也统一 404（§21.12.4：越权统一 404，不泄露存在性）。"""

    http_status = 404
    code = 40401
    type = "not_found_error"


class Conflict(OpsCenterError):
    http_status = 409
    code = 40902
    type = "conflict_error"


class StepUpRequired(OpsCenterError):
    """缺 step-up 或超过 5 分钟有效期（§21.4.3 二次认证）。"""

    http_status = 424
    code = 42401
    type = "protocol_error"


class BreakGlassReadOnly(OpsCenterError):
    """break-glass 只读模式下拒绝任何写（§22.21 权限与密钥）。"""

    http_status = 423
    code = 42301
    type = "permission_error"
