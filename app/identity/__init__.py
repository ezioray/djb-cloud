# SPDX-License-Identifier: Apache-2.0
"""M01 identity-tenant（DEV-M01-T1：账户 / 组织 / 租户模型 + 五态机 + 迁移 1xx）。

本包是 M01 的**唯一写入口**，也是 8 张身份表的唯一写者（01-ownership §2）::

    users · user_accounts · orgs · org_members · api_keys · sessions · role_bindings · tenant_quotas

分层（M01 §0 目标路径的精简版）::

    models.py       领域模型 + 数据访问（含 Key 哈希、配额 min、租户隔离）
    state.py        账户五态机 + 冻结期限 + 注销三步
    facts.py        03-facts §8 常量（CR-4：从 contracts/facts.yaml 读）
    credentials.py  口令 / MFA 因子 / 令牌派生（只出哈希，不落明文）
    mfa.py          MFA 因子生命周期（none → pending → enabled）
    tokens.py       会话与令牌（登录 / 刷新轮换 / 登出 / 鉴权 / step-up）
    scan.py         扫码登录中间态（120 s，一次性）
    router.py       HTTP 路由（T2 的 5 个 spec 操作；不接 app/api.py）
    admin.py        管理面领域（冻结 / 解冻 / 角色 SoD / 配额版本）
    migrate.py      1xx 迁移与回滚（证据用 CLI）

边界：不 import 任何其它 ``app.*`` 业务模块；不读 M06 / M10 基表；
不实现登录 / 会话 / HTTP 端点（T2 起）；不建第二套后台用户表。
"""
from __future__ import annotations

from . import (admin, clock, credentials, errors, facts, mfa, migrate, models, router, scan,
               state, tokens)
from .models import (
    ACCOUNT_STATES,
    ACCOUNT_TYPES,
    ADMIN_ROLES,
    CLOSING_COOLOFF_DAYS,
    FREEZE_MAX_DAYS,
    INVITE_TTL_HOURS,
    KEY_MAX_PER_ACCOUNT,
    KEY_PREFIX_LEN,
    ORG_ROLES,
    QUOTA_KINDS,
    ROLE_RECLAIM_DAYS,
    SEATS,
)
from .state import TRANSITIONS, can_transition, legal_targets

__version__ = "0.2.0-dev-m01t2"

__all__ = [
    "models", "state", "migrate", "facts", "credentials", "mfa", "tokens", "scan",
    "errors", "router", "clock", "admin",
    "ACCOUNT_STATES", "ACCOUNT_TYPES", "ADMIN_ROLES", "ORG_ROLES", "QUOTA_KINDS",
    "FREEZE_MAX_DAYS", "CLOSING_COOLOFF_DAYS", "INVITE_TTL_HOURS", "ROLE_RECLAIM_DAYS",
    "KEY_PREFIX_LEN", "KEY_MAX_PER_ACCOUNT", "SEATS",
    "TRANSITIONS", "can_transition", "legal_targets",
]
