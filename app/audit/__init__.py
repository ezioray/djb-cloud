# SPDX-License-Identifier: AGPL-3.0-or-later
"""M16 platform-infra · 审计链（只追加 HMAC 哈希链 + 每日 Merkle 根）。

本包是 M16 §4.1 / §6.3 的服务端实现，语义与现行运维链完全一致：

* ``ops/audit/append.mjs``（追加：HMAC-SHA256、``prev_hash``、GENESIS 起点、高危字段、锁串行化）
* ``ops/audit/verify.mjs``（校验：逐条重算、算法一致、双人复核、字段完整、pending 超时、``--seal``）

与运维链的唯一差别是**存储**：从 ``ops/audit/chain.jsonl`` 换成数据库热表 ``audit_log``
（迁移 1400–1499），因此并发串行化从文件锁换成 ``pg_advisory_xact_lock``。

模块边界（01-ownership §2 / 00-conventions §1）：

* 本包只写 ``audit_log`` / ``audit_anchors`` / ``m16_outbox``；不读任何业务表；
* 不 import 其它模块的内部包（``app.ledger`` / ``app.metering`` …），只依赖 stdlib + psycopg + fastapi；
* 路由用 ``create_router(...)`` / ``create_health_router(...)`` 工厂注入依赖，
  **不**在 ``app/api.py`` 里接线（由 Lead 合并时统一 include）。

密钥（M16 §1 / 05-security S6）：

* 只从 ``DJB_AUDIT_HMAC_KEY_FILE``（文件路径，权限 0600）或注入的 key provider 读取；
* 缺失 / 权限不对 / 空文件 → **fail-closed**：写入 423 + 42301，verify 返回 ``ok=false``（不静默通过）；
* 密钥不进日志、不进数据库、不进证据文件，``repr`` 一律脱敏。
"""
from __future__ import annotations

from .errors import (
    AuditError,
    ChainLocked,
    Conflict,
    Forbidden,
    InvalidArgument,
    ServiceUnavailable,
    Unauthorized,
)
from .health import create_health_handler, create_health_router
from .keys import FileKeyProvider, KeyProvider, StaticKeyProvider, from_env
from .router import create_router

__all__ = [
    "AuditError",
    "ChainLocked",
    "Conflict",
    "Forbidden",
    "InvalidArgument",
    "ServiceUnavailable",
    "Unauthorized",
    "FileKeyProvider",
    "KeyProvider",
    "StaticKeyProvider",
    "from_env",
    "create_router",
    "create_health_handler",
    "create_health_router",
    "SERVICE_VERSION",
]

#: 服务版本（/healthz 回显；与 spec 版本对齐，可用 DJB_SERVICE_VERSION 覆盖）
from .facts import SERVICE_VERSION  # noqa: E402  (放末尾避免循环导入时的顺序问题)
