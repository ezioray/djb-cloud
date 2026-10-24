# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 model-sync 常量（唯一来源；业务代码不得再写字面量）。

口径来源：

* ``M18-model-sync.md`` §3（数据模型 1800–1899）/ §4（采集与发布，TTL 24 h、回滚只改指针）/
  §8（接口）/ §9（特性开关三字段）/ §10（安全与隐私：只分发元数据 / 指纹）；
* ``task-17`` 任务卡与 lead 2026-10-24 的 wire 形状（node catalog / state / admin）。

**不写凭据**：签名密钥只从环境变量读（:data:`SIGNING_KEY_ENV`），本文件不含任何密钥材料。
"""
from __future__ import annotations

from datetime import timedelta
from typing import Final

MODULE_ID: Final[str] = "M18"
MODULE_RANGE: Final[tuple[int, int]] = (1800, 1899)

# ───────────────────────────────────────────────────────── 表（01-ownership 待登记，CR-M18-01）
VENDOR_MODELS_TABLE: Final[str] = "vendor_models"
BUNDLES_TABLE: Final[str] = "model_sync_bundles"
EVENTS_TABLE: Final[str] = "model_sync_events"
NODE_STATE_TABLE: Final[str] = "node_model_sync_state"

M18_TABLES: Final[tuple[str, ...]] = (
    VENDOR_MODELS_TABLE, BUNDLES_TABLE, EVENTS_TABLE, NODE_STATE_TABLE)
M18_FUNCTIONS: Final[tuple[str, ...]] = (
    "m18_bundles_guard", "m18_events_guard", "m18_forbid_truncate")

# ───────────────────────────────────────────────────────── 枚举（§3 / lead wire）
MODEL_STATES: Final[tuple[str, ...]] = ("active", "retired")
MODEL_SOURCES: Final[tuple[str, ...]] = ("vendor_api", "sdk", "admin")
"""采集来源（§4）：厂商 API / 官方 SDK 包元数据 / 管理员上传。"""

BUNDLE_STATES: Final[tuple[str, ...]] = ("draft", "published", "revoked", "rolled_back")
BUNDLE_SOURCES: Final[tuple[str, ...]] = ("registry", "vendor_api", "sdk", "admin", "rollback")

EVENTS: Final[tuple[str, ...]] = (
    "draft", "published", "revoked", "rolled_back", "state_applied")
"""``model_sync_events.event``（只追加；state_applied 也进同一流水，便于按版本对账）。"""

# ───────────────────────────────────────────────────────── 限额
TTL: Final[timedelta] = timedelta(hours=24)
"""§4：bundle TTL 默认 24 h；超过 72 h 由读方标 stale（本卡只发布 expires_at）。"""

MAX_MODELS: Final[int] = 500
MAX_ALIASES: Final[int] = 16
MAX_FIELD_LEN: Final[int] = 128
MAX_ERROR_CLASS_LEN: Final[int] = 64
MAX_LIST_LIMIT: Final[int] = 200
DEFAULT_LIST_LIMIT: Final[int] = 50

TOKENIZER_HASH_LEN: Final[int] = 64
"""tokenizer_hash 形态：64 位 hex（sha256）；本卡存**占位**指纹，不是厂商权重。"""

# ───────────────────────────────────────────────────────── 签名（§4 / §10）
SIGNING_KEY_ENV: Final[str] = "DJB_MODEL_SYNC_KEY"
SIGNING_ALG: Final[str] = "hmac-sha256"
SIGNING_PREFIX: Final[str] = SIGNING_ALG + ":"
SIGNING_KEY_MIN_LEN: Final[int] = 32
"""S2 过渡期用 HMAC-SHA256（S3 换 Ed25519）；密钥 <32 字符视为未配置（fail-closed）。"""

# ───────────────────────────────────────────────────────── 开关（§9，三字段，默认关）
ENABLED_FLAG: Final[str] = "model.sync.enabled"
AUTO_PUBLISH_FLAG: Final[str] = "model.sync.auto_publish"
ACTIVATION_ENV: Final[str] = "DJB_MODEL_SYNC"
"""S2 测试网显式激活：``DJB_MODEL_SYNC=1``；代码默认仍关闭。"""

# ───────────────────────────────────────────────────────── 错误 / 原因码
REASONS: Final[tuple[str, ...]] = (
    "invalid_request", "unauthorized", "forbidden", "not_found", "conflict",
    "feature_disabled", "signing_key_missing", "signature_invalid", "state_invalid",
    "server_error",
)
"""对外 reason 只给这些短码（机器可判；不含阈值 / 名单 / 密钥信息）。"""

#: node 侧一次返回的最大模型数（超过则由客户端分页？本卡不做分页：bundle 是单个快照）
NODE_CATALOG_SINCE_MAX: Final[int] = 1_000_000
