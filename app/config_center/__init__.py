# SPDX-License-Identifier: Apache-2.0
"""M10 config-center（DEV-M10 T1+T2：schema 注册 + 校验器 + 版本存储 + digest + 幂等）。

本包是配置中心的**领域层**，不注册任何 HTTP 路由（T3/T4 才接管理面 ``/api/v1/admin/config/*``），
也不碰 ``app/admin/ops_center.py``（只读适配器，DEC-0004 遗留）。分层::

    facts.py        contracts/facts.yaml 读取层（M10 §9 / §4 / §2 的默认值与阈值，只读）
    errors.py       47xxx 码值（47001–47009 + 40919 + 42401）的类型化错误，不做 HTTP 包装
    units.py        单位与量纲（bps / pct / USD / USD 分 / 秒 / 分 / 时 / 天 / count / clock / window）
    canonical.py    规范化 JSON + sha256（INV-01 content_digest；INV-08 snapshot_digest）
    registry.py     十域键注册表（§21.1.1）：36 键，含 JSON Schema 2020-12 与八个 x-djb-*
    validators.py   类型 / 范围 / 枚举 / 跨字段 / 危险键 / 密钥形态 / expire_at（纯函数）
    features.py     特性开关登记（owner / expire_at / rollback_rule，默认关闭，无可写面）
    store.py        版本存储（只追加）、digest 复算、幂等键、原子切换原语
    migrate.py      1000–1004 迁移的 up / down / status

边界（_boundary-checks §1）：不 import 其它 ``app.*`` 业务模块；不写别人的表；不带业务数字
（facts.yaml + 注册表 + 迁移 CHECK 三处对齐）；T1/T2 不建任何可写开关、不接路由、不发事件。
"""
from __future__ import annotations

from . import (canonical, dispatcher, drift, errors, facts, features, migrate, outbox, publish,
               registry, snapshot, store, units, validators)
from .canonical import (
    canonical_json,
    policy_version,
    request_digest,
    sha256_hex,
    snapshot_digest,
    version_digest,
)
from .errors import (
    ERROR_CODES,
    ApproverNotAllowed,
    StateConflict,
    CooldownActive,
    ConfigCenterError,
    CrossFieldViolation,
    DangerousKeyForbidden,
    FactsError,
    GrayPlanInvalid,
    IdempotencyConflict,
    KeyLocked,
    OutsidePublishWindow,
    RangeViolation,
    SecretShapeForbidden,
    SelfApprovalForbidden,
    StepUpRequired,
    TypeMismatch,
    UnitViolation,
    UnknownKey,
    ValidationFailed,
    VersionNotFound,
)
from .features import FEATURE_SWITCHES, FeatureSwitch, enabled
from .migrate import BASE_MIGRATIONS, M10_TABLES, MODULE_MIGRATIONS, down, up
from .registry import (
    AUX_NAMESPACES,
    DOMAINS,
    FORBIDDEN_KEY_PATTERNS,
    MISSING,
    ConfigKey,
    Domain,
    Registry,
    forbidden_reason,
)
from .store import (
    IDEMPOTENCY_TTL,
    activate,
    create_draft,
    get_version,
    list_versions,
    recompute_digests,
    sync_items,
    verify_version,
)
from .validators import (
    ValidationResult,
    check_publishable,
    check_writable,
    validate_cross_field,
    validate_group,
    validate_secret_ref,
    validate_value,
)

__all__ = [
    # 子模块
    "canonical", "dispatcher", "drift", "errors", "facts", "features", "migrate", "outbox",
    "publish", "registry", "snapshot", "store", "units", "validators",
    # 摘要
    "canonical_json", "sha256_hex", "version_digest", "request_digest", "snapshot_digest",
    "policy_version",
    # 错误
    "ERROR_CODES", "ConfigCenterError", "ValidationFailed", "UnknownKey", "TypeMismatch",
    "UnitViolation", "RangeViolation", "CrossFieldViolation", "SecretShapeForbidden",
    "DangerousKeyForbidden", "KeyLocked", "CooldownActive", "VersionNotFound", "GrayPlanInvalid",
    "OutsidePublishWindow", "StepUpRequired", "SelfApprovalForbidden", "ApproverNotAllowed",
    "StateConflict", "IdempotencyConflict", "FactsError",
    # 注册表
    "MISSING", "ConfigKey", "Domain", "Registry", "DOMAINS", "AUX_NAMESPACES",
    "FORBIDDEN_KEY_PATTERNS", "forbidden_reason",
    # 校验
    "ValidationResult", "check_writable", "check_publishable", "validate_value",
    "validate_group", "validate_cross_field", "validate_secret_ref",
    # 存储
    "IDEMPOTENCY_TTL", "sync_items", "create_draft", "activate", "get_version", "list_versions",
    "verify_version", "recompute_digests",
    # 迁移
    "MODULE_MIGRATIONS", "BASE_MIGRATIONS", "M10_TABLES", "up", "down",
    # 特性开关
    "FeatureSwitch", "FEATURE_SWITCHES", "enabled",
]
