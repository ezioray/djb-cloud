# SPDX-License-Identifier: Apache-2.0
"""M16 审计链常量（与 ``ops/audit/policy.mjs`` 一一对应，改一处必须同步改另一处）。

来源：M16-platform-infra.md §3（不变量）/ §4.1（接口）/ §5（表与索引）/ §6.3（流程）/ §8.2（常量）
      spec-1.2.2 ``AuditEntry`` / ``AuditAppendRequest`` / ``AuditVerifyRequest``
      ops/audit/policy.mjs（HIGH_RISK_ACTION / REQUIRED_ON_HIGH_RISK / REQUIRE_HMAC_ENV）
"""
from __future__ import annotations

import os
import re
from datetime import timedelta

# ────────────────────────────────────────────────────────────── 链
#: 算法（M16 §8.2 ``audit_alg``；spec AuditEntry.alg 唯一枚举值）
ALG = "hmac-sha256"

#: 链首的前向引用（M16 §3：``audit: GENESIS → entry(1..n) → daily_root``）
GENESIS = "GENESIS"

#: 链哈希消息分隔符：``hmac(key, prev_hash + "\n" + canonical_json(entry))``
MESSAGE_SEPARATOR = "\n"

#: 参与链哈希的条目字段（= M16 §5 audit_log 列去掉 hash；顺序即 canonical 的键集）
ENTRY_FIELDS: tuple[str, ...] = (
    "seq", "entry_id", "ts", "actor", "actor_type", "role", "action", "target",
    "before", "after", "reason_code", "ticket", "evidence", "approval_chain",
    "status", "alg", "prev_hash",
)

# ────────────────────────────────────────────────────────────── 枚举
ACTOR_TYPES: tuple[str, ...] = ("human", "agent", "service", "lead")
STATUSES: tuple[str, ...] = ("recorded", "pending_approval", "approved", "rejected", "revoked")
DECISIONS: tuple[str, ...] = ("propose", "approve", "execute", "reject")

#: 追加时缺省状态（与 ops/audit/append.mjs 一致）
DEFAULT_STATUS = "recorded"

# ────────────────────────────────────────────────────────────── 策略（与 policy.mjs 同步）
#: 高危动作前缀（ops/audit/policy.mjs HIGH_RISK_ACTION，逐字一致）
HIGH_RISK_ACTION = re.compile(
    r"^(reverse|freeze|unfreeze|fee|routefn|revoke|retire|export|settle|grant|window"
    r"|authorize|release|rollback|migrate)",
    re.IGNORECASE,
)

#: 高危动作必须齐备的字段（M16 INV-M16-02：reason_code / ticket / actor_type / role / before / after）
HIGH_RISK_REQUIRED: tuple[str, ...] = (
    "reason_code", "ticket", "actor_type", "role", "before", "after",
)

#: 复核类动作：必须有审批链（propose ≠ approve；M16 INV-M16-02「propose / approve / execute 不同人」）
APPROVAL_ACTION = re.compile(r"^(approve|authorize|execute|release)\.", re.IGNORECASE)

#: ``pending_approval`` 超时（M16 §6.3 / ops/audit/verify.mjs：默认 4 小时，超时作废，不得自动放行）
PENDING_TIMEOUT = timedelta(hours=4)

# ────────────────────────────────────────────────────────────── 字段上限（与 1400 约束一致）
MAX_ACTOR_LEN = 128
MAX_ROLE_LEN = 64
MAX_ACTION_LEN = 64
MAX_TARGET_LEN = 256
MAX_REASON_LEN = 64
MAX_TICKET_LEN = 64
MAX_EVIDENCE_LEN = 512
MIN_IDEMPOTENCY_LEN = 16           # spec IdempotencyKey.minLength
MAX_IDEMPOTENCY_LEN = 128          # spec IdempotencyKey.maxLength
MAX_CHAIN_ITEMS = 20               # 一条审批链最多 20 人（防滥用）

#: 请求体指纹去重窗口（00-conventions §5：非流式请求体指纹 300s）
FINGERPRINT_WINDOW_S = 300

# ────────────────────────────────────────────────────────────── 分页（spec Page / Limit）
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# ────────────────────────────────────────────────────────────── 事件（02-events §3 / M16 §4.2）
EVENT_TYPE = "audit.appended"
EVENT_VERSION = 1
EVENT_PRODUCER = "M16"
EVENT_AGGREGATE_TYPE = "audit_entry"
EVENT_PAYLOAD_KEYS: tuple[str, ...] = ("audit_id", "actor", "action", "hash", "seq")

# ────────────────────────────────────────────────────────────── 密钥（fail-closed）
#: 密钥只从这个环境变量拿**路径**（不拿明文；M16 §1「密钥由决策人保管并路径注入」）
KEY_FILE_ENV = "DJB_AUDIT_HMAC_KEY_FILE"
#: 密钥最小长度（弱密钥直接拒绝，避免"配了等于没配"）
MIN_KEY_BYTES = 16

# ────────────────────────────────────────────────────────────── 其它
#: 服务版本（spec 版本；可用 DJB_SERVICE_VERSION 覆盖，healthz 回显）
SERVICE_VERSION = os.environ.get("DJB_SERVICE_VERSION", "1.2.2")

#: 未知字段忽略（spec：tolerant reader / additionalProperties: true），这里只记录已知字段
KNOWN_REQUEST_FIELDS: tuple[str, ...] = (
    "actor", "actor_type", "role", "action", "target", "before", "after",
    "reason_code", "ticket", "evidence", "approval_chain", "status", "alg",
)
