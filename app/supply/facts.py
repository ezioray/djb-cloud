# SPDX-License-Identifier: Apache-2.0
"""M02 node-supply · 常量（一份事实一个来源）。

本文件的每个常量都能追到出处，代码里**不再出现同义字面量**：

* **模块常量**（M02 §8.1 配置键默认值 / §8.2 本模块常量 / §3 不变量）：03-facts 明确不覆盖
  单模块内部算法常量（M01 同样处理），故常量留在本文件，逐条标注 M02 小节号。
* **契约派生**（spec 1.2.x）：枚举、协议矩阵、限定长度等来自 spec / 04-api-contracts，
  改这些值必须先改契约（00-conventions §1.3「共享契约只有 5 份」）。
* **配置键**（M10 管理）：这里只登记**键名与默认值**；运行时值由 config-center 下发，
  模块不得读环境变量里的业务常量（00-conventions §1.5）。T1/T2 未接 config-center，
  默认值与 §8.1 一致，T3 起改为从快照读取。
"""
from __future__ import annotations

# --------------------------------------------------------------------------- 枚举（M02 §5）
NODE_STATES: tuple[str, ...] = ("pending", "active", "frozen", "retired")
"""``nodes.lifecycle_state`` 枚举（M02 §5；与存量 003 的 CHECK 一致）。

在线 / 离线是**派生只读视图**（§3「一层权威 + 一层派生，不得混用」），不是状态：
见 ``state.derive_presence()`` / ``state.derive_online()``。
"""
PRESENCE_STATES: tuple[str, ...] = ("online", "stale", "offline")
"""派生视图取值（§3）；另有 ``never``（从未上报）仅由派生函数返回，不入库。"""

PLATFORMS: tuple[str, ...] = ("macos", "windows", "linux")     # spec NodeRegisterRequest.platform
ACCESS_TYPES: tuple[str, ...] = ("A1", "A2", "B")               # M02 §5 / §5.4.1
UPSTREAM_STATES: tuple[str, ...] = ("declared", "probing", "verified", "rejected")  # M02 §3
CAPACITY_KINDS: tuple[str, ...] = ("token_relay", "gpu", "ram", "fabric")            # M02 §5
POLICY_STATUSES: tuple[str, ...] = ("active", "superseded")     # M02 §3 / 202 迁移

RUNTIME_STATES: tuple[str, ...] = ("unbound", "online", "quota_exhausted",
                                   "yield_paused", "user_paused", "error")
"""客户端运行态**约定值**（spec 1.2.0 heartbeat ``runtime_state`` 描述 / CR-5）。

服务端不把这些值当状态机用（M02 §3 注）：只作为调度输入原样登记；
未知值**忽略且不报错**（spec 描述），库层也不加 CHECK（``nodes.runtime_state`` 是自由 TEXT）。
"""

# --------------------------------------------------------------------------- 配置键（M02 §8.1，Owner M10）
CONFIG_NAMESPACE = "supply"
HEARTBEAT_INTERVAL_S = 30          # supply.heartbeat_interval_s，范围 10–120，P1
STALE_AFTER_S = 45                 # supply.stale_after_s，范围 30–300，P1
ANNOUNCEMENT_TTL_S = 60            # supply.announcement_ttl_s，范围 30–300，P1
MAX_NODES_PER_ACCOUNT = 100        # supply.max_nodes_per_account，范围 1–1000，P2
REVIEW_SLA_H = 24                  # supply.review_sla_h，范围 1–72，P2

CONFIG_KEYS: dict[str, str] = {
    "heartbeat_interval_s": "supply.heartbeat_interval_s",
    "stale_after_s": "supply.stale_after_s",
    "announcement_ttl_s": "supply.announcement_ttl_s",
    "max_nodes_per_account": "supply.max_nodes_per_account",
    "review_sla_h": "supply.review_sla_h",
}
"""配置键全名（M02 §8.1）。T3 起从 config-center 快照读取；本模块不缓存、不写。"""

# --------------------------------------------------------------------------- 本模块常量（M02 §8.2）
HEARTBEAT_MIN_INTERVAL_S = 5       # 心跳最短间隔（防刷；超限 42901）
OFFLINE_AFTER_CYCLES = 3           # 离线判定 = 3 个心跳周期
KEY_OVERLAP_MAX_S = 86_400         # 密钥重叠窗口 24 h（INV-10）
KEY_PREFIX_LEN = 8                 # 只展示 / 排障，不能用于鉴权
KEY_ENTROPY_BYTES = 32             # 256 bit 不透明密钥（与 M01 同口径）
POLICY_HISTORY_MONTHS = 12         # 策略版本历史（只读）
RETIRE_DRAIN_MINUTES = 30          # 清退在途等待（超时后摘除，INV-09）
MAX_UPSTREAMS_PER_NODE = 16        # 单节点上游上限（超出 40001）
MAX_MODELS_PER_UPSTREAM = 200      # 单上游模型上限（超出 40001）
MAX_CAPABILITIES_PER_ANNOUNCEMENT = 200   # 公告单批上限（超出 40001）

BINDING_CODE_TTL_S = 600           # 一次性绑定码默认时效（spec：一次性、短时效；库层 ≤1 h）
BINDING_CODE_MAX_ATTEMPTS = 5      # 单码最多尝试次数（防爆破）
BINDING_CODE_ENTROPY_BYTES = 24    # 192 bit

# --------------------------------------------------------------------------- 隐私与凭据（INV-03 / INV-04）
FINGERPRINT_MIN_LEN = 16           # 硬件指纹哈希最短（客户端本地算好后上报）
FINGERPRINT_MAX_LEN = 256
SUSPECT_CREDENTIAL_MIN_LEN = 16    # 疑似凭据字段的「值长度」阈值（INV-04）
SUSPECT_CREDENTIAL_FIELDS: tuple[str, ...] = (
    "key", "apikey", "api_key", "secret", "token", "password", "passwd", "credential",
)
CREDENTIAL_FIELD_ALLOWLIST: tuple[str, ...] = (
    "credential_handle",           # spec NodeUpstreamRequest：只提交句柄，服务端不解析
)
SECRET_VALUE_MIN_LEN = 16          # 同上（值长度阈值），单独命名便于测试引用

# --------------------------------------------------------------------------- 协议（M02 §1 / INV-05）
PROTOCOL_VERSION = "1.0.0"         # 服务端当前版本（spec NodeRegisterRequest pattern 同形）
PROTOCOL_PATTERN = r"^[0-9]+\.[0-9]+\.[0-9]+$"
PROTOCOL_SUPPORT_DEPTH = 3         # N / N-1 / N-2
PROTOCOL_CAPABILITY_HEADER = "X-DJB-Capabilities"
DEPRECATION_MIN_DAYS = 90          # 弃用提前 ≥90 天
DEPRECATION_MIN_MAJORS = 2         # 且 ≥2 个 MAJOR
CAPABILITY_STATUSES: tuple[str, ...] = ("stable", "beta", "deprecated")
"""能力状态枚举（spec ``ProtocolCapabilities.capabilities[].status``）。

服务端**能力清单**（含版本与状态）在 ``protocol.CAPABILITIES`` 单点定义，facts 只放枚举。
"""

# --------------------------------------------------------------------------- 幂等与事件
IDEMPOTENCY_TTL_HOURS = 24         # M02 §3 幂等段（00-conventions §5 同窗口）
IDEMPOTENCY_SCOPE_MAX_LEN = 64
IDEMPOTENCY_KEY_MAX_LEN = 128

EVENT_PRODUCER = "M02"
EVENT_AGGREGATE_TYPE = "node"
EVENT_TYPES: tuple[str, ...] = (
    "node.registered",
    "node.state.changed",
    "node.upstream.changed",
    "capacity.announced",
)
"""M02 生产的 4 个事件（02-events §3 / M02 §4.2）。**未登记的事件不得上线**。"""

# --------------------------------------------------------------------------- 用户态节点面（spec 1.2.6）
USER_NODE_VIEW_STATES: tuple[str, ...] = ("unbound", "pending_receipt", "bound", "revoked")
"""绑定视图状态（spec ``UserNode.state``；由 ``nodes`` 列派生的只读视图，不落库）。"""
USER_NODE_DEFAULT_PAGE_SIZE = 50       # spec Limit default 50（04-api-contracts §2 约定 2）
USER_NODE_MAX_PAGE_SIZE = 200          # spec Limit maximum 200
USER_NODE_MAX_CURSOR_LEN = 512         # spec Cursor maxLength 512
USER_UNBIND_REASON_MAX_LEN = 512       # spec UserNodeUnbindRequest.reason maxLength 512
NODE_EVENT_REASON_MAX_LEN = 500        # migrations/203 node_events.reason CHECK ≤500
MAX_NODE_ID_LEN = 128                  # nodes.id TEXT 的实用上限（与 M05 MAX_ID_LEN 同量级）

# 审核决策（spec NodeReviewRequest.decision）
REVIEW_DECISIONS: tuple[str, ...] = ("approve", "reject")
REVIEW_REASON_MAX_LEN = 500

__all__ = [name for name in dir() if name.isupper()] + ["CONFIG_KEYS"]
