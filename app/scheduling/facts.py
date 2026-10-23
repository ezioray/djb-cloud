# SPDX-License-Identifier: Apache-2.0
"""M04 scheduler-pricing · 常量（一份事实一个来源）。

本文件的每个常量都能追到出处，代码里**不再出现同义字面量**：

* **契约枚举**：`access` / `tier` / `outcome` / 取价策略 —— 来自 M04 §5「枚举」与 spec
  （`RouteRequest.kind`、`QuoteRequest.access`、`BidRequest.strategy`、`RouteDecision`）。
  改这些值必须先改契约（00-conventions §1.3）。
* **配置键**（M04 §8.1，Owner = M10）：这里只登记**键名与默认值 / 合法区间**；
  运行时值由 config-center 下发（经 ``config_source`` 的注入 provider），
  模块不得读环境变量里的业务常量（00-conventions §1.5）。
* **本模块常量**（M04 §8.2）：03-facts §13.4 明确不覆盖单模块内部算法常量
  （M06 同样处理，见 CR-L7），故留在本文件并逐条标注小节号。
* **淘汰码 / 原因码**：M04 §6 流程 2 的 P1 码表（F1–F5）与 §7 降级顺序。

金额一律 **USD 分**（``*_minor``，整数）；比例一律 **bps** 或 **milli**（整数），
禁止 float 进判定（00-conventions §3.1 / INV-13）。
"""
from __future__ import annotations

# --------------------------------------------------------------------------- 枚举（M04 §5 / spec）
ACCESS_TYPES: tuple[str, ...] = ("A1", "A2", "B")
"""``access`` 枚举（M04 §5「枚举」；与 spec、02-events 同源）。"""

TIERS: tuple[str, ...] = ("realtime", "batch")
"""请求档位（spec ``RouteRequest.kind``；INV-09 只允许 realtime 抢 batch）。"""

QUOTE_STATES: tuple[str, ...] = ("active", "consumed", "expired")
BID_STATES: tuple[str, ...] = ("active", "expired")
BOOKING_STATES: tuple[str, ...] = ("held", "consumed", "expired")
OUTCOMES: tuple[str, ...] = ("routed", "fallback", "queued", "rejected")
"""决策结果（M04 §5 枚举）；拒绝 / 排队必须给原因与下一步（INV-06）。"""

PRICE_STRATEGIES: tuple[str, ...] = ("mid", "floor", "ceiling")
"""取价策略（M04 §8.1 ``billing.price_strategy``；mid 默认 / floor 冷启动 / ceiling 供给紧张）。"""

MODEL_STATES: tuple[str, ...] = ("active", "deprecated", "retired")
QUOTA_WINDOWS: tuple[str, ...] = ("day", "week", "month")
"""配额窗口（M04 §3 QuotaUsage.window）；库列名 ``window_kind``（``window`` 是 PG 保留字）。"""

# --------------------------------------------------------------------------- P1 淘汰码（M04 §6 流程 2）
ELIMINATION_CODES: dict[str, str] = {
    "F1": "capability_mismatch",          # model slug（归一后）/ access / tier 与公告不一致
    "F2": "stale_or_offline",             # 心跳超新鲜度 或 state ≠ online
    "F3": "access_or_region_ineligible",  # 准入待审 / 冻结 / 清退、地域口径、档位不匹配
    "F4": "tenant_isolation",             # 白黑名单命中 / 同账户自成交
    "F5": "quote_invalid_or_no_intersection",  # 无有效报价，或与出价区间无交集
}
"""P1 淘汰码 → 粗粒度原因（M04 §6；对外只暴露粗粒度码，不含阈值）。"""

# --------------------------------------------------------------------------- 原因码（拒绝 / 排队 / 兜底）
REASON_CODES: dict[str, str] = {
    "no_candidates": "候选集为空（P1 全淘汰）",
    "no_quote": "无有效报价（P1 F5）",
    "no_intersection": "报价与出价区间无交集（INV-01）",
    "quota_exhausted": "配额 / 并发触顶（P3）",
    "spend_cap_exceeded": "每日花费上限（42902）",
    "affinity_violation": "反亲和硬约束命中（P3）",
    "share_exceeded": "单租户同模型并发占比超限（INV-08）",
    "preempt_budget_exhausted": "节点抢占预算用尽（INV-10）",
    "preempt_disabled": "抢占开关关闭（features.scheduling.p4_preemption）",
    "no_checkpoint": "无可用检查点，禁止入组网队列（INV-09）",
    "queue_full": "队列水位 95%，只保实时（§8.2）",
    "queue_tight": "队列水位 85%，开始收紧（§8.2）",
    "stale_snapshot": "快照过期，用最后有效快照并打 stale（§7）",
    "budget_exceeded": "超决策时延预算，降级放行并留痕（INV-05）",
    "tenant_widened": "终端试图放宽并发，已按平台值夹取并告警（INV-07）",
    "rep_missing": "信誉分缺失，兜底系数 0.80（§4.7.3 P2）",
    "load_missing": "负载缺失，按 load=1.00（§4.7.3 P2）",
}
"""决策原因码（只做粗粒度可见性；不含权重与阈值）。"""

#: 拒绝时必须给的三个可选动作（INV-06「拒绝也必须给原因与下一步」）
REJECT_ACTIONS: tuple[dict[str, str], ...] = (
    {"action": "retry_later", "hint": "稍后重试（决策会随报价簿刷新变化）"},
    {"action": "switch_model", "hint": "换一个模型（当前模型无可用供给）"},
    {"action": "raise_max_price", "hint": "放宽出价上限（价格与供给区间无交集）"},
)

#: 降级顺序（M04 §7 候选集为空）：换节点 → 换区域 → 转慢任务 → 中继 → 拒绝
FALLBACK_CHAIN: tuple[str, ...] = ("same_region_other_node", "other_region", "slow_task",
                                   "relay_network", "reject")

# --------------------------------------------------------------------------- 配置键（M04 §8.1，Owner M10）
CONFIG_KEYS: dict[str, str] = {
    "candidate_freshness_s": "routing.candidate_freshness_s",
    "quotebook_refresh_s": "routing.quotebook_refresh_s",
    "max_tenant_share_pct": "routing.max_tenant_share_pct",
    "preempt_budget_per_h": "routing.preempt_budget_per_h",
    "latency_lambda": "routing.latency_lambda",
    "tie_break_epsilon_bps": "routing.tie_break_epsilon_bps",
    "service_fee_bps": "billing.service_fee_bps",
    "price_strategy": "billing.price_strategy",
    "policy_version": "routing.policy_version",
}
"""M04 §8.1 配置键全名。运行时值来自 config-center；本模块不缓存、不写、不读环境变量。"""

CANDIDATE_FRESHNESS_S = 45          # routing.candidate_freshness_s，30–120，P1
QUOTEBOOK_REFRESH_S = 60            # routing.quotebook_refresh_s，30–120，P1
MAX_TENANT_SHARE_PCT = 25           # routing.max_tenant_share_pct，5–50，P2
PREEMPT_BUDGET_PER_H = 6            # routing.preempt_budget_per_h，1–12，P2
TIE_BREAK_EPSILON_BPS = 300         # routing.tie_break_epsilon_bps，0–1000，P2
LATENCY_LAMBDA_DEFAULT = 1.0        # routing.latency_lambda 全局倍率，0.5–10.0，P2
PRICE_STRATEGY_DEFAULT = "mid"      # billing.price_strategy：mid / floor / ceiling
SERVICE_FEE_BPS = 1500              # billing.service_fee_bps（只读；费率计算归 M05/M06）

# --------------------------------------------------------------------------- 本模块常量（M04 §8.2）
DECISION_LATENCY_P99_MS: dict[str, int] = {"token": 20, "task": 2_000, "fabric": 10_000}
"""决策时延 P99 预算（INV-05）：token ≤20 ms / 任务 ≤2 s / 组网准入 ≤10 s。"""

RHO_MIN_MILLI = 500                 # ρ ∈ [0.50, 1.20]，以 milli 存（§8.2）
RHO_MAX_MILLI = 1_200
KAPPA_MIN_MILLI = 1_000             # κ ∈ [1.00, 3.00]，以 milli 存（§8.2）
KAPPA_MAX_MILLI = 3_000
RHO_MISSING_MILLI = 800             # 信誉分缺失 → 兜底系数 0.80（product §4.7.3 P2）
KAPPA_MISSING_MILLI = 1_000         # 负载缺失 → load=1.00（product §4.7.3 P2）
KAPPA_CIRCUIT_MILLI = 2_500         # κ ≥ 2.50 持续 60 s → 熔断（§8.2）
CIRCUIT_SUSTAIN_S = 60
CIRCUIT_FAIL_RATE_BPS = 3_000        # 5 min 失败率 >30%
CIRCUIT_OPEN_S = 600                # 熔断 10 min

#: 延迟代价 λ（分 / ms 当量，product §4.7.3）：realtime 1.0 / batch 2.5 / fabric 4.0
LATENCY_LAMBDA_MICRO: dict[str, int] = {"realtime": 1_000_000, "batch": 2_500_000,
                                        "fabric": 4_000_000}
"""λ 以**微分**（1e-6 分）存，避免浮点；元组是「通道 → 常量」。"""

GINI_MAX_MILLI = 350                # 基尼 ≤0.35（公平观测，§8.2）
SMALL_NODE_MEDIAN_WAIT_S = 300      # 小节点中位等待 >5 min 触发公平告警
PREEMPT_GRACEFUL_S = 30             # 优雅中断 ≤30 s（§8.2）
ANTI_STARVATION_S = 1_800          # 等待 >30 min 进优先队列
MAX_REDISPATCH = 3                  # 重派次数 ≤3 次：同节点 → 换节点 → 换区域
COLD_START_UNITS = 10               # 冷启动权重：前 10 个调度单元
COLD_START_WEIGHT_MAX_MILLI = 300   # ≤0.3（渐进放量）
QUEUE_WATERMARK_PCT: tuple[int, int, int] = (70, 85, 95)   # 提示 / 收紧 / 只保实时
TIE_EPSILON_DEFAULT_BPS = 300       # 同分带宽 300 bps（§8.2）
TIE_EPSILON_MAX_BPS = 1_000         # routing.tie_break_epsilon_bps 上限（§8.1）
BOOKING_TTL_S = 60                  # 成交锁 60 s（§8.2）
MAX_ATTEMPTS = 2                    # 一次请求最多 2 次尝试（INV-12）
DISPATCH_RETRY_MAX = 2              # 派发失败同 key 重试 ≤2 次（§7）

#: 报价 / 决策 / 配额保留（§8.2 + M04 §5）
QUOTE_RETENTION_DAYS = 90
DECISION_RETENTION_MONTHS = 12
QUOTA_RETENTION_MONTHS = 13

# --------------------------------------------------------------------------- 金额（INV-13）
AMOUNT_SCALE = 100                  # USD 分 = 2 位小数；超精度直接拒绝
CURRENCY = "USD"                    # S1 仅 USD
MAX_PRICE_MINOR = 1_000_000_000     # 单笔报价 / 出价上界（USD 1000 万），防溢出与脏数据
DEFAULT_BID_WINDOW_S = 3_600        # 出价窗口缺省值（spec window_seconds 可选）
MAX_BOOKING_QTY_PER_REQUEST = 1      # 一次请求只锁一个成交（只计费一次，INV-12）

# --------------------------------------------------------------------------- 幂等 / 事件（M04 §3 / §4.2）
IDEMPOTENCY_TTL_HOURS = 24
IDEMPOTENCY_SCOPE_MAX_LEN = 64
IDEMPOTENCY_KEY_MAX_LEN = 128

EVENT_PRODUCER = "M04"
EVENT_AGGREGATE_TYPE: dict[str, str] = {
    "quote.created": "quote",
    "quote.expired": "quote",
    "booking.created": "booking",
    "booking.expired": "booking",
    "routing.decided": "routing_decision",
}
EVENT_TYPES: tuple[str, ...] = tuple(EVENT_AGGREGATE_TYPE)
"""M04 生产的 5 个事件（02-events §3 / M04 §4.2）。**未登记的事件不得上线**。"""

EVENT_VERSION = 1
EVENT_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    # 02-events §3 + M04 §4.2「关键字段」
    "quote.created": ("quote_id", "node_id", "model", "price_minor", "ttl_s"),
    "quote.expired": ("quote_id", "node_id", "model", "price_minor", "ttl_s"),
    "booking.created": ("booking_id", "node_id", "request_id", "expires_at"),
    "booking.expired": ("booking_id", "node_id", "request_id", "expires_at"),
    "routing.decided": ("request_id", "node_id", "reason_codes", "snapshot_id"),
}
"""每个事件的必含业务键（库 / 测试双端校验；值可空但键必须在）。"""

# --------------------------------------------------------------------------- 只读依赖（01-ownership §2）
NODE_SNAPSHOT_VIEW = "v_supply_node_snapshot"        # M02 只读视图（禁止 import 对方包）
CAPACITY_LATEST_VIEW = "v_supply_capacity_latest"    # M02 只读视图（已过滤过期与 0 容量）

#: 决策锚点的默认 policy_version（M10 未接线时用固定 12 位十六进制，保持可复算）
DEFAULT_POLICY_VERSION = "000000000000"
POLICY_VERSION_PATTERN = r"^[0-9a-f]{12}$"

#: 公开快照默认周期（GET /api/v1/schedule/snapshot/{period}）
SNAPSHOT_PERIOD_LATEST = "latest"

__all__ = [name for name in dir() if name.isupper()] + [
    "CONFIG_KEYS", "ELIMINATION_CODES", "REASON_CODES", "REJECT_ACTIONS", "FALLBACK_CHAIN",
    "EVENT_PAYLOAD_KEYS",
]
