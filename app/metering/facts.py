# SPDX-License-Identifier: Apache-2.0
"""M05 metering-receipt · 常量与枚举（**唯一来源**，业务代码不得再写字面量）。

逐条标注出处；凡是 03-facts 已有的口径一律引用不复制，本文件只放：

* M05 §8.2「本模块常量」（批量上限 / 签名算法 / 6 个规范字段 / 差异阈值 / 复核门槛 / 保留）；
* M05 §8.1「配置键」的**默认值与取值范围**（运行期生效值由 M10 注入，见 ``config_source``）；
* M05 §5 的枚举与索引口径、表清单；
* spec 1.2.x / 04-api-contracts 的错误码段、分页与金额形状；
* 02-events §3 里本模块生产的 3 个事件与其 payload 必含字段。

金额口径（00-conventions §3 / 03-facts §6）：一律**整数最小单位**，S1 是 USD 分
（``amount_minor``，2 位小数）；单价按 micro-USD（1e-6 USD，与 M06 ``unit_scale=6`` 同源）
参与乘法，换算成「分」时必须整除，否则按「超精度直接拒绝，不四舍五入」处理（INV-05）。
"""
from __future__ import annotations

# ─────────────────────────────────────────────────────────── 签名（M05 §8.2 / CR-2）
#: 签名算法前缀：``hmac-sha256:`` + 64 位十六进制摘要（CR-2 已裁决，写进 04/02）
SIGNATURE_ALG = "hmac-sha256"
SIGNATURE_PREFIX = f"{SIGNATURE_ALG}:"
SIG_HEX_LEN = 64
#: 密钥长度下限（字节）：不短于 HMAC-SHA256 的摘要长度（32 字节 = 256 bit）
SIGNATURE_MIN_KEY_BYTES = 32
#: 事件 ``signature_ref`` 的短指纹长度（只做关联，不回放完整签名）
SIGNATURE_REF_LEN = 12
#: 规范字段与**固定顺序**（M05 §8.2）；按上报原样字符串拼接，不复用 DB NUMERIC 回读值
CANONICAL_FIELDS: tuple[str, ...] = (
    "receipt_id", "task_id", "access", "usage_amount", "usage_unit", "price_amount")
#: 字段分隔符：不在任何允许字符集里（access 是枚举、金额是数字、其余是 id），不会产生歧义
CANONICAL_SEPARATOR = "\n"
#: 两侧密钥必须不同（INV-01：单方无法伪造双侧签名）
SIGNATURE_SIDES: tuple[str, ...] = ("provider", "consumer")

# ─────────────────────────────────────────────────────────── 批量（M05 §8.2 / spec maxItems）
BATCH_MIN = 1
BATCH_MAX = 500

# ─────────────────────────────────────────────────────────── 枚举（M05 §5 / spec 1.2.0）
ACCESS_MODES: tuple[str, ...] = ("A1", "A2", "B")                       # M05 §5
USAGE_SOURCES: tuple[str, ...] = (                                       # M05 §5
    "client_reported", "server_measured", "dual", "estimated")
USAGE_STATES: tuple[str, ...] = ("recorded", "settled", "corrected")      # M05 §3 / spec UsageRecord
CORRECTION_REASONS: tuple[str, ...] = (                                   # M05 §5
    "overbill", "underbill", "estimate_fix", "dispute")
CORRECTION_STATES: tuple[str, ...] = ("proposed", "applied", "rejected")  # M05 §3
BILL_STATES: tuple[str, ...] = ("imported", "reconciled")                  # M05 §5
RECEIPT_STATES: tuple[str, ...] = ("accepted", "rejected", "expired")      # spec ReceiptStatus
#: 亏损池原因（M05 §6 流程 3 / §7 兜底切换与流式中断；T4 扩展需登记）
LOSS_POOL_REASONS: tuple[str, ...] = (
    "fallback_switch", "stream_interrupt", "upstream_consumed")
#: 上游账单导入的期间形状（spec ``UpstreamBillImportRequest.period``：YYYY-MM）
BILL_PERIOD_PATTERN = r"^[0-9]{4}-(0[1-9]|1[0-2])$"
#: 单次账单导入的行数上限（spec ``rows`` maxItems=500，与收据批同一口径）
BILL_ROWS_MAX = BATCH_MAX
#: 幂等键 / 证据引用长度（与 503/504 DDL 对齐）
MAX_REQUEST_KEY_LEN = 200

# ─────────────────────────────────────────────────────────── 金额（00-conventions §3 / facts §6）
#: USD 分：1 USD = 100 分（S1 只有 USD，03-facts §6 记账单位）
MINOR_UNIT_SCALE = 2
MINOR_PER_MAJOR = 10 ** MINOR_UNIT_SCALE
#: 单价最小单位：micro-USD（1e-6 USD；与 M06 ``unit_scale = 6`` 同源）
PRICE_MICRO_SCALE = 6
MICRO_PER_MINOR = 10 ** (PRICE_MICRO_SCALE - MINOR_UNIT_SCALE)            # 1e4
#: 展示/往返用币种代码（S1 仅 USD；非 USD 在入口拒绝，不做汇率换算）
CURRENCY = "USD"
#: 比例换算（00-conventions §3.5：比例用 bps，万分之一；1% = 100 bps）
BPS_PER_PCT = 100
BPS_DENOMINATOR = 10_000

# ─────────────────────────────────────────────────────────── 长度上限（与 501/502 DDL 逐条对齐）
MAX_ID_LEN = 128
MAX_UNIT_LEN = 32
MAX_AMOUNT_STR_LEN = 38
MAX_REASON_LEN = 64
MAX_DETAIL_LEN = 512
MAX_EVIDENCE_LEN = 256
MAX_PROVIDER_LEN = 64
MAX_PERIOD_LEN = 10
MAX_TRACE_LEN = 128

# ─────────────────────────────────────────────────────────── 分页（04-api-contracts §2 约定 2）
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
MAX_CURSOR_LEN = 512

# ─────────────────────────────────────────────────────────── 账单导出（spec 1.2.6 / M05 §4.1）
EXPORT_FORMATS: tuple[str, ...] = ("csv", "json")
#: 导出响应的媒体类型（Content-Type；spec text/csv / application/json）
EXPORT_MEDIA_TYPES: dict[str, str] = {"csv": "text/csv", "json": "application/json"}
#: 下载凭据有效期 ≤15 分钟（spec ``X-DJB-Export-Expires-At``，本模块取 900 s）
EXPORT_TTL_S = 900
#: 单次导出的时间窗上限（超限 → 400/40001，客户端拆分；不做静默截断）
EXPORT_MAX_WINDOW_DAYS = 366
#: 流式导出的 keyset 批大小（只限制单批内存，不限制导出总量）
EXPORT_BATCH_SIZE = 1000

# ─────────────────────────────────────────────────────────── 配置键（M05 §8.1；M10 管理）
CONFIG_NAMESPACE = "metering"
CONFIG_KEYS: tuple[str, ...] = (
    "metering.overbill_tolerance_pct",
    "metering.correction_dual_threshold_usd",
    "metering.estimated_alert_pct",
    "metering.receipt_late_h",
)
#: 默认值（M05 §8.1 表格原文）；运行期以 M10 发布值为准
CONFIG_DEFAULTS: dict[str, float] = {
    "metering.overbill_tolerance_pct": 1.0,
    "metering.correction_dual_threshold_usd": 50.0,
    "metering.estimated_alert_pct": 5.0,
    "metering.receipt_late_h": 24.0,
}
#: 取值范围（M05 §8.1「范围」列）；越界按边界夹取（配置中心已校验，这里只做兜底）
CONFIG_RANGES: dict[str, tuple[float, float]] = {
    "metering.overbill_tolerance_pct": (0.0, 10.0),
    "metering.correction_dual_threshold_usd": (0.0, 1000.0),
    "metering.estimated_alert_pct": (1.0, 50.0),
    "metering.receipt_late_h": (1.0, 168.0),
}
#: 受理窗口小时数的默认值（M05 §8.2 / §8.1；24h 迟到收据窗口，M15 CR-2 要求 ≥24h）
DEFAULT_RECEIPT_LATE_H = CONFIG_DEFAULTS["metering.receipt_late_h"]

# ─────────────────────────────────────────────────────────── 保留期（M05 §5「保留」列）
RETENTION_YEARS = 5

# ─────────────────────────────────────────────────────────── 数据所有权（M05 §5）
#: 本模块**拥有（可写）**的表；SQL 里只允许出现这些表名（架构门禁）
TABLES: tuple[str, ...] = (
    "usage_records",
    "metering_receipts",
    "usage_corrections",
    "upstream_bills",
    "loss_pool_entries",
    "metering_outbox",
)
#: 事件 outbox（02-events §2.1「本地事务 + outbox」；CR-5 已批准，迁移 506）
OUTBOX_TABLE = "metering_outbox"
#: 只读依赖：跨模块只读**视图**（01-ownership §2 / 00-conventions §7.4）
NODE_SNAPSHOT_VIEW = "v_supply_node_snapshot"        # M02：节点身份 / 归属 / 生命周期
ACCOUNT_VIEW = "v_identity_accounts"                 # M01：账户状态（T3 起用，T1/T2 只登记）
JOURNAL_VIEW = "journal_entry"                       # M06：仅对账读（T4 起用，T1/T2 只登记）

# ─────────────────────────────────────────────────────────── 事件（02-events §3 / M05 §4.2）
EVENT_PRODUCER = "M05"
EVENT_VERSION = 1
#: 生产事件 → payload 必含字段（02-events §3「关键 payload」列）
EVENT_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    "receipt.signed": ("receipt_id", "usage_id", "node_id", "signature_ref"),
    "usage.recorded": ("usage_id", "account_id", "request_id", "amount_minor", "source"),
    "usage.settled": ("usage_id", "final_amount_minor", "correction_id"),
}
EVENT_TYPES: tuple[str, ...] = tuple(EVENT_PAYLOAD_KEYS)
#: 事件聚合根（02-events §1 aggregate_type）
EVENT_AGGREGATE_TYPE: dict[str, str] = {
    "receipt.signed": "receipt",
    "usage.recorded": "usage_record",
    "usage.settled": "usage_record",
}
#: 投递语义（02-events §2.3 / §2.4）：指数退避 1s/5s/30s/5min/30min，最多 8 次后进死信
EVENT_BACKOFF_S: tuple[int, ...] = (1, 5, 30, 300, 1_800)
EVENT_MAX_ATTEMPTS = 8
#: 派发批大小（单次 drain 的默认上限；与 M04/M06 同款口径）
OUTBOX_PENDING_PAGE_DEFAULT = 100
#: 已发布事件的保留天数（M05 §5：metering_outbox「已发布 30 天」）
OUTBOX_PUBLISHED_RETENTION_DAYS = 30
#: last_error 截断长度（不把堆栈 / 连接串写进库）
OUTBOX_ERROR_MAX_LEN = 200

# ─────────────────────────────────────────────────────────── M06 E6 计量结算（M05 §6 流程 2）
#: E6「计量结算与消耗」：借 2101（服务预付款）/ 贷 4101（服务费收入，毛额法全额）
#: 出处：product/v4/src/20-payment-ledger.md §20.3.1 E6 · 03-facts §6 收入口径（毛额法）
E6_EVENT_TYPE = "E6"
E6_SOURCE_TYPE = "usage_settle"
E6_EVENT_SEQ = 1
E6_ENTRY_TYPE = "consume"
E6_LINES: tuple[tuple[str, str], ...] = (("2101", "D"), ("4101", "C"))
#: 贷方行用科目账户（M06 约定 coa:<code>），借方行用需方账户
E6_CREDIT_ACCOUNT = "coa:4101"

#: 本模块**消费**的事件（M05 §4.2；T3 接线，T1/T2 只登记幂等口径）
CONSUMED_EVENTS: dict[str, str] = {
    "request.completed": "request_id",        # 缺失时以收据为准并标 estimated
    "request.failed": "request_id",           # 同 request 不计费
    "booking.created": "booking_id",          # 取成交价做金额校验
    "config.published": "namespace+version",  # 刷新 metering.* 参数（单调前进）
}
