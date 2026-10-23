# SPDX-License-Identifier: Apache-2.0
"""M08 payments-treasury · 常量、枚举与口径（**唯一来源**，业务代码不得再写字面量）。

出处逐条标注：

* 03-facts §1（链 / 确认数 / gas 预留）、§2（池参数 / cap / 上限 / TTL）、§3（归集 / 出款 /
  白名单 / 冷却 / 首笔 / 最低额 / 分润节奏）、§4（gas 三种模式）、§5（收款与退款）；
* M08 规格 §8.2「本模块常量」（批次笔数 / 签名 TTL / 2-of-3 / 退款冷却 / 审批失效 / 预测窗口）；
* M08 规格 §8.1「配置键」的默认值（运行期生效值由 M10 注入，见 config_source）；
* 00-conventions §2/§3/§5（ID、金额、错误码段）与 02-events §3（9 个生产事件）。

金额口径（03-facts §6「金额标度」）：payment_orders.amount_minor 是 **USD 分**（unit_scale=2）；
M06 账本 journal_line.amount_minor 用 **micro-USD**（unit_scale=6）；本模块在记账边界统一
×10,000 换算（MICRO_PER_MINOR），绝不做浮点运算。
"""
from __future__ import annotations

from typing import Final

# ───────────────────────────────────────────────────────────── 链与确认（03-facts §1）
CHAIN_POLYGON: Final[str] = "polygon"
CHAIN_ID: Final[str] = CHAIN_POLYGON              # 一期单链（K6；TRON 延后到 S4）
PAYOUT_ASSET: Final[str] = "USDT"
CONFIRMATIONS: Final[int] = 64                    # 达 64 才可入账（INV-09）
LARGE_CONFIRMATIONS: Final[int] = 200             # 大额（> 日限额 50%）≥200
LARGE_TX_THRESHOLD_PCT: Final[int] = 50           # 大额判定：日限额的 50%
GAS_RESERVE_POL: Final[int] = 10                  # gas 预留 ≥10 POL，低于即暂停归集

# ───────────────────────────────────────────────────────────── 钱包池与扩容（03-facts §2）
MIN_SPARE: Final[int] = 3
MAX_ACTIVE_HOT: Final[int] = 8
MAX_ACTIVE_WARM: Final[int] = 4
MAX_ACTIVE_HARD_CAP: Final[int] = 20              # 自动上调硬顶
MAX_ACTIVE_STEP: Final[int] = 4                   # 每次自动 +4，只升不降
SWITCH_THRESHOLD_PCT: Final[int] = 70             # 单钱包余额 ≥cap×70% → 切新地址
SWITCH_THRESHOLD_MIN_PCT: Final[int] = 50
SWITCH_THRESHOLD_MAX_PCT: Final[int] = 95
ACTIVATE_BATCH_SIZE: Final[int] = 4               # 每批 4 只（可配 1–8）
ACTIVATE_BATCH_MIN: Final[int] = 1
ACTIVATE_BATCH_MAX: Final[int] = 8
PROVISION_LEAD_TIME_H: Final[int] = 12            # 预生成提前量
PROVISION_LEAD_TIME_MIN_H: Final[int] = 1
PROVISION_LEAD_TIME_MAX_H: Final[int] = 48
PROVISION_BATCH_TTL_H: Final[int] = 24            # 批次 TTL（过期回 40914）
FORECAST_WINDOW_DAYS: Final[int] = 14
HORIZON_DAYS: Final[int] = 7
CAP_FORECAST_DAYS: Final[int] = 5                 # 单钱包 cap = min(10,000 USD, 5 天预测)
TARGET_CAPACITY_MULTIPLIER: Final[int] = 2        # 目标容量 ≥2× 7 天预测
PROVISION_TRIGGER_PCT: Final[int] = 60            # 预计利用率 >60% 触发预生成
CAPACITY_BUFFER_PCT: Final[int] = 100             # 目标容量 = 预测 × (1+buffer)

#: 金额单位：USD 分（03-facts §6）
MINOR_PER_USD: Final[int] = 100
WALLET_CAP_MINOR: Final[int] = 10_000 * MINOR_PER_USD       # 单钱包 cap 基准 10,000 USD
WALLET_CAP_FLOOR_MINOR: Final[int] = 1_000 * MINOR_PER_USD  # cap 被压下限 1,000 USD
POOL_CAP_MINOR: Final[int] = 50_000 * MINOR_PER_USD         # 池合计上限 50,000 USD（或 treasury 10%，取小）

# ───────────────────────────────────────────────────────────── 归集与出款（03-facts §3）
SWEEP_TRIGGER_PCT: Final[int] = 60                # 余额 > cap 60% 触发归集
SWEEP_HOUR_UTC4: Final[int] = 2                   # 每日 02:00（UTC+4）
SWEEP_MAX_BATCHES_PER_DAY: Final[int] = 2
SWEEP_MAX_SOURCE_WALLETS: Final[int] = 5          # 一批源地址数 ≤ max_active（≤5）
DUST_MINOR: Final[int] = 1 * MINOR_PER_USD        # 尘埃 <1 USDT 留待下次
LARGE_PAYOUT_THRESHOLD_PCT: Final[int] = 50       # 单笔 > 日限额 50% → 24h 延迟队列
LARGE_PAYOUT_DELAY_H: Final[int] = 24
PAYOUT_MIN_ITEM_MINOR: Final[int] = 10 * MINOR_PER_USD      # 单笔 ≥10 USDT，不足滚存
PAYOUT_BATCH_MAX_ITEMS: Final[int] = 50           # 同批出款笔数上限（§19.5.6）
PAYOUT_WEEKDAY_UTC4: Final[int] = 1               # 周一
PAYOUT_HOUR_UTC4: Final[int] = 10                 # 10:00（UTC+4）

# 收款人白名单（INV-13）
ADDRESS_COOLDOWN_H: Final[int] = 72               # 新地址 72h 冷却
ADDRESS_CHANGE_COOLDOWN_H: Final[int] = 24        # 地址变更 24h 冷却
ADDRESS_FREEZE_BEFORE_PAYOUT_D: Final[int] = 7    # 出款前 7 天禁改
OLD_ADDRESS_MONITOR_D: Final[int] = 90            # 旧地址监听 ≥90 天
FIRST_TRANSFER_MAX_MINOR: Final[int] = 100 * MINOR_PER_USD  # 首笔试转 ≤100 USDT

# ───────────────────────────────────────────────────────────── 费率与 gas（03-facts §4）
PLATFORM_FEE_BPS: Final[int] = 1500               # 15%（默认；和 provider 8500 = 10000）
PROVIDER_FEE_BPS: Final[int] = 8500
TOTAL_BPS: Final[int] = 10000
FEE_BPS_MAX: Final[int] = 10000
FEE_BPS_SECOND_CONFIRM: Final[int] = 3000         # >3000 bps 需决策人二次确认
GAS_MODE_INTERNAL: Final[str] = "INTERNAL"
GAS_MODE_EXTERNAL_PLATFORM: Final[str] = "EXTERNAL_PLATFORM"
GAS_MODE_EXTERNAL_PAYER: Final[str] = "EXTERNAL_PAYER"
GAS_MODES: Final[tuple[str, ...]] = (
    GAS_MODE_INTERNAL, GAS_MODE_EXTERNAL_PLATFORM, GAS_MODE_EXTERNAL_PAYER,
)
#: 03-facts §9 的 legacy 写法（billing.gas_fee_mode=EXTERNAL + bearer）→ 三分量
GAS_MODE_LEGACY: Final[dict[tuple[str, str], str]] = {
    ("INTERNAL", "PLATFORM"): GAS_MODE_INTERNAL,
    ("INTERNAL", "PAYER"): GAS_MODE_INTERNAL,
    ("EXTERNAL", "PLATFORM"): GAS_MODE_EXTERNAL_PLATFORM,
    ("EXTERNAL", "PAYER"): GAS_MODE_EXTERNAL_PAYER,
}

# ───────────────────────────────────────────────────────────── 收款与退款（03-facts §5）
REFUND_WINDOW_DAYS: Final[int] = 14               # 14 天内可申请（INV-12）
REFUND_WINDOW_MIN_DAYS: Final[int] = 7
REFUND_WINDOW_MAX_DAYS: Final[int] = 30
REFUND_COOLDOWN_H: Final[int] = 24                # 审批冷却（§8.2）
CARD_FREEZE_PCT: Final[int] = 10                  # 卡入账冻结 10% × 90 天
CARD_FREEZE_DAYS: Final[int] = 90
WALLET_FREEZE_PCT: Final[int] = 5                 # 微信 / 支付宝 5% × 30 天
WALLET_FREEZE_DAYS: Final[int] = 30
CHARGEBACK_WINDOW_DAYS: Final[int] = 120
CHARGEBACK_EVIDENCE_DAYS: Final[int] = 7

# ───────────────────────────────────────────────────────────── 本模块常量（M08 §8.2）
SIGNING_TTL_S: Final[int] = 1800                  # 资金意图签名有效期 30 分钟
WALLET_PROVISION_SIGNING_TTL_S: Final[int] = 86400  # WALLET_PROVISION 放宽 24h
SIGNER_THRESHOLD: Final[int] = 2                  # 2-of-3
SIGNER_COUNT: Final[int] = 3
APPROVAL_EXPIRE_H: Final[int] = 4                 # 双人复核 / 审批动作失效（03-facts §8）
MAX_BATCH_SIZE: Final[int] = 8                    # 单批只数硬顶（03-facts §2）
WEBHOOK_SKEW_S: Final[int] = 300                  # 回调 timestamp 偏差 ±5 分钟
PAYOUT_APPROVAL_EXPIRE_S: Final[int] = 30 * 60    # 审批后 30 分钟内可执行（§19.11.3）

# ───────────────────────────────────────────────────────────── 枚举（M08 §3 / §5）
ORDER_STATUSES: Final[tuple[str, ...]] = (
    "created", "pending", "paid", "credited", "failed", "closed", "expired",
)
ORDER_TERMINAL: Final[frozenset[str]] = frozenset({"credited", "failed", "closed", "expired"})
ORDER_PAYABLE: Final[frozenset[str]] = frozenset({"paid", "credited"})

ATTEMPT_STATUSES: Final[tuple[str, ...]] = ("initiated", "succeeded", "failed")
ATTEMPT_TERMINAL: Final[frozenset[str]] = frozenset({"succeeded", "failed"})

WALLET_STATUSES: Final[tuple[str, ...]] = (
    "provisioning", "active", "draining", "zero", "frozen", "retired",
)
WALLET_FAILED_STATUS: Final[str] = "provisioning_failed"
#: 004 的库层枚举比规格多一个 paused（兼容旧数据；新代码只产规格 7 值）
WALLET_STATUSES_DB: Final[tuple[str, ...]] = WALLET_STATUSES + (WALLET_FAILED_STATUS, "paused")
WALLET_PROVISIONING: Final[str] = "provisioning"
WALLET_ACTIVE: Final[str] = "active"
WALLET_DRAINING: Final[str] = "draining"
WALLET_ZERO: Final[str] = "zero"
WALLET_FROZEN: Final[str] = "frozen"
WALLET_RETIRED: Final[str] = "retired"

SWITCH_STATES: Final[tuple[str, ...]] = ("standby", "in_service", "switching_out", "draining")
SWITCH_STANDBY: Final[str] = "standby"
SWITCH_IN_SERVICE: Final[str] = "in_service"
SWITCH_SWITCHING_OUT: Final[str] = "switching_out"
SWITCH_DRAINING: Final[str] = "draining"

PROVISION_BATCH_STATUSES: Final[tuple[str, ...]] = (
    "draft", "pending_sign", "signed", "activated", "expired", "failed", "cancelled",
)
PROVISION_BATCH_TERMINAL: Final[frozenset[str]] = frozenset(
    {"activated", "expired", "failed", "cancelled"})

PAYOUT_BATCH_STATUSES: Final[tuple[str, ...]] = (
    "draft", "prepared", "checked", "signed", "broadcast", "settled", "partial", "failed",
)
PAYOUT_BATCH_TERMINAL: Final[frozenset[str]] = frozenset({"settled", "partial", "failed"})
PAYOUT_ITEM_STATUSES: Final[tuple[str, ...]] = ("pending", "sent", "carried", "failed")

REFUND_STATUSES: Final[tuple[str, ...]] = (
    "requested", "approved", "executing", "succeeded", "failed", "cancelled",
)
REFUND_OPEN: Final[frozenset[str]] = frozenset({"requested", "approved", "executing"})
REFUND_TERMINAL: Final[frozenset[str]] = frozenset({"succeeded", "failed", "cancelled"})

INTENT_KINDS: Final[tuple[str, ...]] = (
    "PAYOUT", "REFUND", "SWEEP", "REBALANCE", "GAS_TOPUP", "POLICY_CHANGE", "RECOVERY",
    "WALLET_PROVISION",
)
INTENT_STATUSES: Final[tuple[str, ...]] = ("proposed", "signing", "executed", "expired")
SIGNING_REQUEST_STATUSES: Final[tuple[str, ...]] = ("pending", "signed", "expired", "failed")
SIGNING_EVENTS: Final[tuple[str, ...]] = (
    "requested", "presented", "signed", "verified", "co_signed", "broadcast",
)
SIGNER_TYPES: Final[tuple[str, ...]] = ("owner", "reviewer", "company")
AUTH_OBJECT_TYPES: Final[tuple[str, ...]] = ("intentHash", "multisigTxHash")

PAYOUT_ADDRESS_STATUSES: Final[tuple[str, ...]] = ("pending", "whitelisted", "rejected", "revoked")

#: 支付方式（PSP capabilities，§19.10.1）——链上 USDT 收款走 M08 T3（不在本任务）
PSP_METHODS: Final[tuple[str, ...]] = ("card", "bank_transfer", "wechat", "alipay")
PROVIDERS: Final[tuple[str, ...]] = ("mock", "upg", "gifpay")
PROVIDER_STATUSES: Final[dict[str, str]] = {
    "0": "pending", "3": "pending", "1": "succeeded", "2": "failed", "6": "closed",
}

PSP_CURRENCIES: Final[dict[str, int]] = {"USD": 2, "CNY": 2, "JPY": 0, "KWD": 3}
DEFAULT_CURRENCY: Final[str] = "USD"

# ───────────────────────────────────────────────────────────── 分页 / 幂等 / 长度
MIN_PAGE_SIZE: Final[int] = 1
MAX_PAGE_SIZE: Final[int] = 200
DEFAULT_PAGE_SIZE: Final[int] = 50
MIN_IDEMPOTENCY_LEN: Final[int] = 16
MAX_IDEMPOTENCY_LEN: Final[int] = 128
MAX_TEXT_LEN: Final[int] = 512
MAX_REASON_LEN: Final[int] = 64
MAX_ADDRESS_LEN: Final[int] = 64
MAX_CHAIN_TX_ID_LEN: Final[int] = 128
MAX_ITEM_COUNT: Final[int] = 50
MAX_BODY_BYTES: Final[int] = 64 * 1024

# ───────────────────────────────────────────────────────────── 事件（02-events §3 已登记）
EVENT_PAYMENT_CREATED: Final[str] = "payment.created"
EVENT_PAYMENT_PAID: Final[str] = "payment.paid"
EVENT_PAYMENT_FAILED: Final[str] = "payment.failed"
EVENT_WALLET_SWITCHED: Final[str] = "wallet.switched"
EVENT_SWEEP_COMPLETED: Final[str] = "sweep.completed"
EVENT_PAYOUT_PAID: Final[str] = "payout.paid"
EVENT_REFUND_COMPLETED: Final[str] = "refund.completed"
EVENT_SIGNING_REQUESTED: Final[str] = "signing.requested"
EVENT_SIGNING_SIGNED: Final[str] = "signing.signed"
PRODUCED_EVENTS: Final[tuple[str, ...]] = (
    EVENT_PAYMENT_CREATED, EVENT_PAYMENT_PAID, EVENT_PAYMENT_FAILED, EVENT_WALLET_SWITCHED,
    EVENT_SWEEP_COMPLETED, EVENT_PAYOUT_PAID, EVENT_REFUND_COMPLETED, EVENT_SIGNING_REQUESTED,
    EVENT_SIGNING_SIGNED,
)
#: payload 白名单（02-events §3 + M08 §4.2）；多一个键就拒绝（防止把卡号 / 完整报文带出去）
EVENT_PAYLOAD_FIELDS: Final[dict[str, frozenset[str]]] = {
    EVENT_PAYMENT_CREATED: frozenset({"order_no", "amount_minor", "method", "currency"}),
    EVENT_PAYMENT_PAID: frozenset({"order_no", "paid_at", "provider_ref", "amount_minor"}),
    EVENT_PAYMENT_FAILED: frozenset({"order_no", "error_code"}),
    EVENT_WALLET_SWITCHED: frozenset({"pool_id", "from_wallet", "to_wallet", "reason"}),
    EVENT_SWEEP_COMPLETED: frozenset(
        {"batch_no", "from_wallet", "to_wallet", "amount_minor", "txid"}),
    EVENT_PAYOUT_PAID: frozenset({"batch_no", "item_count", "total_minor", "txid"}),
    EVENT_REFUND_COMPLETED: frozenset({"refund_no", "order_no", "amount_minor", "method"}),
    EVENT_SIGNING_REQUESTED: frozenset({"intent_id", "signer_type", "expires_at", "kind"}),
    EVENT_SIGNING_SIGNED: frozenset({"intent_id", "signer_type", "signed_at"}),
}
EVENT_IDEMPOTENCY_PREFIX: Final[dict[str, str]] = {
    EVENT_PAYMENT_CREATED: "payment_order",
    EVENT_PAYMENT_PAID: "payment_order_paid",
    EVENT_PAYMENT_FAILED: "payment_order_failed",
    EVENT_WALLET_SWITCHED: "wallet_switch",
    EVENT_SWEEP_COMPLETED: "sweep",
    EVENT_PAYOUT_PAID: "payout_batch",
    EVENT_REFUND_COMPLETED: "refund",
    EVENT_SIGNING_REQUESTED: "signing_request",
    EVENT_SIGNING_SIGNED: "signing_signed",
}

# ───────────────────────────────────────────────────────────── 金额换算
MICRO_PER_MINOR: Final[int] = 10_000            # 分 → micro-USD（unit_scale 2 → 6）
LEDGER_UNIT_SCALE: Final[int] = 6
