# SPDX-License-Identifier: Apache-2.0
"""M09 对账与报表 · 常量（唯一事实源出口）。

出处纪律（M09 §8.2 / 03-facts §6–§7）：本模块**不定义**容差、档位、覆盖率阈值之外的
业务数字；下面每一条都标注出处。产品规格没写的常量一律不在这里发明（宁可留空/留待 T4）。

    severity 档位     03-facts §7「差异档位」：P0 >1,000 USD 或结构性（15 分钟首响）；
                      P1 100–1,000（1 小时）；P2 <100（1 个工作日）
    容差             03-facts §7（链上 0 / PSP / 银行 / 汇率）—— T2/T3 不实现 psp/bank/chain，
                      故本轮不落容差比较；scope=receipt 的容差是 0（逐条金额必须相等）
    S1 收据差异率     03-facts §10「收据差异率 ≤1%」（指标，不作为自动开差异的阈值，见 reports）
    账龄桶            M09 §8.2「0–1 / 1–3 / 3–7 / 7–30 / 30 天以上」
    grace 默认值      M09 §8.1 recon.grace_seconds = 300（0–1800）
    分页              spec `Limit`（1..200，默认 50）· 00-conventions §5
    幂等键长度        spec `IdempotencyKey`（16..128，24h）

金额一律**整数最小单位（USD 分）**，不浮点、不四舍五入（INV-08 / 03-facts §6）。
"""
from __future__ import annotations

from datetime import timedelta

__all__ = [
    "SCOPES", "SCOPES_IMPLEMENTED", "SCOPES_DEFERRED", "DEFERRED_SCOPE_OWNER",
    "RUN_STATUSES", "RUN_STATUS_MATCHED", "RUN_STATUS_EXCEPTIONS_OPEN",
    "RUN_STATUS_SIGNED_OFF", "RUN_STATUS_CLOSED", "RUN_SIGNOFF_READONLY",
    "RUN_STATUS_TRANSITIONS",
    "EXCEPTION_STATUSES", "EXCEPTION_OPEN_STATUSES", "EXCEPTION_CLOSED",
    "EXCEPTION_STATUS_TRANSITIONS",
    "SEVERITIES", "SEVERITY_SLA_SECONDS",
    "RECEIPT_KINDS", "DAILY_CLOSE_KINDS", "PAYMENT_KINDS", "STRUCTURAL_KINDS",
    "RESOLUTION_CODES", "RESOLUTION_REQUIRES_JOURNAL", "RESOLUTION_REQUIRES_CAUSE",
    "P0_AMOUNT_MINOR_EXCLUSIVE", "P1_AMOUNT_MINOR_MIN",
    "DEFAULT_GRACE_SECONDS", "MAX_GRACE_SECONDS",
    "RULE_VERSION", "POLICY_VERSION", "MINOR_UNIT_SCALE",
    "ATTESTATION_STATUSES", "ATTESTATION_TRANSITIONS",
    "POR_GRANULARITIES", "POR_STATUSES", "REPORT_STATUSES",
    "REPORTS_IMPLEMENTED", "REPORTS_DEFERRED", "REPORT_VERSION_SEQ",
    "AGE_BUCKETS",
    "MIN_PAGE_SIZE", "MAX_PAGE_SIZE", "DEFAULT_PAGE_SIZE",
    "MIN_IDEMPOTENCY_LEN", "MAX_IDEMPOTENCY_LEN", "IDEMPOTENCY_TTL_HOURS",
    "RECEIPT_DIFF_RATE_TARGET_BPS", "SERVICE_SCOPES",
    "LEDGER_ROOT_PATTERN", "HEX64_PATTERN", "BATCH_HASH_PATTERN",
]

# ─────────────────────────────────────────────────────────────── scope（M09 §5 枚举 5 值）
SCOPES: tuple[str, ...] = ("chain", "psp", "bank", "receipt", "daily_close")

#: 本轮（T1–T3）实现的 scope。chain/psp/bank 依赖 M08（钱包 / 批次只读视图），
#: 未合并 → 不实现、不注册路由、不返回假数据；扩展点见 ``engine.SCOPE_HANDLERS``。
SCOPES_IMPLEMENTED: tuple[str, ...] = ("receipt", "daily_close")
SCOPES_DEFERRED: tuple[str, ...] = ("chain", "psp", "bank")
DEFERRED_SCOPE_OWNER: dict[str, str] = {
    "chain": "M08（链上钱包 / chain_tx 只读视图）",
    "psp": "M08（payment_orders / payment_attempts）",
    "bank": "M08（payout_batches / payout_items / 银行对账单）",
}

# ─────────────────────────────────────────────────────────── run 状态机（M09 §3.2）
RUN_STATUSES: tuple[str, ...] = ("scheduled", "running", "matched", "exceptions_open",
                                 "signed_off", "closed")
RUN_STATUS_MATCHED = "matched"
RUN_STATUS_EXCEPTIONS_OPEN = "exceptions_open"
RUN_STATUS_SIGNED_OFF = "signed_off"
RUN_STATUS_CLOSED = "closed"

#: 签核后只读（M09 §3.2「closed 后只读」「signed_off 后改数字必须新版本重出」）
RUN_SIGNOFF_READONLY: tuple[str, ...] = (RUN_STATUS_SIGNED_OFF, RUN_STATUS_CLOSED)

RUN_STATUS_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "scheduled": ("running",),
    "running": ("matched", "exceptions_open"),
    "matched": ("signed_off", "exceptions_open"),
    "exceptions_open": ("matched", "signed_off"),
    "signed_off": ("closed",),
    "closed": (),
}

# ─────────────────────────────────────────────────────── exception 状态机（M09 §3.2）
EXCEPTION_STATUSES: tuple[str, ...] = ("open", "investigating", "escalated",
                                       "resolved", "accepted", "closed")
#: 未结 = 会阻断签核（INV-03 只拦 P0/P1）与计入 diff_minor（INV-01 统计「未关闭」）
EXCEPTION_OPEN_STATUSES: tuple[str, ...] = ("open", "investigating", "escalated")
EXCEPTION_CLOSED = "closed"

EXCEPTION_STATUS_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "open": ("investigating", "escalated", "resolved", "accepted", "closed"),
    "investigating": ("escalated", "resolved", "accepted", "closed"),
    "escalated": ("investigating", "resolved", "accepted", "closed"),
    "resolved": ("closed",),
    "accepted": ("closed",),
    "closed": (),                          # 关闭后不可重开（M09 §3.2）
}

# ───────────────────────────────────────────────────── severity（03-facts §7）
SEVERITIES: tuple[str, ...] = ("P0", "P1", "P2")

#: 首响 SLA：P0 15 分钟 / P1 1 小时 / P2 1 个工作日。
#: P2 用 24h 近似「1 个工作日」——工作日历属 03-facts §8（保留期/日历）未收录项，
#: 已在证据「遗留」登记；逐笔口径以 sla_due 为准（M09 §8.2）。
SEVERITY_SLA_SECONDS: dict[str, int] = {
    "P0": 15 * 60,
    "P1": 60 * 60,
    "P2": 24 * 60 * 60,
}
SEVERITY_SLA_BUSINESS_APPROX = ("P2",)

# ───────────────────────────────────────────────────── 差异 kind（M09 §5）
#: scope=receipt 四类（M09 §5 / §6.3）。``duplicate_receipt`` 是 receipt scope 的
#: 结构性扩展（重复入账，INV-02 要求 P0），规格 §3.3 明确「重复入账」属结构性差异。
RECEIPT_KINDS: tuple[str, ...] = ("only_platform", "only_node", "amount_mismatch",
                                  "signature_bad", "duplicate_receipt")
#: scope=daily_close 两类（试算不平 / 派生余额漂移）。
DAILY_CLOSE_KINDS: tuple[str, ...] = ("trial_imbalance", "balance_drift")
#: scope=payment 的 9 类属 M08 域（§20.5.6），T2–T3 不做；仅登记名字空间占位，不伪造。
PAYMENT_KINDS: tuple[str, ...] = ()

#: INV-02：结构性差异一律 P0，与金额无关（M09 §3.3）。
#: 借贷不平 / 重复入账 / 地址不符 / 拒付无匹配 / 覆盖率低 —— 本轮落地的对应 kind：
#:   trial_imbalance = 借贷不平；duplicate_receipt = 重复入账；balance_drift = 派生余额与分录不符；
#:   only_node / signature_bad = 平台无对应 / 签名不可验（伪造或密钥问题，结构性）；
#: 地址不符 / 拒付无匹配 / 覆盖率低 属 chain/psp/por（M08 / T4）。
STRUCTURAL_KINDS: frozenset[str] = frozenset({
    "signature_bad", "only_node", "duplicate_receipt", "trial_imbalance", "balance_drift",
})

# ───────────────────────────────────────────────────── 处置码（M09 §5）
RESOLUTION_CODES: tuple[str, ...] = ("adjust_journal", "external_fix", "write_off", "false_positive")
#: 调整分录必须回填已入账的 journal_id（M09 §6.2 / spec resolve description）
RESOLUTION_REQUIRES_JOURNAL: tuple[str, ...] = ("adjust_journal",)
#: 核销类必须有原因码（M09 §6.2「accepted 必须双人 + 原因码 + 月度集中说明」）
RESOLUTION_REQUIRES_CAUSE: tuple[str, ...] = ("write_off", "false_positive")

# ───────────────────────────────────────── 金额档位（03-facts §7，整数最小单位）
#: P0 阈值：>1,000 USD（严格大于）→ >100000 分；1000.00 整落在 P1（「100–1,000」含端点）。
P0_AMOUNT_MINOR_EXCLUSIVE = 1000 * 100
#: P1 下界：100 USD 起（含端点）→ 10000 分；<10000 为 P2。
P1_AMOUNT_MINOR_MIN = 100 * 100

# ───────────────────────────────────────────────────── 宽限期（M09 §8.1 recon.grace_seconds）
DEFAULT_GRACE_SECONDS = 300
MAX_GRACE_SECONDS = 1800

# ───────────────────────────────────────────────────── 版本口径
#: 对账规则版本（比较键 / 配对算法 / 分级口径）；改口径必须换版本号，便于回溯。
RULE_VERSION = "m09-receipt-r1"
#: 事实源版本（03-facts §7 档位与容差）。
POLICY_VERSION = "facts-v4@2026-10-21"
#: 最小单位标度：1 USD = 100 分（03-facts §6）
MINOR_UNIT_SCALE = 2

# ───────────────────────────────────────────── attestation 状态机（M09 §3.2）
ATTESTATION_STATUSES: tuple[str, ...] = ("valid", "superseded", "revoked")
ATTESTATION_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "valid": ("superseded", "revoked"),
    "superseded": (),
    "revoked": (),
}

# ───────────────────────────────────────────── PoR / 报表（T4 落地，表与视图本轮建好）
POR_GRANULARITIES: tuple[str, ...] = ("daily", "monthly")
POR_STATUSES: tuple[str, ...] = ("computed", "published", "month_proof")
REPORT_STATUSES: tuple[str, ...] = ("draft", "rendered", "signed_off", "archived")

#: 本轮实现的报表：REP-02 exceptions / REP-01 recon-daily（数据只来自 runs / exceptions）。
REPORTS_IMPLEMENTED: tuple[str, ...] = ("REP-01", "REP-02")
#: 留 T4：por（REP-03）/ wallet-pool（REP-04）/ monthly（REP-06）。
#: 不注册路由、不返回空壳数据（spec 有这 5 条端点，接线由 Lead 在 T4 合并时排期）。
REPORTS_DEFERRED: dict[str, str] = {
    "REP-03": "por：依赖 T4 PoR 快照与发布",
    "REP-04": "wallet-pool：依赖 M08 钱包池只读视图",
    "REP-06": "monthly：依赖 T4 月结聚合",
}

#: 报表版本号（INV-07：report_version = H(report_id, cutoff_at, data_hash, renderer_version)）
#: 本轮只做 JSON 报表（无 SVG/PDF），渲染件版本留 T4。
REPORT_VERSION_SEQ = "json-v1"

# ───────────────────────────────────────────── 账龄桶（M09 §8.2）
#: (下界天数含, 上界天数不含)；None = 开区间
AGE_BUCKETS: tuple[tuple[int, int | None], ...] = ((0, 1), (1, 3), (3, 7), (7, 30), (30, None))
AGE_BUCKET_LABELS: tuple[str, ...] = ("0-1", "1-3", "3-7", "7-30", "30+")

# ───────────────────────────────────────────── 分页 / 幂等（spec 参数定义）
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50
MIN_IDEMPOTENCY_LEN = 16
MAX_IDEMPOTENCY_LEN = 128
IDEMPOTENCY_TTL_HOURS = 24

# ───────────────────────────────────────────── S1 指标（03-facts §10）
#: 收据差异率目标 ≤1%（bps）。**只作报表指标**，不自动开差异（阈值属 §10 验收指标，
#: 不是 §7 的分级阈值；自动开差异会污染 diff_minor 口径）。
RECEIPT_DIFF_RATE_TARGET_BPS = 100

# ───────────────────────────────────────────── 服务间 scope（validate）
SERVICE_SCOPES: dict[str, str] = {
    "validate": "recon.attestation.validate",
    "read": "recon.attestation.read",
    "write": "recon.write",
}

# ───────────────────────────────────────────── 形态校验
LEDGER_ROOT_PATTERN = r"^[0-9a-f]{64}$"
HEX64_PATTERN = r"^[0-9a-f]{64}$"
BATCH_HASH_PATTERN = r"^[0-9a-f]{16,128}$"

#: P2 的「1 个工作日」近似窗口（见 SEVERITY_SLA_SECONDS 注释）
P2_SLA_APPROX = timedelta(seconds=SEVERITY_SLA_SECONDS["P2"])
