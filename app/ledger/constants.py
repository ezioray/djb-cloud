# SPDX-License-Identifier: Apache-2.0
"""M06 常量单点定义（唯一来源 + 出处）。

来源分层（重要，避免"两处各写一份"）：
  · ``contracts/facts.yaml``（03-facts §6，W0-QA 生成）：科目数 / 分组数 / E1–E17 / Merkle 四类
    —— 本模块**读**它，并在导入时断言下面的表与之等长（漂移即起不来）；
  · ``product/v4/src/20-payment-ledger.md`` §20.2（42 科目与 fund_class 归属）、§20.4.4（entry_type）、
    §20.2.8 C4（资产双记）；spec 1.2.0 ``SourceType``（16 值）—— 科目码与枚举清单**不在** facts.yaml，
    故在此单点定义，并由 ``tests/ledger/test_facts.py`` 与数据库 CHECK 约束逐条对齐；
  · ``M06-ledger.md`` §8.2：本模块私有常量（JOURNAL_MAX_LINES / MERKLE_KINDS_OWNED）。
"""
from __future__ import annotations

from . import facts
from .legacy import LEDGER_APPEND_LOCK_ID

# ────────────────────────────────────────────── 42 科目（§20.2.2–§20.2.6）
COA_ASSETS = (
    "1101", "1102", "1103", "1109", "1111", "1120", "1121", "1130", "1140", "1190", "1901", "1910",
)
COA_LIABILITIES_EQUITY = (
    "2101", "2102", "2103", "2201", "2202", "2203", "2204", "2210", "2301", "2901", "2990", "3101",
)
COA_REVENUE = ("4101", "4102", "4103", "4104", "4105", "4201")
COA_EXPENSE_LOSS = ("5101", "5102", "5103", "5104", "5105", "5106", "5201", "5301", "5401", "5501")
COA_NON_CASH_ADJUST = ("6101", "6901")

COA_GROUPS: dict[str, tuple[str, ...]] = {
    "资产": COA_ASSETS,
    "负债权益": COA_LIABILITIES_EQUITY,
    "收入": COA_REVENUE,
    "费用损失": COA_EXPENSE_LOSS,
    "非现金": COA_NON_CASH_ADJUST,
}

# fund_class 归属（INV-03，与 600 迁移里的 journal_line_coa_fund_class_ck 一一对应）
_FUND_CLASS_BY_COA: dict[str, str] = {
    **{code: "CLIENT" for code in COA_ASSETS if code not in ("1109", "1140")},
    "1109": "PLATFORM",
    "1140": "PLATFORM",
    **{code: "CLIENT" for code in COA_LIABILITIES_EQUITY if code not in ("2901", "3101")},
    "2901": "FEE",
    "3101": "PLATFORM",
    **{code: "FEE" for code in COA_REVENUE},
    **{code: "FEE" for code in COA_EXPENSE_LOSS},
    **{code: "FEE" for code in COA_NON_CASH_ADJUST},
}
COA_FUND_CLASS: dict[str, str] = _FUND_CLASS_BY_COA

# 科目名称（§20.2.2–§20.2.6 原文）：管理面展示用，避免前端各自维护一份译名。
COA_NAMES: dict[str, str] = {
    "1101": "客户资金-热钱包 USDT", "1102": "客户资金-温钱包 USDT", "1103": "客户资金-冷钱包 USDT",
    "1109": "平台自有-温钱包 USDT", "1111": "链上在途", "1120": "PSP 在途应收",
    "1121": "银行在途", "1130": "兑换在途", "1140": "预置 gas", "1190": "待清算过渡",
    "1901": "应收-用户欠款", "1910": "平台应补足客户资金",
    "2101": "服务预付款", "2102": "锁定服务预付款", "2103": "COP 余额",
    "2201": "应付共享方分润", "2202": "应付渠道返佣", "2203": "应付退款",
    "2204": "应付代扣款", "2210": "确认中 / 未识别充值", "2301": "拒付准备金",
    "2901": "尾差", "2990": "确认中充值", "3101": "累计留存收益",
    "4101": "接入与优化服务费收入", "4102": "通道接入费收入", "4103": "结算服务费收入",
    "4104": "COP 抵扣确认收入", "4105": "未识别资金确认收入", "4201": "汇兑收益",
    "5101": "上游 Token 成本", "5102": "链上 gas 费", "5103": "PSP 手续费",
    "5104": "亏损池", "5105": "资产损失", "5106": "兑换手续费 / 点差",
    "5201": "汇兑损失", "5301": "拒付损失", "5401": "坏账损失", "5501": "分润成本",
    "6101": "COP 发放成本", "6901": "调整损益",
}

# 正常方向（§20.2.1–§20.2.6；"B" = 借/贷皆可为正常，例如 6901 调整损益）。
# T3 展示"正常方向余额"时按此换算；存储层 balance_minor 只用「借方为正」一种口径。
COA_NORMAL_DC: dict[str, str] = {
    **{code: "D" for code in COA_ASSETS},
    **{code: "C" for code in COA_LIABILITIES_EQUITY},
    **{code: "C" for code in COA_REVENUE},
    **{code: "D" for code in COA_EXPENSE_LOSS},
    "6101": "D",
    "6901": "B",
}

# §20.2.8 C4：链上资产行必须同时记 qty_minor 与 amount_minor（INV-11）
COA_QTY_REQUIRED = ("1101", "1102", "1103")

ALL_COA = tuple(COA_FUND_CLASS)

# ────────────────────────────────────────────── 枚举（spec：unit_type / SourceType / entry_type）
UNIT_TYPES = ("USD", "COP", "STABLE_USDT", "FIAT_CNY")                    # M06 §3 / §20.4.2
SOURCE_TYPES = (                                                          # spec 1.2.0 SourceType（16）
    "chain_tx", "payment_attempt", "conversion_trade", "usage_settle", "lock_expiry",
    "payout_accrual", "payout_item", "payout_batch", "wallet_transfer", "refund",
    "chargeback", "rebate", "fx_reval", "loss_pool", "void", "unidentified",
)
ENTRY_TYPES = (                                                           # §20.4.4（六值 + 十增补）
    "earn", "redeem", "adjust", "freeze", "unfreeze", "void",
    "deposit", "consume", "payout", "refund", "chargeback", "transfer", "gas", "conversion",
    "fx_reval", "writeoff",
)
EVENT_TYPES = facts.event_types()                                         # E1–E17（facts.yaml）

# ────────────────────────────────────────────── 本模块常量（M06 §8.2）
JOURNAL_MAX_LINES = 64
MERKLE_KINDS_OWNED = ("journal", "daily_close")       # audit 属 M16、por 属 M09
HASH_ALGO = "sha256"
HASH_LEN = 32                                         # 字节（journal_entry.hash BYTEA）
MINOR_UNIT_SCALE = 6                                  # micro（001_init「微单位 1e-6」/ §20.3「整数 micro」）
JOURNAL_MIN_LINES = 2                                 # INV-01：行数下限（≥2）

# 长度 / 取值范围上限：逐条对齐迁移里的 length CHECK（600 journal_entry_source_id_ck 等），
# 校验器与 outbox 都从这里取，避免各处散落数字。
MAX_ID_LEN = 128                                      # 600/601：source_id / account_id / ref_id 1..128
MAX_POLICY_VERSION_LEN = 64                           # 600：policy_version 1..64
MAX_AGGREGATE_ID_LEN = 128                            # 604：m06_outbox.aggregate_id 1..128
MAX_TRACE_ID_LEN = 128                                # 604：trace_id 1..128
MAX_IDEMPOTENCY_KEY_LEN = 200                         # 604：idempotency_key 1..200
MAX_UNIT_SCALE = 18                                   # 600：unit_scale 0..18
PENDING_PAGE_DEFAULT = 100                            # outbox 待投递查询的默认页大小
DEFAULT_PAGE_SIZE = 50                                # 管理面分页默认条数（spec Limit.default）
MAX_PAGE_SIZE = 200                                   # 管理面分页上限（spec Limit.maximum）
DECIMAL_BASE = 10                                     # 十进制（最小单位 ↔ 展示值换算的底数）
HEX_PREVIEW_LEN = 12                                  # 错误信息里的哈希前缀长度
PERIOD_LEN_MONTH = 7                                  # 期间形状：YYYY-MM
PERIOD_LEN_DAY = 10                                   # 期间形状：YYYY-MM-DD
PERIOD_LEN_HOUR = 13                                  # 期间形状：YYYY-MM-DDTHH

# ── T3：冲正与余额派生 ──────────────────────────────────────────────
REVERSAL_EVENT_TYPE = "E16"        # §20.3.1 E16「错链 / 假充值冲正」= 冲正凭证的事件模板
REVERSAL_SOURCE_TYPE = "void"      # spec SourceType 的 ``void``
REVERSAL_EVENT_SEQ = 1             # 同一原凭证的冲正事件序号固定 1（重复请求 → 同一幂等键）
REVERSAL_COOLDOWN_H = 24           # M06 §8.2：同一 ref_id 二次冲正冷却 24h（40921）
MAX_REASON_CODE_LEN = 64           # 冲正原因码长度上限（ledger.reversed.reason_code）
MAX_REASON_TEXT_LEN = 500          # 管理面冲正理由上限（spec 1.2.1 ReversalRequest.reason）
RECOMPUTE_LOCK_ID = 4_442_003      # 「同一时刻只允许 1 个复算作业」的 advisory lock key
STEP_UP_MAX_AGE_S = 300            # step-up ≤5 分钟（00-conventions / spec AdminStepUp）

# 子账户（§20.2.7）：余额派生键里的 sub_account。锁定预付款走 2102 → LOCKED，其余按 AVAILABLE。
# 2201 的 AVAILABLE/LOCKED 子账户细分需要行级维度（entry_type=freeze），随 T4/day-close 再定。
DEFAULT_SUB_ACCOUNT = "AVAILABLE"
SUB_ACCOUNT_BY_COA: dict[str, str] = {"2102": "LOCKED"}
SUB_ACCOUNTS = (DEFAULT_SUB_ACCOUNT, "LOCKED")

# I-4：这些科目不得出现「正常方向为负」的余额（§20.2.8 C2 / IP-4）
NEGATIVE_FORBIDDEN_COA = ("2101", "2102", "2103", "2201", "2202", "2203")

# ────────────────────────────────────────────── 与事实源对齐（漂移即导入失败）
def _assert_aligned() -> None:
    if len(COA_FUND_CLASS) != facts.coa_count():
        raise facts.FactsError(
            f"科目表 {len(COA_FUND_CLASS)} 条与 facts 的科目数 {facts.coa_count()} 不一致")
    if len(set(ALL_COA)) != len(ALL_COA):
        raise facts.FactsError("科目码有重复")
    grouped = {name: len(codes) for name, codes in COA_GROUPS.items()}
    if grouped != facts.coa_group_counts():
        raise facts.FactsError(f"科目分组 {grouped} 与 facts 的 {facts.coa_group_counts()} 不一致")
    if set(ALL_COA) != set(COA_FUND_CLASS):
        raise facts.FactsError("科目码与 fund_class 表键集不一致")
    if set(COA_NAMES) != set(ALL_COA):
        raise facts.FactsError("科目名称表与科目码集合不一致")
    if set(COA_NORMAL_DC) != set(ALL_COA):
        raise facts.FactsError("正常方向表缺科目")
    if not set(MERKLE_KINDS_OWNED) <= set(facts.merkle_kinds()):
        raise facts.FactsError("M06 拥有的 Merkle 类别不在 facts 的四类根之内")
    unknown_sub = set(SUB_ACCOUNT_BY_COA) - set(ALL_COA)
    if unknown_sub:
        raise facts.FactsError(f"子账户映射指向未知科目：{unknown_sub}")
    if not set(NEGATIVE_FORBIDDEN_COA) <= set(ALL_COA):
        raise facts.FactsError("I-4 科目组里有未知科目")
    if REVERSAL_EVENT_TYPE not in EVENT_TYPES:
        raise facts.FactsError("冲正事件模板不在 facts 的资金事件内")
    if REVERSAL_SOURCE_TYPE not in SOURCE_TYPES:
        raise facts.FactsError("冲正 source_type 不在 spec SourceType 内")
    if JOURNAL_MAX_LINES < JOURNAL_MIN_LINES:
        raise facts.FactsError("JOURNAL_MAX_LINES 必须 ≥ 2（INV-01 行数下限）")


_assert_aligned()
