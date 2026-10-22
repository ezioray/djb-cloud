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
    if set(COA_NORMAL_DC) != set(ALL_COA):
        raise facts.FactsError("正常方向表缺科目")
    if not set(MERKLE_KINDS_OWNED) <= set(facts.merkle_kinds()):
        raise facts.FactsError("M06 拥有的 Merkle 类别不在 facts 的四类根之内")
    if JOURNAL_MAX_LINES < JOURNAL_MIN_LINES:
        raise facts.FactsError("JOURNAL_MAX_LINES 必须 ≥ 2（INV-01 行数下限）")


_assert_aligned()
