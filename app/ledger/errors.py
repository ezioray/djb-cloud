# SPDX-License-Identifier: Apache-2.0
"""M06 账本错误类型（码值按 CR-L1 裁决，HTTP 映射归 T4）。

CR-L1（已裁决，_CR-REGISTER M06 行）：账本错误码 ``40920–40924`` / ``42220–42223``。
本模块只携带码值，不做 HTTP 包装 —— 记账网关是库内 API，被 M05/M08 以服务间调用使用；
HTTP 状态与 Error 信封由 T4 的管理面负责，避免两处各写一份映射。

语义对照（M06-ledger.md §7 失败表）：
  · 42220 = 借贷不平 / 行数不足 / 金额非法（网关校验拒绝）
  · 42221 = 科目 / entry_type / unit_type / source_type 未知（INV-05）
  · 40920 / 40921 = 冲正重复 / 冷却期（T3）
  · 40924 = 凭证不存在（读路径）
"""
from __future__ import annotations


class LedgerError(Exception):
    """账本领域错误基类：带 CR-L1 码值与结构化 detail。"""

    code = "42220"

    def __init__(self, message: str, *, detail: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message, **({"detail": self.detail} if self.detail else {})}


class JournalValidationError(LedgerError):
    """凭证内容不合法（借贷不平 / 行数 / 金额 / 数量）。"""

    code = "42220"


class UnbalancedJournal(JournalValidationError):
    """Σ借 ≠ Σ贷（INV-01）。"""


class LineCountOutOfRange(JournalValidationError):
    """行数不在 2..JOURNAL_MAX_LINES（INV-01 / §8.2）。"""


class AmountOutOfRange(JournalValidationError):
    """金额不是正的整数最小单位（INV-01「整数 amount_minor」）。"""


class MissingAssetQuantity(JournalValidationError):
    """资产行缺 qty_minor（INV-11 / §20.2.8 C4 双记）。"""


class UnknownCoaCode(LedgerError):
    """科目不在 42 条白名单内（INV-03 / INV-05）。"""

    code = "42221"


class FundClassMismatch(LedgerError):
    """fund_class 与科目归属不一致（INV-03）。"""

    code = "42221"


class InvalidUnitType(LedgerError):
    """unit_type 不在 USD / COP / STABLE_USDT / FIAT_CNY（INV-04）。"""

    code = "42221"


class InvalidEventType(LedgerError):
    """event_type 不在 E1–E17（facts.yaml 为准）。"""

    code = "42221"


class InvalidSourceType(LedgerError):
    """source_type 不在 spec SourceType 的 16 值内。"""

    code = "42221"


class InvalidEntryType(LedgerError):
    """entry_type 不在 §20.4.4 的 16 值内（INV-05）。"""

    code = "42221"


class JournalNotFound(LedgerError):
    """凭证不存在（读路径，如冲正的原凭证）。"""

    code = "40924"


class ReversalNotAllowed(LedgerError):
    """冲正被拒（重复冲正 / 冷却期，T3 使用）。"""

    code = "40920"


class ReversalCooldown(ReversalNotAllowed):
    """同一 ref_id 的二次冲正在冷却期内（40921，M06 §8.2 REVERSAL_COOLDOWN_H）。"""

    code = "40921"


class PartialReversalNotAllowed(LedgerError):
    """部分冲正：冲正必须整单逐行取反（INV-07 / §7「不部分冲正」）。"""

    code = "42220"


class InvariantViolation(LedgerError):
    """冲正后的不变量复算失败（I-4 负债为负 / I-5 余额派生漂移），整笔回滚（INV-14）。"""

    code = "42220"


class TransactionRequired(RuntimeError):
    """必须是显式事务（autocommit 连接无法持有 pg_advisory_xact_lock）。"""
