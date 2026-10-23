# SPDX-License-Identifier: Apache-2.0
"""M06 记账适配层：**只 propose 凭证形状**，真正的落账由注入的 M06 posting API 完成。

边界（00-conventions §1.2 / _boundary-checks §1）：本模块**不 import app.ledger**；
记账走「Owner 提供的内部 API」——合并期由 Lead 注入适配器：

    poster.post(conn, PostingRequest) -> {"journal_id": str, "idempotent": bool}

未接线时默认 NullLedgerPoster **fail-closed**（LedgerUnavailable / 45001）：
资金写不自动重试（00-conventions §6.3），宁可让回调失败重试，也不能「收了钱没记账」。

金额口径：订单 / 退款 / 出款都是 **USD 分**（unit_scale=2）；账本行是 **micro-USD**
（unit_scale=6，03-facts §6）。本层在边界统一 ×10,000（MICRO_PER_MINOR），不做浮点。

E3 / E4 / E5 的借贷方向逐条对应产品 §20.3.1（E4 / E5 是**两步记法**：先 1910 后补足）::

    E3  借 1120 PSP 在途 / 贷 2101 服务预付款            （event_seq=1）
    E4① 借 1121 银行在途（净额）+ 1910 平台应补足（手续费） / 贷 1120（全额）  （event_seq=2）
    E4② 借 1121（手续费）+ 5103 PSP 手续费 / 贷 1109 平台自有（手续费）+ 1910（手续费） （event_seq=3）
    E5① 借 1102 客户资金温钱包（净额）+ 1910（兑换费） / 贷 1121（全额）     （event_seq=1）
    E5② 借 1102（兑换费）+ 5106 兑换手续费 / 贷 1109（兑换费）+ 1910（兑换费） （event_seq=2）

幂等键（R8 / I-8）：(source_type, source_id, event_seq)。E3 用 payment_attempt +
provider_txn_id + 1；E4 用同一 attempt + 2 / 3；E5 用 conversion_trade + trade_id + 1 / 2。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Protocol, Sequence

from . import clock, facts
from .errors import BadRequest, LedgerUnavailable

__all__ = [
    "LedgerLine", "PostingRequest", "LedgerPoster", "NullLedgerPoster", "RecordingPoster",
    "platform_account", "subject_account", "to_micro", "e3_request", "e4_requests",
    "e5_requests", "post_one", "post_many", "E3_SOURCE", "E4_SOURCE", "E5_SOURCE",
]

E3_SOURCE = "payment_attempt"
E4_SOURCE = "payment_attempt"
E5_SOURCE = "conversion_trade"
PLATFORM_ACCOUNT = "platform:treasury"


def platform_account(coa_code: str) -> str:
    """平台级科目账户（M06 约定：coa:<code>）。"""
    return f"coa:{coa_code}"


def subject_account(account_id: str) -> str:
    """主体账户（M06 约定：acct:<subject>）。"""
    return f"acct:{account_id}"


def to_micro(amount_minor: int) -> int:
    """分 → micro-USD（unit_scale 2 → 6）。整数运算，不做四舍五入。"""
    return int(amount_minor) * facts.MICRO_PER_MINOR


@dataclass(frozen=True)
class LedgerLine:
    """一行凭证形状（M06 JournalLine 的镜像；由适配器转成 M06 类型）。"""

    account_id: str
    coa_code: str
    dc: str
    amount_minor: int                     # micro-USD
    entry_type: str
    wallet_id: str | None = None
    qty_minor: int | None = None


@dataclass(frozen=True)
class PostingRequest:
    """一次资金事件的凭证形状（不含 journal_id：那是 M06 的返回值）。"""

    event_type: str
    unit_type: str
    source_type: str
    source_id: str
    event_seq: int
    policy_version: str
    lines: tuple[LedgerLine, ...]
    occurred_at: datetime
    trace_id: str | None = None
    correlation_id: str | None = None
    ref_id: str | None = None
    idempotency_key: str | None = None

    def key(self) -> tuple[str, str, int]:
        return (self.source_type, self.source_id, int(self.event_seq))

    def total_debit_minor(self) -> int:
        return sum(line.amount_minor for line in self.lines if line.dc == "D")

    def total_credit_minor(self) -> int:
        return sum(line.amount_minor for line in self.lines if line.dc == "C")

    def balanced(self) -> bool:
        return self.total_debit_minor() == self.total_credit_minor() > 0

    def as_dict(self) -> dict[str, Any]:
        """适配器 / 测试用的普通字典（不暴露 M06 类型）。"""
        return {
            "event_type": self.event_type,
            "unit_type": self.unit_type,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "event_seq": int(self.event_seq),
            "policy_version": self.policy_version,
            "occurred_at": clock.as_utc(self.occurred_at),
            "trace_id": self.trace_id,
            "correlation_id": self.correlation_id,
            "ref_id": self.ref_id or self.source_id,
            "idempotency_key": self.idempotency_key or ":".join(
                [self.source_type, self.source_id, str(int(self.event_seq))]),
            "lines": [
                {"account_id": line.account_id, "coa_code": line.coa_code, "dc": line.dc,
                 "amount_minor": int(line.amount_minor), "entry_type": line.entry_type,
                 "wallet_id": line.wallet_id, "qty_minor": line.qty_minor,
                 "unit_scale": facts.LEDGER_UNIT_SCALE}
                for line in self.lines
            ],
        }


class LedgerPoster(Protocol):                        # pragma: no cover - 结构协议
    def post(self, conn: Any, request: PostingRequest) -> Mapping[str, Any]: ...


class NullLedgerPoster:
    """未接线 M06：fail-closed（资金写不自动重试；回调会按 PSP 语义重试）。"""

    def post(self, conn: Any, request: PostingRequest) -> Mapping[str, Any]:
        raise LedgerUnavailable(
            "M06 记账未接线：拒绝在未记账的情况下标记入账（fail-closed）",
            reason="ledger_unavailable")


class RecordingPoster:
    """测试 / 演练用：只记录请求，不落账（断言形状与幂等键）。"""

    def __init__(self) -> None:
        self.requests: list[PostingRequest] = []

    def post(self, conn: Any, request: PostingRequest) -> Mapping[str, Any]:
        self.requests.append(request)
        return {"journal_id": f"rec-{len(self.requests)}", "idempotent": False}


def _line(account_id: str, coa_code: str, dc: str, amount_minor: int, entry_type: str,
          *, wallet_id: str | None = None, qty_minor: int | None = None) -> LedgerLine:
    if int(amount_minor) <= 0:
        raise BadRequest("账本行金额必须 > 0（不为 0 金额记账）", field="amount_minor")
    return LedgerLine(account_id=account_id, coa_code=coa_code, dc=dc,
                      amount_minor=int(amount_minor), entry_type=entry_type,
                      wallet_id=wallet_id, qty_minor=qty_minor)


# ═══════════════════════════════════════════════════════════ E3（PSP 收款入账）
def e3_request(*, attempt: Mapping[str, Any], order: Mapping[str, Any],
               policy_version: str, occurred_at: datetime,
               trace_id: str | None = None) -> PostingRequest:
    """E3：借 1120 PSP 在途 / 贷 2101 服务预付款（毛额法，§20.3.1）。"""
    amount_minor = int(attempt.get("amount_minor") or order.get("amount_minor") or 0)
    amount_micro = to_micro(amount_minor)
    account = subject_account(str(order.get("account_id")))
    provider_txn = str(attempt.get("provider_txn_id") or "")
    if not provider_txn:
        raise BadRequest("E3 需要 provider_txn_id（幂等键 source_id）", field="provider_txn_id")
    return PostingRequest(
        event_type="E3", unit_type="USD", source_type=E3_SOURCE, source_id=provider_txn,
        event_seq=1, policy_version=policy_version,
        lines=(
            _line(account, "1120", "D", amount_micro, "deposit"),
            _line(account, "2101", "C", amount_micro, "deposit"),
        ),
        occurred_at=occurred_at, trace_id=trace_id,
        correlation_id=str(order.get("order_no") or ""), ref_id=provider_txn)


# ═══════════════════════════════════════════════════════════ E4（PSP 结算到账，两步）
def e4_requests(*, attempt: Mapping[str, Any], order: Mapping[str, Any],
                settled_minor: int, fee_minor: int, policy_version: str,
                occurred_at: datetime, trace_id: str | None = None) -> tuple[PostingRequest, ...]:
    """E4 两步记法（§20.3.1 / §20.7.4 G-2）：

    ① 借 1121（净额）+ 1910（手续费） / 贷 1120（全额）
    ② 借 1121（手续费）+ 5103（手续费） / 贷 1109（手续费）+ 1910（手续费）
    """
    gross = int(attempt.get("amount_minor") or order.get("amount_minor") or 0)
    net = int(settled_minor)
    fee = int(fee_minor)
    if net < 0 or fee < 0:
        raise BadRequest("结算净额与手续费必须 ≥ 0", field="settled_minor")
    if net + fee != gross:
        raise BadRequest(
            f"E4 结算不平：净额 {net} + 手续费 {fee} ≠ 订单金额 {gross}（容差 0）",
            field="settled_minor")
    provider_txn = str(attempt.get("provider_txn_id") or "")
    if not provider_txn:
        raise BadRequest("E4 需要 provider_txn_id（幂等键 source_id）", field="provider_txn_id")
    gross_micro, net_micro, fee_micro = to_micro(gross), to_micro(net), to_micro(fee)
    bank = platform_account("1121")
    topup = platform_account("1910")
    own = platform_account("1109")
    psp_fee = platform_account("5103")
    correlation = str(order.get("order_no") or "")
    step1 = PostingRequest(
        event_type="E4", unit_type="USD", source_type=E4_SOURCE, source_id=provider_txn,
        event_seq=2, policy_version=policy_version,
        lines=(
            _line(bank, "1121", "D", net_micro, "deposit"),
            _line(topup, "1910", "D", fee_micro, "adjust"),
            _line(subject_account(str(order.get("account_id"))), "1120", "C", gross_micro,
                  "deposit"),
        ),
        occurred_at=occurred_at, trace_id=trace_id, correlation_id=correlation,
        ref_id=provider_txn)
    step2 = PostingRequest(
        event_type="E4", unit_type="USD", source_type=E4_SOURCE, source_id=provider_txn,
        event_seq=3, policy_version=policy_version,
        lines=(
            _line(bank, "1121", "D", fee_micro, "deposit"),
            _line(psp_fee, "5103", "D", fee_micro, "adjust"),
            _line(own, "1109", "C", fee_micro, "transfer"),
            _line(topup, "1910", "C", fee_micro, "adjust"),
        ),
        occurred_at=occurred_at, trace_id=trace_id, correlation_id=correlation,
        ref_id=provider_txn)
    return (step1, step2)


# ═══════════════════════════════════════════════════════════ E5（法币兑换 USDT，两步）
def e5_requests(*, trade: Mapping[str, Any], policy_version: str, occurred_at: datetime,
                wallet_id: str | None = None, trace_id: str | None = None
                ) -> tuple[PostingRequest, ...]:
    """E5 两步记法（§20.3.1）：兑换 + 平台补足兑换费。

    trade 需要 trade_id / amount_minor（到账 USDT 对应 USD 分）/ fee_minor（兑换费）。
    目标科目由资金来源决定：客户备付法币 → 1102（CLIENT）；平台自有 → 1109（PLATFORM）。
    """
    trade_id = str(trade.get("trade_id") or "")
    if not trade_id:
        raise BadRequest("E5 需要 trade_id（幂等键 source_id）", field="trade_id")
    gross = int(trade.get("amount_minor") or 0)
    fee = int(trade.get("fee_minor") or 0)
    net = gross - fee
    if gross <= 0 or fee < 0 or net <= 0:
        raise BadRequest("E5 金额非法：amount_minor > fee_minor ≥ 0", field="amount_minor")
    net_micro, fee_micro, gross_micro = to_micro(net), to_micro(fee), to_micro(gross)
    target_coa = "1109" if str(trade.get("fund_class") or "CLIENT") == "PLATFORM" else "1102"
    target = platform_account(target_coa)
    bank = platform_account("1121")
    topup = platform_account("1910")
    own = platform_account("1109")
    conversion_fee = platform_account("5106")
    step1 = PostingRequest(
        event_type="E5", unit_type="USD", source_type=E5_SOURCE, source_id=trade_id,
        event_seq=1, policy_version=policy_version,
        lines=(
            _line(target, target_coa, "D", net_micro, "conversion", wallet_id=wallet_id,
                  qty_minor=net_micro),
            _line(topup, "1910", "D", fee_micro, "adjust"),
            _line(bank, "1121", "C", gross_micro, "conversion"),
        ),
        occurred_at=occurred_at, trace_id=trace_id,
        correlation_id=str(trade.get("correlation_id") or trade_id), ref_id=trade_id)
    step2 = PostingRequest(
        event_type="E5", unit_type="USD", source_type=E5_SOURCE, source_id=trade_id,
        event_seq=2, policy_version=policy_version,
        lines=(
            _line(target, target_coa, "D", fee_micro, "adjust", wallet_id=wallet_id,
                  qty_minor=fee_micro),
            _line(conversion_fee, "5106", "D", fee_micro, "adjust"),
            _line(own, "1109", "C", fee_micro, "transfer"),
            _line(topup, "1910", "C", fee_micro, "adjust"),
        ),
        occurred_at=occurred_at, trace_id=trace_id,
        correlation_id=str(trade.get("correlation_id") or trade_id), ref_id=trade_id)
    return (step1, step2)


def post_one(conn: Any, poster: LedgerPoster | None, request: PostingRequest) -> Mapping[str, Any]:
    """校验平衡后交给 M06 posting API（同一事务；失败由调用方回滚）。"""
    if not request.balanced():
        raise BadRequest(
            f"凭证借贷不平：Σ借 {request.total_debit_minor()} ≠ Σ贷 "
            f"{request.total_credit_minor()}（M06 INV-01）", field="lines")
    if poster is None:
        raise LedgerUnavailable("M06 记账未接线：拒绝在未记账的情况下推进资金状态",
                                reason="ledger_unavailable")
    result = poster.post(conn, request)
    if not isinstance(result, Mapping) or not result.get("journal_id"):
        raise LedgerUnavailable("M06 posting 返回非法结果（fail-closed）",
                               reason="ledger_bad_result")
    return result


def post_many(conn: Any, poster: LedgerPoster | None,
              requests: Iterable[PostingRequest]) -> list[Mapping[str, Any]]:
    """按 event_seq 顺序落多步凭证（E4 / E5 两步记法）。"""
    ordered = sorted(requests, key=lambda item: int(item.event_seq))
    return [post_one(conn, poster, request) for request in ordered]
