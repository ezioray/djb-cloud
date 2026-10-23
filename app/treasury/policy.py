# SPDX-License-Identifier: Apache-2.0
"""M08 领域策略（纯函数，零 IO）：状态机 / 池深度与扩容 / cap / 归集 / 出款 / 退款 / 签名 / 白名单。

这些函数是**不变量唯一入口**：order / wallet / payout / refund / router 都只通过它们判定，
测试也直接打这里。逐条对应规格 §3 不变量：

INV-01 一只钱包只属一个池与一个 fund_class；池键三元组不可变（库层 004 触发器 + 本层校验）
INV-02 激活批次不得携带转账指令（批次描述符只含地址 / wallet_id / 角色 / 阈值）
INV-03 standby 余额 = 0；ready = active ∧ gas_ok（激活 ≠ 可用）
INV-04 cap × 在用只数 ≤ 池合计上限；cap 下限 1,000 USD
INV-05 max_active 只自动上调（+4，硬顶 20），永不自动缩容
INV-06 池空不得停收款：新地址先摊到现有钱包，扩容量另行走批次
INV-07 金额一律整数最小单位；一单一币种；不接受浮点
INV-08 回调只认服务端通知 + 验签；provider_txn_id 唯一；重复回调不重复入账
INV-09 确认数 ≥64 可入账；大额 ≥200（链上路径；PSP 路径不适用）
INV-10 出款四要素：审批链 + 有效 attestation + 白名单生效 + 2/3 签名，缺一拒绝
INV-11 出款 ≤ 应付；只发 USDT；一期仅 Polygon
INV-12 退款只回原路、≤14 天、≤已付未消耗；不向第三方地址退款
INV-13 地址白名单 72h 冷却；首笔 ≤100 USDT 试转；出款前 7 天禁改
INV-14 gas 模式按批次快照，下一批生效、不追溯
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping, Sequence

from . import clock, facts
from .errors import (
    AmountMismatch,
    AttestationMissing,
    BadRequest,
    ChainUnsupported,
    Conflict,
    PayeeNotEligible,
)

__all__ = [
    # 订单 / 回调
    "order_transition", "order_is_terminal", "can_cancel_order", "validate_amount",
    "validate_currency", "provider_status", "check_callback_amount",
    "is_duplicate_callback", "utilization_pct",
    # 钱包 / 池
    "wallet_transition", "switch_transition", "wallet_ready", "pool_key", "split_pool_key",
    "canonical_fund_class", "legacy_fund_class", "storage_pool_key", "canonical_pool_id",
    "FUND_CLASSES", "depth", "utilization_pct", "forecast_daily", "target_capacity",
    "should_provision",
    "next_max_active", "select_switch_wallet", "switch_needed", "pool_empty_plan",
    "sweep_amount", "retire_step", "retire_required_attestation", "descriptor_merkle_root",
    "descriptors_for_batch", "assert_no_transfer_instructions", "cap_plan",
    # 出款 / 签名 / gas
    "payout_transition", "payout_totals", "classify_payout_item", "items_hash",
    "ensure_separation", "ensure_attestation", "approval_window_open", "payout_min_item",
    "large_payout_delayed", "intent_ttl_seconds", "intent_expires_at", "check_intent_alive",
    "signing_transition", "signing_complete", "event_stage", "ensure_stage_order",
    "normalize_gas_mode", "gas_snapshot",
    # 退款
    "refund_deadline", "check_refund_window", "check_original_route", "remaining_refundable",
    "refund_transition", "approval_cooldown_ready", "ensure_dual_control",
    # 地址白名单
    "address_cooldown_until", "check_first_transfer", "check_address_change_allowed",
    "address_eligible", "check_payee_eligible",
]


# ═══════════════════════════════════════════════════════════ 订单（§3 / INV-07 / INV-08）
_ORDER_TRANSITIONS: dict[str, frozenset[str]] = {
    "created": frozenset({"pending", "failed", "closed", "expired"}),
    "pending": frozenset({"paid", "failed", "closed", "expired"}),
    "paid": frozenset({"credited"}),
    "credited": frozenset(),
    "failed": frozenset(),
    "closed": frozenset(),
    "expired": frozenset(),
}


def order_is_terminal(status: str) -> bool:
    return status in facts.ORDER_TERMINAL


def order_transition(status: str, target: str) -> str:
    """订单状态机（created → pending → paid → credited；终态不可回退）。"""
    allowed = _ORDER_TRANSITIONS.get(status)
    if allowed is None:
        raise Conflict(f"未知订单状态：{status}", reason="unknown_order_status")
    if target not in allowed:
        raise Conflict(f"订单状态迁移不允许：{status} → {target}", reason="illegal_transition")
    return target


def can_cancel_order(status: str) -> bool:
    """取消只允许 created / pending（已支付只能退款，不能取消）。"""
    return status in ("created", "pending")


def validate_amount(value: Any, *, field: str = "amount_minor") -> int:
    """INV-07：正整数最小单位，拒绝布尔 / 浮点 / 字符串数字 / ≤0。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadRequest(f"{field} 必须是整数最小单位（不接受浮点 / 字符串）", field=field)
    if value <= 0:
        raise BadRequest(f"{field} 必须 > 0", field=field)
    return int(value)


def validate_currency(value: Any, *, amount_minor: int | None = None) -> str:
    """ISO-4217 三字母大写；超精度直接拒绝（整数最小单位本身不丢精度）。"""
    if not isinstance(value, str):
        raise BadRequest("currency 必须是 ISO-4217 三字母代码", field="currency")
    text = value.strip().upper()
    if len(text) != 3 or not text.isalpha():
        raise BadRequest("currency 必须是 ISO-4217 三字母代码", field="currency")
    if text not in facts.PSP_CURRENCIES:
        raise BadRequest(f"currency 不在支持列表 {sorted(facts.PSP_CURRENCIES)}", field="currency")
    if amount_minor is not None and isinstance(amount_minor, int) and amount_minor <= 0:
        raise BadRequest("amount_minor 必须 > 0", field="amount_minor")
    return text


def provider_status(raw: Any) -> str:
    """通道状态码 → 内部粗粒度状态（0/3 pending，1 succeeded，2 failed，6 closed）。"""
    text = str(raw).strip()
    status = facts.PROVIDER_STATUSES.get(text)
    if status is None:
        raise BadRequest(f"未知通道状态码：{text}", field="provider_status")
    return status


#: 可以被回调推进到 paid / credited 的「未入账」状态（created / pending 属于正常在途）
_ORDER_CREDITABLE = frozenset({"created", "pending", "paid", "credited"})


def check_callback_amount(*, order_status: str, order_amount_minor: int,
                          paid_minor: int, credited_minor: int) -> None:
    """回调四项校验里的金额校验（INV-08 / 40911）：订单状态可入账、到账 == 订单金额。

    重复回调（已入账 >= 订单金额）走 40910 幂等路径，不在这里判成 40911。
    """
    if order_status not in _ORDER_CREDITABLE:
        raise Conflict(f"订单当前状态不可入账（{order_status}）", reason="order_not_payable")
    if int(paid_minor) != int(order_amount_minor):
        raise AmountMismatch(
            f"到账金额与订单不符（订单 {int(order_amount_minor)} 分，到账 {int(paid_minor)} 分）",
            reason="amount_mismatch")


def is_duplicate_callback(credited_minor: int, amount_minor: int) -> bool:
    """INV-08：已入账金额已达订单金额 → 重复回调（40910，幂等返回成功）。"""
    return int(credited_minor) >= int(amount_minor)


# ═══════════════════════════════════════════════════════════ 钱包与池（INV-01…INV-06）
_WALLET_TRANSITIONS: dict[str, frozenset[str]] = {
    facts.WALLET_PROVISIONING: frozenset({facts.WALLET_ACTIVE, facts.WALLET_FAILED_STATUS}),
    facts.WALLET_ACTIVE: frozenset({facts.WALLET_DRAINING, facts.WALLET_FROZEN}),
    facts.WALLET_DRAINING: frozenset({facts.WALLET_ZERO, facts.WALLET_FROZEN}),
    facts.WALLET_ZERO: frozenset({facts.WALLET_FROZEN}),
    facts.WALLET_FROZEN: frozenset({facts.WALLET_RETIRED}),
    facts.WALLET_RETIRED: frozenset(),
    facts.WALLET_FAILED_STATUS: frozenset(),
    "paused": frozenset({facts.WALLET_ACTIVE, facts.WALLET_FROZEN}),
}
_SWITCH_TRANSITIONS: dict[str, frozenset[str]] = {
    facts.SWITCH_STANDBY: frozenset({facts.SWITCH_IN_SERVICE}),
    facts.SWITCH_IN_SERVICE: frozenset({facts.SWITCH_SWITCHING_OUT}),
    facts.SWITCH_SWITCHING_OUT: frozenset({facts.SWITCH_DRAINING}),
    facts.SWITCH_DRAINING: frozenset(),
}


#: 规范 fund_class（Lead 2026-10-24 裁决：只有 CLIENT / PLATFORM；hot/warm/cold 是 role）
FUND_CLASSES: tuple[str, ...] = ("CLIENT", "PLATFORM")
#: 004 存量表的**历史命名**（只做存储层映射，不改旧表、不改旧命名）
FUND_CLASS_LEGACY: dict[str, str] = {"CLIENT": "customer", "PLATFORM": "platform"}
FUND_CLASS_CANONICAL: dict[str, str] = {value: key for key, value in FUND_CLASS_LEGACY.items()}


def canonical_fund_class(value: Any) -> str:
    """接受 CLIENT / PLATFORM（规范）与 customer / platform（历史），一律返回规范值。"""
    raw = str(value or "").strip()
    if raw.upper() in FUND_CLASSES:
        return raw.upper()
    if raw.lower() in FUND_CLASS_CANONICAL:
        return FUND_CLASS_CANONICAL[raw.lower()]
    raise BadRequest("fund_class 必须是 CLIENT / PLATFORM", field="fund_class")


def legacy_fund_class(value: Any) -> str:
    """规范 fund_class → 004 存量表的历史命名（customer / platform）。"""
    return FUND_CLASS_LEGACY[canonical_fund_class(value)]


def pool_key(chain: str, role: str, fund_class: str) -> str:
    """规范池键：chain:role:fund_class（fund_class ∈ CLIENT / PLATFORM）。"""
    return f"{chain}:{role}:{canonical_fund_class(fund_class)}"


def storage_pool_key(pool_id: str) -> str:
    """规范池键 → 004 存量表存储键（fund_class 用历史命名 customer / platform）。"""
    chain, role, fund_class = split_pool_key(pool_id)
    return f"{chain}:{role}:{FUND_CLASS_LEGACY[fund_class]}"


def canonical_pool_id(storage_pool_id: str) -> str:
    """存储键 → 规范池键（API / 事件 / 响应一律用规范值）。"""
    parts = str(storage_pool_id).split(":")
    if len(parts) != 3:
        return str(storage_pool_id)
    chain, role, fund_class = parts
    return f"{chain}:{role}:{canonical_fund_class(fund_class)}"


def split_pool_key(pool_id: str) -> tuple[str, str, str]:
    """池键三元组（INV-01：chain:role:fund_class，三段缺一不可；fund_class 归一为规范值）。"""
    parts = str(pool_id).split(":")
    if len(parts) != 3 or not all(parts):
        raise BadRequest("pool_id 必须是 chain:role:fund_class", field="pool_id")
    chain, role, raw_fund_class = parts
    if chain not in ("polygon",):
        raise ChainUnsupported("一期仅 Polygon（K6）", reason="chain_unsupported")
    if role not in ("hot", "warm"):
        raise BadRequest("role 必须是 hot / warm", field="pool_id")
    fund_class = canonical_fund_class(raw_fund_class)
    if role == "hot" and fund_class == "PLATFORM":
        raise BadRequest("平台热池不建（决策 K5）", field="pool_id")
    return chain, role, fund_class


def wallet_transition(status: str, target: str) -> str:
    allowed = _WALLET_TRANSITIONS.get(status)
    if allowed is None:
        raise Conflict(f"未知钱包状态：{status}", reason="unknown_wallet_status")
    if target not in allowed:
        raise Conflict(f"钱包状态迁移不允许：{status} → {target}", reason="illegal_transition")
    return target


def switch_transition(state: str, target: str) -> str:
    allowed = _SWITCH_TRANSITIONS.get(state)
    if allowed is None:
        raise Conflict(f"未知 switch_state：{state}", reason="unknown_switch_state")
    if target not in allowed:
        raise Conflict(f"switch_state 迁移不允许：{state} → {target}", reason="illegal_transition")
    return target


def wallet_ready(wallet: Mapping[str, Any]) -> bool:
    """INV-03：ready = active ∧ gas_ok（激活 ≠ 可用）。"""
    return wallet.get("status") == facts.WALLET_ACTIVE and bool(wallet.get("gas_ok"))


def depth(wallets: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """池深度：depth_ready = active ∧ gas_ok；depth_available = ready + provisioning。"""
    ready = available = in_service = 0
    for wallet in wallets:
        status = wallet.get("status")
        if wallet_ready(wallet):
            ready += 1
            available += 1
            if wallet.get("switch_state") == facts.SWITCH_IN_SERVICE:
                in_service += 1
        elif status == facts.WALLET_PROVISIONING:
            available += 1
    return {"depth_ready": ready, "depth_available": available, "in_service": in_service}


def forecast_daily(series_minor: Sequence[int], window_days: int) -> int:
    """14 天滚动窗口的日均收款预测（整数分；空序列 → 0）。"""
    if not series_minor:
        return 0
    window = list(series_minor)[-int(window_days):] if window_days > 0 else list(series_minor)
    if not window:
        return 0
    return int(sum(int(x) for x in window) // len(window))


def target_capacity(daily_minor: int, horizon_days: int = facts.HORIZON_DAYS,
                    multiplier: int = facts.TARGET_CAPACITY_MULTIPLIER) -> int:
    """目标容量 = 未来 7 天预测 × 2（03-facts §2）。"""
    return int(daily_minor) * int(horizon_days) * int(multiplier)


def should_provision(*, depth_available: int, min_spare: int, projected_utilization_pct: int,
                     auto_expand: bool = True, provision_trigger_pct: int = facts.PROVISION_TRIGGER_PCT
                     ) -> bool:
    """预生成触发：备用深度不足，或预计利用率 >60%（03-facts §2）。"""
    if not auto_expand:
        return False
    if depth_available < int(min_spare):
        return True
    return int(projected_utilization_pct) > int(provision_trigger_pct)


def next_max_active(current: int) -> int:
    """INV-05：只自动上调（每次 +4），硬顶 20；永不自动缩容。"""
    return min(int(current) + facts.MAX_ACTIVE_STEP, facts.MAX_ACTIVE_HARD_CAP)


def cap_plan(*, pool_cap_minor: int, in_service_count: int,
             forecast_5d_minor: int | None = None) -> int:
    """单钱包 cap = min(10,000 USD, 5 天预测)；池上限压缩时向下取整但不低于 1,000 USD。

    INV-04：cap × 在用只数 ≤ 池合计上限。若池上限连「下限 × 只数」都放不下，拒绝激活
    （配置不一致，不是扩容动作能解决的）。
    """
    count = max(int(in_service_count), 1)
    cap = facts.WALLET_CAP_MINOR
    if forecast_5d_minor is not None and int(forecast_5d_minor) > 0:
        cap = min(cap, int(forecast_5d_minor))
    if cap * count > int(pool_cap_minor):
        cap = int(pool_cap_minor) // count
    cap = max(cap, facts.WALLET_CAP_FLOOR_MINOR)
    if cap * count > int(pool_cap_minor):
        raise Conflict(
            "池合计上限不足以覆盖 cap 下限（INV-04）：请先抬高池上限或减少在用只数",
            reason="pool_cap_exceeded")
    return cap


def utilization_pct(*, balance_minor: int, cap_minor: int) -> int:
    """单钱包利用率（百分数，整数向下取整；cap=0 视为 100%）。"""
    if cap_minor <= 0:
        return 100
    return int(int(balance_minor) * 100 // int(cap_minor))


def switch_needed(*, balance_minor: int, cap_minor: int,
                  threshold_pct: int = facts.SWITCH_THRESHOLD_PCT) -> bool:
    """一级触发：单钱包余额 ≥ cap × switch_threshold_pct。"""
    if cap_minor <= 0:
        return True
    return int(balance_minor) * 100 >= int(cap_minor) * int(threshold_pct)


def select_switch_wallet(wallets: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    """选择策略：least_utilized（余额 / cap 最低）→ 并列取 newest_activated。"""
    candidates = [w for w in wallets if wallet_ready(w)]
    if not candidates:
        return None

    def sort_key(wallet: Mapping[str, Any]):
        cap = int(wallet.get("cap_minor") or facts.WALLET_CAP_MINOR)
        utilization = int(wallet.get("balance_minor") or 0) / cap if cap else 1.0
        activated = wallet.get("activated_at") or wallet.get("provisioned_at") or datetime.min
        return (utilization, -clock.as_utc(activated).timestamp())

    return dict(sorted(candidates, key=sort_key)[0])


def pool_empty_plan(*, wallets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """INV-06 / §19.5.7 二级：池空（无 ready 钱包）时**不停收款**，新地址摊到现有钱包。

    返回 {stop_collection: False, spread_to: [...wallet_id], reason}：
    spread_to 是 active（gas 不足也算）的钱包，按余额升序；扩容量另行走批次。
    """
    active = [w for w in wallets if w.get("status") == facts.WALLET_ACTIVE]
    ordered = sorted(active, key=lambda w: int(w.get("balance_minor") or 0))
    return {
        "stop_collection": False,
        "spread_to": [str(w.get("wallet_id")) for w in ordered],
        "expand_required": True,
        "reason": "pool_empty_spread_then_provision",
    }


def sweep_amount(*, balance_minor: int, cap_minor: int, gas_ok: bool,
                 gas_reserve_pol: int = facts.GAS_RESERVE_POL,
                 dust_minor: int = facts.DUST_MINOR) -> int:
    """归集金额 = 余额 − gas 预留 − 尘埃；未达 60% 阈值 / gas 不足 / 只剩尘埃 → 0。

    gas_reserve_pol 传钱包可用 POL 余额；低于 10 POL 不归集（03-facts §1）。
    """
    if not gas_ok or int(gas_reserve_pol) < facts.GAS_RESERVE_POL:
        return 0
    if not switch_needed(balance_minor=balance_minor, cap_minor=cap_minor,
                         threshold_pct=facts.SWEEP_TRIGGER_PCT):
        return 0
    remaining = int(balance_minor) - int(dust_minor)
    return max(remaining, 0)


_RETIRE_STEPS: tuple[str, ...] = ("drain", "zero", "frozen", "retire")
_RETIRE_TARGET: dict[str, tuple[str, str]] = {
    "drain": (facts.WALLET_ACTIVE, facts.WALLET_DRAINING),
    "zero": (facts.WALLET_DRAINING, facts.WALLET_ZERO),
    "frozen": (facts.WALLET_ZERO, facts.WALLET_FROZEN),
    "retire": (facts.WALLET_FROZEN, facts.WALLET_RETIRED),
}


def retire_step(*, status: str, step: str, balance_minor: int, in_flight: int,
                last_switched_at: datetime | None, now: datetime,
                hot_wallet_wait_h: int = 24) -> str:
    """退休四步（§19.4.10(5)）：drain → zero → frozen → retire。

    热钱包先切地址并等 ≥24h（覆盖晚到入金与确认延迟）；zero 要求余额 0 且无在途。
    """
    if step not in _RETIRE_TARGET:
        raise BadRequest(f"retire step 必须是 {list(_RETIRE_STEPS)} 之一", field="step")
    expected, target = _RETIRE_TARGET[step]
    if status != expected:
        raise Conflict(f"退休步骤顺序错误：当前 {status}，{step} 要求 {expected}",
                       reason="retire_step_out_of_order")
    if step == "zero":
        if int(balance_minor) != 0:
            raise Conflict("余额不为 0 不得进入 zero（先归集）", reason="balance_not_zero")
        if int(in_flight) != 0:
            raise Conflict("存在在途交易，不得进入 zero", reason="in_flight_pending")
        if last_switched_at is not None:
            waited = clock.as_utc(now) - clock.as_utc(last_switched_at)
            if waited < timedelta(hours=int(hot_wallet_wait_h)):
                raise Conflict("切地址后未满 24h，不得归零（晚到入金与确认延迟）",
                               reason="retire_wait_not_met")
    return target


def retire_required_attestation(step: str) -> bool:
    """退休门禁：复核人对「对账已平 + 余额 0 + 无在途」签 recon_attestation。"""
    return step == "retire"


def descriptor_merkle_root(descriptors: Sequence[Mapping[str, Any]]) -> str:
    """批次描述符 Merkle 根（sha256 两两配对；奇数补自身），稳定排序后计算。"""
    leaves = []
    for descriptor in descriptors:
        text = "|".join(str(descriptor[key]) for key in (
            "wallet_id", "address", "role", "fund_class", "signer_set_ref", "threshold"))
        leaves.append(hashlib.sha256(text.encode("utf-8")).hexdigest())
    if not leaves:
        return hashlib.sha256(b"empty").hexdigest()
    level = sorted(leaves)
    while len(level) > 1:
        nxt: list[str] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            nxt.append(hashlib.sha256((left + right).encode("utf-8")).hexdigest())
        level = nxt
    return level[0]


def descriptors_for_batch(*, pool_id: str, wallet_ids: Sequence[str],
                          addresses: Sequence[str], signer_set_ref: str,
                          threshold: int = facts.SIGNER_THRESHOLD) -> list[dict[str, Any]]:
    """构造一批描述符（地址 + wallet_id + 角色 + 阈值）；**不含任何转账指令**（INV-02）。"""
    chain, role, fund_class = split_pool_key(pool_id)
    if len(wallet_ids) != len(addresses):
        raise BadRequest("wallet_ids 与 addresses 数量必须一致", field="wallets")
    if not (facts.ACTIVATE_BATCH_MIN <= len(wallet_ids) <= facts.ACTIVATE_BATCH_MAX):
        raise BadRequest(
            f"每批只数必须在 {facts.ACTIVATE_BATCH_MIN}..{facts.ACTIVATE_BATCH_MAX}",
            field="wallet_count")
    return [
        {"wallet_id": wallet_id, "address": address.lower(), "role": role,
         "fund_class": fund_class, "chain_id": chain, "signer_set_ref": signer_set_ref,
         "threshold": int(threshold)}
        for wallet_id, address in zip(wallet_ids, addresses)
    ]


def assert_no_transfer_instructions(payload: Mapping[str, Any]) -> None:
    """INV-02：激活批次载荷不得出现转账指令（收款人 / 金额 / calldata / 目的地址）。"""
    forbidden = {"to", "to_address", "recipient", "recipients", "amount", "amount_minor",
                 "calldata", "data", "value", "transfer", "transfer_instruction"}
    hit = sorted(forbidden & {str(key).lower() for key in payload})
    if hit:
        raise BadRequest(f"激活批次不得携带转账指令（INV-02）：{hit}", field="batch")


# ═══════════════════════════════════════════════════════════ 出款 / 签名 / gas（INV-10/11/14）
_PAYOUT_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"prepared", "failed"}),
    "prepared": frozenset({"checked", "failed"}),
    "checked": frozenset({"signed", "failed"}),
    "signed": frozenset({"broadcast", "failed"}),
    "broadcast": frozenset({"settled", "partial", "failed"}),
    "settled": frozenset(),
    "partial": frozenset(),
    "failed": frozenset(),
}


def payout_transition(status: str, target: str) -> str:
    allowed = _PAYOUT_TRANSITIONS.get(status)
    if allowed is None:
        raise Conflict(f"未知批次状态：{status}", reason="unknown_batch_status")
    if target not in allowed:
        raise Conflict(f"批次状态迁移不允许：{status} → {target}", reason="illegal_transition")
    return target


def classify_payout_item(*, gross_minor: int, fee_minor: int,
                         min_item_minor: int = facts.PAYOUT_MIN_ITEM_MINOR) -> dict[str, Any]:
    """明细分类：fee >= gross 或净额 <10 USDT → carried 滚存；否则 pending。

    净额公式（§19.8.1）：platform_fee 不进明细；明细 gross 已是共享方毛额，
    net = gross − network_fee。尾差归平台（2901），本模块不重算分润比例。
    """
    gross = int(gross_minor)
    fee = int(fee_minor)
    if gross < 0 or fee < 0:
        raise BadRequest("gross_minor / fee_minor 必须 ≥ 0", field="gross_minor")
    if fee >= gross:
        return {"status": "carried", "gross_minor": gross, "fee_minor": fee, "net_minor": 0}
    net = gross - fee
    if net < int(min_item_minor):
        return {"status": "carried", "gross_minor": gross, "fee_minor": fee, "net_minor": 0}
    return {"status": "pending", "gross_minor": gross, "fee_minor": fee, "net_minor": net}


def payout_totals(items: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """批次合计：carried 笔不进总额（滚存下批，不出现负数应付）。"""
    gross = fee = net = count = 0
    for item in items:
        if item.get("status") == "carried":
            continue
        gross += int(item.get("gross_minor") or 0)
        fee += int(item.get("fee_minor") or 0)
        net += int(item.get("net_minor") or 0)
        count += 1
    return {"total_gross_minor": gross, "total_fee_minor": fee,
            "total_net_minor": net, "item_count": count}


def items_hash(items: Sequence[Mapping[str, Any]]) -> str:
    """明细 Merkle 根（对 net_amount 与收款地址；决策人签的摘要含 total_gross/fee/net）。"""
    lines = sorted(
        f"{item.get('payee_address')}|{int(item.get('net_minor') or 0)}" for item in items)
    if not lines:
        return hashlib.sha256(b"empty").hexdigest()
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def ensure_separation(maker: str | None, checker: str | None, *, what: str = "复核") -> None:
    """SoD：制单 ≠ 复核（§19.11.2 硬规则；库层 CHECK 兜底）。"""
    if maker and checker and str(maker) == str(checker):
        raise Conflict(f"{what}人不得是制单人（职责分离）", reason="separation_of_duty")


def ensure_attestation(*, attestation_ref: str | None, valid: bool) -> None:
    """INV-10：无 attestation / 校验不通过 → 40916，不得进入 checked / retired。"""
    if not attestation_ref or not valid:
        raise AttestationMissing("缺有效 recon_attestation：不得出款 / 不得退休（INV-10）")


def approval_window_open(*, checked_at: datetime | None, now: datetime,
                         ttl_s: int = facts.PAYOUT_APPROVAL_EXPIRE_S) -> bool:
    """审批后 30 分钟内可执行，超时作废（§19.11.3）。"""
    if checked_at is None:
        return False
    return clock.as_utc(now) <= clock.as_utc(checked_at) + timedelta(seconds=int(ttl_s))


def payout_min_item(net_minor: int) -> bool:
    """单笔 ≥10 USDT 才出款，不足滚存（03-facts §3）。"""
    return int(net_minor) >= facts.PAYOUT_MIN_ITEM_MINOR


def large_payout_delayed(amount_minor: int, daily_limit_minor: int | None) -> bool:
    """单笔 > 日限额 50% → 进 24h 链下延迟队列（可撤销）。"""
    if daily_limit_minor is None or int(daily_limit_minor) <= 0:
        return False
    return int(amount_minor) * 100 > int(daily_limit_minor) * facts.LARGE_PAYOUT_THRESHOLD_PCT


def intent_ttl_seconds(kind: str) -> int:
    """WALLET_PROVISION 不动钱、只开容量 → 24h；其余 30 分钟（§19.5.2）。"""
    if kind == "WALLET_PROVISION":
        return facts.WALLET_PROVISION_SIGNING_TTL_S
    return facts.SIGNING_TTL_S


def intent_expires_at(kind: str, created_at: datetime) -> datetime:
    return clock.as_utc(created_at) + timedelta(seconds=intent_ttl_seconds(kind))


def check_intent_alive(kind: str, created_at: datetime, expires_at: datetime,
                       now: datetime) -> None:
    """过期 / 超窗口 → 40919（签名域只认未过期 intent）。"""
    allowed = intent_ttl_seconds(kind)
    if expires_at > clock.as_utc(created_at) + timedelta(seconds=allowed):
        raise Conflict(f"{kind} 的签名有效期不得超过 {allowed}s（§19.5.2）",
                       reason="intent_ttl_exceeded")
    if clock.as_utc(now) >= clock.as_utc(expires_at):
        raise Conflict("资金意图已过期：请重新发起（新 nonce）", reason="intent_expired")


_SIGNING_TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({"signed", "expired", "failed"}),
    "signed": frozenset(),
    "expired": frozenset(),
    "failed": frozenset(),
}


def signing_transition(status: str, target: str) -> str:
    allowed = _SIGNING_TRANSITIONS.get(status)
    if allowed is None:
        raise Conflict(f"未知签名请求状态：{status}", reason="unknown_signing_status")
    if target not in allowed:
        raise Conflict(f"签名状态迁移不允许：{status} → {target}", reason="illegal_transition")
    return target


_EVENT_STAGE: dict[str, int] = {name: index for index, name in enumerate(facts.SIGNING_EVENTS)}


def event_stage(event: str) -> int:
    if event not in _EVENT_STAGE:
        raise BadRequest(f"签名事件必须是 {list(facts.SIGNING_EVENTS)} 之一", field="event")
    return _EVENT_STAGE[event]


def ensure_stage_order(last_event: str | None, event: str) -> None:
    """六事件按序：requested→presented→signed→verified→co_signed→broadcast。

    允许「同一阶段不同签名人」（2-of-3 的两次 signed 用 signer_type 区分），不允许回退；
    broadcast 只能有一次（库层唯一索引兜底）。
    """
    if last_event is None:
        if event != "requested":
            raise Conflict("签名请求必须先有 requested 事件", reason="signing_stage_out_of_order")
        return
    if _EVENT_STAGE[event] < _EVENT_STAGE[last_event]:
        raise Conflict(f"签名事件顺序错误：{last_event} → {event}", reason="signing_stage_out_of_order")


def signing_complete(events: Iterable[Mapping[str, Any]], *, threshold: int = facts.SIGNER_THRESHOLD
                     ) -> bool:
    """2/3 签齐：owner signed + reviewer/company co_signed + HSM verified，签名数 ≥ 门限。"""
    signed = co_signed = verified = False
    signers: set[str] = set()
    for item in events:
        name = item.get("event")
        signer = item.get("signer_type")
        if name == "signed":
            signed = True
            if signer:
                signers.add(str(signer))
        elif name == "co_signed":
            co_signed = True
            if signer:
                signers.add(str(signer))
        elif name == "verified":
            verified = True
    return signed and co_signed and verified and len(signers) >= int(threshold)


def normalize_gas_mode(mode: Any, bearer: Any = None) -> str:
    """gas 三模式规范化（含 03-facts §9 legacy 写法）。"""
    from . import config_source

    return config_source.gas_mode_for(mode, bearer)


def gas_snapshot(config) -> dict[str, str]:
    """批次 gas 快照（INV-14：下一批生效、不追溯；切换不退不补）。"""
    return {"gas_mode": config.gas_mode, "gas_bearer": config.gas_bearer,
            "policy_version": config.policy_version}


# ═══════════════════════════════════════════════════════════ 退款（INV-12）
_REFUND_TRANSITIONS: dict[str, frozenset[str]] = {
    "requested": frozenset({"approved", "cancelled", "failed"}),
    "approved": frozenset({"executing", "cancelled"}),
    "executing": frozenset({"succeeded", "failed"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}


def refund_deadline(paid_at: datetime, window_days: int = facts.REFUND_WINDOW_DAYS) -> datetime:
    """原订单 paid_at + 14 天（03-facts §5 / INV-12）。"""
    return clock.as_utc(paid_at) + timedelta(days=int(window_days))


def check_refund_window(deadline_at: datetime, now: datetime) -> None:
    if clock.as_utc(now) > clock.as_utc(deadline_at):
        raise Conflict("退款已超过 14 天窗口（INV-12）", reason="refund_window_expired")


def check_original_route(original_route: str, requested_route: str) -> None:
    """INV-12：只回原路；请求里带不同路由（第三方地址）→ 拒绝。"""
    if not original_route or not requested_route:
        raise BadRequest("退款必须指定原路信息", field="original_route")
    if str(original_route).strip().lower() != str(requested_route).strip().lower():
        raise Conflict("退款只回原路，不接受第三方地址（INV-12）", reason="original_route_only")


def remaining_refundable(*, paid_minor: int, refunded_minor: int, consumed_minor: int) -> int:
    """≤ 已付未消耗：paid − consumed − 已退（不为负）。"""
    remaining = int(paid_minor) - int(consumed_minor) - int(refunded_minor)
    return max(remaining, 0)


def refund_transition(status: str, target: str) -> str:
    allowed = _REFUND_TRANSITIONS.get(status)
    if allowed is None:
        raise Conflict(f"未知退款状态：{status}", reason="unknown_refund_status")
    if target not in allowed:
        raise Conflict(f"退款状态迁移不允许：{status} → {target}", reason="illegal_transition")
    return target


def approval_cooldown_ready(cooldown_until: datetime, now: datetime) -> bool:
    """退款「双人 + 24h 冷却」：冷却是审批前置（§19.9.2）。"""
    return clock.as_utc(now) >= clock.as_utc(cooldown_until)


def ensure_dual_control(requester: str | None, approver: str | None) -> None:
    """INV-12：退款审批双人（审批人 ≠ 申请人）。"""
    if requester and approver and str(requester) == str(approver):
        raise Conflict("退款审批人不得是申请人（双人复核）", reason="separation_of_duty")


# ═══════════════════════════════════════════════════════════ 地址白名单（INV-13）
def address_cooldown_until(verified_at: datetime,
                           cooldown_h: int = facts.ADDRESS_COOLDOWN_H) -> datetime:
    """新地址 72h 冷却（从所有权验证通过时刻算）。"""
    return clock.as_utc(verified_at) + timedelta(hours=int(cooldown_h))


def check_first_transfer(amount_minor: int,
                         max_minor: int = facts.FIRST_TRANSFER_MAX_MINOR) -> None:
    """首笔试转 ≤100 USDT（INV-13）。"""
    if int(amount_minor) > int(max_minor):
        raise PayeeNotEligible(
            f"地址首笔转账不得超过 100 USDT（INV-13），收到 {int(amount_minor)} 分",
            reason="first_transfer_limit")


def check_address_change_allowed(*, changed_at: datetime, next_payout_at: datetime | None,
                                 now: datetime,
                                 freeze_days: int = facts.ADDRESS_FREEZE_BEFORE_PAYOUT_D) -> None:
    """出款前 7 天禁改地址；新地址须过 24h 变更冷却（03-facts §3）。"""
    if next_payout_at is not None:
        gap = clock.as_utc(next_payout_at) - clock.as_utc(now)
        if gap <= timedelta(days=int(freeze_days)):
            raise Conflict("出款前 7 天禁止变更收款地址（03-facts §3）",
                           reason="address_change_frozen")
    if clock.as_utc(now) < clock.as_utc(changed_at) + timedelta(
            hours=facts.ADDRESS_CHANGE_COOLDOWN_H):
        raise Conflict("地址变更 24h 冷却未结束", reason="address_cooldown")


def address_eligible(address: Mapping[str, Any], *, now: datetime) -> tuple[bool, str | None]:
    """出款前地址门禁：whitelisted + 冷却已过 + 风控未命中。"""
    if address.get("status") != "whitelisted":
        return False, "address_not_whitelisted"
    cooldown = address.get("cooldown_until")
    if cooldown is None or clock.as_utc(now) < clock.as_utc(cooldown):
        return False, "address_cooldown"
    if str(address.get("risk_level") or "low").lower() == "high":
        return False, "address_risk_rejected"
    return True, None


def check_payee_eligible(address: Mapping[str, Any] | None, *, now: datetime) -> None:
    """INV-10 第三要素：白名单生效（不存在 → 42210；冷却 / 风险 → 42210 / 42211）。"""
    if address is None:
        raise PayeeNotEligible("收款地址未通过准入（白名单 / 所有权验证，INV-10）",
                               reason="payee_not_eligible")
    ok, reason = address_eligible(address, now=now)
    if ok:
        return
    if reason == "address_risk_rejected":
        from .errors import AddressRiskRejected

        raise AddressRiskRejected("地址风控拒绝（42211）", reason="address_risk_rejected")
    raise PayeeNotEligible(f"收款地址不可用：{reason}（INV-13）", reason=reason or "not_eligible")