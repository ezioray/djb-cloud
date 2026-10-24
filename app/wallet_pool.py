# SPDX-License-Identifier: Apache-2.0
"""钱包池与自动扩容（设计 v4 §19.4.3 / §19.4.10，决策 K5）。

本模块只做三件事，**不签名、不转账、不写账本**：

1. 容量预测：14 天滚动收款 → 预测未来 7 天；异常/无数据时按近 7 天实测兜底。
2. 扩容决策：min_spare / 2× 预测 / 利用率 >60% 预生成 / 池空优先保业务 / max_active 自动上调。
3. 批次状态机：`WALLET_PROVISION` 批次（2/3 签激活、24h 过期作废、幂等、不得夹带转账）。

红线（与设计文档一致）：
- 扩容只开容量，不加权限、不抬限额；不改变单钱包 cap 之外的任何限额口径。
- 批次内不得携带任何转账指令；链上动作只产描述符 / intent，签名由签名服务完成。
- 池空时先把新地址摊到现有钱包（最高 100% cap）并同时扩容，**不以池空为由停收款**。
- 金额一律整数 minor（USD 分，1 USD = 100 minor）；不出现浮点。

开关（三字段齐全，默认关闭）见 `FEATURE_FLAGS`；关闭后回到手工扩容，批次表保留不删。
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Callable, Iterable, Mapping, Sequence

from .ledger import recompute

# --------------------------------------------------------------------------- 口径常量
# 池深与批次（§19.4.10(1)(2)(3)，决策 K5）
MIN_SPARE = 3
MAX_ACTIVE_HOT = 8
MAX_ACTIVE_WARM = 4
MAX_ACTIVE_HARD_CAP = 20          # 自动上调硬顶
MAX_ACTIVE_STEP = 4               # 每次 +4
SWITCH_THRESHOLD_PCT = 70         # 余额 / cap 触顶 → 切新收款地址
ACTIVATE_BATCH_SIZE = 4           # 每批只数（可配 1–8）
PROVISION_LEAD_TIME_H = 12        # 提前量
BATCH_TTL_H = 24                  # 批次 expiresAt 上限（该动作不动钱，放宽到 24h）
MAX_BATCH_SIZE = 8

# 预测（§19.4.10(4)）
HISTORY_WINDOW_DAYS = 14          # 14 天滚动
HORIZON_DAYS = 7                  # 预测未来 7 天
MIN_HISTORY_DAYS = 3              # 少于 3 天历史视为预测不可用
TARGET_MULTIPLIER = 2             # 目标容量 ≥ 2× 7 天预测
ANOMALY_RATIO = 3                 # 预测与近 7 天实测相差 3 倍 → 判为异常，实测兜底
UTILIZATION_PREGEN_PCT = 60       # 预计利用率 >60% 即预生成（不等到触顶）
COLLECTION_PCT = 60               # 归集阈值（余额 > cap 60%），本模块不执行归集
SHRINK_REVIEW_UTIL_PCT = 40       # 低于该利用率且有缩容空间时给人工建议，绝不自动缩容

# 单钱包 / 池合计上限（§19.4.3、§19.4.10(6)）
WALLET_CAP_USD_MINOR = 10_000 * 100   # 单钱包 cap 硬顶 = 10,000 USD
WALLET_CAP_FORECAST_DAYS = 5          # 或 5 天预计收款额，取小
POOL_CAP_USD_MINOR = 50_000 * 100     # 池合计上限默认 50,000 USD
MIN_WALLET_CAP_MINOR = 1_000 * 100    # 下调 cap 时不低于 1,000 USD

# 一期池（平台热池不建）
PHASE1_CHAIN = "polygon"
FUND_CLASSES = ("customer", "platform")


def pool_id_of(chain_id: str, role: str, fund_class: str) -> str:
    return f"{chain_id}:{role}:{fund_class}"


POOL_ID_CUSTOMER_HOT = pool_id_of(PHASE1_CHAIN, "hot", "customer")
POOL_ID_CUSTOMER_WARM = pool_id_of(PHASE1_CHAIN, "warm", "customer")
POOL_ID_PLATFORM_WARM = pool_id_of(PHASE1_CHAIN, "warm", "platform")
POOL_ID_PLATFORM_HOT = pool_id_of(PHASE1_CHAIN, "hot", "platform")   # 平台热池：不建
PHASE1_POOL_IDS = (POOL_ID_CUSTOMER_HOT, POOL_ID_CUSTOMER_WARM, POOL_ID_PLATFORM_WARM)


# --------------------------------------------------------------------------- 开关
@dataclass(frozen=True)
class FeatureFlag:
    """特性开关（§B.5 `feature_flag` 三字段必填：owner / expire_at / rollback_rule）。"""

    name: str
    default: bool
    owner: str
    expire_at: str
    rollback_rule: str

    @property
    def env_var(self) -> str:
        return "DJB_FF_" + self.name.upper()


FEATURE_FLAGS: dict[str, FeatureFlag] = {
    "wallet_pool_v2": FeatureFlag(
        name="wallet_pool_v2",
        default=False,                      # 默认关闭：关闭时系统只读池深，不做任何自动扩容
        owner="cloud-dev",
        expire_at="2026-12-31",
        rollback_rule="关闭开关回到手工扩容（treasury.wallet.provision）；不删批次表，"
                      "已生成批次保留可查，未签批次按 24h 过期作废",
    ),
    "wallet_pool_auto_max_active": FeatureFlag(
        name="wallet_pool_auto_max_active",
        default=False,                      # 默认关闭：关闭时 max_active 触顶只报人工复核，不自动 +4
        owner="cloud-dev",
        expire_at="2026-12-31",
        rollback_rule="关闭开关后 max_active 不再自动上调（只保留人工确认上调路径），"
                      "已上调的 max_active 不回滚，需人工下调",
    ),
}

_TRUTHY = {"1", "true", "on", "yes", "y", "t"}


def flag_expired(flag: FeatureFlag | str, *, today: date | None = None) -> bool:
    """开关是否已过 expire_at（到期即强制为关，口径同 chain/admin）。

    expire_at 非法时 fail-closed 视为已到期：配置错误不得变成永久开启。
    """
    if isinstance(flag, str):
        flag = FEATURE_FLAGS[flag]
    today = today or date.today()
    try:
        return today > date.fromisoformat(flag.expire_at)
    except (TypeError, ValueError):
        return True


def flag_enabled(flag: FeatureFlag | str, override: bool | None = None,
                 env: Mapping[str, str] | None = None, *,
                 today: date | None = None) -> bool:
    """开关判定：到期强制关 > 显式 override > 环境变量 > 默认（默认一律关闭）。"""
    if isinstance(flag, str):
        flag = FEATURE_FLAGS[flag]
    if flag_expired(flag, today=today):
        return False
    if override is not None:
        return bool(override)
    environ = os.environ if env is None else env
    raw = environ.get(flag.env_var)
    if raw is None or raw == "":
        return flag.default
    return raw.strip().lower() in _TRUTHY


# --------------------------------------------------------------------------- 异常
class WalletPoolError(RuntimeError):
    """本模块的基类异常（均不涉及资金动作）。"""


class PoolNotFound(WalletPoolError):
    pass


class TransferNotAllowed(WalletPoolError):
    """扩容批次里出现转账字段：拒绝（扩容只开容量）。"""


class SignatureIncomplete(WalletPoolError):
    """2/3 签不齐（决策人 + 对账复核人 + HSM 验签）。"""


class BatchExpired(WalletPoolError):
    pass


class BatchStateError(WalletPoolError):
    pass


# --------------------------------------------------------------------------- 预测
@dataclass(frozen=True)
class Forecast:
    source: str                 # rolling_14d | fallback_trailing_7d | no_data
    history_days: int
    horizon_days: int
    predicted_minor: int        # 未来 7 天预计收款额（USD 分）
    daily_minor: int            # 日均（USD 分，向下取整）
    anomaly: bool = False


def rolling_forecast(daily_minor: Sequence[int],
                     window_days: int = HISTORY_WINDOW_DAYS,
                     horizon_days: int = HORIZON_DAYS) -> Forecast:
    """14 天滚动收款 → 预测未来 7 天；异常或无数据时按近 7 天实测兜底。

    - 输入按时间升序，只取最后 `window_days` 天（14 天滚动窗口）。
    - 预测值 = 窗口日均 × 7。
    - 预测不可用（历史 <3 天 / 全 0）或异常（近 7 天与前 7 天相差 >3 倍，即突增或断崖）
      → 按近 7 天实测兜底 `fallback_trailing_7d`。
    """
    if horizon_days <= 0:
        raise ValueError("horizon_days must be > 0")
    tail = [int(v) for v in list(daily_minor)[-window_days:]]
    if any(v < 0 for v in tail):
        raise ValueError("daily_minor must be >= 0")
    trailing7 = sum(tail[-HORIZON_DAYS:])
    if not tail or sum(tail) == 0:
        return Forecast("no_data", len(tail), horizon_days, 0, 0, anomaly=False)
    if len(tail) < MIN_HISTORY_DAYS:
        return Forecast("fallback_trailing_7d", len(tail), horizon_days, trailing7,
                        trailing7 // horizon_days, anomaly=True)
    daily = sum(tail) / len(tail)
    predicted = int(round(daily * horizon_days))
    prior7 = sum(tail[:-HORIZON_DAYS])
    anomaly = prior7 > 0 and trailing7 > 0 and (
        trailing7 > ANOMALY_RATIO * prior7 or prior7 > ANOMALY_RATIO * trailing7)
    if anomaly:
        return Forecast("fallback_trailing_7d", len(tail), horizon_days, trailing7,
                        trailing7 // horizon_days, anomaly=True)
    return Forecast("rolling_14d", len(tail), horizon_days, predicted,
                    int(daily), anomaly=False)


# --------------------------------------------------------------------------- 池快照与决策
@dataclass(frozen=True)
class PoolSnapshot:
    pool_id: str
    role: str
    max_active: int
    min_spare: int
    activate_batch_size: int
    switch_threshold_pct: int
    pool_cap_minor: int
    active_count: int = 0            # status = active（含 standby / in_service）
    ready_count: int = 0             # active ∧ gas_ok（可立刻接新地址）
    provisioning_count: int = 0      # 预生成可用（地址未分发、余额 0）
    in_service_count: int = 0
    in_use_balance_minor: int = 0    # 池内在用钱包余额合计
    status: str = "active"

    @property
    def depth_available(self) -> int:
        """`depth_available` = `depth_ready` + 预生成可用只数（§19.4.10(1)）。"""
        return self.ready_count + self.provisioning_count

    @property
    def slots_used(self) -> int:
        return self.active_count + self.provisioning_count


@dataclass(frozen=True)
class ExpansionPlan:
    action: str                        # provision | no_action
    reason: str
    batch_size: int                    # 本批只数（0 = 不建批次）
    target_wallets: int                # 2× 预测目标只数
    cap_per_wallet_minor: int
    projected_utilization_pct: float
    max_active_before: int
    max_active_after: int
    auto_max_active_raised: bool
    new_address_allocation: str        # normal | spread_existing | provision_first
    stop_collection: bool              # 恒 False：不得以池空为由停收款
    needs_manual_review: bool
    p_level: str


def cap_per_wallet_minor(snap: PoolSnapshot, forecast: Forecast) -> int:
    """单钱包 cap = min(10,000 USD, 5 天预计收款额)，并按池合计上限收敛。"""
    daily = forecast.daily_minor
    five_day = int(math.ceil(daily * WALLET_CAP_FORECAST_DAYS)) if daily > 0 else WALLET_CAP_USD_MINOR
    cap = min(WALLET_CAP_USD_MINOR, five_day) if five_day > 0 else WALLET_CAP_USD_MINOR
    # 单钱包 cap × 在用只数 ≤ 池合计上限：只在被池上限压下来时保底 1,000 USD
    share = snap.pool_cap_minor // max(snap.active_count, 1)
    if share < cap:
        cap = max(MIN_WALLET_CAP_MINOR, share)
    return cap


def target_active_wallets(forecast: Forecast, cap_minor: int) -> int:
    """目标容量 ≥ 2× 7 天预测 → 需要的在用只数。"""
    capacity = forecast.predicted_minor * TARGET_MULTIPLIER
    if capacity <= 0 or cap_minor <= 0:
        return 0
    return int(math.ceil(capacity / cap_minor))


def _projected_utilization_pct(snap: PoolSnapshot, forecast: Forecast, cap_minor: int) -> float:
    capacity = max(snap.slots_used, 1) * cap_minor
    used = snap.in_use_balance_minor + forecast.predicted_minor
    return round(used * 100.0 / capacity, 1)


def _apply_max_active(base: dict, snap: PoolSnapshot, size: int, auto_max_active: bool) -> dict:
    """max_active 只自动上调（每次 +4，硬顶 20）；下调永远留给人工。"""
    needed = snap.slots_used + size
    after, raised = snap.max_active, False
    if needed > after and auto_max_active:
        while after < needed and after < MAX_ACTIVE_HARD_CAP:
            after = min(MAX_ACTIVE_HARD_CAP, after + MAX_ACTIVE_STEP)
            raised = True
    base = dict(base, max_active_after=after, auto_max_active_raised=raised)
    if needed > after:
        size = max(0, after - snap.slots_used)
    base["batch_size"] = size
    return base


def plan_expansion(snap: PoolSnapshot, forecast: Forecast, *,
                   flag_enabled: bool = True,
                   auto_max_active: bool = False) -> ExpansionPlan:
    """扩容决策（纯函数，不碰库、不碰钱）。

    判定顺序（决策表见 docs/DEV-0001-wallet-pool.md）：
    1. 开关关闭 → 不动作；
    2. 池 paused → 不动作；
    3. `depth_available = 0`（池空）→ P0，先摊量 + 扩一批，**不停收款**；
    4. 预测不可用 → 只维持 `min_spare` 底线；
    5. `depth_available < min_spare` → 补到 min_spare（P1）；
    6. 需要的只数 > 现有槽位（2× 预测）→ 扩一批；
    7. 预计利用率 >60% → 预生成一批；
    8. 其余 → 不动作；需要缩容时只给人工建议，绝不自动缩容。
    """
    cap = cap_per_wallet_minor(snap, forecast)
    target = target_active_wallets(forecast, cap)
    util = _projected_utilization_pct(snap, forecast, cap)
    bs = max(1, min(snap.activate_batch_size, MAX_BATCH_SIZE))

    base = dict(target_wallets=target, cap_per_wallet_minor=cap,
                projected_utilization_pct=util, max_active_before=snap.max_active,
                max_active_after=snap.max_active, auto_max_active_raised=False,
                new_address_allocation="normal", stop_collection=False,
                needs_manual_review=False, p_level="P3")

    def no_action(reason: str, **over) -> ExpansionPlan:
        return ExpansionPlan(action="no_action", reason=reason, batch_size=0, **{**base, **over})

    def provision(reason: str, size: int, **over) -> ExpansionPlan:
        allocation = over.pop("new_address_allocation", "normal")
        merged = {**base, **over}
        merged.update(_apply_max_active(merged, snap, max(1, size), auto_max_active))
        merged.pop("new_address_allocation", None)
        if merged.get("batch_size", 0) <= 0:
            # 槽位已满：不自动扩容，但继续摊量，绝不停收款
            merged.pop("batch_size", None)
            merged.pop("needs_manual_review", None)
            return ExpansionPlan(action="no_action", reason="max_active_reached",
                                 batch_size=0, needs_manual_review=True,
                                 new_address_allocation="spread_existing", **merged)
        return ExpansionPlan(action="provision", reason=reason, batch_size=merged.pop("batch_size"),
                             new_address_allocation=allocation, **merged)

    if not flag_enabled:
        return no_action("flag_disabled")
    if snap.status != "active":
        return no_action("pool_not_active")

    # 池空：业务优先——新地址先摊到现有钱包（最高 100% cap），同时自动扩容
    if snap.depth_available == 0:
        return provision("pool_empty_urgent", bs, p_level="P0",
                         new_address_allocation=("spread_existing" if snap.active_count else "provision_first"))

    if forecast.source == "no_data":
        if snap.depth_available < snap.min_spare:
            return provision("min_spare_floor_no_forecast", snap.min_spare - snap.depth_available,
                             p_level="P1", new_address_allocation="normal")
        return no_action("forecast_no_data")

    if snap.depth_available < snap.min_spare:
        return provision("min_spare_shortfall", snap.min_spare - snap.depth_available,
                         p_level="P1")

    if target > snap.slots_used:
        return provision("forecast_2x_target", target - snap.slots_used)

    if util > UTILIZATION_PREGEN_PCT:
        return provision("utilization_above_60pct", bs)

    if target < snap.active_count and util < SHRINK_REVIEW_UTIL_PCT:
        # 下调必须人工确认（避免误缩容）
        return no_action("shrink_needs_manual_review", needs_manual_review=True)

    return no_action("capacity_sufficient")


# --------------------------------------------------------------------------- 描述符
_FORBIDDEN_DESCRIPTOR_KEYS = {
    "amount", "amounts", "value", "transfer", "transfers", "tx", "txhash", "to",
    "to_address", "payee", "recipient", "payment", "raw_tx", "signed_tx", "calldata",
}
DESCRIPTOR_KEYS = {
    "wallet_id", "chain_id", "address", "address_source", "role", "fund_class",
    "signer_set_ref", "threshold", "signers_total", "cap_applied_minor",
}


def _canonical(payload: Mapping) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def descriptor_hash(descriptor: Mapping) -> str:
    return "sha256:" + hashlib.sha256(_canonical(descriptor)).hexdigest()


def merkle_root(hashes: Iterable[str]) -> str:
    """描述符 Merkle 根（逐层两两 hash，奇数个时复制末尾）。"""
    layer = [h.split(":", 1)[-1] for h in hashes]
    if not layer:
        raise ValueError("empty descriptor set")
    while len(layer) > 1:
        if len(layer) % 2:
            layer = layer + [layer[-1]]
        layer = [hashlib.sha256((layer[i] + layer[i + 1]).encode()).hexdigest()
                 for i in range(0, len(layer), 2)]
    return "sha256:" + layer[0]


def assert_no_transfer(descriptors: Sequence[Mapping]) -> None:
    """扩容批次不得携带任何转账指令；出现即拒绝（不是靠自觉）。"""
    if not descriptors:
        raise TransferNotAllowed("empty descriptor set")
    for d in descriptors:
        keys = {str(k).lower() for k in d}
        bad = keys & _FORBIDDEN_DESCRIPTOR_KEYS
        if bad:
            raise TransferNotAllowed(f"provision batch must not carry transfer fields: {sorted(bad)}")
        unknown = keys - DESCRIPTOR_KEYS
        if unknown:
            raise TransferNotAllowed(f"unknown descriptor fields: {sorted(unknown)}")


def _placeholder_address(pool_id: str, wallet_id: str, index: int) -> str:
    """开发/测试用占位地址（确定性）。

    生产必须由签名服务注入 HSM 派生的真实地址；`DJB_ENV=prod` 下不注入派生器直接报错，
    避免占位地址被当成真实收款地址使用。
    """
    digest = hashlib.sha256(f"{pool_id}|{wallet_id}|{index}".encode()).hexdigest()
    return "0x" + digest[:40]


AddressDeriver = Callable[[str, str, int], str]


def _resolve_deriver(address_deriver: AddressDeriver | None) -> tuple[AddressDeriver, str]:
    if address_deriver is not None:
        return address_deriver, "hsm_derived"
    if os.environ.get("DJB_ENV", "").lower() == "prod":
        raise WalletPoolError(
            "生产环境必须注入 HSM 派生器（address_deriver）；不接受开发占位地址")
    return _placeholder_address, "placeholder_dev"


# --------------------------------------------------------------------------- DB：池 & 快照
def ensure_pools(c) -> list[str]:
    """幂等写入一期 3 池（平台热池不建）。返回池 id 列表。"""
    rows = [
        (POOL_ID_CUSTOMER_HOT, PHASE1_CHAIN, "hot", "customer", MIN_SPARE, MAX_ACTIVE_HOT),
        (POOL_ID_CUSTOMER_WARM, PHASE1_CHAIN, "warm", "customer", MIN_SPARE, MAX_ACTIVE_WARM),
        (POOL_ID_PLATFORM_WARM, PHASE1_CHAIN, "warm", "platform", MIN_SPARE, MAX_ACTIVE_WARM),
    ]
    with c.cursor() as cur:
        for pool_id, chain_id, role, fund_class, min_spare, max_active in rows:
            cur.execute(
                """INSERT INTO wallet_pool (pool_id, chain_id, role, fund_class, min_spare_count,
                                            max_active_count, switch_threshold_pct, activate_batch_size,
                                            provision_lead_time_h, pool_cap_minor, switch_policy, policy_version)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'least_utilized','v4.0')
                   ON CONFLICT (pool_id) DO NOTHING""",
                (pool_id, chain_id, role, fund_class, min_spare, max_active,
                 SWITCH_THRESHOLD_PCT, ACTIVATE_BATCH_SIZE, PROVISION_LEAD_TIME_H, POOL_CAP_USD_MINOR),
            )
    return [r[0] for r in rows]


def load_snapshot(c, pool_id: str) -> PoolSnapshot:
    with c.cursor() as cur:
        cur.execute(
            """SELECT p.pool_id, p.role, p.max_active_count, p.min_spare_count, p.activate_batch_size,
                      p.switch_threshold_pct, p.pool_cap_minor, p.status,
                      COUNT(w.*) FILTER (WHERE w.status = 'active')                       AS active_count,
                      COUNT(w.*) FILTER (WHERE w.status = 'active' AND w.gas_ok)           AS ready_count,
                      COUNT(w.*) FILTER (WHERE w.status = 'provisioning')                  AS provisioning_count,
                      COUNT(w.*) FILTER (WHERE w.status = 'active'
                                          AND w.switch_state = 'in_service')               AS in_service_count,
                      COALESCE(SUM(w.balance_minor) FILTER (WHERE w.status = 'active'), 0) AS in_use_balance
                 FROM wallet_pool p
                 LEFT JOIN wallet w ON w.pool_id = p.pool_id
                WHERE p.pool_id = %s
                GROUP BY p.pool_id, p.role, p.max_active_count, p.min_spare_count,
                         p.activate_batch_size, p.switch_threshold_pct, p.pool_cap_minor, p.status""",
            (pool_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise PoolNotFound(pool_id)
    (pid, role, max_active, min_spare, batch_size, switch_pct, pool_cap, status,
     active_n, ready_n, prov_n, in_service_n, balance) = row
    return PoolSnapshot(pool_id=pid, role=role, max_active=max_active, min_spare=min_spare,
                        activate_batch_size=batch_size, switch_threshold_pct=switch_pct,
                        pool_cap_minor=pool_cap, active_count=active_n, ready_count=ready_n,
                        provisioning_count=prov_n, in_service_count=in_service_n,
                        in_use_balance_minor=int(balance), status=status)


def _event(c, pool_id: str, event: str, batch_id=None, payload: Mapping | None = None) -> None:
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO wallet_pool_event (pool_id, event, batch_id, payload)
               VALUES (%s,%s,%s,%s::jsonb)""",
            (pool_id, event, batch_id, json.dumps(payload or {}, ensure_ascii=False, sort_keys=True)),
        )


def open_batch(c, pool_id: str, now: datetime | None = None):
    """该池是否存在未过期的在签批次（幂等的第二道闸）。"""
    now = now or _utcnow()
    with c.cursor() as cur:
        cur.execute(
            """SELECT batch_id, status, expires_at, wallet_count
                 FROM wallet_provision_batch
                WHERE pool_id = %s AND status IN ('pending_sign', 'signed') AND expires_at > %s
                ORDER BY created_at DESC LIMIT 1""",
            (pool_id, now),
        )
        return cur.fetchone()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dedupe_key(pool_id: str, now: datetime, plan: ExpansionPlan) -> str:
    """同池同秒同参数的自动扩容只落一个批次（UNIQUE(pool_id, dedupe_key) 兜底）。"""
    bucket = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"auto:{pool_id}:{bucket}:{plan.batch_size}:{plan.cap_per_wallet_minor}:{plan.reason}"


def create_batch(c, snap: PoolSnapshot, plan: ExpansionPlan, *,
                 now: datetime | None = None,
                 idempotency_key: str | None = None,
                 address_deriver: AddressDeriver | None = None) -> dict:
    """建一个 WALLET_PROVISION 批次 + 预生成钱包（余额 0、地址不对外分发）。

    并发安全：调用方先对 `wallet_pool` 行加锁（`run_expansion` 已加），
    再加 `UNIQUE(pool_id, dedupe_key)` 兜底；同批次只会生成一次。
    """
    now = now or _utcnow()
    if plan.batch_size <= 0:
        raise BatchStateError("batch_size must be > 0")
    batch_id = uuid.uuid4()
    deriver, address_source = _resolve_deriver(address_deriver)
    dedupe = idempotency_key or _dedupe_key(snap.pool_id, now, plan)

    descriptors = []
    for i in range(plan.batch_size):
        wallet_id = f"wlt_{snap.pool_id.replace(':', '-')}_{str(batch_id)[:8]}_{i}"
        descriptors.append({
            "wallet_id": wallet_id,
            "chain_id": PHASE1_CHAIN,
            "address": deriver(snap.pool_id, wallet_id, i),
            "address_source": address_source,
            "role": snap.role,
            "fund_class": snap.pool_id.rsplit(":", 1)[-1],
            "signer_set_ref": f"signerset/{snap.role}/v1",   # 扩容不新增签名人
            "threshold": 2,
            "signers_total": 3,
            "cap_applied_minor": plan.cap_per_wallet_minor,
        })
    assert_no_transfer(descriptors)      # 任何转账字段 → 直接拒绝
    root = merkle_root([descriptor_hash(d) for d in descriptors])
    cap_params = {
        "cap_per_wallet_minor": plan.cap_per_wallet_minor,
        "pool_cap_minor": snap.pool_cap_minor,
        "max_active_count": plan.max_active_after,
        "in_use_count": max(snap.active_count, 1),
    }

    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO wallet_provision_batch
                 (batch_id, pool_id, wallet_count, descriptor_merkle_root, cap_params,
                  dedupe_key, expires_at, created_at, reason, contains_transfer)
               VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,FALSE)
               ON CONFLICT (pool_id, dedupe_key) DO NOTHING
               RETURNING batch_id, nonce, status, expires_at""",
            (str(batch_id), snap.pool_id, len(descriptors), root,
             json.dumps(cap_params, ensure_ascii=False, sort_keys=True), dedupe,
             now + timedelta(hours=BATCH_TTL_H), now, plan.reason),
        )
        inserted = cur.fetchone()
        if inserted is None:
            cur.execute(
                """SELECT batch_id, nonce, status, expires_at, wallet_count, descriptor_merkle_root
                     FROM wallet_provision_batch WHERE pool_id = %s AND dedupe_key = %s""",
                (snap.pool_id, dedupe),
            )
            existing = cur.fetchone()
            return {"batch_id": str(existing[0]), "nonce": existing[1], "status": existing[2],
                    "expires_at": existing[3], "wallet_count": existing[4],
                    "descriptor_merkle_root": existing[5], "created": False,
                    "descriptors": []}

        for d in descriptors:
            cur.execute(
                """INSERT INTO wallet (wallet_id, chain_id, address, pool_id, pool_role, fund_class,
                                       custody_kind, status, signer_set_ref, descriptor_hash, balance_minor)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,'provisioning',%s,%s,0)""",
                (d["wallet_id"], d["chain_id"], d["address"], snap.pool_id, d["role"],
                 d["fund_class"], "self_custody_hot" if snap.role == "hot" else "self_custody_warm",
                 d["signer_set_ref"], descriptor_hash(d)),
            )
            cur.execute(
                """INSERT INTO wallet_activation (batch_id, wallet_id, switch_state,
                                                 cap_applied_minor, status)
                   VALUES (%s,%s,NULL,%s,'pending')""",
                (str(batch_id), d["wallet_id"], d["cap_applied_minor"]),
            )
        _event(c, snap.pool_id, "batch_created", str(batch_id),
               {"reason": plan.reason, "wallet_count": len(descriptors),
                "merkle_root": root, "cap_params": cap_params,
                "expires_at": (now + timedelta(hours=BATCH_TTL_H)).isoformat()})

    return {"batch_id": str(batch_id), "nonce": inserted[1], "status": inserted[2],
            "expires_at": inserted[3], "wallet_count": len(descriptors),
            "descriptor_merkle_root": root, "created": True, "descriptors": descriptors}


# --------------------------------------------------------------------------- DB：编排
def run_expansion(c, pool_id: str, daily_minor: Sequence[int] = (), *,
                  now: datetime | None = None,
                  idempotency_key: str | None = None,
                  flag: bool | None = None,
                  auto_max_active: bool | None = None,
                  address_deriver: AddressDeriver | None = None) -> dict:
    """一次扩容判定（每日定时 / 手工 `treasury.wallet.provision` 共用同一套逻辑）。

    返回决策 + 批次；`ledger_entries` 永远不动（扩容不碰钱）。
    """
    now = now or _utcnow()
    flag_on = flag_enabled(FEATURE_FLAGS["wallet_pool_v2"], flag)
    auto_on = flag_enabled(FEATURE_FLAGS["wallet_pool_auto_max_active"], auto_max_active)

    # 行锁串行化同池并发（池键不可变，锁顺序固定：先 pool 后 batch）
    with c.cursor() as cur:
        cur.execute("SELECT pool_id FROM wallet_pool WHERE pool_id = %s FOR UPDATE", (pool_id,))
        if cur.fetchone() is None:
            raise PoolNotFound(pool_id)

    snap = load_snapshot(c, pool_id)
    forecast = rolling_forecast(daily_minor)
    plan = plan_expansion(snap, forecast, flag_enabled=flag_on, auto_max_active=auto_on)

    out = {
        "pool_id": pool_id,
        "action": plan.action,
        "reason": plan.reason,
        "flag_enabled": flag_on,
        "auto_max_active_enabled": auto_on,
        "forecast": {"source": forecast.source, "history_days": forecast.history_days,
                     "horizon_days": forecast.horizon_days,
                     "predicted_minor": forecast.predicted_minor,
                     "daily_minor": forecast.daily_minor, "anomaly": forecast.anomaly},
        "plan": {"batch_size": plan.batch_size, "target_wallets": plan.target_wallets,
                 "cap_per_wallet_minor": plan.cap_per_wallet_minor,
                 "projected_utilization_pct": plan.projected_utilization_pct,
                 "max_active_before": plan.max_active_before,
                 "max_active_after": plan.max_active_after,
                 "auto_max_active_raised": plan.auto_max_active_raised,
                 "new_address_allocation": plan.new_address_allocation,
                 "stop_collection": plan.stop_collection,
                 "needs_manual_review": plan.needs_manual_review,
                 "p_level": plan.p_level},
        "depth": {"ready": snap.ready_count, "provisioning": snap.provisioning_count,
                  "available": snap.depth_available, "active": snap.active_count,
                  "min_spare": snap.min_spare},
        "batch": None,
    }

    # 幂等第一道闸：已有未过期在签批次 → 不再新建（同一批次只生成一次）
    pending = open_batch(c, pool_id, now=now)
    if pending is not None:
        out.update(action="no_action", reason="batch_pending_sign",
                   batch={"batch_id": str(pending[0]), "status": pending[1],
                          "expires_at": pending[2], "wallet_count": pending[3], "created": False})
        _event(c, pool_id, "expansion_skipped", str(pending[0]), {"reason": "batch_pending_sign"})
        return out

    if plan.action != "provision":
        _event(c, pool_id, "expansion_skipped", None, {"reason": plan.reason})
        return out

    if plan.auto_max_active_raised and plan.max_active_after > snap.max_active:
        with c.cursor() as cur:
            cur.execute(
                """UPDATE wallet_pool SET max_active_count = %s, updated_at = now()
                    WHERE pool_id = %s AND max_active_count = %s""",
                (plan.max_active_after, pool_id, snap.max_active),
            )
        _event(c, pool_id, "max_active_raised", None,
               {"from": snap.max_active, "to": plan.max_active_after, "step": MAX_ACTIVE_STEP})

    batch = create_batch(c, snap, plan, now=now, idempotency_key=idempotency_key,
                         address_deriver=address_deriver)
    out["batch"] = batch
    if not batch["created"]:
        out.update(action="no_action", reason="duplicate_batch_suppressed")
    return out


# --------------------------------------------------------------------------- DB：批次状态机
def activate_batch(c, batch_id: str, *,
                   owner_signed_at: datetime | None = None,
                   reviewer_attested_at: datetime | None = None,
                   hsm_verified_at: datetime | None = None,
                   now: datetime | None = None,
                   actor: str = "signer_service") -> dict:
    """2/3 签 + HSM 验签后批量激活（一批一签，不是一只一签）。

    激活只把 `wallet.status` 从 `provisioning` 转 `active/standby` 并置 `cap_applied_minor`；
    **激活 ≠ 可用**：`gas_ok` 仍为 false，不计入 `depth_ready`。
    """
    now = now or _utcnow()
    missing = [n for n, v in (("owner_signed_at", owner_signed_at),
                              ("reviewer_attested_at", reviewer_attested_at),
                              ("hsm_verified_at", hsm_verified_at)) if v is None]
    if missing:
        raise SignatureIncomplete(f"2/3 signature incomplete: missing {missing}")

    with c.cursor() as cur:
        cur.execute(
            """SELECT pool_id, status, expires_at, wallet_count, descriptor_merkle_root
                 FROM wallet_provision_batch WHERE batch_id = %s FOR UPDATE""",
            (batch_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise BatchStateError(f"batch not found: {batch_id}")
        pool_id, status, expires_at, wallet_count, root = row

        if status in ("expired", "failed", "cancelled"):
            raise BatchExpired(f"batch {batch_id} is {status}; regenerate descriptors and sign again")
        if status == "activated":
            cur.execute("SELECT wallet_id FROM wallet_activation WHERE batch_id = %s ORDER BY wallet_id",
                        (batch_id,))
            return {"batch_id": batch_id, "activated": [r[0] for r in cur.fetchall()],
                    "already": True, "merkle_root": root}
        if expires_at <= now:
            cur.execute("UPDATE wallet_provision_batch SET status = 'expired' WHERE batch_id = %s", (batch_id,))
            raise BatchExpired(f"batch {batch_id} expired at {expires_at.isoformat()}")

        cur.execute("SELECT wallet_id FROM wallet_activation WHERE batch_id = %s", (batch_id,))
        wallet_ids = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT wallet_id, status FROM wallet WHERE wallet_id = ANY(%s)", (wallet_ids,))
        states = dict(cur.fetchall())
        bad = {w: s for w, s in states.items() if s != "provisioning"}
        if bad:
            raise BatchStateError(f"batch has wallets not in provisioning: {bad}")

        auth_hash = "sha256:" + hashlib.sha256(
            _canonical({"batch_id": batch_id, "merkle_root": root,
                        "owner": owner_signed_at.isoformat(),
                        "reviewer": reviewer_attested_at.isoformat(),
                        "hsm": hsm_verified_at.isoformat()})).hexdigest()

        cur.execute(
            """UPDATE wallet SET status = 'active', switch_state = 'standby', activated_at = %s
                WHERE wallet_id = ANY(%s) AND status = 'provisioning'""",
            (now, wallet_ids),
        )
        cur.execute(
            """UPDATE wallet_activation SET status = 'activated', switch_state = 'standby',
                                            activated_at = %s
                WHERE batch_id = %s AND status = 'pending'""",
            (now, batch_id),
        )
        cur.execute(
            """UPDATE wallet_provision_batch
                  SET status = 'activated', activated_at = %s, owner_signed_at = %s,
                      reviewer_attested_at = %s, hsm_verified_at = %s,
                      auth_object_type = 'WALLET_PROVISION', auth_hash = %s
                WHERE batch_id = %s""",
            (now, owner_signed_at, reviewer_attested_at, hsm_verified_at, auth_hash, batch_id),
        )
        _event(c, pool_id, "batch_activated", batch_id,
               {"wallet_count": wallet_count, "merkle_root": root, "actor": actor,
                "note": "扩容只开容量，gas 未到位前不计入 depth_ready"})
    return {"batch_id": batch_id, "activated": wallet_ids, "already": False,
            "merkle_root": root, "auth_hash": auth_hash}


def fail_batch(c, batch_id: str, reason: str, *, now: datetime | None = None) -> dict:
    """预生成失败：批次 failed，钱包 provisioning_failed，地址作废不复用。"""
    now = now or _utcnow()
    with c.cursor() as cur:
        cur.execute("SELECT pool_id, status FROM wallet_provision_batch WHERE batch_id = %s FOR UPDATE",
                    (batch_id,))
        row = cur.fetchone()
        if row is None:
            raise BatchStateError(f"batch not found: {batch_id}")
        pool_id, status = row
        if status == "activated":
            raise BatchStateError("cannot fail an activated batch; use retirement path")
        if status in ("expired", "failed"):
            return {"batch_id": batch_id, "status": status, "wallets": [], "already": True}
        cur.execute("SELECT wallet_id FROM wallet_activation WHERE batch_id = %s AND status = 'pending'",
                    (batch_id,))
        wallet_ids = [r[0] for r in cur.fetchall()]
        cur.execute("UPDATE wallet SET status = 'provisioning_failed' WHERE wallet_id = ANY(%s)",
                    (wallet_ids,))
        cur.execute("UPDATE wallet_activation SET status = 'void' WHERE batch_id = %s AND status = 'pending'",
                    (batch_id,))
        cur.execute("UPDATE wallet_provision_batch SET status = 'failed' WHERE batch_id = %s", (batch_id,))
        _event(c, pool_id, "batch_failed", batch_id, {"reason": reason, "wallets": wallet_ids})
    return {"batch_id": batch_id, "status": "failed", "wallets": wallet_ids, "already": False}


def expire_batches(c, now: datetime | None = None) -> list[str]:
    """24h 过期作废：批次 expired，钱包作废，激活明细 void（需重新生成描述符再签）。"""
    now = now or _utcnow()
    with c.cursor() as cur:
        cur.execute(
            """SELECT batch_id, pool_id FROM wallet_provision_batch
                WHERE status IN ('pending_sign', 'signed') AND expires_at <= %s FOR UPDATE""",
            (now,),
        )
        rows = cur.fetchall()
        expired = []
        for batch_id, pool_id in rows:
            cur.execute("SELECT wallet_id FROM wallet_activation WHERE batch_id = %s AND status = 'pending'",
                        (batch_id,))
            wallet_ids = [r[0] for r in cur.fetchall()]
            cur.execute("UPDATE wallet SET status = 'provisioning_failed' WHERE wallet_id = ANY(%s)",
                        (wallet_ids,))
            cur.execute("UPDATE wallet_activation SET status = 'void' WHERE batch_id = %s AND status = 'pending'",
                        (batch_id,))
            cur.execute("UPDATE wallet_provision_batch SET status = 'expired' WHERE batch_id = %s",
                        (batch_id,))
            _event(c, pool_id, "batch_expired", batch_id, {"wallets": wallet_ids})
            expired.append(str(batch_id))
    return expired


# --------------------------------------------------------------------------- 不变量 / 证据
def check_invariants(c) -> dict:
    """池与钱包的不变量（供每日巡检与测试断言）。"""
    with c.cursor() as cur:
        cur.execute("SELECT pool_id, chain_id, role, fund_class, max_active_count FROM wallet_pool")
        pools = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM wallet WHERE status = 'active' AND balance_minor > 0 "
                    "AND switch_state = 'standby'")
        standby_with_balance = cur.fetchone()[0]
        cur.execute("""SELECT COUNT(*) FROM wallet_provision_batch
                        WHERE status IN ('pending_sign','signed') AND expires_at <= now()""")
        overdue_batches = cur.fetchone()[0]
        cur.execute("""SELECT COUNT(*) FROM wallet_activation a
                         JOIN wallet w ON w.wallet_id = a.wallet_id
                        WHERE a.status = 'activated' AND w.status = 'provisioning_failed'""")
        revived = cur.fetchone()[0]
    problems = []
    if len(pools) != len(PHASE1_POOL_IDS):
        problems.append(f"phase1 pool count {len(pools)} != {len(PHASE1_POOL_IDS)}")
    if any(p[0] == POOL_ID_PLATFORM_HOT for p in pools):
        problems.append("platform hot pool must not exist")
    if any(p[4] > MAX_ACTIVE_HARD_CAP for p in pools):
        problems.append("max_active over hard cap 20")
    if standby_with_balance:
        problems.append("standby wallet carries balance")
    if overdue_batches:
        problems.append("overdue provision batch still open")
    if revived:
        problems.append("failed wallet appears activated")
    return {"pools": len(pools), "problems": problems}


def ledger_fingerprint(c) -> dict:
    """账本指纹：扩容前后必须完全一致（扩容不碰钱）。"""
    report = recompute(c)
    with c.cursor() as cur:
        cur.execute("SELECT COUNT(*), COALESCE(SUM(amount_micro), 0) FROM ledger_entries")
        entries, total = cur.fetchone()
        cur.execute("SELECT COUNT(*), COALESCE(SUM(balance_micro), 0) FROM accounts")
        accounts, balance = cur.fetchone()
    return {"entries": entries, "sum_micro": int(total), "accounts": accounts,
            "accounts_sum_micro": int(balance), "recompute_diff": report["diff"]}
