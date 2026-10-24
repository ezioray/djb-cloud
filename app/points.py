# SPDX-License-Identifier: AGPL-3.0-or-later
"""COP 积分台账与转让开关（K4 / v4 §4.5 §6.6 §9.1 §20.1 §20.4.4）。

COP = 拉新奖励积分，是用户侧**唯一**持有物；本模块是它唯一的记账处：

- **独立台账**：只写 ``points_*`` 表，不写 ``ledger_entries`` / ``accounts``，不产生 USD 分录，
  不 import ``ledger.post_entry``；COP 只在 ``unit_type='COP'`` 维度内平衡（R9 永不互转）。
- **不设现金账户**：没有可兑出为现金的能力（``capabilities()`` 里 withdrawable/custodial 恒 False）。
- **默认不可转让**：``points.transfer_enabled`` 默认 false；开启后也只在平台内双边记账，
  不触链、不产生 USD 分录、不进 PoR。
- **六值动作**：``earn / redeem / adjust / freeze / unfreeze / void``（§20.4.4）+ ``transfer``。
  读路径遇到未知 action 直接报错拒绝，不静默跳过。

科目口径：``coa_code = '2103'``（§20.1 COP 科目）、``unit_type = 'COP'``；
对外命名只出现「持有量 / 可用 / 锁定」，不出现「现金账户」类措辞。
"""
from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

# --------------------------------------------------------------------------- 口径常量
COP_UNIT_TYPE = "COP"
COP_COA_CODE = "2103"                 # §20.1：2103 COP 科目（独立维度）
POLICY_VERSION = "v4.0"
ACTIONS = ("earn", "redeem", "adjust", "freeze", "unfreeze", "void", "transfer")
SIX_VALUE_ACTIONS = ACTIONS[:6]        # §20.4.4 六值；transfer 是转让动作（§9.1）
BUCKETS = ("available", "locked", "system")
SYSTEM_ACCOUNT = "system:cop"          # 对偶腿账户（发放 / 抵扣 / 调整的对手方）
ELIGIBLE_STATES = ("normal",)          # 仅 normal 可转出 / 接收（frozen / closing / closed 拒绝）
ACCRUAL_STATES = ("normal", "frozen")   # 冻结账户仍可累积，但不可使用


# --------------------------------------------------------------------------- 开关
@dataclass(frozen=True)
class FeatureFlag:
    """特性开关（B.5 feature_flag 三字段必填：owner / expire_at / rollback_rule）。"""

    name: str
    default: bool
    owner: str
    expire_at: str
    rollback_rule: str


# K4：默认不可转让；开启后只在平台用户之间转让，不可兑出为现金。
FEATURE_FLAG = FeatureFlag(
    name="points.transfer_enabled",
    default=False,
    owner="cloud-dev",
    expire_at="2026-12-31",
    rollback_rule="关闭 points.transfer_enabled 即禁止新转让；已转让积分保留、不回溯扣回（除非命中风控）",
)


@dataclass(frozen=True)
class Policy:
    transfer_enabled: bool = FEATURE_FLAG.default
    per_transfer_max_units: int = 1_000            # §9.1 单笔 ≤1,000 COP
    daily_out_max_units: int = 10_000             # §9.1 单日转出 ≤10,000 COP
    daily_in_max_units: int = 10_000              # §9.1 单日接收 ≤10,000 COP
    lock_days: int = 7                            # §9.1 收到后 7 天内不可再转出 / 抵扣
    redeem_cop_per_usd: int = 100                 # 1 USD = 100 COP（抵扣换算）
    redeem_max_share_bps: int = 2_000             # 单笔账单最多 20% 由 COP 抵扣
    policy_version: str = POLICY_VERSION

    def validated(self) -> "Policy":
        if self.per_transfer_max_units <= 0 or self.daily_out_max_units <= 0 \
                or self.daily_in_max_units <= 0:
            raise ValueError("转让上限必须 > 0")
        if not 1 <= self.lock_days <= 90:
            raise ValueError("lock_days 必须在 1..90")
        if self.redeem_cop_per_usd <= 0:
            raise ValueError("redeem_cop_per_usd 必须 > 0")
        if not 0 <= self.redeem_max_share_bps <= 10_000:
            raise ValueError("redeem_max_share_bps 必须在 0..10000")
        return self


DEFAULT_POLICY = Policy().validated()


# --------------------------------------------------------------------------- 异常
class PointsError(Exception):
    """COP 台账错误。``status_code`` / ``code`` 直接对应 §6.3b 已登记错误码。"""

    status_code = 400
    code = "40001"

    def __init__(self, message: str, *, reason: str | None = None, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason
        self.details = details

    def as_dict(self) -> dict:
        return {"code": self.code, "status": self.status_code, "message": self.message,
                "reason": self.reason, **self.details}


class TransferDisabled(PointsError):
    """开关关闭：转让一律拒绝（403 / 40303 特性未开启）。"""

    status_code = 403
    code = "40303"


class TransferRejected(PointsError):
    """自转 / 超限 / 账户状态 / 同一设备或支付簇等客户端可纠正的拒绝。"""

    status_code = 400
    code = "40001"


class InsufficientHolding(PointsError):
    """可用持有量不足。"""

    status_code = 400
    code = "40001"


class UnknownAction(PointsError):
    """读路径遇到未登记的 action：报错拒绝，不静默跳过（§20.4.4）。"""

    status_code = 500
    code = "45001"


# --------------------------------------------------------------------------- 工具
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime:
    if value is None:
        return _utcnow()
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _day_start(moment: datetime) -> datetime:
    return moment.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _check_action(action: str) -> str:
    if action not in ACTIONS:
        raise UnknownAction(f"未登记的 COP 动作：{action}", reason="unknown_action", action=action)
    return action


# --------------------------------------------------------------------------- 账户
def open_account(c, account_id: str, *, verified: bool = True,
                 device_cluster: str | None = None, payment_cluster: str | None = None,
                 state: str = "normal") -> dict:
    """登记 / 更新账户档案（幂等）。风控簇字段用于拒绝「同设备 / 同支付方式」互转。"""
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO points_account (account_id, state, verified, device_cluster, payment_cluster)
               VALUES (%s,%s,%s,%s,%s)
               ON CONFLICT (account_id) DO UPDATE
                 SET state = EXCLUDED.state,
                     verified = EXCLUDED.verified,
                     device_cluster = COALESCE(EXCLUDED.device_cluster, points_account.device_cluster),
                     payment_cluster = COALESCE(EXCLUDED.payment_cluster, points_account.payment_cluster),
                     updated_at = now()
               RETURNING account_id, state, verified, device_cluster, payment_cluster""",
            (account_id, state, verified, device_cluster, payment_cluster))
        row = cur.fetchone()
    return {"account_id": row[0], "state": row[1], "verified": row[2],
            "device_cluster": row[3], "payment_cluster": row[4]}


def set_account_state(c, account_id: str, state: str, *, actor: str) -> dict:
    """冻结 / 注销账户（运营动作）：状态变更即时生效，不写 COP 分录。"""
    if state not in ("normal", "frozen", "closing", "closed"):
        raise PointsError(f"非法账户状态：{state}", reason="invalid_state")
    with c.cursor() as cur:
        cur.execute(
            """UPDATE points_account SET state = %s, updated_at = now()
                WHERE account_id = %s
                RETURNING account_id, state""",
            (state, account_id))
        row = cur.fetchone()
    if row is None:
        raise PointsError(f"COP 账户不存在：{account_id}", reason="account_missing")
    return {"account_id": row[0], "state": row[1], "actor": actor}


def _account_row(c, account_id: str) -> dict:
    with c.cursor() as cur:
        cur.execute("""SELECT account_id, state, verified, device_cluster, payment_cluster
                         FROM points_account WHERE account_id = %s""", (account_id,))
        row = cur.fetchone()
    if row is None:
        raise PointsError(f"COP 账户不存在：{account_id}", reason="account_missing",
                          account_id=account_id)
    return {"account_id": row[0], "state": row[1], "verified": row[2],
            "device_cluster": row[3], "payment_cluster": row[4]}


# --------------------------------------------------------------------------- 策略
def load_policy(c) -> Policy:
    """读生效策略（P0 配置项 points.transfer_enabled 的落地值）。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT transfer_enabled, per_transfer_max_units, daily_out_max_units,
                      daily_in_max_units, lock_days, redeem_cop_per_usd,
                      redeem_max_share_bps, policy_version
                 FROM points_policy WHERE policy_key = 'default'""")
        row = cur.fetchone()
    if row is None:
        return DEFAULT_POLICY
    return Policy(*row).validated()


def update_policy(c, *, actor: str, reason: str, **changes: Any) -> Policy:
    """更新策略（配置中心发布后的落地动作）。只允许改白名单字段，且必须留 actor + reason。"""
    allowed = {"transfer_enabled", "per_transfer_max_units", "daily_out_max_units",
               "daily_in_max_units", "lock_days", "redeem_cop_per_usd",
               "redeem_max_share_bps", "policy_version"}
    unknown = set(changes) - allowed
    if unknown:
        raise PointsError(f"不可改写的策略字段：{sorted(unknown)}", reason="unknown_field")
    if not actor or not reason:
        raise PointsError("策略变更必须记录 actor 与 reason", reason="audit_required")
    current = load_policy(c)
    target = replace(current, **changes).validated()
    with c.cursor() as cur:
        cur.execute(
            """UPDATE points_policy
                  SET transfer_enabled = %s, per_transfer_max_units = %s,
                      daily_out_max_units = %s, daily_in_max_units = %s, lock_days = %s,
                      redeem_cop_per_usd = %s, redeem_max_share_bps = %s,
                      policy_version = %s, updated_at = now()
                WHERE policy_key = 'default'""",
            (target.transfer_enabled, target.per_transfer_max_units, target.daily_out_max_units,
             target.daily_in_max_units, target.lock_days, target.redeem_cop_per_usd,
             target.redeem_max_share_bps, target.policy_version))
    return target


def capabilities(policy: Policy | None = None) -> dict:
    """能力位（§4.6）：COP 可消费、不可兑出为现金、非托管；转让跟随开关。"""
    policy = policy or DEFAULT_POLICY
    return {"spendable": True, "transferable": bool(policy.transfer_enabled),
            "withdrawable": False, "custodial": False,
            "settlement_asset": COP_UNIT_TYPE, "unit_type": COP_UNIT_TYPE,
            "coa_code": COP_COA_CODE}


def por_contribution() -> dict:
    """储备证明贡献（§20.7）：COP 是非货币积分，**不进分子也不进分母**。"""
    return {"numerator_minor": 0, "denominator_minor": 0, "excluded": True,
            "unit_type": COP_UNIT_TYPE,
            "reason": "COP 是非货币积分，不计入 PoR 分子或分母"}


# --------------------------------------------------------------------------- 持有量
def holding(c, account_id: str) -> dict:
    """可用 / 锁定持有量（COP 单位）。锁定 = 收到转让后 7 天锁定 + 风控冻结。"""
    with c.cursor() as cur:
        cur.execute("""SELECT usable_units, locked_units FROM points_holding
                        WHERE account_id = %s""", (account_id,))
        row = cur.fetchone()
    usable, locked = (row if row else (0, 0))
    return {"account_id": account_id, "usable_units": int(usable),
            "locked_units": int(locked), "total_units": int(usable) + int(locked),
            "unit_type": COP_UNIT_TYPE}


# --------------------------------------------------------------------------- 记账原语
def _open_journal(c, *, action: str, account_id: str, units: int, actor: str,
                  reason_code: str | None = None, request_id: str | None = None,
                  ref_id: str | None = None, counterparty_id: str | None = None,
                  approved_by: str | None = None, policy: Policy | None = None) -> str:
    _check_action(action)
    if units <= 0:
        raise PointsError("units 必须 > 0", reason="invalid_units")
    policy = policy or load_policy(c)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO points_journal
                 (action, account_id, counterparty_id, units, reason_code, request_id,
                  ref_id, policy_version, actor, approved_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               RETURNING journal_id""",
            (action, account_id, counterparty_id, units, reason_code, request_id,
             ref_id, policy.policy_version, actor, approved_by))
        return str(cur.fetchone()[0])


def _add_leg(c, *, journal_id: str, account_id: str, bucket: str, delta: int, action: str,
             actor: str, reason_code: str | None = None, ref_id: str | None = None,
             unlock_at: datetime | None = None, reverse_of: str | None = None) -> str:
    if bucket not in BUCKETS:
        raise PointsError(f"非法桶：{bucket}", reason="invalid_bucket")
    if delta == 0:
        raise PointsError("delta 不能为 0", reason="invalid_units")
    _check_action(action)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO points_ledger
                 (journal_id, account_id, bucket, delta, action, unit_type, coa_code,
                  reason_code, ref_id, unlock_at, reverse_of, actor)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               RETURNING entry_id""",
            (journal_id, account_id, bucket, delta, action, COP_UNIT_TYPE, COP_COA_CODE,
             reason_code, ref_id, unlock_at, reverse_of, actor))
        return str(cur.fetchone()[0])


def _journal_result(c, journal_id: str) -> dict:
    """读回一个 journal（含分录与持有量变化），未知 action 直接报错拒绝。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT journal_id, action, account_id, counterparty_id, units, reason_code,
                      request_id, ref_id, policy_version, actor, approved_by, created_at
                 FROM points_journal WHERE journal_id = %s""", (journal_id,))
        j = cur.fetchone()
        if j is None:
            raise PointsError(f"journal 不存在：{journal_id}", reason="journal_missing")
        _check_action(j[1])
        cur.execute(
            """SELECT entry_id, account_id, bucket, delta, action, reason_code, ref_id,
                      unlock_at, reverse_of
                 FROM points_ledger WHERE journal_id = %s ORDER BY seq""", (journal_id,))
        legs = cur.fetchall()
        for leg in legs:
            _check_action(leg[4])
    if sum(int(leg[3]) for leg in legs) != 0:
        raise PointsError(f"journal 不平衡：{journal_id}", reason="journal_unbalanced")
    return {
        "journal_id": str(j[0]), "action": j[1], "account_id": j[2],
        "counterparty_id": j[3], "units": int(j[4]), "reason_code": j[5],
        "request_id": j[6], "ref_id": j[7], "policy_version": j[8], "actor": j[9],
        "approved_by": j[10], "created_at": j[11],
        "legs": [{"entry_id": str(l[0]), "account_id": l[1], "bucket": l[2],
                  "delta": int(l[3]), "action": l[4], "reason_code": l[5],
                  "ref_id": l[6], "unlock_at": l[7],
                  "reverse_of": str(l[8]) if l[8] else None} for l in legs],
    }


def read_journal(c, journal_id: str) -> dict:
    """公开读路径（未知 action / 不平衡一律报错，不静默忽略）。"""
    return _journal_result(c, journal_id)


# --------------------------------------------------------------------------- 六值动作
def earn(c, account_id: str, units: int, *, reason_code: str = "invite_reward",
         ref_id: str | None = None, request_id: str | None = None,
         actor: str = "system:points") -> dict:
    """`earn`：邀请 / 贡献发放 COP（2103 贷，对偶系统腿；不产生 USD 分录）。"""
    account = _account_row(c, account_id)
    if account["state"] not in ACCRUAL_STATES:
        raise PointsError(f"账户状态 {account['state']} 不可获得 COP", reason="account_state")
    jid = _open_journal(c, action="earn", account_id=account_id, units=int(units),
                        actor=actor, reason_code=reason_code, request_id=request_id,
                        ref_id=ref_id)
    _add_leg(c, journal_id=jid, account_id=account_id, bucket="available", delta=int(units),
             action="earn", actor=actor, reason_code=reason_code, ref_id=ref_id)
    _add_leg(c, journal_id=jid, account_id=SYSTEM_ACCOUNT, bucket="system", delta=-int(units),
             action="earn", actor=actor, reason_code=reason_code, ref_id=ref_id)
    return _journal_result(c, jid)


def redeem_service_fee(c, account_id: str, *, usd_minor: int,
                       reason_code: str = "service_fee", ref_id: str | None = None,
                       request_id: str | None = None,
                       actor: str = "system:points", now: datetime | None = None) -> dict:
    """`redeem`：用 COP 抵扣服务费（按策略比例换算，单笔抵扣比例受 redeem_max_share_bps 限制）。"""
    now = _as_utc(now)
    if usd_minor <= 0:
        raise PointsError("usd_minor 必须 > 0", reason="invalid_units")
    policy = load_policy(c)
    account = _account_row(c, account_id)
    if account["state"] != "normal":
        raise PointsError(f"账户状态 {account['state']} 不可抵扣", reason="account_state")

    # 1 USD = redeem_cop_per_usd COP → 所需 COP；再按「单笔抵扣上限比例」截断
    cop_needed = int(math.ceil(usd_minor * policy.redeem_cop_per_usd / 100))
    cop_cap = int(usd_minor * policy.redeem_max_share_bps * policy.redeem_cop_per_usd // 10_000 // 100)
    cop_used = min(cop_needed, cop_cap)
    if cop_used <= 0:
        raise PointsError("按当前抵扣比例无需使用 COP", reason="nothing_to_redeem")

    release_due(c, now=now, account_id=account_id)
    available = holding(c, account_id)["usable_units"]
    if available < cop_used:
        raise InsufficientHolding(
            f"COP 可用量不足：需要 {cop_used}，可用 {available}",
            reason="insufficient_points", required_units=cop_used, available_units=available)

    jid = _open_journal(c, action="redeem", account_id=account_id, units=cop_used, actor=actor,
                        reason_code=reason_code, request_id=request_id, ref_id=ref_id,
                        policy=policy)
    _add_leg(c, journal_id=jid, account_id=account_id, bucket="available", delta=-cop_used,
             action="redeem", actor=actor, reason_code=reason_code, ref_id=ref_id)
    _add_leg(c, journal_id=jid, account_id=SYSTEM_ACCOUNT, bucket="system", delta=cop_used,
             action="redeem", actor=actor, reason_code=reason_code, ref_id=ref_id)
    out = _journal_result(c, jid)
    out.update({"usd_minor": usd_minor, "cop_used": cop_used,
                "redeem_cop_per_usd": policy.redeem_cop_per_usd,
                "max_share_bps": policy.redeem_max_share_bps})
    return out


def adjust(c, account_id: str, units: int, *, reason_code: str, approved_by: str,
           actor: str, ref_id: str | None = None, request_id: str | None = None) -> dict:
    """`adjust`：人工 / 系统调整。必须带 reason_code 且双人复核（approved_by ≠ actor）。"""
    if not reason_code:
        raise PointsError("adjust 必须带 reason_code", reason="reason_required")
    if not approved_by or approved_by == actor:
        raise PointsError("adjust 需要另一名复核人（approved_by ≠ actor）", reason="sod_violation")
    if units == 0:
        raise PointsError("units 不能为 0", reason="invalid_units")
    account = _account_row(c, account_id)
    if account["state"] not in ACCRUAL_STATES:
        raise PointsError(f"账户状态 {account['state']} 不可调整", reason="account_state")
    if units < 0:
        release_due(c, account_id=account_id)
        available = holding(c, account_id)["usable_units"]
        if available < -units:
            raise InsufficientHolding(
                f"COP 可用量不足：需要 {-units}，可用 {available}",
                reason="insufficient_points", required_units=-units, available_units=available)

    jid = _open_journal(c, action="adjust", account_id=account_id, units=abs(int(units)),
                        actor=actor, reason_code=reason_code, request_id=request_id,
                        ref_id=ref_id, approved_by=approved_by)
    _add_leg(c, journal_id=jid, account_id=account_id, bucket="available", delta=int(units),
             action="adjust", actor=actor, reason_code=reason_code, ref_id=ref_id)
    _add_leg(c, journal_id=jid, account_id=SYSTEM_ACCOUNT, bucket="system", delta=-int(units),
             action="adjust", actor=actor, reason_code=reason_code, ref_id=ref_id)
    return _journal_result(c, jid)


def freeze(c, account_id: str, units: int, *, reason_code: str = "risk_hold",
           actor: str = "ops:points", ref_id: str | None = None,
           request_id: str | None = None) -> dict:
    """`freeze`：可用 → 锁定（风控冻结，无自动到期，需人工解冻）。"""
    release_due(c, account_id=account_id)
    available = holding(c, account_id)["usable_units"]
    if available < units:
        raise InsufficientHolding(
            f"COP 可用量不足：需要 {units}，可用 {available}",
            reason="insufficient_points", required_units=units, available_units=available)
    jid = _open_journal(c, action="freeze", account_id=account_id, units=int(units), actor=actor,
                        reason_code=reason_code, request_id=request_id, ref_id=ref_id)
    _add_leg(c, journal_id=jid, account_id=account_id, bucket="available", delta=-int(units),
             action="freeze", actor=actor, reason_code=reason_code, ref_id=ref_id)
    _add_leg(c, journal_id=jid, account_id=account_id, bucket="locked", delta=int(units),
             action="freeze", actor=actor, reason_code=reason_code, ref_id=ref_id,
             unlock_at=None)
    return _journal_result(c, jid)


def unfreeze(c, account_id: str, units: int, *, reason_code: str = "manual_release",
             actor: str = "ops:points", now: datetime | None = None) -> dict:
    """`unfreeze`：锁定 → 可用（人工解冻，只能动「无到期时间」的风控冻结 lot）。"""
    now = _as_utc(now)
    lots = _manual_lots(c, account_id)
    outstanding = sum(lot["outstanding_units"] for lot in lots)
    if outstanding < units:
        raise InsufficientHolding(
            f"可解冻的锁定量不足：需要 {units}，可解冻 {outstanding}",
            reason="insufficient_locked", required_units=units, available_units=outstanding)
    jid = _open_journal(c, action="unfreeze", account_id=account_id, units=int(units),
                        actor=actor, reason_code=reason_code)
    _release_from_lots(c, jid, account_id, int(units), lots, action="unfreeze",
                       reason_code=reason_code, actor=actor)
    return _journal_result(c, jid)


def _manual_lots(c, account_id: str) -> list[dict]:
    """无到期时间的锁定 lot（风控冻结），供人工解冻使用。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT lot_id, outstanding_units FROM points_locked_lot
                WHERE account_id = %s AND unlock_at IS NULL AND outstanding_units > 0
                ORDER BY lot_id""", (account_id,))
        return [{"lot_id": str(r[0]), "outstanding_units": int(r[1])} for r in cur.fetchall()]


def _release_from_lots(c, journal_id: str, account_id: str, units: int, lots: Sequence[Mapping],
                       *, action: str, reason_code: str, actor: str) -> None:
    remaining = units
    for lot in lots:
        if remaining <= 0:
            break
        take = min(remaining, int(lot["outstanding_units"]))
        if take <= 0:
            continue
        _add_leg(c, journal_id=journal_id, account_id=account_id, bucket="locked",
                 delta=-take, action=action, actor=actor, reason_code=reason_code,
                 ref_id=str(lot["lot_id"]))
        remaining -= take
    if remaining > 0:
        raise InsufficientHolding("锁定量不足，无法释放", reason="insufficient_locked")
    _add_leg(c, journal_id=journal_id, account_id=account_id, bucket="available",
             delta=units, action=action, actor=actor, reason_code=reason_code)


def release_due(c, *, now: datetime | None = None, account_id: str | None = None) -> list[dict]:
    """把已到期的「收到转让 7 天锁定」释放为可用；可重复执行（按未释放量计算，不重复释放）。"""
    now = _as_utc(now)
    params: list[Any] = [now]
    where = "unlock_at IS NOT NULL AND unlock_at <= %s AND outstanding_units > 0"
    if account_id:
        where += " AND account_id = %s"
        params.append(account_id)
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT lot_id, account_id, outstanding_units FROM points_locked_lot
                 WHERE {where} ORDER BY account_id, lot_id""", tuple(params))
        lots = [(str(r[0]), r[1], int(r[2])) for r in cur.fetchall()]

    released: list[dict] = []
    for lot_id, acct, units in lots:
        jid = _open_journal(c, action="unfreeze", account_id=acct, units=units,
                            actor="system:points", reason_code="lock_expired")
        _add_leg(c, journal_id=jid, account_id=acct, bucket="locked", delta=-units,
                 action="unfreeze", actor="system:points", reason_code="unfreeze", ref_id=lot_id)
        _add_leg(c, journal_id=jid, account_id=acct, bucket="available", delta=units,
                 action="unfreeze", actor="system:points", reason_code="lock_expired")
        released.append({"journal_id": jid, "account_id": acct, "units": units,
                         "reason_code": "lock_expired"})
    return released


def void(c, journal_id: str, *, reason_code: str, actor: str) -> dict:
    """`void`：作废原 journal（逐条取反 + reverse_of 指向原分录，原分录永不改）。"""
    original = _journal_result(c, journal_id)
    if original["action"] == "void":
        raise PointsError("不能作废一条 void 分录", reason="invalid_void_target")
    with c.cursor() as cur:
        cur.execute("""SELECT 1 FROM points_journal WHERE action = 'void' AND ref_id = %s LIMIT 1""",
                    (journal_id,))
        if cur.fetchone() is not None:
            raise PointsError(f"journal 已作废：{journal_id}", reason="already_voided")

    # 被锁定的收款腿若已释放/已用掉，就不能作废（否则会把负数打进 available）
    reversed_locked: dict[str, int] = {}
    for leg in original["legs"]:
        if leg["bucket"] == "locked" and leg["delta"] > 0:
            with c.cursor() as cur:
                cur.execute(
                    """SELECT COALESCE(outstanding_units,0) FROM points_locked_lot WHERE lot_id = %s""",
                    (leg["entry_id"],))
                row = cur.fetchone()
            if row is None or int(row[0]) < int(leg["delta"]):
                raise PointsError("目标分录的锁定已被释放或使用，无法作废",
                                  reason="locked_consumed", entry_id=leg["entry_id"])
            reversed_locked[leg["entry_id"]] = int(leg["delta"])

    jid = _open_journal(c, action="void", account_id=original["account_id"],
                        units=original["units"], actor=actor, reason_code=reason_code,
                        ref_id=journal_id)
    for leg in original["legs"]:
        _add_leg(c, journal_id=jid, account_id=leg["account_id"], bucket=leg["bucket"],
                 delta=-leg["delta"], action="void", actor=actor, reason_code=reason_code,
                 ref_id=leg["entry_id"], reverse_of=leg["entry_id"])
    return _journal_result(c, jid)


# --------------------------------------------------------------------------- 转让（§9.1）
def _daily_transfer_sum(c, account_id: str, moment: datetime, *, direction: str) -> int:
    column = "from_account_id" if direction == "out" else "to_account_id"
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT COALESCE(SUM(amount_units), 0) FROM points_transfer
                 WHERE {column} = %s AND created_at >= %s""",
            (account_id, _day_start(moment)))
        return int(cur.fetchone()[0])


def transfer(c, from_account_id: str, to_account_id: str, units: int, *,
             request_id: str, reason: str | None = None, actor: str = "user:transfer",
             now: datetime | None = None) -> dict:
    """平台内 COP 转让（§9.1）：不触链、不产生 USD 分录、不进 PoR、不收转让费。

    拒绝顺序（都在写账之前完成）：
    开关关闭 → 403/40303；缺 request_id / 自转 / 账户状态 / 未验证 / 同设备或支付簇 /
    单笔超限 / 单日转出或接收超限 / 可用持有量不足。
    收款方进 ``locked`` 桶并带 7 天解锁时间（锁定期内不可再转出、不可抵扣）。
    """
    now = _as_utc(now)
    policy = load_policy(c)

    # ① 开关（默认 false）：关闭即 403，不静默降级
    if not policy.transfer_enabled:
        raise TransferDisabled("积分转让未开启（points.transfer_enabled=false）",
                               reason="feature_not_open",
                               open_phase="S1 默认关闭，由后台配置项 points.transfer_enabled 开启")

    if not request_id:
        raise TransferRejected("转让必须带 request_id 以便幂等与审计", reason="request_id_required")
    units = int(units)
    if units <= 0:
        raise TransferRejected("转让数量必须 > 0", reason="invalid_units")
    if from_account_id == to_account_id:
        raise TransferRejected("不可自转", reason="self_transfer")

    # ② 幂等：同一 request_id 只记一次
    with c.cursor() as cur:
        cur.execute("""SELECT journal_id FROM points_journal
                        WHERE request_id = %s AND action = 'transfer'""", (request_id,))
        row = cur.fetchone()
    if row is not None:
        existing = _journal_result(c, str(row[0]))
        existing["idempotent"] = True
        with c.cursor() as cur:
            cur.execute("""SELECT transfer_id, from_account_id, to_account_id, amount_units
                             FROM points_transfer WHERE request_id = %s""", (request_id,))
            t = cur.fetchone()
        if t is not None:
            existing.update({"transfer_id": str(t[0]), "from_account_id": t[1],
                             "to_account_id": t[2], "amount_units": int(t[3])})
        return existing

    # ③ 账户资格：仅 normal 且已验证
    sender = _account_row(c, from_account_id)
    receiver = _account_row(c, to_account_id)
    for role, account in (("from", sender), ("to", receiver)):
        if account["state"] not in ELIGIBLE_STATES:
            raise TransferRejected(f"{role} 账户状态 {account['state']} 不可转让",
                                   reason="account_state", account_id=account["account_id"])
        if not account["verified"]:
            raise TransferRejected(f"{role} 账户未验证", reason="account_unverified",
                                   account_id=account["account_id"])
    if sender["device_cluster"] and sender["device_cluster"] == receiver["device_cluster"]:
        raise TransferRejected("不可转给同一设备簇", reason="same_device_cluster")
    if sender["payment_cluster"] and sender["payment_cluster"] == receiver["payment_cluster"]:
        raise TransferRejected("不可转给同一支付方式簇", reason="same_payment_cluster")

    # ④ 限额
    if units > policy.per_transfer_max_units:
        raise TransferRejected(f"单笔超过上限 {policy.per_transfer_max_units} COP",
                               reason="per_transfer_limit", limit=policy.per_transfer_max_units)
    out_today = _daily_transfer_sum(c, from_account_id, now, direction="out")
    if out_today + units > policy.daily_out_max_units:
        raise TransferRejected(f"单日转出超过上限 {policy.daily_out_max_units} COP",
                               reason="daily_out_limit", limit=policy.daily_out_max_units,
                               used_units=out_today)
    in_today = _daily_transfer_sum(c, to_account_id, now, direction="in")
    if in_today + units > policy.daily_in_max_units:
        raise TransferRejected(f"单日接收超过上限 {policy.daily_in_max_units} COP",
                               reason="daily_in_limit", limit=policy.daily_in_max_units,
                               used_units=in_today)

    # ⑤ 可用量（先把已到期的锁定释放）
    release_due(c, now=now, account_id=from_account_id)
    available = holding(c, from_account_id)["usable_units"]
    if available < units:
        raise InsufficientHolding(
            f"COP 可用量不足：需要 {units}，可用 {available}",
            reason="insufficient_points", required_units=units, available_units=available)

    unlock_at = now + timedelta(days=policy.lock_days)
    jid = _open_journal(c, action="transfer", account_id=from_account_id, units=units,
                        actor=actor, reason_code="user_transfer", request_id=request_id,
                        counterparty_id=to_account_id, policy=policy)
    _add_leg(c, journal_id=jid, account_id=from_account_id, bucket="available", delta=-units,
             action="transfer", actor=actor, reason_code="transfer_out", ref_id=to_account_id)
    _add_leg(c, journal_id=jid, account_id=to_account_id, bucket="locked", delta=units,
             action="transfer", actor=actor, reason_code="transfer_in",
             ref_id=from_account_id, unlock_at=unlock_at)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO points_transfer
                 (journal_id, from_account_id, to_account_id, amount_units, reason,
                  request_id, policy_version, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
               RETURNING transfer_id""",
            (jid, from_account_id, to_account_id, units, reason, request_id,
             policy.policy_version, now))
        transfer_id = str(cur.fetchone()[0])

    out = _journal_result(c, jid)
    out.update({"transfer_id": transfer_id, "from_account_id": from_account_id,
                "to_account_id": to_account_id, "amount_units": units,
                "locked_until": unlock_at, "idempotent": False,
                "fee_units": 0, "on_chain": False, "usd_entries": 0,
                "in_por": False})
    return out


# --------------------------------------------------------------------------- 复算 / 证据
def recompute(c, account_id: str | None = None) -> dict:
    """COP 维度复算：每笔 journal 借贷平衡、无负可用量、无负锁定量、从未出现 USD 维度。"""
    params: tuple = ()
    where = ""
    if account_id:
        where = " WHERE account_id = %s"
        params = (account_id,)
    with c.cursor() as cur:
        cur.execute(f"SELECT journal_id, SUM(delta) FROM points_ledger{where} GROUP BY journal_id",
                    params)
        unbalanced = [str(j) for j, total in cur.fetchall() if int(total) != 0]
        cur.execute(
            f"""SELECT COUNT(*) FROM points_ledger{where}
                 {'AND' if where else 'WHERE'} (unit_type <> 'COP' OR coa_code <> '2103')""",
            params)
        non_cop = int(cur.fetchone()[0])
        cur.execute("""SELECT COUNT(*) FROM points_holding
                        WHERE usable_units < 0 OR locked_units < 0""")
        negative = int(cur.fetchone()[0])
        cur.execute("SELECT COUNT(*) FROM points_ledger")
        entries = int(cur.fetchone()[0])
        cur.execute("SELECT COUNT(*) FROM points_journal")
        journals = int(cur.fetchone()[0])
    return {"journals": journals, "entries": entries, "unbalanced_journals": unbalanced,
            "non_cop_entries": non_cop, "negative_holdings": negative,
            "diff": len(unbalanced) + non_cop + negative}


def usd_ledger_fingerprint(c) -> dict:
    """USD 账本指纹：COP 动作前后必须完全一致（COP 不碰 USD 账本）。"""
    with c.cursor() as cur:
        cur.execute("SELECT COUNT(*), COALESCE(SUM(amount_micro),0) FROM ledger_entries")
        entries, total = cur.fetchone()
        cur.execute("""SELECT COUNT(*) FROM ledger_entries
                        WHERE unit_type IS NOT NULL AND unit_type <> 'USD'""")
        non_usd = int(cur.fetchone()[0])
        cur.execute("SELECT COUNT(*), COALESCE(SUM(balance_micro),0) FROM accounts")
        accounts, balance = cur.fetchone()
    return {"entries": int(entries), "sum_micro": int(total), "non_usd_entries": non_usd,
            "accounts": int(accounts), "accounts_sum_micro": int(balance)}
