# SPDX-License-Identifier: Apache-2.0
"""M07 COP 适配层（**薄封装** ``app/points.py``；COP 唯一账本仍是 ``points_*``）。

Lead 裁决（task-5）：**COP 账本不重建**。``app/points.py``（DEV-0003 / migration 006）是 COP
的唯一账本与唯一记账实现，本模块：

* **不改** ``app/points.py``、**不改** migration 006、**不建** ``cop_ledger``（703）；
* 只做三件事：① 读余额 / 台账（走只读视图 ``v_m07_cop_ledger`` / ``v_m07_cop_status``）；
  ② 调 points 的六值动作（``earn`` / ``adjust`` / ``transfer``）与同一套记账原语；
  ③ 把 ``points`` 的异常翻成 spec 1.2.4 的错误码（同一异常在**兑换**与**转让**上下文里
  语义不同：余额不足在兑换是 402/40201，在转让的锁定期 / 超限是 422/42240）。

关于直接调用 ``points._open_journal`` / ``points._add_leg``（私有原语）的说明：
兑换接口的入参是「兑换多少 COP」（spec ``CopRedemptionRequest.units``），而
``points.redeem_service_fee`` 的入参是「某张账单多少 USD」，两者口径不同；为**避免出现
第二套记账实现**（INV-02 只追加 / INV-01 余额守恒都依赖单一写路径），本模块复用 points
的记账原语写 ``redeem`` / ``earn(locked)`` 分录，余额与锁定的判定仍全部走 points 的公开函数
（``release_due`` / ``holding`` / ``load_policy``）。这是**已知的私有 API 耦合**，
交付报告里作为遗留项列出：建议 points.py 增加公开的 ``earn_locked()`` / ``redeem_units()``
（需 points 所有者批准，本席位无权改）。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from app import points as cop_ledger

from . import clock, errors, outbox
from .models import CopBalance, CopLedgerEntry, Redemption, Transfer, decode_cursor, encode_cursor

__all__ = [
    "policy", "ensure_account", "balance", "ledger_page", "redemption", "redeem",
    "transfer", "post_earn", "translate", "account_state",
]

SYSTEM_ACCOUNT = cop_ledger.SYSTEM_ACCOUNT
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


# --------------------------------------------------------------------------- 基础
def policy(conn: Any) -> "cop_ledger.Policy":
    """读生效 COP 策略（``points_policy``，含 P0 开关 ``points.transfer_enabled``）。"""
    return cop_ledger.load_policy(conn)


def account_state(conn: Any, account_id: str) -> str | None:
    """COP 账户状态（``points_account.state``）；无档案返回 ``None``。"""
    with conn.cursor() as cur:
        cur.execute("SELECT state FROM points_account WHERE account_id = %s", (account_id,))
        row = cur.fetchone()
    return row[0] if row else None


def ensure_account(conn: Any, account_id: str) -> None:
    """COP 账户档案不存在时补建（**插入式**，绝不覆盖既有 verified / 风控簇）。

    新档案 ``verified=False``：实名 / 风控簇由 M01 / M11 同步，本模块不自行「认证」用户
    （fail-closed：未认证不可转让）。
    """
    if not account_id:
        raise errors.InvalidArgument("account_id 必填")
    if account_state(conn, account_id) is None:
        cop_ledger.open_account(conn, account_id, verified=False)


def _limit(raw: Any) -> int:
    if raw in (None, ""):
        return DEFAULT_PAGE_LIMIT
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument("limit 必须是整数") from exc
    if not 1 <= value <= MAX_PAGE_LIMIT:
        raise errors.InvalidArgument(f"limit 必须在 1..{MAX_PAGE_LIMIT}")
    return value


# --------------------------------------------------------------------------- 读
def balance(conn: Any, account_id: str, *, now: datetime | None = None,
            policy_override: "cop_ledger.Policy | None" = None) -> CopBalance:
    """可用 / 锁定 / 累计 COP（spec ``CopBalance``；INV-01：available + locked = total）。

    无 COP 档案的账户返回全 0（不是 404：用户侧「还没攒过 COP」是正常态）。
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT COALESCE(s.available, 0), COALESCE(s.locked, 0),
                      COALESCE(s.total_earned, 0),
                      (SELECT max(l.created_at) FROM v_m07_cop_ledger l
                        WHERE l.account_id = %s)
                 FROM (SELECT 1) one
                 LEFT JOIN v_m07_cop_status s ON s.account_id = %s""",
            (account_id, account_id))
        row = cur.fetchone()
    available, locked, earned, last_entry = (int(row[0]), int(row[1]), int(row[2]), row[3])
    pol = policy_override or policy(conn)
    state = account_state(conn, account_id)
    usable = state == "normal"
    moment = clock.as_utc(now)
    return CopBalance(
        available=max(0, available), locked=max(0, locked), total_earned=max(0, earned),
        redeemable=bool(usable and available > 0),
        transferable=bool(usable and pol.transfer_enabled),
        updated_at=last_entry or moment)


def ledger_page(conn: Any, account_id: str, *, limit: Any = None,
                cursor: str | None = None) -> tuple[list[CopLedgerEntry], str | None]:
    """COP 台账分页（游标 keyset：``(created_at, id)`` 倒序；来源与锁定到期见视图）。"""
    size = _limit(limit)
    params: list[Any] = [account_id]
    clause = ""
    if cursor:
        moment, row_id = decode_cursor(cursor)
        clause = " AND (created_at, id) < (%s, %s)"
        params.extend([moment, row_id])
    with conn.cursor() as cur:
        cur.execute(
            f"""SELECT id, account_id, direction, amount, source, ref_id, status,
                       lock_until, created_at
                  FROM v_m07_cop_ledger
                 WHERE account_id = %s{clause}
                 ORDER BY created_at DESC, id DESC
                 LIMIT %s""", (*params, size + 1))
        rows = cur.fetchall()
    entries = [CopLedgerEntry.from_row(row) for row in rows[:size]]
    next_cursor = None
    if len(rows) > size and entries:
        next_cursor = encode_cursor(entries[-1].created_at, entries[-1].id)
    return entries, next_cursor


def redemption(conn: Any, account_id: str, redemption_id: Any) -> Redemption:
    """兑换单状态（兑换单 = 一条 ``redeem`` journal；没有独立表）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT ref_id, units, created_at, journal_id
                 FROM points_journal
                WHERE action = 'redeem' AND account_id = %s
                  AND (ref_id = %s OR journal_id::text = %s)
                ORDER BY created_at DESC LIMIT 1""",
            (account_id, str(redemption_id), str(redemption_id)))
        row = cur.fetchone()
    if row is None:
        raise errors.NotFound("兑换单不存在")
    # 兑换单号 = 创建时返回的 ref_id（老数据没有 ref_id 时退回 journal_id）
    try:
        redemption_key = uuid.UUID(str(row[0])) if row[0] else uuid.UUID(str(row[3]))
    except (TypeError, ValueError):
        redemption_key = uuid.UUID(str(row[3]))
    return Redemption(redemption_id=redemption_key, units=int(row[1]), state="posted",
                      created_at=row[2])


# --------------------------------------------------------------------------- 写：兑换
def redeem(conn: Any, account_id: str, units: int, *, request_id: str | None,
           actor: str, now: datetime | None = None,
           target: str | None = None) -> Redemption:
    """申请兑换：**只扣 available**（locked 不可兑换），余额不足 → 402 / 40201。

    兑换单没有独立表：一次兑换 = 一条 ``redeem`` journal（``points_journal`` /
    ``points_ledger``），``ref_id`` 就是兑换单号，``GET /redemptions/{id}`` 按它回查。
    """
    moment = clock.as_utc(now)
    units = _positive_units(units)
    if target not in (None, "service_fee"):
        raise errors.InvalidArgument("target 只支持 service_fee", reason="invalid_target")
    ensure_account(conn, account_id)

    state = account_state(conn, account_id)
    if state != "normal":
        raise errors.AccountUnavailable(
            "账户当前不可操作（已获得的 COP 保留）", state=state or "missing")

    if request_id:
        replay = _replay_redeem(conn, account_id, request_id)
        if replay is not None:
            return replay

    pol = policy(conn)
    cop_ledger.release_due(conn, now=moment, account_id=account_id)   # 先释放到期锁定
    available = int(cop_ledger.holding(conn, account_id)["usable_units"])
    if available < units:
        raise errors.InsufficientBalance(
            f"COP 可用量不足：需要 {units}，可用 {available}",
            required_units=units, available_units=available)

    ref_id = str(uuid.uuid4())
    journal_id = cop_ledger._open_journal(                       # noqa: SLF001 - 见模块 docstring
        conn, action="redeem", account_id=account_id, units=units, actor=actor,
        reason_code="cop_redemption", request_id=request_id, ref_id=ref_id, policy=pol)
    cop_ledger._add_leg(                                          # noqa: SLF001
        conn, journal_id=journal_id, account_id=account_id, bucket="available",
        delta=-units, action="redeem", actor=actor, reason_code="cop_redemption",
        ref_id=ref_id)
    cop_ledger._add_leg(                                          # noqa: SLF001
        conn, journal_id=journal_id, account_id=SYSTEM_ACCOUNT, bucket="system",
        delta=units, action="redeem", actor=actor, reason_code="cop_redemption",
        ref_id=ref_id)
    journal = cop_ledger.read_journal(conn, journal_id)
    redemption = Redemption(redemption_id=uuid.UUID(ref_id), units=units,
                            state="posted", created_at=journal["created_at"])
    # §4.2：兑换扣减发 cop.spent（与账本同一事务；outbox 按 (type, key) 幂等）
    outbox.enqueue(conn, outbox.cop_spent(
        account_id=account_id, units=units, source="redeem", ref_id=str(redemption.redemption_id),
        occurred_at=redemption.created_at, journal_id=journal_id))
    return redemption


def _replay_redeem(conn: Any, account_id: str, request_id: str) -> Redemption | None:
    """同一幂等键的重复兑换：原样回放第一次结果（不重复扣减）。"""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT journal_id, account_id, units, ref_id, created_at
                 FROM points_journal WHERE action = 'redeem' AND request_id = %s""",
            (request_id,))
        row = cur.fetchone()
    if row is None:
        return None
    if row[1] != account_id:
        raise errors.Conflict("幂等键已被其它账户使用", reason="idempotency_conflict")
    return Redemption(redemption_id=uuid.UUID(row[3]), units=int(row[2]),
                      state="posted", created_at=row[4])


# --------------------------------------------------------------------------- 写：转让
def transfer(conn: Any, from_account_id: str, to_account_id: str, units: int, *,
             request_id: str | None, now: datetime | None = None,
             reason: str | None = None, actor: str = "user:cop") -> Transfer:
    """用户间转让（INV-06 / K4）：开关关闭 → 409 / 40902；锁定期 / 超限 / 自转 → 422 / 42240。

    写账完全交给 ``points.transfer``（唯一实现）：收款方所得入 ``locked``，
    ``points.transfer_lock_days`` 内不可再转出或兑换。
    """
    moment = clock.as_utc(now)
    units = _positive_units(units)
    if not request_id:
        raise errors.InvalidArgument("转让必须带 X-DJB-Idempotency-Key", reason="idempotency_required")
    if not to_account_id:
        raise errors.InvalidArgument("to_account_id 必填")
    ensure_account(conn, from_account_id)
    ensure_account(conn, to_account_id)
    try:
        result = cop_ledger.transfer(
            conn, from_account_id, to_account_id, units, request_id=request_id,
            reason=reason, actor=actor, now=moment)
    except cop_ledger.PointsError as exc:
        raise translate(exc, context="transfer") from exc
    transfer = Transfer(transfer_id=uuid.UUID(str(result["transfer_id"])),
                        units=int(result["amount_units"]), state="posted",
                        created_at=result["created_at"],
                        from_account_id=result["from_account_id"],
                        to_account_id=result["to_account_id"],
                        locked_until=result.get("locked_until"))
    # §6.3：转让在 02-events 没有独立事件类型 → 两条分录各记一条（source 都在 INV-05 枚举内）
    outbox.enqueue(conn, outbox.cop_spent(
        account_id=from_account_id, units=transfer.units, source="transfer_out",
        ref_id=str(transfer.transfer_id), occurred_at=transfer.created_at))
    outbox.enqueue(conn, outbox.cop_earned(
        account_id=str(transfer.to_account_id), units=transfer.units, source="transfer_in",
        ref_id=str(transfer.transfer_id), lock_until=transfer.locked_until,
        occurred_at=transfer.created_at))
    return transfer


# --------------------------------------------------------------------------- 写：计提
def post_earn(conn: Any, account_id: str, units: int, *, source: str, ref_id: str,
              request_id: str | None, actor: str = "system:m07",
              lock_days: int = 0, now: datetime | None = None,
              reason_code: str | None = None) -> dict[str, Any]:
    """计提 COP（``usage`` / ``invite`` / ``reward``）：同一幂等键只记一次。

    ``lock_days > 0`` 时入 ``locked`` 并带 ``unlock_at``（§6.1：结算计提按
    ``points.transfer_lock_days`` 锁定；锁定期内不可再转出或兑换）。
    """
    moment = clock.as_utc(now)
    units = _positive_units(units)
    if source not in ("usage", "invite", "reward"):
        raise errors.InvalidArgument(f"不支持的计提来源：{source}", reason="invalid_source")
    if not ref_id:
        raise errors.InvalidArgument("计提必须带 ref_id（INV-05）", reason="ref_id_required")
    ensure_account(conn, account_id)

    if request_id:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT journal_id, account_id, units, created_at
                     FROM points_journal WHERE request_id = %s""", (request_id,))
            row = cur.fetchone()
        if row is not None:
            if row[1] != account_id:
                raise errors.Conflict("幂等键已被其它账户使用", reason="idempotency_conflict")
            return {"journal_id": str(row[0]), "units": int(row[2]),
                    "created_at": row[3], "idempotent": True, "lock_until": None}

    pol = policy(conn)
    bucket = "locked" if int(lock_days) > 0 else "available"
    unlock_at = (moment + timedelta(days=int(lock_days))) if int(lock_days) > 0 else None
    reason = reason_code or ("usage_settled" if source == "usage"
                             else "invite_reward" if source == "invite" else "manual_reward")
    journal_id = cop_ledger._open_journal(                     # noqa: SLF001
        conn, action="earn", account_id=account_id, units=units, actor=actor,
        reason_code=reason, request_id=request_id, ref_id=ref_id, policy=pol)
    cop_ledger._add_leg(                                        # noqa: SLF001
        conn, journal_id=journal_id, account_id=account_id, bucket=bucket, delta=units,
        action="earn", actor=actor, reason_code=reason, ref_id=ref_id, unlock_at=unlock_at)
    cop_ledger._add_leg(                                        # noqa: SLF001
        conn, journal_id=journal_id, account_id=SYSTEM_ACCOUNT, bucket="system",
        delta=-units, action="earn", actor=actor, reason_code=reason, ref_id=ref_id)
    journal = cop_ledger.read_journal(conn, journal_id)
    return {"journal_id": journal_id, "units": units, "created_at": journal["created_at"],
            "idempotent": False, "lock_until": unlock_at}


# --------------------------------------------------------------------------- 工具
def _positive_units(units: Any) -> int:
    try:
        value = int(units)
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument("units 必须是正整数") from exc
    if value <= 0:
        raise errors.InvalidArgument("units 必须 > 0")
    if value > 10_000_000:
        raise errors.InvalidArgument("units 超出单次上限")
    return value


#: 转让上下文里「账户 / 门槛不满足」→ 409/40902；「参数与限额」→ 422/42240
_TRANSFER_CONFLICT_REASONS = {"account_state", "account_unverified"}
_TRANSFER_VALIDATION_REASONS = {"self_transfer", "per_transfer_limit", "daily_out_limit",
                                "daily_in_limit", "invalid_units", "same_device_cluster",
                                "same_payment_cluster", "insufficient_points"}


def translate(exc: "cop_ledger.PointsError", *, context: str) -> errors.ReputationError:
    """把 points 的异常翻成 spec 1.2.4 的错误码（**唯一**的码翻译处）。

    * ``context='transfer'``：开关关闭 → 409/40902；锁定期 / 超限 / 自转 → 422/42240；
      账户不可用 → 409/40902。
    * ``context='redeem'``：余额不足 → 402/40201；账户不可用 → 409/40902。
    * 其它 → 400/40001（**绝不**把 403/40303 等 points 内部码透出去：spec 1.2.4 只登记了
      40902 / 42240 / 40201）。
    """
    reason = getattr(exc, "reason", None) or "points_error"
    details = {key: value for key, value in (getattr(exc, "details", {}) or {}).items()}

    if isinstance(exc, cop_ledger.TransferDisabled):
        return errors.TransferDisabled(
            "积分转让未开启（points.transfer_enabled=false）", reason="transfer_disabled",
            feature="points.transfer_enabled")
    if isinstance(exc, cop_ledger.InsufficientHolding):
        if context == "transfer":
            return errors.ValidationFailed(
                "可用 COP 不足（锁定期内的积分不可转出）", reason="insufficient_points",
                **details)
        return errors.InsufficientBalance("COP 可用量不足", **details)
    if isinstance(exc, cop_ledger.TransferRejected):
        if reason in _TRANSFER_CONFLICT_REASONS:
            return errors.AccountUnavailable(str(exc.message), reason=reason, **details)
        if reason in _TRANSFER_VALIDATION_REASONS:
            return errors.ValidationFailed(str(exc.message), reason=reason, **details)
        return errors.ValidationFailed(str(exc.message), reason=reason, **details)
    return errors.InvalidArgument(str(exc.message), reason=reason, **details)
