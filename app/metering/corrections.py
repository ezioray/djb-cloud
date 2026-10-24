# SPDX-License-Identifier: AGPL-3.0-or-later
"""校正在案（M05 §3 状态机 / INV-06 / INV-07 / INV-08 / §6 流程 3）。

四条硬规则：

1. **只追加**：校正只新增行；usage 的 ``amount_minor`` 永不修改（INV-06）；
2. **累计不超原额**：同一 usage 的 proposed + applied 差额合计（取绝对值）不得超过原额（INV-08），
   超过 → 拒绝并转人工（§7「校正累计超额」）；
3. **复核**：负向校正（退款方向）必须人工复核；差额 ≥ ``metering.correction_dual_threshold_usd``
   时复核人必填且 ≠ 操作人（§8.1 / spec「≥50 USD 双人复核」）。校验在**提交**与**生效**两处都做；
4. **幂等**：``request_key``（X-DJB-Idempotency-Key 原样）与 ``(usage_id, upstream_bill_id)``
   两个唯一键；重复提交返回首次结果，不新增行。

生效（apply）时：校正 ``proposed → applied``，usage ``recorded|settled → corrected``（508 放宽了
``settled → corrected``，因为上游账单 T+1 到达时用量往往已经结算），并在**同一事务**里发
``usage.settled``（M07 计 COP、M09 对账用）。M05 **不写分录**——冲正由 M06 完成。
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

import psycopg

from . import (amounts, clock, config_source, errors, events, facts, models, outbox)

log = logging.getLogger("djb.metering.corrections")

#: 参与「累计」计算的校正状态（proposed 也算，避免连续提交绕过 INV-08）
COUNTED_STATES = ("proposed", "applied")


@dataclass(frozen=True)
class CorrectionInput:
    usage_id: str
    delta_minor: int
    reason_code: str
    requested_by: str
    upstream_bill_id: str | None = None
    second_approver: str | None = None
    detail: str | None = None
    request_key: str | None = None


# --------------------------------------------------------------------------- 读取
def load(c: Any, correction_id: str) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT correction_id, usage_id, delta_minor, original_minor, reason_code,
                      upstream_bill_id, state, requested_by, second_approver, detail,
                      created_at, applied_at, rejected_at, request_key
                 FROM usage_corrections WHERE correction_id = %s""", (correction_id,))
        return _row(cur)
    return None


def _row(cur: Any) -> dict[str, Any] | None:
    row = cur.fetchone()
    if row is None:
        return None
    keys = ("correction_id", "usage_id", "delta_minor", "original_minor", "reason_code",
            "upstream_bill_id", "state", "requested_by", "second_approver", "detail",
            "created_at", "applied_at", "rejected_at", "request_key")
    item = dict(zip(keys, row))
    item["correction_id"] = str(item["correction_id"])
    item["usage_id"] = str(item["usage_id"])
    return item


def find_by_request_key(c: Any, request_key: str) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT correction_id, usage_id, delta_minor, original_minor, reason_code,
                      upstream_bill_id, state, requested_by, second_approver, detail,
                      created_at, applied_at, rejected_at, request_key
                 FROM usage_corrections WHERE request_key = %s""", (request_key,))
        return _row(cur)


def find_by_bill(c: Any, usage_id: str, upstream_bill_id: str) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT correction_id, usage_id, delta_minor, original_minor, reason_code,
                      upstream_bill_id, state, requested_by, second_approver, detail,
                      created_at, applied_at, rejected_at, request_key
                 FROM usage_corrections WHERE usage_id = %s AND upstream_bill_id = %s""",
            (usage_id, upstream_bill_id))
        return _row(cur)


def load_usage_amount(c: Any, usage_id: str) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT amount_minor, state, receipt_id FROM usage_records WHERE usage_id = %s""",
            (usage_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return {"amount_minor": int(row[0]), "state": row[1], "receipt_id": row[2]}


def counted_delta(c: Any, usage_id: str, *, exclude_correction_id: str | None = None) -> int:
    """该 usage 已占用的校正差额合计（proposed + applied，带符号）。

    ``exclude_correction_id`` 用于**生效**路径：本校正此刻仍是 ``proposed``，若不排除会与
    待生效的 delta 重复计算（累计校验会虚高）。
    """
    with c.cursor() as cur:
        cur.execute(
            """SELECT COALESCE(sum(delta_minor), 0) FROM usage_corrections
                WHERE usage_id = %s AND state = ANY(%s)
                  AND (%s::uuid IS NULL OR correction_id <> %s::uuid)""",
            (usage_id, list(COUNTED_STATES), exclude_correction_id, exclude_correction_id))
        return int(cur.fetchone()[0])


# --------------------------------------------------------------------------- 规则
def within_tolerance(delta_minor: int, original_minor: int, tolerance_pct: float) -> bool:
    """差额率是否在容差内（**整数**比较，不引入浮点误差；1% = 100 bps）。"""
    if original_minor <= 0:
        return delta_minor == 0
    tolerance_bps = int(round(float(tolerance_pct) * facts.BPS_PER_PCT))
    return abs(int(delta_minor)) * facts.BPS_DENOMINATOR <= int(original_minor) * tolerance_bps


def needs_dual_approval(delta_minor: int, config: config_source.MeteringConfig) -> bool:
    """负向校正一律需复核；正向校正达到 §8.1 门槛（默认 50 USD）也需复核。"""
    if delta_minor < 0:
        return True
    threshold_minor = int(round(config.correction_dual_threshold_usd * facts.MINOR_PER_MAJOR))
    return abs(int(delta_minor)) >= threshold_minor


def _require_approver(item: CorrectionInput, config: config_source.MeteringConfig) -> None:
    if not needs_dual_approval(item.delta_minor, config):
        return
    if not item.second_approver:
        raise errors.Conflict("该校正需要双人复核（second_approver 必填）",
                              reason="dual_approval_required")
    if item.second_approver == item.requested_by:
        raise errors.Conflict("复核人不能是操作人本人", reason="second_approver_must_differ")


# --------------------------------------------------------------------------- 提交
def propose(c: Any, item: CorrectionInput, *, now: Any = None,
            config: config_source.MeteringConfig | None = None,
            require_approval: bool = True) -> dict[str, Any]:
    """提交一条校正（``proposed``）。``require_approval=False`` 仅供自动对账（待人工复核）。"""
    moment = clock.as_utc(now or clock.utcnow())
    snapshot = config or config_source.snapshot()
    usage = load_usage_amount(c, item.usage_id)
    if usage is None:
        raise errors.NotFound("用量不存在", object="usage")
    if item.reason_code not in facts.CORRECTION_REASONS:
        raise errors.InvalidArgument("reason_code 取值非法", field="reason_code",
                                     allowed=list(facts.CORRECTION_REASONS))
    if item.delta_minor == 0:
        raise errors.InvalidArgument("校正差额不能为 0", field="delta")
    _validate_text(item.requested_by, "requested_by", facts.MAX_ID_LEN)
    _validate_text(item.detail, "detail", facts.MAX_DETAIL_LEN, required=False)
    _validate_text(item.upstream_bill_id, "upstream_bill_id", facts.MAX_ID_LEN, required=False)
    _validate_text(item.request_key, "request_key", facts.MAX_REQUEST_KEY_LEN, required=False)
    if require_approval:
        _require_approver(item, snapshot)

    # 幂等：先按 request_key、再按 (usage_id, upstream_bill_id)
    if item.request_key:
        existing = find_by_request_key(c, item.request_key)
        if existing is not None:
            return {"created": False, "correction": existing}
    if item.upstream_bill_id:
        existing = find_by_bill(c, item.usage_id, item.upstream_bill_id)
        if existing is not None:
            return {"created": False, "correction": existing}

    # INV-08：累计不超原额
    total_after = counted_delta(c, item.usage_id) + item.delta_minor
    if abs(total_after) > usage["amount_minor"]:
        raise errors.Conflict(
            f"校正累计超过原额（累计 {total_after} > 原额 {usage['amount_minor']}），转人工复核",
            reason="cumulative_exceeded", original_minor=usage["amount_minor"],
            cumulative_minor=total_after)

    correction_id = str(models.uuid7(moment))
    try:
        with c.transaction():
            with c.cursor() as cur:
                cur.execute(
                    """INSERT INTO usage_corrections
                         (correction_id, usage_id, delta_minor, original_minor, reason_code,
                          upstream_bill_id, state, requested_by, second_approver, detail,
                          created_at, request_key)
                       VALUES (%s,%s,%s,%s,%s,%s,'proposed',%s,%s,%s,%s,%s)""",
                    (correction_id, item.usage_id, int(item.delta_minor),
                     usage["amount_minor"], item.reason_code, item.upstream_bill_id,
                     item.requested_by, item.second_approver, item.detail, moment,
                     item.request_key))
    except psycopg.errors.UniqueViolation:
        existing = find_by_request_key(c, item.request_key or "") or find_by_bill(
            c, item.usage_id, item.upstream_bill_id or "")
        if existing is None:                                # pragma: no cover - 竞态兜底
            raise
        return {"created": False, "correction": existing}
    log.info("metering.correction.proposed",
             extra={"correction_id": correction_id, "usage_id": item.usage_id,
                    "delta_minor": item.delta_minor})
    return {"created": True, "correction": load(c, correction_id)}


# --------------------------------------------------------------------------- 生效 / 驳回
def apply(c: Any, correction_id: str, *, approver: str, now: Any = None,
          trace_id: str = "", config: config_source.MeteringConfig | None = None) -> dict[str, Any]:
    """复核通过：``proposed → applied``，usage ``recorded|settled → corrected``，发 usage.settled。"""
    moment = clock.as_utc(now or clock.utcnow())
    snapshot = config or config_source.snapshot()
    correction = load(c, correction_id)
    if correction is None:
        raise errors.NotFound("校正不存在", object="correction")
    if correction["state"] != "proposed":
        raise errors.Conflict(f"校正状态 {correction['state']} 不可生效",
                              reason="state_conflict", state=correction["state"])
    _validate_text(approver, "approver", facts.MAX_ID_LEN)
    item = CorrectionInput(usage_id=correction["usage_id"],
                           delta_minor=int(correction["delta_minor"]),
                           reason_code=correction["reason_code"],
                           requested_by=correction["requested_by"],
                           second_approver=approver,
                           upstream_bill_id=correction["upstream_bill_id"])
    _require_approver(item, snapshot)

    usage = load_usage_amount(c, correction["usage_id"])
    if usage is None:
        raise errors.NotFound("用量不存在", object="usage")
    total_after = counted_delta(c, correction["usage_id"],
                                exclude_correction_id=correction_id) + int(correction["delta_minor"])
    if abs(total_after) > usage["amount_minor"]:
        raise errors.Conflict("校正累计超过原额，拒绝生效（INV-08）",
                              reason="cumulative_exceeded")

    with c.transaction():
        with c.cursor() as cur:
            cur.execute(
                """UPDATE usage_corrections
                      SET state = 'applied', applied_at = %s, second_approver = %s
                    WHERE correction_id = %s""", (moment, approver, correction_id))
            cur.execute(
                """UPDATE usage_records SET state = 'corrected', corrected_at = %s,
                          correction_id = %s
                    WHERE usage_id = %s""", (moment, correction_id, correction["usage_id"]))
        final_amount = usage["amount_minor"] + total_after
        outbox.append(c, events.usage_settled_event(
            usage_id=correction["usage_id"], final_amount_minor=final_amount,
            correction_id=correction_id, trace_id=trace_id or correction_id,
            occurred_at=moment))
    applied = load(c, correction_id)
    log.info("metering.correction.applied",
             extra={"correction_id": correction_id, "usage_id": correction["usage_id"],
                    "final_amount_minor": final_amount})
    return {"correction": applied, "final_amount_minor": final_amount,
            "usage_state": "corrected"}


def reject(c: Any, correction_id: str, *, approver: str, now: Any = None) -> dict[str, Any]:
    """复核驳回：``proposed → rejected``（不改 usage、不改原校正的业务列）。"""
    moment = clock.as_utc(now or clock.utcnow())
    _validate_text(approver, "approver", facts.MAX_ID_LEN)
    correction = load(c, correction_id)
    if correction is None:
        raise errors.NotFound("校正不存在", object="correction")
    if correction["state"] != "proposed":
        raise errors.Conflict(f"校正状态 {correction['state']} 不可驳回",
                              reason="state_conflict", state=correction["state"])
    with c.cursor() as cur:
        cur.execute("UPDATE usage_corrections SET state = 'rejected', rejected_at = %s "
                    "WHERE correction_id = %s", (moment, correction_id))
    return {"correction": load(c, correction_id)}


# --------------------------------------------------------------------------- 小工具
def _validate_text(value: Any, field: str, max_len: int, *, required: bool = True) -> None:
    if value is None:
        if required:
            raise errors.InvalidArgument(f"缺 {field}", field=field)
        return
    if not isinstance(value, str) or not (1 <= len(value.strip()) <= max_len):
        raise errors.InvalidArgument(f"{field} 长度必须是 1..{max_len}", field=field)


def parse_delta(raw: Any) -> int:
    """解析差额（spec ``Amount``）：允许负数（退款方向），最多 2 位小数。"""
    try:
        return amounts.parse_minor(raw, field="delta", allow_negative=True)
    except amounts.AmountError as exc:
        raise errors.InvalidArgument(f"delta 非法：{exc}", field="delta") from exc


def from_request(body: Mapping[str, Any], *, requested_by: str,
                 request_key: str | None) -> CorrectionInput:
    """把 spec ``UsageCorrectionRequest`` 转成域对象（金额走 Amount 对象或扁平字段）。"""
    usage_id = body.get("usage_id")
    if not isinstance(usage_id, str) or not usage_id.strip():
        raise errors.InvalidArgument("缺 usage_id", field="usage_id")
    delta_raw = body.get("delta")
    if isinstance(delta_raw, Mapping):
        delta_raw = delta_raw.get("amount")
    reason = body.get("reason_code")
    if not isinstance(reason, str) or reason not in facts.CORRECTION_REASONS:
        raise errors.InvalidArgument("reason_code 取值非法", field="reason_code",
                                     allowed=list(facts.CORRECTION_REASONS))
    second = body.get("second_approver")
    return CorrectionInput(
        usage_id=usage_id.strip(), delta_minor=parse_delta(delta_raw), reason_code=reason,
        requested_by=requested_by,
        upstream_bill_id=(body.get("upstream_bill_id") or None),
        second_approver=(second or None), detail=(body.get("evidence_ref") or None),
        request_key=request_key)


__all__ = ["CorrectionInput", "load", "find_by_request_key", "find_by_bill",
           "load_usage_amount", "counted_delta", "within_tolerance", "needs_dual_approval",
           "propose", "apply", "reject", "parse_delta", "from_request"]
