# SPDX-License-Identifier: Apache-2.0
"""上游账单导入与对账（M05 §5 / §6 流程 3 / §7 / INV-07 / spec ``UpstreamBillImportRequest``）。

逐行受理（单行失败不回滚整批）：

* 先按 ``bill_id`` 幂等入表（``imported``）；重复导入返回首次结果（``duplicate``）；
* 行里给了 ``usage_id`` 时按 (access, period) 匹配本地用量，算差额：
  - 差额率 ≤ ``metering.overbill_tolerance_pct``（默认 1%）→ 账单 ``reconciled``，
    发 ``usage.settled``（最终金额 = 原额，**不产生校正**）；
  - 超过阈值 → 追加一条 ``proposed`` 校正（``overbill`` / ``underbill``）+ 差异工单口径，
    账单停在 ``imported``（等人工复核后 apply），**原 usage 一个字段都不改**（INV-06）；
  - 匹配不到用量 → ``unmatched``（账单留着，等下一轮对账），不静默丢弃。
* 差额率比较用**整数**算术（bps），不引入浮点误差。

符号约定（与 503 注释一致）：``delta = 上游账单金额 − 本地计费金额``；
``delta > 0`` = 我们少计（补收，``underbill``）；``delta < 0`` = 我们多计（退款方向，``overbill``）。
"""
from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Iterable, Mapping

import psycopg

from . import (amounts, clock, config_source, corrections, errors, events, facts, models,
               outbox)

log = logging.getLogger("djb.metering.bills")


def _validate_common(provider: Any, period: Any, imported_by: Any) -> tuple[str, str, str]:
    if not isinstance(provider, str) or not (1 <= len(provider.strip()) <= facts.MAX_PROVIDER_LEN):
        raise errors.InvalidArgument(f"provider 长度必须是 1..{facts.MAX_PROVIDER_LEN}",
                                     field="provider")
    if not isinstance(period, str) or not re.match(facts.BILL_PERIOD_PATTERN, period.strip()):
        raise errors.InvalidArgument("period 必须是 YYYY-MM（spec pattern）", field="period")
    if not isinstance(imported_by, str) or not (1 <= len(imported_by.strip()) <= facts.MAX_ID_LEN):
        raise errors.InvalidArgument("imported_by 必填（FIN / OPS 后台 id）", field="imported_by")
    return provider.strip(), period.strip(), imported_by.strip()


def load(c: Any, bill_id: str) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT bill_id, provider, period, amount_minor, access, state, imported_at,
                      reconciled_at, imported_by
                 FROM upstream_bills WHERE bill_id = %s""", (bill_id,))
        row = cur.fetchone()
    if row is None:
        return None
    keys = ("bill_id", "provider", "period", "amount_minor", "access", "state", "imported_at",
            "reconciled_at", "imported_by")
    return dict(zip(keys, row))


def _parse_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """解析一行账单（spec ``UpstreamBillRow``）：``amount`` 是 ``Amount`` 对象或扁平值。

    ``unit=usd`` 按主单位（美元）解析；``unit=usd_minor`` 按整数分直传（内部/测试便捷写法）。
    """
    row_id = row.get("row_id")
    if not isinstance(row_id, str) or not (1 <= len(row_id.strip()) <= facts.MAX_ID_LEN):
        raise errors.InvalidArgument("缺 row_id（上游账单行号）", field="row_id")
    amount_raw = row.get("amount")
    unit: Any = None
    if isinstance(amount_raw, Mapping):
        unit = amount_raw.get("unit", facts.CURRENCY)
        amount_raw = amount_raw.get("amount")
    normalised_unit = str(unit or facts.CURRENCY).strip().lower()
    try:
        if normalised_unit == f"{facts.CURRENCY.lower()}_minor":
            amount_minor = amounts.parse_quantity(amount_raw, field="amount")
        elif normalised_unit == facts.CURRENCY.lower():
            amount_minor = amounts.parse_minor(amount_raw, field="amount")
        else:
            raise errors.UnsupportedCurrency(
                f"S1 只对 {facts.CURRENCY} 账单，收到 amount.unit={unit!r}")
    except amounts.AmountError as exc:
        raise errors.InvalidArgument(f"amount 非法：{exc}", field="amount") from exc
    return {"row_id": row_id.strip(), "amount_minor": amount_minor,
            "access": row.get("access"), "model": row.get("model"),
            "usage_id": row.get("usage_id")}


def import_rows(c: Any, *, provider: Any, period: Any, rows: Iterable[Mapping[str, Any]],
                imported_by: Any, now: Any = None,
                config: config_source.MeteringConfig | None = None,
                trace_id: str = "") -> dict[str, Any]:
    """逐行导入（幂等 + 对账）；返回 spec ``UpstreamBillImportAck`` 形状 + 单行结果。"""
    moment = clock.as_utc(now or clock.utcnow())
    snapshot = config or config_source.snapshot()
    provider_text, period_text, operator = _validate_common(provider, period, imported_by)
    batch = list(rows)
    if not 1 <= len(batch) <= facts.BILL_ROWS_MAX:
        raise errors.BatchTooLarge(f"账单行数必须是 1..{facts.BILL_ROWS_MAX}（收到 {len(batch)}）")

    import_id = f"imp_{models.uuid7(moment).hex[:20]}"
    accepted = 0
    total_minor = 0
    rejected: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for raw in batch:
        try:
            parsed = _parse_row(raw)
        except errors.MeteringError as exc:
            rejected.append({"row_id": str((raw or {}).get("row_id") or ""),
                             "code": int(exc.code), "message": exc.message})
            continue
        bill_id = parsed["row_id"]
        try:
            with c.transaction():
                inserted = _insert_bill(c, bill_id=bill_id, provider=provider_text,
                                        period=period_text, amount_minor=parsed["amount_minor"],
                                        access=parsed["access"], imported_by=operator,
                                        moment=moment)
            if not inserted:
                existing = load(c, bill_id)
                results.append({"row_id": bill_id, "status": "duplicate",
                                "state": existing["state"] if existing else None})
                accepted += 1
                continue
            outcome = _reconcile(c, parsed=parsed, provider=provider_text, period=period_text,
                                 operator=operator, moment=moment, snapshot=snapshot,
                                 trace_id=trace_id)
            results.append({"row_id": bill_id, **outcome})
            accepted += 1
            total_minor += parsed["amount_minor"]
        except errors.MeteringError as exc:
            rejected.append({"row_id": bill_id, "code": int(exc.code), "message": exc.message})
        except psycopg.errors.Error as exc:                # pragma: no cover - 传染性故障
            log.warning("metering.bill.persist_failed",
                        extra={"bill_id": bill_id, "error": type(exc).__name__})
            rejected.append({"row_id": bill_id, "code": 40001, "message": "账单落库失败"})

    return {"import_id": import_id, "rows_accepted": accepted,
            "rows_rejected": len(rejected), "total_amount":
                {"amount": amounts.format_minor(total_minor), "unit": facts.CURRENCY},
            "rejected": rejected, "imported_at": models.iso(moment), "results": results}


def _insert_bill(c: Any, *, bill_id: str, provider: str, period: str, amount_minor: int,
                 access: Any, imported_by: str, moment: Any) -> bool:
    access_text = (access or "A1")
    if access_text not in facts.ACCESS_MODES:
        raise errors.InvalidArgument("access 取值非法", field="access")
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO upstream_bills
                 (bill_id, provider, period, amount_minor, access, state, imported_at,
                  imported_by)
               VALUES (%s,%s,%s,%s,%s,'imported',%s,%s)
               ON CONFLICT (bill_id) DO NOTHING""",
            (bill_id, provider, period, int(amount_minor), access_text, moment, imported_by))
        return cur.rowcount == 1


def _reconcile(c: Any, *, parsed: Mapping[str, Any], provider: str, period: str, operator: str,
               moment: Any, snapshot: config_source.MeteringConfig,
               trace_id: str) -> dict[str, Any]:
    usage_id = parsed.get("usage_id")
    if not usage_id:
        return {"status": "unmatched", "reason": "no_usage_id"}
    usage = corrections.load_usage_amount(c, str(usage_id))
    if usage is None:
        return {"status": "unmatched", "reason": "usage_not_found"}
    delta = int(parsed["amount_minor"]) - usage["amount_minor"]
    if corrections.within_tolerance(delta, usage["amount_minor"],
                                    snapshot.overbill_tolerance_pct):
        with c.transaction():
            with c.cursor() as cur:
                cur.execute("UPDATE upstream_bills SET state = 'reconciled', "
                            "reconciled_at = %s WHERE bill_id = %s", (moment, parsed["row_id"]))
                if usage["state"] != "corrected":
                    cur.execute("UPDATE usage_records SET state = 'settled', settled_at = %s "
                                "WHERE usage_id = %s AND state = 'recorded'",
                                (moment, str(usage_id)))
            outbox.append(c, events.usage_settled_event(
                usage_id=str(usage_id), final_amount_minor=usage["amount_minor"],
                correction_id=None, trace_id=trace_id or parsed["row_id"],
                occurred_at=moment))
        return {"status": "reconciled", "usage_id": str(usage_id), "delta_minor": delta,
                "tolerance_pct": snapshot.overbill_tolerance_pct}
    reason_code = "underbill" if delta > 0 else "overbill"
    proposed = corrections.propose(
        c, corrections.CorrectionInput(
            usage_id=str(usage_id), delta_minor=delta, reason_code=reason_code,
            requested_by=operator, upstream_bill_id=parsed["row_id"],
            detail=f"upstream_bill:{provider}:{period}"),
        now=moment, config=snapshot, require_approval=False)
    correction = proposed["correction"]
    return {"status": "correction_proposed" if proposed["created"] else "correction_exists",
            "usage_id": str(usage_id), "delta_minor": delta,
            "correction_id": correction["correction_id"], "reason_code": reason_code,
            "tolerance_pct": snapshot.overbill_tolerance_pct,
            "ticket": "usage_diff",                       # 差异工单口径（M14 建单）
            "created": proposed["created"]}


__all__ = ["load", "import_rows"]
