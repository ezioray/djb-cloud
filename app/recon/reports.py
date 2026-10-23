# SPDX-License-Identifier: Apache-2.0
"""报表渲染（本轮：REP-01 recon-daily / REP-02 exceptions）。

纪律（INV-07）：报表数字**只来自当期 run / 差异**，不做二次估算、不填空壳。
`por`（REP-03）/ `wallet-pool`（REP-04）/ `monthly`（REP-06）属 T4，**不注册路由**，
因此不会出现「返回假数据」的端点（见 ``facts.REPORTS_DEFERRED``）。

口径：
* 期间 = spec ``ReportPeriod`` 的 ``YYYY-MM``（UTC 自然月）；run 归属按 ``cutoff_at`` 落月；
* ``period`` 非法 / 当月无 run → ``49210``（spec 1.2.3 登记的「报表周期非法或无数据」）；
* 金额一律整数最小单位（分）；``diff_minor`` 有符号（book − external）。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

import psycopg
from psycopg.rows import dict_row

from . import clock, facts, grading
from .errors import BadRequest, ReportUnavailable

__all__ = ["recon_daily", "exceptions_report", "envelope"]

#: REP-01 里最多列多少条待签核批次（避免报表被大期次撑爆；完整列表走 runs 接口）
PENDING_SIGN_OFF_LIMIT = 50


def _month(period: str, report_id: str) -> tuple[datetime, datetime]:
    """``YYYY-MM`` → 半开区间；非法周期按 spec 1.2.3 归 49210（不是 400）。"""
    try:
        return clock.parse_month(period)
    except BadRequest as exc:
        raise ReportUnavailable(f"报表周期非法（需要 YYYY-MM）：{period!r}",
                               reason="report_period_invalid",
                               report_id=report_id) from exc


def envelope(report_id: str, period: str, data: Mapping[str, Any],
             now: datetime | None = None) -> dict[str, Any]:
    """spec ``ReportEnvelope``：``{report_id, period, generated_at, data}``。"""
    if report_id not in facts.REPORTS_IMPLEMENTED:
        raise ValueError(f"{report_id} 不在本轮实现范围 {facts.REPORTS_IMPLEMENTED}")
    return {
        "report_id": report_id,
        "period": period,
        "generated_at": clock.iso_micros(clock.as_utc(now or clock.utcnow())),
        "data": dict(data),
    }


def _period_runs(conn: psycopg.Connection, start: datetime, end: datetime,
                 tenant_id: str | None) -> list[Mapping[str, Any]]:
    """当期批次 + 各自的未结 / 待签核计数（口径只写一次）。"""
    clause = "r.cutoff_at >= %s AND r.cutoff_at < %s"
    params: list[Any] = [start, end]
    if tenant_id is not None:
        clause += " AND (r.tenant_id IS NULL OR r.tenant_id = %s)"
        params.append(tenant_id)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""SELECT r.run_id, r.scope, r.subject_ref, r.cutoff_at, r.status,
                       r.book_minor, r.external_minor, r.diff_minor, r.matched_count,
                       r.unmatched_count, r.metrics, r.signed_off_at, r.created_by,
                       r.signed_off_by,
                       (SELECT count(*) FROM reconciliation_exceptions e
                         WHERE e.run_id = r.run_id AND e.status <> 'closed') AS open_count,
                       (SELECT count(*) FROM reconciliation_exceptions e
                         WHERE e.run_id = r.run_id AND e.status <> 'closed'
                           AND e.severity IN ('P0', 'P1')) AS pending_p0_p1
                  FROM reconciliation_runs r
                 WHERE {clause}
                 ORDER BY r.cutoff_at, r.run_id""", params)
        return cur.fetchall()


def recon_daily(conn: psycopg.Connection, *, period: str, tenant_id: str | None = None,
                now: datetime | None = None) -> dict[str, Any]:
    """REP-01 日结三方对账报告（数据来自本轮 runs / exceptions）。"""
    moment = clock.as_utc(now or clock.utcnow())
    start, end = _month(period, "REP-01")
    rows = _period_runs(conn, start, end, tenant_id)
    if not rows:
        raise ReportUnavailable(f"期间 {period} 无对账批次：报表无数据（REP-01）",
                               reason="report_no_data", report_id="REP-01")

    days: dict[str, dict[str, Any]] = {}
    by_scope: dict[str, dict[str, Any]] = {}
    totals = {"runs": 0, "signed_off_runs": 0, "pending_sign_off_runs": 0,
              "book_minor": 0, "external_minor": 0, "diff_minor": 0,
              "open_exceptions": 0, "pending_p0_p1": 0}
    pending: list[dict[str, Any]] = []

    for row in rows:
        day = clock.day_of(row["cutoff_at"])
        bucket = days.setdefault(day, {"date": day, "runs": 0, "matched_runs": 0,
                                       "exception_runs": 0, "signed_off_runs": 0,
                                       "book_minor": 0, "external_minor": 0, "diff_minor": 0,
                                       "open_exceptions": 0, "pending_p0_p1": 0})
        scope_bucket = by_scope.setdefault(row["scope"], {"runs": 0, "open_exceptions": 0,
                                                          "pending_p0_p1": 0, "diff_minor": 0})
        for target in (bucket, totals):
            target["runs"] += 1
            target["book_minor"] += int(row["book_minor"])
            target["external_minor"] += int(row["external_minor"])
            target["diff_minor"] += int(row["diff_minor"])
            target["open_exceptions"] += int(row["open_count"])
            target["pending_p0_p1"] += int(row["pending_p0_p1"])
        scope_bucket["runs"] += 1
        scope_bucket["open_exceptions"] += int(row["open_count"])
        scope_bucket["pending_p0_p1"] += int(row["pending_p0_p1"])
        scope_bucket["diff_minor"] += int(row["diff_minor"])

        if row["status"] == facts.RUN_STATUS_MATCHED:
            bucket["matched_runs"] += 1
        if row["status"] == facts.RUN_STATUS_EXCEPTIONS_OPEN:
            bucket["exception_runs"] += 1
        if row["status"] in facts.RUN_SIGNOFF_READONLY:
            bucket["signed_off_runs"] += 1
            totals["signed_off_runs"] += 1
        else:
            totals["pending_sign_off_runs"] += 1
            if len(pending) < PENDING_SIGN_OFF_LIMIT:
                pending.append({
                    "run_id": str(row["run_id"]),
                    "scope": row["scope"],
                    "subject_ref": row["subject_ref"],
                    "cutoff_at": clock.iso_micros(row["cutoff_at"]),
                    "status": row["status"],
                    "pending_p0_p1": int(row["pending_p0_p1"]),
                    "diff_minor": int(row["diff_minor"]),
                })

    receipt_rates = [int((row["metrics"] or {}).get("diff_rate_bps") or 0)
                     for row in rows if row["scope"] == "receipt" and row["metrics"]]
    data = {
        "days": [days[key] for key in sorted(days)],
        "by_scope": by_scope,
        "totals": totals,
        "pending_sign_off": pending,
        "sign_off_pending_truncated": totals["pending_sign_off_runs"] > len(pending),
        # 03-facts §10 的 S1 指标：最近一次 receipt 批次的差异率（bps）
        "receipt_diff_rate_bps": receipt_rates[-1] if receipt_rates else None,
        "receipt_diff_rate_target_bps": facts.RECEIPT_DIFF_RATE_TARGET_BPS,
        # 本轮未实现的报表（不返回假数据，只声明缺口）
        "deferred_reports": facts.REPORTS_DEFERRED,
    }
    return envelope("REP-01", period, data, now=moment)


def _period_exceptions(conn: psycopg.Connection, start: datetime, end: datetime,
                       tenant_id: str | None) -> list[Mapping[str, Any]]:
    clause = "r.cutoff_at >= %s AND r.cutoff_at < %s"
    params: list[Any] = [start, end]
    if tenant_id is not None:
        clause += " AND (r.tenant_id IS NULL OR r.tenant_id = %s)"
        params.append(tenant_id)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""SELECT e.exception_id, e.run_id, e.scope, e.kind, e.severity, e.status,
                       e.diff_minor, e.owner, e.sla_due, e.created_at, e.closed_at
                  FROM reconciliation_exceptions e
                  JOIN reconciliation_runs r ON r.run_id = e.run_id
                 WHERE {clause}
                 ORDER BY e.created_at""", params)
        return cur.fetchall()


def exceptions_report(conn: psycopg.Connection, *, period: str,
                      tenant_id: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    """REP-02 差异台账与账龄（账龄桶按 M09 §8.2；未结 = status <> closed）。"""
    moment = clock.as_utc(now or clock.utcnow())
    start, end = _month(period, "REP-02")
    rows = _period_exceptions(conn, start, end, tenant_id)
    runs = _period_runs(conn, start, end, tenant_id)
    if not runs:
        raise ReportUnavailable(f"期间 {period} 无对账批次：报表无数据（REP-02）",
                               reason="report_no_data", report_id="REP-02")

    by_severity = {sev: {"open": 0, "closed": 0, "total": 0} for sev in facts.SEVERITIES}
    by_status = {status: 0 for status in facts.EXCEPTION_STATUSES}
    by_kind: dict[str, dict[str, int]] = {}
    aging = {label: {"bucket": label, "open": 0, "diff_minor": 0}
             for label in facts.AGE_BUCKET_LABELS}
    totals = {"exceptions": 0, "open": 0, "closed": 0, "overdue": 0,
              "open_diff_minor": 0, "pending_p0_p1": 0}

    for row in rows:
        closed = row["status"] == facts.EXCEPTION_CLOSED
        severity = row["severity"]
        by_severity[severity]["total"] += 1
        by_severity[severity]["closed" if closed else "open"] += 1
        by_status[row["status"]] += 1
        kind_bucket = by_kind.setdefault(row["kind"], {"open": 0, "closed": 0})
        kind_bucket["closed" if closed else "open"] += 1

        totals["exceptions"] += 1
        if closed:
            totals["closed"] += 1
            continue
        totals["open"] += 1
        totals["open_diff_minor"] += int(row["diff_minor"])
        if severity in ("P0", "P1"):
            totals["pending_p0_p1"] += 1
        if row["sla_due"] is not None and clock.as_utc(row["sla_due"]) < moment:
            totals["overdue"] += 1
        bucket = aging[grading.age_bucket(clock.as_utc(row["created_at"]), moment)]
        bucket["open"] += 1
        bucket["diff_minor"] += int(row["diff_minor"])

    data = {
        "by_severity": by_severity,
        "by_status": by_status,
        "by_kind": by_kind,
        "aging": [aging[label] for label in facts.AGE_BUCKET_LABELS],
        "totals": totals,
        "runs_in_period": len(runs),
    }
    return envelope("REP-02", period, data, now=moment)
