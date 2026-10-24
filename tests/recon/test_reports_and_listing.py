# SPDX-License-Identifier: AGPL-3.0-or-later
"""批次列表 / 详情 / 报表（REP-01 / REP-02）+ 未实现报表不注册路由。"""
from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal

import pytest

from app.recon import engine, facts, models
from reconkit import (FIXED_NOW, fetch_exceptions, post_journal, receipt_spec, seed_receipt,
                      seed_usage, simple_journal_lines)

RUNS = "/api/v1/admin/treasury/recon/runs"
REP_01 = "/api/v1/admin/reports/recon-daily"
REP_02 = "/api/v1/admin/reports/exceptions"


def _receipt_run(conn, *, amount: int = 100, price: int = 100, task: str = "task-r",
                 cutoff=FIXED_NOW, tenant_id: str | None = None) -> dict:
    seed_usage(conn, task_id=task, amount_minor=amount, recorded_at=cutoff - timedelta(hours=2))
    seed_receipt(conn, task_id=task, price_minor=price, receipt_id=f"rcpt-{task}",
                 reported_at=cutoff - timedelta(hours=1))
    spec = models.RunSpec(scope="receipt", subject_ref="m05",
                          period_start=cutoff - timedelta(days=1), period_end=cutoff,
                          cutoff_at=cutoff, tenant_id=tenant_id)
    return engine.run(conn, spec, now=cutoff)[0]["run"]


# ───────────────────────────────────────────────────────────── 批次列表 / 详情
def test_list_runs_orders_by_cutoff_desc_and_pages(client, savepoint_conn) -> None:
    for index in range(3):
        _receipt_run(savepoint_conn, task=f"task-list-{index}",
                     cutoff=FIXED_NOW - timedelta(hours=index))
    first = client.get(RUNS, params={"limit": 2}).json()
    assert len(first["data"]) == 2
    assert first["page"]["has_more"] is True
    assert first["data"][0]["cutoff_at"] > first["data"][1]["cutoff_at"]

    second = client.get(RUNS, params={"limit": 2, "cursor": first["page"]["next_cursor"]}).json()
    assert len(second["data"]) == 1
    assert second["page"]["has_more"] is False
    assert second["page"]["next_cursor"] is None

    everything = client.get(RUNS).json()["data"]
    assert len(everything) == 3
    required = {"run_id", "scope", "period_start", "period_end", "cutoff_at", "status",
                "diff_minor"}
    assert required <= set(everything[0])


def test_list_runs_filters(client, savepoint_conn) -> None:
    _receipt_run(savepoint_conn, task="task-f1")
    post_journal(savepoint_conn, simple_journal_lines(1_000), ts=FIXED_NOW - timedelta(hours=1))
    engine.run(savepoint_conn, models.RunSpec(
        scope="daily_close", period_start=FIXED_NOW - timedelta(days=1), period_end=FIXED_NOW,
        cutoff_at=FIXED_NOW), now=FIXED_NOW)

    receipt_only = client.get(RUNS, params={"scope": "receipt"}).json()["data"]
    assert {item["scope"] for item in receipt_only} == {"receipt"}
    closed = client.get(RUNS, params={"status": "closed"}).json()["data"]
    assert closed == []
    assert client.get(RUNS, params={"scope": "bogus"}).status_code == 400
    assert client.get(RUNS, params={"status": "bogus"}).status_code == 400
    assert client.get(RUNS, params={"limit": 0}).status_code == 400
    assert client.get(RUNS, params={"limit": 201}).status_code == 400
    assert client.get(RUNS, params={"from": "nope"}).status_code == 400


def test_run_detail_returns_diff_summary(client, savepoint_conn) -> None:
    seed_usage(savepoint_conn, task_id="task-detail", amount_minor=50_000,
               recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(savepoint_conn, task_id="task-detail", price_minor=0,
                 receipt_id="rcpt-detail", reported_at=FIXED_NOW - timedelta(hours=1))
    run = engine.run(savepoint_conn, receipt_spec(), now=FIXED_NOW)[0]["run"]

    response = client.get(f"{RUNS}/{run['run_id']}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["run"]["run_id"] == str(run["run_id"])
    summary = payload["diff_summary"]
    assert summary["pending_p0_p1"] == 1
    assert summary["by_severity"]["P1"] == 1
    assert summary["by_status"]["open"] == 1
    assert summary["by_status"]["closed"] == 0


def test_run_detail_not_found_and_cross_tenant(client, savepoint_conn) -> None:
    unknown = "00000000-0000-7000-8000-000000000002"
    response = client.get(f"{RUNS}/{unknown}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 49201
    assert client.get(f"{RUNS}/not-a-uuid").json()["error"]["code"] == 49201

    hidden = _receipt_run(savepoint_conn, task="task-hidden", tenant_id="tenant-z")
    assert client.get(f"{RUNS}/{hidden['run_id']}").status_code == 404


# ───────────────────────────────────────────────────────────── REP-01
def test_recon_daily_report_reports_from_runs(client, savepoint_conn) -> None:
    seed_usage(savepoint_conn, task_id="task-rep1", amount_minor=100,
               recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(savepoint_conn, task_id="task-rep1", price_minor=97,
                 receipt_id="rcpt-rep1", reported_at=FIXED_NOW - timedelta(hours=1))
    engine.run(savepoint_conn, receipt_spec(), now=FIXED_NOW)

    response = client.get(REP_01, params={"period": "2026-10"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["report_id"] == "REP-01"
    assert payload["period"] == "2026-10"
    assert payload["generated_at"].endswith("Z")
    data = payload["data"]
    assert data["totals"]["runs"] == 1
    assert data["totals"]["book_minor"] == 100
    assert data["totals"]["external_minor"] == 97
    assert data["totals"]["diff_minor"] == 3
    assert data["totals"]["open_exceptions"] == 1
    assert data["totals"]["pending_p0_p1"] == 0
    assert data["by_scope"]["receipt"]["runs"] == 1
    assert data["days"][0]["date"] == "2026-10-23"
    assert data["receipt_diff_rate_bps"] == 5000
    assert data["pending_sign_off"][0]["run_id"]
    assert set(data["deferred_reports"]) == {"REP-03", "REP-04", "REP-06"}


def test_recon_daily_without_data_is_49210(client) -> None:
    response = client.get(REP_01, params={"period": "2025-01"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 49210
    invalid = client.get(REP_01, params={"period": "2026-13"})
    assert invalid.status_code == 404
    assert invalid.json()["error"]["code"] == 49210
    assert client.get(REP_01).status_code == 400          # 缺必填参数是请求错误


# ───────────────────────────────────────────────────────────── REP-02
def test_exception_report_aggregates(client, savepoint_conn) -> None:
    seed_usage(savepoint_conn, task_id="task-rep2", amount_minor=50_000,
               recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(savepoint_conn, task_id="task-rep2", price_minor=0,
                 receipt_id="rcpt-rep2", reported_at=FIXED_NOW - timedelta(hours=1))
    run = engine.run(savepoint_conn, receipt_spec(), now=FIXED_NOW)[0]["run"]

    # 造一条 10 天前开启的未结差异（账龄桶 7-30；created_at 不可改 → 直接插行造数）
    with savepoint_conn.cursor() as cur:
        cur.execute(
            """INSERT INTO reconciliation_exceptions
                 (exception_id, run_id, scope, kind, severity, ref_type, ref_id, diff_minor,
                  sla_due, status, created_at, updated_at)
               VALUES (%s,%s,'receipt','amount_mismatch','P2','task','task-old',7,%s,'open',%s,%s)""",
            (str(uuid.uuid4()), str(run["run_id"]), FIXED_NOW - timedelta(days=20),
             FIXED_NOW - timedelta(days=10), FIXED_NOW - timedelta(days=10)))

    response = client.get(REP_02, params={"period": "2026-10"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["report_id"] == "REP-02"
    data = payload["data"]
    assert data["totals"]["exceptions"] == 2
    assert data["totals"]["open"] == 2
    assert data["totals"]["closed"] == 0
    assert data["totals"]["pending_p0_p1"] == 1          # 那条 P1
    assert data["by_severity"]["P1"]["open"] == 1
    assert data["by_severity"]["P2"]["open"] == 1
    assert data["by_status"]["open"] == 2
    assert data["by_kind"]["amount_mismatch"]["open"] == 2
    aging = {bucket["bucket"]: bucket for bucket in data["aging"]}
    assert aging["0-1"]["open"] == 1
    assert aging["7-30"]["open"] == 1
    assert data["totals"]["overdue"] == 1                # 20 天前到期的那条
    assert data["runs_in_period"] == 1
    assert [bucket["bucket"] for bucket in data["aging"]] == list(facts.AGE_BUCKET_LABELS)


def test_exception_report_without_runs_is_49210(client) -> None:
    response = client.get(REP_02, params={"period": "2025-02"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 49210


# ───────────────────────────────────────────────────────────── 未实现的报表
@pytest.mark.parametrize("path", ["/api/v1/admin/reports/por",
                                  "/api/v1/admin/reports/wallet-pool",
                                  "/api/v1/admin/reports/monthly",
                                  "/api/v1/admin/reports/REP-01/renders/2026-10.svg"])
def test_deferred_reports_are_not_routed(client, path: str) -> None:
    """T4 未实现 → 不注册路由（404），绝不返回空壳 / 假数据。"""
    response = client.get(path, params={"period": "2026-10"})
    assert response.status_code == 404
    assert "detail" in response.json()                   # FastAPI 默认 404，不是我们的信封
    assert facts.REPORTS_DEFERRED and facts.REPORTS_IMPLEMENTED == ("REP-01", "REP-02")


def test_cross_tenant_reports_exclude_other_tenants(savepoint_conn) -> None:
    from reconkit import build_client

    # INV-04 唯一键不含 tenant（§3.3 原文如此）→ 两个租户共用同一 cutoff 会撞键，
    # 造数时错开 cutoff；隔离性验证不受影响。
    _receipt_run(savepoint_conn, task="task-ta", tenant_id="tenant-a")
    _receipt_run(savepoint_conn, task="task-tb", tenant_id="tenant-b",
                 cutoff=FIXED_NOW - timedelta(hours=1))
    tenant_b = {"admin_id": "admin-b", "tenant_id": "tenant-b",
                "scopes": ["recon.read", "recon.write"]}
    with build_client(savepoint_conn, admin=tenant_b) as client_b:
        data = client_b.get(REP_01, params={"period": "2026-10"}).json()["data"]
    assert data["totals"]["runs"] == 1
    assert data["by_scope"]["receipt"]["runs"] == 1


def test_daily_close_runs_appear_in_report(client, savepoint_conn) -> None:
    post_journal(savepoint_conn, simple_journal_lines(1_234), ts=FIXED_NOW - timedelta(hours=1))
    engine.run(savepoint_conn, models.RunSpec(
        scope="daily_close", period_start=FIXED_NOW - timedelta(days=1), period_end=FIXED_NOW,
        cutoff_at=FIXED_NOW), now=FIXED_NOW)
    data = client.get(REP_01, params={"period": "2026-10"}).json()["data"]
    assert data["by_scope"]["daily_close"]["runs"] == 1
    assert data["totals"]["book_minor"] == Decimal(1_234).to_integral_value()
    assert data["totals"]["diff_minor"] == 0
