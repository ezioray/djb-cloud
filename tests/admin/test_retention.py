# SPDX-License-Identifier: AGPL-3.0-or-later
"""保留任务：矩阵 / dry-run / 删除报告 / (object, cutoff) 幂等 / 失败重放 / 30 天 SLA。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from admin_kit import (
    FIXED_NOW,
    FakeRetentionExecutor,
    build_client,
    idempotency_key,
    make_retention,
    outbox_rows,
    write_headers,
)
from app.data_gov import clock, errors, ids, retention, store

BASE = "/api/v1/admin/data/retention-jobs"


def _body(*, object_name: str = "logs", policy_days=None, dry_run: bool = True,
          reason=None, cutoff=None) -> dict:
    body: dict = {"object": object_name, "dry_run": dry_run}
    if policy_days is not None:
        body["policy_days"] = policy_days
    if reason is not None:
        body["reason"] = reason
    if cutoff is not None:
        body["cutoff"] = cutoff
    return body


def _create(client, *, key: str, **kwargs):
    return client.post(BASE, json=_body(**kwargs), headers=write_headers(key))


# ─────────────────────────────────────────────────────── 权限 / step-up / 幂等
def test_retention_requires_authentication(unauth_client) -> None:
    assert unauth_client.get(BASE).status_code == 401
    response = unauth_client.post(BASE, json=_body(), headers=write_headers("u"))
    assert response.status_code == 401


def test_retention_rejects_non_admin(nonadmin_client) -> None:
    assert nonadmin_client.get(BASE).status_code == 403
    response = nonadmin_client.post(BASE, json=_body(), headers=write_headers("na"))
    assert response.status_code == 403


def test_retention_requires_step_up_and_idempotency(no_stepup_client, client) -> None:
    response = no_stepup_client.post(BASE, json=_body(), headers=write_headers("rt-ns"))
    assert response.status_code == 424
    response = client.post(BASE, json=_body(),
                           headers={"X-Admin-Step-Up": "step-up-token"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


# ─────────────────────────────────────────────────────── dry-run
def test_dry_run_uses_executor_and_keeps_report(savepoint_conn) -> None:
    executor = FakeRetentionExecutor()
    with build_client(savepoint_conn, retention_executor=executor) as test_client:
        response = _create(test_client, key="dry-run", object_name="logs",
                           policy_days=30, reason="季度清理")
    assert response.status_code == 201
    payload = response.json()
    assert payload["state"] == "done" and payload["dry_run"] is True
    assert payload["deleted_count"] == 0
    report = payload["report"]
    assert report["dry_run"] is True
    assert report["candidates"] == 12 and report["would_delete"] == 12
    assert report["method"] == "owner_api"
    assert report["retained"][0]["reason"] == "legal_hold"
    assert report["latest_clear_dates"]["backups"] == "2026-11-28"
    assert report["sampling"]["after_days"] == 40
    assert executor.calls and executor.calls[0][2] is True
    assert outbox_rows(savepoint_conn) == []                   # dry-run 不发执行事件


def test_dry_run_without_executor_reports_unknown(client) -> None:
    response = _create(client, key="dry-unwired", object_name="analytics")
    assert response.status_code == 201
    payload = response.json()
    assert payload["state"] == "done"
    assert payload["report"]["candidates"] is None
    assert payload["report"]["method"] == "unwired"
    assert "note" in payload["report"]


# ─────────────────────────────────────────────────────── 真实执行 / 事件 / 失败
def test_real_run_emits_retention_executed(savepoint_conn) -> None:
    executor = FakeRetentionExecutor()
    with build_client(savepoint_conn, retention_executor=executor) as test_client:
        response = _create(test_client, key="real-run", object_name="backups",
                           policy_days=35, dry_run=False)
    assert response.status_code == 201
    payload = response.json()
    assert payload["state"] == "done"
    assert payload["deleted_count"] == 10 and payload["retained_count"] == 2
    assert payload["report"]["retained_count"] == 2
    assert payload["sla"]["window_days"] == 30 and payload["sla"]["sampling_days"] == 40
    rows = outbox_rows(savepoint_conn)
    assert [row["type"] for row in rows] == ["retention.executed"]
    assert rows[0]["payload"]["deleted_count"] == 10
    assert executor.calls[0][2] is False


def test_real_run_without_executor_fails_closed(client, savepoint_conn) -> None:
    response = _create(client, key="real-unwired", object_name="usage",
                       policy_days=720, dry_run=False)
    assert response.status_code == 201
    payload = response.json()
    assert payload["state"] == "failed"
    assert payload["failure_reason"] == "owner_executor_unavailable"
    assert outbox_rows(savepoint_conn) == []


def test_executor_error_marks_failed_then_replay(savepoint_conn, sink) -> None:
    broken = FakeRetentionExecutor(error=RuntimeError("owner down"))
    with build_client(savepoint_conn, retention_executor=broken, audit_sink=sink) as client:
        response = _create(client, key="broken", object_name="tickets", policy_days=720,
                           dry_run=False)
    assert response.json()["state"] == "failed"
    assert response.json()["failure_reason"] == "owner_executor_error"
    job_id = response.json()["job_id"]
    healthy = FakeRetentionExecutor()
    replayed = retention.replay_job(savepoint_conn, job_id, now=FIXED_NOW,
                                    audit_sink=sink, executor=healthy)
    assert replayed["state"] == "done"
    assert replayed["replay_count"] == 1
    assert "retention.job.replayed" in sink.actions()
    assert "retention.job.completed" in sink.actions()


# ─────────────────────────────────────────────────────── 幂等 / 唯一键
def test_idempotent_same_key_returns_same_job(client) -> None:
    first = _create(client, key="idem-ret", object_name="logs", policy_days=30)
    second = _create(client, key="idem-ret", object_name="logs", policy_days=30)
    assert first.status_code == second.status_code == 201
    assert first.json()["job_id"] == second.json()["job_id"]


def test_same_object_cutoff_executes_once(savepoint_conn, client) -> None:
    cutoff = clock.start_of_utc_day(FIXED_NOW - timedelta(days=30))
    make_retention(savepoint_conn, state="done", object_name="logs", policy_days=30,
                   cutoff=cutoff)
    response = _create(client, key="dup-cutoff", object_name="logs", policy_days=30,
                       dry_run=False)
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "retention_already_executed"


def test_dry_run_reuses_same_cutoff_preview(client) -> None:
    first = _create(client, key="dry-a", object_name="backups", policy_days=35)
    second = _create(client, key="dry-b", object_name="backups", policy_days=35)
    assert first.json()["job_id"] == second.json()["job_id"]


def test_idempotency_key_reuse_conflicts(client) -> None:
    assert _create(client, key="ret-diff", object_name="logs", policy_days=30).status_code == 201
    response = _create(client, key="ret-diff", object_name="logs", policy_days=31)
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "idempotency_key_reused"


# ─────────────────────────────────────────────────────── cutoff / 矩阵
def test_default_retention_matrix(client) -> None:
    expected = {"usage": 720, "receipts": 720, "tickets": 720, "logs": 30,
                "backups": 35, "analytics": 420}
    for object_name, days in expected.items():
        response = _create(client, key=f"matrix-{object_name}", object_name=object_name)
        assert response.status_code == 201, response.text
        payload = response.json()
        assert payload["policy_days"] == days
        assert payload["cutoff"].endswith("T00:00:00.000Z")


def test_explicit_cutoff_derives_policy_days(client) -> None:
    response = _create(client, key="explicit-cutoff", object_name="logs",
                       cutoff="2026-09-01T00:00:00Z")
    assert response.status_code == 201
    payload = response.json()
    assert payload["cutoff"].startswith("2026-09-01T00:00:00")
    assert payload["policy_days"] == (FIXED_NOW - clock.parse_datetime(
        "2026-09-01T00:00:00Z")).days


def test_cutoff_policy_days_mismatch_is_400(client) -> None:
    response = _create(client, key="mismatch", object_name="logs", policy_days=30,
                       cutoff="2026-09-01T00:00:00Z")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == 40001


def test_invalid_retention_body(client) -> None:
    assert client.post(BASE, json={"object": "unknown", "dry_run": True},
                       headers=write_headers("bad-obj")).status_code == 400
    assert client.post(BASE, json={"object": "logs", "policy_days": 0},
                       headers=write_headers("bad-days")).status_code == 400
    assert client.post(BASE, json={"object": "logs", "reason": "x", "extra": 1},
                       headers=write_headers("bad-extra")).status_code == 400


# ─────────────────────────────────────────────────────── 列表 / SLA
def test_retention_list_filters_and_pagination(client) -> None:
    for index, object_name in enumerate(("logs", "backups", "tickets")):
        assert _create(client, key=f"list-{index}", object_name=object_name).status_code == 201
    page = client.get(BASE, params={"limit": 2}).json()
    assert len(page["data"]) == 2 and page["page"]["has_more"] is True
    second = client.get(BASE, params={"limit": 2,
                                      "cursor": page["page"]["next_cursor"]}).json()
    assert len(second["data"]) == 1 and second["page"]["has_more"] is False
    by_object = client.get(BASE, params={"object": "logs"}).json()["data"]
    assert len(by_object) == 1 and by_object[0]["object"] == "logs"
    done = client.get(BASE, params={"state": "done"}).json()["data"]
    assert len(done) == 3
    dry = client.get(BASE, params={"dry_run": "true"}).json()["data"]
    assert len(dry) == 3
    assert client.get(BASE, params={"dry_run": "maybe"}).status_code == 400


def test_sla_fields_and_overdue(savepoint_conn, client) -> None:
    response = _create(client, key="sla", object_name="logs")
    payment = response.json()
    assert payment["sla"]["overdue"] is False
    due = clock.parse_datetime(payment["sla"]["due_at"])
    created = clock.parse_datetime(payment["created_at"])
    assert due == created + timedelta(days=30)
    job_id = store.insert_retention(
        savepoint_conn, job_id=str(ids.uuid7()), job_no="RET-OVERDUE-1", object_name="logs",
        policy_days=30, cutoff=FIXED_NOW - timedelta(days=60), dry_run=True,
        report_ref="report://retention/jobs/overdue", requested_by="ops-admin",
        idempotency_key=None, sla_due_at=FIXED_NOW - timedelta(days=10),
        created_at=FIXED_NOW - timedelta(days=5))["job_id"]
    listed = client.get(BASE, params={"object": "logs"}).json()["data"]
    overdue = [row for row in listed if row["job_id"] == str(job_id)]
    assert overdue and overdue[0]["sla"]["overdue"] is True


def test_replay_only_failed_jobs(savepoint_conn) -> None:
    row = make_retention(savepoint_conn, state="done")
    with pytest.raises(errors.Conflict):
        retention.replay_job(savepoint_conn, str(row["job_id"]), now=FIXED_NOW)


def test_get_job_unknown_raises_not_found(savepoint_conn) -> None:
    import uuid

    with pytest.raises(errors.NotFound):
        retention.get_job(savepoint_conn, str(uuid.uuid4()))
