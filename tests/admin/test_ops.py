# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ops 只读面：七块健康总览 / 变更日历（只读视图 + audit_log 聚合，INV-01）。"""
from __future__ import annotations

from datetime import timedelta

from admin_kit import (
    FIXED_NOW,
    apply_migrations,
    build_client,
    connect,
    insert_audit,
    m14_migration_files,
    create_schema,
    drop_schema,
)
from app.data_gov import facts

HEALTH = "/api/v1/admin/ops/health"
CHANGES = "/api/v1/admin/ops/changes"


def _probe(status: str, **extra):
    def probe(connection, now):
        return {"status": status, **extra}

    return probe


# ─────────────────────────────────────────────────────── 权限
def test_ops_reads_require_authentication_and_admin(unauth_client, nonadmin_client) -> None:
    assert unauth_client.get(HEALTH).status_code == 401
    assert unauth_client.get(CHANGES).status_code == 401
    assert nonadmin_client.get(HEALTH).status_code == 403
    assert nonadmin_client.get(CHANGES).status_code == 403


def test_readonly_auditor_can_read_health(readonly_client) -> None:
    response = readonly_client.get(HEALTH)
    assert response.status_code == 200
    assert response.json()["block_count"] == 7


# ─────────────────────────────────────────────────────── 健康总览
def test_health_default_probes_are_honest(client) -> None:
    response = client.get(HEALTH)
    assert response.status_code == 200
    payload = response.json()
    assert payload["block_count"] == 7
    assert [block["block"] for block in payload["data"]] == list(facts.HEALTH_BLOCKS)
    blocks = {block["block"]: block for block in payload["data"]}
    # 已接只读视图的块：wallet 空链上交易 → green；recon / ledger 无数据 → yellow（不假装健康）
    assert blocks["wallet"]["status"] == "green"
    assert blocks["recon"]["status"] == "yellow"
    assert blocks["recon"]["reason"] == "no_recon_run"
    assert blocks["ledger"]["status"] == "yellow"
    assert blocks["ledger"]["reason"] == "no_balance_snapshot"
    # 未接线块 → yellow + probe_not_wired
    for name in ("gateway", "scheduling", "config", "notification"):
        assert blocks[name]["status"] == "yellow"
        assert blocks[name]["reason"] == "probe_not_wired"
    assert payload["overall"] == "yellow"
    assert payload["observed_at"]
    assert "last_change" not in blocks["gateway"]


def test_health_with_injected_probes_and_metrics(savepoint_conn) -> None:
    probes = {name: _probe("green") for name in facts.HEALTH_BLOCKS}
    probes["ledger"] = _probe("red", reason="recompute_diff",
                              detail="账本复算差异非 0", metrics={"diff": 12})
    probes["config"] = _probe("yellow", reason="drift", metrics={"drifts": 1})
    with build_client(savepoint_conn, health_probes=probes) as client:
        payload = client.get(HEALTH).json()
    blocks = {block["block"]: block for block in payload["data"]}
    assert payload["overall"] == "red"
    assert blocks["ledger"]["status"] == "red"
    assert blocks["ledger"]["metrics"] == {"diff": 12}
    assert blocks["config"]["status"] == "yellow"
    assert blocks["gateway"]["status"] == "green"


def test_health_probe_error_degrades_to_yellow(savepoint_conn) -> None:
    def boom(connection, now):
        raise RuntimeError("probe down")

    probes = {name: _probe("green") for name in facts.HEALTH_BLOCKS}
    probes["gateway"] = boom
    probes["scheduling"] = lambda connection, now: {"status": "purple"}
    with build_client(savepoint_conn, health_probes=probes) as client:
        payload = client.get(HEALTH).json()
    blocks = {block["block"]: block for block in payload["data"]}
    assert blocks["gateway"]["status"] == "yellow"
    assert blocks["gateway"]["reason"] == "probe_error"
    assert blocks["scheduling"]["reason"] == "unavailable"
    assert payload["overall"] == "yellow"


def test_health_attaches_last_change_from_audit_log(savepoint_conn, client) -> None:
    insert_audit(savepoint_conn, action="config.publish", actor="release-manager",
                 ts=FIXED_NOW)
    insert_audit(savepoint_conn, action="gateway.restarted", actor="sre",
                 ts=FIXED_NOW + timedelta(minutes=1))
    payload = client.get(HEALTH).json()
    blocks = {block["block"]: block for block in payload["data"]}
    assert blocks["config"]["last_change"]["action"] == "config.publish"
    assert blocks["config"]["last_change"]["actor"] == "release-manager"
    assert blocks["gateway"]["last_change"]["action"] == "gateway.restarted"
    assert "last_change" not in blocks["recon"]


# ─────────────────────────────────────────────────────── 变更日历
def test_changes_projects_audit_entries(savepoint_conn, client) -> None:
    insert_audit(savepoint_conn, action="deploy.started", actor="sre",
                 target="svc/gateway", ts=FIXED_NOW,
                 after={"window_start": "2026-10-24T02:00:00Z",
                        "window_end": "2026-10-24T04:00:00Z",
                        "rollback_plan": "回滚到上一镜像", "impact_scope": "gateway"})
    insert_audit(savepoint_conn, action="deploy.completed", actor="sre",
                 ts=FIXED_NOW + timedelta(minutes=10), ticket="CHG-1")
    insert_audit(savepoint_conn, action="config.publish", actor="release-manager",
                 target="config/gateway.rate_limit", ts=FIXED_NOW + timedelta(minutes=1))
    insert_audit(savepoint_conn, action="backup.completed", actor="sre",
                 ts=FIXED_NOW + timedelta(minutes=2))
    insert_audit(savepoint_conn, action="account.frozen", actor="risk",
                 ts=FIXED_NOW + timedelta(minutes=3))
    response = client.get(CHANGES)
    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == {"audit_log": "ok"}
    assert payload["observed_at"]
    entries = payload["data"]
    assert len(entries) == 4                                   # account.frozen 不入变更日历
    assert [entry["kind"] for entry in entries] == [
        "deploy", "backup", "config_publish", "deploy"]
    started = entries[-1]
    assert started["status"] == "in_progress"
    assert started["window"] == {"start": "2026-10-24T02:00:00.000Z",
                                 "end": "2026-10-24T04:00:00.000Z"}
    assert started["rollback_plan"] == "回滚到上一镜像"
    assert started["impact_scope"] == "gateway"
    completed = entries[0]
    assert completed["status"] == "completed" and completed["ticket"] == "CHG-1"
    publish = entries[2]
    assert publish["kind"] == "config_publish"
    assert publish["rollback_plan"].startswith("未登记")
    assert publish["impact_scope"] == "config/gateway.rate_limit"


def test_changes_pagination_and_window_filter(savepoint_conn, client) -> None:
    for index in range(3):
        insert_audit(savepoint_conn, action="upgrade.completed", actor="release",
                     ts=FIXED_NOW + timedelta(minutes=index))
    first = client.get(CHANGES, params={"limit": 2}).json()
    assert len(first["data"]) == 2 and first["page"]["has_more"] is True
    second = client.get(CHANGES, params={"limit": 2,
                                         "cursor": first["page"]["next_cursor"]}).json()
    assert len(second["data"]) == 1 and second["page"]["has_more"] is False
    windowed = client.get(CHANGES, params={
        "from": "2026-10-24T03:01:30Z", "to": "2026-10-24T03:02:30Z"}).json()
    assert len(windowed["data"]) == 1
    assert client.get(CHANGES, params={"from": "not-a-time"}).status_code == 400


def test_audit_log_absent_degrades_gracefully(db, schema_prefix) -> None:
    name = f"{schema_prefix}_noaudit"
    create_schema(name)
    try:
        apply_migrations(name, m14_migration_files())
        connection = connect(name, autocommit=False)
        try:
            with build_client(connection) as client:
                health = client.get(HEALTH).json()
                changes = client.get(CHANGES).json()
        finally:
            connection.close()
    finally:
        drop_schema(name)
    assert health["block_count"] == 7
    assert health["overall"] == "yellow"
    for block in health["data"]:
        assert "last_change" not in block
        assert block["status"] == "yellow"                      # 视图未接线 → 不假装健康
    assert changes["data"] == []
    assert changes["source"] == {"audit_log": "unavailable"}
