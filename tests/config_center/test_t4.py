# SPDX-License-Identifier: AGPL-3.0-or-later
"""T4：回滚 / kill switch / 快照 / 漂移 / 事件派发（需要 DJB_DSN）。

时间基线：``NOW = 2026-10-21T02:30Z`` = 周三 10:30（UTC+8）。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from psycopg.types.json import Jsonb

from app.config_center import canonical, dispatcher, drift, outbox, publish, registry, snapshot, store
from app.config_center.errors import (
    DangerousKeyForbidden,
    IdempotencyConflict,
    StateConflict,
    ValidationFailed,
    VersionNotFound,
)
from configkit import assert_db_error, new_idempotency_key

REG = registry.load()
NOW = datetime(2026, 10, 21, 2, 30, tzinfo=timezone.utc)          # 周三 10:30 CST
LATER = NOW + timedelta(hours=25)                                  # 周四 11:30 CST


def who(actor="u1", roles=("FIN",), *, now=NOW, step_up=True, ref=None):
    return publish.Principal(
        actor, frozenset(roles),
        step_up_at=now - timedelta(minutes=1) if step_up else None,
        step_up_ref=(ref or f"step-{uuid.uuid4().hex[:8]}") if step_up else None)


def draft(conn, *, key="billing.service_fee_bps", value=1500, actor="u1", **kwargs):
    return store.create_draft(conn, key=key, value=value, reason="T4 测试草稿",
                              actor=actor, **kwargs)


def request(conn, *, key, version, roles=("FIN",), now=NOW, step_up=True, **kwargs):
    return publish.create_request(conn, key=key, version=version,
                                  principal=who("u1", roles, now=now, step_up=step_up),
                                  reason="T4 测试发布", now=now, **kwargs)


def activate(conn, *, key, version, roles=("FIN",), now=NOW, approver_roles=("FIN",)):
    req = request(conn, key=key, version=version, roles=roles, now=now)
    publish.approve_request(conn, req["publish_request_id"],
                            principal=who("u2", approver_roles, now=now),
                            decision="approve", reason="T4 复核通过", now=now)
    return publish.activate_request(conn, req["publish_request_id"], now=now)


# ─────────────────────────────────────────────── 回滚（INV-09）
def test_rollback_creates_new_version_and_rolled_back_event(conn):
    v1 = draft(conn, value=1500)
    activate(conn, key="billing.service_fee_bps", version=v1["version"])
    v2 = draft(conn, value=1600)
    activate(conn, key="billing.service_fee_bps", version=v2["version"], now=LATER)

    # 回滚到 v1：生成 v3（内容 = v1，rollback_to=1）；不受冷却与发布窗口限制
    req = publish.rollback(conn, key="billing.service_fee_bps", target_version=1,
                           principal=who("u1", now=LATER), reason="费率回滚到基线", now=LATER)
    assert req["status"] == "pending_approval"
    assert req["rollback_target_version"] == 1
    assert req["rollback_to"] == 1 and req["new_version"] == 3
    new_row = store.get_version(conn, key="billing.service_fee_bps", version=3)
    assert new_row["value"] == 1500 and new_row["rollback_to"] == 1
    assert new_row["content_digest"] == store.get_version(
        conn, key="billing.service_fee_bps", version=1)["content_digest"]   # 内容寻址

    rollback_approve_at = datetime(2026, 10, 22, 14, 30, tzinfo=timezone.utc)
    publish.approve_request(conn, req["publish_request_id"],
                            principal=who("u2", now=rollback_approve_at), decision="approve",
                            reason="回滚复核", now=rollback_approve_at)
    result = publish.activate_request(
        conn, req["publish_request_id"],
        now=rollback_approve_at)   # 22:30 CST：回滚免窗口
    assert result["version"]["status"] == "active"
    assert result["version"]["rollback_to"] == 1
    statuses = dict(conn.execute(
        "SELECT version, status FROM config_versions WHERE key = %s ORDER BY version",
        ("billing.service_fee_bps",)).fetchall())
    assert statuses == {1: "superseded", 2: "superseded", 3: "active"}

    events = conn.execute("SELECT type, payload FROM config_outbox ORDER BY created_at").fetchall()
    assert [row[0] for row in events] == ["config.published", "config.published",
                                          "config.rolled_back"]
    payload = events[-1][1]
    assert payload["rollback_to"] == 1 and payload["reason_code"] == "manual_rollback"
    assert payload["version"] == 3 and payload["snapshot_digest"] == result["snapshot_digest"]


def test_rollback_target_validation(conn):
    v1 = draft(conn, value=1500)
    activate(conn, key="billing.service_fee_bps", version=v1["version"])
    with pytest.raises(VersionNotFound):
        publish.rollback(conn, key="billing.service_fee_bps", target_version=99,
                         principal=who("u1", now=LATER), reason="目标不存在", now=LATER)
    with pytest.raises(StateConflict):
        publish.rollback(conn, key="billing.service_fee_bps", target_version=1,
                         principal=who("u1", now=LATER), reason="目标就是当前版本", now=LATER)
    draft(conn, value=1600)                                   # v2 draft：不可作为回滚目标
    with pytest.raises(StateConflict):
        publish.rollback(conn, key="billing.service_fee_bps", target_version=2,
                         principal=who("u1", now=LATER), reason="草稿不可回滚", now=LATER)


def test_rollback_idempotency(conn):
    v1 = draft(conn, value=1500)
    activate(conn, key="billing.service_fee_bps", version=v1["version"])
    v2 = draft(conn, value=1600)
    activate(conn, key="billing.service_fee_bps", version=v2["version"], now=LATER)
    idem = new_idempotency_key()
    first = publish.rollback(conn, key="billing.service_fee_bps", target_version=1,
                             principal=who("u1", now=LATER), reason="回滚到基线", now=LATER,
                             idempotency_key=idem)
    replay = publish.rollback(conn, key="billing.service_fee_bps", target_version=1,
                              principal=who("u1", now=LATER), reason="回滚到基线", now=LATER,
                              idempotency_key=idem)
    assert replay["replayed"] is True
    assert replay["publish_request_id"] == first["publish_request_id"]
    with pytest.raises(IdempotencyConflict):
        publish.rollback(conn, key="billing.service_fee_bps", target_version=2,
                         principal=who("u1", now=LATER), reason="不同目标", now=LATER,
                         idempotency_key=idem)


# ─────────────────────────────────────────────── kill switch
def test_kill_switch_creates_emergency_version(conn):
    v1 = draft(conn, value=1500)
    activate(conn, key="billing.service_fee_bps", version=v1["version"])
    result = publish.kill_switch(conn, key="billing.service_fee_bps", value=1400,
                                 ttl_seconds=600, principal=who("u1", step_up=False),
                                 reason="事故止损", now=NOW + timedelta(minutes=10))
    version = result["version"]
    assert version["status"] == "active"
    assert version["emergency"] is True
    assert version["kill_switch_ttl_s"] == 600
    assert version["kill_switch_prev_version"] == 1
    assert version["published_by"] == "u1"
    assert version["approved_by"] is None                     # 单人可发（INV-03 豁免）
    event = conn.execute(
        "SELECT payload FROM config_outbox WHERE payload ? 'emergency'").fetchone()[0]
    assert event["emergency"] is True and event["version"] == 2


def test_kill_switch_only_tighten(conn):
    v1 = draft(conn, value=1500)
    activate(conn, key="billing.service_fee_bps", version=v1["version"])
    # 放宽：1600 > 1500 → 47004
    with pytest.raises(DangerousKeyForbidden):
        publish.kill_switch(conn, key="billing.service_fee_bps", value=1600, ttl_seconds=60,
                            principal=who("u1", step_up=False), reason="借开关放宽", now=NOW)
    with pytest.raises(DangerousKeyForbidden):
        publish.kill_switch(conn, key="billing.service_fee_bps", value=1500, ttl_seconds=60,
                            principal=who("u1", step_up=False), reason="没有收紧", now=NOW)
    # 非 kill-switch 键
    with pytest.raises(DangerousKeyForbidden):
        publish.kill_switch(conn, key="notify.report.daily_send_at", value="00:00",
                            ttl_seconds=60, principal=who("u1", ("OPS",), step_up=False),
                            reason="不可急停", now=NOW)
    for ttl in (0, 86401):
        with pytest.raises(ValidationFailed):
            publish.kill_switch(conn, key="billing.service_fee_bps", value=1400,
                                ttl_seconds=ttl, principal=who("u1", step_up=False),
                                reason="ttl 非法", now=NOW)


def test_kill_switch_expiry_restores_previous(conn):
    v1 = draft(conn, value=1500)
    activate(conn, key="billing.service_fee_bps", version=v1["version"])
    publish.kill_switch(conn, key="billing.service_fee_bps", value=1400, ttl_seconds=600,
                        principal=who("u1", step_up=False), reason="事故止损", now=NOW)
    assert publish.expire_kill_switches(conn, now=NOW + timedelta(seconds=599)) == []
    restored = publish.expire_kill_switches(conn, now=NOW + timedelta(seconds=601))
    assert restored == [{"key": "billing.service_fee_bps", "scope": "global", "scope_id": "",
                         "expired_version": 2, "restored_from": 1, "new_version": 3}]
    current = store.active_version(conn, key="billing.service_fee_bps")
    assert current["value"] == 1500 and current["rollback_to"] == 1
    assert current["published_by"] == publish.SYSTEM_ACTOR
    event = conn.execute(
        "SELECT payload FROM config_outbox WHERE payload ? 'reason_code'").fetchone()[0]
    assert event["reason_code"] == "kill_switch_expired" and event["rollback_to"] == 1


def test_restore_kill_switch_manual(conn):
    v1 = draft(conn, value=1500)
    activate(conn, key="billing.service_fee_bps", version=v1["version"])
    publish.kill_switch(conn, key="billing.service_fee_bps", value=1400, ttl_seconds=3600,
                        principal=who("u1", step_up=False), reason="事故止损", now=NOW)
    result = publish.restore_kill_switch(conn, key="billing.service_fee_bps",
                                         principal=who("u3", step_up=False),
                                         reason="事故已解除，提前恢复", now=NOW + timedelta(minutes=5))
    assert result["restored_from"] == 1
    assert store.active_version(conn, key="billing.service_fee_bps")["value"] == 1500
    with pytest.raises(StateConflict):
        publish.restore_kill_switch(conn, key="billing.service_fee_bps",
                                    principal=who("u3", step_up=False),
                                    reason="没有紧急版本", now=NOW + timedelta(minutes=6))


# ─────────────────────────────────────────────── 快照（INV-08 / R-14）
def test_activation_writes_snapshot_and_replays(conn):
    v1 = draft(conn, key="notify.report.daily_send_at", value="02:00")
    result = publish.activate_request(
        conn, request(conn, key="notify.report.daily_send_at", version=v1["version"],
                      roles=("OPS",), step_up=False)["publish_request_id"], now=NOW)
    row = conn.execute("SELECT * FROM config_snapshots").fetchone()
    assert row is not None
    assert row[1] == result["snapshot_digest"]                # snapshot_digest
    assert row[2] == result["policy_version"]                 # policy_version 生成列
    assert snapshot.verify_snapshot(dict(zip(
        [d.name for d in conn.execute("SELECT * FROM config_snapshots LIMIT 0").description], row)))
    assert snapshot.replay_snapshot(conn, snapshot_digest=result["snapshot_digest"]) is not None
    assert snapshot.replay_snapshot(conn, period=f"publish:{result['request']['publish_request_id']}")
    assert len(snapshot.list_snapshots(conn)) == 1


def test_snapshot_same_content_is_idempotent(conn):
    v1 = draft(conn, key="notify.report.daily_send_at", value="02:00")
    publish.activate_request(
        conn, request(conn, key="notify.report.daily_send_at", version=v1["version"],
                      roles=("OPS",), step_up=False)["publish_request_id"], now=NOW)
    first = snapshot.write_snapshot(conn, period="daily-1", now=NOW)
    second = snapshot.write_snapshot(conn, period="daily-2", now=NOW)
    assert first["snapshot_id"] == second["snapshot_id"]
    assert conn.execute("SELECT count(*) FROM config_snapshots").fetchone()[0] == 1


def test_snapshot_digest_mismatch_blocks_activation(conn, monkeypatch):
    """R-14：落库 digest 与事件 digest 不一致 → 拒绝并回滚（版本仍 draft）。"""
    v1 = draft(conn, key="notify.report.daily_send_at", value="02:00")
    req = request(conn, key="notify.report.daily_send_at", version=v1["version"],
                  roles=("OPS",), step_up=False)
    real = snapshot.write_snapshot

    def tampered(connection, **kwargs):
        row = real(connection, **kwargs)
        return {**row, "snapshot_digest": "a" * 64}

    monkeypatch.setattr(publish.snapshot, "write_snapshot", tampered)
    with pytest.raises(ValidationFailed) as excinfo:
        with conn.transaction():
            publish.activate_request(conn, req["publish_request_id"], now=NOW)
    assert "digest" in str(excinfo.value)
    assert store.get_version(conn, key="notify.report.daily_send_at", version=1)["status"] == "draft"
    assert conn.execute("SELECT count(*) FROM config_outbox").fetchone()[0] == 0


# ─────────────────────────────────────────────── 漂移（A/B/C 三源）
def _active_notify(conn, value="02:00"):
    v1 = draft(conn, key="notify.report.daily_send_at", value=value)
    publish.activate_request(
        conn, request(conn, key="notify.report.daily_send_at", version=v1["version"],
                      roles=("OPS",), step_up=False)["publish_request_id"], now=NOW)
    return v1


def test_drift_desired_vs_effective(conn):
    _active_notify(conn)
    rows = drift.scan_drifts(conn, desired={(("notify.report.daily_send_at"), "global", ""): 2},
                             now=NOW + timedelta(minutes=1))
    assert len(rows) == 1
    row = rows[0]
    assert row["desired_version"] == 2 and row["effective_version"] == 1
    assert row["expected"] == {"source": "desired", "version": 2}
    event = conn.execute(
        "SELECT type, payload FROM config_outbox WHERE type = 'config.drift_detected' LIMIT 1").fetchone()
    assert event[0] == "config.drift_detected"
    assert event[1]["key"] == "notify.report.daily_send_at"


def test_drift_running_mismatch_and_resolve(conn):
    _active_notify(conn)
    rows = drift.scan_effective_vs_running(
        conn, {"notify.report.daily_send_at": 1}, now=NOW)          # 相同 → 无漂移
    assert rows == []
    rows = drift.scan_effective_vs_running(
        conn, {"notify.report.daily_send_at": 2}, now=NOW + timedelta(minutes=5))
    assert len(rows) == 1 and rows[0]["running_version"] == 2
    assert drift.open_drifts(conn)
    resolved = drift.resolve_drift(conn, str(rows[0]["drift_id"]), resolution="节点已重启收敛",
                                   now=NOW + timedelta(minutes=10))
    assert resolved["resolved_at"] is not None
    assert drift.list_drifts(conn, resolved=False) == []
    with pytest.raises(ValidationFailed):
        drift.resolve_drift(conn, str(rows[0]["drift_id"]), resolution="再解决一次")


def test_drift_dedup_and_validation(conn):
    _active_notify(conn)
    desired = {("notify.report.daily_send_at", "global", ""): 2}
    assert len(drift.scan_drifts(conn, desired=desired, now=NOW)) == 1
    assert drift.scan_drifts(conn, desired=desired, now=NOW + timedelta(minutes=1)) == []
    with pytest.raises(ValidationFailed):
        drift.scan_drifts(conn)
    with pytest.raises(ValidationFailed):
        drift.scan_drifts(conn, desired={"billing.unknown": 1}, now=NOW)
    with pytest.raises(ValidationFailed):
        drift.scan_drifts(conn, desired={"billing.service_fee_bps": 0}, now=NOW)


# ─────────────────────────────────────────────── 事件派发 / DLQ
def test_dispatcher_delivers_and_marks(conn):
    outbox.append_event(conn, outbox.published_event(
        namespace="billing", key="billing.service_fee_bps", version=1, risk_level="P0",
        policy_version="323b64cf6e17", effective_at=NOW, occurred_at=NOW))
    seen = []
    stats = dispatcher.dispatch_pending(conn, publisher=lambda row: seen.append(row["type"]))
    assert stats["delivered"] and not stats["failed"] and not stats["dead_lettered"]
    assert seen == ["config.published"]
    assert dispatcher.pending_count(conn) == 0
    assert outbox.pending_events(conn) == []


def test_dispatcher_failures_go_to_dlq(conn):
    outbox.append_event(conn, outbox.published_event(
        namespace="billing", key="billing.service_fee_bps", version=1, risk_level="P0",
        policy_version="323b64cf6e17", effective_at=NOW, occurred_at=NOW))
    alerts = []

    def boom(_row):
        raise RuntimeError("下游不可用")

    for attempt in range(1, dispatcher.MAX_ATTEMPTS):
        stats = dispatcher.dispatch_pending(conn, publisher=boom,
                                            now=NOW + timedelta(hours=attempt),
                                            on_dead_letter=alerts.append)
        assert stats["failed"] and not stats["dead_lettered"]
        row = conn.execute("SELECT delivery_attempts, last_error FROM config_outbox").fetchone()
        assert row[0] == attempt and "下游不可用" in row[1]
    stats = dispatcher.dispatch_pending(conn, publisher=boom,
                                        now=NOW + timedelta(hours=dispatcher.MAX_ATTEMPTS),
                                        on_dead_letter=alerts.append)
    assert stats["dead_lettered"] and stats["pending"] == 0
    assert len(alerts) == 1 and alerts[0]["delivery_attempts"] == dispatcher.MAX_ATTEMPTS
    dead = dispatcher.dead_letters(conn)
    assert len(dead) == 1 and dead[0]["dead_lettered_at"] is not None
    assert outbox.pending_events(conn) == []


def test_outbox_delivery_guards(conn):
    row = outbox.append_event(conn, outbox.published_event(
        namespace="billing", key="billing.service_fee_bps", version=1, risk_level="P0",
        policy_version="323b64cf6e17", effective_at=NOW, occurred_at=NOW))
    conn.execute("UPDATE config_outbox SET delivery_attempts = 3, last_error = 'x' "
                 "WHERE event_id = %s", (row["event_id"],))
    assert_db_error(conn, "must not decrease", lambda c: c.execute(
        "UPDATE config_outbox SET delivery_attempts = 2 WHERE event_id = %s", (row["event_id"],)))
    assert_db_error(conn, "append-only", lambda c: c.execute(
        "UPDATE config_outbox SET payload = %s WHERE event_id = %s",
        (Jsonb({"x": 1}), row["event_id"])))
    conn.execute("UPDATE config_outbox SET dead_lettered_at = %s WHERE event_id = %s",
                 (NOW, row["event_id"]))
    assert_db_error(conn, "write-once", lambda c: c.execute(
        "UPDATE config_outbox SET dead_lettered_at = NULL WHERE event_id = %s",
        (row["event_id"],)))
