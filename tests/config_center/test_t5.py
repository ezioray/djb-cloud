# SPDX-License-Identifier: Apache-2.0
"""T5：审计接口 / CLI（verify·replay）/ worker / 退避与 DLQ / 灰度推进。

CLI 与 worker 用例用**函数级独立 schema**（写入需要提交，避免污染模块级共享 schema）。
"""
from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from app.config_center import (
    audit,
    cli,
    dispatcher,
    drift,
    features,
    outbox,
    publish,
    registry,
    store,
    worker,
)
from app.config_center.errors import AuditUnavailable, GrayPlanInvalid, ValidationFailed
from configkit import apply_migrations, connect, create_schema, drop_schema

NOW = datetime(2026, 10, 21, 2, 30, tzinfo=timezone.utc)          # 周三 10:30 CST
LATER = NOW + timedelta(hours=25)
REG = registry.load()


def who(actor="u1", roles=("FIN",), *, now=NOW, step_up=True, ref=None):
    return publish.Principal(actor, frozenset(roles),
                             step_up_at=now - timedelta(minutes=1) if step_up else None,
                             step_up_ref=(ref or f"step-{uuid.uuid4().hex[:8]}") if step_up else None)


def draft(conn, *, key="billing.service_fee_bps", value=1500, actor="u1", **kwargs):
    return store.create_draft(conn, key=key, value=value, reason="T5 测试草稿", actor=actor, **kwargs)


@pytest.fixture
def fresh_schema(db, schema_prefix):
    name = f"{schema_prefix}_t5_{uuid.uuid4().hex[:6]}"
    create_schema(name)
    apply_migrations(name)
    try:
        yield name
    finally:
        drop_schema(name)


@contextmanager
def autocommit(schema):
    conn = connect(schema, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


# ─────────────────────────────────────────────── 审计接口
def test_audit_events_recorded_across_flow(conn):
    sink = audit.InMemoryAuditSink()
    draft_row = draft(conn)
    req = publish.create_request(conn, key="billing.service_fee_bps", version=draft_row["version"],
                                 principal=who("u1"), reason="审计流程", now=NOW, audit=sink)
    publish.approve_request(conn, req["publish_request_id"], principal=who("u2"),
                            decision="approve", reason="复核通过", now=NOW, audit=sink)
    publish.activate_request(conn, req["publish_request_id"], now=NOW, audit=sink)
    publish.close_request(conn, req["publish_request_id"], principal=who("u1"),
                          observation="观测无异常", now=NOW + timedelta(minutes=5), audit=sink)

    assert [row["action"] for row in sink.events] == [
        "config.publish.requested", "config.publish.approved", "config.published", "config.closed"]
    assert all(row["key"] == "billing.service_fee_bps" for row in sink.events)
    assert sink.events[0]["request_id"] == str(req["publish_request_id"])
    assert sink.events[2]["metadata"]["policy_version"]
    assert sink.query("billing.service_fee_bps")[0]["action"] == "config.closed"


def test_audit_rollback_kill_switch_and_drift(conn):
    sink = audit.InMemoryAuditSink()
    v1 = draft(conn)
    req = publish.create_request(conn, key="billing.service_fee_bps", version=v1["version"],
                                 principal=who("u1"), reason="审计回滚", now=NOW, audit=sink)
    publish.approve_request(conn, req["publish_request_id"], principal=who("u2"),
                            decision="approve", reason="通过", now=NOW, audit=sink)
    publish.activate_request(conn, req["publish_request_id"], now=NOW, audit=sink)
    v2 = draft(conn, value=1600)
    req2 = publish.create_request(conn, key="billing.service_fee_bps", version=v2["version"],
                                  principal=who("u1", now=LATER), reason="第二版本", now=LATER,
                                  audit=sink)
    publish.approve_request(conn, req2["publish_request_id"], principal=who("u2", now=LATER),
                            decision="approve", reason="通过", now=LATER, audit=sink)
    publish.activate_request(conn, req2["publish_request_id"], now=LATER, audit=sink)
    publish.rollback(conn, key="billing.service_fee_bps", target_version=1,
                     principal=who("u1", now=LATER), reason="回滚到基线", now=LATER, audit=sink)
    publish.kill_switch(conn, key="billing.service_fee_bps", value=1400, ttl_seconds=600,
                        principal=who("u1", step_up=False), reason="紧急止损", now=LATER, audit=sink)
    drift.scan_effective_vs_running(conn, {"billing.service_fee_bps": 1},
                                    now=LATER + timedelta(minutes=1), audit=sink)
    actions = [row["action"] for row in sink.events]
    assert "config.rollback.requested" in actions
    assert "config.kill_switch" in actions
    assert "config.drift.detected" in actions
    assert all(row["action"] in audit.ACTIONS for row in sink.events)


def test_audit_failure_blocks_activation(conn):
    class BrokenSink:
        def append(self, event):
            raise RuntimeError("M16 不可用")

    v1 = draft(conn)
    req = publish.create_request(conn, key="billing.service_fee_bps", version=v1["version"],
                                 principal=who("u1"), reason="审计失败", now=NOW)
    publish.approve_request(conn, req["publish_request_id"], principal=who("u2"),
                            decision="approve", reason="通过", now=NOW)
    with pytest.raises(AuditUnavailable) as excinfo:
        with conn.transaction():
            publish.activate_request(conn, req["publish_request_id"], now=NOW,
                                     audit=BrokenSink())
    assert excinfo.value.code == 40919
    assert store.get_version(conn, key="billing.service_fee_bps", version=1)["status"] == "draft"
    assert conn.execute("SELECT count(*) FROM config_outbox").fetchone()[0] == 0


def test_audit_event_rejects_unregistered_action():
    with pytest.raises(ValueError):
        audit.build_event("config.unknown", actor="u1", key="a.b").as_payload()


# ─────────────────────────────────────────────── CLI：verify / replay（只读）
def test_cli_verify_and_replay_are_read_only(fresh_schema, capsys):
    with autocommit(fresh_schema) as conn:
        store.sync_items(conn)
        v1 = draft(conn, key="notify.report.daily_send_at", value="02:00")
        req = publish.create_request(conn, key="notify.report.daily_send_at",
                                     version=v1["version"], principal=who("ops1", ("OPS",), step_up=False),
                                     reason="CLI 快照", now=NOW)
        publish.activate_request(conn, req["publish_request_id"], now=NOW)
        snapshot_digest = conn.execute("SELECT snapshot_digest FROM config_snapshots").fetchone()[0]

    assert cli.main(["--schema", fresh_schema, "verify", "--expect-zero"]) == 0
    verify = json.loads(capsys.readouterr().out)
    assert verify["diff"] == 0 and verify["versions"]["total"] == 1
    assert verify["snapshots"]["total"] == 1 and verify["snapshots"]["bad"] == []
    assert verify["active_policy"]["policy_version"] == snapshot_digest[:12]

    assert cli.main(["--schema", fresh_schema, "replay", "--digest", snapshot_digest]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["snapshot_digest"] == snapshot_digest
    assert replay["verified"] is True and replay["entries"][0]["key"] == "notify.report.daily_send_at"
    assert cli.main(["--schema", fresh_schema, "replay", "--period", "no-such-period"]) == 1

    # 只读连接在数据库层拒绝写
    with cli.read_only_connection(fresh_schema) as conn:
        assert conn.execute("SHOW transaction_read_only").fetchone()[0] == "on"
        with pytest.raises(Exception) as excinfo:
            conn.execute("DELETE FROM config_items")
        assert "read-only" in str(excinfo.value).lower()


def test_cli_verify_detects_bad_digest(fresh_schema, capsys):
    with autocommit(fresh_schema) as conn:
        store.sync_items(conn)
        v1 = draft(conn)
        conn.execute(
            """INSERT INTO config_versions
                 (namespace, key, scope, scope_id, version, value_type, unit, schema_ref,
                  value, content_digest, request_digest, reason, created_by)
               VALUES ('billing', 'billing.service_fee_bps', 'global', '', 2, 'integer', 'bps',
                       'billing.service_fee_bps@v1', '1600'::jsonb, %s, %s, '篡改摘要', 'u1')""",
            ("a" * 64, "b" * 64))
    assert cli.main(["--schema", fresh_schema, "verify", "--expect-zero"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["versions"]["diff"] == 1


# ─────────────────────────────────────────────── worker
def test_worker_advances_scheduled_and_expires(fresh_schema):
    with autocommit(fresh_schema) as conn:
        store.sync_items(conn)
        v1 = draft(conn)
        req = publish.create_request(conn, key="billing.service_fee_bps", version=v1["version"],
                                     principal=who("u1"), reason="定时生效",
                                     effective_at=NOW + timedelta(hours=2), now=NOW)
        publish.approve_request(conn, req["publish_request_id"], principal=who("u2"),
                                decision="approve", reason="通过", now=NOW)
        assert publish.get_request(conn, str(req["publish_request_id"]))["status"] == "approved"

        first = worker.tick(conn, now=NOW)
        assert first["scheduled"] == []
        assert first["marked_scheduled"] == 1
        assert publish.get_request(conn, str(req["publish_request_id"]))["status"] == "scheduled"

        second = worker.tick(conn, now=NOW + timedelta(hours=2))
        assert second["scheduled"][0]["status"] == "active"
        assert store.active_version(conn, key="billing.service_fee_bps")["version"] == 1


def test_worker_expires_reviews_and_kill_switches(fresh_schema):
    with autocommit(fresh_schema) as conn:
        store.sync_items(conn)
        v1 = draft(conn)
        publish.create_request(conn, key="billing.service_fee_bps", version=v1["version"],
                               principal=who("u1"), reason="等待复核", now=NOW)
        later = NOW + timedelta(hours=5)
        report = worker.tick(conn, now=later)
        assert report["expired_requests"]
        assert publish.list_requests(conn, status="expired")

        # kill switch 到期：先激活一个基线版本
        v2 = draft(conn, value=1500)
        req2 = publish.create_request(conn, key="billing.service_fee_bps", version=v2["version"],
                                      principal=who("u1", now=LATER), reason="基线版本", now=LATER)
        publish.approve_request(conn, req2["publish_request_id"], principal=who("u2", now=LATER),
                                decision="approve", reason="通过", now=LATER)
        publish.activate_request(conn, req2["publish_request_id"], now=LATER)
        publish.kill_switch(conn, key="billing.service_fee_bps", value=1400, ttl_seconds=60,
                            principal=who("u1", step_up=False, now=LATER), reason="紧急止损", now=LATER)
        report = worker.tick(conn, now=LATER + timedelta(seconds=61))
        assert report["kill_switches"][0]["key"] == "billing.service_fee_bps"
        assert store.active_version(conn, key="billing.service_fee_bps")["value"] == 1500


def test_worker_dispatches_outbox(conn):
    outbox.append_event(conn, outbox.published_event(
        namespace="billing", key="billing.service_fee_bps", version=1, risk_level="P0",
        policy_version="323b64cf6e17", effective_at=NOW, occurred_at=NOW))
    report = worker.tick(conn, now=NOW)
    assert report["dispatch"]["delivered"]
    assert dispatcher.pending_count(conn) == 0


# ─────────────────────────────────────────────── 退避 / DLQ / 人工重放
def test_dispatcher_backoff_and_requeue(conn):
    event = outbox.append_event(conn, outbox.published_event(
        namespace="billing", key="billing.service_fee_bps", version=1, risk_level="P0",
        policy_version="323b64cf6e17", effective_at=NOW, occurred_at=NOW))

    def boom(_row):
        raise RuntimeError("下游不可用")

    stats = dispatcher.dispatch_pending(conn, publisher=boom, now=NOW)
    assert stats["failed"]
    row = conn.execute("SELECT delivery_attempts, next_attempt_at FROM config_outbox").fetchone()
    assert row[0] == 1 and row[1] == NOW + timedelta(seconds=1)
    # 未到退避时间：不重试
    assert dispatcher.dispatch_pending(conn, publisher=boom, now=NOW)["scanned"] == 0
    # 到点后重试并拉长退避
    stats = dispatcher.dispatch_pending(conn, publisher=boom, now=NOW + timedelta(seconds=2))
    row = conn.execute("SELECT delivery_attempts, next_attempt_at FROM config_outbox").fetchone()
    assert row[0] == 2 and row[1] == NOW + timedelta(seconds=2 + 5)

    for i in range(2, dispatcher.MAX_ATTEMPTS):
        dispatcher.dispatch_pending(conn, publisher=boom, now=NOW + timedelta(hours=i))
    dead = dispatcher.dead_letters(conn)
    assert len(dead) == 1
    requeued = dispatcher.requeue_dead_letter(conn, str(dead[0]["event_id"]),
                                              now=NOW + timedelta(hours=10))
    assert requeued["event_id"] != dead[0]["event_id"]
    assert requeued["idempotency_key"].endswith(tuple("0123456789abcdef"))
    assert requeued["delivery_attempts"] == 0
    assert dispatcher.dispatch_pending(conn, now=NOW + timedelta(hours=10))["delivered"]
    assert len(dispatcher.dead_letters(conn)) == 1        # 原死信保留（只追加）
    with pytest.raises(ValidationFailed):
        dispatcher.requeue_dead_letter(conn, str(uuid.uuid4()))


# ─────────────────────────────────────────────── 灰度推进（S2 开关）
def test_promote_requires_feature_switch(conn):
    draft(conn)
    req = publish.create_request(conn, key="billing.service_fee_bps", version=1,
                                 principal=who("u1"), reason="无灰度计划", now=NOW)
    publish.approve_request(conn, req["publish_request_id"], principal=who("u2"),
                            decision="approve", reason="通过", now=NOW)
    with pytest.raises(GrayPlanInvalid):
        publish.promote_request(conn, req["publish_request_id"], principal=who("u1"),
                                target_stage="full", now=NOW)


def test_promote_buckets_when_switch_on(conn, monkeypatch):
    monkeypatch.setattr(features, "enabled", lambda name: True)
    draft(conn)
    req = publish.create_request(conn, key="billing.service_fee_bps", version=1,
                                 principal=who("u1"), reason="灰度计划", now=NOW,
                                 gray_plan={"buckets": [1, 5, 25, 100],
                                            "observation_seconds": 60})
    publish.approve_request(conn, req["publish_request_id"], principal=who("u2"),
                            decision="approve", reason="通过", now=NOW)
    first = publish.promote_request(conn, req["publish_request_id"], principal=who("u1"),
                                    target_stage="next_bucket", now=NOW)
    assert first["bucket"] == 5 and first["activated"] is False
    assert first["request"]["status"] == "rolling_out"
    # 观测窗未满
    with pytest.raises(GrayPlanInvalid):
        publish.promote_request(conn, req["publish_request_id"], principal=who("u1"),
                                target_stage="next_bucket", now=NOW + timedelta(seconds=10))
    # 推进到 25，再到最后一个桶 100（full）
    second = publish.promote_request(conn, req["publish_request_id"], principal=who("u1"),
                                     target_stage="next_bucket", now=NOW + timedelta(seconds=61))
    assert second["bucket"] == 25
    full = publish.promote_request(conn, req["publish_request_id"], principal=who("u1"),
                                   target_stage="next_bucket",
                                   now=NOW + timedelta(seconds=122))
    assert full["activated"] is True and full["request"]["status"] == "active"
    assert store.active_version(conn, key="billing.service_fee_bps")["version"] == 1
