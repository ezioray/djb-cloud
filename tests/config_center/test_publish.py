# SPDX-License-Identifier: AGPL-3.0-or-later
"""发布单九步（T3，S1 子集）：状态机 / 复核 / 冷却 / 窗口 / step-up / outbox 同事务。

时间基线：``NOW = 2026-10-21T02:30Z`` = 周三 10:30（UTC+8）——落在发布窗口内的合法时刻；
窗口外用例用 22:00 CST 与周末。
"""
from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from psycopg.types.json import Jsonb

from app.config_center import canonical, features, publish, registry, store
from app.config_center.errors import (
    ApproverNotAllowed,
    CooldownActive,
    CrossFieldViolation,
    DangerousKeyForbidden,
    GrayPlanInvalid,
    IdempotencyConflict,
    KeyLocked,
    OutsidePublishWindow,
    SelfApprovalForbidden,
    StateConflict,
    StepUpRequired,
    ValidationFailed,
    VersionNotFound,
)
from configkit import assert_db_error, new_idempotency_key

REG = registry.load()
NOW = datetime(2026, 10, 21, 2, 30, tzinfo=timezone.utc)          # 周三 10:30 CST
LATER = NOW + timedelta(hours=25)                                  # 周四 11:30 CST（过冷却）
P0_KEY = "billing.service_fee_bps"
P2_KEY = "notify.report.daily_send_at"


def who(actor: str, roles=("FIN",), *, now: datetime = NOW, step_up: bool = True,
        ref: str | None = None, step_up_age_min: int = 1) -> publish.Principal:
    return publish.Principal(
        actor=actor,
        roles=frozenset(roles),
        step_up_at=now - timedelta(minutes=step_up_age_min) if step_up else None,
        step_up_ref=(ref or f"stepup-{uuid.uuid4().hex[:8]}") if step_up else None,
    )


def draft(conn, *, key: str = P0_KEY, value=1500, actor: str = "u1") -> dict:
    return store.create_draft(conn, key=key, value=value, reason="T3 测试草稿", actor=actor)


def request(conn, *, key: str = P0_KEY, version: int = 1, roles=("FIN",),
            now: datetime = NOW, step_up: bool = True, ref: str | None = None,
            **kwargs) -> dict:
    return publish.create_request(
        conn, key=key, version=version,
        principal=who("u1", roles, now=now, step_up=step_up, ref=ref),
        reason="T3 测试发布", now=now, **kwargs)


def approve(conn, request_id: str, *, actor: str = "u2", roles=("FIN",),
            now: datetime = NOW, decision: str = "approve", ref: str | None = None) -> dict:
    return publish.approve_request(
        conn, request_id, principal=who(actor, roles, now=now, ref=ref),
        decision=decision, reason="复核意见：通过" if decision == "approve" else "复核意见：驳回",
        now=now)


def approved_p0(conn, *, now: datetime = NOW, value=1500) -> dict:
    draft(conn, value=value)
    req = request(conn, now=now)
    return approve(conn, req["publish_request_id"], now=now)


# ─────────────────────────────────────────────── 主路径
def test_p0_happy_path_publishes_event_and_policy_version(conn):
    req = approved_p0(conn)
    result = publish.activate_request(conn, req["publish_request_id"], now=NOW)

    assert result["version"]["status"] == "active"
    assert result["version"]["published_by"] == "u1"
    assert result["version"]["approved_by"] == "u2"
    assert len(result["snapshot_digest"]) == 64
    assert result["policy_version"] == result["snapshot_digest"][:12]
    assert result["request"]["status"] == "active"
    assert result["request"]["snapshot_after"] == result["snapshot_digest"]

    rows = conn.execute(
        "SELECT type, payload, correlation_id FROM config_outbox").fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "config.published"
    assert rows[0][1]["policy_version"] == result["policy_version"]
    assert rows[0][1]["effective_at"] is not None
    assert str(rows[0][2]) == str(req["publish_request_id"])

    # policy_version 可复算（INV-08）
    assert publish.current_policy_version(conn)["policy_version"] == result["policy_version"]


def test_create_request_snapshots_fields(conn):
    draft(conn)
    req = request(conn)
    assert req["status"] == "pending_approval"
    assert req["risk_level"] == "P0"
    assert req["versions"] == {P0_KEY: 1}
    assert req["key_set"] == [P0_KEY]
    assert req["publish_step_up_ref"]
    assert req["expires_at"] == NOW + publish.facts.approval_timeout()
    assert req["impact"]["consumers"] == ["scheduler", "settlement", "provider-console"]
    assert req["impact"]["active_version"] is None


def test_p2_single_person_publish_and_close(conn):
    draft(conn, key=P2_KEY, value="02:00")
    req = request(conn, key=P2_KEY, roles=("OPS",), step_up=False)
    assert req["status"] == "approved"                     # P2 单人可发，不进待复核
    assert req["expires_at"] is None
    assert req["publish_step_up_ref"] is None

    result = publish.activate_request(conn, req["publish_request_id"], now=NOW)
    assert result["request"]["status"] == "active"
    assert result["version"]["approved_by"] is None         # P2 不要求复核人

    closed = publish.close_request(conn, req["publish_request_id"],
                                   principal=who("u1", ("OPS",), step_up=False),
                                   observation="观测 24h：无异常", now=NOW + timedelta(hours=1))
    assert closed["status"] == "closed" and closed["closed_at"] is not None

    # active 不阻塞下一次发布（收口后同 key 可继续）
    draft(conn, key=P2_KEY, value="03:00")
    second = request(conn, key=P2_KEY, version=2, roles=("OPS",), now=LATER, step_up=False)
    assert second["status"] == "approved"


def test_list_requests_filters(conn):
    draft(conn)
    first = request(conn)
    draft(conn, key=P2_KEY, value="02:00")
    second = request(conn, key=P2_KEY, roles=("OPS",), step_up=False)
    assert {row["publish_request_id"] for row in publish.list_requests(conn)} == {
        first["publish_request_id"], second["publish_request_id"]}
    assert [row["publish_request_id"] for row in publish.list_requests(
        conn, status="pending_approval")] == [first["publish_request_id"]]
    assert [row["publish_request_id"] for row in publish.list_requests(
        conn, key=P2_KEY)] == [second["publish_request_id"]]
    with pytest.raises(ValidationFailed):
        publish.list_requests(conn, limit=0)


# ─────────────────────────────────────────────── 第②道校验 / 影响面
def test_publish_gate_catches_cross_field_violation(conn):
    """草稿能存（第①道只做单值），发布前第②道发现承诺上限被突破。"""
    draft(conn, value=2500)                                # 2500 bps > fee_cap 20% = 2000 bps
    with pytest.raises(CrossFieldViolation) as excinfo:
        request(conn)
    assert excinfo.value.code == 47001


def test_impact_analysis_rejects_empty_or_bad_consumers(conn):
    item = REG.require(P0_KEY)
    with pytest.raises(ValidationFailed):
        publish.impact_analysis(conn, dataclasses.replace(item, consumers=()))
    with pytest.raises(ValidationFailed):
        publish.impact_analysis(conn, dataclasses.replace(item, consumers=("Bad Name",)))
    impact = publish.impact_analysis(conn, item)
    assert impact["risk_level"] == "P0" and impact["consumers"]


def test_unpublishable_and_dangerous_keys_are_blocked(conn):
    with pytest.raises(DangerousKeyForbidden):
        publish.create_request(conn, key="risk.rule_version", version=1,
                               principal=who("u1", ("RISK",)), reason="尝试发布危险键", now=NOW)
    with pytest.raises(ValidationFailed):
        publish.create_request(conn, key="content.wordlist_version", version=1,
                               principal=who("u1", ("OPS",)), reason="无默认值键", now=NOW)


# ─────────────────────────────────────────────── 复核（INV-03 / 角色 / step-up）
def test_self_approval_is_rejected(conn):
    draft(conn)
    req = request(conn)
    with pytest.raises(SelfApprovalForbidden) as excinfo:
        approve(conn, req["publish_request_id"], actor="u1")
    assert excinfo.value.code == 47002


def test_approver_roles(conn):
    draft(conn)
    req = request(conn)
    with pytest.raises(ApproverNotAllowed):
        approve(conn, req["publish_request_id"], actor="u3", roles=("CS",))
    # billing 的审批角色是 FIN/SUPER，但 P0 还要求 FIN 或 AUDIT（§21.4.3）
    with pytest.raises(ApproverNotAllowed):
        approve(conn, req["publish_request_id"], actor="u3", roles=("SUPER",))
    assert approve(conn, req["publish_request_id"], actor="u4", roles=("FIN",))["status"] == "approved"


def test_proposer_role_required(conn):
    draft(conn)
    with pytest.raises(ApproverNotAllowed):
        request(conn, roles=("CS",))


def test_step_up_required_valid_and_not_reusable(conn):
    draft(conn)
    with pytest.raises(StepUpRequired):
        request(conn, roles=("FIN",), step_up=False)
    with pytest.raises(StepUpRequired):
        publish.create_request(conn, key=P0_KEY, version=1,
                               principal=who("u1", ("FIN",), step_up_age_min=10),
                               reason="step-up 过期", now=NOW)

    publish_ref = "same-step-up-ref"
    req = request(conn, ref=publish_ref)
    with pytest.raises(StepUpRequired):
        approve(conn, req["publish_request_id"], ref=publish_ref)      # 复用同一个 step-up
    with pytest.raises(StepUpRequired):
        publish.approve_request(conn, req["publish_request_id"],
                                principal=who("u2", ("FIN",), step_up=False),
                                decision="approve", reason="缺 step-up", now=NOW)
    assert approve(conn, req["publish_request_id"], ref="approve-ref")["status"] == "approved"


def test_reject_ends_request(conn):
    draft(conn)
    req = request(conn)
    rejected = approve(conn, req["publish_request_id"], decision="reject")
    assert rejected["status"] == "rejected" and rejected["decision"] == "reject"
    with pytest.raises(StateConflict):
        approve(conn, req["publish_request_id"])
    with pytest.raises(StateConflict):
        publish.activate_request(conn, req["publish_request_id"], now=NOW)


def test_only_pending_can_be_approved(conn):
    draft(conn)
    req = request(conn)
    publish.activate_request(conn, approve(conn, req["publish_request_id"])["publish_request_id"],
                             now=NOW)
    with pytest.raises(StateConflict):
        approve(conn, req["publish_request_id"])


# ─────────────────────────────────────────────── 生效：窗口 / 调度 / 非法迁移
def test_activation_outside_publish_window(conn):
    req = approved_p0(conn)
    with pytest.raises(OutsidePublishWindow) as excinfo:
        publish.activate_request(conn, req["publish_request_id"],
                                 now=datetime(2026, 10, 21, 14, 0, tzinfo=timezone.utc))  # 22:00 CST
    assert excinfo.value.code == 47008
    with pytest.raises(OutsidePublishWindow):
        publish.activate_request(conn, req["publish_request_id"],
                                 now=datetime(2026, 10, 24, 2, 30, tzinfo=timezone.utc))  # 周六


def test_scheduled_request_waits_for_effective_at(conn):
    draft(conn)
    effective = NOW + timedelta(hours=2)                     # 12:30 CST，窗口内
    req = request(conn, effective_at=effective)
    approved = approve(conn, req["publish_request_id"])
    assert approved["status"] == "approved"                  # 复核只到 approved
    with pytest.raises(StateConflict) as excinfo:
        publish.activate_request(conn, req["publish_request_id"], now=NOW)
    assert excinfo.value.code == 40919

    scheduled = publish.schedule_request(
        conn, req["publish_request_id"], principal=who("u1"), now=NOW)
    assert scheduled["status"] == "scheduled"
    with pytest.raises(StateConflict):
        publish.activate_request(conn, req["publish_request_id"], now=NOW)
    result = publish.activate_request(conn, req["publish_request_id"], now=effective)
    assert result["request"]["status"] == "active"


def test_schedule_request_requires_future_effective_at(conn):
    draft(conn)
    no_effective = request(conn)
    approve(conn, no_effective["publish_request_id"])
    with pytest.raises(ValidationFailed):
        publish.schedule_request(conn, no_effective["publish_request_id"],
                                 principal=who("u1"), now=NOW)
    with pytest.raises(ApproverNotAllowed):
        publish.schedule_request(conn, no_effective["publish_request_id"],
                                 principal=who("u9", ("CS",), step_up=False), now=NOW)

    draft(conn, key=P2_KEY, value="02:00")
    p2 = request(conn, key=P2_KEY, roles=("OPS",), step_up=False,
                 effective_at=NOW - timedelta(minutes=5))
    with pytest.raises(ValidationFailed):
        publish.schedule_request(conn, p2["publish_request_id"],
                                 principal=who("u1", ("OPS",), step_up=False), now=NOW)


def test_pending_request_cannot_jump_to_active(conn):
    draft(conn)
    req = request(conn)
    with pytest.raises(StateConflict) as excinfo:
        publish.activate_request(conn, req["publish_request_id"], now=NOW)
    assert "跳过复核" in str(excinfo.value)


def test_activation_requires_draft_version(conn):
    draft(conn)
    req = request(conn)
    approve(conn, req["publish_request_id"])
    # 先把版本直接置 active（模拟已被别的路径发布），再走发布单
    store.activate(conn, key=P0_KEY, version=1, published_by="u1", approved_by="u2")
    with pytest.raises((StateConflict, VersionNotFound)):
        publish.activate_request(conn, req["publish_request_id"], now=NOW)


def test_missing_version_and_request(conn):
    with pytest.raises(VersionNotFound):
        publish.create_request(conn, key=P0_KEY, version=99, principal=who("u1"),
                               reason="版本不存在", now=NOW)
    with pytest.raises(VersionNotFound):
        publish.get_request(conn, str(uuid.uuid4()))


# ─────────────────────────────────────────────── 冷却（INV-04）/ 在飞锁（INV-07）
def test_cooldown_blocks_second_publish(conn):
    req = approved_p0(conn)
    publish.activate_request(conn, req["publish_request_id"], now=NOW)
    draft(conn, value=1600)
    with pytest.raises(CooldownActive) as excinfo:
        request(conn, version=2, now=NOW + timedelta(hours=1))
    assert excinfo.value.code == 47005
    assert request(conn, version=2, now=LATER)["status"] == "pending_approval"


def test_only_one_in_flight_request_per_key(conn):
    draft(conn)
    first = request(conn)
    draft(conn, value=1600)
    with pytest.raises(KeyLocked) as excinfo:
        request(conn, version=2)
    assert excinfo.value.code == 47003
    assert first["status"] == "pending_approval"

    # 库层兜底：绕过应用层直接插第二个在飞发布单会被部分唯一索引拒绝
    assert_db_error(conn, "config_publish_requests_inflight_uq", lambda c: c.execute(
        """INSERT INTO config_publish_requests
             (key, namespace, key_set, versions, risk_level, status, proposed_by, reason)
           VALUES (%s, 'billing', %s, %s, 'P0', 'pending_approval', 'u9', '重复在飞')""",
        (P0_KEY, [P0_KEY], Jsonb({P0_KEY: 2}))))


# ─────────────────────────────────────────────── 过期 / 撤销
def test_expire_does_not_auto_approve(conn):
    draft(conn)
    req = request(conn)
    expired = publish.expire_requests(conn, now=NOW + timedelta(hours=5))
    assert expired == [req["publish_request_id"]]
    row = publish.get_request(conn, req["publish_request_id"])
    assert row["status"] == "expired"
    with pytest.raises(StateConflict):
        approve(conn, req["publish_request_id"])
    # 版本仍是 draft：过期只是状态，不产生生效版本（§21.4.2）
    assert store.get_version(conn, key=P0_KEY, version=1)["status"] == "draft"


def test_expire_noop_when_not_due(conn):
    draft(conn)
    request(conn)
    assert publish.expire_requests(conn, now=NOW) == []


def test_cancel_only_by_proposer_or_super(conn):
    draft(conn)
    req = request(conn)
    with pytest.raises(ApproverNotAllowed):
        publish.cancel_request(conn, req["publish_request_id"],
                               principal=who("u9", ("CS",), step_up=False), reason="无权撤销")
    assert publish.cancel_request(conn, req["publish_request_id"],
                                  principal=who("u1", ("FIN",), step_up=False),
                                  reason="计划取消")["status"] == "cancelled"
    with pytest.raises(StateConflict):
        publish.cancel_request(conn, req["publish_request_id"],
                               principal=who("u1", ("FIN",), step_up=False), reason="再撤一次")


# ─────────────────────────────────────────────── 幂等
def test_idempotent_request_replay_and_conflict(conn):
    draft(conn)
    idem = new_idempotency_key()
    first = request(conn, idempotency_key=idem)
    replay = request(conn, idempotency_key=idem)
    assert replay["replayed"] is True
    assert replay["publish_request_id"] == first["publish_request_id"]
    draft(conn, value=1600)
    with pytest.raises(IdempotencyConflict) as excinfo:
        request(conn, version=2, idempotency_key=idem)
    assert excinfo.value.code == 40919


# ─────────────────────────────────────────────── 灰度（S2，开关关闭）
def test_gray_plan_is_blocked_until_s2(conn):
    draft(conn)
    with pytest.raises(GrayPlanInvalid) as excinfo:
        request(conn, gray_plan={"buckets": [1, 5, 25, 100]})
    assert excinfo.value.code == 47007


def test_gray_plan_validation_when_switch_on(conn, monkeypatch):
    """开关只读、默认关；这里用 monkeypatch 打开，验证 S2 接线前的结构校验。"""
    monkeypatch.setattr(features, "enabled", lambda name: True)
    draft(conn)
    req = request(conn, gray_plan={"buckets": [1, 5, 25, 100], "observation_seconds": 86400})
    assert req["gray_plan"]["buckets"] == [1, 5, 25, 100]
    draft(conn, value=1600)
    for bad in ({"buckets": [1, 5, 25, 90]}, {"buckets": []}, {"buckets": [1, 5, 25, 100],
                                                               "observation_seconds": 30}):
        with pytest.raises(GrayPlanInvalid):
            request(conn, version=2, gray_plan=bad)


# ─────────────────────────────────────────────── 事务性 / 库层护栏
def test_outbox_failure_rolls_back_activation(conn, monkeypatch):
    req = approved_p0(conn)

    def boom(*_args, **_kwargs):
        raise RuntimeError("outbox 写入失败（模拟）")

    monkeypatch.setattr(publish.outbox, "append_event", boom)
    with pytest.raises(RuntimeError):
        with conn.transaction():
            publish.activate_request(conn, req["publish_request_id"], now=NOW)
    monkeypatch.undo()

    assert store.get_version(conn, key=P0_KEY, version=1)["status"] == "draft"
    assert publish.get_request(conn, req["publish_request_id"])["status"] == "approved"
    assert conn.execute("SELECT count(*) FROM config_outbox").fetchone()[0] == 0


def test_state_machine_is_enforced_by_db(conn):
    draft(conn)
    req = request(conn)
    request_id = req["publish_request_id"]
    # pending_approval → active：跳过复核，库层直接拒
    assert_db_error(conn, "illegal transition", lambda c: c.execute(
        "UPDATE config_publish_requests SET status = 'active' WHERE publish_request_id = %s",
        (request_id,)))
    # 不可变列（versions）改不了
    assert_db_error(conn, "immutable", lambda c: c.execute(
        "UPDATE config_publish_requests SET versions = %s WHERE publish_request_id = %s",
        (Jsonb({P0_KEY: 9}), request_id)))
    # DELETE 拒绝
    assert_db_error(conn, "DELETE not allowed", lambda c: c.execute(
        "DELETE FROM config_publish_requests WHERE publish_request_id = %s", (request_id,)))
    # 收口必须带观测结论
    publish.expire_requests(conn, now=NOW + timedelta(hours=5))
    assert_db_error(conn, "illegal transition", lambda c: c.execute(
        "UPDATE config_publish_requests SET status = 'approved', decision = 'approve', "
        "approved_by = ARRAY['u2'] WHERE publish_request_id = %s", (request_id,)))


def test_closed_requires_observation(conn):
    draft(conn, key=P2_KEY, value="02:00")
    req = request(conn, key=P2_KEY, roles=("OPS",), step_up=False)
    publish.activate_request(conn, req["publish_request_id"], now=NOW)
    assert_db_error(conn, "closed requires", lambda c: c.execute(
        "UPDATE config_publish_requests SET status = 'closed', closed_at = now() "
        "WHERE publish_request_id = %s", (req["publish_request_id"],)))


def test_activate_supersedes_previous_active(conn):
    first = approved_p0(conn)
    publish.activate_request(conn, first["publish_request_id"], now=NOW)
    draft(conn, value=1600)
    second = request(conn, version=2, now=LATER)
    approve(conn, second["publish_request_id"], now=LATER)
    result = publish.activate_request(conn, second["publish_request_id"], now=LATER)
    assert result["version"]["version"] == 2
    statuses = dict(conn.execute(
        "SELECT version, status FROM config_versions WHERE key = %s ORDER BY version",
        (P0_KEY,)).fetchall())
    assert statuses == {1: "superseded", 2: "active"}
    assert publish.current_policy_version(conn)["entries"] == 1


def test_current_policy_version_none_without_active(conn):
    assert publish.current_policy_version(conn) is None
