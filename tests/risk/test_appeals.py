# SPDX-License-Identifier: Apache-2.0
"""申诉：30 天窗口 / 重复 48003 / 7 工作日 SLA / 裁决 SoD 48006 / 撤销解冻提案 / 误伤恢复。"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.risk import clock, errors, facts, policy, store
from riskkit import ADMIN_PRINCIPAL, OTHER_TENANT_PRINCIPAL, build_client
from riskkit import FIXED_NOW, make_appeal, make_case, outbox_events

STEP_UP = {"X-Admin-Step-Up": "step-up-token-123"}
REVIEWER = {"admin_id": "reviewer", "tenant_id": "tenant-a",
            "scopes": ["risk.read", "risk.write"]}


def _actioned_case(savepoint_conn, *, decided_at: datetime | None = None,
                   decided_by: str = "disposer"):
    return make_case(savepoint_conn, status="actioned",
                     decided_at=decided_at or (FIXED_NOW - timedelta(days=2)),
                     decided_by=decided_by)


# ───────────────────────────────────────────────────────────── 纯策略
def test_sla_skips_weekends() -> None:
    friday = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)
    assert friday.weekday() == 4
    due = policy.sla_due(friday)
    assert due == datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)   # +7 个工作日
    assert due.weekday() < 5


def test_appeal_window_and_coarse_reason() -> None:
    decided = datetime(2026, 10, 1, 0, 0, tzinfo=timezone.utc)
    assert policy.appeal_window_closes(decided) == decided + timedelta(days=facts.APPEAL_WINDOW_D)
    with pytest.raises(errors.AppealConflict) as excinfo:
        policy.check_appeal_window(decided, decided + timedelta(days=31))
    assert excinfo.value.code == 48003
    policy.check_appeal_window(decided, decided + timedelta(days=30))       # 边界允许
    assert policy.coarse_reason(48001) in facts.COARSE_REASONS
    assert policy.coarse_reason("not-a-code") == "policy_blocked"
    assert policy.coarse_reason(48006) == "account_restricted"


# ───────────────────────────────────────────────────────────── 受理
def test_submit_appeal_sets_sla_and_case_status(savepoint_conn) -> None:
    case = _actioned_case(savepoint_conn)
    with build_client(savepoint_conn) as client:
        response = client.post("/api/v1/admin/risk/appeals",
                               json={"case_id": str(case["case_id"]), "reason": "误伤申诉"})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "submitted"
    assert body["case_id"] == str(case["case_id"])
    assert body["submitted_at"] == clock.iso(FIXED_NOW)
    assert body["sla_due"] == clock.iso(policy.sla_due(FIXED_NOW))
    updated = store.get_case(savepoint_conn, str(case["case_id"]))
    assert updated["status"] == "appealed"


def test_duplicate_appeal_is_48003(savepoint_conn) -> None:
    case = _actioned_case(savepoint_conn)
    make_appeal(savepoint_conn, str(case["case_id"]))
    with build_client(savepoint_conn) as client:
        response = client.post("/api/v1/admin/risk/appeals",
                               json={"case_id": str(case["case_id"]), "reason": "再次申诉"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 48003
    assert response.json()["error"]["reason"] == "appeal_duplicate"


def test_expired_appeal_window_is_48003(savepoint_conn) -> None:
    case = _actioned_case(savepoint_conn, decided_at=FIXED_NOW - timedelta(days=31))
    with build_client(savepoint_conn) as client:
        response = client.post("/api/v1/admin/risk/appeals",
                               json={"case_id": str(case["case_id"]), "reason": "迟到的申诉"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 48003
    assert response.json()["error"]["reason"] == "appeal_window_expired"


def test_case_not_actioned_cannot_be_appealed(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="opened")
    with build_client(savepoint_conn) as client:
        response = client.post("/api/v1/admin/risk/appeals",
                               json={"case_id": str(case["case_id"]), "reason": "未处置"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 48003


def test_appeal_for_missing_case_is_404(savepoint_conn) -> None:
    with build_client(savepoint_conn) as client:
        response = client.post("/api/v1/admin/risk/appeals",
                               json={"case_id": str(uuid.uuid4()), "reason": "不存在"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


# ───────────────────────────────────────────────────────────── 裁决
def _appeal(savepoint_conn):
    case = _actioned_case(savepoint_conn)
    appeal = make_appeal(savepoint_conn, str(case["case_id"]),
                         submitted_at=FIXED_NOW - timedelta(days=1),
                         sla_due=policy.sla_due(FIXED_NOW - timedelta(days=1)))
    return case, appeal


def test_decide_upheld_closes_case(savepoint_conn) -> None:
    case, appeal = _appeal(savepoint_conn)
    with build_client(savepoint_conn, admin=REVIEWER) as client:
        response = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                               json={"outcome": "upheld", "reason": "证据充分，维持"},
                               headers=STEP_UP)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "upheld"
    assert response.json()["outcome"] == "upheld"
    updated = store.get_case(savepoint_conn, str(case["case_id"]))
    assert updated["status"] == "closed"
    closed = [event for event in outbox_events(savepoint_conn)
              if event["type"] == "risk.case.closed"]
    assert len(closed) == 1
    assert closed[0]["payload"]["outcome"] == "upheld"


def test_decide_overturned_emits_unfreeze_proposal(savepoint_conn) -> None:
    case, appeal = _appeal(savepoint_conn)
    with build_client(savepoint_conn, admin=REVIEWER) as client:
        response = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                               json={"outcome": "overturned", "reason": "误伤，撤销"},
                               headers=STEP_UP)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "overturned"
    proposals = [event for event in outbox_events(savepoint_conn)
                 if event["type"] == "risk.action.requested"]
    assert len(proposals) == 1
    assert proposals[0]["payload"]["action"] == "unfreeze"
    assert proposals[0]["payload"]["reason_code"] == "risk_case_overturned"
    updated = store.get_case(savepoint_conn, str(case["case_id"]))
    assert updated["status"] == "closed"


def test_decider_cannot_be_original_disposer(savepoint_conn) -> None:
    case, appeal = _appeal(savepoint_conn)
    with build_client(savepoint_conn, admin=ADMIN_PRINCIPAL) as client:   # admin_id=disposer
        response = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                               json={"outcome": "upheld", "reason": "自己复核自己"},
                               headers=STEP_UP)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 48006
    assert response.json()["error"]["reason"] == "same_actor"


def test_appeal_decide_requires_step_up(savepoint_conn) -> None:
    _case, appeal = _appeal(savepoint_conn)
    with build_client(savepoint_conn, admin=REVIEWER) as client:
        response = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                               json={"outcome": "upheld", "reason": "维持"})
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401


def test_re_decide_is_409(savepoint_conn) -> None:
    _case, appeal = _appeal(savepoint_conn)
    headers = STEP_UP
    with build_client(savepoint_conn, admin=REVIEWER) as client:
        first = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                            json={"outcome": "upheld", "reason": "维持"}, headers=headers)
        again = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                            json={"outcome": "overturned", "reason": "改判"}, headers=headers)
    assert first.status_code == 200
    assert again.status_code == 409
    assert again.json()["error"]["code"] == 40919


def test_overdue_appeal_is_escalated_on_decide(savepoint_conn) -> None:
    case = _actioned_case(savepoint_conn)
    appeal = make_appeal(savepoint_conn, str(case["case_id"]),
                         submitted_at=FIXED_NOW - timedelta(days=20),
                         sla_due=FIXED_NOW - timedelta(days=1))
    overdue_ids = [str(row["appeal_id"]) for row in
                   store.overdue_appeals(savepoint_conn, FIXED_NOW)]
    assert str(appeal["appeal_id"]) in overdue_ids
    with build_client(savepoint_conn, admin=REVIEWER) as client:
        response = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                               json={"outcome": "upheld", "reason": "超期后答复"},
                               headers=STEP_UP)
    assert response.status_code == 200
    row = store.get_appeal(savepoint_conn, str(appeal["appeal_id"]))
    assert row["escalated_at"] is not None                      # SLA 超期 → 升级 P1 留痕


def test_appeal_tenant_isolation(savepoint_conn) -> None:
    _case, appeal = _appeal(savepoint_conn)
    with build_client(savepoint_conn, admin=OTHER_TENANT_PRINCIPAL) as other:
        response = other.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                              json={"outcome": "upheld", "reason": "越权"}, headers=STEP_UP)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


def test_appeal_decision_validation(savepoint_conn) -> None:
    _case, appeal = _appeal(savepoint_conn)
    with build_client(savepoint_conn, admin=REVIEWER) as client:
        bad_outcome = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                                  json={"outcome": "maybe", "reason": "x"}, headers=STEP_UP)
        no_reason = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                                json={"outcome": "upheld", "reason": ""}, headers=STEP_UP)
    assert bad_outcome.status_code == 400
    assert bad_outcome.json()["error"]["code"] == 40001
    assert no_reason.status_code == 400


def test_appeal_decide_idempotency_replay(savepoint_conn) -> None:
    _case, appeal = _appeal(savepoint_conn)
    key = "idem-" + uuid.uuid4().hex
    headers = {**STEP_UP, "X-DJB-Idempotency-Key": key}
    with build_client(savepoint_conn, admin=REVIEWER) as client:
        first = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                            json={"outcome": "upheld", "reason": "维持"}, headers=headers)
        replay = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                             json={"outcome": "upheld", "reason": "维持"}, headers=headers)
        reused = client.post(f"/api/v1/admin/risk/appeals/{appeal['appeal_id']}/decide",
                             json={"outcome": "overturned", "reason": "改判"}, headers=headers)
    assert first.status_code == 200 and replay.status_code == 200
    assert replay.json()["outcome"] == "upheld"
    assert reused.status_code == 409
    assert reused.json()["error"]["code"] == 40919
    closed = [event for event in outbox_events(savepoint_conn)
              if event["type"] == "risk.case.closed"]
    assert len(closed) == 1                                   # 重放不重复发事件
