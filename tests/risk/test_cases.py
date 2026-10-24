# SPDX-License-Identifier: AGPL-3.0-or-later
"""案件：开案去重（INV-06）/ 证据（INV-03）/ 处置分级与只提案（INV-04）/ 状态机 / SoD。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.risk import cases, errors, models, store
from riskkit import ADMIN_PRINCIPAL, OTHER_TENANT_PRINCIPAL, build_client
from riskkit import FIXED_NOW, make_appeal, make_case, outbox_events

STEP_UP = {"X-Admin-Step-Up": "step-up-token-123"}


def _draft(conn, *, subject_hash: str | None = None, evidence=("evt-0001",), risk_type="self_trade"):
    return models.CaseDraft(
        subject_type="account",
        subject_hash=subject_hash or "sha256:" + uuid.uuid4().hex.ljust(64, "0")[:64],
        risk_type=risk_type,
        severity="P2",
        evidence_refs=list(evidence),
        tenant_id="tenant-a",
        opened_by="maker",
        opened_at=FIXED_NOW,
        rule_key="self_trade.ratio",
        rule_version=3,
        config_ref="risk.case.auto_action",
    )


# ───────────────────────────────────────────────────────────── 开案（域层）
def test_open_case_emits_opened_event_without_thresholds(conn) -> None:
    row = cases.open_case(conn, _draft(conn))
    assert row["status"] == "opened"
    assert row["case_no"].startswith("RC-")
    outbox = outbox_events(conn)
    opened = [event for event in outbox if event["type"] == "risk.case.opened"]
    assert len(opened) == 1
    payload = opened[0]["payload"]
    assert payload == {
        "case_id": str(row["case_id"]),
        "subject_id": row["subject_hash"],
        "risk_type": "self_trade",
        "severity": "P2",
        "rule_version": 3,
    }
    assert set(payload) <= {
        "case_id", "subject_id", "risk_type", "severity", "rule_version"}


def test_duplicate_open_case_is_48002(conn) -> None:
    draft = _draft(conn)
    cases.open_case(conn, draft)
    with pytest.raises(errors.CaseExists) as excinfo:
        with conn.transaction():
            cases.open_case(conn, _draft(conn, subject_hash=draft.subject_hash))
    assert excinfo.value.status_code == 409
    assert excinfo.value.code == 48002


def test_open_or_merge_merges_evidence(conn) -> None:
    draft = _draft(conn)
    first, merged = cases.open_or_merge(conn, draft)
    assert merged is False
    again, merged = cases.open_or_merge(
        conn, _draft(conn, subject_hash=draft.subject_hash, evidence=("evt-0002",)))
    assert merged is True
    assert str(again["case_id"]) == str(first["case_id"])
    assert set(again["evidence_refs"]) == {"evt-0001", "evt-0002"}
    assert store.find_open_case(conn, draft.subject_hash, draft.risk_type) is not None


def test_open_case_requires_evidence(conn) -> None:
    with pytest.raises(errors.EvidenceMissing) as excinfo:
        cases.open_case(conn, _draft(conn, evidence=()))
    assert excinfo.value.status_code == 400
    assert excinfo.value.code == 48004


# ───────────────────────────────────────────────────────────── 处置（HTTP）
def _freeze_body(**overrides):
    body = {"action": "freeze", "reason": "同主体挂单吃单（证据见引用）",
            "evidence_refs": ["evt-0001"],
            "expires_at": (FIXED_NOW + timedelta(days=30)).isoformat()}
    body.update(overrides)
    return body


def test_freeze_creates_proposal_event_and_keeps_accounts_untouched(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="opened", opened_by="maker")
    before = _accounts_fingerprint(savepoint_conn)
    with build_client(savepoint_conn) as client:
        response = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                               json=_freeze_body(), headers=STEP_UP)
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["action"] == "freeze"
    assert payload["proposal_id"]
    assert payload["decided_by"] == "disposer"
    assert payload["case_id"] == str(case["case_id"])

    # INV-04：只写提案事件，不改 accounts 状态
    assert _accounts_fingerprint(savepoint_conn) == before
    proposal = [event for event in outbox_events(savepoint_conn)
                if event["type"] == "risk.action.requested"]
    assert len(proposal) == 1
    body = proposal[0]["payload"]
    assert body["action"] == "freeze"
    assert body["case_id"] == str(case["case_id"])
    assert body["subject_type"] == "account"
    assert body["subject_id"] == case["subject_hash"]
    assert body["reason_code"] == "risk_case_freeze"
    assert body["expires_at"] is not None
    assert set(body) == {"case_id", "subject_type", "subject_id", "action", "reason_code",
                         "expires_at"}

    updated = store.get_case(savepoint_conn, str(case["case_id"]))
    assert updated["status"] == "actioned"
    assert updated["decision"] == "freeze"
    assert updated["decided_by"] == "disposer"
    assert len(store.case_decisions(updated)) == 1


def test_freeze_requires_expiry_within_180_days(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="opened")
    with build_client(savepoint_conn) as client:
        missing = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                              json=_freeze_body(expires_at=None), headers=STEP_UP)
        too_long = client.post(
            f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
            json=_freeze_body(expires_at=(FIXED_NOW + timedelta(days=181)).isoformat()),
            headers=STEP_UP)
        past = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                           json=_freeze_body(expires_at=(FIXED_NOW - timedelta(days=1)).isoformat()),
                           headers=STEP_UP)
        boundary = client.post(
            f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
            json=_freeze_body(expires_at=(FIXED_NOW + timedelta(days=180)).isoformat()),
            headers=STEP_UP)
    assert missing.status_code == 400 and missing.json()["error"]["code"] == 40001
    assert missing.json()["error"]["reason"] == "freeze_requires_expiry"
    assert too_long.status_code == 400
    assert too_long.json()["error"]["reason"] == "freeze_window_exceeded"
    assert past.status_code == 400 and past.json()["error"]["reason"] == "freeze_expiry_in_past"
    assert boundary.status_code == 201                          # 边界 180 天允许


def test_decision_without_evidence_is_48004(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="opened")
    with build_client(savepoint_conn) as client:
        no_evidence = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                                  json=_freeze_body(evidence_refs=[]), headers=STEP_UP)
        no_reason = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                                json=_freeze_body(reason=""), headers=STEP_UP)
    assert no_evidence.status_code == 400
    assert no_evidence.json()["error"]["code"] == 48004
    assert no_reason.status_code == 400
    assert no_reason.json()["error"]["code"] == 40001


def test_separation_of_duty_on_self_freeze(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="opened", opened_by="maker")
    maker = {"admin_id": "maker", "tenant_id": "tenant-a",
             "scopes": ["risk.read", "risk.write"]}
    with build_client(savepoint_conn, admin=maker) as client:
        response = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                               json=_freeze_body(), headers=STEP_UP)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 48006


def test_illegal_transition_is_409(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="opened")
    with build_client(savepoint_conn) as client:
        response = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                               json=_freeze_body(action="close"), headers=STEP_UP)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40919
    assert response.json()["error"]["reason"] == "illegal_transition"


def test_terminal_case_rejects_further_decisions(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="closed", decided_at=FIXED_NOW,
                     decided_by="disposer")
    with build_client(savepoint_conn) as client:
        response = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                               json=_freeze_body(action="close"), headers=STEP_UP)
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "case_terminal"


def test_retire_blocked_during_open_appeal(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="appealed", decided_at=FIXED_NOW - timedelta(days=2),
                     decided_by="disposer")
    make_appeal(savepoint_conn, str(case["case_id"]))
    with build_client(savepoint_conn) as client:
        response = client.post(
            f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
            json=_freeze_body(action="retire_proposal", expires_at=None), headers=STEP_UP)
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "appeal_window_open"


def test_merge_and_close_emit_case_closed(savepoint_conn) -> None:
    subject = "sha256:" + uuid.uuid4().hex.ljust(64, "0")[:64]
    source = make_case(savepoint_conn, status="actioned", subject_hash=subject,
                       risk_type="self_trade", decided_at=FIXED_NOW - timedelta(days=3))
    target = make_case(savepoint_conn, status="actioned", subject_hash=subject,
                       risk_type="sybil", decided_at=FIXED_NOW - timedelta(days=1))
    with build_client(savepoint_conn) as client:
        merged = client.post(f"/api/v1/admin/risk/cases/{source['case_id']}/decisions",
                             json=_freeze_body(action="merge",
                                               merge_into=str(target["case_id"])),
                             headers=STEP_UP)
        closed = client.post(f"/api/v1/admin/risk/cases/{target['case_id']}/decisions",
                             json=_freeze_body(action="close"), headers=STEP_UP)
    assert merged.status_code == 201, merged.text
    merged_row = store.get_case(savepoint_conn, str(source["case_id"]))
    assert merged_row["status"] == "merged"
    assert str(merged_row["merged_into"]) == str(target["case_id"])
    assert closed.status_code == 201
    closed_events = [event for event in outbox_events(savepoint_conn)
                     if event["type"] == "risk.case.closed"]
    outcomes = {event["payload"]["outcome"] for event in closed_events}
    assert {"merged", "closed"} <= outcomes


def test_decision_idempotency_replay_single_proposal(savepoint_conn) -> None:
    case = make_case(savepoint_conn, status="opened")
    key = "idem-" + uuid.uuid4().hex
    headers = {**STEP_UP, "X-DJB-Idempotency-Key": key}
    with build_client(savepoint_conn) as client:
        first = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                            json=_freeze_body(), headers=headers)
        replay = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                             json=_freeze_body(), headers=headers)
    assert first.status_code == 201 and replay.status_code == 201
    assert replay.json()["proposal_id"] == first.json()["proposal_id"]
    proposals = [event for event in outbox_events(savepoint_conn)
                 if event["type"] == "risk.action.requested"]
    assert len(proposals) == 1
    row = store.get_case(savepoint_conn, str(case["case_id"]))
    assert len(store.case_decisions(row)) == 1


def test_case_detail_and_listing_are_tenant_scoped(savepoint_conn) -> None:
    subject = "sha256:" + uuid.uuid4().hex.ljust(64, "0")[:64]
    case = make_case(savepoint_conn, status="opened", subject_hash=subject)
    with build_client(savepoint_conn) as client:
        detail = client.get(f"/api/v1/admin/risk/cases/{case['case_id']}")
        listing = client.get("/api/v1/admin/risk/cases", params={"subject": subject})
        filtered = client.get("/api/v1/admin/risk/cases", params={"status": "opened"})
        missing = client.get(f"/api/v1/admin/risk/cases/{uuid.uuid4()}")
        bad_uuid = client.get("/api/v1/admin/risk/cases/not-a-uuid")
    assert detail.status_code == 200
    body = detail.json()
    assert body["case"]["case_id"] == str(case["case_id"])
    assert body["evidence_refs"] == ["evt-0001"]
    assert body["decisions"] == []
    assert body["appeals"] == []
    assert listing.status_code == 200
    assert any(row["case_id"] == str(case["case_id"]) for row in listing.json()["data"])
    assert filtered.status_code == 200
    assert missing.status_code == 404 and missing.json()["error"]["code"] == 40401
    assert bad_uuid.status_code == 404

    with build_client(savepoint_conn, admin=OTHER_TENANT_PRINCIPAL) as other:
        cross = other.get(f"/api/v1/admin/risk/cases/{case['case_id']}")
        cross_list = other.get("/api/v1/admin/risk/cases")
    assert cross.status_code == 404
    assert cross_list.json()["data"] == []


def test_case_listing_filters_and_pagination(savepoint_conn) -> None:
    subject = "sha256:" + uuid.uuid4().hex.ljust(64, "0")[:64]
    for index in range(3):
        make_case(savepoint_conn, status="opened", subject_hash=subject,
                  risk_type=("self_trade", "sybil", "key_leak")[index])
    with build_client(savepoint_conn) as client:
        page = client.get("/api/v1/admin/risk/cases", params={"limit": 2})
        assert page.status_code == 200
        assert len(page.json()["data"]) == 2
        assert page.json()["page"]["has_more"] is True
        nxt = page.json()["page"]["next_cursor"]
        page2 = client.get("/api/v1/admin/risk/cases",
                           params={"limit": 2, "cursor": nxt})
        assert page2.status_code == 200
        ids1 = {row["case_id"] for row in page.json()["data"]}
        ids2 = {row["case_id"] for row in page2.json()["data"]}
        assert ids1.isdisjoint(ids2)


def test_unknown_case_returns_404(savepoint_conn) -> None:
    with build_client(savepoint_conn) as client:
        response = client.post(f"/api/v1/admin/risk/cases/{uuid.uuid4()}/decisions",
                               json=_freeze_body(), headers=STEP_UP)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


def _accounts_fingerprint(connection) -> tuple:
    """accounts / user_accounts 全表指纹：证明处置没有改账户状态（INV-04）。"""
    out = []
    with connection.cursor() as cur:
        for table in ("accounts", "user_accounts"):
            cur.execute(f"SELECT count(*) FROM {table}")     # noqa: S608 - 固定表名
            count = cur.fetchone()[0]
            cur.execute(
                f"SELECT coalesce(md5(string_agg(t::text, '|' ORDER BY t::text)), '')"
                f" FROM {table} t")
            out.append((table, count, cur.fetchone()[0]))
    return tuple(out)


def test_audit_sink_records_decision_reason(savepoint_conn) -> None:
    """INV-07：处置必须同时写审计并留 decision 理由（sink 注入点）。"""
    records: list[dict] = []
    case = make_case(savepoint_conn, status="opened")
    with build_client(savepoint_conn, audit_sink=records.append) as client:
        response = client.post(f"/api/v1/admin/risk/cases/{case['case_id']}/decisions",
                               json=_freeze_body(), headers=STEP_UP)
    assert response.status_code == 201
    assert records, "处置没有调用审计 sink（INV-07）"
    record = records[0]
    assert record["action"] == "freeze"
    assert record["object_type"] == "risk_case"
    assert record["actor"] == "disposer"
    assert record["reason"] == "同主体挂单吃单（证据见引用）"
    assert record["proposal_id"] == response.json()["proposal_id"]
