# SPDX-License-Identifier: Apache-2.0
"""批量五步：预览 / 双人复核 / 执行 / 10 分钟撤销 / 只读沙箱（INV-03 / INV-09）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from admin_kit import (
    ADMIN_PRINCIPAL,
    FIXED_NOW,
    SECOND_ADMIN,
    FakeBatchExecutor,
    FakeBatchProbe,
    build_client,
    idempotency_key,
    write_headers,
)
from app.data_gov import batch as batch_service, clock, errors, facts, policy

BASE = "/api/v1/admin/ops/batch-ops"


def _ids(count: int, prefix: str = "acct") -> list[str]:
    return [f"{prefix}-{index}" for index in range(count)]


def _preview_body(*, ids_list=None, action: str = "notify", reason: str | None = "批量通知",
                  labels=None, target_object: str = "account") -> dict:
    target: dict = {"object": target_object}
    if ids_list is not None:
        target["ids"] = list(ids_list)
    body: dict = {"step": "preview", "action_type": action, "target": target}
    if reason is not None:
        body["reason"] = reason
    if labels is not None:
        body["labels"] = labels
    return body


def _preview(client, *, tag: str = "pv", **kwargs):
    return client.post(BASE, json=_preview_body(**kwargs), headers=write_headers(tag))


def _execute(client, batch_id: str, *, tag: str = "ex", step: str = "execute"):
    return client.post(BASE, json={"step": step, "batch_id": batch_id},
                       headers=write_headers(tag))


# ─────────────────────────────────────────────────────── 权限 / step-up
def test_batch_requires_authentication_and_admin(unauth_client, nonadmin_client) -> None:
    body = _preview_body(ids_list=["a"])
    assert unauth_client.post(BASE, json=body, headers=write_headers("u")).status_code == 401
    assert nonadmin_client.post(BASE, json=body, headers=write_headers("n")).status_code == 403


def test_batch_requires_step_up(no_stepup_client) -> None:
    response = no_stepup_client.post(BASE, json=_preview_body(ids_list=["a"]),
                                     headers={"X-DJB-Idempotency-Key":
                                              idempotency_key("ns")})
    assert response.status_code == 424


def test_readonly_cannot_execute_batch(readonly_client) -> None:
    response = readonly_client.post(BASE, json=_preview_body(ids_list=["a"]),
                                    headers=write_headers("ro"))
    assert response.status_code == 403


# ─────────────────────────────────────────────────────── 预览
def test_preview_returns_impact_and_sample(savepoint_conn, sink) -> None:
    with build_client(savepoint_conn, audit_sink=sink) as client:
        response = _preview(client, ids_list=_ids(3),
                            labels={"acct-0": "账户 0"})
    assert response.status_code == 201
    payload = response.json()
    assert payload["state"] == "previewed" and payload["step"] == "preview"
    assert payload["count"] == 3 and payload["sample_size"] == 3
    assert set(payload["sample"]) <= set(_ids(3))
    assert all(isinstance(item, str) for item in payload["sample"])
    assert payload["impact"][0] == {"id": "acct-0", "label": "账户 0"}
    assert payload["dual_review_required"] is False
    assert payload["undo_window_s"] == 600 and payload["max_items"] == 200
    assert payload["initiator"] == "ops-admin"
    assert "ops.batch.previewed" in sink.actions()


def test_preview_sample_is_capped_at_ten(client) -> None:
    response = _preview(client, ids_list=_ids(30))
    assert response.status_code == 201
    payload = response.json()
    assert payload["sample_size"] == 10 and len(payload["sample"]) == 10
    assert len(payload["impact"]) == 30


def test_preview_over_200_rejected_with_hint(client) -> None:
    response = _preview(client, ids_list=_ids(201))
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == 49001 and error["reason"] == "batch_too_large"


def test_preview_without_ids_uses_probe(savepoint_conn) -> None:
    probe = FakeBatchProbe(["acct-1", "acct-2"])
    with build_client(savepoint_conn, batch_probe=probe) as client:
        response = _preview(client, ids_list=None)
    assert response.status_code == 201
    assert response.json()["count"] == 2
    assert probe.calls


def test_preview_without_ids_or_probe_is_400(client) -> None:
    assert _preview(client, ids_list=None).status_code == 400


def test_preview_reason_is_optional(client) -> None:
    response = _preview(client, ids_list=["acct-1"], reason=None)
    assert response.status_code == 201
    assert response.json()["reason"] == "批量操作（未提供理由）"


def test_preview_rejects_invalid_body(client) -> None:
    bad_step = client.post(BASE, json={"step": "explode"}, headers=write_headers("bs"))
    assert bad_step.status_code == 400
    bad_action = client.post(BASE, json={"step": "preview", "action_type": "nuke",
                                         "target": {"object": "account", "ids": ["a"]}},
                             headers=write_headers("ba"))
    assert bad_action.status_code == 400
    bad_target = client.post(BASE, json={"step": "preview", "action_type": "notify",
                                         "target": {"object": "planet", "ids": ["a"]}},
                             headers=write_headers("bt"))
    assert bad_target.status_code == 400
    unknown = client.post(BASE, json={**_preview_body(ids_list=["a"]), "surprise": 1},
                          headers=write_headers("bu"))
    assert unknown.status_code == 400


def test_preview_idempotency(client) -> None:
    first = _preview(client, tag="idem-pv", ids_list=_ids(2))
    second = _preview(client, tag="idem-pv", ids_list=_ids(2))
    assert first.json()["batch_id"] == second.json()["batch_id"]
    conflict = _preview(client, tag="idem-pv", ids_list=_ids(3))
    assert conflict.status_code == 409
    assert conflict.json()["error"]["reason"] == "idempotency_key_reused"


# ─────────────────────────────────────────────────────── 执行 / 双人复核
def test_execute_without_preview_is_404(client) -> None:
    response = _execute(client, str(uuid.uuid4()))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401


def test_execute_without_owner_api_fails_closed(savepoint_conn) -> None:
    with build_client(savepoint_conn) as client:
        preview = _preview(client, tag="no-owner", ids_list=_ids(2)).json()
        response = _execute(client, preview["batch_id"], tag="no-owner-ex")
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "owner_api_unavailable"


def test_execute_partial_failure_keeps_successes(savepoint_conn) -> None:
    executor = FakeBatchExecutor(fail_ids={"acct-1"})
    with build_client(savepoint_conn, batch_executor=executor) as client:
        preview = _preview(client, tag="partial", ids_list=_ids(3)).json()
        response = _execute(client, preview["batch_id"], tag="partial-ex")
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "executed"
    assert payload["succeeded_count"] == 2 and payload["failed_count"] == 1
    failed = [item for item in payload["results"] if item["status"] == "failed"]
    assert failed and failed[0]["id"] == "acct-1"
    assert payload["undo_deadline"] is not None
    assert len(executor.calls) == 3


def test_execute_idempotent_replay(savepoint_conn) -> None:
    executor = FakeBatchExecutor()
    with build_client(savepoint_conn, batch_executor=executor) as client:
        preview = _preview(client, tag="replay", ids_list=_ids(2)).json()
        first = _execute(client, preview["batch_id"], tag="replay-ex")
        second = _execute(client, preview["batch_id"], tag="replay-ex")
    assert first.status_code == second.status_code == 200
    assert first.json()["results"] == second.json()["results"]
    assert len(executor.calls) == 2                      # 幂等命中不重复执行


def test_all_failed_marks_batch_failed(savepoint_conn) -> None:
    executor = FakeBatchExecutor(error=RuntimeError("owner down"))
    with build_client(savepoint_conn, batch_executor=executor) as client:
        preview = _preview(client, tag="allfail", ids_list=_ids(2)).json()
        response = _execute(client, preview["batch_id"], tag="allfail-ex")
        undo = _execute(client, preview["batch_id"], tag="allfail-undo", step="undo")
    assert response.json()["state"] == "failed"
    assert undo.status_code == 409


# ─────────────────────────────────────────────────────── 双人复核（>50 条）
def test_dual_review_requires_second_admin(savepoint_conn) -> None:
    shared_store = batch_service.InMemoryBatchStore()
    executor = FakeBatchExecutor()
    with build_client(savepoint_conn, principal=ADMIN_PRINCIPAL,
                      batch_store=shared_store, batch_executor=executor) as initiator, \
            build_client(savepoint_conn, principal=SECOND_ADMIN,
                         batch_store=shared_store, batch_executor=executor) as reviewer:
        preview = _preview(initiator, tag="dual", ids_list=_ids(51)).json()
        assert preview["dual_review_required"] is True
        blocked = _execute(initiator, preview["batch_id"], tag="dual-self")
        assert blocked.status_code == 409
        assert blocked.json()["error"]["reason"] == "review_required"
        assert executor.calls == []                       # 复核前不得执行
        executed = _execute(reviewer, preview["batch_id"], tag="dual-reviewer")
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["state"] == "executed"
    assert payload["approver"] == "ops-admin-b"
    assert payload["succeeded_count"] == 51


def test_freeze_action_forces_dual_review(savepoint_conn) -> None:
    shared_store = batch_service.InMemoryBatchStore()
    with build_client(savepoint_conn, batch_store=shared_store,
                      batch_executor=FakeBatchExecutor()) as initiator:
        preview = _preview(initiator, tag="freeze", action="freeze",
                           ids_list=_ids(2)).json()
        assert preview["dual_review_required"] is True
        blocked = _execute(initiator, preview["batch_id"], tag="freeze-self")
    assert blocked.status_code == 409


# ─────────────────────────────────────────────────────── 撤销（10 分钟窗口）
def test_undo_within_window(savepoint_conn, sink) -> None:
    shared_store = batch_service.InMemoryBatchStore()
    executor = FakeBatchExecutor()
    undoer = FakeBatchExecutor()
    with build_client(savepoint_conn, batch_store=shared_store,
                      batch_executor=executor, batch_undoer=undoer,
                      audit_sink=sink) as client:
        preview = _preview(client, tag="undo", ids_list=_ids(2)).json()
        executed = _execute(client, preview["batch_id"], tag="undo-ex").json()
        response = _execute(client, preview["batch_id"], tag="undo-undo", step="undo")
    assert executed["state"] == "executed"
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "undone" and payload["step"] == "undo"
    assert len(payload["undo_results"]) == 2
    assert len(undoer.calls) == 2
    assert "ops.batch.executed" in sink.actions() and "ops.batch.undone" in sink.actions()


def test_undo_after_window_is_rejected(savepoint_conn) -> None:
    shared_store = batch_service.InMemoryBatchStore()
    with build_client(savepoint_conn, batch_store=shared_store,
                      batch_executor=FakeBatchExecutor()) as client:
        preview = _preview(client, tag="late", ids_list=_ids(2)).json()
        assert _execute(client, preview["batch_id"], tag="late-ex").status_code == 200
    later = FIXED_NOW + timedelta(seconds=facts.BATCH_UNDO_WINDOW_S + 1)
    with build_client(savepoint_conn, now=later, batch_store=shared_store,
                      batch_undoer=FakeBatchExecutor()) as late_client:
        response = _execute(late_client, preview["batch_id"], tag="late-undo",
                            step="undo")
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "undo_window_closed"


def test_undo_without_owner_api_is_409(savepoint_conn) -> None:
    shared_store = batch_service.InMemoryBatchStore()
    with build_client(savepoint_conn, batch_store=shared_store,
                      batch_executor=FakeBatchExecutor()) as client:
        preview = _preview(client, tag="undo-noapi", ids_list=_ids(2)).json()
        _execute(client, preview["batch_id"], tag="undo-noapi-ex")
        response = _execute(client, preview["batch_id"], tag="undo-noapi-undo",
                            step="undo")
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "owner_api_unavailable"


def test_undo_twice_same_key_is_idempotent(savepoint_conn) -> None:
    shared_store = batch_service.InMemoryBatchStore()
    with build_client(savepoint_conn, batch_store=shared_store,
                      batch_executor=FakeBatchExecutor(),
                      batch_undoer=FakeBatchExecutor()) as client:
        preview = _preview(client, tag="undo2", ids_list=_ids(1)).json()
        _execute(client, preview["batch_id"], tag="undo2-ex")
        first = _execute(client, preview["batch_id"], tag="undo2-u", step="undo")
        second = _execute(client, preview["batch_id"], tag="undo2-u", step="undo")
        third = _execute(client, preview["batch_id"], tag="undo2-other", step="undo")
    assert first.status_code == second.status_code == 200
    assert third.status_code == 409


def test_batch_is_tenant_scoped(savepoint_conn) -> None:
    shared_store = batch_service.InMemoryBatchStore()
    with build_client(savepoint_conn, batch_store=shared_store,
                      batch_executor=FakeBatchExecutor()) as client:
        preview = _preview(client, tag="tenant", ids_list=_ids(1)).json()
    other = {"admin_id": "ops-admin-c", "tenant_id": "tenant-b", "scopes": ["*"]}
    with build_client(savepoint_conn, principal=other, batch_store=shared_store,
                      batch_executor=FakeBatchExecutor()) as other_client:
        response = _execute(other_client, preview["batch_id"], tag="tenant-ex")
    assert response.status_code == 404


# ─────────────────────────────────────────────────────── 只读沙箱（INV-09）
def test_sandbox_session_is_read_only_and_bounded() -> None:
    session = batch_service.open_sandbox(actor="auditor", now=FIXED_NOW)
    assert session["read_only"] is True and session["recording"] is True
    expires = clock.parse_datetime(session["expires_at"])
    assert expires <= FIXED_NOW + timedelta(hours=4)
    policy.assert_sandbox_read_only(session, now=FIXED_NOW)
    with pytest.raises(errors.Forbidden):
        policy.assert_sandbox_read_only(session, now=FIXED_NOW, write=True)
    with pytest.raises(errors.Forbidden):
        policy.assert_sandbox_read_only(session, now=FIXED_NOW + timedelta(hours=5))
    with pytest.raises(errors.Forbidden):
        policy.assert_sandbox_read_only({"read_only": False}, now=FIXED_NOW)
    bounded = batch_service.open_sandbox(actor="auditor", now=FIXED_NOW, ttl_s=10 ** 6)
    assert clock.parse_datetime(bounded["expires_at"]) == FIXED_NOW + timedelta(hours=4)
