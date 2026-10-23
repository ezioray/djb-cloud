# SPDX-License-Identifier: Apache-2.0
"""M08c 退款（14 天 / 原路 / 双人 24h 冷却；INV-12）。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.treasury import config_source, errors, models, refund, store

import m08kit
from conftest import OTHER_USER_PRINCIPAL, build_client

NOW = m08kit.FIXED_NOW


def _body(**over):
    payload = {"order_no": "PO-RF-1", "amount_minor": 5_000, "reason_code": "unused_balance",
               "original_route": "psp:mock:txn-ref"}
    payload.update(over)
    return payload


def test_create_refund_requires_step_up_and_validates(client, savepoint_conn):
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RF-1", provider_txn_id="txn-ref")
    with build_client(savepoint_conn, step_up=False) as no_step:
        response = no_step.post("/api/v1/pay/refund-requests", json=_body())
        assert response.status_code == 424
        assert response.json()["error"]["code"] == 42401
    created = client.post("/api/v1/pay/refund-requests", json=_body())
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["status"] == "requested" and body["refund_no"]
    assert body["original_route_hash"] and body["deadline_at"]
    assert body["currency"] == "USD"
    # 同订单重复申请 → 40917
    duplicate = client.post("/api/v1/pay/refund-requests", json=_body(amount_minor=1_000))
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == 40917
    # 第三方地址（原路不符）→ 409
    other_order = m08kit.make_paid_order(savepoint_conn, order_no="PO-RF-2",
                                         provider_txn_id="txn-ref2")
    third_party = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RF-2", original_route="psp:mock:txn-evil"))
    assert third_party.status_code == 409
    assert third_party.json()["error"]["reason"] == "original_route_only"


def test_refund_window_and_amount(client, savepoint_conn):
    old = NOW - timedelta(days=20)
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RF-OLD", provider_txn_id="txn-old",
                           now=old)
    expired = client.post("/api/v1/pay/refund-requests", json=_body(order_no="PO-RF-OLD",
                                                                    original_route="psp:mock:txn-old"))
    assert expired.status_code == 409
    assert expired.json()["error"]["reason"] == "refund_window_expired"
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RF-3", provider_txn_id="txn-3")
    over = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RF-3", amount_minor=20_000, original_route="psp:mock:txn-3"))
    assert over.status_code == 409
    assert over.json()["error"]["code"] == 40911
    missing_order = client.post("/api/v1/pay/refund-requests", json=_body(order_no="PO-NOPE",
                                                                         original_route="psp:mock:x"))
    assert missing_order.status_code == 404


def test_refund_approve_cooldown_and_lifecycle(client, savepoint_conn):
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RF-4", provider_txn_id="txn-4")
    created = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RF-4", original_route="psp:mock:txn-4")).json()
    refund_id = created["refund_request_id"]
    # 24h 冷却未结束（域内审批；HTTP 面只暴露申请 / 查询）
    with pytest.raises(errors.Conflict) as early:
        refund.approve_refund_request(savepoint_conn, refund_id, approver="auditor-9",
                                      now=NOW + timedelta(hours=1))
    assert early.value.reason == "refund_cooldown"
    # 双人：审批人 ≠ 申请人
    with pytest.raises(errors.Conflict) as same:
        refund.approve_refund_request(savepoint_conn, refund_id, approver="acct-1",
                                      now=NOW + timedelta(hours=25))
    assert same.value.reason == "separation_of_duty"
    # 正常：冷却后由他人审批 → 执行 → 完成（域内完成，HTTP 面只有 approve/execute 的域内等价）
    approved = refund.approve_refund_request(savepoint_conn, refund_id, approver="auditor-9",
                                             now=NOW + timedelta(hours=25))
    assert approved["refund"]["status"] == "approved"
    executing = refund.execute_refund_request(savepoint_conn, refund_id, actor="auditor-9",
                                              now=NOW + timedelta(hours=26))
    assert executing["refund"]["status"] == "executing"
    completed = refund.complete_refund_request(savepoint_conn, refund_id,
                                               now=NOW + timedelta(hours=27))
    assert completed["refund"]["status"] == "succeeded"
    assert "refund.completed" in [item["type"] for item in m08kit.outbox_events(savepoint_conn)]
    view = refund.refund_view(savepoint_conn, refund_id, account_id="acct-1")
    assert view["status"] == "succeeded"
    with pytest.raises(errors.NotFound):
        refund.refund_view(savepoint_conn, refund_id, account_id="acct-2")


def test_refund_failed_blocks_new_request(savepoint_conn):
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RF-5", provider_txn_id="txn-5")
    cfg = config_source.load(None)
    created = refund.create_refund_request(
        savepoint_conn, models.RefundDraft(order_no="PO-RF-5", amount_minor=1_000,
                                           reason_code="unused",
                                           original_route="psp:mock:txn-5"),
        account_id="acct-1", requested_by="acct-1", idempotency_key=None, config=cfg,
        consumed_provider=None, risk_check=None, now=NOW)
    refund.fail_refund_request(savepoint_conn, created["refund"]["refund_request_id"],
                               failure_code="original_route_unavailable", now=NOW)
    with pytest.raises(errors.RefundFailed):
        refund.create_refund_request(
            savepoint_conn, models.RefundDraft(order_no="PO-RF-5", amount_minor=500,
                                               reason_code="unused",
                                               original_route="psp:mock:txn-5"),
            account_id="acct-1", requested_by="acct-1", idempotency_key=None, config=cfg,
            consumed_provider=None, risk_check=None, now=NOW)


def test_refund_consumed_provider_and_risk(savepoint_conn):
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RF-6", provider_txn_id="txn-6")
    cfg = config_source.load(None)
    with pytest.raises(errors.AmountMismatch):
        refund.create_refund_request(
            savepoint_conn, models.RefundDraft(order_no="PO-RF-6", amount_minor=9_000,
                                               reason_code="unused",
                                               original_route="psp:mock:txn-6"),
            account_id="acct-1", requested_by="acct-1", idempotency_key=None, config=cfg,
            consumed_provider=lambda order_no: 5_000, risk_check=None, now=NOW)
    with pytest.raises(errors.RiskLevelRequired):
        refund.create_refund_request(
            savepoint_conn, models.RefundDraft(order_no="PO-RF-6", amount_minor=1_000,
                                               reason_code="unused",
                                               original_route="psp:mock:txn-6"),
            account_id="acct-1", requested_by="acct-1", idempotency_key=None, config=cfg,
            consumed_provider=None, risk_check=lambda **kwargs: False, now=NOW)
