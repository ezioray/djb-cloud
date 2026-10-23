# SPDX-License-Identifier: Apache-2.0
"""M08 退款原路服务端推导 + 掩码展示（契约 1.2.7 / INV-12）。

覆盖 Lead 口径：

1) GET /pay/orders/{id} → original_route_masked（psp:<provider>:****<末4>，null=不可唯一确定）
2) POST /pay/refund-requests 的 original_route 可选：省略 → 从唯一成功 attempt 推导并按其执行；
   提供 → 必须逐字相等；掩码串不接受
3) 无成功 attempt / 多条成功无法唯一确定 → 409 + 40919 + reason=original_route_unavailable
4) 幂等不回归（同键同载荷返回首次结果、不同载荷 409）
"""
from __future__ import annotations

import hashlib
import re
from datetime import timedelta

import pytest

from app.treasury import config_source, errors, models, policy, refund

import m08kit
from m08kit import OTHER_USER_PRINCIPAL, build_client

NOW = m08kit.FIXED_NOW
MASK_RE = re.compile(r"^psp:mock:\*{4}.{1,4}$")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _body(**over):
    payload = {"order_no": "PO-RT-1", "amount_minor": 5_000,
               "reason_code": "unused_balance"}
    payload.update(over)
    return payload


def _refund_row(conn, refund_id):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM refund_requests WHERE refund_request_id = %s",
                    (refund_id,))
        row = cur.fetchone()
        keys = [desc.name for desc in cur.description]
        return dict(zip(keys, row))


# ───────────────────────────────────────────── 1) 省略 → 服务端推导并执行
def test_omit_route_derives_and_executes(client, savepoint_conn):
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RT-1",
                           provider_txn_id="txn-route-1")
    response = client.post("/api/v1/pay/refund-requests", json=_body())
    assert response.status_code == 201, response.text
    body = response.json()
    derived = "psp:mock:txn-route-1"
    assert body["original_route_hash"] == _sha256(derived)
    row = _refund_row(savepoint_conn, body["refund_request_id"])
    assert row["original_route"] == derived          # 真实原路落库（不是掩码）
    assert row["payment_ref"] == derived
    assert "*" not in row["original_route"]
    # 按推导出的真实原路执行（域内生命周期）
    refund_id = body["refund_request_id"]
    approved = refund.approve_refund_request(savepoint_conn, refund_id, approver="auditor",
                                             now=NOW + timedelta(hours=25))
    assert approved["refund"]["status"] == "approved"
    refund.execute_refund_request(savepoint_conn, refund_id, actor="auditor",
                                  now=NOW + timedelta(hours=26))
    completed = refund.complete_refund_request(savepoint_conn, refund_id,
                                               now=NOW + timedelta(hours=27))
    assert completed["refund"]["status"] == "succeeded"
    assert "refund.completed" in [item["type"]
                                  for item in m08kit.outbox_events(savepoint_conn)]


# ───────────────────────────────────────────── 2) 提供 → 必须逐字相等
def test_provided_route_must_match_exactly(client, savepoint_conn):
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RT-2",
                           provider_txn_id="txn-route-2")
    wrong = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RT-2", original_route="psp:mock:txn-route-9"))
    assert wrong.status_code == 409
    assert wrong.json()["error"]["code"] == 40919
    assert wrong.json()["error"]["reason"] == "original_route_only"
    # 大小写不同 = 不逐字相等（1.2.7 明确逐字）
    case_mismatch = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RT-2", original_route="PSP:mock:txn-route-2"))
    assert case_mismatch.status_code == 409
    assert case_mismatch.json()["error"]["reason"] == "original_route_only"
    exact = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RT-2", original_route="psp:mock:txn-route-2"))
    assert exact.status_code == 201, exact.text
    assert exact.json()["original_route_hash"] == _sha256("psp:mock:txn-route-2")


# ───────────────────────────────────────────── 掩码串不接受
def test_masked_route_rejected(client, savepoint_conn):
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RT-3",
                           provider_txn_id="txn-route-3")
    masked = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RT-3", original_route="psp:mock:****te-3"))
    assert masked.status_code == 400
    assert masked.json()["error"]["code"] == 40001
    # 显式空串违反 minLength=1（不静默当省略）
    empty = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RT-3", original_route=""))
    assert empty.status_code == 400
    with savepoint_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM refund_requests WHERE order_no = 'PO-RT-3'")
        assert int(cur.fetchone()[0]) == 0          # 两次拒绝均未落库
    # 显式 null = 省略 → 推导成功
    explicit_null = client.post("/api/v1/pay/refund-requests", json=_body(
        order_no="PO-RT-3", original_route=None))
    assert explicit_null.status_code == 201


# ───────────────────────────────────────────── 3) 无成功 attempt → 409/40919
def test_no_success_attempt_unavailable(client, savepoint_conn):
    # 已入账订单但完全没有 attempt
    m08kit.make_order(savepoint_conn, order_no="PO-RT-4", status="credited",
                      credited_minor=5_000, paid_at=NOW, now=NOW)
    response = client.post("/api/v1/pay/refund-requests", json=_body(order_no="PO-RT-4"))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40919
    assert response.json()["error"]["reason"] == "original_route_unavailable"
    # 只有失败 attempt
    order = m08kit.make_order(savepoint_conn, order_no="PO-RT-5", status="credited",
                              credited_minor=5_000, paid_at=NOW, now=NOW)
    m08kit.make_attempt(savepoint_conn, order, provider_txn_id="txn-failed-5",
                        status="failed")
    failed_only = client.post("/api/v1/pay/refund-requests", json=_body(order_no="PO-RT-5"))
    assert failed_only.status_code == 409
    assert failed_only.json()["error"]["reason"] == "original_route_unavailable"
    # 只有 pending / initiated attempt（有通道单号但未成功）
    order = m08kit.make_order(savepoint_conn, order_no="PO-RT-6", status="credited",
                              credited_minor=5_000, paid_at=NOW, now=NOW)
    m08kit.make_attempt(savepoint_conn, order, provider_txn_id="txn-init-6",
                        status="initiated")
    pending_only = client.post("/api/v1/pay/refund-requests", json=_body(order_no="PO-RT-6"))
    assert pending_only.status_code == 409
    assert pending_only.json()["error"]["reason"] == "original_route_unavailable"


def test_multiple_success_attempts_unavailable(client, savepoint_conn):
    order = m08kit.make_paid_order(savepoint_conn, order_no="PO-RT-7",
                                   provider_txn_id="txn-route-7a")
    m08kit.make_attempt(savepoint_conn, order["order"], provider_txn_id="txn-route-7b")
    response = client.post("/api/v1/pay/refund-requests", json=_body(order_no="PO-RT-7"))
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "original_route_unavailable"


# ───────────────────────────────────────────── 掩码展示形态（GET /pay/orders/{id}）
def test_order_detail_masked_route_shape(client, savepoint_conn):
    order = m08kit.make_paid_order(savepoint_conn, order_no="PO-RT-8",
                                   provider_txn_id="txn-route-8")
    detail = client.get("/api/v1/pay/orders/PO-RT-8")
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    masked = payload["original_route_masked"]
    assert masked == "psp:mock:****" + "txn-route-8"[-4:]
    assert MASK_RE.match(masked)
    assert "txn-route-8" not in masked          # 完整引用不外泄
    # 其他账户不可见（404，不泄露）
    with build_client(savepoint_conn, user=OTHER_USER_PRINCIPAL) as other:
        assert other.get("/api/v1/pay/orders/PO-RT-8").status_code == 404


def test_order_detail_masked_none_when_not_unique(client, savepoint_conn):
    m08kit.make_order(savepoint_conn, order_no="PO-RT-9", status="created")
    no_attempt = client.get("/api/v1/pay/orders/PO-RT-9").json()
    assert "original_route_masked" in no_attempt
    assert no_attempt["original_route_masked"] is None
    order = m08kit.make_paid_order(savepoint_conn, order_no="PO-RT-10",
                                   provider_txn_id="txn-route-10a")
    m08kit.make_attempt(savepoint_conn, order["order"], provider_txn_id="txn-route-10b")
    ambiguous = client.get("/api/v1/pay/orders/PO-RT-10").json()
    assert ambiguous["original_route_masked"] is None


# ───────────────────────────────────────────── 4) 幂等不回归
def test_idempotency_no_regression(client, savepoint_conn):
    m08kit.make_paid_order(savepoint_conn, order_no="PO-RT-11",
                           provider_txn_id="txn-route-11")
    headers = {"X-DJB-Idempotency-Key": "refund-route-idem-0001"}
    first = client.post("/api/v1/pay/refund-requests", json=_body(order_no="PO-RT-11"),
                        headers=headers)
    assert first.status_code == 201, first.text
    replay = client.post("/api/v1/pay/refund-requests", json=_body(order_no="PO-RT-11"),
                         headers=headers)
    assert replay.status_code == 201
    assert replay.json()["refund_no"] == first.json()["refund_no"]
    with savepoint_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM refund_requests WHERE order_no = 'PO-RT-11'")
        assert int(cur.fetchone()[0]) == 1
    changed = client.post("/api/v1/pay/refund-requests",
                          json=_body(order_no="PO-RT-11", amount_minor=4_000),
                          headers=headers)
    assert changed.status_code == 409
    assert changed.json()["error"]["reason"] == "idempotency_key_reused"


def test_models_mask_and_policy_resolution_units():
    assert models.mask_original_route(None) is None
    assert models.mask_original_route("psp:mock:txn-abcd") == "psp:mock:****abcd"
    assert models.mask_original_route("chain:polygon:0xdeadbeef") == \
        "chain:polygon:****beef"
    assert models.mask_original_route("short") == "****hort"
    attempts = [{"provider": "mock", "provider_txn_id": "t1", "status": "succeeded"}]
    assert policy.resolve_original_route(attempts) == "psp:mock:t1"
    with pytest.raises(errors.Conflict):
        policy.resolve_original_route([])

# ───────────────────────────────────────────── CR-11：内部构造覆盖推导失败分支
def test_internal_construction_unavailable_details(savepoint_conn):
    """CR-11：公开 API 顺序下（未支付先报 order_not_payable）不易直达推导失败分支，
    这里用 tests/treasury 内部 fixture 直接造 0 / 2 个成功 attempt 的订单，
    调 refund.create_refund_request（服务端推导路径，不走 HTTP），断言错误码/原因/条数。"""
    config = config_source.load(None)

    def draft(order_no: str) -> models.RefundDraft:
        return models.RefundDraft(order_no=order_no, amount_minor=1_000,
                                  reason_code="unused_balance")

    # ① 0 个成功 attempt（已入账订单，能过 order_payable；但尝试表为空）
    m08kit.make_order(savepoint_conn, order_no="PO-CR11-0", status="credited",
                      credited_minor=5_000, paid_at=NOW, now=NOW)
    with pytest.raises(errors.Conflict) as zero_error:
        refund.create_refund_request(savepoint_conn, draft("PO-CR11-0"),
                                     account_id="acct-1", requested_by="acct-1",
                                     idempotency_key=None, config=config,
                                     consumed_provider=None, risk_check=None, now=NOW)
    zero = zero_error.value
    assert zero.status_code == 409 and zero.code == 40919
    assert zero.reason == "original_route_unavailable"
    assert zero.details["successful_attempts"] == 0

    # ② 2 个成功 attempt → 无法唯一确定原路
    order = m08kit.make_order(savepoint_conn, order_no="PO-CR11-2", status="credited",
                              credited_minor=5_000, paid_at=NOW, now=NOW)
    m08kit.make_attempt(savepoint_conn, order, provider_txn_id="txn-cr11-a",
                        status="succeeded")
    m08kit.make_attempt(savepoint_conn, order, provider_txn_id="txn-cr11-b",
                        status="succeeded")
    with pytest.raises(errors.Conflict) as two_error:
        refund.create_refund_request(savepoint_conn, draft("PO-CR11-2"),
                                     account_id="acct-1", requested_by="acct-1",
                                     idempotency_key=None, config=config,
                                     consumed_provider=None, risk_check=None, now=NOW)
    two = two_error.value
    assert two.status_code == 409 and two.code == 40919
    assert two.reason == "original_route_unavailable"
    assert two.details["successful_attempts"] == 2

    # ③ 对照：未支付订单在公开顺序里先命中 order_not_payable（说明为何用内部构造）
    m08kit.make_order(savepoint_conn, order_no="PO-CR11-U", status="created")
    with pytest.raises(errors.Conflict) as unpaid_error:
        refund.create_refund_request(savepoint_conn, draft("PO-CR11-U"),
                                     account_id="acct-1", requested_by="acct-1",
                                     idempotency_key=None, config=config,
                                     consumed_provider=None, risk_check=None, now=NOW)
    assert unpaid_error.value.reason == "order_not_payable"
    assert "successful_attempts" not in unpaid_error.value.details

