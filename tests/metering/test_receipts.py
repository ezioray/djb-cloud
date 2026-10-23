# SPDX-License-Identifier: Apache-2.0
"""收据受理：双签 / 24h 窗口 / 幂等 / 唯一计费 / 留痕 / 不泄露密钥（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.metering import errors, facts, receipts, signing
from meterkit import (
    NOW,
    TEST_CONSUMER_KEY,
    TEST_PROVIDER_KEY,
    connect,
    count,
    fetch_all,
    hours_ago,
    receipt,
)


def _accept(conn, batch, *, node_id=None, now=NOW, keys=None, config=None, check_node=True):
    return receipts.accept_batch(conn, batch, node_id=node_id, trace_id="trace-test", now=now,
                                 keys=keys or signing.SignatureKeys(TEST_PROVIDER_KEY,
                                                                    TEST_CONSUMER_KEY),
                                 config=config, check_node=check_node)


# ─────────────────────────────────────────────────────── 受理 + 落库
def test_accepts_dual_signed_receipt_and_records_usage(migrated, conn, account):
    from meterkit import seed_node
    node_id = "n_t1_accept"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id, request_id="req_accept_1")
    outcome = _accept(conn, [body], node_id=node_id)

    assert outcome.accepted == (body["receipt_id"],)
    assert outcome.rejected == () and outcome.duplicates == ()
    rows = fetch_all(migrated,
                     """SELECT u.request_id, u.attempt_no, u.amount_minor, u.usage_amount,
                               u.usage_unit, u.state, u.usage_source, u.account_id
                          FROM usage_records u WHERE u.request_id = %s""", ("req_accept_1",))
    assert len(rows) == 1
    request_id, attempt_no, amount_minor, usage_amount, usage_unit, state, source, account_id = rows[0]
    assert (amount_minor, usage_amount, usage_unit, state, source) == (125, "1500", "token",
                                                                     "recorded", "dual")
    assert str(account_id) == str(account) and attempt_no == 1
    receipts_rows = fetch_all(migrated,
                              "SELECT state, price_minor FROM metering_receipts "
                              "WHERE receipt_id = %s", (body["receipt_id"],))
    assert receipts_rows == [("accepted", 125)]


def test_accepts_flat_shape_receipt_too(migrated, conn, account):
    node_id = "n_t1_flat"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    body = receipt(shape="flat", account_id=account, node_id=node_id)
    outcome = _accept(conn, [body], node_id=node_id)
    assert outcome.accepted == (body["receipt_id"],)


def test_duplicate_submission_returns_same_usage_without_double_billing(migrated, conn, account):
    """INV-03：同一 receipt_id 重复提交 100 次 → 只有 1 条 usage、1 条 accepted 收据。"""
    node_id = "n_t1_dup"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id)
    first = _accept(conn, [body], node_id=node_id)
    assert first.accepted == (body["receipt_id"],)
    usage_id = fetch_all(migrated, "SELECT usage_id FROM usage_records WHERE receipt_id = %s",
                         (body["receipt_id"],))[0][0]

    for _ in range(100):
        again = _accept(conn, [body], node_id=node_id)
        assert again.accepted == () and again.duplicates == (body["receipt_id"],)
        assert again.verdicts[0].usage_id == str(usage_id)

    assert count(migrated, "usage_records") >= 1
    rows = fetch_all(migrated, "SELECT count(*) FROM usage_records WHERE receipt_id = %s",
                     (body["receipt_id"],))
    assert rows[0][0] == 1
    accepted = fetch_all(migrated, "SELECT count(*) FROM metering_receipts "
                                   "WHERE receipt_id = %s AND state = 'accepted'",
                         (body["receipt_id"],))
    assert accepted[0][0] == 1


# ─────────────────────────────────────────────────────── 24h 窗口（M05 §8.1）
@pytest.mark.parametrize("age_hours,expect_state", [(0, "accepted"), (23, "accepted"),
                                                    (24, "accepted"), (24.001, "expired")])
def test_receipt_window_boundary(migrated, conn, account, age_hours, expect_state):
    node_id = f"n_t1_win_{str(age_hours).replace('.', '_')}"
    from meterkit import seed_node
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id,
                   reported_at=hours_ago(age_hours))
    outcome = _accept(conn, [body], node_id=node_id)
    verdict = outcome.verdicts[0]
    assert verdict.state == expect_state
    if expect_state == "accepted":
        assert outcome.accepted == (body["receipt_id"],)
    else:
        assert verdict.code == 40001 and verdict.reason == "receipt_window_exceeded"
        rows = fetch_all(migrated,
                         """SELECT state, rejected_code FROM metering_receipts
                             WHERE receipt_id = %s""", (body["receipt_id"],))
        assert rows == [("expired", 40001)]


def test_window_uses_config_provider(migrated, conn, account):
    """窗口小时数来自 metering.receipt_late_h（注入 provider 后 1h 也能生效）。"""
    from app.metering import config_source
    from meterkit import seed_node
    node_id = "n_t1_win_cfg"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id, reported_at=hours_ago(2))
    strict = config_source.snapshot(lambda namespace: {"metering.receipt_late_h": 1})
    outcome = _accept(conn, [body], node_id=node_id, config=strict)
    assert outcome.verdicts[0].state == "expired"
    loose = config_source.snapshot(lambda namespace: {"metering.receipt_late_h": 3})
    outcome2 = _accept(conn, [receipt(account_id=account, node_id=node_id,
                                      reported_at=hours_ago(2))], node_id=node_id, config=loose)
    assert outcome2.verdicts[0].state == "accepted"


# ─────────────────────────────────────────────────────── 双签（INV-01 / 46001）
def test_missing_consumer_signature_rejects_only_that_row(migrated, conn, account):
    """验收场景①：缺 sig_consumer → 该条 46001，整批其余 accepted。"""
    from meterkit import seed_node
    node_id = "n_t1_sig"
    seed_node(migrated, node_id)
    bad = receipt(account_id=account, node_id=node_id, sig_consumer="")
    good = receipt(account_id=account, node_id=node_id)
    outcome = _accept(conn, [bad, good], node_id=node_id)

    assert outcome.accepted == (good["receipt_id"],)
    assert [item.receipt_id for item in outcome.rejected] == [bad["receipt_id"]]
    assert outcome.rejected[0].code == 46001
    assert outcome.rejected[0].reason == "missing_consumer_signature"
    # 留痕：被拒行落库，供节点自查与失败率告警
    rows = fetch_all(migrated, "SELECT state, rejected_code, reject_reason "
                               "FROM metering_receipts WHERE receipt_id = %s",
                     (bad["receipt_id"],))
    assert rows == [("rejected", 46001, "missing_consumer_signature")]


def test_missing_provider_signature_is_rejected(migrated, conn, account):
    from meterkit import seed_node
    node_id = "n_t1_sig2"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id, sig_provider="")
    outcome = _accept(conn, [body], node_id=node_id)
    assert outcome.rejected[0].code == 46001
    assert outcome.rejected[0].reason == "missing_provider_signature"


def test_tampered_amount_breaks_signature(migrated, conn, account):
    """伪造金额（改 price 但沿用旧签名）→ 46001，且**不落** usage。"""
    from meterkit import seed_node
    node_id = "n_t1_tamper"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id, request_id="req_tamper_1")
    body["price"] = {"amount": "0.01", "unit": "USD"}
    outcome = _accept(conn, [body], node_id=node_id)
    assert outcome.rejected[0].code == 46001
    rows = fetch_all(migrated, "SELECT count(*) FROM usage_records WHERE request_id = %s",
                     ("req_tamper_1",))
    assert rows[0][0] == 0


def test_cross_signed_sides_are_rejected(migrated, conn, account):
    from meterkit import seed_node
    node_id = "n_t1_cross"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id)
    body["sig_provider"], body["sig_consumer"] = body["sig_consumer"], body["sig_provider"]
    outcome = _accept(conn, [body], node_id=node_id)
    assert outcome.rejected[0].code == 46001


def test_wrong_consumer_key_is_rejected(migrated, conn, account):
    from meterkit import seed_node
    node_id = "n_t1_wrongkey"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id,
                   consumer_key=b"another-consumer-key-0123456789abcdef")
    outcome = _accept(conn, [body], node_id=node_id)
    assert outcome.rejected[0].reason == "consumer_signature_mismatch"


# ─────────────────────────────────────────────────────── 归属 / 账户（安全）
def test_receipt_claiming_other_node_is_rejected(migrated, conn, account):
    """越权提交他人节点收据 → 该条 40001（不泄露他人节点存在性、不落 usage）。"""
    from meterkit import seed_node
    seed_node(migrated, "n_t1_owner")
    seed_node(migrated, "n_t1_other")
    body = receipt(account_id=account, node_id="n_t1_other")
    outcome = _accept(conn, [body], node_id="n_t1_owner")
    assert outcome.rejected[0].code == 40001
    assert outcome.rejected[0].reason == "node_identity_mismatch"
    assert fetch_all(migrated, "SELECT count(*) FROM usage_records WHERE receipt_id = %s",
                     (body["receipt_id"],))[0][0] == 0


def test_receipt_for_unknown_node_is_rejected(migrated, conn, account):
    body = receipt(account_id=account, node_id="n_not_registered")
    outcome = _accept(conn, [body], node_id="n_not_registered")
    assert outcome.rejected[0].code == 40001
    rows = fetch_all(migrated, "SELECT reject_reason FROM metering_receipts WHERE receipt_id = %s",
                     (body["receipt_id"],))
    assert rows[0][0] == "invalid_argument"


def test_missing_account_id_is_rejected(migrated, conn):
    from meterkit import seed_node
    seed_node(migrated, "n_t1_noacct")
    body = receipt(node_id="n_t1_noacct")
    outcome = _accept(conn, [body], node_id="n_t1_noacct")
    assert outcome.rejected[0].code == 40001
    assert "account_id" in outcome.rejected[0].message


def test_node_check_can_be_skipped_for_warmup(migrated, conn, account):
    body = receipt(account_id=account, node_id="n_not_in_snapshot")
    outcome = _accept(conn, [body], node_id="n_not_in_snapshot", check_node=False)
    assert outcome.accepted == (body["receipt_id"],)


# ─────────────────────────────────────────────────────── 唯一计费（INV-04）
def test_same_request_other_attempt_is_billable_but_same_attempt_is_not(migrated, conn, account):
    from meterkit import seed_node
    node_id = "n_t1_attempt"
    seed_node(migrated, node_id)
    first = receipt(account_id=account, node_id=node_id, request_id="req_attempt_1", attempt_no=1)
    assert _accept(conn, [first], node_id=node_id).accepted == (first["receipt_id"],)

    # 同 (request, attempt) 换一个 receipt_id → 拒收（一次请求只计费一次）
    second = receipt(account_id=account, node_id=node_id, request_id="req_attempt_1", attempt_no=1)
    outcome = _accept(conn, [second], node_id=node_id)
    assert outcome.rejected[0].code == 40001
    assert outcome.rejected[0].reason == "duplicate_request_attempt"

    # 另一个尝试可以计费
    third = receipt(account_id=account, node_id=node_id, request_id="req_attempt_1", attempt_no=2)
    assert _accept(conn, [third], node_id=node_id).accepted == (third["receipt_id"],)
    rows = fetch_all(migrated, "SELECT attempt_no FROM usage_records WHERE request_id = %s "
                               "ORDER BY attempt_no", ("req_attempt_1",))
    assert [row[0] for row in rows] == [1, 2]


# ─────────────────────────────────────────────────────── 金额复算（INV-05，注入成交价）
def test_amount_recomputed_from_booking_price_must_match(migrated, conn, account, monkeypatch):
    """验收场景②：1000 tokens × 0.0008 + 500 tokens × 0.0010 = $1.30，与收据一致才受理。"""
    from meterkit import seed_node
    node_id = "n_t1_amount"
    seed_node(migrated, node_id)
    monkeypatch.setattr(receipts, "_price_provider",
                        lambda request_id, model, access: {"in_price_micro": 800,
                                                           "out_price_micro": 1000},
                        raising=False)
    matched = receipt(account_id=account, node_id=node_id, price_amount="1.30",
                      request_id="req_amount_ok")
    outcome = _accept(conn, [matched], node_id=node_id)
    assert outcome.accepted == (matched["receipt_id"],)
    assert fetch_all(migrated, "SELECT amount_minor FROM usage_records WHERE request_id = %s",
                     ("req_amount_ok",))[0][0] == 130

    mismatched = receipt(account_id=account, node_id=node_id, price_amount="1.25",
                         request_id="req_amount_bad")
    outcome2 = _accept(conn, [mismatched], node_id=node_id)
    assert outcome2.rejected[0].code == 40001
    assert outcome2.rejected[0].reason == "amount_mismatch"
    assert fetch_all(migrated, "SELECT count(*) FROM usage_records WHERE request_id = %s",
                     ("req_amount_bad",))[0][0] == 0


def test_price_provider_failure_does_not_block_recording(migrated, conn, account, monkeypatch):
    from meterkit import seed_node
    node_id = "n_t1_pricefail"
    seed_node(migrated, node_id)

    def boom(request_id, model, access):
        raise RuntimeError("booking service down")

    monkeypatch.setattr(receipts, "_price_provider", boom, raising=False)
    body = receipt(account_id=account, node_id=node_id)
    outcome = _accept(conn, [body], node_id=node_id)
    assert outcome.accepted == (body["receipt_id"],)


# ─────────────────────────────────────────────────────── 批量 / 密钥 / 不泄露
def test_batch_size_bounds(migrated, conn, account):
    with pytest.raises(errors.InvalidArgument):
        _accept(conn, [])
    too_many = [receipt(account_id=account) for _ in range(facts.BATCH_MAX + 1)]
    with pytest.raises(errors.BatchTooLarge) as exc:
        _accept(conn, too_many)
    assert exc.value.status_code == 413 and exc.value.code == "40013"


def test_keys_unavailable_fails_closed(migrated, conn, account, monkeypatch):
    """密钥未接线 → KeysUnavailable（fail-closed，绝不降级放行或当作节点签名错误）。"""
    from app.metering import signing

    monkeypatch.setattr(signing, "_keys_provider", None, raising=False)
    monkeypatch.delenv(signing.ENV_PROVIDER_KEY, raising=False)
    monkeypatch.delenv(signing.ENV_CONSUMER_KEY, raising=False)
    with pytest.raises(errors.KeysUnavailable):
        receipts.accept_batch(conn, [receipt(account_id=account)], node_id=None, now=NOW)


def test_no_key_material_or_prompt_in_database(migrated, conn, account):
    """INV-10：库里的收据行不含密钥、不含 prompt / response 正文。"""
    from meterkit import seed_node
    node_id = "n_t1_leak"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id)
    _accept(conn, [body], node_id=node_id)
    rows = fetch_all(migrated, "SELECT * FROM metering_receipts WHERE receipt_id = %s",
                     (body["receipt_id"],))
    serialised = " ".join(str(value) for row in rows for value in row)
    assert TEST_PROVIDER_KEY.decode() not in serialised
    assert TEST_CONSUMER_KEY.decode() not in serialised
    for forbidden in ("prompt", "response", "content", "secret", "password"):
        assert forbidden not in serialised.lower().replace("hmac-sha256", "")
    usage_rows = fetch_all(migrated, "SELECT * FROM usage_records WHERE receipt_id = %s",
                           (body["receipt_id"],))
    assert "prompt" not in " ".join(str(value) for row in usage_rows for value in row).lower()


def test_events_are_built_for_accepted_rows_only(migrated, conn, account):
    from meterkit import seed_node
    node_id = "n_t1_events"
    seed_node(migrated, node_id)
    good = receipt(account_id=account, node_id=node_id)
    bad = receipt(account_id=account, node_id=node_id, sig_provider="")
    outcome = _accept(conn, [good, bad], node_id=node_id)
    types = [envelope["type"] for envelope in outcome.events]
    assert types == ["receipt.signed", "usage.recorded"]
    for envelope in outcome.events:
        assert envelope["producer"] == "M05"
        assert envelope["trace_id"] == "trace-test"
    recorded = outcome.events[1]["payload"]
    assert recorded["amount_minor"] == 125 and isinstance(recorded["amount_minor"], int)
    assert outcome.rejected[0].code == 46001


# ─────────────────────────────────────────────────────── 节点自查（GET 语义）
def test_receipt_status_reports_accepted_and_rejected(migrated, conn, account):
    from meterkit import seed_node
    node_id = "n_t1_status"
    seed_node(migrated, node_id)
    good = receipt(account_id=account, node_id=node_id)
    bad = receipt(account_id=account, node_id=node_id, sig_consumer="")
    _accept(conn, [good, bad], node_id=node_id)

    accepted = receipts.receipt_status(conn, receipt_id=good["receipt_id"], node_id=node_id)
    assert accepted["state"] == "accepted" and accepted["received_at"].endswith("Z")
    assert "code" not in accepted

    rejected = receipts.receipt_status(conn, receipt_id=bad["receipt_id"], node_id=node_id)
    assert rejected["state"] == "rejected" and rejected["code"] == 46001

    assert receipts.receipt_status(conn, receipt_id="rcpt_missing", node_id=node_id) is None
    # 跨节点查询一律 None（不泄露存在性）
    assert receipts.receipt_status(conn, receipt_id=good["receipt_id"],
                                   node_id="n_someone_else") is None


def test_node_in_snapshot_is_read_only_view(migrated, conn):
    from meterkit import seed_node
    seed_node(migrated, "n_t1_view")
    assert receipts.node_in_snapshot(conn, "n_t1_view") is True
    assert receipts.node_in_snapshot(conn, "n_t1_missing") is False


# ─────────────────────────────────────────────────────── 竞态兜底与状态回显
def test_resolve_conflict_falls_back_to_first_result_for_same_receipt(migrated, conn, account):
    """竞态：两条并发提交同一 receipt_id → 唯一键冲突按首次结果回落（duplicate）。"""
    from app.metering import models
    from meterkit import seed_node

    node_id = "n_t1_race"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id)
    assert _accept(conn, [body], node_id=node_id).accepted == (body["receipt_id"],)
    draft = models.parse_receipt(body, now=NOW)
    verdict, envelopes = receipts._resolve_conflict(
        conn, draft, RuntimeError("unique violation"), node_id=node_id, now=NOW)
    assert verdict.duplicate is True and verdict.state == "accepted"
    assert envelopes == []


def test_resolve_conflict_rejects_when_request_attempt_already_billed(migrated, conn, account):
    from app.metering import models
    from meterkit import seed_node

    node_id = "n_t1_race2"
    seed_node(migrated, node_id)
    first = receipt(account_id=account, node_id=node_id, request_id="req_race_2")
    assert _accept(conn, [first], node_id=node_id).accepted == (first["receipt_id"],)
    second = receipt(account_id=account, node_id=node_id, request_id="req_race_2")
    draft = models.parse_receipt(second, now=NOW)
    verdict, envelopes = receipts._resolve_conflict(
        conn, draft, RuntimeError("unique violation"), node_id=node_id, now=NOW)
    assert verdict.state == "rejected" and verdict.reason == "duplicate_request_attempt"
    assert verdict.code == 40001 and envelopes == []


def test_receipt_status_reports_settled_at_after_settlement(migrated, conn, account):
    from meterkit import seed_node

    node_id = "n_t1_settled"
    seed_node(migrated, node_id)
    body = receipt(account_id=account, node_id=node_id)
    _accept(conn, [body], node_id=node_id)
    with connect(migrated) as writer:
        writer.execute("UPDATE usage_records SET state='settled', settled_at=%s "
                       "WHERE receipt_id=%s", (NOW, body["receipt_id"]))
    status = receipts.receipt_status(conn, receipt_id=body["receipt_id"], node_id=node_id)
    assert status["state"] == "accepted"
    assert status["settled_at"] == "2026-10-23T04:00:00Z"


def test_current_price_provider_getter_reflects_injection(monkeypatch):
    """注入钩子的读回（合并时 Lead 用它确认接线状态）。"""
    assert receipts.current_price_provider() is None
    provider = lambda request_id, model, access: None       # noqa: E731
    monkeypatch.setattr(receipts, "_price_provider", provider, raising=False)
    assert receipts.current_price_provider() is provider
