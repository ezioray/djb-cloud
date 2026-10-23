# SPDX-License-Identifier: Apache-2.0
"""校正：只追加 / 累计不超原额 / 双人复核 / 幂等 / usage.settled（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid

import pytest

from app.metering import corrections, errors, facts, outbox, receipts, signing
from meterkit import NOW, TEST_CONSUMER_KEY, TEST_PROVIDER_KEY, connect, fetch_all, receipt


def _usage(schema: str, *, amount_minor: int = 10_000, account_id=None,
           state: str = "recorded") -> str:
    usage_id = str(uuid.uuid4())
    with connect(schema) as conn:
        conn.execute(
            """INSERT INTO usage_records
                 (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                  tokens_in, tokens_out, usage_amount, usage_unit, amount_minor, usage_source,
                  state, receipt_id, recorded_at)
               VALUES (%s,%s,1,%s,'n1','m1','A1',1000,500,'1500','token',%s,'dual','recorded',
                       %s,%s)""",
            (usage_id, f"req_{uuid.uuid4().hex[:10]}", account_id or uuid.uuid4(),
             amount_minor, f"rcpt_{uuid.uuid4().hex[:10]}", NOW))
        if state == "settled":
            conn.execute("UPDATE usage_records SET state='settled', settled_at=%s "
                         "WHERE usage_id=%s", (NOW, usage_id))
    return usage_id


def _input(usage_id: str, delta_minor: int, *, reason: str = "overbill",
           requested_by: str = "ops-1", second_approver: str | None = None,
           upstream_bill_id: str | None = None,
           request_key: str | None = None) -> corrections.CorrectionInput:
    return corrections.CorrectionInput(usage_id=usage_id, delta_minor=delta_minor,
                                       reason_code=reason, requested_by=requested_by,
                                       second_approver=second_approver,
                                       upstream_bill_id=upstream_bill_id,
                                       request_key=request_key)


# ─────────────────────────────────────────────────────── 提交 / 复核门槛
def test_propose_positive_small_delta_needs_no_approver(migrated, conn):
    usage_id = _usage(migrated, amount_minor=10_000)
    result = corrections.propose(conn, _input(usage_id, 1_000))    # 10 USD
    assert result["created"] is True
    correction = result["correction"]
    assert correction["state"] == "proposed" and correction["delta_minor"] == 1_000
    assert correction["original_minor"] == 10_000


def test_propose_negative_delta_requires_second_approver(migrated, conn):
    usage_id = _usage(migrated)
    with pytest.raises(errors.Conflict) as exc:
        corrections.propose(conn, _input(usage_id, -1_000))
    assert exc.value.status_code == 409 and exc.value.code == "40902"
    assert exc.value.reason == "dual_approval_required"


def test_propose_rejects_same_approver(migrated, conn):
    usage_id = _usage(migrated)
    with pytest.raises(errors.Conflict) as exc:
        corrections.propose(conn, _input(usage_id, -1_000, second_approver="ops-1"))
    assert exc.value.reason == "second_approver_must_differ"


def test_propose_threshold_comes_from_config(migrated, conn):
    """≥ ``metering.correction_dual_threshold_usd``（默认 50 USD = 5000 分）需复核。"""
    usage_id = _usage(migrated, amount_minor=100_000)
    with pytest.raises(errors.Conflict):
        corrections.propose(conn, _input(usage_id, 5_000))          # 恰好 50 USD
    ok = corrections.propose(conn, _input(usage_id, 5_000, second_approver="fin-2"))
    assert ok["created"] is True
    assert corrections.needs_dual_approval(5_000, __import__(
        "app.metering.config_source", fromlist=["x"]).snapshot()) is True


def test_propose_rejects_zero_or_unknown_reason(migrated, conn):
    usage_id = _usage(migrated)
    with pytest.raises(errors.InvalidArgument):
        corrections.propose(conn, _input(usage_id, 0))
    with pytest.raises(errors.InvalidArgument):
        corrections.propose(conn, _input(usage_id, 100, reason="guess"))


def test_propose_unknown_usage_is_404(migrated, conn):
    with pytest.raises(errors.NotFound):
        corrections.propose(conn, _input(str(uuid.uuid4()), 100))


# ─────────────────────────────────────────────────────── 累计（INV-08）
def test_cumulative_delta_cannot_exceed_original(migrated, conn):
    usage_id = _usage(migrated, amount_minor=1_000)
    corrections.propose(conn, _input(usage_id, 600, second_approver="fin-2"))
    with pytest.raises(errors.Conflict) as exc:
        # 600 + 500 = 1100 > 1000（proposed 也计入，防止连续提交绕过）
        corrections.propose(conn, _input(usage_id, 500))
    assert exc.value.reason == "cumulative_exceeded"
    remaining = corrections.propose(conn, _input(usage_id, 400))
    assert remaining["created"] is True


def test_within_tolerance_uses_integer_math():
    assert corrections.within_tolerance(100, 10_000, 1.0) is True        # 恰好 1%
    assert corrections.within_tolerance(101, 10_000, 1.0) is False       # 1.01%
    assert corrections.within_tolerance(-100, 10_000, 1.0) is True       # 方向无关
    assert corrections.within_tolerance(0, 0, 1.0) is True
    assert corrections.within_tolerance(1, 0, 1.0) is False


# ─────────────────────────────────────────────────────── 幂等
def test_propose_is_idempotent_by_request_key(migrated, conn):
    usage_id = _usage(migrated)
    key = f"idem-{uuid.uuid4().hex[:10]}"
    first = corrections.propose(conn, _input(usage_id, 100, request_key=key))
    second = corrections.propose(conn, _input(usage_id, 100, request_key=key))
    assert first["created"] is True and second["created"] is False
    assert first["correction"]["correction_id"] == second["correction"]["correction_id"]
    rows = fetch_all(migrated, "SELECT count(*) FROM usage_corrections WHERE usage_id = %s",
                     (usage_id,))
    assert rows[0][0] == 1


def test_propose_is_idempotent_by_upstream_bill(migrated, conn):
    usage_id = _usage(migrated)
    first = corrections.propose(conn, _input(usage_id, 100, upstream_bill_id="bill-1"))
    second = corrections.propose(conn, _input(usage_id, 100, upstream_bill_id="bill-1"))
    assert second["created"] is False
    assert first["correction"]["correction_id"] == second["correction"]["correction_id"]


# ─────────────────────────────────────────────────────── 生效 / 驳回
def test_apply_marks_usage_corrected_and_emits_settled(migrated, conn):
    usage_id = _usage(migrated, amount_minor=10_000)
    proposed = corrections.propose(conn, _input(usage_id, 1_500, second_approver="fin-2"))
    correction_id = proposed["correction"]["correction_id"]
    result = corrections.apply(conn, correction_id, approver="fin-2", trace_id="trace-corr")
    assert result["usage_state"] == "corrected"
    assert result["final_amount_minor"] == 10_000 + 1_500
    rows = fetch_all(migrated, "SELECT state, correction_id, amount_minor FROM usage_records "
                               "WHERE usage_id = %s", (usage_id,))
    assert rows[0][0] == "corrected" and rows[0][1] == correction_id
    assert rows[0][2] == 10_000                                    # 原值未改（INV-06）
    settled = fetch_all(migrated, "SELECT payload FROM metering_outbox WHERE type = %s "
                                  "AND aggregate_id = %s", ("usage.settled", usage_id))
    assert settled and settled[0][0]["final_amount_minor"] == 11_500
    assert settled[0][0]["correction_id"] == correction_id


def test_apply_on_settled_usage_is_allowed_after_508(migrated, conn):
    """迟到账单：usage 已 settled 时仍可追加校正（508 放宽，INV-06）。"""
    usage_id = _usage(migrated, amount_minor=10_000, state="settled")
    proposed = corrections.propose(conn, _input(usage_id, -500, second_approver="fin-2"))
    result = corrections.apply(conn, proposed["correction"]["correction_id"], approver="fin-2")
    assert result["usage_state"] == "corrected"
    assert result["final_amount_minor"] == 9_500
    rows = fetch_all(migrated, "SELECT state, settled_at FROM usage_records WHERE usage_id = %s",
                     (usage_id,))
    assert rows[0][0] == "corrected" and rows[0][1] is not None     # 保留先结算的时序


def test_apply_requires_dual_approval_at_apply_time(migrated, conn):
    """自动对账产生的 proposed（无复核人）必须由他人复核后才能生效。"""
    usage_id = _usage(migrated, amount_minor=100_000)
    proposed = corrections.propose(conn, _input(usage_id, -1_000),
                                   require_approval=False)
    correction_id = proposed["correction"]["correction_id"]
    with pytest.raises(errors.Conflict):
        corrections.apply(conn, correction_id, approver="ops-1")     # 与提交人相同
    applied = corrections.apply(conn, correction_id, approver="fin-9")
    assert applied["correction"]["state"] == "applied"


def test_apply_rejects_non_proposed(migrated, conn):
    usage_id = _usage(migrated)
    proposed = corrections.propose(conn, _input(usage_id, 100))
    correction_id = proposed["correction"]["correction_id"]
    corrections.reject(conn, correction_id, approver="fin-2")
    with pytest.raises(errors.Conflict):
        corrections.apply(conn, correction_id, approver="fin-2")


def test_reject_keeps_usage_untouched(migrated, conn):
    usage_id = _usage(migrated)
    proposed = corrections.propose(conn, _input(usage_id, -100, second_approver="fin-2"))
    correction_id = proposed["correction"]["correction_id"]
    result = corrections.reject(conn, correction_id, approver="fin-2")
    assert result["correction"]["state"] == "rejected"
    rows = fetch_all(migrated, "SELECT state, correction_id FROM usage_records "
                               "WHERE usage_id = %s", (usage_id,))
    assert rows[0] == ("recorded", None)


def test_apply_unknown_correction_is_404(migrated, conn):
    with pytest.raises(errors.NotFound):
        corrections.apply(conn, str(uuid.uuid4()), approver="fin-2")


# ─────────────────────────────────────────────────────── spec 请求解析
def test_from_request_parses_spec_shape():
    body = {"usage_id": "u-1", "delta": {"amount": "-1.50", "unit": "USD"},
            "reason_code": "overbill", "second_approver": "fin-2"}
    item = corrections.from_request(body, requested_by="ops-1", request_key="k-1")
    assert item.delta_minor == -150 and item.reason_code == "overbill"
    assert item.second_approver == "fin-2" and item.request_key == "k-1"


@pytest.mark.parametrize("body", [
    {"delta": {"amount": "1", "unit": "USD"}, "reason_code": "overbill"},
    {"usage_id": "u", "delta": {"amount": "1", "unit": "USD"}, "reason_code": "nope"},
    {"usage_id": "u", "delta": {"amount": "1.234", "unit": "USD"}, "reason_code": "overbill"},
])
def test_from_request_rejects_bad_shapes(body):
    with pytest.raises(errors.InvalidArgument):
        corrections.from_request(body, requested_by="ops-1", request_key=None)


def test_correction_events_are_appended_once_per_apply(migrated, conn):
    usage_id = _usage(migrated, amount_minor=5_000)
    proposed = corrections.propose(conn, _input(usage_id, 500, second_approver="fin-2"))
    corrections.apply(conn, proposed["correction"]["correction_id"], approver="fin-2")
    rows = fetch_all(migrated, "SELECT count(*) FROM metering_outbox WHERE type = %s "
                               "AND aggregate_id = %s", ("usage.settled", usage_id))
    assert rows[0][0] == 1
