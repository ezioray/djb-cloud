# SPDX-License-Identifier: AGPL-3.0-or-later
"""上游账单导入与对账：幂等 / 1% 容差 / >1% 追加校正 / 原 usage 不改（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid

import pytest

from app.metering import bills, corrections, errors, facts
from meterkit import NOW, connect, fetch_all


def _usage(schema: str, *, amount_minor: int = 10_000, access: str = "A1",
           state: str = "recorded") -> str:
    usage_id = str(uuid.uuid4())
    with connect(schema) as conn:
        conn.execute(
            """INSERT INTO usage_records
                 (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                  tokens_in, tokens_out, usage_amount, usage_unit, amount_minor, usage_source,
                  state, receipt_id, recorded_at)
               VALUES (%s,%s,1,%s,'n1','m1',%s,1000,500,'1500','token',%s,'dual','recorded',
                       %s,%s)""",
            (usage_id, f"req_{uuid.uuid4().hex[:10]}", uuid.uuid4(), access, amount_minor,
             f"rcpt_{uuid.uuid4().hex[:10]}", NOW))
        if state == "settled":
            conn.execute("UPDATE usage_records SET state='settled', settled_at=%s "
                         "WHERE usage_id=%s", (NOW, usage_id))
    return usage_id


def _row(usage_id: str, amount: str = "100.00", *, row_id: str | None = None,
         access: str = "A1") -> dict:
    return {"row_id": row_id or f"bill_{uuid.uuid4().hex[:10]}", "usage_id": usage_id,
            "access": access, "model": "m1", "amount": {"amount": amount, "unit": "USD"}}


def _import(conn, rows, *, provider="openai", period="2026-10", imported_by="fin-1"):
    return bills.import_rows(conn, provider=provider, period=period, rows=rows,
                             imported_by=imported_by, now=NOW, trace_id="trace-bill")


# ─────────────────────────────────────────────────────── 容差内 → reconciled
def test_within_tolerance_reconciles_and_settles(migrated, conn):
    usage_id = _usage(migrated, amount_minor=10_000)                  # 100.00
    ack = _import(conn, [_row(usage_id, "100.50")])                    # +0.5% ≤ 1%
    assert ack["rows_accepted"] == 1 and ack["rows_rejected"] == 0
    assert ack["results"][0]["status"] == "reconciled"
    assert ack["total_amount"] == {"amount": "100.50", "unit": "USD"}
    rows = fetch_all(migrated, "SELECT state, reconciled_at FROM upstream_bills")
    assert rows and rows[-1][0] == "reconciled" and rows[-1][1] is not None
    usage = fetch_all(migrated, "SELECT state, amount_minor FROM usage_records WHERE usage_id=%s",
                      (usage_id,))
    assert usage[0] == ("settled", 10_000)                            # 原额不变
    settled = fetch_all(migrated, "SELECT payload FROM metering_outbox WHERE type=%s "
                                  "AND aggregate_id=%s", ("usage.settled", usage_id))
    assert settled and settled[0][0]["final_amount_minor"] == 10_000
    # 容差内不产生校正
    assert fetch_all(migrated, "SELECT count(*) FROM usage_corrections WHERE usage_id=%s",
                     (usage_id,))[0][0] == 0


def test_exactly_one_percent_is_within_tolerance(migrated, conn):
    usage_id = _usage(migrated, amount_minor=10_000)
    ack = _import(conn, [_row(usage_id, "101.00")])                    # 恰好 1%
    assert ack["results"][0]["status"] == "reconciled"


# ─────────────────────────────────────────────────────── 超阈值 → 追加校正
@pytest.mark.parametrize("amount,expected_reason,expected_delta", [
    ("103.00", "underbill", 300),        # 上游多收/我们少计 → 补收
    ("97.00", "overbill", -300),         # 我们多计 → 退款方向
])
def test_over_tolerance_appends_correction(migrated, conn, amount, expected_reason,
                                           expected_delta):
    usage_id = _usage(migrated, amount_minor=10_000)
    ack = _import(conn, [_row(usage_id, amount)])
    result = ack["results"][0]
    assert result["status"] == "correction_proposed"
    assert result["reason_code"] == expected_reason
    assert result["delta_minor"] == expected_delta
    assert result["ticket"] == "usage_diff"
    correction = corrections.load(conn, result["correction_id"])
    assert correction["state"] == "proposed" and correction["reason_code"] == expected_reason
    assert correction["upstream_bill_id"] == ack["results"][0]["row_id"]
    # 原 usage 一个字段都没改（INV-06）
    usage = fetch_all(migrated, "SELECT amount_minor, state FROM usage_records WHERE usage_id=%s",
                      (usage_id,))
    assert usage[0] == (10_000, "recorded")
    # 账单停在 imported（等人工复核）
    bill = fetch_all(migrated, "SELECT state FROM upstream_bills WHERE bill_id=%s",
                     (ack["results"][0]["row_id"],))
    assert bill[0][0] == "imported"


# ─────────────────────────────────────────────────────── 幂等 / 逐行受理
def test_duplicate_bill_returns_first_result(migrated, conn):
    usage_id = _usage(migrated, amount_minor=10_000)
    row = _row(usage_id, "100.50")
    first = _import(conn, [row])
    second = _import(conn, [row])
    assert first["results"][0]["status"] == "reconciled"
    assert second["results"][0]["status"] == "duplicate"
    assert fetch_all(migrated, "SELECT count(*) FROM upstream_bills WHERE bill_id=%s",
                     (row["row_id"],))[0][0] == 1


def test_single_bad_row_does_not_roll_back_batch(migrated, conn):
    usage_id = _usage(migrated, amount_minor=10_000)
    rows = [
        {"row_id": f"bad_{uuid.uuid4().hex[:6]}", "usage_id": usage_id,
         "amount": {"amount": "not-a-number", "unit": "USD"}},
        _row(usage_id, "100.10"),
    ]
    ack = _import(conn, rows)
    assert ack["rows_accepted"] == 1 and ack["rows_rejected"] == 1
    assert ack["rejected"][0]["code"] == 40001
    assert len(ack["results"]) == 1 and ack["results"][0]["status"] == "reconciled"


def test_unmatched_usage_is_reported_not_dropped(migrated, conn):
    ack = _import(conn, [_row(str(uuid.uuid4()), "10.00")])
    assert ack["results"][0]["status"] == "unmatched"
    assert ack["results"][0]["reason"] == "usage_not_found"
    assert fetch_all(migrated, "SELECT count(*) FROM upstream_bills")[0][0] >= 1


def test_bill_without_usage_id_is_unmatched(migrated, conn):
    row = {"row_id": f"bill_{uuid.uuid4().hex[:8]}", "amount": {"amount": "5.00", "unit": "USD"}}
    ack = _import(conn, [row])
    assert ack["results"][0] == {"row_id": row["row_id"], "status": "unmatched",
                                 "reason": "no_usage_id"}


# ─────────────────────────────────────────────────────── 入参校验
@pytest.mark.parametrize("kwargs", [
    {"provider": "", "period": "2026-10", "imported_by": "fin-1"},
    {"provider": "openai", "period": "2026-13", "imported_by": "fin-1"},
    {"provider": "openai", "period": "2026-10", "imported_by": ""},
])
def test_import_rejects_bad_header_fields(migrated, conn, kwargs):
    with pytest.raises(errors.InvalidArgument):
        bills.import_rows(conn, rows=[_row(str(uuid.uuid4()))], **kwargs)


def test_import_rejects_oversized_batch(migrated, conn):
    rows = [_row(str(uuid.uuid4())) for _ in range(facts.BILL_ROWS_MAX + 1)]
    with pytest.raises(errors.BatchTooLarge):
        _import(conn, rows)


def test_import_rejects_non_usd_amount_unit(migrated, conn):
    usage_id = _usage(migrated)
    row = _row(usage_id)
    row["amount"] = {"amount": "10.00", "unit": "EUR"}
    ack = _import(conn, [row])
    assert ack["rows_rejected"] == 1 and ack["rejected"][0]["code"] == 40001


def test_import_accepts_usd_minor_amount(migrated, conn):
    usage_id = _usage(migrated, amount_minor=10_000)
    row = _row(usage_id)
    row["amount"] = {"amount": "10000", "unit": "usd_minor"}
    ack = _import(conn, [row])
    assert ack["results"][0]["status"] == "reconciled"


def test_bill_amount_snapshot_is_stored(migrated, conn):
    usage_id = _usage(migrated, amount_minor=10_000)
    row = _row(usage_id, "100.50")
    _import(conn, [row])
    stored = fetch_all(migrated, "SELECT amount_minor, provider, period FROM upstream_bills "
                                 "WHERE bill_id=%s", (row["row_id"],))
    assert stored[0] == (10_050, "openai", "2026-10")
