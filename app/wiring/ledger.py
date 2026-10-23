# SPDX-License-Identifier: Apache-2.0
"""M05 E6 → M06 账本的接线段：把 ``settlement.e6_request`` 落成一张凭证。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from app.ledger import gateway as ledger_gateway
from app.ledger.validate import JournalDraft, JournalLine

from .db import Database


def post_topup(db: Database, *, account_id: str, amount_minor: int,
               policy_version: str, trace_id: str) -> dict[str, Any]:
    """E3 法币在线收款：借 1120 / 贷 2101，给 demo 预置正余额（I-4 前置）。"""
    if amount_minor <= 0:
        raise ValueError("topup amount_minor 必须 > 0")
    amount_micro = int(amount_minor) * 10_000
    draft = JournalDraft(
        event_type="E3",
        unit_type="USD",
        source_type="payment_attempt",
        source_id="seed_topup_s1_demo",
        event_seq=1,
        policy_version=policy_version,
        lines=[
            JournalLine(account_id=account_id, coa_code="1120", dc="D",
                        amount_minor=amount_micro, entry_type="deposit", unit_scale=6),
            JournalLine(account_id=account_id, coa_code="2101", dc="C",
                        amount_minor=amount_micro, entry_type="deposit", unit_scale=6),
        ],
        ts=datetime.now(timezone.utc),
        idempotency_key="payment_attempt:seed_topup_s1_demo:1",
        trace_id=trace_id,
        ref_id="seed_topup_s1_demo",
    )
    with db.connect(autocommit=False) as conn:
        result = ledger_gateway.post_journal(conn, draft)
        conn.commit()
    return {"journal_id": result.journal_id, "amount_minor": int(amount_minor),
            "amount_micro": amount_micro}


def post_e6(db: Database, request: Mapping[str, Any]) -> dict[str, Any]:
    """在**显式事务**里落 E6；金额单位是 micro-USD（M06 口径）。"""
    lines = [
        JournalLine(
            account_id=str(line["account_id"]),
            coa_code=str(line["coa_code"]),
            dc=str(line["dc"]),
            amount_minor=int(line["amount_minor"]),
            entry_type=str(line["entry_type"]),
            unit_scale=6,
        )
        for line in request["lines"]
    ]
    draft = JournalDraft(
        event_type=str(request["event_type"]),
        unit_type=str(request["unit_type"]),
        source_type=str(request["source_type"]),
        source_id=str(request["source_id"]),
        event_seq=int(request["event_seq"]),
        policy_version=str(request["policy_version"]),
        lines=lines,
        ts=datetime.now(timezone.utc),
        idempotency_key=str(request["idempotency_key"]),
        trace_id=str(request["trace_id"]),
        correlation_id=request.get("correlation_id"),
        ref_id=str(request["source_id"]),
    )
    with db.connect(autocommit=False) as conn:
        result = ledger_gateway.post_journal(conn, draft)
        conn.commit()
    return {
        "journal_id": result.journal_id,
        "seq": int(result.seq),
        "hash": result.hash_hex,
        "line_count": int(result.line_count),
        "total_debit_minor": int(result.total_debit_minor),
        "amount_micro": int(request["amount_micro"]),
    }
