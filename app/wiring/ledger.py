# SPDX-License-Identifier: Apache-2.0
"""M05 E6 → M06 账本的接线段：把 ``settlement.e6_request`` 落成一张凭证。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from app.ledger import gateway as ledger_gateway
from app.ledger.validate import JournalDraft, JournalLine

from .db import Database


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
