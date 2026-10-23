# SPDX-License-Identifier: Apache-2.0
"""M08 → M06 / M09 接线段：账本 poster 与 attestation verifier。

边界：M08 不 import M06/M09，只通过注入的协议调用；本文件是合并窗口的适配层。

* `M06LedgerPoster.post(conn, PostingRequest)` → `{"journal_id", "idempotent"}`
  把 M08 的凭证形状（micro-USD、coa_code、dc）转成 M06 `JournalDraft`，在调用方事务内落账。
* `make_attestation_verifier(connection_factory)` → `(attestation_ref) -> bool`
  查 `reconciliation_attestations`，按 M09 `attestation.validate` 口径判定；查不到/非法 id 一律 False（fail-closed）。
"""
from __future__ import annotations

import uuid
from typing import Any, Callable

from psycopg.rows import dict_row

from app.ledger import gateway as ledger_gateway
from app.ledger.validate import JournalDraft, JournalLine
from app.recon import attestation as recon_attestation


class M06LedgerPoster:
    """M08 LedgerPoster 协议实现：只做形状转换 + 调 M06 `post_journal`。"""

    def post(self, conn: Any, request: Any) -> dict[str, Any]:
        lines = [
            JournalLine(
                account_id=line.account_id,
                coa_code=line.coa_code,
                dc=line.dc,
                amount_minor=int(line.amount_minor),
                entry_type=line.entry_type,
                unit_scale=6,
                qty_minor=getattr(line, "qty_minor", None),
                wallet_id=getattr(line, "wallet_id", None),
            )
            for line in request.lines
        ]
        draft = JournalDraft(
            event_type=request.event_type,
            unit_type=request.unit_type,
            source_type=request.source_type,
            source_id=request.source_id,
            event_seq=int(request.event_seq),
            policy_version=request.policy_version,
            lines=lines,
            ts=request.occurred_at,
            idempotency_key=request.idempotency_key,
            trace_id=request.trace_id,
            correlation_id=request.correlation_id,
            ref_id=request.ref_id,
        )
        result = ledger_gateway.post_journal(conn, draft)
        return {"journal_id": str(result.journal_id), "idempotent": bool(result.idempotent)}


def make_attestation_verifier(connection_factory: Callable[[], Any]) -> Callable[[str], bool]:
    """attestation_id → 是否有效（未知 / 非 UUID / 非 valid 一律 False）。"""

    def verify(attestation_ref: str) -> bool:
        try:
            attestation_id = str(uuid.UUID(str(attestation_ref)))
        except (TypeError, ValueError):
            return False
        with connection_factory() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT * FROM reconciliation_attestations WHERE attestation_id = %s",
                (attestation_id,),
            )
            row = cur.fetchone()
        return bool(recon_attestation.validate(row)["valid"])

    return verify
