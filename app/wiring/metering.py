# SPDX-License-Identifier: AGPL-3.0-or-later
"""M05 计量 → M03 网关 / M06 账本的接线段。

* ``UsageAdapter`` 实现 M03 ``UsageProvider``：网关给出 ``UsageDraft``，这里生成
  **双签收据**并调 M05 ``receipts.accept_batch``（不绕过网关直接拼收据）；
* ``settle_usage`` 在 demo 中显式触发 M06 E6 入账，并补一条 ``usage.settled`` 事件
  （M05 的同步结算入口只管理面重放用，默认被开关挡住，所以 demo 用 ``force=True``）。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.gateway import models as gateway_models
from app.metering import events, outbox, receipts, settlement, signing

from .db import Database
from .ledger import post_e6

DEMO_USAGE_UNIT = "token"


def _price_text(amount_minor: int) -> str:
    if amount_minor < 0:
        raise ValueError("amount_minor 不能为负")
    return f"{amount_minor // 100}.{amount_minor % 100:02d}"


class UsageAdapter:
    """M03 ``UsageProvider``：把网关用量落成 M05 双签收据 + usage_records。"""

    def __init__(self, db: Database, keys: signing.SignatureKeys) -> None:
        self._db = db
        self._keys = keys

    def record(self, draft: gateway_models.UsageDraft) -> Any:
        if draft.amount_minor is None or draft.amount_minor <= 0:
            raise ValueError("网关用量金额必须 > 0（demo 要求）")
        access = draft.access or "A1"
        usage_amount = str(int(draft.tokens_in) + int(draft.tokens_out))
        price_amount = _price_text(int(draft.amount_minor))
        fields = {
            "receipt_id": f"rcpt_{draft.request_id}",
            "task_id": draft.request_id,
            "access": access,
            "usage_amount": usage_amount,
            "usage_unit": DEMO_USAGE_UNIT,
            "price_amount": price_amount,
        }
        signatures = signing.sign(fields, self._keys)
        raw = {
            "receipt_id": fields["receipt_id"],
            "task_id": fields["task_id"],
            "access": access,
            "usage": {"amount": usage_amount, "unit": DEMO_USAGE_UNIT},
            "price": {"amount": price_amount, "unit": "USD"},
            "tokens_in": int(draft.tokens_in),
            "tokens_out": int(draft.tokens_out),
            "request_id": draft.request_id,
            "model": draft.model,
            "node_id": draft.node_id,
            "account_id": draft.account_id,
            "attempt_no": int(draft.attempt_no),
            "usage_source": "dual",
            **signatures,
        }
        with self._db.connect() as conn:
            outcome = receipts.accept_batch(
                conn,
                [raw],
                node_id=draft.node_id,
                trace_id=draft.trace_id,
                keys=self._keys,
            )
            conn.commit()
        accepted = [verdict for verdict in outcome.verdicts if verdict.accepted]
        if not accepted:
            first = outcome.rejected[0] if outcome.rejected else None
            reason = getattr(first, "reason", None) or "unknown"
            code = getattr(first, "code", None)
            raise RuntimeError(f"M05 拒收收据：code={code} reason={reason}")
        usage_id = accepted[0].usage_id
        if not usage_id:
            raise RuntimeError("M05 受理成功但未返回 usage_id")
        return gateway_models.UsageReceipt(usage_id=usage_id, amount_minor=int(draft.amount_minor))


def settle_usage(db: Database, usage_id: str, *, policy_version: str,
                 trace_id: str) -> tuple[dict[str, Any], list[str]]:
    """E6 入账 + ``usage.settled`` 事件 + 派发 M05 outbox。"""
    usage_id = str(usage_id)
    with db.connect() as conn:
        usage = settlement.load_usage(conn, usage_id)
        if usage is None:
            raise RuntimeError(f"usage 不存在：{usage_id}")
        result = settlement.post_usage_settle(
            conn,
            usage_id,
            policy_version=policy_version,
            provider=lambda request: post_e6(db, request),
            force=True,
            trace_id=trace_id,
        )
        if not result.get("posted"):
            raise RuntimeError(f"E6 未入账：{result}")
        envelope = events.usage_settled_event(
            usage_id=usage_id,
            final_amount_minor=int(usage["amount_minor"]),
            correction_id=None,
            trace_id=trace_id,
            occurred_at=datetime.now(timezone.utc),
        )
        with conn.transaction():
            outbox.append(conn, envelope)
        published: list[str] = []

        def _publisher(event_type: str, _envelope: dict[str, Any]) -> None:
            published.append(event_type)

        outbox.dispatch(conn, publisher=_publisher)
        return result, published
