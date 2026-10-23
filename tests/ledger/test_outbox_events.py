# SPDX-License-Identifier: Apache-2.0
"""outbox 事件契约验收：三个事件的业务键、同事务落库、幂等、待投递查询。

契约来源：contracts/02-events.md §1/§3 + 604 迁移的 m06_outbox CHECK（库里也有一份兜底）。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.ledger import (
    OutboxEvent,
    append_event,
    journal_posted_event,
    ledger_reversed_event,
    merkle_anchored_event,
    pending_events,
)
from app.ledger.constants import MERKLE_KINDS_OWNED
from app.ledger.outbox import (
    AGGREGATE_TYPE,
    REQUIRED_PAYLOAD_KEYS,
    OutboxEventInvalid,
    validate_event,
)

from ledger_gatewaykit import e6_draft, outbox_rows, post_ok
from ledgerkit import connect, run_ok, tx

NOW = datetime(2026, 10, 23, 3, 0, tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────── 构造器
def test_journal_posted_payload_has_required_keys() -> None:
    event = journal_posted_event(journal_id=str(uuid.uuid4()), event_type="E6",
                                 amount_minor=1234, ref_id="usage-1", trace_id="t-1")
    assert event.type == "journal.posted"
    assert event.aggregate_type == "journal_entry"
    assert set(REQUIRED_PAYLOAD_KEYS["journal.posted"]) <= set(event.payload)
    assert event.payload["amount_minor"] == 1234 and event.payload["ref_id"] == "usage-1"
    assert event.idempotency_key == f"journal.posted:{event.aggregate_id}"
    assert event.producer == "M06"


def test_ledger_reversed_payload_has_required_keys() -> None:
    event = ledger_reversed_event(journal_id="j-rev", reverse_of="j-orig", reason_code="user_request")
    assert event.type == "ledger.reversed"
    assert event.aggregate_type == "journal_entry"
    assert event.aggregate_id == "j-rev"                 # 聚合根是冲正凭证
    assert set(REQUIRED_PAYLOAD_KEYS["ledger.reversed"]) <= set(event.payload)
    assert event.payload["reverse_of"] == "j-orig"


@pytest.mark.parametrize("kind", MERKLE_KINDS_OWNED)
def test_merkle_anchored_payload_has_required_keys(kind: str) -> None:
    event = merkle_anchored_event(root="a" * 64, kind=kind, period="2026-10", anchored_at=NOW)
    assert event.type == "merkle.anchored"
    assert event.aggregate_type == "merkle_commitment"
    assert event.aggregate_id == f"{kind}:2026-10"
    assert set(REQUIRED_PAYLOAD_KEYS["merkle.anchored"]) <= set(event.payload)
    assert event.payload["anchored_at"].startswith("2026-10-23T03:00")


@pytest.mark.parametrize("kind", ["audit", "por"])
def test_merkle_anchored_rejects_other_modules_kinds(kind: str) -> None:
    """audit 归 M16、por 归 M09：M06 不得发布这两类根（§8.2 MERKLE_KINDS_OWNED）。"""
    with pytest.raises(OutboxEventInvalid, match="不属于 M06"):
        merkle_anchored_event(root="a" * 64, kind=kind, period="2026-10", anchored_at=NOW)


# ─────────────────────────────────────────────────────── 契约校验
def _event(**over) -> OutboxEvent:
    fields = dict(type="journal.posted", aggregate_type="journal_entry",
                  aggregate_id=str(uuid.uuid4()),
                  payload={"journal_id": "j", "event_type": "E6", "amount_minor": 1, "ref_id": "r"},
                  idempotency_key=f"k-{uuid.uuid4().hex}", trace_id="t")
    fields.update(over)
    return OutboxEvent(**fields)


@pytest.mark.parametrize("over,match", [
    ({"type": "journal.updated"}, "未登记"),
    ({"aggregate_type": "merkle_commitment"}, "aggregate_type"),
    ({"payload": {"journal_id": "j"}}, "缺业务键"),
    ({"idempotency_key": ""}, "idempotency_key"),
    ({"trace_id": "x" * 200}, "trace_id"),
    ({"producer": "M08"}, "producer"),
    ({"version": 0}, "version"),
])
def test_event_contract_violations(over, match: str) -> None:
    with pytest.raises(OutboxEventInvalid, match=match):
        validate_event(_event(**over))


def test_unknown_aggregate_mapping_is_covered() -> None:
    assert set(AGGREGATE_TYPE) == {"journal.posted", "ledger.reversed", "merkle.anchored"}


# ─────────────────────────────────────────────────────── 落库（真库）
def test_append_event_is_idempotent(shared: str) -> None:
    event = journal_posted_event(journal_id=str(uuid.uuid4()), event_type="E6",
                                 amount_minor=10, ref_id=f"ref-{uuid.uuid4().hex[:8]}")
    first = run_ok(shared, lambda c: append_event(c, event))
    second = run_ok(shared, lambda c: append_event(c, event))
    assert first == second
    rows = outbox_rows(shared, aggregate_id=event.aggregate_id)
    assert len(rows) == 1
    assert rows[0]["type"] == "journal.posted"
    assert rows[0]["payload"]["ref_id"] == event.payload["ref_id"]


def test_gateway_writes_journal_posted_in_same_transaction(shared: str) -> None:
    result = post_ok(shared, e6_draft(amount_minor=999))
    rows = outbox_rows(shared, aggregate_id=result.journal_id)
    assert len(rows) == 1
    assert rows[0]["idempotency_key"] == f"journal.posted:{result.journal_id}"
    assert rows[0]["payload"]["amount_minor"] == 999
    assert rows[0]["aggregate_type"] == "journal_entry"


def test_pending_events_only_returns_unpublished(migrated: str) -> None:
    event = journal_posted_event(journal_id=str(uuid.uuid4()), event_type="E6",
                                 amount_minor=5, ref_id="pending-1")
    event_id = run_ok(migrated, lambda c: append_event(c, event))
    pending = run_ok(migrated, lambda c: pending_events(c))
    assert [row["event_id"] for row in pending] == [event_id]
    assert pending[0]["payload"]["ref_id"] == "pending-1"

    with tx(migrated) as c, c.cursor() as cur:
        cur.execute("UPDATE m06_outbox SET published_at = now() WHERE event_id = %s", (event_id,))
    assert run_ok(migrated, lambda c: pending_events(c)) == []


def test_reversed_and_anchored_events_are_accepted_by_db(shared: str) -> None:
    """三类事件都能落库（Python 校验与 604 迁移 CHECK 双向一致）。"""
    reversed_event = ledger_reversed_event(journal_id=str(uuid.uuid4()),
                                           reverse_of=str(uuid.uuid4()), reason_code="ops")
    anchored_event = merkle_anchored_event(root="b" * 64, kind="daily_close",
                                           period="2026-10-23", anchored_at=NOW)
    ids = run_ok(shared, lambda c: (append_event(c, reversed_event), append_event(c, anchored_event)))
    assert len(set(ids)) == 2
    assert {row["type"] for row in outbox_rows(shared)} >= {"ledger.reversed", "merkle.anchored"}
