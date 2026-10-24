# SPDX-License-Identifier: AGPL-3.0-or-later
"""准入审核（``POST /api/v1/admin/supply/nodes/{id}/review``，CR-3 归 M02）。

状态机：``approve`` 使 ``pending → active``；``reject`` 保留 pending 并留理由；
不合法迁移 → 40305；retired 不可逆 → 40902；审核必须留理由与 actor。
"""
from __future__ import annotations

import pytest

from app.supply import models
from app.supply.errors import (
    InvalidArgument,
    NodeNotFound,
    NodeStateForbidden,
    RetireIrreversible,
)


def _events(conn, node_id, kind=None):
    sql = ("SELECT kind, from_state, to_state, reason, reason_code, actor, payload "
           "FROM node_events WHERE node_id = %s")
    params = [node_id]
    if kind:
        sql += " AND kind = %s"
        params.append(kind)
    with conn.cursor() as cur:
        cur.execute(sql + " ORDER BY seq", tuple(params))
        return models._rows(cur)


def _state_changes(conn, node_id):
    with conn.cursor() as cur:
        cur.execute("SELECT payload FROM supply_outbox WHERE aggregate_id = %s "
                    "AND type = 'node.state.changed' ORDER BY occurred_at", (node_id,))
        return [row["payload"] for row in models._rows(cur)]


def test_approve_moves_pending_to_active(conn, factory):
    node = factory.register().node
    reviewed = models.review(conn, node_id=node.id, decision="approve",
                             reason="材料齐全", actor="admin-1", tier="t1",
                             now=factory.moment, trace_id="trace-review")

    assert reviewed.state == "active"
    assert reviewed.lifecycle_state == "active"
    assert reviewed.reviewed_at == factory.moment
    assert reviewed.reviewed_by == "admin-1"

    events = _events(conn, node.id, "review_approved")
    assert len(events) == 1
    assert events[0]["from_state"] == "pending"
    assert events[0]["to_state"] == "active"
    assert events[0]["reason"] == "材料齐全"
    assert events[0]["actor"] == "admin-1"
    assert events[0]["payload"]["tier"] == "t1"

    changes = _state_changes(conn, node.id)
    assert changes[-1] == {"node_id": node.id, "from": "pending", "to": "active",
                           "reason": "approved"}


def test_reject_keeps_pending_and_requires_reason(conn, factory):
    node = factory.register().node
    reviewed = models.review(conn, node_id=node.id, decision="reject",
                             reason="指纹信息不完整", actor="admin-1", now=factory.moment,
                             trace_id="trace-review")

    assert reviewed.state == "pending"                 # 驳回保留 pending（不落 retired）
    assert reviewed.reviewed_at is None                # 只在通过时记审核时刻

    events = _events(conn, node.id, "review_rejected")
    assert len(events) == 1
    assert events[0]["reason"] == "指纹信息不完整"
    assert events[0]["to_state"] == "pending"

    changes = _state_changes(conn, node.id)
    assert changes[-1]["reason"] == "rejected"

    # 驳回后仍可再次审核通过
    approved = models.review(conn, node_id=node.id, decision="approve", reason="补充材料齐全",
                             actor="admin-2", now=factory.moment, trace_id="t")
    assert approved.state == "active"


@pytest.mark.parametrize("setup_state", ["active", "frozen"])
def test_approve_on_non_pending_is_40305(conn, factory, setup_state):
    node = factory.register().node
    if setup_state == "active":
        node = models.review(conn, node_id=node.id, decision="approve", reason="ok",
                             actor="admin-1", now=factory.moment)
    else:
        with conn.cursor() as cur:
            cur.execute("UPDATE nodes SET state = 'frozen' WHERE id = %s", (node.id,))
        node = models.get_node(conn, node.id)

    with pytest.raises(NodeStateForbidden) as excinfo:
        models.review(conn, node_id=node.id, decision="approve", reason="再审",
                      actor="admin-1", now=factory.moment)
    assert excinfo.value.code == "40305"
    assert excinfo.value.details["state"] == setup_state


def test_reject_on_non_pending_is_40305(conn, factory):
    node = factory.register().node
    models.review(conn, node_id=node.id, decision="approve", reason="ok", actor="admin-1",
                  now=factory.moment)
    with pytest.raises(NodeStateForbidden) as excinfo:
        models.review(conn, node_id=node.id, decision="reject", reason="反悔",
                      actor="admin-1", now=factory.moment)
    assert excinfo.value.code == "40305"


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_retired_node_cannot_be_reviewed(conn, factory, decision):
    node = factory.register().node
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET state = 'retired', retired_at = now() WHERE id = %s",
                    (node.id,))
    with pytest.raises(RetireIrreversible) as excinfo:
        models.review(conn, node_id=node.id, decision=decision, reason="再审",
                      actor="admin-1", now=factory.moment)
    assert excinfo.value.code == "40902"


def test_unknown_node_is_40401(conn, factory):
    with pytest.raises(NodeNotFound) as excinfo:
        models.review(conn, node_id="n_missing", decision="approve", reason="ok",
                      actor="admin-1", now=factory.moment)
    assert excinfo.value.code == "40401"


@pytest.mark.parametrize("override,field", [
    ({"decision": "maybe"}, "decision"),
    ({"decision": None}, "decision"),
    ({"reason": ""}, "reason"),
    ({"reason": "   "}, "reason"),
    ({"reason": "x" * 501}, "reason"),
    ({"actor": ""}, "actor"),
    ({"actor": None}, "actor"),
    ({"tier": "t" * 40}, "tier"),
])
def test_review_argument_validation(conn, factory, override, field):
    node = factory.register().node
    params = {"node_id": node.id, "decision": "approve", "reason": "ok", "actor": "admin-1",
              "now": factory.moment}
    params.update(override)
    with pytest.raises(InvalidArgument) as excinfo:
        models.review(conn, **params)
    assert excinfo.value.details["field"] == field


def test_review_reason_max_500_is_accepted(conn, factory):
    node = factory.register().node
    reviewed = models.review(conn, node_id=node.id, decision="reject", reason="x" * 500,
                             actor="admin-1", now=factory.moment)
    assert reviewed.state == "pending"


def test_review_does_not_touch_policy_version(conn, factory):
    """准入不生成策略（T5 才递增 policy_version）；Ack 里回当前版本。"""
    node = factory.register().node
    reviewed = models.review(conn, node_id=node.id, decision="approve", reason="ok",
                             actor="admin-1", now=factory.moment)
    assert reviewed.policy_version == "0"
