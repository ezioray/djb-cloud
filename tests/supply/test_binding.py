# SPDX-License-Identifier: Apache-2.0
"""binding（M02 §6.5 / INV-08 / CR-4：绑定存 nodes 列 + node_events 历史）与一次性绑定码。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.supply import facts, models
from app.supply.errors import (
    AccountNotFound,
    BindingCodeInvalid,
    BindingConflict,
    InvalidArgument,
    NodeStateForbidden,
    RetireIrreversible,
)


def _active(factory, *, account_id=None):
    result = factory.register()
    node = models.review(factory.conn, node_id=result.node.id, decision="approve",
                         reason="准予接入", actor="admin-1", now=factory.moment)
    return node


def _bind(factory, node, account_id, *, ttl=facts.BINDING_CODE_TTL_S, moment=None):
    code = models.issue_binding_code(factory.conn, node_id=node.id, account_id=account_id,
                                     ttl_seconds=ttl, now=moment or factory.moment)
    return code


def _events(conn, node_id, kind):
    with conn.cursor() as cur:
        cur.execute("SELECT kind, from_state, to_state, reason_code, payload FROM node_events "
                    "WHERE node_id = %s AND kind = %s ORDER BY seq", (node_id, kind))
        return models._rows(cur)


def _outbox(conn, node_id):
    with conn.cursor() as cur:
        cur.execute("SELECT type, payload FROM supply_outbox WHERE aggregate_id = %s "
                    "ORDER BY occurred_at", (node_id,))
        return models._rows(cur)


# --------------------------------------------------------------------------- 绑定码
def test_issue_binding_code_returns_single_use_plaintext(conn, factory, account):
    node = _active(factory)
    code = _bind(factory, node, account)

    assert len(code.code) >= 24
    assert code.expires_at == factory.moment + timedelta(seconds=facts.BINDING_CODE_TTL_S)
    with conn.cursor() as cur:
        cur.execute("SELECT code_hash, status, account_id FROM node_binding_codes")
        row = models._one(cur)
    assert row["status"] == "issued"
    assert row["account_id"] == account
    assert row["code_hash"] != code.code


def test_issue_binding_code_requires_active_node(conn, factory, account):
    pending = factory.register().node
    with pytest.raises(NodeStateForbidden) as excinfo:
        models.issue_binding_code(conn, node_id=pending.id, account_id=account,
                                  now=factory.moment)
    assert excinfo.value.code == "40305"


def test_issue_binding_code_requires_normal_account(conn, factory, frozen_account):
    node = _active(factory)
    with pytest.raises(BindingConflict) as excinfo:
        models.issue_binding_code(conn, node_id=node.id, account_id=frozen_account,
                                  now=factory.moment)
    assert excinfo.value.code == "40903"
    assert excinfo.value.details["account_state"] == "frozen"


def test_issue_binding_code_unknown_account_is_40401(conn, factory):
    import uuid

    node = _active(factory)
    with pytest.raises(AccountNotFound) as excinfo:
        models.issue_binding_code(conn, node_id=node.id, account_id=uuid.uuid4(),
                                  now=factory.moment)
    assert excinfo.value.code == "40401"


@pytest.mark.parametrize("ttl", [0, -5, 3601, "600"])
def test_issue_binding_code_ttl_bounds(conn, factory, account, ttl):
    node = _active(factory)
    with pytest.raises(InvalidArgument) as excinfo:
        models.issue_binding_code(conn, node_id=node.id, account_id=account,
                                  ttl_seconds=ttl, now=factory.moment)
    assert excinfo.value.details["field"] == "ttl_seconds"


# --------------------------------------------------------------------------- 绑定
def test_bind_sets_owner_and_writes_history(conn, factory, account):
    node = _active(factory)
    code = _bind(factory, node, account)
    binding, updated = models.bind(conn, node_id=node.id, code=code.code,
                                   now=factory.moment, trace_id="trace-bind")

    assert binding.state == "bound"
    assert binding.bound_account_id == account
    assert binding.bound_at == factory.moment
    assert updated.account_id == account
    assert updated.tenant_id == account                      # personal：tenant = account
    assert updated.bound_account_id == account

    events = _events(conn, node.id, "bound")
    assert len(events) == 1
    assert events[0]["payload"]["account_id"] == str(account)

    changed = [item for item in _outbox(conn, node.id)
               if item["type"] == "node.state.changed"
               and item["payload"]["reason"] == "bound"]
    assert len(changed) == 1
    assert changed[0]["payload"]["to"] == "active"

    with conn.cursor() as cur:
        cur.execute("SELECT status, consumed_at FROM node_binding_codes")
        row = models._one(cur)
    assert row["status"] == "consumed"
    assert row["consumed_at"] == factory.moment


def test_bind_code_is_single_use(conn, factory, account):
    node = _active(factory)
    code = _bind(factory, node, account)
    models.bind(conn, node_id=node.id, code=code.code, now=factory.moment, trace_id="t")
    with pytest.raises(BindingCodeInvalid) as excinfo:
        models.bind(conn, node_id=node.id, code=code.code, now=factory.moment, trace_id="t")
    assert excinfo.value.code == "40905"
    assert excinfo.value.reason == "binding_code_consumed"


def test_bind_expired_code_marks_expired(conn, factory, account):
    node = _active(factory)
    code = _bind(factory, node, account, ttl=60)
    later = factory.moment + timedelta(seconds=61)
    with pytest.raises(BindingCodeInvalid) as excinfo:
        models.bind(conn, node_id=node.id, code=code.code, now=later, trace_id="t")
    assert excinfo.value.reason == "binding_code_expired"
    with conn.cursor() as cur:
        cur.execute("SELECT status FROM node_binding_codes")
        assert models._one(cur)["status"] == "expired"


def test_bind_unknown_code_is_40905(conn, factory):
    node = _active(factory)
    with pytest.raises(BindingCodeInvalid) as excinfo:
        models.bind(conn, node_id=node.id, code="not-a-code", now=factory.moment, trace_id="t")
    assert excinfo.value.reason == "binding_code_unknown"


def test_bind_code_must_match_node(conn, factory, account):
    node = _active(factory)
    other = _active(factory)
    code = _bind(factory, node, account)
    with pytest.raises(BindingCodeInvalid) as excinfo:
        models.bind(conn, node_id=other.id, code=code.code, now=factory.moment, trace_id="t")
    assert excinfo.value.reason == "binding_code_mismatch"


def test_bind_requires_active_node(conn, factory, account):
    node = _active(factory)
    code = _bind(factory, node, account)
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET state = 'frozen' WHERE id = %s", (node.id,))
    with pytest.raises(NodeStateForbidden):
        models.bind(conn, node_id=node.id, code=code.code, now=factory.moment, trace_id="t")


def test_bind_rejects_second_account(conn, factory, account, other_account):
    node = _active(factory)
    first = _bind(factory, node, account)
    models.bind(conn, node_id=node.id, code=first.code, now=factory.moment, trace_id="t")

    second = _bind(factory, node, other_account)
    with pytest.raises(BindingConflict) as excinfo:
        models.bind(conn, node_id=node.id, code=second.code, now=factory.moment, trace_id="t")
    assert excinfo.value.code == "40903"
    assert excinfo.value.details["bound_account_id"] == str(account)


def test_bind_rejects_account_mismatch(conn, factory, account, other_account):
    node = _active(factory)
    code = _bind(factory, node, account)
    with pytest.raises(BindingConflict) as excinfo:
        models.bind(conn, node_id=node.id, code=code.code, account_id=other_account,
                    now=factory.moment, trace_id="t")
    assert excinfo.value.reason == "account_mismatch"


def test_max_nodes_per_account_blocks_issue_and_bind(conn, factory, account, monkeypatch):
    """§8.1 ``supply.max_nodes_per_account``：签发与绑定两处都拦（防绕过）。"""
    node_a = _active(factory)
    node_b = _active(factory)
    monkeypatch.setattr(facts, "MAX_NODES_PER_ACCOUNT", 1)

    first = _bind(factory, node_a, account)
    models.bind(conn, node_id=node_a.id, code=first.code, now=factory.moment, trace_id="t")

    with pytest.raises(BindingConflict) as excinfo:
        _bind(factory, node_b, account)
    assert excinfo.value.code == "40903"
    assert excinfo.value.details["max_nodes_per_account"] == 1


def test_bind_requires_code(conn, factory):
    node = _active(factory)
    with pytest.raises(InvalidArgument) as excinfo:
        models.bind(conn, node_id=node.id, code="", now=factory.moment, trace_id="t")
    assert excinfo.value.details["field"] == "code"


# --------------------------------------------------------------------------- 解绑 / 换绑
def test_unbind_is_idempotent_and_keeps_history(conn, factory, account):
    node = _active(factory)
    code = _bind(factory, node, account)
    models.bind(conn, node_id=node.id, code=code.code, now=factory.moment, trace_id="t")

    binding, updated = models.unbind(conn, node=models.get_node(conn, node.id),
                                     now=factory.moment, trace_id="t")
    assert binding.state == "revoked"
    assert updated.revoked_at == factory.moment
    assert updated.account_id is None                       # 当前归属清空
    assert updated.bound_account_id == account              # 历史保留（INV-08）
    assert updated.bound_at == factory.moment

    # 幂等：第二次不再追加事件
    again, _ = models.unbind(conn, node=updated, now=factory.moment, trace_id="t")
    assert again.state == "revoked"
    assert len(_events(conn, node.id, "unbound")) == 1


def test_unbind_then_rebind_to_another_account(conn, factory, account, other_account):
    node = _active(factory)
    first = _bind(factory, node, account)
    models.bind(conn, node_id=node.id, code=first.code, now=factory.moment, trace_id="t")
    models.unbind(conn, node=models.get_node(conn, node.id), now=factory.moment, trace_id="t")

    second = _bind(factory, node, other_account)
    binding, updated = models.bind(conn, node_id=node.id, code=second.code,
                                   now=factory.moment, trace_id="t")
    assert binding.state == "bound"
    assert binding.bound_account_id == other_account
    assert updated.account_id == other_account
    assert updated.revoked_at is None
    assert len(_events(conn, node.id, "bound")) == 2        # 换绑历史保留


def test_unbind_pending_node_is_40305(conn, factory):
    node = factory.register().node
    with pytest.raises(NodeStateForbidden) as excinfo:
        models.unbind(conn, node=node, now=factory.moment, trace_id="t")
    assert excinfo.value.code == "40305"


def test_unbind_retired_node_is_40902(conn, factory):
    node = _active(factory)
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET state = 'retired', retired_at = now() WHERE id = %s",
                    (node.id,))
    with pytest.raises(RetireIrreversible) as excinfo:
        models.unbind(conn, node=models.get_node(conn, node.id), now=factory.moment)
    assert excinfo.value.code == "40902"


# --------------------------------------------------------------------------- 绑定视图
def test_binding_view_states(conn, factory, account):
    pending = factory.register().node
    assert models.binding_of(pending).state == "pending"

    active = _active(factory)
    assert models.binding_of(models.get_node(conn, active.id)).state == "unbound"

    code = _bind(factory, active, account)
    models.bind(conn, node_id=active.id, code=code.code, now=factory.moment, trace_id="t")
    bound = models.get_node(conn, active.id)
    assert models.binding_of(bound).state == "bound"

    models.unbind(conn, node=bound, now=factory.moment, trace_id="t")
    assert models.binding_of(models.get_node(conn, active.id)).state == "revoked"


def test_binding_dict_matches_spec_shape(conn, factory, account):
    node = _active(factory)
    payload = models.binding_dict(models.binding_of(models.get_node(conn, node.id)))
    assert set(payload) == {"node_id", "state", "bound_account_id", "bound_at", "revoked_at"}
    assert payload["state"] == "unbound"
    assert payload["bound_account_id"] is None

    code = _bind(factory, node, account)
    models.bind(conn, node_id=node.id, code=code.code, now=factory.moment, trace_id="t")
    payload = models.binding_dict(models.binding_of(models.get_node(conn, node.id)))
    assert payload["bound_account_id"] == str(account)
    assert payload["bound_at"].endswith("Z")
    assert payload["revoked_at"] is None
