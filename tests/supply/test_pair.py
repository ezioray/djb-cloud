# SPDX-License-Identifier: Apache-2.0
"""pair / 密钥轮换（M02 §4.1 / INV-10 / spec NodePairRequest）。

要点：明文只回一次、库中只有哈希；轮换重叠 ≤24 h，重叠期内旧钥**只验签**、
不接受新注册；状态非 active 一律 40305。
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.supply import facts, models, security
from app.supply.errors import (
    InvalidArgument,
    KeyStateConflict,
    NodeKeyInvalid,
    NodeKeyRevoked,
    NodeStateForbidden,
)

PENDING = "pending"


def _active_node(factory) -> tuple[models.Node, str]:
    result = factory.register()
    node = models.review(factory.conn, node_id=result.node.id, decision="approve",
                         reason="准予接入", actor="admin-1", now=factory.moment)
    return node, result.client_key


def test_pair_rotates_key_without_overlap(conn, factory):
    node, old_key = _active_node(factory)

    rotation = models.rotate_key(conn, node, rotate=False, now=factory.moment,
                                 trace_id="trace-pair")
    assert rotation.client_key != old_key
    assert rotation.previous_key_expires_at is None

    # 旧钥立刻失效
    with pytest.raises(NodeKeyInvalid):
        models.authenticate(conn, old_key)
    assert models.authenticate(conn, rotation.client_key).node.id == node.id

    stored = models.get_node(conn, node.id)
    key_hash, stored_key_id = models.key_material(conn, node.id)
    assert key_hash == security.hash_secret(rotation.client_key)
    assert stored_key_id == rotation.key_id
    assert stored.key_prefix == rotation.client_key[:facts.KEY_PREFIX_LEN]
    assert stored.prev_key_hash is None
    assert stored.prev_key_expires_at is None
    assert rotation.client_key not in str(stored)


def test_pair_with_overlap_keeps_old_key_for_signature_only(conn, factory):
    node, old_key = _active_node(factory)
    rotation = models.rotate_key(conn, node, rotate=True, overlap_seconds=3600,
                                 now=factory.moment)

    assert rotation.previous_key_expires_at == factory.moment + timedelta(seconds=3600)
    previous = models.authenticate(conn, old_key)
    assert previous.key_kind == "previous"
    assert previous.node.id == node.id
    # 重叠期内旧钥**不接受新注册**（allow_previous=False）
    with pytest.raises(NodeKeyInvalid):
        models.authenticate(conn, old_key, allow_previous=False)


def test_previous_key_expires_after_overlap_window(conn, factory):
    node, old_key = _active_node(factory)
    models.rotate_key(conn, node, rotate=True, overlap_seconds=60, now=factory.moment)
    later = factory.moment + timedelta(seconds=61)
    with pytest.raises(NodeKeyRevoked) as excinfo:
        models.authenticate(conn, old_key, now=later)
    assert excinfo.value.code == "40102"


def test_pair_writes_history_row(conn, factory):
    node, _ = _active_node(factory)
    models.rotate_key(conn, node, rotate=True, overlap_seconds=10, now=factory.moment)
    with conn.cursor() as cur:
        cur.execute("SELECT kind, reason_code, payload FROM node_events "
                    "WHERE node_id = %s AND kind = 'key_rotated'", (node.id,))
        rows = models._rows(cur)
    assert len(rows) == 1
    assert rows[0]["reason_code"] == "pair"
    assert rows[0]["payload"]["rotate"] is True
    assert "key_id" in rows[0]["payload"]


@pytest.mark.parametrize("overlap", [-1, 86_401, "10", 1.5])
def test_pair_rejects_bad_overlap(conn, factory, overlap):
    node, _ = _active_node(factory)
    with pytest.raises(InvalidArgument) as excinfo:
        models.rotate_key(conn, node, rotate=True, overlap_seconds=overlap,
                          now=factory.moment)
    assert excinfo.value.details["field"] == "overlap_seconds"


def test_pair_rejects_overlap_without_rotate(conn, factory):
    node, _ = _active_node(factory)
    with pytest.raises(KeyStateConflict) as excinfo:
        models.rotate_key(conn, node, rotate=False, overlap_seconds=60, now=factory.moment)
    assert excinfo.value.code == "40903"


def test_pair_requires_boolean_rotate(conn, factory):
    node, _ = _active_node(factory)
    with pytest.raises(InvalidArgument) as excinfo:
        models.rotate_key(conn, node, rotate="yes", now=factory.moment)
    assert excinfo.value.details["field"] == "rotate"


@pytest.mark.parametrize("target_state", [PENDING, "frozen", "retired"])
def test_pair_rejects_non_active_nodes(conn, factory, target_state):
    node, _ = _active_node(factory)
    if target_state == "frozen":
        with conn.cursor() as cur:
            cur.execute("UPDATE nodes SET state = 'frozen' WHERE id = %s", (node.id,))
        node = models.get_node(conn, node.id)
    elif target_state == "retired":
        with conn.cursor() as cur:
            cur.execute("UPDATE nodes SET state = 'retired', retired_at = now() WHERE id = %s",
                        (node.id,))
        node = models.get_node(conn, node.id)
    else:
        result = factory.register()
        node = result.node

    with pytest.raises(NodeStateForbidden) as excinfo:
        models.rotate_key(conn, node, rotate=True, overlap_seconds=10, now=factory.moment)
    assert excinfo.value.code == "40305"
    assert excinfo.value.details["state"] == target_state


def test_revoked_key_is_rejected_with_40102(conn, factory):
    node, key = _active_node(factory)
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET key_revoked_at = %s WHERE id = %s",
                    (factory.moment, node.id))
    with pytest.raises(NodeKeyRevoked) as excinfo:
        models.authenticate(conn, key, now=factory.moment)
    assert excinfo.value.code == "40102"


def test_rotation_overlap_cannot_exceed_24h_in_db(conn, factory):
    """库层兜底（INV-10）：重叠期写入超过 24 h 直接被 CHECK 拒绝。"""
    import psycopg

    node, _ = _active_node(factory)
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE nodes
                          SET key_issued_at = %s,
                              prev_key_hash = %s,
                              prev_key_expires_at = %s + interval '25 hours'
                        WHERE id = %s""",
                    (factory.moment, "2" * 64, factory.moment, node.id))
