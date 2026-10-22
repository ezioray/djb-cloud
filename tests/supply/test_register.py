# SPDX-License-Identifier: Apache-2.0
"""注册（M02 §6.1 / INV-01 / INV-03 / INV-05 / 验收 A1）——领域层，事务回滚隔离。"""
from __future__ import annotations

import uuid

import pytest

from supplykit import session

from app.supply import facts, models, security
from app.supply.errors import (
    FingerprintConflict,
    InvalidArgument,
    NodeKeyInvalid,
    ProtocolIncompatible,
)


def _nodes(conn) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT id, state, lifecycle_state, hardware_fingerprint, key_prefix, "
                    "policy_version, protocol_version, access_modes, capabilities, region, "
                    "labels FROM nodes ORDER BY created_at")
        return models._rows(cur)


def _events(conn, node_id: str) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT kind, from_state, to_state, reason_code, reason, payload, actor "
                    "FROM node_events WHERE node_id = %s ORDER BY seq", (node_id,))
        return models._rows(cur)


def _outbox(conn) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT event_id, type, version, producer, aggregate_type, aggregate_id, "
                    "trace_id, idempotency_key, payload FROM supply_outbox ORDER BY occurred_at")
        return models._rows(cur)


# --------------------------------------------------------------------------- 首次注册
def test_first_registration_creates_pending_node_with_key(conn, factory):
    result = factory.register(platform="macos", region="cn-east",
                              access_modes=["A1", "A2"],
                              capabilities=["capacity_announcement"])

    assert result.created is True
    assert result.node.state == "pending"
    assert result.node.lifecycle_state == "pending"
    assert result.client_key and len(result.client_key) >= 32
    assert result.node.key_prefix == result.client_key[:facts.KEY_PREFIX_LEN]
    assert result.node.policy_version == "0"          # 策略未下发（T5 起递增）
    assert result.node.protocol_version == "1.0.0"
    assert result.node.account_id is None             # 注册时尚未绑定（CR-4 流程）
    assert result.node.region == "cn-east"
    assert list(result.node.access_modes) == ["A1", "A2"]


def test_registration_writes_event_outbox_and_history_in_one_transaction(conn, factory):
    result = factory.register()
    node = result.node

    events = _events(conn, node.id)
    assert [item["kind"] for item in events] == ["registered"]
    assert events[0]["from_state"] is None
    assert events[0]["to_state"] == "pending"

    outbox = _outbox(conn)
    assert [item["type"] for item in outbox] == ["node.registered"]
    registered = outbox[0]
    assert registered["producer"] == "M02"
    assert registered["version"] == 1
    assert registered["aggregate_type"] == "node"
    assert registered["aggregate_id"] == node.id
    assert set(registered["payload"]) >= {"node_id", "account_id", "protocols", "region"}
    assert registered["payload"]["account_id"] is None
    assert registered["payload"]["protocols"] == ["1.0.0"]


def test_fingerprint_is_only_stored_hashed(conn, factory):
    raw = "fp-raw-machine-0001"
    result = factory.register(hardware_fingerprint=raw)
    expected = security.hash_fingerprint(raw)

    row = _nodes(conn)[0]
    assert row["hardware_fingerprint"] == expected
    assert row["hardware_fingerprint"] != raw
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM nodes WHERE hardware_fingerprint = %s", (raw,))
        assert models._one(cur)["n"] == 0


def test_registration_never_stores_plaintext_key(conn, factory):
    result = factory.register()
    plaintext = result.client_key

    with conn.cursor() as cur:
        cur.execute("SELECT key_hash, key_prefix FROM nodes WHERE id = %s", (result.node.id,))
        row = models._one(cur)
    assert row["key_hash"] == security.hash_secret(plaintext)
    assert row["key_prefix"] == plaintext[:facts.KEY_PREFIX_LEN]
    assert plaintext not in str(row)

    with conn.cursor() as cur:                              # 任何表都不该出现明文
        for table, column in (("node_events", "payload"), ("supply_outbox", "payload")):
            cur.execute(f"SELECT count(*) AS n FROM {table} WHERE {column}::text LIKE %s",
                        (f"%{plaintext}%",))
            assert models._one(cur)["n"] == 0


# --------------------------------------------------------------------------- A1：同指纹幂等
def test_a1_same_fingerprint_returns_same_node_and_rotates_key(conn, factory):
    first = factory.register(hardware_fingerprint="fp-a1-stable-0001")
    second = factory.register(hardware_fingerprint="fp-a1-stable-0001",
                              client_version="1.4.1")

    assert second.created is False
    assert second.node.id == first.node.id
    assert second.client_key != first.client_key
    assert len(_nodes(conn)) == 1                          # 没有第二条节点

    # 旧钥失效（验收 A1）
    with pytest.raises(NodeKeyInvalid):
        models.authenticate(conn, first.client_key)
    auth = models.authenticate(conn, second.client_key)
    assert auth.node.id == first.node.id
    assert auth.key_kind == "primary"

    # 只发一次 node.registered（注册事实不重复）
    assert [item["type"] for item in _outbox(conn)] == ["node.registered"]
    kinds = [item["kind"] for item in _events(conn, first.node.id)]
    assert kinds == ["registered", "re_registered"]


def test_reregistration_updates_client_metadata(conn, factory):
    first = factory.register(hardware_fingerprint="fp-meta-0001-aaaa", client_version="1.0.0",
                             region=None, access_modes=["A1"])
    second = factory.register(hardware_fingerprint="fp-meta-0001-aaaa", client_version="2.0.0",
                              region="eu-west", access_modes=["B"],
                              capabilities=["policy_etag"])
    assert second.node.client_version == "2.0.0"
    assert second.node.region == "eu-west"
    assert list(second.node.access_modes) == ["B"]
    assert list(second.node.capabilities) == ["policy_etag"]


def test_same_fingerprint_with_valid_key_is_allowed_to_rotate(conn, factory, account):
    first = factory.register(hardware_fingerprint="fp-own-0001-aaaaa")
    node = models.review(conn, node_id=first.node.id, decision="approve", reason="ok",
                         actor="admin-1", now=factory.moment)
    code = models.issue_binding_code(conn, node_id=node.id, account_id=account,
                                     now=factory.moment)
    models.bind(conn, node_id=node.id, code=code.code, now=factory.moment, trace_id="t")

    again = factory.register(hardware_fingerprint="fp-own-0001-aaaaa", client_key=first.client_key)
    assert again.node.id == first.node.id
    assert again.created is False


def test_same_fingerprint_without_key_on_bound_node_is_40903(conn, factory, account):
    """指纹哈希不是秘密：已归属账户的节点不能被匿名重注册接管（INV-01 / §7）。"""
    first = factory.register(hardware_fingerprint="fp-bound-0001-aaa")
    node = models.review(conn, node_id=first.node.id, decision="approve", reason="ok",
                         actor="admin-1", now=factory.moment)
    code = models.issue_binding_code(conn, node_id=node.id, account_id=account,
                                     now=factory.moment)
    models.bind(conn, node_id=node.id, code=code.code, now=factory.moment, trace_id="t")

    with pytest.raises(FingerprintConflict) as excinfo:
        factory.register(hardware_fingerprint="fp-bound-0001-aaa")
    assert excinfo.value.code == "40903"
    assert excinfo.value.details["node_id"] == node.id


def test_same_fingerprint_other_platform_is_a_different_node(conn, factory):
    first = factory.register(platform="linux", hardware_fingerprint="fp-cross-0001-aaa")
    second = factory.register(platform="windows", hardware_fingerprint="fp-cross-0001-aaa")
    assert second.node.id != first.node.id
    assert len(_nodes(conn)) == 2


# --------------------------------------------------------------------------- 校验与码
def test_invalid_platform_is_40001(conn, factory):
    with pytest.raises(InvalidArgument) as excinfo:
        factory.register(platform="solaris")
    assert excinfo.value.code == "40001"
    assert excinfo.value.details["field"] == "platform"


@pytest.mark.parametrize("override,field", [
    ({"client_version": ""}, "client_version"),
    ({"client_version": "x" * 80}, "client_version"),
    ({"access_modes": ["A1", "Z9"]}, "access_modes"),
    ({"access_modes": "A1"}, "access_modes"),
    ({"capabilities": [str(i) for i in range(40)]}, "capabilities"),
    ({"region": "r" * 80}, "region"),
    ({"labels": ["not", "an", "object"]}, "labels"),
])
def test_register_argument_validation(conn, factory, override, field):
    with pytest.raises(InvalidArgument) as excinfo:
        factory.register(**override)
    assert excinfo.value.details["field"] == field


def test_protocol_n_minus_1_is_accepted(conn, factory):
    """INV-05：N-1（0.x）仍可用；N-3 的拒绝在 test_protocol.py 用可配置 server 版本覆盖。"""
    result = factory.register(protocol_version="0.9.0")
    assert result.node.protocol_version == "0.9.0"


def test_protocol_too_new_is_42601(conn, factory):
    with pytest.raises(ProtocolIncompatible) as excinfo:
        factory.register(protocol_version="2.0.0")
    assert excinfo.value.code == "42601"
    assert excinfo.value.details["min_supported_version"] == "0.0.0"
    assert "upgrade_hint" in excinfo.value.details


def test_protocol_malformed_is_40001(conn, factory):
    with pytest.raises(InvalidArgument) as excinfo:
        factory.register(protocol_version="1.0")
    assert excinfo.value.details["field"] == "protocol_version"


def test_register_rejects_credential_fields_before_touching_db(conn, factory):
    from app.supply import security as sec

    with pytest.raises(sec.CredentialFieldRejected):
        sec.scan_credentials({"platform": "linux", "hardware_fingerprint": "fp-c",
                              "client_version": "1", "protocol_version": "1.0.0",
                              "api_key": "sk-" + "x" * 40})
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM nodes")
        assert models._one(cur)["n"] == 0


# --------------------------------------------------------------------------- 鉴权
def test_authenticate_requires_key(conn, factory):
    from app.supply.errors import NodeKeyMissing

    with pytest.raises(NodeKeyMissing):
        models.authenticate(conn, None)
    with pytest.raises(NodeKeyMissing):
        models.authenticate(conn, "   ")


def test_authenticate_unknown_key_is_40101(conn, factory):
    factory.register()
    with pytest.raises(NodeKeyInvalid) as excinfo:
        models.authenticate(conn, "not-a-real-key")
    assert excinfo.value.code == "40101"


def test_get_node_and_find_by_fingerprint(conn, factory):
    from app.supply.errors import NodeNotFound

    result = factory.register(hardware_fingerprint="fp-find-0001-aaaa")
    assert models.get_node(conn, result.node.id).id == result.node.id
    digest = security.hash_fingerprint("fp-find-0001-aaaa")
    assert models.find_by_fingerprint(conn, "linux", digest).id == result.node.id
    assert models.find_by_fingerprint(conn, "macos", digest) is None
    with pytest.raises(NodeNotFound):
        models.get_node(conn, "n_missing")
    with pytest.raises(InvalidArgument):
        models.get_node(conn, "")


def test_node_ids_are_unique_and_time_ordered(factory, conn):
    ids = [factory.register().node.id for _ in range(3)]
    assert len(set(ids)) == 3
    for node_id in ids:
        assert node_id.startswith("n_")
        assert uuid.UUID(hex=node_id[2:]).version == 7


def test_runtime_state_is_registered_only_when_known(conn, factory):
    node = factory.register().node
    assert models.record_runtime_state(conn, node, "yield_paused") == "yield_paused"
    assert models.get_node(conn, node.id).runtime_state == "yield_paused"
    # 未知值忽略不报错，也不改库（spec runtime_state 描述）
    assert models.record_runtime_state(conn, models.get_node(conn, node.id),
                                       "teleporting") is None
    assert models.get_node(conn, node.id).runtime_state == "yield_paused"
    assert models.normalize_runtime_state(None) is None
    assert models.normalize_runtime_state(" ONLINE ") == "online"
