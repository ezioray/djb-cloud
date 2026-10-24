# SPDX-License-Identifier: AGPL-3.0-or-later
"""策略版本 + digest + 304（M02 §6.4 / INV-06 / spec NodePolicy）。"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.supply import config_source, facts, features, models, policy
from app.supply.errors import InvalidArgument, PolicyVersionRegression


def _settings(**overrides):
    base = {facts.CONFIG_KEYS["heartbeat_interval_s"]: 30,
            facts.CONFIG_KEYS["stale_after_s"]: 45,
            facts.CONFIG_KEYS["announcement_ttl_s"]: 60,
            facts.CONFIG_KEYS["max_nodes_per_account"]: 100,
            facts.CONFIG_KEYS["review_sla_h"]: 24}
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- canonical / digest
def test_canonical_json_is_order_independent():
    left = {"b": 1, "a": {"y": 2, "x": [1, 2]}}
    right = {"a": {"x": [1, 2], "y": 2}, "b": 1}
    assert policy.canonical_json(left) == policy.canonical_json(right)
    assert policy.digest_of(left) == policy.digest_of(right)
    assert len(policy.digest_of(left)) == 64


def test_digest_changes_with_content():
    base = policy.build_doc(_settings(), protocol_version="1.0.0")
    other = policy.build_doc(_settings(**{facts.CONFIG_KEYS["stale_after_s"]: 50}),
                             protocol_version="1.0.0")
    assert policy.digest_of(base) != policy.digest_of(other)


def test_build_doc_shape_is_spec_compatible():
    doc = policy.build_doc(_settings(), protocol_version="1.0.0",
                           quotas=[{"name": "qps", "window_seconds": 60, "value": 5}],
                           directives=[{"name": "pause_orders"}])
    assert set(doc) == {"protocol_version", "settings", "quotas", "directives"}
    assert doc["quotas"] == [{"name": "qps", "window_seconds": 60, "value": 5}]
    assert doc["directives"] == [{"name": "pause_orders"}]
    assert doc["settings"][facts.CONFIG_KEYS["heartbeat_interval_s"]] == 30


@pytest.mark.parametrize("quotas,field", [
    ([{"name": "", "window_seconds": 60}], "quotas[0].name"),
    ([{"name": "qps", "window_seconds": 0}], "quotas[0].window_seconds"),
    ([{"name": "qps", "window_seconds": 60, "value": -1}], "quotas[0].value"),
    ([{"name": "qps", "window_seconds": 60, "api_key": "x"}], "quotas"),
    ("nope", "quotas"),
])
def test_quota_validation(quotas, field):
    with pytest.raises(InvalidArgument) as excinfo:
        policy.build_doc(_settings(), protocol_version="1.0.0", quotas=quotas)
    assert excinfo.value.details["field"] == field


def test_directive_validation_rejects_secret_keys():
    with pytest.raises(InvalidArgument):
        policy.build_doc(_settings(), protocol_version="1.0.0",
                         directives=[{"name": "x", "secret": "s"}])
    with pytest.raises(InvalidArgument):
        policy.build_doc(_settings(), protocol_version="1.0.0",
                         directives=[{"value": 1}])


# --------------------------------------------------------------------------- 版本
def test_first_policy_gets_version_one(conn, factory):
    node = factory.active_node()[0]
    current = policy.ensure(conn, node=node, settings=_settings(), protocol_version="1.0.0",
                            now=factory.moment)
    assert current.policy_version == "1"
    assert current.status == "active"
    assert models.get_node(conn, node.id).policy_version == "1"
    assert policy.latest_version(conn, node_id=node.id) == "1"


def test_same_content_does_not_bump_version(conn, factory):
    node = factory.active_node()[0]
    first = policy.ensure(conn, node=node, settings=_settings(), protocol_version="1.0.0",
                          now=factory.moment)
    second = policy.ensure(conn, node=node, settings=_settings(), protocol_version="1.0.0",
                           now=factory.moment)
    assert second.policy_version == first.policy_version
    assert len(policy.history(conn, node.id)) == 1


def test_changed_content_bumps_version_and_supersedes(conn, factory):
    node = factory.active_node()[0]
    first = policy.ensure(conn, node=node, settings=_settings(), protocol_version="1.0.0",
                          now=factory.moment)
    second = policy.ensure(conn, node=node,
                           settings=_settings(**{facts.CONFIG_KEYS["stale_after_s"]: 50}),
                           protocol_version="1.0.0", now=factory.moment)

    assert second.policy_version == "2"
    assert second.digest != first.digest
    rows = policy.history(conn, node.id)
    assert [item.policy_version for item in rows] == ["2", "1"]
    assert [item.status for item in rows] == ["active", "superseded"]
    assert models.get_node(conn, node.id).policy_version == "2"


def test_verify_rejects_tampered_doc():
    current = policy.Policy(policy_version="1", node_id="n", protocol_version="1.0.0",
                            issued_at=datetime(2026, 10, 23, tzinfo=timezone.utc),
                            effective_at=datetime(2026, 10, 23, tzinfo=timezone.utc),
                            digest=policy.digest_of({"a": 1}), doc={"a": 2}, status="active")
    with pytest.raises(PolicyVersionRegression) as excinfo:
        policy.verify(current)
    assert excinfo.value.code == "40907"

    ok = policy.Policy(**{**current.__dict__, "doc": {"a": 1}})
    assert policy.verify(ok) is None


def test_version_must_increase(conn, factory):
    node = factory.active_node()[0]
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO node_policies (policy_version, node_id, protocol_version,
                                          effective_at, digest, doc, created_at)
               VALUES ('not-a-number', %s, '1.0.0', now(), %s,
                       '{"quotas": [], "directives": []}'::jsonb, now())""",
            (node.id, "0" * 64))
    with pytest.raises(PolicyVersionRegression) as excinfo:
        policy.ensure(conn, node=node, settings=_settings(), protocol_version="1.0.0",
                      now=factory.moment)
    assert excinfo.value.code == "40907"


def test_policy_content_has_no_credentials_and_no_issued_at(conn, factory):
    node = factory.active_node()[0]
    current = policy.ensure(conn, node=node, settings=_settings(), protocol_version="1.0.0",
                            now=factory.moment)
    assert "issued_at" not in current.doc              # 时间戳不进 digest
    assert "secret" not in policy.canonical_json(current.doc)
    payload = policy.policy_payload(current)
    assert payload["issued_at"].endswith("Z")
    assert payload["digest"] == current.digest


def test_ensure_for_node_uses_config_provider(conn, factory):
    node = factory.active_node()[0]
    config_source.set_provider(lambda c, n: {
        facts.CONFIG_KEYS["heartbeat_interval_s"]: 20,
        "quotas": [{"name": "qps", "window_seconds": 60, "value": 7}],
    })
    try:
        current = policy.ensure_for_node(conn, node=node, now=factory.moment)
    finally:
        config_source.set_provider(None)
    assert current.doc["settings"][facts.CONFIG_KEYS["heartbeat_interval_s"]] == 20
    assert current.quotas == [{"name": "qps", "window_seconds": 60, "value": 7}]


# --------------------------------------------------------------------------- ETag / 304
def test_etag_matching_tolerates_quotes_and_weak_validators():
    current = policy.Policy(policy_version="7", node_id="n", protocol_version="1.0.0",
                            issued_at=datetime(2026, 10, 23, tzinfo=timezone.utc),
                            effective_at=datetime(2026, 10, 23, tzinfo=timezone.utc),
                            digest="a" * 64, doc={}, status="active")
    assert policy.etag_matches("7", current) is True
    assert policy.etag_matches('"7"', current) is True
    assert policy.etag_matches('W/"7"', current) is True
    assert policy.etag_matches("6", current) is False
    assert policy.etag_matches(None, current) is False
    assert policy.etag_matches("a" * 64, current) is True      # 也接受 digest
    assert policy.etag_matches(" 7 , 8 ", current) is True


def test_policy_etag_switch_is_registered_and_off():
    switch = features.get("supply.policy_etag_304")
    assert switch.default is False
    assert switch.owner and switch.rollback_rule and switch.expire_at
