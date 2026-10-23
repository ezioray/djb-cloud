# SPDX-License-Identifier: Apache-2.0
"""上游申报与本地体检回执（M02 §6.3 / §3 / INV-02 / INV-04 / H1）。"""
from __future__ import annotations

import uuid

import pytest

from app.supply import models, upstream
from app.supply.errors import InvalidArgument, NodeStateForbidden, UpstreamNotFound

URL = "https://upstream.example/v1"


def _events(conn, node_id):
    with conn.cursor() as cur:
        cur.execute("SELECT kind, reason_code, payload FROM node_events WHERE node_id = %s "
                    "ORDER BY seq", (node_id,))
        return models._rows(cur)


def _upstream_events(conn, node_id):
    with conn.cursor() as cur:
        cur.execute("SELECT payload FROM supply_outbox WHERE aggregate_id = %s "
                    "AND type = 'node.upstream.changed' ORDER BY occurred_at", (node_id,))
        return [row["payload"] for row in models._rows(cur)]


# --------------------------------------------------------------------------- 申报
def test_declare_creates_declared_upstream(conn, factory):
    node = factory.active_node()[0]
    declared, created = upstream.declare(
        conn, node=node, access_type="A1", base_url=URL, models_list=["gpt-4o-mini", "gpt-4o"],
        upstream_protocol="openai-chat", credential_handle="keychain:djb-up",
        now=factory.moment, trace_id="trace-up")

    assert created is True
    assert declared.state == "declared"
    assert declared.models == ("gpt-4o-mini", "gpt-4o")
    assert declared.credential_handle == "keychain:djb-up"
    assert declared.verified_at is None

    payload = upstream.upstream_payload(declared)
    assert payload["state"] == "declared"
    assert payload["probe_hint"] == upstream.PROBE_HINT
    assert payload["credential_registered"] is True
    assert "keychain:djb-up" not in str(payload)          # 句柄不回显

    assert _events(conn, node.id)[-1]["kind"] == "upstream_declared"
    assert [item["state"] for item in _upstream_events(conn, node.id)] == ["declared"]


def test_declare_is_idempotent_per_node_access_url(conn, factory):
    node = factory.active_node()[0]
    first, created = upstream.declare(conn, node=node, access_type="A2",
                                      base_url="http://127.0.0.1:8080/v1",
                                      models_list=["m1"], now=factory.moment)
    second, created_again = upstream.declare(conn, node=node, access_type="A2",
                                             base_url="http://127.0.0.1:8080/v1",
                                             models_list=["m1", "m2"], now=factory.moment)
    assert created is True and created_again is False
    assert second.id == first.id
    assert second.models == ("m1", "m2")
    assert len(upstream.list_upstreams(conn, node.id)) == 1


def test_declare_requires_active_node(conn, factory):
    node = factory.register().node
    with pytest.raises(NodeStateForbidden) as excinfo:
        upstream.declare(conn, node=node, access_type="A1", base_url=URL,
                         models_list=["m1"], now=factory.moment)
    assert excinfo.value.code == "40305"


@pytest.mark.parametrize("base_url", [
    "ftp://upstream.example/v1",            # 只允许 http/https
    "upstream.example/v1",                  # 不是绝对 URL
    "https://user:pass@upstream.example/v1",  # 禁 userinfo（H1）
    "https://@upstream.example/v1",
    "https:///v1",                          # 缺主机
    "",
])
def test_declare_rejects_bad_base_url(conn, factory, base_url):
    node = factory.active_node()[0]
    with pytest.raises(InvalidArgument) as excinfo:
        upstream.declare(conn, node=node, access_type="A1", base_url=base_url,
                         models_list=["m1"], now=factory.moment)
    assert excinfo.value.details["field"] == "base_url"


@pytest.mark.parametrize("overrides,field", [
    ({"access_type": "Z9"}, "access_type"),
    ({"models_list": []}, "models"),
    ({"models_list": ["m1", ""]}, "models[1]"),
    ({"upstream_protocol": "x" * 80}, "protocol"),
    ({"credential_handle": "  "}, "credential_handle"),
    ({"credential_handle": "h" * 201}, "credential_handle"),
])
def test_declare_argument_validation(conn, factory, overrides, field):
    node = factory.active_node()[0]
    params = {"access_type": "A1", "base_url": URL, "models_list": ["m1"],
              "now": factory.moment}
    params.update(overrides)
    with pytest.raises(InvalidArgument) as excinfo:
        upstream.declare(conn, node=node, **params)
    assert excinfo.value.details["field"] == field


def test_declare_enforces_model_and_upstream_limits(conn, factory):
    node = factory.active_node()[0]
    too_many_models = [f"m{i}" for i in range(201)]
    with pytest.raises(InvalidArgument) as excinfo:
        upstream.declare(conn, node=node, access_type="A1", base_url=URL,
                         models_list=too_many_models, now=factory.moment)
    assert excinfo.value.details["field"] == "models"

    for index in range(16):
        upstream.declare(conn, node=node, access_type="A1",
                         base_url=f"https://up.example/{index}", models_list=["m1"],
                         now=factory.moment)
    with pytest.raises(InvalidArgument) as excinfo:
        upstream.declare(conn, node=node, access_type="A1", base_url="https://up.example/17",
                         models_list=["m1"], now=factory.moment)
    assert excinfo.value.details["field"] == "access_type"


# --------------------------------------------------------------------------- 体检回执
def _declared(conn, factory):
    node = factory.active_node()[0]
    declared, _ = upstream.declare(conn, node=node, access_type="A1", base_url=URL,
                                   models_list=["m1"], now=factory.moment)
    return node, declared


def test_probe_verified(conn, factory):
    node, declared = _declared(conn, factory)
    updated = upstream.report_probe(
        conn, node=node, upstream_id=str(declared.id), reachable=True, latency_ms=42,
        model_checks=[{"model": "m1", "ok": True}], checked_at="2026-10-23T00:00:00Z",
        now=factory.moment, trace_id="trace-probe")

    assert updated.state == "verified"
    assert updated.verified_at == factory.moment
    assert updated.rejected_reason_code is None
    assert [item["state"] for item in _upstream_events(conn, node.id)] == ["declared", "verified"]

    probed = [item for item in _events(conn, node.id) if item["kind"] == "upstream_probed"]
    assert len(probed) == 1
    assert probed[0]["payload"]["from"] == "declared"
    assert probed[0]["payload"]["to"] == "verified"
    assert probed[0]["payload"]["latency_ms"] == 42


def test_probe_unreachable_is_rejected(conn, factory):
    node, declared = _declared(conn, factory)
    updated = upstream.report_probe(conn, node=node, upstream_id=declared.id,
                                    reachable=False, error_class="timeout",
                                    now=factory.moment)
    assert updated.state == "rejected"
    assert updated.rejected_reason_code == "unreachable"
    assert updated.verified_at is None


def test_probe_model_check_failure_uses_its_error_class(conn, factory):
    node, declared = _declared(conn, factory)
    updated = upstream.report_probe(
        conn, node=node, upstream_id=declared.id, reachable=True,
        model_checks=[{"model": "m1", "ok": True},
                      {"model": "m2", "ok": False, "error_class": "model_missing"}],
        now=factory.moment)
    assert updated.state == "rejected"
    assert updated.rejected_reason_code == "model_missing"


def test_probe_can_change_verdict_on_recheck(conn, factory):
    """上游会坏也会好：重复体检允许改变结论，历史进 node_events。"""
    node, declared = _declared(conn, factory)
    upstream.report_probe(conn, node=node, upstream_id=declared.id, reachable=True,
                          now=factory.moment)
    broken = upstream.report_probe(conn, node=node, upstream_id=declared.id, reachable=False,
                                   now=factory.moment)
    assert broken.state == "rejected"
    fixed = upstream.report_probe(conn, node=node, upstream_id=declared.id, reachable=True,
                                  now=factory.moment)
    assert fixed.state == "verified"
    transitions = [item["payload"]["to"] for item in _events(conn, node.id)
                   if item["kind"] == "upstream_probed"]
    assert transitions == ["verified", "rejected", "verified"]


def test_probe_unknown_upstream_is_40401(conn, factory):
    node = factory.active_node()[0]
    with pytest.raises(UpstreamNotFound) as excinfo:
        upstream.report_probe(conn, node=node, upstream_id=uuid.uuid4(), reachable=True,
                              now=factory.moment)
    assert excinfo.value.code == "40401"


def test_probe_cannot_touch_another_nodes_upstream(conn, factory):
    node, declared = _declared(conn, factory)
    other = factory.active_node()[0]
    with pytest.raises(UpstreamNotFound):
        upstream.report_probe(conn, node=other, upstream_id=declared.id, reachable=True,
                              now=factory.moment)


@pytest.mark.parametrize("overrides,field", [
    ({"upstream_id": "not-a-uuid"}, "upstream_id"),
    ({"reachable": "yes"}, "reachable"),
    ({"latency_ms": -5}, "latency_ms"),
    ({"error_class": "x" * 80}, "error_class"),
    ({"model_checks": [{"model": "m1"}]}, "model_checks[0].ok"),
    ({"model_checks": [{"ok": True}]}, "model_checks[0].model"),
    ({"model_checks": "nope"}, "model_checks"),
    ({"checked_at": ""}, "checked_at"),
])
def test_probe_argument_validation(conn, factory, overrides, field):
    node, declared = _declared(conn, factory)
    params = {"upstream_id": declared.id, "reachable": True, "now": factory.moment}
    params.update(overrides)
    with pytest.raises(InvalidArgument) as excinfo:
        upstream.report_probe(conn, node=node, **params)
    assert excinfo.value.details["field"] == field


def test_probe_requires_active_node(conn, factory):
    node, declared = _declared(conn, factory)
    with conn.cursor() as cur:
        cur.execute("UPDATE nodes SET state = 'frozen' WHERE id = %s", (node.id,))
    with pytest.raises(NodeStateForbidden):
        upstream.report_probe(conn, node=models.get_node(conn, node.id),
                              upstream_id=declared.id, reachable=True, now=factory.moment)


def test_upstream_transition_table_is_declared():
    assert upstream.UPSTREAM_TRANSITIONS["declared"] >= {"probing", "verified", "rejected"}
    assert upstream.UPSTREAM_TRANSITIONS["probing"] == frozenset({"verified", "rejected"})
    assert "verified" in upstream.UPSTREAM_TRANSITIONS["rejected"]
    assert "rejected" in upstream.UPSTREAM_TRANSITIONS["verified"]
