# SPDX-License-Identifier: AGPL-3.0-or-later
"""bundle 版本编排（service 层）：版本只增 / 签名 / TTL / 发布 / 回滚不改历史 / 状态上报。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.model_sync import facts, registry, signing, store
from app.model_sync.errors import Conflict, FeatureUnavailable, NotFound

from kit import TEST_SIGNING_KEY


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv(facts.SIGNING_KEY_ENV, TEST_SIGNING_KEY)


def _draft(conn, now, actor="admin:t"):
    return store.create_draft(conn, actor=actor, now=now)


def test_create_draft_seeds_registry_and_builds_payload(conn, now):
    bundle = _draft(conn, now)
    assert bundle["version"] == 1
    assert bundle["state"] == "draft"
    assert bundle["signature"] is None and bundle["published_at"] is None
    assert set(bundle["payload"]) == {"version", "expires_at", "models"}   # M18b 同口径
    assert bundle["payload"]["version"] == 1
    assert bundle["payload_hash"] == registry.payload_hash_of(bundle["payload"])
    assert bundle["expires_at"] == now + facts.TTL                        # 起草即定 TTL
    assert bundle["payload"]["expires_at"].endswith("Z")
    assert len(bundle["payload"]["models"]) == 6
    assert store.list_vendor_models(conn)                 # 内置注册表已灌入
    events = store.list_events(conn, bundle_id=bundle["id"])
    assert [item["event"] for item in events] == ["draft"]


def test_versions_are_monotonic(conn, now):
    versions = [_draft(conn, now)["version"] for _ in range(3)]
    assert versions == [1, 2, 3]
    assert store.latest_version(conn) == 0                # draft 尚未发布
    published = store.publish(conn, _draft(conn, now)["id"], actor="admin:t", now=now)
    assert published["version"] == 4 and store.latest_version(conn) == 4


def test_publish_signs_and_sets_ttl(conn, now):
    draft = _draft(conn, now)
    bundle = store.publish(conn, draft["id"], actor="admin:t", now=now)
    assert bundle["state"] == "published"
    assert signing.verify(bundle["payload_hash"], bundle["signature"]) is True
    assert bundle["published_at"] == now
    assert bundle["expires_at"] == now + timedelta(hours=24) == now + facts.TTL
    events = [item["event"] for item in store.list_events(conn, bundle_id=bundle["id"])]
    assert events == ["published", "draft"]


def test_publish_requires_draft_state(conn, now):
    bundle = store.publish(conn, _draft(conn, now)["id"], actor="admin:t", now=now)
    with pytest.raises(Conflict) as excinfo:
        store.publish(conn, bundle["id"], actor="admin:t", now=now)
    assert excinfo.value.code == 40919 and excinfo.value.details["state"] == "published"


def test_stale_draft_cannot_be_published(conn, now):
    from datetime import timedelta

    draft = _draft(conn, now)
    with pytest.raises(Conflict) as excinfo:
        store.publish(conn, draft["id"], actor="admin:t", now=now + timedelta(hours=25))
    assert "TTL 已过期" in excinfo.value.message
    assert store.get_bundle(conn, draft["id"])["state"] == "draft"


def test_publish_unknown_bundle_is_404(conn, now):
    import uuid

    with pytest.raises(NotFound):
        store.publish(conn, uuid.uuid4(), actor="admin:t", now=now)


def test_publish_without_key_fails_closed(conn, now, monkeypatch):
    draft = _draft(conn, now)
    monkeypatch.delenv(facts.SIGNING_KEY_ENV, raising=False)
    with pytest.raises(FeatureUnavailable) as excinfo:
        store.publish(conn, draft["id"], actor="admin:t", now=now)
    assert excinfo.value.reason == "signing_key_missing"
    assert store.get_bundle(conn, draft["id"])["state"] == "draft"   # 状态没被改


def test_rollback_creates_new_version_and_keeps_history(conn, now):
    first = store.publish(conn, _draft(conn, now)["id"], actor="admin:t", now=now)
    second = store.publish(conn, _draft(conn, now)["id"], actor="admin:t", now=now)
    assert (first["version"], second["version"]) == (1, 2)

    rolled = store.rollback(conn, first["id"], actor="admin:t", now=now)
    assert rolled["version"] == 3                         # 版本只增
    assert rolled["state"] == "published"
    # 回滚 = 同一个 models 快照 + 新版本号 / 新 TTL（version 与 expires_at 参与 hash）
    assert rolled["payload"]["models"] == first["payload"]["models"]
    assert rolled["payload"]["version"] == 3
    assert rolled["payload_hash"] != first["payload_hash"]
    assert rolled["source"] == "rollback"
    assert signing.verify(rolled["payload_hash"], rolled["signature"]) is True
    # 历史没被改写：v1 仍是 published（payload 未变），v2 变 rolled_back
    assert store.get_bundle(conn, first["id"])["state"] == "published"
    assert store.get_bundle(conn, first["id"])["payload"] == first["payload"]
    assert store.get_bundle(conn, first["id"])["payload_hash"] == first["payload_hash"]
    assert store.get_bundle(conn, second["id"])["state"] == "rolled_back"
    events = [item["event"] for item in store.list_events(conn, bundle_id=rolled["id"])]
    assert events == ["published", "rolled_back"]
    assert store.latest_version(conn) == 3


def test_rollback_to_current_is_conflict(conn, now):
    bundle = store.publish(conn, _draft(conn, now)["id"], actor="admin:t", now=now)
    with pytest.raises(Conflict) as excinfo:
        store.rollback(conn, bundle["id"], actor="admin:t", now=now)
    assert "已经是当前版本" in excinfo.value.message


def test_rollback_rejects_never_published_bundle(conn, now):
    draft = _draft(conn, now)
    with pytest.raises(Conflict):
        store.rollback(conn, draft["id"], actor="admin:t", now=now)


def test_record_state_upserts_and_emits_event(conn, now):
    row = store.record_state(conn, node_id="node-m18-alpha", applied_version=3,
                             drift={"gpt-4o-mini": "tokenizer_version"}, error_class=None,
                             now=now)
    assert row["applied_version"] == 3
    assert row["drift"] == {"gpt-4o-mini": "tokenizer_version"}
    updated = store.record_state(conn, node_id="node-m18-alpha", applied_version=4,
                                 drift={}, error_class="sync_rejected", now=now)
    assert updated["applied_version"] == 4 and updated["last_error"] == "sync_rejected"
    assert store.get_node_state(conn, "node-m18-alpha")["applied_version"] == 4
    events = [item for item in store.list_events(conn) if item["event"] == "state_applied"]
    assert len(events) == 2
    payload = {key: events[0]["detail"][key] for key in events[0]["detail"]}
    assert set(payload) <= {"error_class", "drift"}
