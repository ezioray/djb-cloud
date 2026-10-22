# SPDX-License-Identifier: Apache-2.0
"""版本存储 / digest / 幂等 / 只追加护栏（T2，需要 DJB_DSN）。

覆盖 M10 §3 不变量：
INV-01（digest 可复算、version 单调不跳号不复用、同 key 单 active）、INV-03（自批自核）、
INV-05（secret-ref 只存引用）、INV-09（回滚不改历史，新版本记 rollback_to）；
以及 §5 的唯一约束 / 索引与 1002–1004 三张表的结构性约束。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from psycopg.types.json import Jsonb

from app.config_center import canonical, registry, store
from app.config_center.errors import (
    DangerousKeyForbidden,
    IdempotencyConflict,
    ValidationFailed,
    VersionNotFound,
)
from configkit import assert_db_error, new_idempotency_key

REG = registry.load()
NOW = datetime(2026, 10, 23, 0, 0, tzinfo=timezone.utc)


def draft(conn, *, key="billing.service_fee_bps", value=1500, actor="u1", **kwargs):
    return store.create_draft(conn, key=key, value=value, reason="测试变更", actor=actor, **kwargs)


def count_versions(conn, key="billing.service_fee_bps") -> int:
    row = conn.execute("SELECT count(*) FROM config_versions WHERE key = %s", (key,)).fetchone()
    return int(row[0])


def raw_version(conn, *, key="billing.service_fee_bps", version=1, value=1500,
                value_type="integer", unit="bps", content_digest=None, request_digest=None,
                status="draft", published_by=None, approved_by=None, scope="global",
                scope_id="", secret_ref=None, rollback_to=0, idempotency_key=None,
                schema_ref=None):
    """绕过 store 直接插一行（用来证明库层约束自己站得住，不靠应用层自觉）。"""
    store.sync_item(conn, REG.require(key))
    digest = content_digest or canonical.version_digest(
        key=key, value=value, schema_ref=schema_ref or f"{key}@v1", unit=unit)
    req = request_digest or canonical.request_digest(
        key=key, scope=scope, scope_id=scope_id, value=value)
    conn.execute(
        """INSERT INTO config_versions
             (namespace, key, scope, scope_id, version, value_type, unit, schema_ref,
              value, secret_ref, content_digest, request_digest, status, published_by,
              approved_by, rollback_to, reason, idempotency_key, created_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (key.split(".")[0], key, scope, scope_id, version, value_type, unit,
         schema_ref or f"{key}@v1", None if secret_ref else Jsonb(value),
         Jsonb(secret_ref) if secret_ref else None, digest, req, status, published_by,
         approved_by, rollback_to, "测试变更", idempotency_key, "u1"))


# ─────────────────────────────────────────────── 注册表落库
def test_sync_items_is_idempotent(conn):
    first = store.sync_items(conn)
    assert first == {"total": 36, "inserted": 36}
    second = store.sync_items(conn)
    assert second == {"total": 36, "inserted": 0}
    row = conn.execute("""SELECT risk_level, default_value, dangerous
                            FROM config_items WHERE key = 'billing.service_fee_bps'""").fetchone()
    assert row[0] == "P0" and row[1] == 1500 and row[2] is False


def test_config_items_is_registry_only(conn):
    store.sync_items(conn)
    assert_db_error(conn, "immutable", lambda c: c.execute(
        "UPDATE config_items SET key = 'billing.other_key' WHERE key = 'billing.service_fee_bps'"))
    assert_db_error(conn, "DELETE not allowed", lambda c: c.execute(
        "DELETE FROM config_items WHERE key = 'billing.service_fee_bps'"))
    # 外键会让 TRUNCATE 先被 FK 拦下；用 CASCADE 才能走到本模块的语句级触发器
    assert_db_error(conn, "TRUNCATE not allowed", lambda c: c.execute(
        "TRUNCATE config_items CASCADE"))


# ─────────────────────────────────────────────── 建草稿 + digest（INV-01）
def test_create_draft_digest_is_recomputable(conn):
    row = draft(conn)
    assert row["version"] == 1
    assert row["status"] == "draft"
    assert row["replayed"] is False
    assert row["namespace"] == "billing"
    assert row["content_digest"] == canonical.version_digest(
        key="billing.service_fee_bps", value=1500,
        schema_ref="billing.service_fee_bps@v1", unit="bps")
    assert store.verify_version(row) is True
    assert store.recompute_digests(conn) == {"total": 1, "ok": 1, "bad": [], "diff": 0}


def test_versions_increment_without_gap(conn):
    assert draft(conn)["version"] == 1
    assert draft(conn, value=1600)["version"] == 2
    assert draft(conn, value=1700)["version"] == 3
    versions = [row["version"] for row in store.list_versions(conn, key="billing.service_fee_bps")]
    assert versions == [1, 2, 3]
    assert store.get_version(conn, key="billing.service_fee_bps")["version"] == 3
    assert store.get_version(conn, key="billing.service_fee_bps", version=2)["value"] == 1600
    assert store.get_version(conn, key="billing.service_fee_bps", version=99) is None


def test_version_gap_and_reuse_are_rejected(conn):
    draft(conn)                                        # v1
    assert_db_error(conn, "INV-01", lambda c: raw_version(c, version=3))


def test_digest_shape_is_enforced_by_db(conn):
    assert_db_error(conn, "config_versions_digest_ck", lambda c: raw_version(
        c, content_digest="z" * 64))


def test_value_type_shape_is_enforced_by_db(conn):
    assert_db_error(conn, "config_versions_value_shape_ck", lambda c: raw_version(
        c, value="1500", value_type="integer", unit="bps"))


# ─────────────────────────────────────────────── 只追加（INV-01 / INV-09）
def test_versions_are_append_only(conn):
    row = draft(conn)
    version_id = row["version_id"]
    assert_db_error(conn, "immutable", lambda c: c.execute(
        "UPDATE config_versions SET value = '1600'::jsonb WHERE version_id = %s", (version_id,)))
    assert_db_error(conn, "append-only", lambda c: c.execute(
        "DELETE FROM config_versions WHERE version_id = %s", (version_id,)))
    assert_db_error(conn, "TRUNCATE not allowed", lambda c: c.execute("TRUNCATE config_versions"))


def test_status_machine_transitions(conn):
    key = "content.wordlist_version"                    # P2：不要求复核人
    draft(conn, key=key, value="v1")
    activated = store.activate(conn, key=key, version=1, published_by="u1")
    assert activated["status"] == "active"
    assert activated["published_by"] == "u1"

    # active → draft 非法（INV-09：回滚只生成新版本）
    assert_db_error(conn, "illegal status transition", lambda c: c.execute(
        "UPDATE config_versions SET status = 'draft' WHERE key = %s AND version = 1", (key,)))
    # active → superseded 合法
    conn.execute("UPDATE config_versions SET status = 'superseded' WHERE key = %s AND version = 1",
                 (key,))
    assert conn.execute("SELECT status FROM config_versions WHERE key = %s", (key,)).fetchone()[0] \
        == "superseded"
    # 终态不可复活
    assert_db_error(conn, "illegal status transition", lambda c: c.execute(
        "UPDATE config_versions SET status = 'active' WHERE key = %s AND version = 1", (key,)))


def test_effective_and_publisher_only_set_on_activation(conn):
    key = "content.wordlist_version"
    draft(conn, key=key, value="v1")
    assert_db_error(conn, "only set when activating", lambda c: c.execute(
        "UPDATE config_versions SET approved_by = 'u2' WHERE key = %s AND version = 1", (key,)))


def test_inv03_approver_required_for_p0(conn):
    key = "billing.service_fee_bps"                     # P0
    draft(conn)
    # 缺复核人
    assert_db_error(conn, "INV-03", lambda c: store.activate(
        c, key=key, version=1, published_by="u1"))
    # 自批自核
    assert_db_error(conn, "INV-03", lambda c: store.activate(
        c, key=key, version=1, published_by="u1", approved_by="u1"))
    # 正常双人
    row = store.activate(conn, key=key, version=1, published_by="u1", approved_by="u2")
    assert (row["status"], row["approved_by"]) == ("active", "u2")


def test_direct_active_insert_requires_publisher(conn):
    assert_db_error(conn, "config_versions_active_publisher_ck", lambda c: raw_version(
        c, status="active", published_by=None))


def test_only_one_active_version_per_key(conn):
    key = "billing.service_fee_bps"
    draft(conn)
    draft(conn, value=1600)
    store.activate(conn, key=key, version=1, published_by="u1", approved_by="u2")
    store.activate(conn, key=key, version=2, published_by="u1", approved_by="u2")
    statuses = dict(conn.execute(
        "SELECT version, status FROM config_versions WHERE key = %s ORDER BY version", (key,)
    ).fetchall())
    assert statuses == {1: "superseded", 2: "active"}
    assert store.active_version(conn, key=key)["version"] == 2
    # 再插一个 active 直接被部分唯一索引拒绝
    assert_db_error(conn, "config_versions_one_active_uq", lambda c: raw_version(
        c, version=3, status="active", published_by="u1"))


def test_activate_missing_or_non_draft_raises(conn):
    with pytest.raises(VersionNotFound) as excinfo:
        store.activate(conn, key="content.wordlist_version", version=1, published_by="u1")
    assert excinfo.value.code == 47006

    key = "content.wordlist_version"
    draft(conn, key=key, value="v1")
    store.activate(conn, key=key, version=1, published_by="u1")
    with pytest.raises(VersionNotFound):
        store.activate(conn, key=key, version=1, published_by="u1")


# ─────────────────────────────────────────────── 幂等（§3 / uq_idem）
def test_idempotent_replay_returns_first_result(conn):
    idem = new_idempotency_key()
    first = draft(conn, idempotency_key=idem)
    second = draft(conn, idempotency_key=idem)
    assert second["replayed"] is True
    assert second["version_id"] == first["version_id"]
    assert count_versions(conn) == 1


def test_idempotent_conflict_on_different_payload(conn):
    idem = new_idempotency_key()
    draft(conn, idempotency_key=idem)
    with pytest.raises(IdempotencyConflict) as excinfo:
        draft(conn, value=1600, idempotency_key=idem)
    assert excinfo.value.code == 40919
    assert count_versions(conn) == 1


def test_idempotency_key_is_scoped(conn):
    idem = new_idempotency_key()
    draft(conn, idempotency_key=idem)
    other = draft(conn, scope="tenant", scope_id="tenant-a", idempotency_key=idem)
    assert other["replayed"] is False
    assert other["scope"] == "tenant" and other["scope_id"] == "tenant-a"


def test_idempotency_race_falls_back_to_replay(conn, monkeypatch):
    """并发兜底：同幂等键被「别人」先落（这里用 hide 首次查询模拟），应回到同载荷重放。"""
    idem = new_idempotency_key()
    first = draft(conn, idempotency_key=idem)

    real_find = store.find_idempotent
    calls = {"n": 0}

    def flaky(connection, *, scope, idempotency_key):
        if idempotency_key == idem and calls["n"] == 0:
            calls["n"] += 1
            return None                      # 首次查询「看不见」已有行 → 走到 INSERT
        return real_find(connection, scope=scope, idempotency_key=idempotency_key)

    monkeypatch.setattr(store, "find_idempotent", flaky)
    replayed = draft(conn, idempotency_key=idem)
    assert calls["n"] == 1
    assert replayed["replayed"] is True
    assert replayed["version_id"] == first["version_id"]
    assert count_versions(conn) == 1


def test_idempotency_key_shape(conn):
    with pytest.raises(ValidationFailed):
        draft(conn, idempotency_key="short")


# ─────────────────────────────────────────────── secret-ref（INV-05）
def test_secret_ref_only_key_stores_reference(conn):
    ref = {"scheme": "kms", "path": "alias/treasury-signing", "inject": "sdk", "version": "v1"}
    row = store.create_draft(conn, key="treasury.deposit_address_ref", secret_ref=ref,
                             reason="初始化引用", actor="u1")
    assert row["value"] is None
    assert row["secret_ref"] == ref
    assert store.verify_version(row) is True
    assert store.recompute_digests(conn)["diff"] == 0


def test_secret_ref_key_rejects_plaintext(conn):
    with pytest.raises(ValidationFailed):
        store.create_draft(conn, key="treasury.deposit_address_ref", value={"a": 1},
                           reason="初始化引用", actor="u1")
    with pytest.raises(ValidationFailed):
        store.create_draft(conn, key="treasury.deposit_address_ref",
                           reason="初始化引用", actor="u1")
    with pytest.raises(ValidationFailed):
        store.create_draft(conn,
                           key="treasury.deposit_address_ref",
                           secret_ref={"scheme": "kms", "path": "a", "inject": "sdk",
                                       "version": "v1", "extra": 1},
                           reason="初始化引用", actor="u1")


def test_db_rejects_plaintext_for_secret_ref_key(conn):
    assert_db_error(conn, "INV-05", lambda c: raw_version(
        c, key="treasury.deposit_address_ref", value={"scheme": "kms"}, value_type="json",
        unit="json"))


# ─────────────────────────────────────────────── digest 复算（可发现被篡改的摘要）
def test_recompute_detects_bad_digest(conn):
    draft(conn)
    raw_version(conn, version=2, value=1600, content_digest="a" * 64)
    report = store.recompute_digests(conn)
    assert report["total"] == 2 and report["diff"] == 1
    assert report["bad"][0]["version"] == 2
    assert len(report["bad"][0]["recomputed"]) == 64


# ─────────────────────────────────────────────── scope / 输入校验
@pytest.mark.parametrize("kwargs", [
    {"scope": "galaxy"},
    {"scope": "global", "scope_id": "x"},
    {"scope": "tenant", "scope_id": ""},
    {"scope": "tenant", "scope_id": "bad id"},
])
def test_scope_validation(conn, kwargs):
    with pytest.raises(ValidationFailed):
        draft(conn, **kwargs)


def test_reason_actor_and_value_type_validation(conn):
    with pytest.raises(ValidationFailed):
        store.create_draft(conn, key="billing.service_fee_bps", value=1500, reason="短", actor="u1")
    with pytest.raises(ValidationFailed):
        store.create_draft(conn, key="billing.service_fee_bps", value=1500, reason="测试变更", actor="")
    with pytest.raises(ValidationFailed):
        draft(conn, value_type="json")
    with pytest.raises(ValidationFailed):
        draft(conn, value=None)


def test_dangerous_and_unknown_keys_rejected(conn):
    with pytest.raises(DangerousKeyForbidden):
        draft(conn, key="risk.rule_version", value="v1")
    with pytest.raises(ValidationFailed):
        draft(conn, key="billing.unknown_key", value=1)


def test_effective_at_requires_timezone(conn):
    row = draft(conn, effective_at="2026-11-01T02:00:00Z")
    assert row["effective_at"] is not None
    with pytest.raises(ValidationFailed):
        draft(conn, effective_at="2026-11-01T02:00:00")


# ─────────────────────────────────────────────── 1002–1004 三表结构
def _insert_request(conn, *, proposed_by="u1", approved_by=(), status="pending_approval",
                    key="billing.service_fee_bps", decision=None):
    conn.execute(
        """INSERT INTO config_publish_requests
             (key, namespace, key_set, versions, risk_level, proposed_by, approved_by,
              status, decision, reason, expires_at)
           VALUES (%s, %s, %s, %s, 'P0', %s, %s, %s, %s, '测试发布单', now() + interval '4 hours')""",
        (key, key.split(".")[0], [key], Jsonb({key: 1}), proposed_by, list(approved_by), status,
         decision))


def test_publish_requests_inv03_and_enums(conn):
    store.sync_items(conn)
    _insert_request(conn, approved_by=("u2",))
    assert conn.execute("SELECT count(*) FROM config_publish_requests").fetchone()[0] == 1
    assert_db_error(conn, "config_publish_requests_sod_ck", lambda c: _insert_request(
        c, proposed_by="u1", approved_by=("u1",)))
    assert_db_error(conn, "config_publish_requests_status_ck", lambda c: _insert_request(
        c, status="not_a_state"))
    assert_db_error(conn, "config_publish_requests_closed_ck", lambda c: _insert_request(
        c, status="closed", approved_by=("u2",), decision="approve"))


def test_snapshot_policy_version_is_derived_and_append_only(conn):
    digest = canonical.snapshot_digest([{
        "key": "billing.service_fee_bps", "scope": "global", "scope_id": "", "version": 1,
        "content_digest": canonical.version_digest(
            key="billing.service_fee_bps", value=1500,
            schema_ref="billing.service_fee_bps@v1", unit="bps")}])
    entries = [{"key": "billing.service_fee_bps", "scope": "global", "scope_id": "",
                "version": 1, "content_digest": "a" * 64}]
    conn.execute(
        """INSERT INTO config_snapshots (snapshot_digest, period, entries, entries_count)
           VALUES (%s, '2026-10-23', %s, 1)""", (digest, Jsonb(entries)))
    row = conn.execute("SELECT policy_version FROM config_snapshots").fetchone()
    assert row[0] == digest[:12]                                   # INV-08
    assert_db_error(conn, "append-only", lambda c: c.execute(
        "UPDATE config_snapshots SET period = 'x'"))
    assert_db_error(conn, "config_snapshots_digest_uq", lambda c: c.execute(
        """INSERT INTO config_snapshots (snapshot_digest, period, entries, entries_count)
           VALUES (%s, '2026-10-24', %s, 1)""", (digest, Jsonb(entries))))
    assert_db_error(conn, "config_snapshots_entries_ck", lambda c: c.execute(
        """INSERT INTO config_snapshots (snapshot_digest, period, entries, entries_count)
           VALUES (%s, '2026-10-25', '[]'::jsonb, 2)""", ("b" * 64,)))


def test_drift_append_only_and_resolve_once(conn):
    conn.execute(
        """INSERT INTO config_drifts (namespace, key, desired_version, effective_version,
                                      running_version, expected, actual)
           VALUES ('billing', 'billing.service_fee_bps', 2, 1, 1, '1500', '1400')""")
    drift_id = conn.execute("SELECT drift_id FROM config_drifts").fetchone()[0]
    conn.execute("UPDATE config_drifts SET resolved_at = now(), resolution = '已收敛' "
                 "WHERE drift_id = %s", (drift_id,))
    assert_db_error(conn, "already resolved", lambda c: c.execute(
        "UPDATE config_drifts SET resolution = 'again' WHERE drift_id = %s", (drift_id,)))
    assert_db_error(conn, "append-only", lambda c: c.execute(
        "DELETE FROM config_drifts WHERE drift_id = %s", (drift_id,)))
    assert_db_error(conn, "config_drifts_resolution_ck", lambda c: c.execute(
        """INSERT INTO config_drifts (namespace, key, running_version, resolution)
           VALUES ('billing', 'billing.service_fee_bps', 1, '只有结论没有时间')"""))
