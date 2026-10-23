# SPDX-License-Identifier: Apache-2.0
"""幂等与指纹去重（M03 §3.1 / §8.2 / INV-M03-03）。纯函数 + DB 两段。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.gateway import errors, facts, idempotency, models, store
from gatewaykit import NOW, principal_dict


@pytest.fixture
def caller() -> models.Principal:
    return models.coerce_principal(principal_dict(account_id=uuid.uuid4(),
                                                  tenant_id=uuid.uuid4(), api_key_id=11))


# ─────────────────────────────────────────────────────── 纯函数
def test_body_hash_is_stable_across_key_order():
    first = idempotency.body_hash({"model": "m1", "messages": [{"role": "user"}]})
    second = idempotency.body_hash({"messages": [{"role": "user"}], "model": "m1"})
    assert first == second and len(first) == 64


def test_body_hash_changes_with_payload():
    assert idempotency.body_hash({"model": "m1"}) != idempotency.body_hash({"model": "m2"})


def test_require_key_accepts_valid_length():
    key = "a" * facts.IDEMPOTENCY_KEY_MIN_LENGTH
    assert idempotency.require_key(key) == key
    assert idempotency.require_key(None) is None
    assert idempotency.require_key("   ") is None


@pytest.mark.parametrize("key", ["short", "x" * (facts.IDEMPOTENCY_KEY_MAX_LENGTH + 1)])
def test_require_key_rejects_bad_length_with_40001(key):
    with pytest.raises(errors.GatewayError) as info:
        idempotency.require_key(key)
    assert (info.value.http_status, info.value.code) == (400, 40001)
    assert info.value.details["field"] == "X-DJB-Idempotency-Key"


def test_scope_includes_account_and_key(caller):
    scope = idempotency.scope_of("POST", "/v1/chat/completions", caller)
    assert scope.startswith("idem:POST:/v1/chat/completions:")
    assert caller.account_id in scope and str(caller.api_key_id) in scope
    assert idempotency.fingerprint_scope("POST", "/v1/chat/completions",
                                        caller).startswith("fp:POST:")


def test_scopes_differ_between_accounts(caller):
    other = models.coerce_principal(principal_dict(account_id=uuid.uuid4(),
                                                   tenant_id=uuid.UUID(caller.tenant_id),
                                                   api_key_id=caller.api_key_id))
    assert idempotency.scope_of("POST", "/v1/chat/completions", caller) != \
        idempotency.scope_of("POST", "/v1/chat/completions", other)


def test_window_for_stream_is_shorter():
    assert idempotency.window_for(stream=False) == facts.FINGERPRINT_WINDOW_S
    assert idempotency.window_for(stream=True) == facts.STREAM_DEDUP_WINDOW_S


# ─────────────────────────────────────────────────────── DB：回放 / 冲突 / 过期
def _save(c, *, caller, key, request_hash, now=NOW, status_code=200, payload=None,
          ttl=300, scope_kind="idem"):
    scope = (idempotency.scope_of("POST", "/v1/chat/completions", caller)
             if scope_kind == "idem"
             else idempotency.fingerprint_scope("POST", "/v1/chat/completions", caller))
    idempotency.remember(c, scope=scope, key=key, request_hash=request_hash,
                         status_code=status_code, payload=payload or {"ok": True},
                         now=now, ttl_s=ttl)
    return scope


def test_replay_returns_first_result(conn, caller):
    scope = _save(conn, caller=caller, key="k" * 20, request_hash="h" * 64,
                  payload={"id": "r1"})
    replay = idempotency.replay_or_conflict(conn, scope=scope, key="k" * 20,
                                            request_hash="h" * 64, now=NOW + timedelta(seconds=5))
    assert replay is not None
    assert replay.status_code == 200 and replay.payload == {"id": "r1"}


def test_same_key_different_payload_is_40919(conn, caller):
    scope = _save(conn, caller=caller, key="k" * 20, request_hash="h" * 64)
    with pytest.raises(errors.GatewayError) as info:
        idempotency.replay_or_conflict(conn, scope=scope, key="k" * 20,
                                       request_hash="x" * 64, now=NOW + timedelta(seconds=5))
    assert (info.value.http_status, info.value.code) == (409, 40919)
    assert info.value.type == "conflict_error"


def test_expired_record_is_not_replayed(conn, caller):
    scope = _save(conn, caller=caller, key="k" * 20, request_hash="h" * 64, ttl=60)
    assert idempotency.replay_or_conflict(conn, scope=scope, key="k" * 20,
                                          request_hash="h" * 64,
                                          now=NOW + timedelta(seconds=61)) is None


def test_fingerprint_window_is_respected(conn, caller):
    # TTL 长于窗口：专测「窗口外不再回放」这一条分支
    scope = _save(conn, caller=caller, key="f" * 64, request_hash="f" * 64, ttl=600,
                  scope_kind="fp")
    assert idempotency.replay_or_conflict(conn, scope=scope, key="f" * 64,
                                          request_hash="f" * 64,
                                          now=NOW + timedelta(seconds=299),
                                          window_s=300) is not None
    assert idempotency.replay_or_conflict(conn, scope=scope, key="f" * 64,
                                          request_hash="f" * 64,
                                          now=NOW + timedelta(seconds=301),
                                          window_s=300) is None


def test_missing_record_returns_none(conn, caller):
    scope = idempotency.scope_of("POST", "/v1/chat/completions", caller)
    assert idempotency.replay_or_conflict(conn, scope=scope, key="not-there-key-1",
                                          request_hash="h" * 64, now=NOW) is None


def test_expired_rows_are_purged(conn, caller):
    _save(conn, caller=caller, key="p" * 20, request_hash="h" * 64, ttl=10)
    purged = idempotency.delete_expired(conn, now=NOW + timedelta(seconds=11))
    assert purged == 1


def test_unexpired_rows_are_not_purged(conn, caller):
    _save(conn, caller=caller, key="q" * 20, request_hash="h" * 64, ttl=600)
    assert idempotency.delete_expired(conn, now=NOW + timedelta(seconds=5)) == 0


def test_store_returns_full_record(conn, caller):
    scope = _save(conn, caller=caller, key="s" * 20, request_hash="c" * 64,
                  payload={"x": 1}, ttl=120)
    record = store.get_idempotency(conn, scope=scope, key="s" * 20)
    assert record is not None
    assert record.request_hash == "c" * 64
    assert record.payload == {"x": 1}
    assert record.expires_at - record.created_at == timedelta(seconds=120)


def test_record_shape_rejects_bad_status_code(conn, caller):
    scope = idempotency.scope_of("POST", "/v1/chat/completions", caller)
    with pytest.raises(Exception):
        idempotency.remember(conn, scope=scope, key="t" * 20, request_hash="h" * 64,
                             status_code=999, payload={}, now=NOW, ttl_s=60)
