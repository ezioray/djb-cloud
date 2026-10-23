# SPDX-License-Identifier: Apache-2.0
"""幂等键（CR-5 / 迁移 408 / M04 §3 / 00-conventions §6.1）。

两条语义，缺一不可：
* **业务幂等**（T1/T2 已有）：同一事实不重复落库；
* **字节级回放**（本任务）：同一 (scope, key) 同载荷 → 回放首次响应；异载荷 → 40919。
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.scheduling import facts, idempotency
from app.scheduling.errors import IdempotencyConflict, InvalidArgument


# --------------------------------------------------------------------------- 纯函数
def test_scope_normalises_path_parameters():
    scope = idempotency.scope_of("post", "/api/v1/schedule/quotes")
    assert scope == "POST /api/v1/schedule/quotes"
    assert idempotency.scope_of("get", f"/api/v1/schedule/decisions/{uuid.uuid4()}") \
        == "GET /api/v1/schedule/decisions/{id}"
    assert idempotency.scope_of("get", "/api/v1/node/n_abcdef12/binding") \
        == "GET /api/v1/node/{id}/binding"


def test_body_hash_is_order_insensitive():
    left = idempotency.body_hash({"model": "m1", "ttl_s": 60})
    right = idempotency.body_hash({"ttl_s": 60, "model": "m1"})
    assert left == right
    assert len(left) == 64
    assert left != idempotency.body_hash({"model": "m2", "ttl_s": 60})


def test_storable_response_strips_plaintext():
    stored = idempotency.storable_response({"quote_id": "q", "client_key": "sekrit",
                                            "token": "t"})
    assert stored == {"quote_id": "q"}


def test_require_key_validates_shape():
    assert idempotency.require_key(None) is None
    assert idempotency.require_key("   ") is None
    assert idempotency.require_key(" k1 ") == "k1"
    with pytest.raises(InvalidArgument):
        idempotency.require_key("k" * (facts.IDEMPOTENCY_KEY_MAX_LEN + 1))


# --------------------------------------------------------------------------- 表语义
def test_save_and_lookup_round_trip(conn, now):
    scope = idempotency.scope_of("POST", "/api/v1/schedule/quotes")
    digest = idempotency.body_hash({"a": 1})
    idempotency.save(conn, scope=scope, key="k1", request_hash=digest, status_code=201,
                     response={"quote_id": "q1"}, now=now)
    record = idempotency.lookup(conn, scope=scope, key="k1", request_hash=digest, now=now)
    assert record is not None
    assert record.status_code == 201
    assert record.response == {"quote_id": "q1"}


def test_same_key_different_payload_is_a_conflict(conn, now):
    scope = idempotency.scope_of("POST", "/api/v1/schedule/quotes")
    idempotency.save(conn, scope=scope, key="k1",
                     request_hash=idempotency.body_hash({"a": 1}), status_code=201,
                     response={"quote_id": "q1"}, now=now)
    with pytest.raises(IdempotencyConflict) as excinfo:
        idempotency.lookup(conn, scope=scope, key="k1",
                           request_hash=idempotency.body_hash({"a": 2}), now=now)
    assert int(excinfo.value.code) == 40919


def test_expired_keys_are_ignored(conn, now):
    scope = idempotency.scope_of("POST", "/api/v1/schedule/bids")
    digest = idempotency.body_hash({"m": 1})
    idempotency.save(conn, scope=scope, key="k1", request_hash=digest, status_code=201,
                     response={"bid_id": "b1"}, now=now)
    later = now + timedelta(hours=facts.IDEMPOTENCY_TTL_HOURS + 1)
    assert idempotency.lookup(conn, scope=scope, key="k1", request_hash=digest,
                              now=later) is None


def test_save_is_idempotent(conn, now):
    scope = idempotency.scope_of("POST", "/api/v1/schedule/quotes")
    digest = idempotency.body_hash({"a": 1})
    idempotency.save(conn, scope=scope, key="k1", request_hash=digest, status_code=201,
                     response={"quote_id": "q1"}, now=now)
    idempotency.save(conn, scope=scope, key="k1", request_hash=digest, status_code=201,
                     response={"quote_id": "other"}, now=now)
    assert conn.execute("SELECT count(*) FROM scheduling_idempotency").fetchone()[0] == 1
    record = idempotency.lookup(conn, scope=scope, key="k1", request_hash=digest, now=now)
    assert record.response == {"quote_id": "q1"}          # 首次响应不被覆盖


def test_rows_cannot_be_updated(conn, now):
    scope = idempotency.scope_of("POST", "/api/v1/schedule/quotes")
    digest = idempotency.body_hash({"a": 1})
    idempotency.save(conn, scope=scope, key="k1", request_hash=digest, status_code=201,
                     response={"quote_id": "q1"}, now=now)
    with pytest.raises(Exception):
        conn.execute("UPDATE scheduling_idempotency SET response = '{}'::jsonb")
    conn.rollback()


def test_purge_expired(conn, now):
    scope = idempotency.scope_of("POST", "/api/v1/schedule/quotes")
    digest = idempotency.body_hash({"a": 1})
    idempotency.save(conn, scope=scope, key="k1", request_hash=digest, status_code=201,
                     response={}, now=now)
    idempotency.save(conn, scope=scope, key="k2", request_hash=digest, status_code=201,
                     response={}, now=now + timedelta(hours=30))
    assert idempotency.purge_expired(conn, now=now + timedelta(hours=25)) == 1
    assert conn.execute("SELECT count(*) FROM scheduling_idempotency").fetchone()[0] == 1


# --------------------------------------------------------------------------- 路由层（字节级回放）
QUOTES = "/api/v1/schedule/quotes"


def test_same_key_replays_the_first_response_byte_for_byte(client, auth):
    body = {"access": "A1", "model": "m1", "unit": "token", "price_min": "8.00",
            "price_max": "10.00", "ttl_s": 600}
    headers = {"X-DJB-Idempotency-Key": "idem-quote-1"}
    first = client.post(QUOTES, json=body, headers=headers)
    second = client.post(QUOTES, json=body, headers=headers)
    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()                  # 连 created=True 都回放
    assert second.headers.get("X-DJB-Idempotent-Replay") == "true"


def test_same_key_with_a_different_body_is_40919(client, auth):
    headers = {"X-DJB-Idempotency-Key": "idem-quote-2"}
    body = {"access": "A1", "model": "m1", "unit": "token", "price_min": "8.00", "ttl_s": 600}
    assert client.post(QUOTES, json=body, headers=headers).status_code == 201
    changed = dict(body, price_min="8.50")
    response = client.post(QUOTES, json=changed, headers=headers)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40919


def test_without_a_key_behaviour_stays_semantic(client, auth):
    """不带幂等键 → 保持业务幂等（内容不变不升版本），不回放响应体。"""
    # 用独立 model 隔离（api_schema 是模块级共享的，别和别的用例抢同一条报价）
    body = {"access": "A1", "model": "m-semantic", "unit": "token", "price_min": "8.00",
            "ttl_s": 600}
    first = client.post(QUOTES, json=body)
    second = client.post(QUOTES, json=body)
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert first.json()["quote_id"] == second.json()["quote_id"]


def test_route_is_idempotent_with_a_key(client, auth):
    client.post(QUOTES, json={"access": "A1", "model": "m1", "unit": "token",
                              "price_min": "8.00", "price_max": "10.00", "ttl_s": 600})
    body = {"model": "m1", "kind": "realtime", "max_price": "9.50"}
    headers = {"X-DJB-Idempotency-Key": "idem-route-1"}
    first = client.post("/api/v1/schedule/route", json=body, headers=headers)
    second = client.post("/api/v1/schedule/route", json=body, headers=headers)
    assert first.status_code == second.status_code == 201
    assert first.json()["decision_id"] == second.json()["decision_id"]
    assert second.headers.get("X-DJB-Idempotent-Replay") == "true"
