# SPDX-License-Identifier: Apache-2.0
"""Webhook 订阅：secret 一次性 / 只存哈希 / SSRF / 唯一与幂等 / 账户隔离。"""
from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

import psycopg
import pytest

from app.notify import errors, signing, webhooks
from notifykit import NOW, count, scalar


def _url(name: str = "hooks.example.com") -> str:
    return f"https://{name}/djb/callback"


@pytest.mark.parametrize("url", [
    "https://hooks.example.com/cb",
    "https://hooks.example.com:8443/cb",
    "https://93.184.216.34/cb",                       # 公网 IP 字面量可以
])
def test_valid_urls_are_accepted(url):
    assert webhooks.validate_url(url) in url


@pytest.mark.parametrize("url,reason", [
    ("http://hooks.example.com/cb", "scheme_not_allowed"),
    ("ftp://hooks.example.com/cb", "scheme_not_allowed"),
    ("https://user:pass@hooks.example.com/cb", "userinfo_not_allowed"),
    ("https://localhost/cb", "internal_hostname"),
    ("https://api.localhost/cb", "internal_hostname"),
    ("https://db.internal/cb", "internal_hostname"),
    ("https://metadata.google.internal/cb", "internal_hostname"),
    ("https://127.0.0.1/cb", "private_host"),
    ("https://127.1.2.3/cb", "private_host"),
    ("https://10.1.2.3/cb", "private_host"),
    ("https://172.16.0.9/cb", "private_host"),
    ("https://192.168.1.5/cb", "private_host"),
    ("https://169.254.169.254/cb", "private_host"),
    ("https://100.64.0.1/cb", "private_host"),
    ("https://0.0.0.0/cb", "private_host"),
    ("https://[::1]/cb", "private_host"),
    ("https://[fe80::1]/cb", "private_host"),
    ("https://[fc00::1]/cb", "private_host"),
    ("https://[::ffff:10.0.0.1]/cb", "private_host"),
    ("https://2130706433/cb", "private_host"),        # 十进制 127.0.0.1
    ("https://0x7f000001/cb", "private_host"),        # 十六进制 127.0.0.1
    ("https://hooks.example.com:22/cb", "port_not_allowed"),
    ("https://hooks.example.com/cb#frag", "fragment_not_allowed"),
])
def test_ssrf_and_shape_rejections(url, reason):
    with pytest.raises(errors.UrlRejected) as caught:
        webhooks.validate_url(url)
    assert caught.value.code == "40001"
    assert caught.value.details.get("detail") == reason


@pytest.mark.parametrize("url", ["", "   ", "not a url", "https://", 12, None,
                                 "https://" + "a" * 300 + ".com/cb"])
def test_invalid_urls_are_rejected(url):
    with pytest.raises(errors.UrlRejected):
        webhooks.validate_url(url)


def test_private_address_detector():
    assert webhooks.is_private_address("10.0.0.1")
    assert webhooks.is_private_address("::1")
    assert webhooks.is_private_address("169.254.169.254")
    assert not webhooks.is_private_address("93.184.216.34")
    assert not webhooks.is_private_address("example.com")


def test_redact_url_strips_query_string():
    assert webhooks.redact_url("https://hooks.example.com/cb?token=abc&x=1") == (
        "https://hooks.example.com/cb")
    assert webhooks.redact_url("https://hooks.example.com:8443/cb") == (
        "https://hooks.example.com:8443/cb")


# ─────────────────────────────────────────────────── 创建（secret 一次性 / 只存哈希）
def test_create_returns_secret_once_and_stores_only_hash(conn, account_id):
    subscription, secret = webhooks.create(
        conn, account_id=account_id, url=_url(), events=["payment.settled"], now=NOW)
    conn.commit()
    api = subscription.to_api()
    assert "secret" not in api and "secret_hash" not in api
    assert subscription.secret_hash == hashlib.sha256(secret.encode()).hexdigest()
    stored = scalar(conn, "SELECT secret_hash FROM webhook_subscriptions WHERE id = %s",
                    (subscription.id,))
    assert stored == subscription.secret_hash
    # 明文绝不落库：整表任何文本列都找不到 secret
    with conn.cursor() as cur:
        cur.execute("""SELECT count(*) FROM webhook_subscriptions
                        WHERE url LIKE %s OR description LIKE %s""",
                    (f"%{secret}%", f"%{secret}%"))
        assert cur.fetchone()[0] == 0
    # 列表也不含密钥
    listed = webhooks.list_page(conn, account_id)
    assert listed["data"] and "secret" not in listed["data"][0]


def test_duplicate_url_is_rejected(conn, account_id):
    webhooks.create(conn, account_id=account_id, url=_url(), events=["task.completed"], now=NOW)
    conn.commit()
    with pytest.raises(errors.DuplicateSubscription) as caught:
        webhooks.create(conn, account_id=account_id, url=_url(), events=["task.failed"],
                        now=NOW)
    assert caught.value.code == "40902"
    conn.rollback()


def test_idempotency_key_replay_cannot_return_secret_again(conn, account_id):
    key = "idem-key-0123456789abcdef"
    webhooks.create(conn, account_id=account_id, url=_url(),
                    events=["payment.settled"], idempotency_key=key, now=NOW)
    conn.commit()
    with pytest.raises(errors.IdempotencyConflict) as caught:
        webhooks.create(conn, account_id=account_id, url=_url(),
                        events=["payment.settled"], idempotency_key=key, now=NOW)
    assert caught.value.reason == "idempotent_replay"
    conn.rollback()
    with pytest.raises(errors.IdempotencyConflict) as reused:
        webhooks.create(conn, account_id=account_id, url=_url("other.example.com"),
                        events=["payment.settled"], idempotency_key=key, now=NOW)
    assert reused.value.reason == "idempotency_key_reused"
    conn.rollback()
    assert count(conn, "webhook_subscriptions", "account_id = %s", (account_id,)) == 1


def test_idempotency_key_shape_is_validated(conn, account_id):
    with pytest.raises(errors.InvalidArgument):
        webhooks.create(conn, account_id=account_id, url=_url(), events=["payment.settled"],
                        idempotency_key="short", now=NOW)


def test_max_subscriptions_per_account(conn, account_id):
    for index in range(5):
        webhooks.create(conn, account_id=account_id, url=_url(f"h{index}.example.com"),
                        events=["payment.settled"], now=NOW)
        conn.commit()
    with pytest.raises(errors.WebhookLimitReached):
        webhooks.create(conn, account_id=account_id, url=_url("h9.example.com"),
                        events=["payment.settled"], now=NOW)
    conn.rollback()


def test_events_and_description_validation(conn, account_id):
    with pytest.raises(errors.InvalidArgument):
        webhooks.create(conn, account_id=account_id, url=_url(), events=[], now=NOW)
    with pytest.raises(errors.InvalidArgument):
        webhooks.create(conn, account_id=account_id, url=_url(),
                        events=["batch.completed"], now=NOW)
    with pytest.raises(errors.InvalidArgument):
        webhooks.create(conn, account_id=account_id, url=_url(), events=["task.completed"],
                        description="x" * 201, now=NOW)
    with pytest.raises(errors.InvalidArgument):
        webhooks.create(conn, account_id=account_id, url=_url(), events=["task.completed"],
                        description=12, now=NOW)


def test_events_are_deduplicated(conn, account_id):
    subscription, _ = webhooks.create(conn, account_id=account_id, url=_url(),
                                      events=["task.completed", "task.completed"], now=NOW)
    conn.commit()
    assert subscription.events == ("task.completed",)


# ─────────────────────────────────────────────────── 列表 / 删除 / 账户隔离
def test_list_pagination_and_isolation(conn, account_id):
    other = uuid.uuid4()
    for index in range(3):
        webhooks.create(conn, account_id=account_id, url=_url(f"a{index}.example.com"),
                        events=["payment.settled"], now=NOW + timedelta(minutes=index))
    webhooks.create(conn, account_id=other, url=_url("b.example.com"),
                    events=["payment.settled"], now=NOW)
    conn.commit()
    page = webhooks.list_page(conn, account_id, limit=2)
    assert len(page["data"]) == 2
    assert page["page"]["has_more"] is True
    second = webhooks.list_page(conn, account_id, limit=2, cursor=page["page"]["next_cursor"])
    assert len(second["data"]) == 1 and second["page"]["has_more"] is False
    assert webhooks.count_for_account(conn, account_id) == 3
    assert webhooks.count_for_account(conn, other) == 1


def test_delete_is_idempotent_and_account_scoped(conn, account_id):
    subscription, _ = webhooks.create(conn, account_id=account_id, url=_url(),
                                      events=["payment.settled"], now=NOW)
    conn.commit()
    assert webhooks.delete(conn, uuid.uuid4(), subscription.id) is False     # 别人的 = 删不到
    conn.commit()
    assert webhooks.delete(conn, account_id, subscription.id) is True
    conn.commit()
    assert webhooks.delete(conn, account_id, subscription.id) is False      # 幂等
    conn.commit()


def test_active_for_event_whitelist_and_paused(conn, account_id):
    active, _ = webhooks.create(conn, account_id=account_id, url=_url("active.example.com"),
                                events=["payment.settled"], now=NOW)
    paused, _ = webhooks.create(conn, account_id=account_id, url=_url("paused.example.com"),
                                events=["payment.settled", "task.completed"], now=NOW)
    future, _ = webhooks.create(conn, account_id=account_id, url=_url("future.example.com"),
                                events=["payment.settled"], now=NOW)
    conn.commit()
    with conn.cursor() as cur:
        cur.execute("UPDATE webhook_subscriptions SET status = 'paused' WHERE id = %s",
                    (paused.id,))
        cur.execute("""UPDATE webhook_subscriptions
                          SET status = 'paused', paused_until = %s WHERE id = %s""",
                    (NOW - timedelta(minutes=1), future.id))
    conn.commit()
    targets = webhooks.active_for_event(conn, account_id, "payment.settled", now=NOW)
    ids = {str(item.id) for item in targets}
    assert str(active.id) in ids
    assert str(future.id) in ids                        # paused 到期 → 自动恢复可用
    assert str(paused.id) not in ids
    # 事件白名单：task.completed 只命中 subscriptions 里声明过它的（paused 的不算）
    assert webhooks.active_for_event(conn, account_id, "task.completed", now=NOW) == []
    # 别的账户看不到
    assert webhooks.active_for_event(conn, uuid.uuid4(), "payment.settled", now=NOW) == []


def test_register_failure_pauses_on_permanent(conn, account_id):
    subscription, _ = webhooks.create(conn, account_id=account_id, url=_url(),
                                      events=["payment.settled"], now=NOW)
    conn.commit()
    webhooks.register_failure(conn, subscription.id, permanent=True, now=NOW)
    conn.commit()
    status = scalar(conn, "SELECT status FROM webhook_subscriptions WHERE id = %s",
                    (subscription.id,))
    failures = scalar(conn, "SELECT failure_count FROM webhook_subscriptions WHERE id = %s",
                      (subscription.id,))
    assert status == "paused" and failures == 1
    webhooks.register_failure(conn, subscription.id, permanent=False, now=NOW)
    conn.commit()
    assert scalar(conn, "SELECT failure_count FROM webhook_subscriptions WHERE id = %s",
                  (subscription.id,)) == 2
    assert scalar(conn, "SELECT status FROM webhook_subscriptions WHERE id = %s",
                  (subscription.id,)) == "paused"


def test_secret_hash_format_is_enforced_in_db(migrated):
    conn = _connect(migrated)
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO webhook_subscriptions
                           (id, account_id, url, url_host, events, secret_hash, status,
                            created_at, updated_at)
                       VALUES (%s, %s, 'https://x.example.com/cb', 'x.example.com',
                               ARRAY['task.completed'], 'plaintext-secret', 'active',
                               now(), now())""",
                    (uuid.uuid4(), uuid.uuid4()))
        conn.rollback()
        with pytest.raises(psycopg.errors.CheckViolation):       # 只允许 https
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO webhook_subscriptions
                           (id, account_id, url, url_host, events, secret_hash, status,
                            created_at, updated_at)
                       VALUES (%s, %s, 'http://x.example.com/cb', 'x.example.com',
                               ARRAY['task.completed'], %s, 'active', now(), now())""",
                    (uuid.uuid4(), uuid.uuid4(), "a" * 64))
        conn.rollback()
    finally:
        conn.close()


def test_secret_hash_is_immutable(migrated):
    conn = _connect(migrated)
    account = uuid.uuid4()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO webhook_subscriptions
                       (id, account_id, url, url_host, events, secret_hash, status,
                        created_at, updated_at)
                   VALUES (%s, %s, 'https://x.example.com/cb', 'x.example.com',
                           ARRAY['task.completed'], %s, 'active', now(), now())""",
                (uuid.uuid4(), account, "b" * 64))
        conn.commit()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.cursor() as cur:
                cur.execute("UPDATE webhook_subscriptions SET secret_hash = %s", ("c" * 64,))
        conn.rollback()
    finally:
        conn.close()


def _connect(schema: str):
    from notifykit import connect

    return connect(schema)
