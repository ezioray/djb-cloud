# SPDX-License-Identifier: Apache-2.0
"""完整链路：请求 → 双签收据 → 账本 → 复算（差异必须 0）"""
import hashlib
import os
import secrets

os.environ.setdefault("DJB_PRICING_FILE", os.path.join(os.path.dirname(__file__), "..", "config", "pricing.dev.json"))
os.environ.setdefault("DJB_SIG_SUPPLIER_KEY", "test-supplier-key-not-real")
os.environ.setdefault("DJB_SIG_CONSUMER_KEY", "test-consumer-key-not-real")

from fastapi.testclient import TestClient  # noqa: E402

from app import db  # noqa: E402
from app.api import app  # noqa: E402
from app.ledger import recompute  # noqa: E402
from app import receipt as rcpt  # noqa: E402

client = TestClient(app)


def _mk_user() -> str:
    user = f"user:t-{secrets.token_hex(4)}"
    raw = "djb_" + secrets.token_urlsafe(24)
    with db.conn() as c, c.cursor() as cur:
        cur.execute("INSERT INTO api_keys (user_id, key_prefix, key_hash) VALUES (%s,%s,%s)",
                    (user, raw[:8], hashlib.sha256(raw.encode()).hexdigest()))
    return f"Bearer {raw}"


def _count(sql: str, args=()) -> int:
    with db.conn() as c, c.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchone()[0]


def test_full_chain_request_to_receipt_to_ledger():
    auth = _mk_user()
    user = _count("SELECT user_id FROM api_keys ORDER BY id DESC LIMIT 1") or None
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT user_id FROM api_keys ORDER BY id DESC LIMIT 1")
        user = cur.fetchone()[0]

    before = _count("SELECT count(*) FROM ledger_entries")
    r = client.post("/v1/chat/completions",
                    headers={"Authorization": auth, "X-Request-Id": "11111111-1111-1111-1111-111111111111"},
                    json={"model": "djb/chat-lite", "messages": [{"role": "user", "content": "你好，算一笔账"}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["role"] == "assistant"
    assert body["usage"]["total_tokens"] > 0
    assert r.headers["X-Request-Id"]
    rid = body["djb_receipt_id"]

    # 收据存在且双签可验证
    with db.conn() as c, c.cursor() as cur:
        cur.execute("""SELECT id,node_id,consumer_id,request_id,model,tokens_in,tokens_out,amount_micro,
                              sig_supplier,sig_consumer,ts_start,ts_end FROM receipts WHERE id=%s""", (rid,))
        row = cur.fetchone()
    assert row, "收据未写入"
    rec = {"receipt_id": str(row[0]), "node_id": row[1], "consumer_id": row[2], "request_id": row[3],
           "model": row[4], "tokens_in": row[5], "tokens_out": row[6], "amount_micro": row[7],
           "ts_start": f"{row[10].timestamp():.3f}", "ts_end": f"{row[11].timestamp():.3f}"}
    assert row[8].startswith("hmac-sha256:") and row[9].startswith("hmac-sha256:")
    assert rcpt.verify({**rec, "sig_supplier": row[8], "sig_consumer": row[9]}), "双签校验失败"

    # 账本：一次调用产生 usage + fee 两条
    assert _count("SELECT count(*) FROM ledger_entries") == before + 2

    # 全量复算必须归零
    with db.conn() as c:
        assert recompute(c)["diff"] == 0


def test_idempotency_key_prevents_double_charge():
    auth = _mk_user()
    key = "idem-" + secrets.token_hex(8)
    payload = {"model": "djb/chat-pro", "messages": [{"role": "user", "content": "只收一次钱"}]}
    r1 = client.post("/v1/chat/completions", headers={"Authorization": auth, "X-DJB-Idempotency-Key": key}, json=payload)
    r2 = client.post("/v1/chat/completions", headers={"Authorization": auth, "X-DJB-Idempotency-Key": key}, json=payload)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["djb_receipt_id"] == r2.json()["djb_receipt_id"]
    assert r2.json().get("djb_idempotent") is True
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT count(*) FROM receipts WHERE idempotency_key=%s", (key,))
        assert cur.fetchone()[0] == 1


def test_unknown_model_and_missing_auth():
    assert client.post("/v1/chat/completions", json={"model": "nope", "messages": [{"role": "user", "content": "x"}]}).status_code == 401
    auth = _mk_user()
    r = client.post("/v1/chat/completions", headers={"Authorization": auth},
                    json={"model": "nope", "messages": [{"role": "user", "content": "x"}]})
    assert r.status_code == 400
