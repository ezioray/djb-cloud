# SPDX-License-Identifier: Apache-2.0
"""节点接入闭环：注册 → 策略 → 上报双签收据 → 双边对账 diff=0；篡改必须被拒。"""
import hashlib
import hmac
import os
import secrets

os.environ.setdefault("DJB_PRICING_FILE", os.path.join(os.path.dirname(__file__), "..", "config", "pricing.dev.json"))
os.environ.setdefault("DJB_SIG_SUPPLIER_KEY", "test-supplier-key-not-real")
os.environ.setdefault("DJB_SIG_CONSUMER_KEY", "test-consumer-key-not-real")
os.environ.setdefault("DJB_NODE_MASTER_KEY", "test-node-master-not-real")
os.environ.setdefault("DJB_NODE_BOOTSTRAP_KEY", "test-bootstrap-not-real")

from fastapi.testclient import TestClient  # noqa: E402

from app import db  # noqa: E402
from app.api import app  # noqa: E402
from app.reconcile import run as reconcile_run  # noqa: E402

client = TestClient(app)
BOOT = {"X-Client-Key": os.environ["DJB_NODE_BOOTSTRAP_KEY"]}   # 从环境读，避免与 CI 注入值不一致


def _register() -> dict:
    r = client.post("/api/v1/node/register", headers=BOOT,
                    json={"platform": "linux", "hardware_fingerprint": secrets.token_hex(16),
                          "client_version": "0.1.0", "protocol_version": "1.0.0"})
    assert r.status_code == 201, r.text
    return r.json()


def _canonical(rid, task, access, amt, unit, price) -> bytes:
    return "|".join(map(str, (rid, task, access, amt, unit, price))).encode()


def _receipt(node_secret: str, task_id: str, price: str = "0.010800") -> dict:
    rid = "rcpt-" + secrets.token_hex(6)
    usage_amount, usage_unit = "1200", "tokens"
    sig = "hmac-sha256:" + hmac.new(node_secret.encode(),
                                    _canonical(rid, task_id, "A1", usage_amount, usage_unit, price),
                                    hashlib.sha256).hexdigest()
    return {"receipt_id": rid, "task_id": task_id, "access": "A1",
            "usage": {"amount": usage_amount, "unit": usage_unit},
            "price": {"amount": price, "currency": "COIN"},
            "sig_provider": sig, "sig_consumer": "consumer-sig-placeholder"}


def test_register_policy_and_dual_signed_receipts_reconcile_to_zero():
    node = _register()
    assert node["state"] == "active" and node["node_id"].startswith("node-")
    assert node["client_key"] and node["signing_secret"]

    h = {"X-Client-Key": node["client_key"]}
    pol = client.get("/api/v1/node/policy", headers=h)
    assert pol.status_code == 200
    assert {"policy_version", "protocol_version", "issued_at"} <= set(pol.json())
    assert pol.json()["digest"].startswith("sha256:")

    assert client.post("/api/v1/node/heartbeat", headers=h, json={}).status_code == 201

    # 平台侧先产生一笔收据（模拟一次真实调用）
    auth_key = "djb_" + secrets.token_urlsafe(24)
    with db.conn() as c, c.cursor() as cur:
        cur.execute("INSERT INTO api_keys (user_id,key_prefix,key_hash) VALUES ('user:node-test',%s,%s)",
                    (auth_key[:8], hashlib.sha256(auth_key.encode()).hexdigest()))
    chat = client.post("/v1/chat/completions",
                       headers={"Authorization": f"Bearer {auth_key}"},
                       json={"model": "djb/chat-lite", "messages": [{"role": "user", "content": "对账"}]})
    assert chat.status_code == 200
    task_id = chat.headers["X-Request-Id"]
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT amount_micro FROM receipts WHERE task_id=%s", (task_id,))
        platform_micro = cur.fetchone()[0]
    price = f"{platform_micro / 1_000_000:.6f}"

    up = client.post("/api/v1/node/receipts", headers=h,
                     json={"receipts": [_receipt(node["signing_secret"], task_id, price)]})
    assert up.status_code == 200, up.text
    assert len(up.json()["accepted"]) == 1 and up.json()["rejected"] == []

    with db.conn() as c:
        r = reconcile_run(c)
    assert r["matched"] >= 1
    assert r["diff"] == 0, r


def test_bad_signature_is_rejected_not_accepted():
    node = _register()
    h = {"X-Client-Key": node["client_key"]}
    bad = _receipt("wrong-secret", "task-forged")
    r = client.post("/api/v1/node/receipts", headers=h, json={"receipts": [bad]})
    assert r.status_code == 200
    assert r.json()["accepted"] == []
    assert r.json()["rejected"][0]["code"] == 40301
    assert "签名" in r.json()["rejected"][0]["message"]


def test_missing_dual_signature_is_rejected():
    node = _register()
    h = {"X-Client-Key": node["client_key"]}
    bad = _receipt(node["signing_secret"], "task-x")
    bad["sig_consumer"] = ""
    r = client.post("/api/v1/node/receipts", headers=h, json={"receipts": [bad]})
    assert r.json()["accepted"] == []


def test_policy_requires_valid_node_key():
    assert client.get("/api/v1/node/policy").status_code == 401
    assert client.get("/api/v1/node/policy", headers={"X-Client-Key": "nope"}).status_code == 401
