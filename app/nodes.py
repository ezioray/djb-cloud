# SPDX-License-Identifier: AGPL-3.0-or-later
"""节点接入：注册 / 策略下发 / 收据上报（双签校验）。

密钥设计：节点密钥不落库明文。平台用主密钥按 node_id 派生：
    node_secret = HMAC-SHA256(DJB_NODE_MASTER_KEY, node_id)
注册时一次性下发给节点，之后平台随时可重算用于验签 —— 只有主密钥需要保管。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException

from . import db

router = APIRouter(prefix="/api/v1/node")

POLICY_VERSION = os.environ.get("DJB_NODE_POLICY_VERSION", "policy-1")
PROTOCOL_VERSION = os.environ.get("DJB_PROTOCOL_VERSION", "1.0.0")


def _master() -> bytes:
    v = os.environ.get("DJB_NODE_MASTER_KEY")
    if not v:
        raise RuntimeError("缺 DJB_NODE_MASTER_KEY")
    return v.encode()


def derive_secret(node_id: str) -> str:
    return hmac.new(_master(), node_id.encode(), hashlib.sha256).hexdigest()


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _auth_node(x_client_key: str | None) -> dict:
    if not x_client_key:
        raise HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "missing X-Client-Key"})
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT id, state FROM nodes WHERE key_hash=%s", (_sha(x_client_key),))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail={"code": "invalid_key", "message": "unknown node key"})
        if row[1] != "active":
            raise HTTPException(status_code=403, detail={"code": "node_not_active", "message": row[1]})
        cur.execute("UPDATE nodes SET last_seen_at=now() WHERE id=%s", (row[0],))
    return {"node_id": row[0]}


@router.post("/register", status_code=201)
def register(body: dict, x_client_key: str | None = Header(default=None, alias="X-Client-Key")):
    required = ("platform", "hardware_fingerprint", "client_version", "protocol_version")
    missing = [k for k in required if not body.get(k)]
    if missing:
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": f"缺字段: {missing}"})
    if body["platform"] not in ("macos", "windows", "linux"):
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "platform 非法"})

    # 首次接入用引导密钥；已注册节点用自身密钥（可在同指纹下重申，幂等返回新密钥）
    boot = os.environ.get("DJB_NODE_BOOTSTRAP_KEY", "")
    if x_client_key and boot and hmac.compare_digest(x_client_key, boot):
        pass
    elif x_client_key:
        with db.conn() as c, c.cursor() as cur:
            cur.execute("SELECT id FROM nodes WHERE key_hash=%s", (_sha(x_client_key),))
            if not cur.fetchone():
                raise HTTPException(status_code=401, detail={"code": "invalid_key", "message": "unknown key"})
    else:
        raise HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "missing X-Client-Key"})

    fp = _sha(body["hardware_fingerprint"])  # 双保险：即使客户端传了明文也再散列一次
    with db.conn() as c, c.cursor() as cur:
        cur.execute("""SELECT id FROM nodes WHERE hardware_fingerprint=%s AND platform=%s""",
                    (fp, body["platform"]))
        row = cur.fetchone()
        if row:
            node_id = row[0]
            raw_key = secrets.token_urlsafe(32)
            cur.execute("UPDATE nodes SET client_version=%s, protocol_version=%s, key_prefix=%s, key_hash=%s, state='active' WHERE id=%s",
                        (body["client_version"], body["protocol_version"], raw_key[:8], _sha(raw_key), node_id))
        else:
            node_id = "node-" + uuid.uuid4().hex[:16]
            raw_key = secrets.token_urlsafe(32)
            cur.execute("""INSERT INTO nodes (id, platform, hardware_fingerprint, client_version, protocol_version,
                           key_prefix, key_hash) VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                        (node_id, body["platform"], fp, body["client_version"], body["protocol_version"],
                         raw_key[:8], _sha(raw_key)))
    return {"node_id": node_id, "state": "active", "policy_version": POLICY_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "server_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            # 仅此一次下发：注册凭据与收据签名密钥
            "client_key": raw_key, "signing_secret": derive_secret(node_id)}


@router.get("/policy")
def policy(x_client_key: str | None = Header(default=None, alias="X-Client-Key")):
    node = _auth_node(x_client_key)
    doc = {"policy_version": POLICY_VERSION, "protocol_version": PROTOCOL_VERSION,
           "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           # 配额数值由配置下发，spec 不规定（客户端不得内置默认值）
           "quotas": json.loads(os.environ.get("DJB_NODE_QUOTAS_JSON", "[]")),
           "directives": json.loads(os.environ.get("DJB_NODE_DIRECTIVES_JSON", "[]"))}
    doc["digest"] = "sha256:" + hashlib.sha256(
        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return doc


RECEIPT_SIG_FIELDS = ("receipt_id", "task_id", "access", "usage_amount", "usage_unit", "price_amount")


def canonical_receipt(r: dict) -> bytes:
    """收据规范字段（顺序固定，参与签名）。

    注意：全部按**原样字符串**拼接。数据库 NUMERIC 取回会变成
    Decimal('1200.000000000')，与签名时的 "1200" 不相等 —— 所以复验必须
    用上报时的原值（node_receipts.raw），不能直接用 NUMERIC 列。
    """
    return "|".join(str(r.get(k)) for k in RECEIPT_SIG_FIELDS).encode()


@router.post("/receipts")
def submit_receipts(body: dict, x_client_key: str | None = Header(default=None, alias="X-Client-Key")):
    node = _auth_node(x_client_key)
    receipts = body.get("receipts") or []
    if not isinstance(receipts, list) or not receipts or len(receipts) > 500:
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "receipts 需 1..500 条"})

    secret = derive_secret(node["node_id"]).encode()
    accepted, rejected = [], []
    with db.conn() as c, c.cursor() as cur:
        for r in receipts:
            rid = str(r.get("receipt_id") or "")
            try:
                usage = r.get("usage") or {}
                price = r.get("price") or {}
                norm = {"receipt_id": rid, "task_id": str(r.get("task_id")), "access": str(r.get("access")),
                        "usage_amount": str(usage.get("amount")), "usage_unit": str(usage.get("unit")),
                        "price_amount": str(price.get("amount") if isinstance(price, dict) else price)}
                sig_prov, sig_con = r.get("sig_provider"), r.get("sig_consumer")
                if not sig_prov or not sig_con:
                    raise ValueError("双签缺一（sig_provider/sig_consumer 均为必填）")
                want = "hmac-sha256:" + hmac.new(secret, canonical_receipt(norm), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(want, str(sig_prov)):
                    raise ValueError("供方签名不匹配")
                cur.execute("""INSERT INTO node_receipts (receipt_id,node_id,task_id,access,usage_amount,usage_unit,
                               price_amount,sig_provider,sig_consumer,raw)
                               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                               ON CONFLICT (receipt_id) DO NOTHING""",
                            (rid, node["node_id"], norm["task_id"], norm["access"], norm["usage_amount"],
                             norm["usage_unit"], norm["price_amount"], sig_prov, sig_con, json.dumps(r)))
                accepted.append(rid)
            except Exception as e:  # 单条拒绝不影响整批（spec：只描述契约问题）
                rejected.append({"receipt_id": rid, "code": 40301, "message": str(e)[:200]})
    return {"accepted": accepted, "rejected": rejected}


@router.post("/heartbeat", status_code=201)
def heartbeat(body: dict, x_client_key: str | None = Header(default=None, alias="X-Client-Key")):
    node = _auth_node(x_client_key)
    return {"ack": True, "node_id": node["node_id"], "policy_version": POLICY_VERSION,
            "server_time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
