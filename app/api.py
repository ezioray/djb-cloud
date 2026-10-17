# SPDX-License-Identifier: Apache-2.0
"""最小 API：严格按 spec/openapi.yaml 实现（契约测试会比对）。"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from . import db, pricing, receipt as rcpt, upstream

app = FastAPI(title="djb-cloud", version="0.1.0")


# ── 鉴权：用方 Bearer（库里只存 sha256）───────────────────────────────────────
def _auth(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "missing bearer token"})
    raw = authorization.split(" ", 1)[1].strip()
    h = hashlib.sha256(raw.encode()).hexdigest()
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT user_id FROM api_keys WHERE key_hash=%s AND revoked_at IS NULL", (h,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail={"code": "invalid_key", "message": "unknown or revoked key"})
    return row[0]


@app.get("/v1/models")
def list_models():
    models = sorted((pricing.table().get("models") or {}).keys())
    return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "djb"} for m in models]}


@app.post("/v1/chat/completions")
async def create_chat_completion(
    request: Request,
    authorization: str | None = Header(default=None),
    x_request_id: str | None = Header(default=None, alias="X-Request-Id"),
    x_djb_idempotency_key: str | None = Header(default=None, alias="X-DJB-Idempotency-Key"),
):
    consumer = _auth(authorization)
    body = await request.json()
    model = body.get("model")
    messages = body.get("messages") or []
    if not model or not isinstance(messages, list) or not messages:
        raise HTTPException(status_code=400, detail={"code": "bad_request", "message": "model 与 messages 必填"})
    try:
        pricing.quote(model, 0, 0)  # 未知模型提前 400
    except KeyError:
        raise HTTPException(status_code=400, detail={"code": "unknown_model", "message": model})

    # 幂等：同一 key 直接回放已存在的收据（不重复扣费）
    if x_djb_idempotency_key:
        with db.conn() as c, c.cursor() as cur:
            cur.execute("SELECT id, request_id, amount_micro FROM receipts WHERE idempotency_key=%s", (x_djb_idempotency_key,))
            row = cur.fetchone()
        if row:
            return JSONResponse(
                {"id": str(row[1]), "object": "chat.completion", "created": int(time.time()), "model": model,
                 "choices": [{"index": 0, "message": {"role": "assistant", "content": "[idempotent replay]"},
                              "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                 "djb_receipt_id": str(row[0]), "djb_idempotent": True},
                headers={"X-Request-Id": x_request_id or str(row[1])})

    up = upstream.complete(model, messages, body.get("max_tokens"))
    q = pricing.quote(model, up["prompt_tokens"], up["completion_tokens"])

    rid, req_id = str(uuid.uuid4()), (x_request_id or str(uuid.uuid4()))
    now = time.time()
    rec = {"receipt_id": rid, "node_id": "node:stub-001", "consumer_id": consumer, "request_id": req_id,
           "model": model, "tokens_in": up["prompt_tokens"], "tokens_out": up["completion_tokens"],
           "amount_micro": q["amount_micro"], "ts_start": f"{now - 1:.3f}", "ts_end": f"{now:.3f}"}
    signed = rcpt.sign(rec)
    if not rcpt.verify(signed):
        raise HTTPException(status_code=500, detail={"code": "signature_invalid"})

    # 收据 + 账本 + 余额：同一事务（写操作与账本同事务）
    with db.conn() as c, c.cursor() as cur:
        cur.execute("""INSERT INTO accounts (id, kind) VALUES (%s,'user'),(%s,'node'),(%s,'platform')
                       ON CONFLICT (id) DO NOTHING""", (consumer, rec["node_id"], "platform:fee"))
        cur.execute("""INSERT INTO receipts (id,node_id,consumer_id,request_id,model,tokens_in,tokens_out,
                       amount_micro,sig_supplier,sig_consumer,ts_start,ts_end,idempotency_key)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,to_timestamp(%s),to_timestamp(%s),%s)""",
                    (rid, rec["node_id"], consumer, req_id, model, rec["tokens_in"], rec["tokens_out"],
                     rec["amount_micro"], signed["sig_supplier"], signed["sig_consumer"], now - 1, now,
                     x_djb_idempotency_key))
        from .ledger import post_entry
        post_entry(c, debit=consumer, credit=rec["node_id"], amount_micro=q["amount_micro"] - q["fee_micro"],
                   memo="usage settle", receipt_id=rid)
        if q["fee_micro"] > 0:
            post_entry(c, debit=consumer, credit="platform:fee", amount_micro=q["fee_micro"],
                       memo="platform fee", receipt_id=rid)

    payload = {"id": rid, "object": "chat.completion", "created": int(now), "model": model,
               "choices": [{"index": 0, "message": {"role": "assistant", "content": up["text"]},
                            "finish_reason": "stop"}],
               "usage": {"prompt_tokens": up["prompt_tokens"], "completion_tokens": up["completion_tokens"],
                         "total_tokens": up["prompt_tokens"] + up["completion_tokens"]},
               "djb_receipt_id": rid}
    headers = {"X-Request-Id": req_id}

    if body.get("stream"):
        def gen():
            yield "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)
    return JSONResponse(payload, headers=headers)


@app.get("/api/v1/user/usage/summary")
def usage_summary(authorization: str | None = Header(default=None),
                  x_client_key: str | None = Header(default=None, alias="X-Client-Key")):
    consumer = x_client_key or (_auth(authorization) if authorization else None)
    if not consumer:
        raise HTTPException(status_code=401, detail={"code": "unauthenticated", "message": "missing key"})
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT coalesce(sum(amount_micro),0), count(*) FROM receipts WHERE consumer_id=%s", (consumer,))
        total, n = cur.fetchone()
    return {"object": "usage_summary", "consumer": consumer, "receipts": n, "amount_micro": total}


@app.get("/api/v1/admin/ledger/entries")
def ledger_entries(limit: int = 20):
    limit = max(1, min(limit, 200))
    with db.conn() as c, c.cursor() as cur:
        cur.execute("""SELECT seq, debit, credit, amount_micro, memo, hash
                       FROM ledger_entries ORDER BY seq DESC LIMIT %s""", (limit,))
        rows = cur.fetchall()
    return {"object": "list", "data": [{"seq": s, "debit": d, "credit": cr, "amount_micro": a, "memo": m,
                                        "hash": h} for s, d, cr, a, m, h in rows]}


@app.get("/healthz")
def healthz():
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT 1")
    return {"ok": True}
