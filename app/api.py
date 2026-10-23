# SPDX-License-Identifier: Apache-2.0
"""最小 API：严格按 spec/openapi.yaml 实现（契约测试会比对）。"""
from __future__ import annotations

import hashlib
import hmac as hmaclib
import json
import os
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from . import db, pricing, receipt as rcpt, upstream
from .audit import keys as audit_keys
from .audit.health import create_health_router
from .audit.router import create_router as create_audit_router
from .config_center.router import create_router as create_config_center_router
from .data_gov.router import create_router as create_data_gov_router
from .identity.router import router as identity_router
from .ledger.router import router as ledger_router
from .metering.router import router as metering_router
from .nodes import router as node_router
from .notify.router import create_router as create_notify_router
from .recon.router import create_router as create_recon_router
from .reputation.router import create_router as create_reputation_router
from .risk.router import create_router as create_risk_router
from .scheduling.router import router as scheduling_router
from .supply.router import router as supply_router
from .treasury.router import create_router as create_treasury_router
from .wiring.treasury import M06LedgerPoster, make_attestation_verifier

app = FastAPI(title="djb-cloud", version="0.1.0")
app.include_router(node_router)
app.include_router(identity_router)
app.include_router(ledger_router)
# W1 模块接线（Lead 合并窗口）：M02 / M04 / M05 / M10 的路由由各模块自带，
# 鉴权/连接默认 fail-closed；生产部署再注入 provider（见各模块 router 头部说明）。
app.include_router(supply_router)
app.include_router(scheduling_router)
app.include_router(metering_router)
app.include_router(create_config_center_router())


# ── M16 内部运维面接线（spec 1.2.2）────────────────────────────────────────
# 服务身份：mTLS 由网关终结，这里只校验服务令牌（fail-closed：未配置即拒绝）。
# 生产部署须注入更细的主体解析（按 mTLS 证书 SAN 映射 scopes）；S1 用单令牌。
INTERNAL_TOKEN_ENV = "DJB_INTERNAL_SERVICE_TOKEN"


def _internal_service_principal(request: Request) -> dict | None:
    """服务主体：mTLS 由网关终结，这里只校验服务令牌；未配置/不匹配 → None（调用方 fail-closed）。"""
    expected = os.environ.get(INTERNAL_TOKEN_ENV, "")
    provided = request.headers.get("X-DJB-Service-Token", "")
    if not expected or not provided or not hmaclib.compare_digest(provided, expected):
        return None
    return {"service": "internal", "scopes": ["*"]}


def _user_principal(request: Request) -> dict | None:
    """用方主体（Bearer API Key → 账户 UUID）：M12 站内信/Webhook 用。

    失败一律返回 None（由模块侧 fail-closed 成 401/40101）；不在此抛异常。
    """
    authorization = (request.headers.get("authorization") or "").strip()
    if not authorization.lower().startswith("bearer "):
        return None
    raw = authorization.split(" ", 1)[1].strip()
    if not raw:
        return None
    digest = hashlib.sha256(raw.encode()).hexdigest()
    try:
        with db.conn() as c, c.cursor() as cur:
            cur.execute("SELECT user_id FROM api_keys WHERE key_hash=%s AND revoked_at IS NULL", (digest,))
            row = cur.fetchone()
    except Exception:                                   # pragma: no cover - 依赖不可用
        return None
    if not row:
        return None
    try:
        return {"account_id": str(uuid.UUID(str(row[0])))}
    except (TypeError, ValueError):
        return None


def _admin_dev_principal(request: Request) -> dict | None:
    """管理面主体（**仅本地/测试**）：X-Admin-Actor / Roles / Tenant 头。

    生产（DJB_ENV=prod）一律返回 None：必须由 M01 会话 + step-up 解析注入后再放行。
    """
    if os.environ.get("DJB_ENV", "").lower() in ("prod", "production"):
        return None
    actor = (request.headers.get("X-Admin-Actor") or "").strip()
    if not actor:
        return None
    roles = [r.strip().upper() for r in (request.headers.get("X-Admin-Roles") or "").split(",") if r.strip()]
    tenant = (request.headers.get("X-Admin-Tenant") or "").strip() or None
    return {"actor": actor, "roles": roles, "scopes": ["*"], "tenant_id": tenant}


app.include_router(create_audit_router(
    connection_factory=db.conn,
    principal_resolver=_internal_service_principal,
    key_provider=audit_keys.from_env(),
))
app.include_router(create_health_router(
    connection_factory=db.conn,
    key_provider=audit_keys.from_env(),
    version="0.1.0",
))


# ── M09 对账接线（spec 1.2.3）──────────────────────────────────────────────
# 管理面主体沿用本地/测试头约定（生产必须注入 M01 会话解析）；
# 出款前校验（validate）走服务令牌，与 M16 内部面同一套 fail-closed 口径。
app.include_router(create_recon_router(
    connection_factory=db.conn,
    admin_resolver=_admin_dev_principal,
    service_resolver=_internal_service_principal,
))


# ── M12 通知接线（spec 1.2.3）──────────────────────────────────────────────
# 用方主体走 Bearer API Key（与 /v1 同一把钥匙）；未带/无效 → 401/40101。
# Webhook 真实投递默认关闭（开关三字段在模块内），S1 只做订阅 CRUD 与站内信。
app.include_router(create_notify_router(
    connection_factory=db.conn,
    principal_resolver=_user_principal,
))


# ── M07 信誉与 COP 接线（spec 1.2.4）──────────────────────────────────────
# 用方主体同 M12（Bearer→account_id）；管理面 grants 走本地/测试头（生产注入 M01 会话）。
app.include_router(create_reputation_router(
    connection_factory=db.conn,
    principal_resolver=_user_principal,
    admin_resolver=_admin_dev_principal,
))


# ── M11 风控接线（spec 1.2.4）─────────────────────────────────────────────
# 管理面主体同 M07/M09；阈值不入库/响应/事件，限额执行由 M03/M04/M08 读 v_risk_limits。
app.include_router(create_risk_router(
    connection_factory=db.conn,
    admin_resolver=_admin_dev_principal,
))


# ── M14 数据治理与 Ops 接线（spec 1.2.6）──────────────────────────────────
# 管理面主体同 M07/M09/M11；导出台账/保留任务/批量五步/操作回放十条端点。
# audit_sink 未注入（与 M11 同口径）：S2 统一注入 M16 审计适配器，当前默认 fail-closed。
app.include_router(create_data_gov_router(
    connection_factory=db.conn,
    admin_resolver=_admin_dev_principal,
))


# ── M08 支付与资金接线（spec 1.2.5/1.2.6）─────────────────────────────────
# 用方 / 共享方都走 Bearer→account_id（S1 共享方会话同用方）；管理面同 M07/M09/M11/M14。
# 入账走 M06 ledger_poster（E3/E4/E5 两步记法），出款 attestation 走 M09 validate —— 都 fail-closed。
app.include_router(create_treasury_router(
    connection_factory=db.conn,
    user_resolver=_user_principal,
    provider_resolver=_user_principal,
    admin_resolver=_admin_dev_principal,
    ledger_poster=M06LedgerPoster(),
    attestation_verifier=make_attestation_verifier(db.conn),
))


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
                       amount_micro,sig_supplier,sig_consumer,ts_start,ts_end,idempotency_key,task_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,to_timestamp(%s),to_timestamp(%s),%s,%s)""",
                    (rid, rec["node_id"], consumer, req_id, model, rec["tokens_in"], rec["tokens_out"],
                     rec["amount_micro"], signed["sig_supplier"], signed["sig_consumer"], now - 1, now,
                     x_djb_idempotency_key, req_id))
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


@app.get("/api/v1/admin/ledger/entries")
def ledger_entries(limit: int = 20):
    limit = max(1, min(limit, 200))
    with db.conn() as c, c.cursor() as cur:
        cur.execute("""SELECT seq, debit, credit, amount_micro, memo, hash
                       FROM ledger_entries ORDER BY seq DESC LIMIT %s""", (limit,))
        rows = cur.fetchall()
    return {"object": "list", "data": [{"seq": s, "debit": d, "credit": cr, "amount_micro": a, "memo": m,
                                        "hash": h} for s, d, cr, a, m, h in rows]}


