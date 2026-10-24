# SPDX-License-Identifier: AGPL-3.0-or-later
"""最小 API：严格按 spec/openapi.yaml 实现（契约测试会比对）。"""
from __future__ import annotations

import hashlib
import hmac as hmaclib
import json
import os
import time
import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from . import db, pricing, receipt as rcpt, upstream
from .audit import keys as audit_keys
from .audit.health import create_health_router
from .audit.router import create_router as create_audit_router
from .config_center.router import create_router as create_config_center_router
from .data_gov.router import create_router as create_data_gov_router
from .identity.router import router as identity_router
from .integrity import providers as integrity_providers
from .integrity.canary_router import router as canary_router
from .integrity.canary_router import set_admin_authenticator as set_canary_admin_auth
from .integrity.attest_router import router as attest_router
from .integrity.attest_router import set_admin_authenticator as set_attest_admin_auth
from .integrity.attest_router import set_node_authenticator as set_attest_node_auth
from .integrity.router import router as integrity_router, set_admin_authenticator as set_integrity_admin_auth
from .integrity.sampling_router import router as sampling_router
from .integrity.sampling_router import set_admin_authenticator as set_sampling_admin_auth
from .ledger.router import router as ledger_router
from .metering.router import router as metering_router, set_admin_authenticator as set_metering_admin_auth, set_user_authenticator as set_metering_user_auth
from .nodes import router as node_router
from .model_sync.router import admin_router as model_sync_admin_router
from .model_sync.router import router as model_sync_router
from .model_sync.router import set_admin_authenticator as set_model_sync_admin_auth
from .model_sync.router import set_node_authenticator as set_model_sync_node_auth
from .notify.node_push_router import create_router as create_node_push_router
from .notify.router import create_router as create_notify_router
from .recon.router import create_router as create_recon_router
from .reputation.router import create_router as create_reputation_router
from .risk.router import create_router as create_risk_router
from .gateway import tokenizer as gateway_tokenizer
from .scheduling.router import router as scheduling_router
from .supply.router import router as supply_router, set_user_authenticator as set_supply_user_auth
from .treasury.router import create_router as create_treasury_router
from .wiring.treasury import M06LedgerPoster, make_attestation_verifier

app = FastAPI(title="djb-cloud", version="0.1.0")

# ── M03 真实网关路径（M03-R2）───────────────────────────────────────────────
# ``DJB_GATEWAY_M03=1``：装配 ``app.wiring.install``（M01/M04/M05/M02 的注入点）并把 M03
# gateway router **先**挂上——``/v1/chat/completions`` / ``/v1/models`` 由 M03 命中，
# 下方 legacy demo 同路径路由保留但被遮蔽（不删，M03-R3 再清）。
# 默认（不设该 env）整块不执行：import 图、providers、路由表与合并前逐字节一致。
# ``DJB_NODE_CHANNEL=1``：``install(channel=True)``——上游走 M03 内存队列 +
# ``ChannelNodeClient``（节点侧经 M02 ``/api/v1/node/channel/*`` 取任务，C10a/C10d）。
# 特性开关 ``gateway.channel.enabled`` 仍默认关：只认这个**显式 env**，避免误切生产流量。
GATEWAY_M03_ENV = "DJB_GATEWAY_M03"
NODE_CHANNEL_ENV = "DJB_NODE_CHANNEL"
M03_WIRING: Any = None


def _env_flag(name: str) -> bool:
    """环境开关只认显式 ``=1``（``true`` / 空串 / 其它一律视为关）。"""
    return (os.environ.get(name) or "").strip() == "1"


def _install_m03_gateway() -> Any:
    """装配 M03 providers 并挂 router；缺 ``DJB_DSN`` → **导入期**报错（不静默回 legacy）。"""
    if not (os.environ.get("DJB_DSN") or "").strip():
        raise RuntimeError(
            "DJB_GATEWAY_M03=1 需要 DJB_DSN：M03 网关路径 fail-closed，"
            "缺数据库连接串时不允许静默降级到 legacy demo")
    from .gateway.router import router as gateway_router      # 同包；仅 M03 模式才 import
    from .wiring import Database, install as install_wiring

    wiring = install_wiring(Database(schema="public", dsn=os.environ["DJB_DSN"]),
                            channel=_env_flag(NODE_CHANNEL_ENV))
    app.include_router(gateway_router)   # 先注册 → 同路径 M03 优先，legacy 被遮蔽
    return wiring


if _env_flag(GATEWAY_M03_ENV):
    M03_WIRING = _install_m03_gateway()

app.include_router(node_router)
app.include_router(identity_router)
app.include_router(ledger_router)
# W1 模块接线（Lead 合并窗口）：M02 / M04 / M05 / M10 的路由由各模块自带，
# 鉴权/连接默认 fail-closed；生产部署再注入 provider（见各模块 router 头部说明）。
app.include_router(supply_router)
app.include_router(integrity_router)
app.include_router(sampling_router)
app.include_router(canary_router)
app.include_router(create_node_push_router(
    connection_factory=db.conn,
    node_auth=lambda request: _node_principal(request),
    admin_auth=lambda request: _admin_dev_principal(request),
))
app.include_router(attest_router)
app.include_router(model_sync_router)
app.include_router(model_sync_admin_router)
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
    return {"actor": actor, "admin_id": actor, "roles": roles, "scopes": ["*"],
            "tenant_id": tenant}


# ── M02 / M05 用方鉴权接线（spec 1.2.6 新端点）──────────────────────────────
# 会话态节点列表 / 解绑、账单导出都走 userBearer（Bearer API Key → account_id）；
# 解绑还要 step-up：S1 以 X-Admin-Step-Up 头存在视为已 step-up（与 M08 默认口径一致，
# 真 MFA 由 M01 会话注入后替换该判定）。
def _user_principal_step_up(request: Request) -> dict | None:
    principal = _user_principal(request)
    if principal and (request.headers.get("X-Admin-Step-Up") or "").strip():
        principal = {**principal, "step_up": True}
    return principal


set_supply_user_auth(_user_principal_step_up)
set_metering_user_auth(_user_principal)
set_metering_admin_auth(_admin_dev_principal)
set_integrity_admin_auth(_admin_dev_principal)
set_sampling_admin_auth(_admin_dev_principal)
set_canary_admin_auth(_admin_dev_principal)
set_attest_admin_auth(_admin_dev_principal)


def _node_principal(request: Request) -> dict | None:
    """节点侧主体（M02 X-Client-Key）：返回 {node_id}；未带/无效 → None（路由 fail-closed）。"""
    key = (request.headers.get("X-Client-Key") or "").strip()
    if not key:
        return None
    from .supply import models as supply_models

    try:
        with db.conn() as c:
            auth = supply_models.authenticate(c, key, allow_previous=True)
            if auth.node.state != "active":
                return None
            return {"node_id": auth.node.id, "roles": ["node"]}
    except Exception:                                      # noqa: BLE001 - 鉴权失败一律 401
        return None


set_attest_node_auth(_node_principal)
set_model_sync_node_auth(_node_principal)
set_model_sync_admin_auth(_admin_dev_principal)


def _integrity_token_count(prompt: str, model: str) -> int:
    """M17 服务端 tokenizer：复用 M03 的本地计数（同一实现，避免两套口径）。"""
    return gateway_tokenizer.count_prompt_tokens(
        model, ({"role": "user", "content": prompt},))


integrity_providers.set_token_counter(_integrity_token_count,
                                      version="gateway.heuristic.v1")


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


