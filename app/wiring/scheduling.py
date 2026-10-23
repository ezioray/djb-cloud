# SPDX-License-Identifier: Apache-2.0
"""M04 调度 → M03 网关的接线段，以及 demo 市场种子。

节点 / 容量走 M02 的**公开领域入口**；报价走 M04 的 ``quotes.register``；
路由走 M04 ``pipeline.execute``。网关只看到 ``Decision`` 的投影。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.gateway import models as gateway_models
from app.gateway import providers
from app.scheduling import candidates, pipeline, quotes
from app.supply import heartbeat
from app.supply import models as supply_models

from .db import Database

DEMO_MODEL = "demo-model"
DEMO_ACCESS = "A1"


@dataclass(frozen=True)
class Market:
    node_id: str
    quote_id: str
    ask_price_minor: int
    price_max_minor: int


def seed_market(db: Database, *, model: str = DEMO_MODEL) -> Market:
    """建一个 active 节点 + 容量公告 + 有效报价。"""
    with db.connect() as conn:
        registered = supply_models.register(
            conn,
            platform="linux",
            hardware_fingerprint="s1-demo-hardware-fingerprint",
            client_version="1.0.0",
            protocol_version="1.0.0",
            capabilities=("token_relay",),
            access_modes=(DEMO_ACCESS,),
            region="demo",
            trace_id="s1-demo-market",
        )
        node = supply_models.review(
            conn,
            node_id=registered.node.id,
            decision="approve",
            reason="S1 end-to-end demo",
            actor="demo-admin",
            trace_id="s1-demo-market",
        )
        capacity_entries = [
            {
                "kind": "token_relay",
                "access": DEMO_ACCESS,
                "model": model,
                "max_qps": 20,
                "unit": "token",
                "ask_price": "8.00",
                "resource_level": "standard",
            }
        ]
        heartbeat.pulse(
            conn,
            node=node,
            protocol_version="1.0.0",
            policy_version=node.policy_version,
            capacity_entries=capacity_entries,
            trace_id="s1-demo-market",
        )
        quote = quotes.register(
            conn,
            node_id=node.id,
            access=DEMO_ACCESS,
            model=model,
            unit="token",
            ask_price_minor=800,
            price_max_minor=1000,
            ttl_s=600,
            trace_id="s1-demo-market",
        )
        conn.commit()
    return Market(
        node_id=node.id,
        quote_id=quote.quote.quote_id,
        ask_price_minor=quote.quote.ask_price_minor,
        price_max_minor=quote.quote.price_max_minor or 0,
    )


class RouteAdapter:
    """M03 ``RouteProvider``：``RouteRequest`` → M04 ``Decision``。"""

    def __init__(self, db: Database) -> None:
        self._db = db

    def route(self, request: gateway_models.RouteRequest) -> Any:
        with self._db.connect() as conn:
            route = candidates.RouteInput(
                model=request.model,
                kind=request.kind,
                tenant_id=request.tenant_id,
                trace_id=request.trace_id,
                requested_tokens=request.requested_tokens,
                attempt_no=request.attempt_no,
            )
            decision, _created = pipeline.execute(
                conn,
                route,
                request_id=request.request_id,
            )
            conn.commit()
        if not decision.chosen:
            raise providers.NoRoute(
                f"M04 无可用节点（reason={','.join(decision.reason_codes) or 'unknown'}）"
            )
        return decision


def decision_policy_version(decision: Any) -> str:
    value = getattr(decision, "policy_version", None)
    if not value:
        raise RuntimeError("M04 decision 缺 policy_version")
    return str(value)


def node_id_of(decision: Any) -> str:
    chosen = getattr(decision, "chosen", None) or {}
    value = chosen.get("node_id") if isinstance(chosen, dict) else None
    if not value:
        raise RuntimeError("M04 decision 缺 chosen.node_id")
    return str(value)


def trace_id(*, prefix: str = "s1") -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def utcnow() -> datetime:
    from datetime import timezone

    return datetime.now(timezone.utc)
