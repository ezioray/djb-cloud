# SPDX-License-Identifier: AGPL-3.0-or-later
"""S1 端到端 demo 的接线包。

只在这里做跨模块适配：M01→M03、M04→M03、M05→M03/M06、M02→M04。
所有适配器都是注入式；模块代码零改动。
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from app.gateway import providers
from app.metering import signing

from .db import Database
from .identity import IdentityAuth, Provisioned, provision_account
from .availability import SupplyAvailability
from .nodes import DemoCatalog, EchoNodeClient
from .scheduling import Market, RouteAdapter, seed_market
from .metering import UsageAdapter, settle_usage

__all__ = [
    "S1Wiring",
    "install",
    "provision_account",
    "seed_market",
    "Provisioned",
    "Market",
    "Database",
]


@dataclass(frozen=True)
class S1Wiring:
    db: Database
    keys: signing.SignatureKeys
    identity: IdentityAuth
    route: RouteAdapter
    usage: UsageAdapter
    node: Any
    catalog: DemoCatalog
    availability: SupplyAvailability
    channel_queue: Any | None = None
    channel_client: Any | None = None

    def settle(self, usage_id: str, *, policy_version: str, trace_id: str):
        return settle_usage(self.db, usage_id, policy_version=policy_version, trace_id=trace_id)


def install(db: Database, *, keys: signing.SignatureKeys | None = None,
            channel: bool = False) -> S1Wiring:
    """把 M03 的 9 个 provider 中 demo 需要的 5 个接到真实模块入口。"""
    signature_keys = keys or signing.SignatureKeys(
        provider=secrets.token_bytes(32),
        consumer=secrets.token_bytes(32),
    )
    identity = IdentityAuth(db)
    route = RouteAdapter(db)
    usage = UsageAdapter(db, signature_keys)
    channel_queue = None
    channel_client = None
    if channel:
        # 只给 demo/测试显式开启；生产接线必须判 gateway.channel.enabled（默认关）
        from .channel import install_channel

        channel_queue, channel_client = install_channel()
        node = channel_client
    else:
        from app.supply import channel as supply_channel

        supply_channel.set_channel_backend(None)
        node = EchoNodeClient()
    availability = SupplyAvailability(db)
    catalog = DemoCatalog(availability=availability)

    providers.reset_providers()
    providers.set_auth_provider(identity)
    providers.set_route_provider(route)
    providers.set_node_client(node)
    providers.set_usage_provider(usage)
    providers.set_model_catalog_provider(catalog)
    return S1Wiring(
        db=db,
        keys=signature_keys,
        identity=identity,
        route=route,
        usage=usage,
        node=node,
        catalog=catalog,
        availability=availability,
        channel_queue=channel_queue,
        channel_client=channel_client,
    )
