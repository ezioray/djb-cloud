# SPDX-License-Identifier: Apache-2.0
"""S1 端到端 demo 的接线包。

只在这里做跨模块适配：M01→M03、M04→M03、M05→M03/M06、M02→M04。
所有适配器都是注入式；模块代码零改动。
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from app.gateway import providers
from app.metering import signing

from .db import Database
from .identity import IdentityAuth, Provisioned, provision_account
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
    node: EchoNodeClient
    catalog: DemoCatalog

    def settle(self, usage_id: str, *, policy_version: str, trace_id: str):
        return settle_usage(self.db, usage_id, policy_version=policy_version, trace_id=trace_id)


def install(db: Database, *, keys: signing.SignatureKeys | None = None) -> S1Wiring:
    """把 M03 的 9 个 provider 中 demo 需要的 5 个接到真实模块入口。"""
    signature_keys = keys or signing.SignatureKeys(
        provider=secrets.token_bytes(32),
        consumer=secrets.token_bytes(32),
    )
    identity = IdentityAuth(db)
    route = RouteAdapter(db)
    usage = UsageAdapter(db, signature_keys)
    node = EchoNodeClient()
    catalog = DemoCatalog()

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
    )
