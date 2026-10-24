# SPDX-License-Identifier: AGPL-3.0-or-later
"""M01 身份 → M03 网关的接线段。

* ``provision_account``：建登录身份 / personal 账户 / 验证 / API Key（明文只出现一次）；
* ``IdentityAuth``：实现 M03 的 ``AuthProvider`` 契约，内部只调 M01 的公开入口。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.identity import api_keys, models, state

from .db import Database


@dataclass(frozen=True)
class Provisioned:
    account_id: uuid.UUID
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    api_key_id: int
    raw_key: str
    policy_version: str


def provision_account(db: Database, *, policy_version: str = "s1-demo-pv") -> Provisioned:
    """建一个可写、有配额快照的 personal 账户，并签发一枚 API Key。"""
    with db.connect() as conn:
        user = models.create_user(conn, display_name="S1 Demo User")
        account = models.create_account(
            conn, user_id=user.id, type="personal", policy_version=policy_version
        )
        account = state.verify(conn, account.id)
        key, raw_key = api_keys.create(
            conn,
            account_id=account.id,
            name="s1-demo",
            qps=100,
            trace_id="s1-demo-provision",
        )
        conn.commit()
    return Provisioned(
        account_id=account.id,
        tenant_id=account.tenant_id,
        user_id=user.id,
        api_key_id=key.id,
        raw_key=raw_key,
        policy_version=policy_version,
    )


class IdentityAuth:
    """M03 ``AuthProvider``：``raw_key`` → M01 ``AuthContext``（由网关 coerce 成 Principal）。"""

    def __init__(self, db: Database) -> None:
        self._db = db

    def __call__(self, raw_key: str, *, now: datetime, client_ip: str | None,
                 trace_id: str) -> Any:
        with self._db.connect() as conn:
            context = api_keys.verify_api_key(
                conn,
                raw_key,
                now=now,
                require_writable=True,
                require_quota=True,
                trace_id=trace_id,
            )
            conn.commit()
            return context
