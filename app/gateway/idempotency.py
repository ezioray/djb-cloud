# SPDX-License-Identifier: Apache-2.0
"""幂等与请求体指纹去重（M03 §3.1 / §6.1 / INV-M03-03）。

三种窗口（M03 §8.2）：

| 形态 | 键 | 窗口 |
| --- | --- | --- |
| 写请求带 ``X-DJB-Idempotency-Key`` | ``(scope, key)`` 唯一 | **24h** |
| 非流式请求体指纹 | 规范化报文 sha256 | **300s** |
| 流式请求建立 | 同上（只去重「建连」，T3） | **60s** |

不变式：

* **同键同载荷 → 回放首次结果**（HTTP 状态 + 报文原样，头部带
  ``X-DJB-Idempotent-Replay: true``），**不重复落账、不重复扣费**；
* **同键不同载荷 → 409 / 40919**（``conflict``），不给「疑似重复」这类可探测细节；
* 指纹去重的 scope 含 ``account_id`` + ``api_key_id``，**不会**把两个账户的同形请求
  互相回放（越权面为 0）；
* 过期记录在写入时被覆盖（``expires_at <= now``），并顺带做一次小批量清理（保留 7 天之外的
  指纹行），避免表无限增长。

存储读写统一在 :mod:`app.gateway.store`（本文件**不写 SQL**、不 import psycopg）。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from . import clock, errors, facts, models

__all__ = ["IdempotencyRecord", "Replay", "WriteGuard", "canonical_body", "body_hash",
           "require_key", "scope_of", "fingerprint_scope", "window_for", "replay_or_conflict",
           "remember", "delete_expired"]


@dataclass(frozen=True)
class IdempotencyRecord:
    scope: str
    key: str
    request_hash: str
    status_code: int
    payload: Mapping[str, Any]
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class Replay:
    """命中回放：直接返回首次结果（不再走路由 / 派发 / 计量）。"""

    status_code: int
    payload: Mapping[str, Any]
    key: str
    mode: str = "idempotency"


# --------------------------------------------------------------------------- 报文归一
def canonical_body(body: Mapping[str, Any]) -> str:
    """规范化 JSON（键排序、紧凑分隔、非 ASCII 原样）——指纹稳定不随客户端键序变化。"""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def body_hash(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_body(body).encode("utf-8")).hexdigest()


def require_key(raw: str | None) -> str | None:
    """校验 ``X-DJB-Idempotency-Key``（spec：16–128 字符）；非法 → 400 / 40001。"""
    if raw is None or not raw.strip():
        return None
    key = raw.strip()
    if not facts.IDEMPOTENCY_KEY_MIN_LENGTH <= len(key) <= facts.IDEMPOTENCY_KEY_MAX_LENGTH:
        raise errors.GatewayError(
            "bad_request",
            f"X-DJB-Idempotency-Key 长度必须是 "
            f"{facts.IDEMPOTENCY_KEY_MIN_LENGTH}–{facts.IDEMPOTENCY_KEY_MAX_LENGTH} 字符",
            details={"field": "X-DJB-Idempotency-Key"})
    return key


def scope_of(method: str, path: str, principal: models.Principal) -> str:
    """幂等作用域 = ``方法 + 路径 + 账户 + Key``（同键不同账户互不回放）。"""
    key_part = principal.api_key_id if principal.api_key_id is not None else "-"
    return f"idem:{method.upper()}:{path}:{principal.account_id}:{key_part}"


def fingerprint_scope(method: str, path: str, principal: models.Principal) -> str:
    key_part = principal.api_key_id if principal.api_key_id is not None else "-"
    return f"fp:{method.upper()}:{path}:{principal.account_id}:{key_part}"


def window_for(*, stream: bool = False) -> int:
    """请求体指纹窗口：非流式 300s / 流式 60s（M03 §8.2）。"""
    return facts.STREAM_DEDUP_WINDOW_S if stream else facts.FINGERPRINT_WINDOW_S


# --------------------------------------------------------------------------- 查 / 存
def replay_or_conflict(c: Any, *, scope: str, key: str, request_hash: str, now: datetime,
                       ttl_s: int = facts.IDEMPOTENCY_TTL_S,
                       window_s: int | None = None, mode: str = "idempotency") -> Replay | None:
    """查既有记录：同载荷 → 回放；不同载荷（且仍在窗口内）→ 409 / 40919。"""
    from . import store                                    # 同包，避免循环 import

    record = store.get_idempotency(c, scope=scope, key=key)
    if record is None:
        return None
    moment = clock.as_utc(now)
    if record.expires_at <= moment:
        return None                                        # 已过期：本次重新执行并覆盖
    if window_s is not None and record.created_at < moment - timedelta(seconds=int(window_s)):
        return None                                        # 指纹窗口外：允许再次执行
    if record.request_hash != request_hash:
        raise errors.GatewayError(
            "conflict",
            "同一幂等键的请求载荷与首次不同：请换一个幂等键或复用原载荷",
            details={"idempotency_key": key})
    return Replay(status_code=record.status_code, payload=record.payload, key=key, mode=mode)


def remember(c: Any, *, scope: str, key: str, request_hash: str, status_code: int,
             payload: Mapping[str, Any], now: datetime,
             ttl_s: int = facts.IDEMPOTENCY_TTL_S) -> None:
    """记住首次结果（与 ``api_request_log`` / outbox 同事务写入）。"""
    from . import store

    moment = clock.as_utc(now)
    store.save_idempotency(
        c, record_id=str(models.uuid7(int(moment.timestamp() * 1_000_000))),
        scope=scope, key=key, request_hash=request_hash, status_code=int(status_code),
        payload=dict(payload), created_at=moment,
        expires_at=moment + timedelta(seconds=int(ttl_s)))


def delete_expired(c: Any, *, now: datetime, limit: int = 200) -> int:
    """清理过期指纹 / 幂等记录（小批量；保留期由 ``expires_at`` 决定）。"""
    from . import store

    return store.purge_idempotency(c, now=clock.as_utc(now), limit=limit)



# --------------------------------------------------------------------------- 幂等中间件（CR-10）
@dataclass
class WriteGuard:
    """**所有写端点的幂等中间件**（CR-10 规则：新写端点必须走这一条路）。

    用法（router / 领域服务共用）::

        guard = WriteGuard(c, principal=principal, method="POST", path="/v1/batches",
                           key=idempotency_key, body=body, now=now)
        replay = guard.replay()          # 幂等键 24h → 请求体指纹 300s（流式 60s）
        if replay is not None:
            return replay.status_code, replay.payload   # 不重复落账、不重复扣费
        ...
        guard.remember(status_code=202, payload=payload)

    口径（M03 §3.1 / §8.2 / INV-M03-03）：

    * ``key`` 非空时按 ``(scope, key)`` 判 24h 幂等：同载荷回放、异载荷 → 409 / 40919；
    * 无论有没有 ``key``，都再做一次**请求体指纹**去重（非流式 300s / 流式建立 60s）；
    * ``scope`` 含账户与 Key，两个账户的同形请求互不回放；
    * 回放**不再**触发路由 / 派发 / 计量（调用方直接返回 ``replay.payload``）。
    """

    c: Any
    principal: models.Principal
    method: str
    path: str
    key: str | None
    body: Mapping[str, Any]
    now: datetime
    stream: bool = False

    @property
    def body_hash(self) -> str:
        return body_hash(self.body)

    @property
    def window_s(self) -> int:
        return window_for(stream=self.stream)

    def replay(self) -> Replay | None:
        """依次查幂等键（24h）与请求体指纹（300s / 流式 60s）；命中即回放。"""
        digest = self.body_hash
        if self.key:
            found = replay_or_conflict(
                self.c, scope=scope_of(self.method, self.path, self.principal), key=self.key,
                request_hash=digest, now=self.now, ttl_s=facts.IDEMPOTENCY_TTL_S)
            if found is not None:
                return found
        return replay_or_conflict(
            self.c, scope=fingerprint_scope(self.method, self.path, self.principal),
            key=digest, request_hash=digest, now=self.now, ttl_s=self.window_s,
            window_s=self.window_s, mode="fingerprint")

    def remember(self, *, status_code: int, payload: Mapping[str, Any],
                 ttl_s: int | None = None, store_payload: bool = True) -> None:
        """记住首次结果（与业务同事务）；``store_payload=False`` 时只留标记（流式用）。"""
        digest = self.body_hash
        body_payload = dict(payload) if store_payload else {"stream": True}
        if self.key:
            remember(self.c, scope=scope_of(self.method, self.path, self.principal),
                     key=self.key, request_hash=digest, status_code=status_code,
                     payload=body_payload, now=self.now,
                     ttl_s=int(ttl_s or facts.IDEMPOTENCY_TTL_S))
        remember(self.c, scope=fingerprint_scope(self.method, self.path, self.principal),
                 key=digest, request_hash=digest, status_code=status_code,
                 payload=body_payload, now=self.now,
                 ttl_s=int(ttl_s or self.window_s))
