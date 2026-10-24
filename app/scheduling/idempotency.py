# SPDX-License-Identifier: AGPL-3.0-or-later
"""幂等键（M04 §3 / 00-conventions §6.1 / CR-5，迁移 408）。

窗口 24 h，作用域 = ``方法 + 归一化路径``（路径参数折成 ``{id}``）。三条铁律与 M02 同款：

1. **同键同载荷** → 回放首次响应（状态码也回放），不重复落业务事实；
2. **同键不同载荷** → ``40919``（幂等冲突），不做猜测性覆盖；
3. **库里不存明文**：M04 的响应体只有 id / 价格 / 时间，没有一次性明文；
   若将来引入明文（如密钥），入库前必须剔除（``storable_response``）。

与 T1/T2 的**业务幂等**的关系：业务幂等（报价内容不变不升版本 / 决策四元锚点复用）保证
「同一事实不重复落库」；本表再保证「同一请求回放首次响应」——两者互补，不互相替代。
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from . import clock, facts
from .errors import IdempotencyConflict, InvalidArgument

log = logging.getLogger("djb.scheduling.idempotency")

#: 响应里**永不入库**的字段（一次性明文）；M04 目前没有，留白以防将来加
PLAINTEXT_FIELDS: tuple[str, ...] = ("client_key", "api_key", "token", "secret")

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{12}")
_NODE_RE = re.compile(r"(?<=/)n_[0-9a-z]{4,}")


@dataclass(frozen=True)
class IdemRecord:
    request_hash: str
    status_code: int
    response: dict[str, Any]


def body_hash(body: dict[str, Any] | None) -> str:
    """载荷指纹（规范化 JSON：键排序 + 紧凑分隔），避免字段顺序导致误判。"""
    canonical = json.dumps(body or {}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def scope_of(method: str, path: str) -> str:
    """``方法 + 归一化路径``（路径参数折成 ``{id}``；超长用摘要兜底）。"""
    normalized = _UUID_RE.sub("{id}", path or "/")
    normalized = _NODE_RE.sub("{id}", normalized)
    scope = f"{(method or 'GET').upper()} {normalized}"
    if len(scope) > facts.IDEMPOTENCY_SCOPE_MAX_LEN:                  # pragma: no cover - 兜底
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
        scope = f"{(method or 'GET').upper()} #{digest}"
    return scope


def storable_response(payload: dict[str, Any]) -> dict[str, Any]:
    """剔除一次性明文字段后再入库（否则等于凭据落库）。"""
    return {key: value for key, value in payload.items() if key not in PLAINTEXT_FIELDS}


def lookup(c, *, scope: str, key: str, request_hash: str,
           now: datetime | None = None) -> IdemRecord | None:
    """查已有记录：同键同载荷返回记录；同键不同载荷抛 ``40919``。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute(
            """SELECT request_hash, status_code, response FROM scheduling_idempotency
                WHERE scope = %s AND idem_key = %s AND expires_at > %s""",
            (scope, key, moment))
        row = cur.fetchone()
    if row is None:
        return None
    record = IdemRecord(request_hash=row[0], status_code=int(row[1]), response=dict(row[2]))
    if record.request_hash != request_hash:
        raise IdempotencyConflict("同一幂等键携带了不同载荷", reason="idempotency_conflict")
    log.info("scheduling.idem.replay", extra={"event": "idempotency.replay", "scope": scope})
    return record


def save(c, *, scope: str, key: str, request_hash: str, status_code: int,
         response: dict[str, Any], now: datetime | None = None) -> uuid.UUID:
    """落首次响应（同事务；只存剔除明文后的响应体）。"""
    moment = now or clock.utcnow()
    identifier = uuid.uuid4()
    expires_at = moment + timedelta(hours=facts.IDEMPOTENCY_TTL_HOURS)
    store = storable_response(response)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO scheduling_idempotency
                   (id, scope, idem_key, request_hash, status_code, response, created_at,
                    expires_at)
               VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
               ON CONFLICT (scope, idem_key) DO NOTHING""",
            (identifier, scope, key, request_hash, status_code,
             json.dumps(store, ensure_ascii=False), moment, expires_at))
    return identifier


def require_key(value: str | None) -> str | None:
    """校验客户端幂等键形态（可缺省：缺省即不做字节级回放，业务幂等仍然生效）。"""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) > facts.IDEMPOTENCY_KEY_MAX_LEN:
        raise InvalidArgument(
            f"X-DJB-Idempotency-Key 最多 {facts.IDEMPOTENCY_KEY_MAX_LEN} 字符",
            field="X-DJB-Idempotency-Key")
    return text


def purge_expired(c, *, now: datetime | None = None) -> int:
    """清理过期键（24 h 窗口外的缓存行；这是缓存不是审计，允许删）。"""
    moment = now or clock.utcnow()
    with c.cursor() as cur:
        cur.execute("DELETE FROM scheduling_idempotency WHERE expires_at <= %s", (moment,))
        return cur.rowcount


__all__ = ["IdemRecord", "PLAINTEXT_FIELDS", "body_hash", "scope_of", "storable_response",
           "lookup", "save", "require_key", "purge_expired"]
