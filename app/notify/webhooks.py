# SPDX-License-Identifier: Apache-2.0
"""Webhook 订阅管理与 SSRF 校验（M12 §4.1 / §6.3 / INV-05）。

三条硬约束：

1. **secret 只返回一次**：创建时生成 32 字节随机密钥，响应里给明文，库里只有
   ``sha256(secret)``；重复提交同一幂等键**也不能**再拿到 secret（只存哈希，INV-05），
   只能得到 ``40902 idempotent_replay``；
2. **SSRF**：只允许 ``https``；禁回环 / 私网 / link-local / 保留 / CGNAT / IPv4 映射 IPv6，
   禁 ``localhost`` / ``*.local`` / ``*.internal`` / 元数据主机名；带凭据的 URL 一律拒。
   S1 不做 DNS 解析（不发网络请求），因此**解析后私网**由 S2 投递适配器在每次发送前
   二次校验（同一 :func:`is_private_address` 复用），见 §6.3「注册与投递双校验」；
3. **账户隔离**：列表 / 删除 / 计数都带 ``account_id``；越权得到 404，不泄露他人订阅。
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from psycopg import errors as pg_errors

from . import clock, config_source, errors, facts, signing
from .models import WebhookSubscription, as_uuid
from .store import dict_cursor

__all__ = [
    "validate_url", "is_private_address", "redact_url", "create", "list_page", "delete",
    "register_failure", "active_for_event", "count_for_account", "find_by_url",
    "by_idempotency_key", "MAX_URL_LENGTH",
]

MAX_URL_LENGTH = 2048
MIN_IDEMPOTENCY_LENGTH = 16
MAX_IDEMPOTENCY_LENGTH = 128

#: 元数据 / 内部解析用的主机名（大小写不敏感，含常见云厂商元数据域名）
_BLOCKED_HOSTNAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal", "instance-data", "instance-data.ec2.internal",
    "metadata.azure.internal",
})
_BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".localdomain")
#: 只允许 443 与高位端口（低端口常被内部服务占用，属 SSRF 首要目标）
_ALLOWED_LOW_PORTS = frozenset({443})
#: 显式补充网段：不同 Python 版本的 ``is_private`` 口径不一致（如 100.64/10 CGNAT），
#: 这里按 §6.3「禁私网与元数据网段」把钱该堵的都堵死，不依赖标准库版本。
_BLOCKED_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32",
    "fc00::/7", "fe80::/10", "ff00::/8",
))
_DECIMAL_HOST_RE = re.compile(r"^[0-9]+$")
_HEX_HOST_RE = re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE)


def is_private_address(address: str | ipaddress._BaseAddress) -> bool:  # type: ignore[attr-defined]
    """私网 / 回环 / link-local / 保留 / 组播 / 未指定 / CGNAT 一律视为「不许访问」。

    同时处理 IPv4、IPv6 以及 ``::ffff:10.0.0.1`` 这类 IPv4 映射地址（去掉映射再判）。
    """
    try:
        ip = (address if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
              else ipaddress.ip_address(str(address)))
    except ValueError:
        return False                                  # 不是 IP 字面量 → 交给主机名规则
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if any(ip in network for network in _BLOCKED_NETWORKS if network.version == ip.version):
        return True
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified)


def _blocked_hostname(host: str) -> bool:
    lowered = host.lower().rstrip(".")
    if lowered in _BLOCKED_HOSTNAMES:
        return True
    if any(lowered.endswith(suffix) for suffix in _BLOCKED_HOST_SUFFIXES):
        return True
    if "." not in lowered and not lowered.isdigit():
        return True                                   # 单标签主机（内网短名）一律拒
    return False


def _ip_literal(host: str) -> ipaddress._BaseAddress | None:  # type: ignore[attr-defined]
    """把 IP 字面量（含十进制 / 十六进制 / IPv4 映射写法）解析成地址；不是 IP 返回 None。"""
    candidate = host.strip("[]").lower()
    if _DECIMAL_HOST_RE.match(candidate):
        try:
            number = int(candidate, 10)
            if 0 <= number <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(number)
        except ValueError:                            # pragma: no cover - 超长数字
            return None
        return None
    if _HEX_HOST_RE.match(candidate):
        try:
            number = int(candidate, 16)
            if 0 <= number <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(number)
        except ValueError:                            # pragma: no cover
            return None
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def validate_url(url: Any) -> str:
    """校验并返回 URL 主机名；不合格抛 :class:`errors.UrlRejected`（40001）。"""
    if not isinstance(url, str) or not url.strip():
        raise errors.UrlRejected("url 必填", field="url")
    if len(url) > MAX_URL_LENGTH:
        raise errors.UrlRejected(f"url 超过 {MAX_URL_LENGTH} 字符", field="url")
    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        raise errors.UrlRejected("url 无法解析", field="url") from exc
    scheme = (parts.scheme or "").lower()
    if scheme != "https":
        raise errors.UrlRejected("只允许 https（§6.3：仅 https）", field="url",
                                 detail="scheme_not_allowed")
    if "@" in parts.netloc:
        raise errors.UrlRejected("url 不得带用户名 / 口令", field="url",
                                 detail="userinfo_not_allowed")
    if parts.fragment:
        raise errors.UrlRejected("url 不得带 fragment", field="url", detail="fragment_not_allowed")
    host = parts.hostname
    if not host:
        raise errors.UrlRejected("url 缺主机名", field="url")
    try:
        port = parts.port
    except ValueError as exc:
        raise errors.UrlRejected("url 端口不合法", field="url") from exc
    if port is not None and (port < 1 or (port < 1024 and port not in _ALLOWED_LOW_PORTS)):
        raise errors.UrlRejected("url 端口不允许（只允许 443 与 ≥1024 端口）",
                                 field="url", detail="port_not_allowed")
    literal = _ip_literal(host)
    if literal is not None:
        if is_private_address(literal):
            raise errors.UrlRejected("url 指向私网 / 回环 / link-local 地址，已拒绝（SSRF）",
                                     field="url", detail="private_host")
    else:
        if _blocked_hostname(host):
            raise errors.UrlRejected("url 指向内部主机名，已拒绝（SSRF）", field="url",
                                     detail="internal_hostname")
        try:
            host.encode("idna")
        except UnicodeError as exc:
            raise errors.UrlRejected("url 主机名不合法", field="url") from exc
    if len(host) > 253:
        raise errors.UrlRejected("url 主机名过长", field="url")
    return host.lower()


def redact_url(url: str) -> str:
    """日志 / 审计用的脱敏 URL：去掉查询串与 fragment（INV-07：日志不含 URL 查询串）。"""
    try:
        parts = urlsplit(url)
    except ValueError:                                # pragma: no cover - 已在校验时拦住
        return "<invalid-url>"
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or ""
    return f"{parts.scheme}://{host}{port}{path}" if parts.scheme else path


def _describe(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise errors.InvalidArgument("description 必须是字符串", field="description")
    text = value.strip()
    if len(text) > 200:
        raise errors.InvalidArgument("description 最多 200 字符", field="description")
    return text or None


def _idempotency_key(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise errors.InvalidArgument("X-DJB-Idempotency-Key 必须是字符串",
                                     field="X-DJB-Idempotency-Key")
    key = value.strip()
    if not MIN_IDEMPOTENCY_LENGTH <= len(key) <= MAX_IDEMPOTENCY_LENGTH:
        raise errors.InvalidArgument(
            f"幂等键长度必须 {MIN_IDEMPOTENCY_LENGTH}–{MAX_IDEMPOTENCY_LENGTH}",
            field="X-DJB-Idempotency-Key")
    return key


def _fingerprint(url: str, events: Iterable[str], description: str | None) -> str:
    """请求指纹（不含 secret）：同幂等键 + 不同指纹 = 客户端用错了键。"""
    import hashlib
    import json

    raw = json.dumps({"url": url, "events": sorted(events), "description": description},
                     separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def count_for_account(conn: Any, account_id: uuid.UUID | str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM webhook_subscriptions WHERE account_id = %s",
                    (as_uuid(account_id),))
        return int(cur.fetchone()[0])


def find_by_url(conn: Any, account_id: uuid.UUID | str, url: str) -> WebhookSubscription | None:
    with dict_cursor(conn) as cur:
        cur.execute(
            """SELECT id, account_id, url, events, status, created_at, updated_at, description,
                      secret_hash, paused_until, failure_count
                 FROM webhook_subscriptions WHERE account_id = %s AND url = %s""",
            (as_uuid(account_id), url))
        row = cur.fetchone()
    return WebhookSubscription.from_row(row) if row else None


def by_idempotency_key(conn: Any, account_id: uuid.UUID | str,
                       key: str) -> Mapping[str, Any] | None:
    with dict_cursor(conn) as cur:
        cur.execute(
            """SELECT id, url, events, description, request_fingerprint
                 FROM webhook_subscriptions
                WHERE account_id = %s AND idempotency_key = %s""",
            (as_uuid(account_id), key))
        return cur.fetchone()


def create(conn: Any, *, account_id: uuid.UUID | str, url: Any, events: Any,
           description: Any = None, idempotency_key: Any = None,
           config: config_source.NotifyConfig | None = None,
           now: datetime | None = None) -> tuple[WebhookSubscription, str]:
    """注册订阅。返回 ``(订阅, secret)``——**secret 只在这一刻出现**（INV-05）。"""
    account = as_uuid(account_id)
    cfg = config or config_source.snapshot()
    moment = clock.to_utc(now) if now is not None else clock.now()
    host = validate_url(url)
    try:
        parsed_events = facts.validate_events(events)
    except ValueError as exc:
        raise errors.InvalidArgument(str(exc), field="events") from exc
    note = _describe(description)
    key = _idempotency_key(idempotency_key)
    fingerprint = _fingerprint(url.strip(), parsed_events, note)

    if key is not None:
        existing = by_idempotency_key(conn, account, key)
        if existing is not None:
            if existing["request_fingerprint"] == fingerprint:
                raise errors.IdempotencyConflict(
                    "同一幂等键的订阅已创建；签名密钥只在创建响应返回一次，"
                    "无法再次下发（INV-05）——如已丢失请删除后重建",
                    reason="idempotent_replay")
            raise errors.IdempotencyConflict("同一幂等键被用于不同载荷",
                                             reason="idempotency_key_reused")

    if count_for_account(conn, account) >= int(cfg.webhook_max_per_account):
        raise errors.WebhookLimitReached(
            f"订阅数已达上限 {cfg.webhook_max_per_account}（notify.webhook_max_per_account）")
    if find_by_url(conn, account, url.strip()) is not None:
        raise errors.DuplicateSubscription("该 URL 已有订阅（§3 UNIQUE(account_id, url)）")

    secret = signing.new_secret()
    subscription_id = uuid.uuid4()
    try:
        with dict_cursor(conn) as cur:
            cur.execute(
                """INSERT INTO webhook_subscriptions
                       (id, account_id, url, url_host, events, description, secret_hash,
                        secret_alg, status, paused_until, failure_count, idempotency_key,
                        request_fingerprint, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, 'sha256', 'active', NULL, 0, %s, %s,
                           %s, %s)
                   RETURNING id, account_id, url, events, status, created_at, updated_at,
                             description, secret_hash, paused_until, failure_count""",
                (subscription_id, account, url.strip(), host, list(parsed_events), note,
                 signing.hash_secret(secret), key, fingerprint if key else None,
                 moment, moment))
            row = cur.fetchone()
    except pg_errors.UniqueViolation as exc:
        constraint = getattr(getattr(exc, "diag", None), "constraint_name", "") or ""
        if "idem" in constraint:
            raise errors.IdempotencyConflict("同一幂等键的订阅已创建（并发提交）",
                                             reason="idempotent_replay") from exc
        raise errors.DuplicateSubscription("该 URL 已有订阅（并发提交）") from exc
    return WebhookSubscription.from_row(row), secret


def list_page(conn: Any, account_id: uuid.UUID | str, *, limit: Any = None,
              cursor: Any = None) -> dict[str, Any]:
    """订阅列表（不含密钥），按 ``created_at DESC, id DESC`` keyset 分页。"""
    from . import inbox                          # 复用同一游标实现（单一口径）

    account = as_uuid(account_id)
    page_limit = inbox._limit(limit)             # noqa: SLF001 - 同模块内的校验口径
    where = ["account_id = %s"]
    params: list[Any] = [account]
    if cursor not in (None, ""):
        last_created, last_id = inbox.decode_cursor(cursor)
        where.append("(created_at, id) < (%s, %s)")
        params.extend([last_created, last_id])
    params.append(page_limit + 1)
    with dict_cursor(conn) as cur:
        cur.execute(
            f"""SELECT id, account_id, url, events, status, created_at, updated_at, description,
                       secret_hash, paused_until, failure_count
                  FROM webhook_subscriptions
                 WHERE {' AND '.join(where)}
                 ORDER BY created_at DESC, id DESC
                 LIMIT %s""", params)
        rows = [WebhookSubscription.from_row(row) for row in cur.fetchall()]
    has_more = len(rows) > page_limit
    page_rows = rows[:page_limit]
    next_cursor = (inbox.encode_cursor(page_rows[-1].created_at, page_rows[-1].id)
                   if has_more and page_rows else None)
    return {
        "data": [row.to_api() for row in page_rows],
        "page": {"cursor": cursor if isinstance(cursor, str) else "",
                 "has_more": has_more, "next_cursor": next_cursor},
    }


def delete(conn: Any, account_id: uuid.UUID | str, subscription_id: uuid.UUID | str) -> bool:
    """取消订阅（幂等：不存在也当成功，路由统一 204）。"""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM webhook_subscriptions WHERE account_id = %s AND id = %s",
                    (as_uuid(account_id), as_uuid(subscription_id)))
        return cur.rowcount > 0


def register_failure(conn: Any, subscription_id: uuid.UUID | str, *,
                     permanent: bool, now: datetime) -> None:
    """记一次投递失败：永久失败（4xx 非 429）→ ``paused``；否则累加计数。"""
    with conn.cursor() as cur:
        if permanent:
            cur.execute(
                """UPDATE webhook_subscriptions
                      SET status = 'paused', failure_count = failure_count + 1, updated_at = %s
                    WHERE id = %s""", (now, as_uuid(subscription_id)))
        else:
            cur.execute(
                """UPDATE webhook_subscriptions
                      SET failure_count = failure_count + 1, updated_at = %s
                    WHERE id = %s""", (now, as_uuid(subscription_id)))


def active_for_event(conn: Any, account_id: uuid.UUID | str, event: str,
                     *, now: datetime) -> list[WebhookSubscription]:
    """派发前挑出「active 且事件在白名单里」的订阅（paused 到期自动视为可用）。"""
    with dict_cursor(conn) as cur:
        cur.execute(
            """SELECT id, account_id, url, events, status, created_at, updated_at, description,
                      secret_hash, paused_until, failure_count
                 FROM webhook_subscriptions
                WHERE account_id = %s
                  AND %s = ANY (events)
                  AND (status = 'active'
                       OR (status = 'paused' AND paused_until IS NOT NULL AND paused_until <= %s))
                ORDER BY created_at""",
            (as_uuid(account_id), event, now))
        return [WebhookSubscription.from_row(row) for row in cur.fetchall()]
