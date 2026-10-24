# SPDX-License-Identifier: AGPL-3.0-or-later
"""API Key 生命周期与网关鉴权（DEV-M01-T3）。

职责边界：
- **生命周期**：创建 / 列举（游标分页）/ 撤销（幂等）/ 轮换（可选重叠期），
  一律经 :mod:`app.identity.models` 的唯一写入函数，明文只在返回值里出现一次。
- **网关鉴权**：:func:`verify_api_key` 是给 M03（以及 M02 的新注册路径）用的**唯一入口**，
  返回 :class:`app.identity.tokens.AuthContext`；M01 不实现网关，也不接 ``app/api.py``。

Key 口径（spec 1.2.1 + M01 §3 / §8）：

| 字段 | 语义 |
| --- | --- |
| `key_hash` | ``sha256(明文)``；明文不入库、不入日志、不可回读 |
| `key_prefix` | 前 8 位，仅展示 / 排障（spec 的 `prefix`） |
| `label` | spec 的 `name`（同义列禁止新建，01-ownership §7.4） |
| `revoked_at` | **失效时刻**：撤销 = now；轮换带重叠 = now + overlap（重叠期只验签） |
| `expires_at` | Key 级过期（106 新增）；到点即失效，与账户无关 |
| `scopes` | 可选字符串数组（106 新增）；NULL = 未声明 |

INV-10（轮换重叠）：重叠 ≤24 h；重叠期内旧钥**只验签**（``allow_overlap=True``），
新注册类动作必须 ``allow_overlap=False`` → 409 / 40902。
"""
from __future__ import annotations

import base64
import binascii
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Sequence

from . import clock, errors, models, tokens

KEY_NAME_MAX = 64
PAGE_DEFAULT = 50
PAGE_MAX = 200


@dataclass(frozen=True)
class KeyPage:
    items: list[models.ApiKey]
    cursor: str | None
    has_more: bool
    next_cursor: str | None


# --------------------------------------------------------------------------- 入参校验
def _check_name(name: str | None) -> str | None:
    if name is None:
        return None
    if not isinstance(name, str) or not name.strip():
        raise models.InvalidArgument("name 必填且不能为空", field="name")
    if len(name) > KEY_NAME_MAX:
        raise models.InvalidArgument(f"name 最长 {KEY_NAME_MAX}", field="name")
    return name.strip()


def _check_limit(limit: int | None) -> int:
    if limit is None:
        return PAGE_DEFAULT
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= PAGE_MAX:
        raise models.InvalidArgument(f"limit 必须在 1..{PAGE_MAX}", field="limit")
    return limit


def encode_cursor(key_id: int) -> str:
    """游标 = base64(``k:<id>``)：不透明但可校验（不暴露明文、不允许猜 id 顺序）。"""
    return base64.urlsafe_b64encode(f"k:{key_id}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int | None:
    if cursor is None or cursor == "":
        return None
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        prefix, sep, value = raw.partition(":")
        key_id = int(value)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise models.InvalidArgument("cursor 非法", field="cursor") from exc
    if prefix != "k" or sep != ":" or key_id <= 0:
        raise models.InvalidArgument("cursor 非法", field="cursor")
    return key_id


# --------------------------------------------------------------------------- 生命周期
def create(c, *, account_id: uuid.UUID, name: str, scopes: Sequence[str] | None = None,
           expires_at: datetime | None = None, qps: int | None = None,
           tenant_id: uuid.UUID | None = None, now: datetime | None = None,
           trace_id: str | None = None) -> tuple[models.ApiKey, str]:
    """建 Key（明文只在此返回一次）。读只态账户 → 403 40304；超过 10 枚 → 429 42901。"""
    moment = now or clock.utcnow()
    label = _check_name(name)
    if not label:
        raise models.InvalidArgument("name 必填", field="name")
    try:
        return models.create_api_key(
            c, account_id=account_id, tenant_id=tenant_id, label=label, qps=qps,
            scopes=scopes, expires_at=expires_at, now=moment, trace_id=trace_id)
    except models.KeyLimitReached as exc:
        # spec 的 POST /api-keys 只声明 201/400/401/403/429；配额类上限按 429 表达
        raise errors.QuotaExhausted("Key 数已达上限", reason="key_limit_reached",
                                    limit=models.KEY_MAX_PER_ACCOUNT) from exc


def list_page(c, *, account_id: uuid.UUID, tenant_id: uuid.UUID | None = None,
              include_revoked: bool = False, cursor: str | None = None,
              limit: int | None = None, now: datetime | None = None) -> KeyPage:
    """游标分页（id DESC）：「只回 8 位前缀与元数据，永不回明文 / 哈希」——见 spec listApiKeys。"""
    moment = now or clock.utcnow()
    size = _check_limit(limit)
    after = decode_cursor(cursor)
    sql = (f"SELECT {models._KEY_COLS} FROM api_keys WHERE account_id = %s")
    params: list[Any] = [account_id]
    if tenant_id is not None:
        sql += " AND tenant_id = %s"
        params.append(tenant_id)
    if not include_revoked:
        sql += (" AND (revoked_at IS NULL OR revoked_at > %s)"
                " AND (expires_at IS NULL OR expires_at > %s)")
        params.extend([moment, moment])
    if after is not None:
        sql += " AND id < %s"
        params.append(after)
    sql += " ORDER BY id DESC LIMIT %s"
    params.append(size + 1)                       # 多取一条判断 has_more
    with c.cursor() as cur:
        cur.execute(sql, params)
        rows = models._rows(cur)
    items = [models._make(models.ApiKey, row) for row in rows[:size]]
    has_more = len(rows) > size
    next_cursor = encode_cursor(items[-1].id) if (has_more and items) else None
    return KeyPage(items=items, cursor=cursor or None, has_more=has_more,
                   next_cursor=next_cursor)


def revoke(c, *, key_id: int, account_id: uuid.UUID, tenant_id: uuid.UUID | None = None,
           reason: str = "user_revoked", now: datetime | None = None,
           trace_id: str | None = None) -> tuple[models.ApiKey, bool]:
    """撤销（幂等）：跨租户 / 不存在 → 404；已安排失效 → 原样返回（changed=False）。

    撤销是**安全动作**，不因账户 frozen / closing 而被拦（只读账户也必须能杀自己的 Key）。
    """
    moment = now or clock.utcnow()
    key = _owned_key(c, key_id, account_id=account_id, tenant_id=tenant_id)
    if key.revoked_at is not None:
        return key, False
    revoked = models.revoke_api_key(c, key.id, reason=reason, now=moment,
                                    trace_id=trace_id)
    return revoked, True


def rotate(c, *, key_id: int, account_id: uuid.UUID, tenant_id: uuid.UUID | None = None,
           name: str | None = None, overlap_seconds: int = 0,
           scopes: Sequence[str] | None = None, expires_at: datetime | None = None,
           now: datetime | None = None, trace_id: str | None = None) -> tuple[models.ApiKey, str]:
    """轮换：新钥 + 旧钥按 ``overlap_seconds`` 失效（0 = 立即；≤86400）。"""
    moment = now or clock.utcnow()
    key = _owned_key(c, key_id, account_id=account_id, tenant_id=tenant_id)
    label = _check_name(name)
    return models.rotate_api_key(c, key.id, overlap_seconds=overlap_seconds,
                                 name=label, scopes=scopes, expires_at=expires_at,
                                 now=moment, trace_id=trace_id)


def _owned_key(c, key_id: int, *, account_id: uuid.UUID,
               tenant_id: uuid.UUID | None) -> models.ApiKey:
    """按账户作用域取 Key：非本账户 / 跨租户一律 404（不泄露存在性，A6）。"""
    try:
        key = models.get_api_key(c, key_id)
    except models.NotFound:
        raise models.NotFound("Key 不存在", api_key_id=key_id)
    if key.account_id != account_id or (tenant_id is not None and key.tenant_id != tenant_id):
        raise models.NotFound("Key 不存在", api_key_id=key_id)
    return key


# --------------------------------------------------------------------------- 网关鉴权
def verify_api_key(c, raw: str, *, now: datetime | None = None, allow_overlap: bool = True,
                   require_writable: bool = False, require_quota: bool = True,
                   touch: bool = True, trace_id: str | None = None) -> tokens.AuthContext:
    """**网关鉴权唯一入口**（M03 / M02 复用）：Key 明文 → :class:`AuthContext`。

    校验顺序（任一不过即抛错，全部映射到已登记错误码）：
    1. 哈希命中（``sha256``）→ 401 / 40101；
    2. 失效时刻与 Key 级过期 → 401 / 40101；
    3. 轮换重叠期：``allow_overlap=False`` 时 → 409 / 40902（INV-10：重叠期只验签）；
    4. 账户存在且未注销 → 409 / 40903；``require_writable`` 时 frozen / closing → 403 / 40304；
    5. 配额快照（INV-07）：``require_quota=True`` 且租户无快照 → 409 / 40907。

    返回的 ``AuthContext`` 带 ``api_key_id`` / ``api_key_prefix`` / ``key_overlap`` /
    ``quotas``（= ``quota_snapshot`` 的 effective 与 policy_version），供计费侧写 policy_version。
    """
    moment = now or clock.utcnow()
    key = models.lookup_api_key(c, raw, now=moment)
    overlapping = key.overlapping_at(moment)
    if overlapping and not allow_overlap:
        raise errors.KeyOverlapForbidden(
            "旧 Key 处于轮换重叠期：只允许验签，不接受新注册",
            api_key_id=key.id,
            effective_at=key.revoked_at.isoformat() if key.revoked_at else None)
    if key.account_id is None or key.tenant_id is None:
        raise models.ApiKeyInvalid("Key 未绑定账户")
    account = models.get_account(c, key.account_id, tenant_id=key.tenant_id)
    if account.is_closed:
        raise models.AccountClosed("账户已注销", account_id=str(account.id))
    if require_writable:
        models.assert_writable(account, action="调用计费接口")
    quota: dict[str, Any] | None = None
    if require_quota:
        quota = models.quota_snapshot(c, account.tenant_id, key_id=key.id)
    user = models.get_user(c, account.user_id)
    if touch:
        _touch_usage(c, key.id, moment)
    return tokens.AuthContext(
        session=None,
        account=account,
        user=user,
        roles=tuple(models.effective_roles(c, account.id, now=moment)),
        api_key_id=key.id,
        api_key_prefix=key.key_prefix,
        key_overlap=overlapping,
        quotas=quota,
    )


def _touch_usage(c, key_id: int, moment: datetime) -> None:
    with c.cursor() as cur:
        cur.execute("UPDATE api_keys SET last_used_at = %s WHERE id = %s", (moment, key_id))


__all__ = ["KEY_NAME_MAX", "PAGE_DEFAULT", "PAGE_MAX", "KeyPage", "encode_cursor",
           "decode_cursor", "create", "list_page", "revoke", "rotate", "verify_api_key"]
