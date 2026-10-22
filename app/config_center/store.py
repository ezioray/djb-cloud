# SPDX-License-Identifier: Apache-2.0
"""版本存储 + digest + 幂等（T2）。

本层只回答「怎么把一次草稿变成一个不可变版本，并且能复算、能幂等重放」，不回答
「谁能发布、什么时候生效」（T3 的发布单九步）。四件事：

1. **注册表落库**：``sync_items`` 把 :mod:`app.config_center.registry` 的元数据 upsert 到
   ``config_items``（注册表是唯一来源，后台不直接改库，§21.11.4）；
2. **版本只追加**：``create_draft`` 写 ``config_versions``；version = max+1（不跳号不复用，
   INV-01），内容摘要 ``content_digest = sha256(canonical({key,value,schema_ref,unit}))`` 可复算；
3. **幂等**：``(scope, idempotency_key)`` 唯一；同键同载荷返回首次结果（``replayed=True``），
   同键不同载荷 409 + 40919。窗口 24h（§3）：超过窗口后复用同一键视为冲突，客户端须换键；
4. **原子切换的存储原语**：``activate`` 用单行 CAS 把 draft 置 active 并让旧 active 变 superseded
   （INV-08 的存储前提；发布单 / 复核 / 冷却在 T3）。

事务边界（§6）：调用方负责事务；本模块不 commit。并发下同 key 的版本分配用
``pg_advisory_xact_lock`` 串行化，唯一约束 ``(key,scope,scope_id,version)`` 兜底。
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Mapping

import psycopg
from psycopg.types.json import Jsonb

from . import canonical, validators
from .errors import IdempotencyConflict, ValidationFailed, VersionNotFound
from .registry import SCOPES, ConfigKey, Registry, load

__all__ = [
    "DEFAULT_SCOPE",
    "IDEMPOTENCY_TTL",
    "normalize_scope",
    "sync_item",
    "sync_items",
    "next_version",
    "create_draft",
    "activate",
    "get_version",
    "list_versions",
    "active_entries",
    "active_version",
    "find_idempotent",
    "digest_of",
    "verify_version",
    "recompute_digests",
]

DEFAULT_SCOPE = "global"
#: 写接口幂等键窗口（§3「写接口幂等键 24h」）
IDEMPOTENCY_TTL = timedelta(hours=24)
_SCOPE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


# ───────────────────────────────────────────────────────────── 连接辅助
def _rows(conn: psycopg.Connection, sql: str, params: Any = ()) -> list[dict[str, Any]]:
    """与 row_factory 无关的行读取（返回 dict 列表；``params`` 支持 tuple 与 dict 两种占位）。"""
    cur = conn.execute(sql, params)
    columns = [desc.name for desc in cur.description or ()]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def _one(conn: psycopg.Connection, sql: str, params: Any = ()) -> dict[str, Any] | None:
    rows = _rows(conn, sql, params)
    return rows[0] if rows else None


def normalize_scope(scope: str, scope_id: str = "") -> tuple[str, str]:
    """scope / scope_id 配对校验（M10 §5 枚举；global 不带 id，region/tenant 必带）。"""
    if scope not in SCOPES:
        raise ValidationFailed(f"scope 必须是 {SCOPES}：{scope!r}")
    if scope == "global":
        if scope_id not in ("", None):
            raise ValidationFailed("scope=global 时不允许带 scope_id")
        return scope, ""
    if not scope_id or not _SCOPE_ID.match(scope_id):
        raise ValidationFailed(f"scope={scope} 时 scope_id 必填（[A-Za-z0-9._:-]{{1,128}}）：{scope_id!r}")
    return scope, scope_id


def _require_text(value: Any, *, field: str, minimum: int = 1, maximum: int = 512) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ValidationFailed(f"{field} 必须是 {minimum}–{maximum} 字符的字符串：{value!r}")
    return value


# ───────────────────────────────────────────────────────────── 注册表 → config_items
_ITEM_UPSERT = """
INSERT INTO config_items
  (namespace, key, value_type, unit, schema_ref, schema_body, risk_level, owner_role,
   allow_scope, consumers, dangerous, sensitive, secret_ref_only,
   default_value, default_source, expire_required, state)
VALUES
  (%(namespace)s, %(key)s, %(value_type)s, %(unit)s, %(schema_ref)s, %(schema_body)s,
   %(risk_level)s, %(owner_role)s, %(allow_scope)s, %(consumers)s, %(dangerous)s,
   %(sensitive)s, %(secret_ref_only)s, %(default_value)s, %(default_source)s,
   %(expire_required)s, 'active')
ON CONFLICT (namespace, key) DO UPDATE SET
  value_type      = EXCLUDED.value_type,
  unit            = EXCLUDED.unit,
  schema_ref      = EXCLUDED.schema_ref,
  schema_body     = EXCLUDED.schema_body,
  risk_level      = EXCLUDED.risk_level,
  owner_role      = EXCLUDED.owner_role,
  allow_scope     = EXCLUDED.allow_scope,
  consumers       = EXCLUDED.consumers,
  dangerous       = EXCLUDED.dangerous,
  sensitive       = EXCLUDED.sensitive,
  secret_ref_only = EXCLUDED.secret_ref_only,
  default_value   = EXCLUDED.default_value,
  default_source  = EXCLUDED.default_source,
  expire_required = EXCLUDED.expire_required,
  updated_at      = now()
RETURNING (xmax = 0) AS inserted
"""


def sync_item(conn: psycopg.Connection, item: ConfigKey) -> bool:
    """upsert 一条键元数据；返回 True 表示新插入。"""
    meta = item.as_metadata()
    params = {
        **meta,
        "schema_body": Jsonb(meta["schema_body"]),
        "default_value": None if meta["default_value"] is None else Jsonb(meta["default_value"]),
        "allow_scope": list(meta["allow_scope"]),
        "consumers": list(meta["consumers"]),
    }
    row = _one(conn, _ITEM_UPSERT, params)
    return bool(row and row["inserted"])


def sync_items(conn: psycopg.Connection, *, registry: Registry | None = None) -> dict[str, int]:
    """把整个注册表落库（幂等）；返回 {"total", "inserted"}。"""
    reg = registry or load()
    inserted = sum(1 for item in reg.keys if sync_item(conn, item))
    return {"total": len(reg.keys), "inserted": inserted}


# ───────────────────────────────────────────────────────────── 版本分配 / 读取
def _lock_key(conn: psycopg.Connection, key: str, scope: str, scope_id: str) -> None:
    """同 key 的版本分配串行化（事务级 advisory lock；不阻塞其它 key）。"""
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                 (f"m10:{key}|{scope}|{scope_id}",))


def next_version(conn: psycopg.Connection, *, key: str, scope: str = DEFAULT_SCOPE,
                 scope_id: str = "") -> int:
    """下一个版本号 = 当前最大值 + 1（INV-01）；调用方需在事务内（advisory lock 生效）。"""
    row = _one(conn, """SELECT COALESCE(max(version), 0) AS max_version FROM config_versions
                         WHERE key = %s AND scope = %s AND scope_id = %s""",
               (key, scope, scope_id))
    return int(row["max_version"]) + 1


def find_idempotent(conn: psycopg.Connection, *, scope: str,
                    idempotency_key: str) -> dict[str, Any] | None:
    """按幂等键查已落版本（§5 uq_idem(scope, idempotency_key)）。"""
    return _one(conn, """SELECT * FROM config_versions
                          WHERE scope = %s AND idempotency_key = %s""",
                (scope, idempotency_key))


def get_version(conn: psycopg.Connection, *, key: str, version: int | None = None,
                scope: str = DEFAULT_SCOPE, scope_id: str = "") -> dict[str, Any] | None:
    """读单键版本：``version=None`` 取该 key/scope 的最大版本。"""
    scope, scope_id = normalize_scope(scope, scope_id)
    if version is None:
        return _one(conn, """SELECT * FROM config_versions
                             WHERE key = %s AND scope = %s AND scope_id = %s
                             ORDER BY version DESC LIMIT 1""", (key, scope, scope_id))
    return _one(conn, """SELECT * FROM config_versions
                          WHERE key = %s AND scope = %s AND scope_id = %s AND version = %s""",
                (key, scope, scope_id, version))


def list_versions(conn: psycopg.Connection, *, key: str, scope: str = DEFAULT_SCOPE,
                  scope_id: str = "") -> list[dict[str, Any]]:
    scope, scope_id = normalize_scope(scope, scope_id)
    return _rows(conn, """SELECT * FROM config_versions
                           WHERE key = %s AND scope = %s AND scope_id = %s
                           ORDER BY version""", (key, scope, scope_id))


def active_entries(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """全部 active 版本（INV-08 快照 entries 的来源；policy_version = snapshot_digest[:12]）。"""
    return _rows(conn, """SELECT key, scope, scope_id, version, content_digest
                            FROM config_versions WHERE status = 'active'
                           ORDER BY key, scope, scope_id""")


def active_version(conn: psycopg.Connection, *, key: str, scope: str = DEFAULT_SCOPE,
                   scope_id: str = "") -> dict[str, Any] | None:
    scope, scope_id = normalize_scope(scope, scope_id)
    return _one(conn, """SELECT * FROM config_versions
                          WHERE key = %s AND scope = %s AND scope_id = %s AND status = 'active'""",
                (key, scope, scope_id))


# ───────────────────────────────────────────────────────────── 建草稿（写入 + 幂等）
def create_draft(
    conn: psycopg.Connection,
    *,
    key: str,
    scope: str = DEFAULT_SCOPE,
    scope_id: str = "",
    value: Any = None,
    secret_ref: Mapping[str, Any] | None = None,
    value_type: str | None = None,
    reason: str,
    actor: str,
    effective_at: Any = None,
    ticket: str | None = None,
    idempotency_key: str | None = None,
    expire_at: Any = None,
    now: datetime | None = None,
    registry: Registry | None = None,
) -> dict[str, Any]:
    """建一个不可变草稿版本（不生效；生效走 T3 的发布单）。

    · 危险键 / 生成键 → 47004；未知键 / 类型 / 单位 / 范围 / 跨字段 → 47001；
    · ``secret_ref_only`` 的键只接受 ``secret_ref``（``value`` 必须为空），其余键只接受 ``value``；
    · ``idempotency_key`` 命中同载荷 → 返回首次结果（``replayed=True``）；不同载荷 → 409/40919。
    """
    reg = registry or load()
    item = validators.check_writable(key, registry=reg)
    scope, scope_id = normalize_scope(scope, scope_id)
    reason = _require_text(reason, field="reason", minimum=4, maximum=512)
    actor = _require_text(actor, field="actor", minimum=1, maximum=128)
    if idempotency_key is not None:
        _require_text(idempotency_key, field="idempotency_key", minimum=8, maximum=128)
    if value_type is not None and value_type != item.value_type:
        raise ValidationFailed(
            f"{key} 的 value_type 必须是 {item.value_type}（收到 {value_type}）", key=key)

    # 敏感键：只接 secret_ref；普通键：只接 value（None 视为缺值，不当作合法配置值）
    if item.secret_ref_only:
        if value is not None:
            raise ValidationFailed(f"{key} 是 secret-ref 键，不接受明文 value（INV-05）", key=key)
        if secret_ref is None:
            raise ValidationFailed(f"{key} 必须提供 secret_ref（INV-05）", key=key)
        payload = secret_ref
    else:
        if value is None:
            raise ValidationFailed(f"{key} 缺少 value（配置版本必须携带内容）", key=key)
        if secret_ref is not None:
            raise ValidationFailed(f"{key} 不是 secret-ref 键，不接受 secret_ref", key=key)
        payload = value

    result = validators.validate_value(
        key, payload, registry=reg,
        current=None,                       # 草稿不与生效值比较（幅度/收紧在发布前第②道做）
        expire_at=expire_at, now=now,
    )
    normalized = result.value

    request_digest = canonical.request_digest(
        key=key, scope=scope, scope_id=scope_id, value=normalized)
    content_digest = canonical.version_digest(
        key=key, value=normalized, schema_ref=item.schema_ref, unit=item.unit)

    # 幂等：先查再写；并发由 uq_idem 兜底（23505 → 重新读取比对）
    if idempotency_key is not None:
        existing = find_idempotent(conn, scope=scope, idempotency_key=idempotency_key)
        if existing is not None:
            return _replay(existing, request_digest)

    sync_item(conn, item)                    # 注册表是唯一来源：保证 FK 一定能落
    _lock_key(conn, key, scope, scope_id)
    version = next_version(conn, key=key, scope=scope, scope_id=scope_id)

    effective = validators.as_utc(effective_at, field=f"{key}.effective_at") if effective_at else None
    sql = """
        INSERT INTO config_versions
          (namespace, key, scope, scope_id, version, value_type, unit, schema_ref,
           value, secret_ref, content_digest, request_digest, status, effective_at,
           rollback_to, reason, ticket, idempotency_key, created_by)
        VALUES
          (%(namespace)s, %(key)s, %(scope)s, %(scope_id)s, %(version)s, %(value_type)s, %(unit)s,
           %(schema_ref)s, %(value)s, %(secret_ref)s, %(content_digest)s, %(request_digest)s,
           'draft', %(effective_at)s, 0, %(reason)s, %(ticket)s, %(idempotency_key)s, %(actor)s)
        RETURNING *
    """
    params = {
        "namespace": item.namespace,
        "key": key,
        "scope": scope,
        "scope_id": scope_id,
        "version": version,
        "value_type": item.value_type,
        "unit": item.unit,
        "schema_ref": item.schema_ref,
        "value": None if item.secret_ref_only else Jsonb(normalized),
        "secret_ref": Jsonb(normalized) if item.secret_ref_only else None,
        "content_digest": content_digest,
        "request_digest": request_digest,
        "effective_at": effective,
        "reason": reason,
        "ticket": ticket,
        "idempotency_key": idempotency_key,
        "actor": actor,
    }
    try:
        # SAVEPOINT：并发下同幂等键撞唯一约束时只回滚这条 INSERT，外层事务仍可用，
        # 才能回到「同键」判定（同载荷重放 / 不同载荷 409）；否则事务已 aborted，查不了。
        with conn.transaction():
            row = _one(conn, sql, params)
    except psycopg.errors.UniqueViolation:
        # 并发下同幂等键被别的连接先落：回到「同键」判定（同载荷重放 / 不同载荷 409）
        if idempotency_key is None:
            raise
        existing = find_idempotent(conn, scope=scope, idempotency_key=idempotency_key)
        if existing is None:
            raise
        return _replay(existing, request_digest)
    assert row is not None
    row["replayed"] = False
    return row


def _replay(existing: Mapping[str, Any], request_digest: str) -> dict[str, Any]:
    """同幂等键：同载荷 → 首次结果；不同载荷 → 409 / 40919。"""
    if existing["request_digest"] != request_digest:
        raise IdempotencyConflict(
            f"幂等键 {existing['idempotency_key']!r} 已用于不同载荷"
            f"（首次 {existing['key']} v{existing['version']}）",
            key=existing["key"])
    row = dict(existing)
    row["replayed"] = True
    return row


# ───────────────────────────────────────────────────────────── 原子切换（T3 调用）
def activate(
    conn: psycopg.Connection,
    *,
    key: str,
    version: int,
    published_by: str,
    approved_by: str | None = None,
    effective_at: Any = None,
    scope: str = DEFAULT_SCOPE,
    scope_id: str = "",
) -> dict[str, Any]:
    """把 draft 版本置为 active，并把同 key/scope 的旧 active 置 superseded。

    · 单行 CAS：``UPDATE ... WHERE status='draft'``，0 行即目标状态不对（409 语义由 T3 映射）；
    · INV-03 由库触发器兜底（P0/P1 的 approved_by 必填且 ≠ published_by）；
    · INV-08 的「同 key 只一个 active」由部分唯一索引 + 先 supersede 后 activate 保证。
    """
    scope, scope_id = normalize_scope(scope, scope_id)
    published_by = _require_text(published_by, field="published_by", minimum=1, maximum=128)
    if approved_by is not None:
        approved_by = _require_text(approved_by, field="approved_by", minimum=1, maximum=128)
    effective = validators.as_utc(effective_at, field=f"{key}.effective_at") if effective_at else None

    # 先验目标再改旧行：目标不是 draft 就直接 47006，不留「旧的已 superseded、新的没 active」的中间态
    _lock_key(conn, key, scope, scope_id)
    target = _one(conn, """SELECT status FROM config_versions
                            WHERE key = %s AND scope = %s AND scope_id = %s AND version = %s""",
                  (key, scope, scope_id, version))
    if target is None or target["status"] != "draft":
        raise VersionNotFound(
            f"{key} v{version} 不存在或不是 draft（不能从当前状态切换为 active）", key=key)

    superseded = conn.execute(
        """UPDATE config_versions SET status = 'superseded', updated_at = now()
            WHERE key = %s AND scope = %s AND scope_id = %s AND status = 'active'""",
        (key, scope, scope_id)).rowcount
    row = _one(conn,
               """UPDATE config_versions
                     SET status = 'active',
                         published_by = %s,
                         approved_by = %s,
                         effective_at = %s,
                         updated_at = now()
                   WHERE key = %s AND scope = %s AND scope_id = %s AND version = %s
                     AND status = 'draft'
               RETURNING *""",
               (published_by, approved_by, effective, key, scope, scope_id, version))
    if row is None:
        raise VersionNotFound(
            f"{key} v{version} 不存在或不是 draft（不能从当前状态切换为 active）", key=key)
    row["superseded"] = superseded
    return row


# ───────────────────────────────────────────────────────────── digest 复算
def digest_of(row: Mapping[str, Any]) -> str:
    """按库内行复算 content_digest（INV-01）。secret-ref 键的「值」就是引用结构本身。"""
    value = row["value"] if row.get("value") is not None else row.get("secret_ref")
    return canonical.version_digest(
        key=row["key"], value=value, schema_ref=row["schema_ref"], unit=row["unit"])


def verify_version(row: Mapping[str, Any]) -> bool:
    """单版本 digest 是否可复算（True = 一致）。"""
    return digest_of(row) == row["content_digest"]


def recompute_digests(conn: psycopg.Connection) -> dict[str, Any]:
    """全量复算（``djb-config verify`` 的存储层；T5 的只读 CLI 复用本函数）。"""
    rows = _rows(conn, """SELECT version_id, key, scope, scope_id, version, unit, schema_ref,
                                 value, secret_ref, content_digest
                            FROM config_versions
                           ORDER BY key, scope, scope_id, version""")
    bad: list[dict[str, Any]] = []
    for row in rows:
        expected = digest_of(row)
        if expected != row["content_digest"]:
            bad.append({
                "key": row["key"], "scope": row["scope"], "scope_id": row["scope_id"],
                "version": row["version"], "stored": row["content_digest"],
                "recomputed": expected,
            })
    return {"total": len(rows), "ok": len(rows) - len(bad), "bad": bad, "diff": len(bad)}


