# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 持久化 + 版本编排（psycopg3，无 ORM，全部参数化 SQL）。

边界：

* 只读写本模块四张表（``vendor_models`` / ``model_sync_bundles`` / ``model_sync_events`` /
  ``node_model_sync_state``）；**不 import 账本、不写 ledger_***（M18 §3「不触账」）；
* 事务边界在 router（``app.db.conn`` 成功提交、异常回滚）：本层只执行语句，不 commit；
* **版本只增**：``version = max(version) + 1``，取号前拿 ``pg_advisory_xact_lock(1800, 1)``
  串行化（并发 create/publish/rollback 不会撞号；DB 侧 ``UNIQUE`` 兜底）；
* **历史不改**：bundle 行只允许 draft → published 一次、published → rolled_back；payload /
  payload_hash / version 由触发器守住不可改；回滚**新建一条**副本，不重写历史（§4）；
* **不存正文**：只有元数据 / 指纹；``node_model_sync_state`` 只存版本号、漂移摘要、错误类。

「当前版本」= ``state='published'`` 中 ``version`` 最大的一条（回滚会新建更高版本并指针化）：
不回退版本号，避免客户端「版本递减 = 认为服务端回滚」的歧义。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import facts, registry, signing

__all__ = [
    "seed_builtin", "list_vendor_models", "create_draft", "publish", "rollback",
    "current_bundle", "get_bundle", "get_bundle_by_version", "list_bundles", "latest_version",
    "record_state", "get_node_state", "list_node_states", "list_events",
    "VERSION_LOCK_KEY",
]

#: 版本取号的咨询锁（事务级；两个 int 形式，避免字符串哈希跨库漂移）
VERSION_LOCK_KEY: tuple[int, int] = (facts.MODULE_RANGE[0], 1)

_BUNDLE_COLUMNS = ("id, version, payload, payload_hash, signature, source, published_at, "
                   "expires_at, state, created_at")
_STATE_COLUMNS = "node_id, applied_version, applied_at, drift, last_error, updated_at"


def _one(cur) -> dict[str, Any] | None:
    row = cur.fetchone()
    return None if row is None else dict(row)


def _rows(cur) -> list[dict[str, Any]]:
    return [dict(row) for row in cur.fetchall()]


def _iso(moment: Any) -> str | None:
    from .clock import iso

    return iso(moment)


def _model_entry(row: Mapping[str, Any]) -> dict[str, Any]:
    """DB 行 → registry 口径（``effective_at`` 统一 ISO-Z 毫秒，payload 可复算）。"""
    return {
        "vendor": row["vendor"],
        "canonical": row["canonical"],
        "aliases": list(row.get("aliases") or []),
        "context_window": int(row["context_window"]),
        "tokenizer_family": row["tokenizer_family"],
        "tokenizer_version": row["tokenizer_version"],
        "tokenizer_hash": row["tokenizer_hash"],
        "effective_at": _iso(row["effective_at"]),
        "source": row["source"],
        "state": row["state"],
    }


def _event(conn: Any, *, bundle_id: uuid.UUID | None, version: int | None, event: str,
           detail: Mapping[str, Any], actor: str, now: datetime) -> None:
    if event not in facts.EVENTS:
        raise ValueError(f"未登记的事件：{event!r}")
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO model_sync_events (id, bundle_id, version, event, detail, actor,
                                               created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (uuid.uuid4(), bundle_id, version, event, Jsonb(dict(detail)), actor, now))


# ───────────────────────────────────────────────────────── 注册表（vendor_models）
def seed_builtin(conn: Any, *, now: datetime) -> int:
    """把内置注册表灌进 ``vendor_models``（幂等：同 ``(vendor, canonical, effective_at)`` 跳过）。"""
    inserted = 0
    with conn.cursor() as cur:
        for entry in registry.BUILTIN_MODELS:
            cur.execute(
                """INSERT INTO vendor_models
                       (id, vendor, canonical, aliases, context_window, tokenizer_family,
                        tokenizer_version, tokenizer_hash, effective_at, source, state,
                        created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (vendor, canonical, effective_at) DO NOTHING""",
                (uuid.uuid4(), entry["vendor"], entry["canonical"], list(entry["aliases"]),
                 entry["context_window"], entry["tokenizer_family"],
                 entry["tokenizer_version"], entry["tokenizer_hash"], entry["effective_at"],
                 entry["source"], entry["state"], now, now))
            inserted += cur.rowcount or 0
    return inserted


def list_vendor_models(conn: Any, *, active_only: bool = True) -> list[dict[str, Any]]:
    sql = ("SELECT vendor, canonical, aliases, context_window, tokenizer_family, "
           "tokenizer_version, tokenizer_hash, effective_at, source, state FROM vendor_models")
    params: tuple[Any, ...] = ()
    if active_only:
        sql += " WHERE state = 'active'"
    sql += " ORDER BY vendor, canonical, effective_at"
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        return [_model_entry(row) for row in _rows(cur)]


# ───────────────────────────────────────────────────────── bundle 版本编排
def _next_version(conn: Any) -> int:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s, %s)",
                    (VERSION_LOCK_KEY[0], VERSION_LOCK_KEY[1]))
        cur.execute("SELECT COALESCE(MAX(version), 0) AS max_version FROM model_sync_bundles")
        row = _one(cur)
    return int(row["max_version"]) + 1


def create_draft(conn: Any, *, actor: str, now: datetime,
                 source: str = "registry") -> dict[str, Any]:
    """从注册表生成 draft（版本 = max+1；同内容也会产生新版本，保证可审计的时间线）。

    **TTL 在起草时定死**：``payload = {version, expires_at, models}`` 且 ``expires_at``
    参与 ``payload_hash``（M18b 客户端同口径）——所以起草即写入 ``expires_at = now + TTL``，
    发布只加签名与 ``published_at``，不再改 payload（否则 hash 与客户端复算不一致）。
    """
    from .clock import iso

    if source not in facts.BUNDLE_SOURCES:
        raise ValueError(f"未登记的 bundle source：{source!r}")
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM vendor_models")
        if int(_one(cur)["n"]) == 0:
            seed_builtin(conn, now=now)
    models = list_vendor_models(conn)
    version = _next_version(conn)
    expires_at = now + facts.TTL
    payload = registry.build_payload(models, version=version, expires_at=iso(expires_at))
    digest = registry.payload_hash_of(payload)
    identifier = uuid.uuid4()
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """INSERT INTO model_sync_bundles
                   (id, version, payload, payload_hash, signature, source, published_at,
                    expires_at, state, created_at)
               VALUES (%s, %s, %s, %s, NULL, %s, NULL, %s, 'draft', %s)
               RETURNING """ + _BUNDLE_COLUMNS,
            (identifier, version, Jsonb(payload), digest, source, expires_at, now))
        bundle = _one(cur)
    _event(conn, bundle_id=identifier, version=version, event="draft", now=now, actor=actor,
           detail={"payload_hash": digest, "models_count": len(payload["models"]),
                   "source": source})
    return bundle


def get_bundle(conn: Any, bundle_id: uuid.UUID, *, for_update: bool = False
               ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {_BUNDLE_COLUMNS} FROM model_sync_bundles WHERE id = %s{suffix}",
                    (bundle_id,))
        return _one(cur)


def get_bundle_by_version(conn: Any, version: int, *, for_update: bool = False
                          ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if for_update else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {_BUNDLE_COLUMNS} FROM model_sync_bundles"
                    f" WHERE version = %s{suffix}", (int(version),))
        return _one(cur)


def publish(conn: Any, bundle_id: uuid.UUID, *, actor: str, now: datetime) -> dict[str, Any]:
    """draft → published（签名 + TTL）。签名密钥缺失 → 503/50001（fail-closed）。"""
    bundle = get_bundle(conn, bundle_id, for_update=True)
    if bundle is None:
        from .errors import NotFound

        raise NotFound("bundle 不存在", reason="not_found", bundle_id=str(bundle_id))
    if bundle["state"] != "draft":
        from .errors import Conflict

        raise Conflict(f"只有 draft 可以发布（当前 {bundle['state']}）", reason="state_invalid",
                       state=bundle["state"])
    expires_at = bundle.get("expires_at")
    if expires_at is None or expires_at <= now:
        from .errors import Conflict

        raise Conflict("draft 的 TTL 已过期：请重新生成（expires_at 参与 payload_hash，"
                       "不能就地延期）", reason="state_invalid")
    signature = signing.sign(bundle["payload_hash"])          # 缺密钥 → FeatureUnavailable
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """UPDATE model_sync_bundles
                  SET state = 'published', signature = %s, published_at = %s
                WHERE id = %s AND state = 'draft'
                RETURNING """ + _BUNDLE_COLUMNS,
            (signature, now, bundle_id))
        published = _one(cur)
    if published is None:                                    # pragma: no cover - 并发兜底
        from .errors import Conflict

        raise Conflict("bundle 状态已被并发修改", reason="state_invalid")
    _event(conn, bundle_id=bundle_id, version=int(published["version"]), event="published",
           now=now, actor=actor,
           detail={"payload_hash": published["payload_hash"], "expires_at": _iso(expires_at)})
    return published


def current_bundle(conn: Any) -> dict[str, Any] | None:
    """当前生效版本 = published 中 version 最大的一条（不回退版本号）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {_BUNDLE_COLUMNS} FROM model_sync_bundles"
                    f" WHERE state = 'published' ORDER BY version DESC LIMIT 1")
        return _one(cur)


def latest_version(conn: Any) -> int:
    bundle = current_bundle(conn)
    return int(bundle["version"]) if bundle else 0


def rollback(conn: Any, bundle_id: uuid.UUID, *, actor: str, now: datetime
             ) -> dict[str, Any]:
    """回滚 = **新建一条**指向目标 payload 的更高版本，不重写历史（§4）。

    * 目标必须是曾经发布过的 bundle（有 payload_hash / signature）；
    * 目标若已是当前版本 → 409（无意义回滚，避免无限加版本）；
    * 当前 published 置 ``rolled_back``（只改 state，不改 payload），并写事件。
    """
    from .errors import Conflict, NotFound

    target = get_bundle(conn, bundle_id, for_update=True)
    if target is None:
        raise NotFound("bundle 不存在", reason="not_found", bundle_id=str(bundle_id))
    if not target.get("signature") or target["state"] not in ("published", "rolled_back"):
        raise Conflict("只能回滚已发布过的 bundle", reason="state_invalid",
                       state=target["state"])
    current = current_bundle(conn)
    if current is not None and uuid.UUID(str(current["id"])) == uuid.UUID(str(bundle_id)):
        raise Conflict("目标已经是当前版本", reason="state_invalid",
                       version=int(current["version"]))

    from .clock import iso

    target_models = list((target.get("payload") or {}).get("models") or [])
    version = _next_version(conn)
    expires_at = now + facts.TTL
    payload = registry.build_payload(target_models, version=version,
                                     expires_at=iso(expires_at))
    payload_hash = registry.payload_hash_of(payload)
    signature = signing.sign(payload_hash)
    identifier = uuid.uuid4()
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """INSERT INTO model_sync_bundles
                   (id, version, payload, payload_hash, signature, source, published_at,
                    expires_at, state, created_at)
               VALUES (%s, %s, %s, %s, %s, 'rollback', %s, %s, 'published', %s)
               RETURNING """ + _BUNDLE_COLUMNS,
            (identifier, version, Jsonb(payload), payload_hash, signature, now, expires_at,
             now))
        created = _one(cur)
    if current is not None:
        with conn.cursor() as cur:
            cur.execute("UPDATE model_sync_bundles SET state = 'rolled_back'"
                        " WHERE id = %s AND state = 'published'", (current["id"],))
    _event(conn, bundle_id=identifier, version=version, event="rolled_back", now=now,
           actor=actor,
           detail={"target_version": int(target["version"]),
                   "replaced_version": int(current["version"]) if current else None,
                   "payload_hash": payload_hash})
    _event(conn, bundle_id=identifier, version=version, event="published", now=now,
           actor=actor,
           detail={"payload_hash": payload_hash, "expires_at": _iso(expires_at),
                   "source": "rollback"})
    return created


def list_bundles(conn: Any, *, state: str | None = None,
                 limit: int = facts.DEFAULT_LIST_LIMIT) -> list[dict[str, Any]]:
    sql = f"SELECT {_BUNDLE_COLUMNS} FROM model_sync_bundles"
    params: list[Any] = []
    if state:
        sql += " WHERE state = %s"
        params.append(state)
    sql += " ORDER BY version DESC LIMIT %s"
    params.append(int(limit))
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, tuple(params))
        return _rows(cur)


def list_events(conn: Any, *, bundle_id: uuid.UUID | None = None,
                limit: int = facts.DEFAULT_LIST_LIMIT) -> list[dict[str, Any]]:
    sql = ("SELECT id, bundle_id, version, event, detail, actor, created_at "
           "FROM model_sync_events")
    params: list[Any] = []
    if bundle_id is not None:
        sql += " WHERE bundle_id = %s"
        params.append(bundle_id)
    sql += " ORDER BY created_at DESC, seq DESC LIMIT %s"
    params.append(int(limit))
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, tuple(params))
        return _rows(cur)


# ───────────────────────────────────────────────────────── 节点应用状态
def record_state(conn: Any, *, node_id: str, applied_version: int, drift: Any,
                 error_class: str | None, now: datetime) -> dict[str, Any]:
    """客户端应用状态上报（只存版本 / 漂移摘要 / 错误类，**不存正文**）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """INSERT INTO node_model_sync_state
                   (node_id, applied_version, applied_at, drift, last_error, updated_at)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (node_id) DO UPDATE
                  SET applied_version = EXCLUDED.applied_version,
                      applied_at = EXCLUDED.applied_at,
                      drift = EXCLUDED.drift,
                      last_error = EXCLUDED.last_error,
                      updated_at = EXCLUDED.updated_at
               RETURNING """ + _STATE_COLUMNS,
            (node_id, int(applied_version), now, Jsonb(drift or {}), error_class, now))
        row = _one(cur)
    _event(conn, bundle_id=None, version=int(applied_version), event="state_applied", now=now,
           actor=f"node:{node_id}",
           detail={"error_class": error_class, "drift": drift or {}})
    return row


def get_node_state(conn: Any, node_id: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {_STATE_COLUMNS} FROM node_model_sync_state WHERE node_id = %s",
                    (node_id,))
        return _one(cur)


def list_node_states(conn: Any, *, limit: int = facts.DEFAULT_LIST_LIMIT,
                     server_version: int | None = None) -> list[dict[str, Any]]:
    """节点应用状态（原始行；wire 形态由 :func:`state_view` 统一转）。"""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {_STATE_COLUMNS} FROM node_model_sync_state"
                    f" ORDER BY updated_at DESC LIMIT %s", (int(limit),))
        return _rows(cur)


def state_view(row: Mapping[str, Any], *, server_version: int) -> dict[str, Any]:
    """admin 状态项（wire）：版本 / 是否同步 / 漂移 / 错误类。"""
    return {
        "node_id": row["node_id"],
        "applied_version": int(row["applied_version"]),
        "applied_at": _iso(row.get("applied_at")),
        "updated_at": _iso(row.get("updated_at")),
        "in_sync": int(row["applied_version"]) == int(server_version),
        "drift": dict(row.get("drift") or {}),
        "error_class": row.get("last_error"),
    }


def _unused(_: Iterable[Any] | None = None) -> None:          # pragma: no cover - 占位
    return None
