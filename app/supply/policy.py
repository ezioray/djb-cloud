# SPDX-License-Identifier: AGPL-3.0-or-later
"""策略版本、digest 与 304（M02 §6.4 / INV-06 / §4.1 GET /node/policy）。

铁律：

* **版本不可变、不可回退**：每个版本一行 ``node_policies``（202 的触发器保证内容不可改），
  ``policy_version`` 单调递增（整数形态的 TEXT），回退即 40907。
* **digest = sha256(canonical_json(doc))**：canonical = 键排序 + 紧凑分隔符 + 不做 ASCII 转义；
  内容不变则 **不升版本**（同一 digest 直接复用），避免客户端被无意义的版本抖动打扰。
* **不内置任何配额默认值**（M02 §1 / INV-06）：配额与指令由配置 provider 给出；
  没给就是空数组，服务端不猜。
* ETag = ``policy_version``（spec：`ETag: 即 policy_version`），``If-None-Match`` 命中 → 304。
* 策略内容不得含凭据或内部阈值（M02 §6.4）：本文件只把 ``supply.`` 配置投影成 settings，
  凭据类键由 :func:`_reject_secret_keys` 在构造期拦掉。
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from psycopg.types.json import Jsonb

from . import clock, config_source, facts, models
from .errors import InvalidArgument, PolicyVersionRegression

log = logging.getLogger("djb.supply.policy")

MAX_QUOTAS = 64
MAX_DIRECTIVES = 64
_FORBIDDEN_TOKENS = ("secret", "token", "password", "apikey", "api_key", "credential")


@dataclasses.dataclass(frozen=True)
class Policy:
    policy_version: str
    node_id: str | None
    protocol_version: str
    issued_at: datetime
    effective_at: datetime
    digest: str
    doc: dict[str, Any]
    status: str

    @property
    def etag(self) -> str:
        return self.policy_version

    @property
    def quotas(self) -> list[dict[str, Any]]:
        return list(self.doc.get("quotas") or [])

    @property
    def directives(self) -> list[dict[str, Any]]:
        return list(self.doc.get("directives") or [])


def _now(now: datetime | None) -> datetime:
    return now.astimezone(timezone.utc) if now else clock.utcnow()


def canonical_json(doc: Mapping[str, Any]) -> str:
    """canonical JSON（00-conventions：稳定 digest 的前提）。"""
    return json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False)


def digest_of(doc: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(doc).encode("utf-8")).hexdigest()


def _reject_secret_keys(payload: Mapping[str, Any], *, path: str = "") -> None:
    """策略里不得出现凭据类键（M02 §6.4 / H1）。"""
    for key, value in payload.items():
        name = str(key).lower()
        where = f"{path}.{key}" if path else str(key)
        if any(token in name for token in _FORBIDDEN_TOKENS):
            raise InvalidArgument(f"策略内容不得含凭据类键 {where!r}", field="quotas")
        if isinstance(value, Mapping):
            _reject_secret_keys(value, path=where)


def _validate_quotas(quotas: Any) -> list[dict[str, Any]]:
    if quotas is None:
        return []
    if not isinstance(quotas, (list, tuple)):
        raise InvalidArgument("quotas 必须是数组", field="quotas")
    if len(quotas) > MAX_QUOTAS:
        raise InvalidArgument(f"quotas 最多 {MAX_QUOTAS} 项", field="quotas")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(quotas):
        if not isinstance(item, Mapping):
            raise InvalidArgument(f"quotas[{index}] 必须是对象", field=f"quotas[{index}]")
        _reject_secret_keys(item, path=f"quotas[{index}]")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 64:
            raise InvalidArgument(f"quotas[{index}].name 不合法", field=f"quotas[{index}].name")
        window = item.get("window_seconds")
        if isinstance(window, bool) or not isinstance(window, int) or window < 1:
            raise InvalidArgument(f"quotas[{index}].window_seconds 必须是正整数",
                                  field=f"quotas[{index}].window_seconds")
        entry: dict[str, Any] = {"name": name.strip(), "window_seconds": window}
        value = item.get("value")
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidArgument(f"quotas[{index}].value 必须是非负整数",
                                      field=f"quotas[{index}].value")
            entry["value"] = value
        result.append(entry)
    return result


def _validate_directives(directives: Any) -> list[dict[str, Any]]:
    if directives is None:
        return []
    if not isinstance(directives, (list, tuple)):
        raise InvalidArgument("directives 必须是数组", field="directives")
    if len(directives) > MAX_DIRECTIVES:
        raise InvalidArgument(f"directives 最多 {MAX_DIRECTIVES} 项", field="directives")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(directives):
        if not isinstance(item, Mapping):
            raise InvalidArgument(f"directives[{index}] 必须是对象", field=f"directives[{index}]")
        _reject_secret_keys(item, path=f"directives[{index}]")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 64:
            raise InvalidArgument(f"directives[{index}].name 不合法",
                                  field=f"directives[{index}].name")
        entry = dict(item)
        entry["name"] = name.strip()
        result.append(entry)
    return result


def build_doc(settings: Mapping[str, int], *, protocol_version: str,
              quotas: Any = None, directives: Any = None) -> dict[str, Any]:
    """构造策略内容（**不含 issued_at**：时间戳会让 digest 每次变化、版本无限膨胀）。"""
    if not isinstance(protocol_version, str) or not protocol_version.strip():
        raise InvalidArgument("protocol_version 必填", field="protocol_version")
    doc = {
        "protocol_version": protocol_version.strip(),
        "settings": {str(key): int(value) for key, value in sorted(settings.items())},
        "quotas": _validate_quotas(quotas),
        "directives": _validate_directives(directives),
    }
    _reject_secret_keys(doc)
    return doc


def _row(row: Mapping[str, Any]) -> Policy:
    return Policy(policy_version=row["policy_version"], node_id=row["node_id"],
                  protocol_version=row["protocol_version"], issued_at=row["issued_at"],
                  effective_at=row["effective_at"], digest=row["digest"],
                  doc=dict(row["doc"]), status=row["status"])


def current(c, *, node_id: str | None) -> Policy | None:
    """当前 active 版本（``node_id=None`` 取全局基线）。"""
    sql = ("SELECT policy_version, node_id, protocol_version, issued_at, effective_at, digest, "
           "doc, status FROM node_policies WHERE status = 'active' AND ")
    params: tuple[Any, ...]
    if node_id is None:
        sql += "node_id IS NULL"
        params = ()
    else:
        sql += "node_id = %s"
        params = (node_id,)
    with c.cursor() as cur:
        cur.execute(sql + " ORDER BY issued_at DESC, policy_version DESC LIMIT 1", params)
        row = models._one(cur)
    return _row(row) if row else None


def latest_version(c, *, node_id: str | None) -> str:
    sql = "SELECT policy_version FROM node_policies WHERE "
    params: tuple[Any, ...]
    if node_id is None:
        sql += "node_id IS NULL"
        params = ()
    else:
        sql += "node_id = %s"
        params = (node_id,)
    with c.cursor() as cur:
        cur.execute(sql + " ORDER BY issued_at DESC, policy_version DESC LIMIT 1", params)
        row = models._one(cur)
    return str(row["policy_version"]) if row else "0"


def _next_version(previous: str) -> str:
    """单调递增：整数版本 +1；非法历史值直接 40907（宁可拒绝也不静默回退）。"""
    try:
        number = int(str(previous))
    except (TypeError, ValueError) as exc:
        raise PolicyVersionRegression("历史策略版本不是整数，无法单调递增",
                                      policy_version=str(previous)) from exc
    return str(number + 1)


def _supersede(c, *, node_id: str | None) -> None:
    sql = "UPDATE node_policies SET status = 'superseded' WHERE status = 'active' AND "
    params: tuple[Any, ...]
    if node_id is None:
        sql += "node_id IS NULL"
        params = ()
    else:
        sql += "node_id = %s"
        params = (node_id,)
    with c.cursor() as cur:
        cur.execute(sql, params)


def ensure(c, *, node, settings: Mapping[str, int], protocol_version: str,
           quotas: Any = None, directives: Any = None,
           now: datetime | None = None) -> Policy:
    """内容变化才生成新版本；内容不变复用当前版本（INV-06：不抖版本）。"""
    moment = _now(now)
    doc = build_doc(settings, protocol_version=protocol_version, quotas=quotas,
                    directives=directives)
    digest = digest_of(doc)
    existing = current(c, node_id=node.id)
    if existing is not None and existing.digest == digest:
        return existing

    version = _next_version(latest_version(c, node_id=node.id))
    _supersede(c, node_id=node.id)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO node_policies
                   (policy_version, node_id, protocol_version, issued_at, effective_at, digest,
                    doc, status, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, 'active', %s)""",
            (version, node.id, protocol_version, moment, moment, digest, Jsonb(doc), moment))
        cur.execute("UPDATE nodes SET policy_version = %s, updated_at = %s WHERE id = %s",
                    (version, moment, node.id))
    log.info("supply.policy.issued", extra={"event": "node.policy.issued", "node_id": node.id,
                                            "policy_version": version, "digest": digest})
    return Policy(policy_version=version, node_id=node.id, protocol_version=protocol_version,
                  issued_at=moment, effective_at=moment, digest=digest, doc=doc,
                  status="active")


def ensure_for_node(c, *, node, now: datetime | None = None) -> Policy:
    """从配置 provider 取值并生成 / 复用当前策略（路由与心跳共用同一入口）。"""
    settings = config_source.load(c, node)
    raw = config_source.raw(c, node)
    return ensure(c, node=node, settings=settings,
                  protocol_version=facts.PROTOCOL_VERSION,
                  quotas=raw.get("quotas"), directives=raw.get("directives"), now=now)


def verify(policy: Policy) -> None:
    """复算 digest（INV-06）：不一致即 40907，客户端不得应用。"""
    recomputed = digest_of(policy.doc)
    if recomputed != policy.digest:
        raise PolicyVersionRegression("策略摘要与内容不一致", policy_version=policy.policy_version,
                                      expected=policy.digest, actual=recomputed)


def policy_payload(policy: Policy) -> dict[str, Any]:
    """spec ``NodePolicy``（+ settings 投影，只加不改）。"""
    payload = {
        "policy_version": policy.policy_version,
        "protocol_version": policy.protocol_version,
        "issued_at": models.iso(policy.issued_at),
        "effective_at": models.iso(policy.effective_at),
        "digest": policy.digest,
        "quotas": policy.quotas,
        "directives": policy.directives,
        "settings": dict(policy.doc.get("settings") or {}),
        "status": policy.status,
    }
    return payload


def etag_matches(if_none_match: str | None, policy: Policy) -> bool:
    """``If-None-Match`` 命中判定（容忍弱校验器 ``W/`` 与引号，spec：传上次的 policy_version）。"""
    if not if_none_match:
        return False
    candidates = []
    for raw in str(if_none_match).split(","):
        token = raw.strip()
        if token.startswith("W/"):
            token = token[2:].strip()
        candidates.append(token.strip('"').strip())
    return policy.policy_version in candidates or policy.digest in candidates


def history(c, node_id: str) -> Sequence[Policy]:
    with c.cursor() as cur:
        cur.execute(
            """SELECT policy_version, node_id, protocol_version, issued_at, effective_at, digest,
                      doc, status FROM node_policies WHERE node_id = %s
                ORDER BY issued_at DESC, policy_version DESC""", (node_id,))
        return [_row(row) for row in models._rows(cur)]


__all__ = ["Policy", "MAX_QUOTAS", "MAX_DIRECTIVES", "canonical_json", "digest_of",
           "build_doc", "current", "latest_version", "ensure", "ensure_for_node", "verify",
           "policy_payload", "etag_matches", "history"]
