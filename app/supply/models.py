# SPDX-License-Identifier: Apache-2.0
"""M02 node-supply · 领域模型与唯一写入口（DEV-M02 T1+T2）。

范围（M02 §10.1）：

* **T1**：``nodes`` / ``node_upstreams`` / ``node_policies`` / ``node_events`` /
  ``capacity_announcements`` 的模型与状态机（表在 ``migrations/200–207``）；
* **T2**：注册 / pair（密钥轮换）/ binding / 准入审核的领域操作 + 事件与留痕。

铁律（本模块自检）：

- **不跨模块**：只 import 标准库、``psycopg`` 与本包；M01 的账户信息**只读**
  ``v_identity_accounts`` 视图（00-conventions §7.4 跨模块只读视图），不碰对方基表，
  也不 import ``app.identity``。
- **不存明文**：密钥 / 绑定码只存 ``sha256`` + 8 位前缀（INV-10）；指纹再哈希后入库、
  不回传（INV-03）；疑似凭据字段直接 400 丢弃（INV-04）。
- **一份事实一个来源**：生命周期状态 = 存量列 ``state``（``lifecycle_state`` 是生成列别名）；
  在线 / 离线只在 ``state.derive_*()`` 派生，不落库。
- **事务边界在调用方**：本模块不自己开事务（``c`` 由调用方给），
  ``nodes`` / ``node_events`` / ``supply_outbox`` 同事务提交（M02 §6.1）。
- 业务常量只在 ``facts.py``；这里不写魔数。
"""
from __future__ import annotations

import dataclasses
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from psycopg.types.json import Jsonb
from psycopg.errors import UniqueViolation

from . import clock, events, facts, protocol, security, state as state_machine
from .errors import (
    AccountNotFound,
    BindingCodeInvalid,
    BindingConflict,
    FingerprintConflict,
    InvalidArgument,
    KeyStateConflict,
    NodeKeyInvalid,
    NodeKeyMissing,
    NodeKeyRevoked,
    NodeNotFound,
    NodeStateForbidden,
    RetireIrreversible,
)

log = logging.getLogger("djb.supply.models")

#: 节点主档列（顺序即 dataclass 顺序，便于 ``_make``）
NODE_COLUMNS: tuple[str, ...] = (
    "id", "platform", "hardware_fingerprint", "client_version", "protocol_version", "state",
    "key_prefix", "created_at", "last_seen_at", "account_id", "tenant_id", "access_modes",
    "capabilities", "policy_version", "region", "labels", "runtime_state", "bound_account_id",
    "bound_at", "revoked_at", "key_id", "key_issued_at", "key_revoked_at", "prev_key_id",
    "prev_key_hash", "prev_key_expires_at", "reviewed_at", "reviewed_by",
    "retire_requested_at", "retired_at", "updated_at", "heartbeat_seq", "offline_announced_at",
)
_COLS_SQL = ", ".join(NODE_COLUMNS)


# --------------------------------------------------------------------------- 工具
def uuid7(now_ns: int | None = None) -> uuid.UUID:
    """UUIDv7（00-conventions §2：内部主键时间有序；PG15 无 ``uuidv7()``）。"""
    millis = (time.time_ns() if now_ns is None else now_ns) // 1_000_000
    rand = secrets.randbits(74)
    value = ((millis & ((1 << 48) - 1)) << 80) | (0x7 << 76) \
        | (((rand >> 62) & 0x0FFF) << 64) | (0b10 << 62) | (rand & ((1 << 62) - 1))
    return uuid.UUID(int=value)


def _now(now: datetime | None) -> datetime:
    return now.astimezone(timezone.utc) if now else clock.utcnow()


def _row_dict(cur, row) -> dict[str, Any]:
    if isinstance(row, Mapping):
        return dict(row)
    return dict(zip([d.name for d in cur.description], row))


def _one(cur) -> dict[str, Any] | None:
    row = cur.fetchone()
    return None if row is None else _row_dict(cur, row)


def _rows(cur) -> list[dict[str, Any]]:
    return [_row_dict(cur, row) for row in cur.fetchall()]


def _make(cls: type, row: Mapping[str, Any]):
    names = {field.name for field in dataclasses.fields(cls)}
    return cls(**{key: value for key, value in row.items() if key in names})


# --------------------------------------------------------------------------- 对象
@dataclasses.dataclass(frozen=True)
class Node:
    """节点主档（M02 §3 Node）。

    ``state`` 是权威生命周期态；``lifecycle_state`` 是**同一事实**的只读别名（库层生成列）。
    """

    id: str
    platform: str
    hardware_fingerprint: str          # **只存哈希**（INV-03）
    client_version: str
    protocol_version: str
    state: str
    key_prefix: str
    created_at: datetime
    last_seen_at: datetime | None
    account_id: uuid.UUID | None
    tenant_id: uuid.UUID | None
    access_modes: tuple[str, ...]
    capabilities: tuple[str, ...]
    policy_version: str
    region: str | None
    labels: dict[str, Any]
    runtime_state: str | None
    bound_account_id: uuid.UUID | None
    bound_at: datetime | None
    revoked_at: datetime | None
    key_id: uuid.UUID | None
    key_issued_at: datetime | None
    key_revoked_at: datetime | None
    prev_key_id: uuid.UUID | None
    prev_key_hash: str | None
    prev_key_expires_at: datetime | None
    reviewed_at: datetime | None
    reviewed_by: str | None
    retire_requested_at: datetime | None
    retired_at: datetime | None
    updated_at: datetime
    heartbeat_seq: int
    offline_announced_at: datetime | None

    @property
    def lifecycle_state(self) -> str:
        return self.state

    @property
    def is_active(self) -> bool:
        return self.state == "active"

    def presence(self, now: datetime) -> str:
        return state_machine.derive_presence(self.last_seen_at, now)

    def binding(self) -> "Binding":
        return binding_of(self)


@dataclasses.dataclass(frozen=True)
class Binding:
    """绑定视图（M02 §3 Binding）：一个节点同时只有一条有效绑定（INV-08）。"""

    node_id: str
    state: str                          # unbound / pending / bound / revoked
    bound_account_id: uuid.UUID | None
    bound_at: datetime | None
    revoked_at: datetime | None


@dataclasses.dataclass(frozen=True)
class AuthResult:
    node: Node
    key_kind: str                       # "primary" | "previous"


@dataclasses.dataclass(frozen=True)
class RegisterResult:
    node: Node
    client_key: str | None              # 明文：只在本次响应出现一次（重放路径为 None）
    key_id: uuid.UUID | None
    created: bool


@dataclasses.dataclass(frozen=True)
class KeyRotation:
    node: Node
    client_key: str
    key_id: uuid.UUID
    previous_key_expires_at: datetime | None


@dataclasses.dataclass(frozen=True)
class BindingCode:
    code: str                           # 明文：只在签发响应出现一次
    code_id: uuid.UUID
    node_id: str
    account_id: uuid.UUID
    expires_at: datetime


# --------------------------------------------------------------------------- 查询
def _load(c, where: str, params: Sequence[Any], *, for_update: bool = False) -> Node | None:
    sql = f"SELECT {_COLS_SQL} FROM nodes WHERE {where}"
    if for_update:
        sql += " FOR UPDATE"
    with c.cursor() as cur:
        cur.execute(sql, tuple(params))
        row = _one(cur)
    return _make(Node, row) if row else None


def get_node(c, node_id: str, *, for_update: bool = False) -> Node:
    if not isinstance(node_id, str) or not node_id.strip():
        raise InvalidArgument("node_id 必填", field="node_id")
    node = _load(c, "id = %s", (node_id.strip(),), for_update=for_update)
    if node is None:
        raise NodeNotFound("节点不存在", node_id=node_id)
    return node


def find_by_fingerprint(c, platform: str, fingerprint_hash: str, *,
                        for_update: bool = False) -> Node | None:
    """INV-01 的唯一键：``(platform, hardware_fingerprint)``。"""
    return _load(c, "platform = %s AND hardware_fingerprint = %s",
                 (platform, fingerprint_hash), for_update=for_update)


def key_material(c, node_id: str) -> tuple[str, uuid.UUID | None]:
    """读当前密钥材料（``key_hash`` / ``key_id``）。

    刻意**不放进** :class:`Node`：领域对象会经路由序列化、日志、异常 details 流转，
    密钥哈希不该搭这趟车（INV-10「只存哈希」的延伸：也不到处传）。
    """
    with c.cursor() as cur:
        cur.execute("SELECT key_hash, key_id FROM nodes WHERE id = %s", (node_id,))
        row = _one(cur)
    if row is None:                                           # pragma: no cover - 调用方已加锁
        raise NodeNotFound("节点不存在", node_id=node_id)
    return row["key_hash"], row["key_id"]


def binding_of(node: Node) -> Binding:
    """派生绑定视图：revoked / bound / pending（未准入） / unbound。"""
    if node.revoked_at is not None:
        view = "revoked"
    elif node.bound_account_id is not None:
        view = "bound"
    elif node.state == "pending":
        view = "pending"
    else:
        view = "unbound"
    return Binding(node_id=node.id, state=view, bound_account_id=node.bound_account_id,
                   bound_at=node.bound_at, revoked_at=node.revoked_at)


def binding_dict(binding: Binding) -> dict[str, Any]:
    """spec ``NodeBinding`` 响应体（时间一律 UTC ISO-8601 Z）。"""
    return {
        "node_id": binding.node_id,
        "state": binding.state,
        "bound_account_id": str(binding.bound_account_id) if binding.bound_account_id else None,
        "bound_at": _iso(binding.bound_at),
        "revoked_at": _iso(binding.revoked_at),
    }


def iso(moment: datetime | None) -> str | None:
    """UTC ISO-8601（``...Z``）；与 ``_iso`` 同一实现，供外部序列化复用。"""
    return _iso(moment)


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_row_id(c, *, node_id: str, kind: str, from_state: str | None,
                  to_state: str | None, reason_code: str | None = None,
                  reason: str | None = None, actor: str | None = None,
                  payload: Mapping[str, Any] | None = None,
                  now: datetime | None = None) -> uuid.UUID:
    """追加一条 ``node_events``（只追加表）；返回事件行 id 作为 outbox 的 causation_id。"""
    identifier = uuid7(int(_now(now).timestamp() * 1_000_000))
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO node_events
                   (id, node_id, kind, from_state, to_state, reason_code, reason, actor,
                    payload, ts)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (identifier, node_id, kind, from_state, to_state, reason_code, reason, actor,
             Jsonb(dict(payload or {})), _now(now)))
    return identifier


# --------------------------------------------------------------------------- 鉴权
def authenticate(c, client_key: str | None, *, allow_previous: bool = True,
                 now: datetime | None = None) -> AuthResult:
    """节点侧鉴权（``X-Client-Key``）。

    INV-10：轮换重叠期内旧钥**只验签**（``allow_previous=True`` 的接口放行），
    但**不接受新注册**（注册路径传 ``allow_previous=False``）。
    """
    if not isinstance(client_key, str) or not client_key.strip():
        raise NodeKeyMissing("缺少 X-Client-Key", reason="missing_client_key")
    moment = _now(now)
    digest = security.hash_secret(client_key.strip())
    node = _load(c, "key_hash = %s", (digest,))
    if node is not None:
        if node.key_revoked_at is not None and node.key_revoked_at <= moment:
            raise NodeKeyRevoked("节点密钥已撤销，请重新 pair", node_id=node.id)
        return AuthResult(node=node, key_kind="primary")
    if allow_previous:
        previous = _load(c, "prev_key_hash = %s", (digest,))
        if previous is not None:
            if previous.prev_key_expires_at is None or previous.prev_key_expires_at <= moment:
                raise NodeKeyRevoked("节点密钥重叠期已过，请重新 pair", node_id=previous.id)
            return AuthResult(node=previous, key_kind="previous")
    raise NodeKeyInvalid("节点密钥无效", reason="invalid_client_key")


# --------------------------------------------------------------------------- 注册（T2）
def _validate_platform(platform: Any) -> str:
    if not isinstance(platform, str) or platform not in facts.PLATFORMS:
        raise InvalidArgument(f"platform 必须是 {'/'.join(facts.PLATFORMS)} 之一",
                              field="platform")
    return platform


def _validate_str_vector(values: Any, *, field: str, allowed: Iterable[str] | None = None,
                         max_items: int = 32, max_len: int = 64) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        raise InvalidArgument(f"{field} 必须是数组", field=field)
    result: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise InvalidArgument(f"{field} 元素必须是非空字符串", field=field)
        text = item.strip()
        if len(text) > max_len:
            raise InvalidArgument(f"{field} 元素超长", field=field)
        if allowed is not None and text not in allowed:
            raise InvalidArgument(f"{field} 含非法值 {text!r}", field=field)
        result.append(text)
    if len(result) > max_items:
        raise InvalidArgument(f"{field} 最多 {max_items} 项", field=field)
    return tuple(dict.fromkeys(result))


def _issue_key_fields(now: datetime) -> tuple[str, str, str, uuid.UUID]:
    plaintext, prefix, digest = security.new_client_key()
    return plaintext, prefix, digest, uuid7(int(now.timestamp() * 1_000_000))


def register(c, *, platform: Any, hardware_fingerprint: Any, client_version: Any,
             protocol_version: Any, capabilities: Any = None, access_modes: Any = None,
             region: Any = None, labels: Any = None, client_key: str | None = None,
             now: datetime | None = None, trace_id: str = "") -> RegisterResult:
    """注册（M02 §6.1 / INV-01）。

    三条路径（全部同事务：nodes + node_events + outbox）：

    1. **首次** → 建 ``pending`` + 发 ``node.registered`` + 下发初始密钥（明文只回一次）；
    2. **同指纹 + 持有效密钥**（同机重装 / 重放）→ 幂等返回同一 ``node_id``，**轮换密钥**、
       旧钥立即失效（验收 A1），不重复发 ``node.registered``；
    3. **同指纹 + 无有效密钥 + 已归属账户** → ``40903``（防凭据接管：指纹哈希不是秘密，
       不能让任何人凭指纹轮换别人的密钥）；未归属（未绑定账户）时按 2 处理。
    """
    moment = _now(now)
    platform = _validate_platform(platform)
    protocol.check(protocol_version)                      # INV-05：越界 → 42601
    fingerprint = security.hash_fingerprint(
        security.normalize_fingerprint(hardware_fingerprint))   # INV-03：再哈希
    capabilities_t = _validate_str_vector(capabilities, field="capabilities")
    access_modes_t = _validate_str_vector(access_modes, field="access_modes",
                                         allowed=facts.ACCESS_TYPES, max_items=3)
    if region is not None and (not isinstance(region, str) or len(region.strip()) > 64):
        raise InvalidArgument("region 不合法", field="region")
    if labels is not None and not isinstance(labels, Mapping):
        raise InvalidArgument("labels 必须是对象", field="labels")
    if not isinstance(client_version, str) or not client_version.strip() \
            or len(client_version.strip()) > 64:
        raise InvalidArgument("client_version 必填（≤64 字符）", field="client_version")

    existing = find_by_fingerprint(c, platform, fingerprint, for_update=True)
    if existing is not None:
        owner_bound = existing.bound_account_id is not None or existing.account_id is not None
        if client_key:
            auth = authenticate(c, client_key, allow_previous=False, now=moment)
            if auth.node.id != existing.id:               # pragma: no cover - 唯一索引兜底
                raise FingerprintConflict("硬件指纹已被其它节点占用", node_id=existing.id)
        elif owner_bound:
            raise FingerprintConflict(
                "该设备已注册并已绑定账户：请在原账户解绑或联系管理员（INV-01）",
                node_id=existing.id)

        plaintext, prefix, digest, key_id = _issue_key_fields(moment)
        with c.cursor() as cur:
            cur.execute(
                """UPDATE nodes
                      SET client_version = %s, protocol_version = %s, capabilities = %s,
                          access_modes = %s, region = COALESCE(%s, region),
                          labels = COALESCE(%s, labels), key_hash = %s, key_prefix = %s,
                          key_id = %s, key_issued_at = %s, key_revoked_at = NULL,
                          prev_key_hash = NULL, prev_key_id = NULL,
                          prev_key_expires_at = NULL, updated_at = %s
                    WHERE id = %s""",
                (client_version.strip(), protocol_version.strip(), list(capabilities_t),
                 list(access_modes_t), region, Jsonb(dict(labels)) if labels else None,
                 digest, prefix, key_id, moment, moment, existing.id))
        _event_row_id(c, node_id=existing.id, kind="re_registered",
                      from_state=existing.state, to_state=existing.state,
                      reason_code="idempotent_reregister", actor="self",
                      payload={"key_id": str(key_id)}, now=moment)
        log.info("supply.node.reregistered", extra={"event": "node.reregistered",
                                                    "node_id": existing.id,
                                                    "trace_id": trace_id})
        return RegisterResult(node=get_node(c, existing.id), client_key=plaintext,
                              key_id=key_id, created=False)

    plaintext, prefix, digest, key_id = _issue_key_fields(moment)
    node_id = f"n_{uuid7(int(moment.timestamp() * 1_000_000)).hex}"
    with c.cursor() as cur:
        try:
            cur.execute(
                """INSERT INTO nodes
                       (id, platform, hardware_fingerprint, client_version, protocol_version,
                        state, key_prefix, key_hash, created_at, account_id, tenant_id,
                        access_modes, capabilities, policy_version, region, labels,
                        key_id, key_issued_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, 'pending', %s, %s, %s, NULL, NULL, %s, %s,
                           '0', %s, %s, %s, %s, %s)""",
                (node_id, platform, fingerprint, client_version.strip(),
                 protocol_version.strip(), prefix, digest, moment, list(access_modes_t),
                 list(capabilities_t), region, Jsonb(dict(labels or {})), key_id, moment,
                 moment))
        except UniqueViolation as exc:                    # pragma: no cover - 并发兜底
            raise FingerprintConflict("该设备已注册（并发注册冲突）", node_id=node_id) from exc
    causes = _event_row_id(c, node_id=node_id, kind="registered", from_state=None,
                           to_state="pending", reason_code="registered", actor="self",
                           payload={"protocol_version": protocol_version.strip(),
                                    "access_modes": list(access_modes_t)}, now=moment)
    events.node_registered(c, node_id=node_id, account_id=None,
                           protocols=[protocol_version.strip()], region=region,
                           trace_id=trace_id, occurred_at=moment, causation_id=causes)
    node = get_node(c, node_id)
    log.info("supply.node.registered", extra={"event": "node.registered", "node_id": node_id,
                                             "trace_id": trace_id})
    return RegisterResult(node=node, client_key=plaintext, key_id=key_id, created=True)


# --------------------------------------------------------------------------- pair（T2）
def rotate_key(c, node: Node, *, rotate: bool = False, overlap_seconds: int = 0,
               now: datetime | None = None, trace_id: str = "") -> KeyRotation:
    """生成 / 轮换客户端密钥（M02 §4.1 pair / INV-10）。

    * 状态非 ``active`` → 40305（spec pair 描述：非 active 拒绝换钥）；
    * ``rotate=False``：新钥立即生效，旧钥**立刻**失效（无重叠）；
    * ``rotate=True``：旧钥在同一 ``overlap_seconds`` 窗口内**只验签**（≤24 h）。
    """
    moment = _now(now)
    state_machine.require_state(node.state, "active", action="rotate_key")
    if not isinstance(rotate, bool):
        raise InvalidArgument("rotate 必须是布尔值", field="rotate")
    if not isinstance(overlap_seconds, int) or isinstance(overlap_seconds, bool) \
            or overlap_seconds < 0:
        raise InvalidArgument("overlap_seconds 必须是非负整数", field="overlap_seconds")
    if overlap_seconds > facts.KEY_OVERLAP_MAX_S:
        raise InvalidArgument(f"overlap_seconds 不得超过 {facts.KEY_OVERLAP_MAX_S}（24 h）",
                              field="overlap_seconds")
    if not rotate and overlap_seconds > 0:
        raise KeyStateConflict("rotate=false 时不允许有重叠期", field="overlap_seconds")

    plaintext, prefix, digest, key_id = _issue_key_fields(moment)
    previous_expires = (moment + timedelta(seconds=overlap_seconds)) if rotate else None
    old_hash, old_key_id = key_material(c, node.id)
    with c.cursor() as cur:
        cur.execute(
            """UPDATE nodes
                  SET key_hash = %s, key_prefix = %s, key_id = %s, key_issued_at = %s,
                      key_revoked_at = NULL, prev_key_hash = %s, prev_key_id = %s,
                      prev_key_expires_at = %s, updated_at = %s
                WHERE id = %s""",
            (digest, prefix, key_id, moment, old_hash if rotate else None,
             old_key_id if rotate else None, previous_expires, moment, node.id))
    _event_row_id(c, node_id=node.id, kind="key_rotated", from_state=node.state,
                  to_state=node.state, reason_code="pair", actor="self",
                  payload={"key_id": str(key_id), "key_prefix": prefix,
                           "rotate": rotate,
                           "previous_key_expires_at": _iso(previous_expires)}, now=moment)
    log.info("supply.node.key_rotated", extra={"event": "node.key_rotated",
                                               "node_id": node.id, "trace_id": trace_id,
                                               "rotate": rotate})
    return KeyRotation(node=get_node(c, node.id), client_key=plaintext, key_id=key_id,
                       previous_key_expires_at=previous_expires)


# --------------------------------------------------------------------------- 绑定（T2）
def _load_account(c, account_id: uuid.UUID) -> dict[str, Any]:
    """M01 账户**只读**视图（00-conventions §7.4：跨模块只读视图，不 join 对方基表）。"""
    with c.cursor() as cur:
        cur.execute(
            "SELECT account_id, state, tenant_id FROM v_identity_accounts WHERE account_id = %s",
            (account_id,))
        row = _one(cur)
    if row is None:
        raise AccountNotFound("账户不存在", account_id=str(account_id))
    return row


def _count_bound_nodes(c, account_id: uuid.UUID) -> int:
    with c.cursor() as cur:
        cur.execute(
            """SELECT count(*) AS n FROM nodes
                WHERE bound_account_id = %s AND revoked_at IS NULL""", (account_id,))
        row = _one(cur)
    return int(row["n"]) if row else 0


def issue_binding_code(c, *, node_id: str, account_id: uuid.UUID,
                       ttl_seconds: int = facts.BINDING_CODE_TTL_S,
                       now: datetime | None = None) -> BindingCode:
    """签发一次性绑定码（网页端已鉴权后调用；明文只回一次）。

    这是 ``POST /api/v1/node/binding`` 的前置：网页端（M13 BFF）在登录态下为本账户签发。
    """
    moment = _now(now)
    if not isinstance(account_id, uuid.UUID):
        raise InvalidArgument("account_id 必须是 UUID", field="account_id")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) \
            or ttl_seconds <= 0 or ttl_seconds > 3600:
        raise InvalidArgument("ttl_seconds 必须在 1–3600 之间", field="ttl_seconds")
    node = get_node(c, node_id, for_update=True)
    state_machine.require_state(node.state, "active", action="bind")
    account = _load_account(c, account_id)
    if account["state"] != "normal":
        raise BindingConflict("账户不可绑定节点（非 normal 状态）",
                              account_id=str(account_id), account_state=account["state"])
    if _count_bound_nodes(c, account_id) >= facts.MAX_NODES_PER_ACCOUNT:
        raise BindingConflict("账户节点数超过上限（supply.max_nodes_per_account）",
                              account_id=str(account_id),
                              max_nodes_per_account=facts.MAX_NODES_PER_ACCOUNT)
    plaintext, digest = security.new_binding_code()
    code_id = uuid7(int(moment.timestamp() * 1_000_000))
    expires_at = moment + timedelta(seconds=ttl_seconds)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO node_binding_codes
                   (id, node_id, account_id, code_hash, status, issued_at, expires_at)
               VALUES (%s, %s, %s, %s, 'issued', %s, %s)""",
            (code_id, node.id, account_id, digest, moment, expires_at))
    return BindingCode(code=plaintext, code_id=code_id, node_id=node.id,
                       account_id=account_id, expires_at=expires_at)


def bind(c, *, node_id: str, code: str, account_id: uuid.UUID | None = None,
         now: datetime | None = None, trace_id: str = "") -> tuple[Binding, Node]:
    """网页端绑定（M02 §6.5 / INV-08）。

    一次性码 → 校验 → 写 ``nodes.bound_account_id/bound_at`` → ``node_events(bound)`` →
    发 ``node.state.changed(reason=bound)``。**不建绑定表**（CR-4）。
    """
    moment = _now(now)
    if not isinstance(code, str) or not code.strip():
        raise InvalidArgument("code 必填", field="code")
    # 先判节点状态：spec 明确「节点须为 active，否则 403 + 40305」，
    # 不该因为手上没带对码就先把 40503/40905 抛出来（顺序影响客户端处理分支）。
    node = get_node(c, node_id, for_update=True)
    state_machine.require_state(node.state, "active", action="bind")
    digest = security.hash_secret(code.strip())
    with c.cursor() as cur:
        cur.execute(
            """SELECT id, node_id, account_id, status, issued_at, expires_at, consumed_at
                 FROM node_binding_codes WHERE code_hash = %s FOR UPDATE""", (digest,))
        record = _one(cur)
    if record is None:
        raise BindingCodeInvalid("绑定码无效，请重新生成", reason="binding_code_unknown")
    if record["node_id"] != node_id:
        raise BindingCodeInvalid("绑定码与节点不匹配", reason="binding_code_mismatch")
    if record["status"] != "issued":
        raise BindingCodeInvalid(f"绑定码不可用（{record['status']}）",
                                 reason=f"binding_code_{record['status']}")
    if record["expires_at"] <= moment:
        with c.cursor() as cur:
            cur.execute(
                """UPDATE node_binding_codes SET status = 'expired'
                    WHERE id = %s AND status = 'issued'""", (record["id"],))
        raise BindingCodeInvalid("绑定码已过期，请重新生成", reason="binding_code_expired")
    code_account = record["account_id"]
    if account_id is not None and account_id != code_account:
        raise BindingConflict("account_id 与绑定码账户不一致", reason="account_mismatch")

    if node.bound_account_id is not None and node.revoked_at is None \
            and node.bound_account_id != code_account:
        raise BindingConflict("节点已绑定其它账户，请先解绑（INV-08）",
                              bound_account_id=str(node.bound_account_id))
    account = _load_account(c, code_account)
    if account["state"] != "normal":
        raise BindingConflict("账户不可绑定节点（非 normal 状态）",
                              account_id=str(code_account), account_state=account["state"])
    if node.bound_account_id != code_account \
            and _count_bound_nodes(c, code_account) >= facts.MAX_NODES_PER_ACCOUNT:
        raise BindingConflict("账户节点数超过上限（supply.max_nodes_per_account）",
                              account_id=str(code_account),
                              max_nodes_per_account=facts.MAX_NODES_PER_ACCOUNT)

    with c.cursor() as cur:
        cur.execute(
            """UPDATE nodes
                  SET bound_account_id = %s, bound_at = %s, revoked_at = NULL,
                      account_id = %s, tenant_id = %s, updated_at = %s
                WHERE id = %s""",
            (code_account, moment, code_account, account["tenant_id"], moment, node.id))
        cur.execute(
            """UPDATE node_binding_codes
                  SET status = 'consumed', consumed_at = %s, attempts = attempts + 1
                WHERE id = %s""", (moment, record["id"]))
    causes = _event_row_id(c, node_id=node.id, kind="bound", from_state=node.state,
                           to_state=node.state, reason_code="bound", actor="self",
                           payload={"account_id": str(code_account),
                                    "binding_code_id": str(record["id"])}, now=moment)
    events.node_state_changed(c, node_id=node.id, from_state=node.state, to_state=node.state,
                              reason="bound", trace_id=trace_id, occurred_at=moment,
                              causation_id=causes)
    updated = get_node(c, node.id)
    log.info("supply.node.bound", extra={"event": "node.bound", "node_id": node.id,
                                         "trace_id": trace_id})
    return binding_of(updated), updated


def unbind(c, *, node: Node, now: datetime | None = None, trace_id: str = "") \
        -> tuple[Binding, Node]:
    """解绑（幂等；M02 §6.5 / INV-08 / INV-09）。

    * 幂等：已解绑直接回首次结果，不再追加事件；
    * 解绑后停新单（T3 起由 M04 快照体现），在途任务不强断；
    * 历史收据与锁定收益不删（本模块不碰 M05/M06 数据）。
    """
    moment = _now(now)
    if node.state == "retired":
        raise RetireIrreversible("节点已清退，不可解绑（INV-09）", node_id=node.id)
    if node.state not in ("active", "frozen"):
        raise NodeStateForbidden("节点未准入，无需解绑（40305）", state=node.state,
                                 action="unbind")
    if node.revoked_at is not None:
        return binding_of(node), node

    previous_account = node.bound_account_id
    with c.cursor() as cur:
        cur.execute(
            """UPDATE nodes
                  SET revoked_at = %s, account_id = NULL, updated_at = %s
                WHERE id = %s""", (moment, moment, node.id))
    causes = _event_row_id(c, node_id=node.id, kind="unbound", from_state=node.state,
                           to_state=node.state, reason_code="unbound", actor="self",
                           payload={"account_id": str(previous_account)
                                    if previous_account else None}, now=moment)
    events.node_state_changed(c, node_id=node.id, from_state=node.state, to_state=node.state,
                              reason="unbound", trace_id=trace_id, occurred_at=moment,
                              causation_id=causes)
    updated = get_node(c, node.id)
    log.info("supply.node.unbound", extra={"event": "node.unbound", "node_id": node.id,
                                           "trace_id": trace_id})
    return binding_of(updated), updated


def set_bound_tenant(c, node: Node, tenant_id: uuid.UUID, *, now: datetime | None = None) -> Node:
    """绑定后同步租户（T3 的账户事件消费会复用；T2 由 bind 内联完成）。"""
    with c.cursor() as cur:
        cur.execute("UPDATE nodes SET tenant_id = %s, updated_at = %s WHERE id = %s",
                    (tenant_id, _now(now), node.id))
    return get_node(c, node.id)


def append_node_event(c, *, node_id: str, kind: str, from_state: str | None = None,
                      to_state: str | None = None, reason_code: str | None = None,
                      reason: str | None = None, actor: str | None = None,
                      payload: Mapping[str, Any] | None = None,
                      now: datetime | None = None) -> uuid.UUID:
    """公共留痕入口（T3/T4 复用）：往只追加的 ``node_events`` 写一条。"""
    return _event_row_id(c, node_id=node_id, kind=kind, from_state=from_state,
                         to_state=to_state, reason_code=reason_code, reason=reason,
                         actor=actor, payload=payload, now=now)


def emit_upstream_changed(c, *, node_id: str, upstream_type: str, state: str, trace_id: str,
                          moment: datetime, causation_id: uuid.UUID) -> dict[str, Any]:
    """上游状态变化事件（M02 §4.2：payload = node_id, upstream_type, state）。"""
    return events.node_upstream_changed(c, node_id=node_id, upstream_type=upstream_type,
                                        state=state, trace_id=trace_id, occurred_at=moment,
                                        causation_id=causation_id)


# --------------------------------------------------------------------------- 容量公告事件（T3）
def emit_capacity_announced(c, *, node_id: str, announcement: Any, trace_id: str,
                            moment: datetime) -> dict[str, Any]:
    """心跳携带**有效**公告时发 ``capacity.announced``（M02 §4.2）。

    ``causation_id`` 直接用 announcement_id：公告明细已在 ``capacity_announcements``，
    不再往 ``node_events`` 里写一条每心跳一条的噪声。
    """
    capabilities = [dict(item) for item in announcement.capabilities]
    models_list = sorted({str(item["model"]) for item in capabilities})
    gpu = next((item.get("gpu") for item in capabilities if item.get("gpu")), None)
    ram_values = [float(item.get("ram_gb") or 0) for item in capabilities]
    ram = int(max(ram_values)) if ram_values and max(ram_values) > 0 else None
    return events.capacity_announced(c, node_id=node_id, models=models_list, gpu=gpu, ram=ram,
                                     expires_at=announcement.expires_at, trace_id=trace_id,
                                     announced_at=moment, causation_id=announcement.id)


# --------------------------------------------------------------------------- 审核（T2）
def review(c, *, node_id: str, decision: Any, reason: Any, actor: Any,
           tier: Any = None, now: datetime | None = None,
           trace_id: str = "") -> Node:
    """准入审核（``POST /api/v1/admin/supply/nodes/{id}/review``，CR-3 归 M02）。

    * ``approve``：``pending → active``；**不合法迁移一律 40305**（spec 描述）；
    * ``reject``：保留 ``pending`` 并留理由（不落 ``retired``）；
    * 审核必须留理由（spec：审核必须留理由）与 actor（管理面身份）。
    """
    moment = _now(now)
    if decision not in facts.REVIEW_DECISIONS:
        raise InvalidArgument("decision 必须是 approve / reject", field="decision")
    if not isinstance(reason, str) or not reason.strip():
        raise InvalidArgument("reason 必填（审核必须留理由）", field="reason")
    if len(reason.strip()) > facts.REVIEW_REASON_MAX_LEN:
        raise InvalidArgument(f"reason 最多 {facts.REVIEW_REASON_MAX_LEN} 字符", field="reason")
    if not isinstance(actor, str) or not actor.strip():
        raise InvalidArgument("actor 必填（管理面身份）", field="actor")
    if tier is not None and (not isinstance(tier, str) or len(tier.strip()) > 32):
        raise InvalidArgument("tier 不合法", field="tier")

    node = get_node(c, node_id, for_update=True)
    if node.state == "retired":
        raise RetireIrreversible("节点已清退，不可再审（INV-09）", node_id=node.id)
    payload = {"tier": tier} if tier else {}

    if decision == "approve":
        # 准入审核只处理 pending → active：frozen → active 走解冻流程（另一条路径），
        # 不在这里复用，否则「审核一个冻结节点」会把风控冻结悄悄解掉（40305）。
        state_machine.require_state(node.state, "pending", action="review_approve")
        state_machine.require_transition(node.state, "active")
        with c.cursor() as cur:
            cur.execute(
                """UPDATE nodes
                      SET state = 'active', reviewed_at = %s, reviewed_by = %s,
                          updated_at = %s
                    WHERE id = %s""", (moment, actor.strip(), moment, node.id))
        causes = _event_row_id(c, node_id=node.id, kind="review_approved",
                               from_state=node.state, to_state="active",
                               reason_code="approved", reason=reason.strip(),
                               actor=actor.strip(), payload=payload, now=moment)
        events.node_state_changed(c, node_id=node.id, from_state=node.state,
                                  to_state="active", reason="approved", trace_id=trace_id,
                                  occurred_at=moment, causation_id=causes)
    else:
        state_machine.require_state(node.state, "pending", action="review_reject")
        causes = _event_row_id(c, node_id=node.id, kind="review_rejected",
                               from_state=node.state, to_state=node.state,
                               reason_code="rejected", reason=reason.strip(),
                               actor=actor.strip(), payload=payload, now=moment)
        events.node_state_changed(c, node_id=node.id, from_state=node.state,
                                  to_state=node.state, reason="rejected", trace_id=trace_id,
                                  occurred_at=moment, causation_id=causes)
    updated = get_node(c, node.id)
    log.info("supply.node.reviewed", extra={"event": "node.reviewed", "node_id": node.id,
                                            "decision": decision, "trace_id": trace_id})
    return updated


def record_credential_rejection(c, node: Node, fields: Sequence[str], *,
                                now: datetime | None = None) -> uuid.UUID:
    """疑似凭据被拒的留痕（INV-04「400 + 告警，不落值」）。

    ``fields`` 只放**字段名**；payload 里绝不放值、不放请求体快照。
    """
    return _event_row_id(c, node_id=node.id, kind="credential_rejected",
                         from_state=node.state, to_state=node.state,
                         reason_code="credential_field_rejected", actor="self",
                         payload={"fields": list(fields)}, now=now)


# --------------------------------------------------------------------------- 运行态（CR-5，T3 心跳用）
def normalize_runtime_state(value: Any) -> str | None:
    """``runtime_state`` 可选项（spec heartbeat 描述 / CR-5）：未知值**忽略不报错**。

    返回值只用于登记：服务端不把它当状态机（M02 §3 注），库层也没有 CHECK。
    """
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    return text if text in facts.RUNTIME_STATES else None


def record_runtime_state(c, node: Node, value: Any, *, now: datetime | None = None) -> str | None:
    """登记客户端自述运行态；未知值忽略且不改库（不报错）。"""
    normalized = normalize_runtime_state(value)
    if normalized is None:
        return None
    with c.cursor() as cur:
        cur.execute("UPDATE nodes SET runtime_state = %s, updated_at = %s WHERE id = %s",
                    (normalized, _now(now), node.id))
    return normalized


# --------------------------------------------------------------------------- 快照 / 只读
def list_nodes(c, *, account_id: uuid.UUID | None = None, states: Sequence[str] | None = None,
               limit: int = 50) -> list[Node]:
    """只读列表（游标分页的领域层留待 T3；这里只给测试与后台读取用）。"""
    clauses: list[str] = []
    params: list[Any] = []
    if account_id is not None:
        clauses.append("bound_account_id = %s")
        params.append(account_id)
    if states:
        clauses.append("state = ANY(%s)")
        params.append(list(states))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with c.cursor() as cur:
        cur.execute(f"SELECT {_COLS_SQL} FROM nodes {where} ORDER BY created_at DESC LIMIT %s",
                    (*params, max(1, min(int(limit), 200))))
        return [_make(Node, row) for row in _rows(cur)]


__all__ = [
    "Node", "Binding", "AuthResult", "RegisterResult", "KeyRotation", "BindingCode",
    "NODE_COLUMNS", "uuid7",
    "get_node", "find_by_fingerprint", "binding_of", "binding_dict",
    "authenticate", "register", "rotate_key",
    "issue_binding_code", "bind", "unbind", "set_bound_tenant",
    "review", "normalize_runtime_state", "record_runtime_state", "list_nodes",
    "record_credential_rejection", "iso", "key_material", "emit_capacity_announced",
    "append_node_event", "emit_upstream_changed",
]
