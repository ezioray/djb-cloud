# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12a 节点通知队列：入队 / 拉取 / ack / read / 过期（spec 1.2.13 形状）。

服务端为**节点**排队通知（告警 / 分润 / 冻结 / 维护 / 活动 / 系统）：节点离线时消息留在
队列里，上线后用 ``GET /api/v1/node/notifications`` 按 keyset 游标拉取，再 ack / read。
C10 的 ``notify.push`` 帧后续复用同一队列（本卡只做 HTTP 拉取与投递状态）。

口径：

* **幂等**：``dedupe_key``（同节点内唯一）与 ``source_event_id``（全局唯一）双保险；
  重复入队返回**既有行**，不产生第二条通知、不写第二条 ``queued`` 事件；
* **payload 白名单**：只允许 id / 金额 / 时间 / 原因码与少量运维短码；键名不得命中
  :data:`app.notify.facts.PII_KEYS`（INV-07），字符串不得是邮箱 / 手机号、长度 ≤128；
  DB 层另有 ``m12_node_payload_bad_key()`` 兜底（迁移 1206）；
* **不返回已 read 的**：``pull`` 只给 ``queued`` / ``delivered``；``include_read=True``
  仅用于管理面排查；
* **投递留痕**：每次交给节点都追加 ``node_notification_deliveries`` 一行 + ``delivered``
  事件；``ack`` / ``read`` 幂等（重复调用不再追加事件）；
* **保留 180 天**：``expire_due`` 把到期的置 ``expired``；删除只允许 180 天前的行（DB 护栏）。

开关：``notify.node_push.enabled``（默认关闭，owner=lead / expire=2026-12-31）。
S2 用显式环境变量 ``DJB_NODE_PUSH=1`` 激活（等价于打开开关，生产仍需改 features + 评审）。
**关闭时**：``enqueue`` / ``pull``（投递面）拒绝并抛 503 / ``50001``；
``ack`` / ``read`` / ``unread_count`` / ``list_for_admin``（消费面）保持可用——
回滚时节点仍能确认已收到的存量（rollback_rule：停新投递、保留已排队可查）。
"""
from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from psycopg.types.json import Jsonb

from . import clock, errors, facts, features
from .inbox import decode_cursor, encode_cursor
from .store import dict_cursor

__all__ = [
    "SWITCH", "PUSH_ENV", "SEVERITIES", "CATEGORIES", "STATES", "DELIVERY_CHANNELS",
    "DELIVERY_STATUSES", "EVENTS", "ALLOWED_PAYLOAD_KEYS", "P0_MAX_TTL_DAYS",
    "RETENTION_DAYS", "DEFAULT_LIMIT", "MAX_LIMIT", "enabled", "require_active",
    "enqueue", "pull", "ack", "read", "unread_count", "expire_due", "list_for_admin",
]

#: 特性开关名（features.py 已登记三字段；**默认关闭**）
SWITCH: str = "notify.node_push.enabled"
#: S2 显式激活用的环境变量（只认 ``=1``；生产打开仍要改 features + 评审）
PUSH_ENV: str = "DJB_NODE_PUSH"

SEVERITIES: tuple[str, ...] = ("P0", "P1", "P2")
CATEGORIES: tuple[str, ...] = ("alert", "earnings", "freeze", "maintenance", "campaign",
                               "system")
STATES: tuple[str, ...] = ("queued", "delivered", "read", "expired")
DELIVERY_CHANNELS: tuple[str, ...] = ("long_poll", "pull")
DELIVERY_STATUSES: tuple[str, ...] = ("success", "failed")
EVENTS: tuple[str, ...] = ("queued", "delivered", "acked", "read", "expired")

#: P0 的 ``expires_at`` 最多 7 天（不允许长期悬挂）
P0_MAX_TTL_DAYS: int = 7
#: 保留期（与 M12 站内信同口径：180 天）
RETENTION_DAYS: int = facts.INBOX_RETENTION_DAYS
DEFAULT_LIMIT: int = facts.DEFAULT_LIMIT
MAX_LIMIT: int = facts.MAX_LIMIT

#: 模板键：小写 + 数字 + ``_ . -``（不含正文，纯键）
_TEMPLATE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
#: payload 键：小写开头的短标识符
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

#: payload 白名单（节点运维域：id / 金额 / 时间 / 原因码 + 少量运维短码）
ALLOWED_PAYLOAD_KEYS: frozenset[str] = frozenset({
    "node_id", "request_id", "task_id", "batch_id", "incident_id", "alert_id", "payout_id",
    "settlement_id", "case_id", "period", "window_start", "window_end", "deadline_at",
    "amount_minor", "currency", "count", "attempt", "capacity", "qps", "model", "region",
    "reason_code", "error_code", "status", "severity", "category", "template_key", "at",
    "created_at", "expires_at",
})

#: 明确禁止的键（与 DB 侧 ``m12_node_payload_bad_key`` 同一批）
FORBIDDEN_KEYS: frozenset[str] = facts.PII_KEYS | frozenset({
    "authorization", "cookie", "signature", "prompt", "response",
})


# --------------------------------------------------------------------------- 开关
def enabled() -> bool:
    """``notify.node_push.enabled`` 或显式 ``DJB_NODE_PUSH=1``（S2 激活）。"""
    return features.enabled(SWITCH) or (os.environ.get(PUSH_ENV) or "").strip() == "1"


def require_active() -> None:
    """投递面（enqueue / pull）的闸门：关闭时 503 / ``50001``（fail-closed，不静默排队）。"""
    if not enabled():
        raise errors.StoreUnavailable(
            "节点通知队列未启用（notify.node_push.enabled=false 且未设 DJB_NODE_PUSH=1）",
            reason="node_push_disabled")


# --------------------------------------------------------------------------- 校验
def _now(now: datetime | None) -> datetime:
    return clock.to_utc(now) or clock.now()


def _limit(value: Any) -> int:
    if value is None:
        return DEFAULT_LIMIT
    if isinstance(value, bool):                        # bool 是 int 子类，先挡掉
        raise errors.InvalidArgument("limit 必须是整数", field="limit")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument("limit 必须是整数", field="limit") from exc
    if number < 1 or number > MAX_LIMIT:
        raise errors.InvalidArgument(f"limit 必须在 1–{MAX_LIMIT}", field="limit")
    return number


def _choice(value: Any, allowed: Iterable[str], *, field: str) -> str:
    text = str(value or "").strip()
    if text not in tuple(allowed):
        raise errors.InvalidArgument(f"{field} 必须是 {tuple(allowed)} 之一", field=field)
    return text


def _template_key(value: Any) -> str:
    text = str(value or "").strip()
    if not _TEMPLATE_RE.match(text):
        raise errors.InvalidArgument("template_key 只能是 [a-z0-9_.-]、长度 1–64",
                                     field="template_key")
    return text


def _node_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 128:
        raise errors.InvalidArgument("node_id 必填且长度 ≤128", field="node_id")
    return text


def _optional_uuid(value: Any, *, field: str) -> uuid.UUID | None:
    if value in (None, ""):
        return None
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError) as exc:
        raise errors.InvalidArgument(f"{field} 必须是 UUID", field=field) from exc


def _optional_text(value: Any, *, field: str, max_length: int) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text or len(text) > max_length:
        raise errors.InvalidArgument(f"{field} 长度必须在 1–{max_length}", field=field)
    return text


def _clean_value(key: str, value: Any) -> Any:
    """payload 值只允许标量或标量列表；字符串不得是邮箱 / 手机号（INV-07）。"""
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            if len(value) > 128:
                raise errors.InvalidArgument(f"payload[{key}] 字符串超长（≤128）", field="payload")
            if facts.looks_like_email(value) or facts.looks_like_phone(value):
                raise errors.InvalidArgument(f"payload[{key}] 疑似邮箱 / 手机号（INV-07）",
                                             field="payload")
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > 16:
            raise errors.InvalidArgument(f"payload[{key}] 列表过长（≤16）", field="payload")
        return [_clean_value(key, item) for item in value]
    raise errors.InvalidArgument(f"payload[{key}] 只允许标量或标量列表", field="payload")


def validate_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    """白名单 + PII 黑名单 + 值形态（DB 约束是兜底，这里是第一道闸）。"""
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise errors.InvalidArgument("payload 必须是对象", field="payload")
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise errors.InvalidArgument("payload 键必须是字符串", field="payload")
        lowered = key.lower()
        if lowered in FORBIDDEN_KEYS:
            raise errors.InvalidArgument(f"payload 含 PII / 正文 / 凭据键：{key!r}（INV-07）",
                                         field="payload")
        if not _KEY_RE.match(lowered) or lowered not in ALLOWED_PAYLOAD_KEYS:
            raise errors.InvalidArgument(f"payload 键未登记：{key!r}", field="payload")
        cleaned[lowered] = _clean_value(lowered, value)
    return cleaned


# --------------------------------------------------------------------------- 行 → API
def _api(row: Mapping[str, Any]) -> dict[str, Any]:
    """spec 1.2.13 通知形状（pull 项）：只放 id / 级别 / 分类 / 模板 / payload / 时间。"""
    return {
        "id": str(row["id"]),
        "severity": row["severity"],
        "category": row["category"],
        "template_key": row["template_key"],
        "payload": dict(row["payload"] or {}),
        "created_at": clock.isoformat(row["created_at"]),
        "expires_at": clock.isoformat(row["expires_at"]),
        "read_at": clock.isoformat(row["read_at"]),
    }


def _admin_api(row: Mapping[str, Any]) -> dict[str, Any]:
    """管理面：通知形状 + 队列状态与投递次数（排障用，无正文）。"""
    payload = _api(row)
    payload.update({
        "node_id": row["node_id"],
        "state": row["state"],
        "delivered_at": clock.isoformat(row["delivered_at"]),
        "dedupe_key": row["dedupe_key"],
        "source_event_id": None if row["source_event_id"] is None
        else str(row["source_event_id"]),
        "deliveries": int(row.get("deliveries") or 0),
    })
    return payload


_SELECT_COLUMNS = ("id, node_id, severity, category, template_key, payload, state, dedupe_key,"
                   " source_event_id, created_at, expires_at, delivered_at, read_at")


# --------------------------------------------------------------------------- 入队
def enqueue(conn: Any, node_id: Any, severity: Any, category: Any, template_key: Any,
            payload: Mapping[str, Any] | None = None, *, dedupe_key: Any = None,
            source_event_id: Any = None, now: datetime | None = None,
            expires_at: datetime | None = None) -> dict[str, Any]:
    """入队一条节点通知（幂等）：重复 ``dedupe_key`` / ``source_event_id`` 返回既有行。"""
    require_active()
    node = _node_id(node_id)
    level = _choice(severity, SEVERITIES, field="severity")
    kind = _choice(category, CATEGORIES, field="category")
    template = _template_key(template_key)
    cleaned = validate_payload(payload)
    dedupe = _optional_text(dedupe_key, field="dedupe_key", max_length=200)
    source_event = _optional_uuid(source_event_id, field="source_event_id")
    moment = _now(now)
    expiry = clock.to_utc(expires_at)
    if level == "P0":
        if expiry is None:
            raise errors.InvalidArgument("P0 通知必须带 expires_at（不允许长期悬挂）",
                                          field="expires_at")
        if expiry > moment + timedelta(days=P0_MAX_TTL_DAYS):
            raise errors.InvalidArgument(f"P0 的 expires_at 不得超过 {P0_MAX_TTL_DAYS} 天",
                                          field="expires_at")
    if expiry is not None and expiry <= moment:
        raise errors.InvalidArgument("expires_at 必须晚于当前时间", field="expires_at")

    notification_id = uuid.uuid4()
    with dict_cursor(conn) as cur:
        cur.execute(
            "INSERT INTO node_notifications"
            " (id, node_id, severity, category, template_key, payload, dedupe_key, state,"
            "  source_event_id, created_at, expires_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued', %s, %s, %s)"
            " ON CONFLICT DO NOTHING RETURNING " + _SELECT_COLUMNS,
            (notification_id, node, level, kind, template, Jsonb(cleaned), dedupe,
             source_event, moment, expiry))
        inserted = cur.fetchone()
        if inserted is None:                            # 命中 dedupe / source_event → 幂等返回
            inserted = _find_existing(cur, node, dedupe, source_event)
            if inserted is None:                        # pragma: no cover - 竞态兜底
                raise errors.Conflict("节点通知入队冲突，请重试", reason="enqueue_conflict")
            return _admin_api(inserted)
        _record_event(cur, notification_id, "queued", detail=kind, now=moment)
    return _admin_api(inserted)


def _find_existing(cur: Any, node_id: str, dedupe_key: str | None,
                   source_event_id: uuid.UUID | None) -> Mapping[str, Any] | None:
    """幂等找回：优先 dedupe_key（同节点），其次 source_event_id（全局）。"""
    if dedupe_key is not None:
        cur.execute("SELECT " + _SELECT_COLUMNS + " FROM node_notifications"
                    " WHERE node_id = %s AND dedupe_key = %s", (node_id, dedupe_key))
        row = cur.fetchone()
        if row is not None:
            return row
    if source_event_id is not None:
        cur.execute("SELECT " + _SELECT_COLUMNS + " FROM node_notifications"
                    " WHERE source_event_id = %s", (source_event_id,))
        return cur.fetchone()
    return None


# --------------------------------------------------------------------------- 拉取
def pull(conn: Any, node_id: Any, *, since: Any = None, limit: Any = DEFAULT_LIMIT,
         category: Any = None, include_read: bool = False, channel: str = "pull",
         now: datetime | None = None) -> dict[str, Any]:
    """节点拉取：``{items, has_more, next_cursor}``；顺带把命中的行标 ``delivered``。"""
    require_active()
    node = _node_id(node_id)
    size = _limit(limit)
    moment = _now(now)
    kind = None if category in (None, "") else _choice(category, CATEGORIES, field="category")
    if channel not in DELIVERY_CHANNELS:                # pragma: no cover - 编程错误
        raise ValueError(f"未知投递渠道：{channel!r}")

    states = ("queued", "delivered", "read") if include_read else ("queued", "delivered")
    where = ["node_id = %s", "state = ANY(%s)", "(expires_at IS NULL OR expires_at > %s)"]
    params: list[Any] = [node, list(states), moment]
    if kind is not None:
        where.append("category = %s")
        params.append(kind)
    if since not in (None, ""):
        created_at, notification_id = decode_cursor(str(since))
        where.append("(created_at, id) > (%s, %s)")
        params.extend([created_at, notification_id])
    params.append(size + 1)                             # 多取一条判断 has_more

    with dict_cursor(conn) as cur:
        cur.execute("SELECT " + _SELECT_COLUMNS + " FROM node_notifications"
                    " WHERE " + " AND ".join(where) +
                    " ORDER BY created_at, id LIMIT %s", tuple(params))
        rows = cur.fetchall()
        has_more = len(rows) > size
        items = rows[:size]
        for row in items:
            if row["state"] in ("queued", "delivered"):
                _mark_delivered(cur, row, channel=channel, now=moment)
    next_cursor = (encode_cursor(items[-1]["created_at"], items[-1]["id"])
                   if items else None)
    return {"items": [_api(row) for row in items], "has_more": has_more,
            "next_cursor": next_cursor}


def _mark_delivered(cur: Any, row: Mapping[str, Any], *, channel: str,
                    now: datetime) -> None:
    """首次交付：state → delivered（已 delivered 的不重复改），追加投递行 + 事件。"""
    if row["state"] == "queued":
        cur.execute("UPDATE node_notifications SET state = 'delivered',"
                    " delivered_at = COALESCE(delivered_at, %s) WHERE id = %s",
                    (now, row["id"]))
    cur.execute("SELECT count(*) AS n FROM node_notification_deliveries"
                " WHERE notification_id = %s", (row["id"],))
    attempt = int(cur.fetchone()["n"]) + 1
    _record_delivery(cur, row["id"], channel=channel, attempt=attempt, status="success",
                     error_class=None, now=now)
    _record_event(cur, row["id"], "delivered", detail=channel, now=now)


# --------------------------------------------------------------------------- 消费确认
def _fetch(conn: Any, node_id: str, notification_id: Any) -> tuple[Any, Mapping[str, Any] | None]:
    try:
        wanted = uuid.UUID(str(notification_id))
    except (TypeError, ValueError):
        return None, None
    cur = dict_cursor(conn)
    cur.execute("SELECT " + _SELECT_COLUMNS + " FROM node_notifications"
                " WHERE id = %s AND node_id = %s FOR UPDATE", (wanted, node_id))
    return cur, cur.fetchone()


def _has_event(cur: Any, notification_id: uuid.UUID, event: str) -> bool:
    cur.execute("SELECT 1 FROM node_notification_events WHERE notification_id = %s"
                " AND event = %s LIMIT 1", (notification_id, event))
    return cur.fetchone() is not None


def ack(conn: Any, node_id: Any, notification_id: Any, *, now: datetime | None = None
        ) -> dict[str, Any]:
    """节点确认（幂等）：``{accepted, state}``；跨节点 / 不存在 → 404（不泄露存在性）。"""
    node = _node_id(node_id)
    moment = _now(now)
    cur, row = _fetch(conn, node, notification_id)
    if row is None:
        raise errors.NotFound("通知不存在")
    if row["state"] == "expired":
        raise errors.Conflict("通知已过期", reason="state_conflict")
    if row["state"] in ("delivered", "read"):
        if not _has_event(cur, row["id"], "acked"):
            _record_event(cur, row["id"], "acked", detail="after_delivery", now=moment)
        return {"accepted": True, "state": row["state"]}
    cur.execute("UPDATE node_notifications SET state = 'delivered',"
                " delivered_at = COALESCE(delivered_at, %s) WHERE id = %s", (moment, row["id"]))
    _record_event(cur, row["id"], "acked", detail="from_queued", now=moment)
    return {"accepted": True, "state": "delivered"}


def read(conn: Any, node_id: Any, notification_id: Any, *, now: datetime | None = None
         ) -> dict[str, Any]:
    """节点标记已读（幂等；**read 隐含 ack**）：``{accepted, state}``。"""
    node = _node_id(node_id)
    moment = _now(now)
    cur, row = _fetch(conn, node, notification_id)
    if row is None:
        raise errors.NotFound("通知不存在")
    if row["state"] == "expired":
        raise errors.Conflict("通知已过期", reason="state_conflict")
    if row["state"] == "read":
        return {"accepted": True, "state": "read"}
    if not _has_event(cur, row["id"], "acked"):
        _record_event(cur, row["id"], "acked", detail="implicit_by_read", now=moment)
    cur.execute("UPDATE node_notifications SET state = 'read',"
                " delivered_at = COALESCE(delivered_at, %s), read_at = %s WHERE id = %s",
                (moment, moment, row["id"]))
    _record_event(cur, row["id"], "read", detail=None, now=moment)
    return {"accepted": True, "state": "read"}


def unread_count(conn: Any, node_id: Any, *, now: datetime | None = None) -> int:
    """该节点「未读且未过期」的条数（含已投递未读）。"""
    node = _node_id(node_id)
    moment = _now(now)
    with dict_cursor(conn) as cur:
        cur.execute("SELECT count(*) AS n FROM node_notifications"
                    " WHERE node_id = %s AND state IN ('queued', 'delivered')"
                    " AND (expires_at IS NULL OR expires_at > %s)", (node, moment))
        return int(cur.fetchone()["n"])


# --------------------------------------------------------------------------- 过期 / 运维
def expire_due(conn: Any, *, now: datetime | None = None) -> int:
    """把到期的 queued/delivered 置 ``expired`` 并留事件；返回处理条数。"""
    moment = _now(now)
    with dict_cursor(conn) as cur:
        cur.execute("UPDATE node_notifications SET state = 'expired'"
                    " WHERE state IN ('queued', 'delivered')"
                    " AND expires_at IS NOT NULL AND expires_at <= %s RETURNING id", (moment,))
        expired = [row["id"] for row in cur.fetchall()]
        for notification_id in expired:
            _record_event(cur, notification_id, "expired", detail=None, now=moment)
    return len(expired)


def list_for_admin(conn: Any, *, node_id: Any = None, state: Any = None,
                   limit: Any = DEFAULT_LIMIT, cursor: Any = None,
                   now: datetime | None = None) -> dict[str, Any]:
    """管理面列表（投递状态排障）：``{items, has_more, next_cursor}``，按创建时间倒序。"""
    size = _limit(limit)
    moment = _now(now)
    where = ["TRUE"]
    params: list[Any] = []
    if node_id not in (None, ""):
        where.append("node_id = %s")
        params.append(_node_id(node_id))
    if state not in (None, ""):
        where.append("state = %s")
        params.append(_choice(state, STATES, field="state"))
    if cursor not in (None, ""):
        created_at, notification_id = decode_cursor(str(cursor))
        where.append("(created_at, id) < (%s, %s)")
        params.extend([created_at, notification_id])
    params.append(size + 1)
    with dict_cursor(conn) as cur:
        cur.execute(
            "SELECT " + _SELECT_COLUMNS + ","
            " (SELECT count(*) FROM node_notification_deliveries d"
            "   WHERE d.notification_id = node_notifications.id) AS deliveries"
            " FROM node_notifications WHERE " + " AND ".join(where) +
            " ORDER BY created_at DESC, id DESC LIMIT %s", tuple(params))
        rows = cur.fetchall()
    has_more = len(rows) > size
    items = rows[:size]
    next_cursor = (encode_cursor(items[-1]["created_at"], items[-1]["id"])
                   if items else None)
    return {"items": [_admin_api(row) for row in items], "has_more": has_more,
            "next_cursor": next_cursor, "now": clock.isoformat(moment)}


# --------------------------------------------------------------------------- 内部写入
def _record_delivery(cur: Any, notification_id: uuid.UUID, *, channel: str, attempt: int,
                     status: str, error_class: str | None, now: datetime) -> None:
    cur.execute("INSERT INTO node_notification_deliveries"
                " (id, notification_id, channel, attempt, status, error_class, created_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (uuid.uuid4(), notification_id, channel, int(attempt), status, error_class,
                 now))


def _record_event(cur: Any, notification_id: uuid.UUID, event: str, *,
                  detail: str | None, now: datetime) -> None:
    cur.execute("INSERT INTO node_notification_events"
                " (id, notification_id, event, detail, created_at)"
                " VALUES (%s, %s, %s, %s, %s)",
                (uuid.uuid4(), notification_id, event, detail, now))
