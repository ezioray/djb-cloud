# SPDX-License-Identifier: Apache-2.0
"""M02 §4.1 会话态节点面（spec 1.2.6）：我的节点列表 / 解绑。

覆盖 **1.2.6 新增的两条用户态端点**（归属 M02，鉴权 userBearer；节点侧仍走 ``/api/v1/node/*``）::

    GET  /api/v1/user/nodes                            listUserNodes    200
    POST /api/v1/user/nodes/{node_id}/unbind           unbindUserNode   200

口径（spec ``UserNode`` / ``UserNodePage`` / M02 §4.1）：

* **只读本账户**：``bound_account_id = 账户`` 或 ``account_id = 账户``；解绑后
  ``account_id`` 置 NULL 但 ``bound_account_id`` 保留（历史可见，``state=revoked``）。
* **state 映射**（绑定视图，不新增库列）::

      无绑定                → unbound
      M02 pending           → pending_receipt
      M02 active            → bound
      M02 frozen            → bound + restricted=true
      M02 retired / 已解绑   → revoked

  ``lifecycle_state`` 是 M02 权威生命周期（``nodes.state`` / 生成列 ``lifecycle_state``）；
  两个字段不一致时以 M02 心跳与 ``node_events`` 为准（spec 描述）。
* **applied_version**：M02 目前不落 M10 的 ``applied_version``（由 M15 心跳上报、M10 侧记录），
  未回传一律 ``null``（spec：「未回传为 null」）；不猜、不用 ``client_version`` 冒充。
* **游标分页**：按最近心跳倒序、无心跳排后（``last_seen_at DESC NULLS LAST, id DESC``），
  游标是不透明串（base64url），不得用 offset（00-conventions §5）。
* **解绑幂等**：已解绑再解绑返回同一结果（``state=revoked``；``bound_at`` 保留、
  ``unbound_at`` 不变），不追加事件；解绑同时撤销节点客户端密钥（INV-08：立即停单，
  在途任务允许完成，历史收据 / 锁定收益不删——本模块不碰 M05/M06 数据）。
* **越权一律 404/40401**（不泄露节点是否存在）；``retired`` → 40902，``frozen`` → 40903
  （spec 1.2.6 unbind 描述：状态不允许 → 409）；未准入 / 未绑定 → 40305（同 M02 §7）。
"""
from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from . import clock, events, facts, models
from .errors import (
    BindingConflict,
    InvalidArgument,
    NodeNotFound,
    NodeStateForbidden,
    RetireIrreversible,
)

#: 列表返回列（顺序即下游序列化顺序；不含任何密钥材料）
_VIEW_COLUMNS: tuple[str, ...] = (
    "id", "state", "last_seen_at", "bound_account_id", "bound_at", "revoked_at", "account_id",
)
_COLUMNS_SQL = ", ".join(_VIEW_COLUMNS)

#: 绑定视图状态的 SQL 投影（与 :func:`view_state` 逐条同义；只读推导，不落库）
_VIEW_STATE_SQL = """
        CASE
            WHEN revoked_at IS NOT NULL OR state = 'retired' THEN 'revoked'
            WHEN bound_account_id IS NULL THEN 'unbound'
            WHEN state = 'pending' THEN 'pending_receipt'
            ELSE 'bound'
        END AS view_state
"""

#: 归属：绑定列是主口径；``account_id`` 兼容 003 存量（只加不改，不 backfill）
_OWNERSHIP_SQL = "(bound_account_id = %(account_id)s OR account_id = %(account_id)s)"

_SELECT_SQL = f"""
    SELECT t.id, t.state, t.last_seen_at, t.bound_account_id, t.bound_at, t.revoked_at,
           t.account_id, t.view_state
      FROM (
            SELECT {_COLUMNS_SQL}, {_VIEW_STATE_SQL}
              FROM nodes
             WHERE {_OWNERSHIP_SQL}
           ) AS t
     WHERE TRUE
"""

#: 解绑时读取的行（FOR UPDATE；同事务内更新 + 留痕）
_LOCK_SQL = f"""
    SELECT {_COLUMNS_SQL}
      FROM nodes
     WHERE id = %(node_id)s AND {_OWNERSHIP_SQL}
     FOR UPDATE
"""


# --------------------------------------------------------------------------- 工具
def _now(now: datetime | None) -> datetime:
    return now.astimezone(timezone.utc) if now else clock.utcnow()


def _get(source: Any, name: str) -> Any:
    """行（Mapping）或 :class:`models.Node` 统一取值。"""
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _dict_rows(cur: Any) -> list[dict[str, Any]]:
    return [dict(zip([item.name for item in cur.description], row)) for row in cur.fetchall()]


def _one(cur: Any) -> dict[str, Any] | None:
    row = cur.fetchone()
    return None if row is None else dict(zip([item.name for item in cur.description], row))


# --------------------------------------------------------------------------- 视图推导
def view_state(*, state: str, bound_account_id: Any, revoked_at: Any) -> str:
    """绑定视图状态（纯函数，与 ``_VIEW_STATE_SQL`` 同义；单测用它对照 SQL 结果）。"""
    if revoked_at is not None or state == "retired":
        return "revoked"
    if bound_account_id is None:
        return "unbound"
    if state == "pending":
        return "pending_receipt"
    return "bound"


def pending_reason(state: str, view: str) -> str | None:
    """pending / pending_receipt 的**粗粒度**原因（不含规则、名单或内部判定）。"""
    if view == "pending_receipt":
        return "awaiting_receipt"
    if view == "unbound" and state == "pending":
        return "awaiting_review"
    return None


def node_view(source: Any) -> dict[str, Any]:
    """spec ``UserNode`` 形状（时间 RFC 3339 UTC；``applied_version`` 暂无来源即 null）。"""
    state = str(_get(source, "state") or "")
    bound_account_id = _get(source, "bound_account_id")
    revoked_at = _get(source, "revoked_at")
    view = view_state(state=state, bound_account_id=bound_account_id, revoked_at=revoked_at)
    return {
        "node_id": str(_get(source, "id") or ""),
        "state": view,
        "lifecycle_state": state,
        "last_seen": models.iso(_get(source, "last_seen_at")),
        "applied_version": None,
        "pending_reason": pending_reason(state, view),
        "restricted": state == "frozen" and view == "bound",
        "bound_at": models.iso(_get(source, "bound_at")),
        "unbound_at": models.iso(revoked_at),
    }


# --------------------------------------------------------------------------- 游标
def encode_cursor(row: Mapping[str, Any] | Any) -> str:
    """游标 = base64url(``<last_seen ISO|->|<node_id>``)；不加密，由服务端生成。"""
    moment = models.iso(_get(row, "last_seen_at")) or "-"
    raw = f"{moment}|{_get(row, 'id')}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime | None, str]:
    """解析游标；非法 / 超长 / 结构不对 → 400/40001（不泄露内部字段名）。"""
    if not isinstance(cursor, str) or not cursor:
        raise InvalidArgument("cursor 不能为空", field="cursor")
    if len(cursor) > facts.USER_NODE_MAX_CURSOR_LEN:
        raise InvalidArgument("cursor 超长", field="cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise InvalidArgument("cursor 非法", field="cursor") from exc
    moment_text, _, node_id = raw.partition("|")
    if not node_id or len(node_id) > facts.MAX_NODE_ID_LEN:      # 与 DDL 同量级，防超长串
        raise InvalidArgument("cursor 非法", field="cursor")
    if moment_text == "-":
        return None, node_id
    try:
        normalised = moment_text[:-1] + "+00:00" if moment_text.endswith(("Z", "z")) \
            else moment_text
        moment = datetime.fromisoformat(normalised).astimezone(timezone.utc)
    except ValueError as exc:
        raise InvalidArgument("cursor 非法", field="cursor") from exc
    return moment, node_id


# --------------------------------------------------------------------------- 列表
def _account_uuid(account_id: Any) -> uuid.UUID:
    if isinstance(account_id, uuid.UUID):
        return account_id
    try:
        return uuid.UUID(str(account_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise InvalidArgument("account_id 必须是 UUID", field="account_id") from exc


def list_page(c: Any, *, account_id: Any, state: Any = None, lifecycle_state: Any = None,
              cursor: str | None = None, limit: int | None = None) -> dict[str, Any]:
    """我的节点分页（只读；默认 50、上限 200；``has_more`` + ``next_cursor``）。"""
    account = _account_uuid(account_id)
    if state is not None and state not in facts.USER_NODE_VIEW_STATES:
        raise InvalidArgument("state 取值非法", field="state",
                              allowed=list(facts.USER_NODE_VIEW_STATES))
    if lifecycle_state is not None and lifecycle_state not in facts.NODE_STATES:
        raise InvalidArgument("lifecycle_state 取值非法", field="lifecycle_state",
                              allowed=list(facts.NODE_STATES))
    page_size = facts.USER_NODE_DEFAULT_PAGE_SIZE if limit is None else int(limit)
    if page_size < 1 or page_size > facts.USER_NODE_MAX_PAGE_SIZE:
        raise InvalidArgument(
            f"limit 必须是 1..{facts.USER_NODE_MAX_PAGE_SIZE}", field="limit")

    where: list[str] = []
    params: dict[str, Any] = {"account_id": account, "limit": page_size + 1}
    if state is not None:
        where.append("t.view_state = %(view_state)s")
        params["view_state"] = state
    if lifecycle_state is not None:
        where.append("t.state = %(lifecycle_state)s")
        params["lifecycle_state"] = lifecycle_state
    if isinstance(cursor, str) and cursor:
        moment, node_id = decode_cursor(cursor)
        params["cursor_id"] = node_id
        if moment is None:
            where.append("(t.last_seen_at IS NULL AND t.id < %(cursor_id)s)")
        else:
            params["cursor_ts"] = moment
            # 非空心跳段之后才是「无心跳」段：无心跳行在游标之后继续参与分页
            where.append("(t.last_seen_at IS NULL"
                         " OR t.last_seen_at < %(cursor_ts)s"
                         " OR (t.last_seen_at = %(cursor_ts)s AND t.id < %(cursor_id)s))")

    clause = f" AND {' AND '.join(where)}" if where else ""
    sql = (f"{_SELECT_SQL}{clause} "
           "ORDER BY t.last_seen_at DESC NULLS LAST, t.id DESC LIMIT %(limit)s")
    with c.cursor() as cur:
        cur.execute(sql, params)
        rows = _dict_rows(cur)

    has_more = len(rows) > page_size
    page_rows = rows[:page_size]
    next_cursor = encode_cursor(page_rows[-1]) if (has_more and page_rows) else None
    return {
        "data": [node_view(row) for row in page_rows],
        "page": {"cursor": str(cursor or ""), "has_more": has_more,
                 "next_cursor": next_cursor},
    }


# --------------------------------------------------------------------------- 解绑
def _validate_reason(reason: Any) -> str | None:
    if reason is None:
        return None
    if not isinstance(reason, str):
        raise InvalidArgument("reason 必须是字符串", field="reason")
    text = reason.strip()
    if not text:
        return None
    if len(text) > facts.USER_UNBIND_REASON_MAX_LEN:
        raise InvalidArgument(
            f"reason 最多 {facts.USER_UNBIND_REASON_MAX_LEN} 字符", field="reason")
    return text


def unbind(c: Any, *, node_id: Any, account_id: Any, reason: Any = None,
           now: datetime | None = None, trace_id: str = "") -> dict[str, Any]:
    """解绑本账户节点（幂等；撤销客户端密钥；同事务写 ``node_events`` + outbox）。

    返回 spec ``UserNode`` 视图。**所有权先判**：不属于本账户的节点一律 404/40401，
    与「不存在」不可区分（不泄露存在性）。
    """
    moment = _now(now)
    if not isinstance(node_id, str) or not node_id.strip():
        raise InvalidArgument("node_id 必填", field="node_id")
    identifier = node_id.strip()
    if len(identifier) > facts.MAX_NODE_ID_LEN:
        raise InvalidArgument("node_id 超长", field="node_id")
    account = _account_uuid(account_id)
    reason_text = _validate_reason(reason)

    with c.cursor() as cur:
        cur.execute(_LOCK_SQL, {"node_id": identifier, "account_id": account})
        row = _one(cur)
    if row is None:
        raise NodeNotFound("节点不存在", node_id=identifier)

    state = str(row["state"])
    if row["revoked_at"] is not None:                    # 幂等：已解绑直接回同一结果
        return node_view(row)
    if state == "retired":
        raise RetireIrreversible("节点已清退，不可解绑（INV-09）", node_id=identifier)
    if state == "frozen":
        raise BindingConflict("节点已冻结，不可解绑（M02 §4.1）", reason="node_frozen",
                              state=state)
    if row["bound_account_id"] is None:
        raise NodeStateForbidden("节点未绑定，无需解绑", state=state, action="unbind")

    with c.cursor() as cur:
        cur.execute(
            """UPDATE nodes
                  SET revoked_at = %(moment)s,
                      account_id = NULL,
                      key_revoked_at = %(moment)s,
                      prev_key_expires_at = CASE
                          WHEN prev_key_hash IS NULL THEN prev_key_expires_at
                          WHEN prev_key_expires_at IS NULL THEN prev_key_expires_at
                          ELSE LEAST(prev_key_expires_at, %(moment)s)
                      END,
                      updated_at = %(moment)s
                WHERE id = %(node_id)s""",
            {"moment": moment, "node_id": identifier})
    causes = models.append_node_event(
        c, node_id=identifier, kind="unbound", from_state=state, to_state=state,
        reason_code="unbound",
        reason=reason_text[:facts.NODE_EVENT_REASON_MAX_LEN] if reason_text else None,
        actor=f"account:{account}",
        payload={"account_id": str(account), "key_revoked": True}, now=moment)
    events.node_state_changed(c, node_id=identifier, from_state=state, to_state=state,
                              reason="unbound", trace_id=trace_id, occurred_at=moment,
                              causation_id=causes)
    refreshed = models.get_node(c, identifier)
    return node_view(refreshed)


__all__ = ["view_state", "pending_reason", "node_view", "encode_cursor", "decode_cursor",
           "list_page", "unbind"]
