# SPDX-License-Identifier: AGPL-3.0-or-later
"""M02 状态机（M02 §3「一层权威 + 一层派生，不得混用」）。

**权威层**：``nodes.lifecycle_state``（= 存量列 ``state``）四态机::

    pending ──准入通过──▶ active ⇄ frozen ──清退──▶ retired（不可逆）

| 状态 | 心跳 | 接新单 | 出状态 |
| pending | 403 未准入 | ❌ | 审核通过 → active；驳回保留 pending |
| active | 200 | ✅ | 风控 / 审核 → frozen；清退 → retired |
| frozen | 403 只读 | ❌ | 解冻 → active；清退 → retired |
| retired | 403 | ❌ | 不可逆（重装 = 新注册 + 新 node_id） |

**派生层**（只读视图，**不落库**）::

    last_seen ≤ stale_after_s        → online
    last_seen ≤ 3 × heartbeat_interval → stale
    其余（超过 3 个周期）             → offline
    从未上报（last_seen 为 NULL）     → never（只由 derive_presence 返回）

派生层不得被写回（不存在 online/stale/offline 状态列），也不得参与状态迁移判定。
"""
from __future__ import annotations

from datetime import datetime, timedelta

from . import facts
from .errors import InvalidArgument, NodeStateForbidden

#: 合法迁移（M02 §3 + §6.1/§6.6）
TRANSITIONS: dict[str, frozenset[str]] = {
    "pending": frozenset({"active"}),                 # 只有准入通过能离开 pending
    "active": frozenset({"frozen", "retired"}),       # 风控冻结 / 清退
    "frozen": frozenset({"active", "retired"}),       # 解冻 / 清退
    "retired": frozenset(),                           # 不可逆
}

#: 状态 → 该状态下允许的动作（40305 的 details 用；只描述语义，不做鉴权）
_ALLOWED_ACTIONS: dict[str, tuple[str, ...]] = {
    "pending": ("await_review",),
    "active": ("heartbeat", "announce", "declare_upstream", "bind", "unbind", "rotate_key",
               "fetch_policy"),
    "frozen": ("fetch_policy", "read_only"),
    "retired": ("none",),
}


def is_state(state: str) -> bool:
    return state in facts.NODE_STATES


def legal_targets(state: str) -> tuple[str, ...]:
    """当前状态的合法目标态（按 ``facts.NODE_STATES`` 顺序，便于稳定断言）。"""
    targets = TRANSITIONS.get(state, frozenset())
    return tuple(item for item in facts.NODE_STATES if item in targets)


def can_transition(src: str, dst: str) -> bool:
    return dst in TRANSITIONS.get(src, frozenset())


def allowed_actions(state: str) -> tuple[str, ...]:
    return _ALLOWED_ACTIONS.get(state, ())


def require_transition(src: str, dst: str) -> None:
    """非法迁移 → 40305（M02 §3 / §4.1 的管理面审核：403 + ``40305``）。"""
    if is_state(src) is False:
        raise InvalidArgument(f"未知状态 {src!r}", field="state")
    if not can_transition(src, dst):
        raise NodeStateForbidden(
            f"节点状态 {src} 不允许迁移到 {dst}（M02 §3）",
            state=src, target=dst, allowed=legal_targets(src))


def require_state(state: str, expected: str, *, action: str) -> None:
    """动作前置状态不满足 → 40305 + 当前状态与可做动作（§7 失败矩阵）。"""
    if state != expected:
        raise NodeStateForbidden(
            f"节点当前状态 {state} 不允许 {action}",
            state=state, action=action, required=expected,
            allowed_actions=list(allowed_actions(state)))


def require_active(state: str, *, action: str) -> None:
    """INV-02：``lifecycle_state ≠ active`` 时心跳 / 公告 / upstream 申报一律拒绝。"""
    require_state(state, "active", action=action)


def is_retired(state: str) -> bool:
    return state == "retired"


# --------------------------------------------------------------------------- 派生层
def derive_presence(last_seen_at: datetime | None, now: datetime, *,
                    heartbeat_interval_s: int = facts.HEARTBEAT_INTERVAL_S,
                    stale_after_s: int = facts.STALE_AFTER_S) -> str:
    """在线派生（只读）：``never`` / ``online`` / ``stale`` / ``offline``（M02 §3）。

    阈值来自 M02 §8.1 / §8.2，运行时由 config-center 下发后作为参数传入（T3 接线）。
    """
    if heartbeat_interval_s <= 0 or stale_after_s <= 0:
        raise InvalidArgument("心跳周期与 stale 阈值必须为正整数", field="heartbeat_interval_s")
    if last_seen_at is None:
        return "never"
    age = now - last_seen_at
    if age <= timedelta(seconds=stale_after_s):
        return "online"
    if age <= timedelta(seconds=facts.OFFLINE_AFTER_CYCLES * heartbeat_interval_s):
        return "stale"
    return "offline"


def derive_online(last_seen_at: datetime | None, now: datetime, *,
                  heartbeat_interval_s: int = facts.HEARTBEAT_INTERVAL_S,
                  stale_after_s: int = facts.STALE_AFTER_S) -> str:
    """派生视图的三值形态（``never`` 归入 ``offline``，供 M04 候选集过滤使用）。"""
    presence = derive_presence(last_seen_at, now, heartbeat_interval_s=heartbeat_interval_s,
                              stale_after_s=stale_after_s)
    return "offline" if presence == "never" else presence


def routable(state: str, last_seen_at: datetime | None, now: datetime, *,
             heartbeat_interval_s: int = facts.HEARTBEAT_INTERVAL_S,
             stale_after_s: int = facts.STALE_AFTER_S) -> bool:
    """能否接新单（M02 §3 表 + INV-02/INV-07）：只有 active 且未离线。"""
    return state == "active" and derive_online(
        last_seen_at, now, heartbeat_interval_s=heartbeat_interval_s,
        stale_after_s=stale_after_s) == "online"


__all__ = [
    "TRANSITIONS", "is_state", "legal_targets", "can_transition", "allowed_actions",
    "require_transition", "require_state", "require_active", "is_retired",
    "derive_presence", "derive_online", "routable",
]
