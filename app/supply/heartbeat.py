# SPDX-License-Identifier: Apache-2.0
"""心跳（M02 §6.2 / INV-02 / §7 心跳限流 / CR-5 runtime_state）。

流程（同事务：``capacity_announcements`` + ``nodes`` + ``supply_outbox``）::

    鉴权（router）→ 状态必须 active（40305）→ 协议版本（42601）→ 限流（42901）
    → 公告落库（seq 递增）→ last_seen_at / runtime_state → 返回 next_heartbeat_seconds 与
    policy_updated

不做的两件事（写进代码也写进证据）：

* **不触发同步 fan-out**：M04 从快照视图 / 事件读（M02 §6.2）；
* **不把运行态落成枚举**：``runtime_state`` 只是可选自述，未知值忽略不报错，
  且受特性开关 ``supply.heartbeat_runtime_state`` 控制（默认关闭，T1/T2 已登记契约）。
"""
from __future__ import annotations

import dataclasses
import logging
import math
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from . import (capacity, clock, config_source, facts, features, models, protocol,
               state as state_machine)
from .errors import HeartbeatTooFast, InvalidArgument

log = logging.getLogger("djb.supply.heartbeat")

RUNTIME_STATE_SWITCH = "supply.heartbeat_runtime_state"


@dataclasses.dataclass(frozen=True)
class HeartbeatResult:
    node: Any                                   # models.Node（心跳后）
    server_time: datetime
    protocol_version: str
    policy_version: str
    next_heartbeat_seconds: int
    policy_updated: bool
    announcement: capacity.Announcement | None
    accepted: bool
    ignored_kinds: tuple[str, ...]
    runtime_state: str | None
    interval_s: int
    stale_after_s: int


def _now(now: datetime | None) -> datetime:
    return now.astimezone(timezone.utc) if now else clock.utcnow()


def _check_load(load: Any) -> None:
    """``load`` 只做形态校验（仅调度输入；不落库、不进信誉分）。"""
    if load is None:
        return
    if not isinstance(load, Mapping):
        raise InvalidArgument("load 必须是对象", field="load")
    inflight = load.get("inflight")
    if inflight is not None and (isinstance(inflight, bool) or not isinstance(inflight, int)
                                 or inflight < 0):
        raise InvalidArgument("load.inflight 必须是非负整数", field="load.inflight")
    queue_seconds = load.get("queue_seconds")
    if queue_seconds is not None:
        if isinstance(queue_seconds, bool) or not isinstance(queue_seconds, (int, float)) \
                or not math.isfinite(float(queue_seconds)) or float(queue_seconds) < 0:
            raise InvalidArgument("load.queue_seconds 必须是非负数", field="load.queue_seconds")


def pulse(c, *, node, protocol_version: Any, policy_version: Any,
          runtime_state: Any = None, capacity_entries: Sequence[Any] | None = None,
          load: Any = None, now: datetime | None = None, trace_id: str = "") -> HeartbeatResult:
    """心跳 + 本轮容量公告（M02 §6.2）。"""
    moment = _now(now)
    state_machine.require_active(node.state, action="heartbeat")     # INV-02 → 40305
    protocol.check(protocol_version)                                  # INV-05 → 42601
    _check_load(load)

    values = config_source.load(c, node)
    interval_s = config_source.heartbeat_interval_s(values)
    stale_after = config_source.stale_after_s(values)
    ttl_s = config_source.announcement_ttl_s(values)

    # 心跳限流（§7：每节点 5 s 一次，超限 42901）
    if node.last_seen_at is not None:
        elapsed = (moment - node.last_seen_at).total_seconds()
        if elapsed < facts.HEARTBEAT_MIN_INTERVAL_S:
            retry = max(1, int(math.ceil(facts.HEARTBEAT_MIN_INTERVAL_S - elapsed)))
            raise HeartbeatTooFast("心跳过于频繁", retry_after_s=retry,
                                   min_interval_s=facts.HEARTBEAT_MIN_INTERVAL_S)

    entries, ignored = ([], ())
    announcement: capacity.Announcement | None = None
    if capacity_entries is not None:
        entries, ignored = capacity.normalize(capacity_entries)
        announcement = capacity.record(c, node_id=node.id, entries=entries, ttl_seconds=ttl_s,
                                       now=moment)

    runtime_seen = None
    if features.enabled(RUNTIME_STATE_SWITCH):
        runtime_seen = _record_runtime_state(c, node, runtime_state, moment)

    with c.cursor() as cur:
        cur.execute(
            """UPDATE nodes
                  SET last_seen_at = %s, offline_announced_at = NULL, updated_at = %s
                WHERE id = %s""", (moment, moment, node.id))

    refreshed = models.get_node(c, node.id)
    policy_updated = isinstance(policy_version, str) \
        and policy_version.strip() != refreshed.policy_version

    if announcement is not None and announcement.accepted:
        models.emit_capacity_announced(
            c, node_id=node.id, announcement=announcement, trace_id=trace_id, moment=moment)

    log.info("supply.heartbeat", extra={"event": "node.heartbeat", "node_id": node.id,
                                        "accepted": announcement.accepted if announcement else None,
                                        "trace_id": trace_id})
    return HeartbeatResult(
        node=refreshed, server_time=moment,
        protocol_version=facts.PROTOCOL_VERSION,
        policy_version=refreshed.policy_version, next_heartbeat_seconds=interval_s,
        policy_updated=bool(policy_updated), announcement=announcement,
        accepted=bool(announcement.accepted) if announcement else False,
        ignored_kinds=ignored, runtime_state=runtime_seen,
        interval_s=interval_s, stale_after_s=stale_after)


def _record_runtime_state(c, node, value: Any, moment: datetime) -> str | None:
    """登记运行态自述（开关打开时才落库）；未知值忽略不报错。"""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text not in facts.RUNTIME_STATES:
        log.info("supply.heartbeat.runtime_state_ignored",
                 extra={"event": "heartbeat.runtime_state_ignored", "node_id": node.id})
        return None
    with c.cursor() as cur:
        cur.execute("UPDATE nodes SET runtime_state = %s, updated_at = %s WHERE id = %s",
                    (text, moment, node.id))
    return text


def heartbeat_payload(result: HeartbeatResult) -> dict[str, Any]:
    """spec ``NodeHeartbeatResponse`` + 可加字段（只加不改）。"""
    payload: dict[str, Any] = {
        "server_time": models.iso(result.server_time),
        "protocol_version": result.protocol_version,
        "policy_version": result.policy_version,
        "next_heartbeat_seconds": result.next_heartbeat_seconds,
        "policy_updated": result.policy_updated,
        "stale_after_seconds": result.stale_after_s,
    }
    if result.announcement is not None:
        payload["announcement"] = {
            "announcement_id": str(result.announcement.id),
            "seq": result.announcement.seq,
            "announced_at": models.iso(result.announcement.announced_at),
            "expires_at": models.iso(result.announcement.expires_at),
            "accepted": result.announcement.accepted,
            "capabilities": list(result.announcement.capabilities),
        }
        payload["accepted"] = result.announcement.accepted
    if result.ignored_kinds:
        payload["ignored_kinds"] = list(result.ignored_kinds)
    if result.runtime_state is not None:
        payload["runtime_state"] = result.runtime_state
    return payload


__all__ = ["HeartbeatResult", "pulse", "heartbeat_payload", "RUNTIME_STATE_SWITCH"]
