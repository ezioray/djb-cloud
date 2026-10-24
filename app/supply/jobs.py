# SPDX-License-Identifier: AGPL-3.0-or-later
"""内部 job（M02 §4.3）：心跳超时 → 派生 offline + 事件。

规则（M02 §7 失败矩阵「心跳超时」）：

* 判定：``active`` 且**曾上报过心跳**、且 ``now - last_seen_at > 3 × heartbeat_interval_s``；
* 动作：写 ``node_events(kind='offline')`` + 发 ``node.state.changed(reason='timeout')``，
  并在 ``nodes.offline_announced_at`` 打标记——**同一段离线只发一次事件**（下一条心跳会清标记）；
* **不改**生命周期状态：在线 / 离线是派生视图（M02 §3「一层权威 + 一层派生，不得混用」），
  M04 用 ``v_supply_node_snapshot.last_seen_at`` 自行判定候选集。

调用方式：由平台的调度器（M16 / cron worker）按分钟节拍调用 :func:`scan_offline`；
本模块不自带常驻进程（M02 §4.3「内部 job」由平台承载）。
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from . import clock, config_source, events, facts, models, state as state_machine

log = logging.getLogger("djb.supply.jobs")


def scan_offline(c, *, now: datetime | None = None, heartbeat_interval_s: int | None = None,
                 limit: int = 500, trace_id: str = "supply.job.offline") -> dict[str, Any]:
    """扫描心跳超时节点，发离线事件（幂等：每段离线只发一次）。"""
    moment = now.astimezone(timezone.utc) if now else clock.utcnow()
    interval = heartbeat_interval_s
    if interval is None:
        values = config_source.load(c)
        interval = config_source.heartbeat_interval_s(values)
    if not isinstance(interval, int) or interval <= 0:
        raise ValueError("heartbeat_interval_s 必须是正整数")
    threshold = timedelta(seconds=facts.OFFLINE_AFTER_CYCLES * interval)
    cutoff = moment - threshold

    with c.cursor() as cur:
        cur.execute(
            """SELECT id, state, last_seen_at FROM nodes
                WHERE state = 'active' AND last_seen_at IS NOT NULL
                  AND last_seen_at <= %s AND offline_announced_at IS NULL
                ORDER BY last_seen_at LIMIT %s
                FOR UPDATE SKIP LOCKED""", (cutoff, max(1, min(int(limit), 2000))))
        rows = models._rows(cur)

    announced: list[str] = []
    for row in rows:
        node_id = row["id"]
        with c.cursor() as cur:
            cur.execute(
                """UPDATE nodes SET offline_announced_at = %s, updated_at = %s
                    WHERE id = %s AND offline_announced_at IS NULL""", (moment, moment, node_id))
            if cur.rowcount != 1:                              # 并发扫描：别人已处理
                continue
        causes = models.append_node_event(
            c, node_id=node_id, kind="offline", from_state=row["state"],
            to_state=row["state"], reason_code="timeout", actor="system",
            payload={"last_seen_at": models.iso(row["last_seen_at"])}, now=moment)
        events.node_state_changed(c, node_id=node_id, from_state=row["state"],
                                  to_state=row["state"], reason="timeout", trace_id=trace_id,
                                  occurred_at=moment, causation_id=causes)
        announced.append(node_id)

    if announced:
        log.warning("supply.job.offline.announced",
                    extra={"event": "node.offline", "count": len(announced),
                           "trace_id": trace_id})
    return {"scanned": len(rows), "announced": announced,
            "offline_after_seconds": int(threshold.total_seconds()),
            "cutoff": models.iso(cutoff)}


def presence_of(node: models.Node, now: datetime, *, values: dict[str, int] | None = None) -> str:
    """派生在线状态的便捷封装（路由 / 看板 / M04 都能复用同一套口径）。"""
    resolved = values or config_source.load(None, node)
    return state_machine.derive_presence(
        node.last_seen_at, now,
        heartbeat_interval_s=config_source.heartbeat_interval_s(resolved),
        stale_after_s=config_source.stale_after_s(resolved))


__all__ = ["scan_offline", "presence_of"]
