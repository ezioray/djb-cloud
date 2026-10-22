# SPDX-License-Identifier: Apache-2.0
"""T5 worker：定时推进（scheduled 生效 / 复核过期 / kill switch 到期 / outbox 重投）。

设计：
  · **一次 tick 只做一轮**，调度频率由外部 cron / 进程管理器决定（本模块不 sleep、不起线程）；
  · 每个动作都可重入（DB 状态机 + 幂等键保证重复 tick 不会重复生效）；
  · 单条失败不拖垮整轮：记录到返回值里，下一轮再试（发布窗口外的 scheduled 单会保留到窗口内）；
  · 审计通过注入的 :class:`app.config_center.audit.AuditSink`（生产 = M16）。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping

import psycopg

from . import audit as audit_mod
from . import dispatcher, publish
from .errors import ConfigCenterError, OutsidePublishWindow

__all__ = ["mark_scheduled", "advance_scheduled", "tick"]


def _now(now: datetime | None) -> datetime:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("now 必须带时区（UTC）")
    return moment.astimezone(timezone.utc)


def mark_scheduled(conn: psycopg.Connection, *, now: datetime | None = None) -> int:
    """把「已复核 + 未来生效时间」的发布单落到 scheduled（§3 状态机 approved → scheduled）。"""
    moment = _now(now)
    cur = conn.execute(
        """UPDATE config_publish_requests SET status = 'scheduled', updated_at = now()
            WHERE status = 'approved' AND effective_at IS NOT NULL AND effective_at > %s""",
        (moment,))
    return cur.rowcount


def advance_scheduled(
    conn: psycopg.Connection,
    *,
    now: datetime | None = None,
    audit: audit_mod.AuditSink | None = None,
    trace_id: str | None = None,
) -> list[dict[str, Any]]:
    """把到点的 scheduled 发布单推进为 active；窗口外跳过（下轮再试）。"""
    moment = _now(now)
    rows = conn.execute(
        """SELECT publish_request_id FROM config_publish_requests
            WHERE status = 'scheduled' AND effective_at IS NOT NULL AND effective_at <= %s
            ORDER BY effective_at""", (moment,)).fetchall()
    results: list[dict[str, Any]] = []
    for (request_id,) in rows:
        try:
            out = publish.activate_request(conn, str(request_id), now=moment,
                                           trace_id=trace_id, audit=audit)
        except OutsidePublishWindow as exc:
            results.append({"request_id": str(request_id), "status": "skipped",
                            "reason": str(exc)})
        except ConfigCenterError as exc:
            results.append({"request_id": str(request_id), "status": "failed",
                            "reason": f"{type(exc).__name__}: {exc}"})
        else:
            results.append({"request_id": str(request_id), "status": out["request"]["status"],
                            "version": out["version"]["version"]})
    return results


def tick(
    conn: psycopg.Connection,
    *,
    now: datetime | None = None,
    publisher: Callable[[Mapping[str, Any]], Any] | None = None,
    audit: audit_mod.AuditSink | None = None,
    on_dead_letter: Callable[[Mapping[str, Any]], Any] | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    """一轮完整维护：过期复核 → 到点生效 → kill switch 到期 → outbox 重投。"""
    moment = _now(now)
    expired = publish.expire_requests(conn, now=moment)
    scheduled_count = mark_scheduled(conn, now=moment)
    scheduled = advance_scheduled(conn, now=moment, audit=audit, trace_id=trace_id)
    kill_switches = publish.expire_kill_switches(conn, now=moment, trace_id=trace_id, audit=audit)
    dispatched = dispatcher.dispatch_pending(
        conn, publisher=publisher, now=moment, on_dead_letter=on_dead_letter)
    return {
        "at": moment.isoformat(),
        "expired_requests": expired,
        "marked_scheduled": scheduled_count,
        "scheduled": scheduled,
        "kill_switches": kill_switches,
        "dispatch": dispatched,
    }
