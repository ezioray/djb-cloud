# SPDX-License-Identifier: Apache-2.0
"""事件 outbox 投递（02-events §2：至少一次 / 退避 / 死信 / 不阻塞主链路）。

分工：

* **写**：:mod:`app.gateway.events` 构造信封 → :func:`app.gateway.store.insert_outbox`
  在业务事务里落库（事务失败则事件不存在，事务成功则至少投递一次）；
* **投**：本模块的 :func:`enqueue` / :func:`dispatch_once` 由后台作业（M16 的调度器或
  网关自己的 worker）驱动；网关主链路**不等待**投递结果（02-events §2.6）；
* **派发器**：``set_publisher(publisher)`` 注入真实消息通道；未接线时只记结构化日志
  ——相当于「入队成功但未发出」，不丢事件，接线后可重放（``published_at IS NULL``）。

多实例：取行用 ``FOR UPDATE SKIP LOCKED``，同一行不会被两个 worker 同时投递。
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping

from . import clock, facts, store

log = logging.getLogger("djb.gateway.outbox")

__all__ = ["Publisher", "set_publisher", "current_publisher", "enqueue", "dispatch_once"]

Publisher = Callable[[str, Mapping[str, Any]], None]
"""``publisher(type, envelope)``：把事件交给真实通道；抛异常即视为投递失败。"""

_publisher: Publisher | None = None


def set_publisher(publisher: Publisher | None) -> None:
    global _publisher
    _publisher = publisher


def current_publisher() -> Publisher | None:
    return _publisher


def enqueue(c: Any, envelope: Mapping[str, Any]) -> None:
    """在**调用方事务**里写入待投递事件（``ON CONFLICT (idempotency_key) DO NOTHING``）。"""
    store.insert_outbox(c, envelope)


def _backoff_seconds(attempts: int) -> int:
    ladder = facts.EVENT_RETRY_BACKOFF_S
    index = min(max(attempts - 1, 0), len(ladder) - 1)
    return int(ladder[index])


def dispatch_once(c: Any, *, now: datetime | None = None, limit: int = 100) -> dict[str, int]:
    """投递一批待发事件；返回 ``{published, failed}``（失败按 02-events §2.3 退避）。"""
    moment = clock.as_utc(now or clock.utcnow())
    rows = store.pending_outbox(c, now=moment, limit=limit)
    published = failed = 0
    for row in rows:
        payload = row["payload"]
        if isinstance(payload, str):                       # jsonb 文本兜底
            import json

            payload = json.loads(payload)
        envelope = {"event_id": row["event_id"], "type": row["type"], "payload": payload,
                    "idempotency_key": row["idempotency_key"]}
        attempts = int(row["attempts"])
        if _publisher is None:
            # 未接线：不伪造「已发布」，只记日志（入队事实已落库，接线后可重放）
            log.info("gateway.outbox.not_wired",
                     extra={"event": "outbox.not_wired", "event_id": row["event_id"],
                            "type": row["type"]})
            break
        try:
            _publisher(row["type"], envelope)
        except Exception as exc:                           # 投递失败：退避重试，不回滚业务
            attempts += 1
            next_at = moment + timedelta(seconds=_backoff_seconds(attempts))
            store.mark_outbox_failed(c, event_id=row["event_id"], attempts=attempts,
                                     next_attempt_at=next_at,
                                     error=f"{type(exc).__name__}: {exc}".strip())
            failed += 1
            log.warning("gateway.outbox.delivery_failed",
                        extra={"event": "outbox.delivery_failed", "event_id": row["event_id"],
                               "attempts": attempts})
            continue
        store.mark_outbox_published(c, event_id=row["event_id"], now=moment)
        published += 1
    return {"published": published, "failed": failed}

