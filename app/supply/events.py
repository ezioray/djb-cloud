# SPDX-License-Identifier: Apache-2.0
"""事件生产（M02 §4.2 / 02-events §1 信封 / §2 至少一次）。

本模块只生产 4 个事件，全部经 ``supply_outbox``（本地事务 + outbox，**禁止分布式事务**）::

    node.registered         注册受理（pending）
    node.state.changed      准入 / 冻结 / 解冻 / 清退 / 离线 *以及* 绑定 / 解绑（reason=bound/unbound）
    node.upstream.changed   申报 / 体检结论变化（T4）
    capacity.announced      心跳携带有效公告（T3）

**payload 铁律**：只放事实字段；不放凭据 / 指纹明文 / PII / 正文（INV-03/04、02-events §1）。
库层 ``supply_outbox_payload_ck`` 会拒绝缺键的事件，因此下面的构造器把所有业务键都写全，
未取到的值写 ``None``（键存在，值可空）。
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Mapping

from psycopg.types.json import Jsonb

from . import clock, facts

log = logging.getLogger("djb.supply.events")


def _new_event_id(now: datetime) -> uuid.UUID:
    """事件 ID = UUIDv7（00-conventions §2：时间有序）。"""
    from .models import uuid7                                  # 延迟导入，避免循环引用

    return uuid7(int(now.timestamp() * 1_000_000))


def emit(c, *, type: str, aggregate_id: str, payload: Mapping[str, Any], trace_id: str,
         idempotency_key: str | None = None, correlation_id: str | None = None,
         causation_id: uuid.UUID | None = None, occurred_at: datetime | None = None,
         event_id: uuid.UUID | None = None) -> dict[str, Any]:
    """写一条待投递事件（同事务）；投递失败不回滚业务事务（02-events §2.6）。"""
    if type not in facts.EVENT_TYPES:
        raise ValueError(f"未登记的事件类型：{type!r}（先在 02-events 登记）")
    moment = occurred_at.astimezone(clock.utcnow().tzinfo) if occurred_at else clock.utcnow()
    identifier = event_id or _new_event_id(moment)
    # 00-conventions §1.6：trace_id 必须出现在事件里；调用方没给就现场生成（不写空串）
    trace = (trace_id or "").strip() or identifier.hex
    # 业务幂等键：只有「一个事实全局唯一」的事件（如 node.registered）传显式键；
    # 其余事件每次发生都是一个新事实，默认键带 event_id 保证唯一（02-events §1 信封要求）。
    key = idempotency_key or f"{type}:{aggregate_id}:{identifier.hex}"
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO supply_outbox
                   (event_id, type, version, occurred_at, producer, aggregate_type,
                    aggregate_id, correlation_id, causation_id, trace_id, idempotency_key,
                    payload)
               VALUES (%s, %s, 1, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (identifier, type, moment, facts.EVENT_PRODUCER, facts.EVENT_AGGREGATE_TYPE,
             aggregate_id, correlation_id, causation_id, trace, key, Jsonb(dict(payload))))
    log.info("supply.event.queued", extra={"event": type, "event_id": str(identifier),
                                           "aggregate_id": aggregate_id, "trace_id": trace})
    return {"event_id": str(identifier), "type": type, "occurred_at": moment}


# --------------------------------------------------------------------------- 4 个构造器
def node_registered(c, *, node_id: str, account_id: str | None, protocols: list[str],
                    region: str | None, trace_id: str, occurred_at: datetime | None = None,
                    causation_id: uuid.UUID | None = None) -> dict[str, Any]:
    """``node.registered``：payload = node_id, account_id, protocols, region（02-events §3）。

    注意：S1 的节点在注册时**尚未绑定账户**（绑定走网页端 CR-4 流程），故 ``account_id``
    通常为 ``null``；归属变化由随后的 ``node.state.changed(reason=bound)`` 补足。
    """
    return emit(c, type="node.registered", aggregate_id=node_id, trace_id=trace_id,
                occurred_at=occurred_at, causation_id=causation_id,
                idempotency_key=f"node.registered:{node_id}",
                payload={"node_id": node_id, "account_id": account_id,
                         "protocols": list(protocols), "region": region})


def node_state_changed(c, *, node_id: str, from_state: str, to_state: str, reason: str,
                       trace_id: str, occurred_at: datetime | None = None,
                       causation_id: uuid.UUID | None = None) -> dict[str, Any]:
    """``node.state.changed``：payload = node_id, from, to, reason（02-events §3）。"""
    return emit(c, type="node.state.changed", aggregate_id=node_id, trace_id=trace_id,
                occurred_at=occurred_at, causation_id=causation_id,
                payload={"node_id": node_id, "from": from_state, "to": to_state,
                         "reason": reason})


def node_upstream_changed(c, *, node_id: str, upstream_type: str, state: str, trace_id: str,
                          occurred_at: datetime | None = None,
                          causation_id: uuid.UUID | None = None) -> dict[str, Any]:
    """``node.upstream.changed``：payload = node_id, upstream_type, state（T4 使用）。"""
    return emit(c, type="node.upstream.changed", aggregate_id=node_id, trace_id=trace_id,
                occurred_at=occurred_at, causation_id=causation_id,
                payload={"node_id": node_id, "upstream_type": upstream_type, "state": state})


def capacity_announced(c, *, node_id: str, models: list[str], gpu: str | None,
                       ram: int | None, expires_at: datetime, trace_id: str,
                       announced_at: datetime | None = None,
                       causation_id: uuid.UUID | None = None) -> dict[str, Any]:
    """``capacity.announced``：payload = node_id, models, gpu, ram, expires_at（T3 使用）。"""
    return emit(c, type="capacity.announced", aggregate_id=node_id, trace_id=trace_id,
                occurred_at=announced_at, causation_id=causation_id,
                payload={"node_id": node_id, "models": list(models), "gpu": gpu, "ram": ram,
                         "expires_at": expires_at.isoformat()})


__all__ = ["emit", "node_registered", "node_state_changed", "node_upstream_changed",
           "capacity_announced"]
