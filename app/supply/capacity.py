# SPDX-License-Identifier: AGPL-3.0-or-later
"""容量公告（M02 §3 CapacityAnnouncement / §6.2 / INV-07 / §8.2 上限）。

要点：

* **时序**：同一 ``(node_id, model, kind)`` 以 ``seq`` 最大一条为准；``seq`` 由
  ``nodes.heartbeat_seq`` 原子递增分配（同一节点内单调，不接受客户端给 seq）。
* **过期**：``now > expires_at`` 的公告不进 M04 候选集（视图 ``v_supply_capacity_latest``
  已在 SQL 层过滤，本文件 :func:`snapshot` 直接读视图）。
* **未知 kind 忽略不报错**（INV-05 的宽容读取精神）：返回给调用方用于提示，不写库、不失败。
* 领域层只做校验与落库；``announcement_id`` 是全局唯一 UUID（00-conventions §2）。
"""
from __future__ import annotations

import dataclasses
import logging
import math
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from psycopg.types.json import Jsonb

from . import clock, facts, models
from .errors import InvalidArgument, NodeNotFound

log = logging.getLogger("djb.supply.capacity")

_DECIMAL_RE = re.compile(r"^[0-9]+(\.[0-9]+)?$")
_ENTRY_FIELDS = ("kind", "access", "model", "max_qps", "unit")


@dataclasses.dataclass(frozen=True)
class Announcement:
    id: uuid.UUID
    node_id: str
    seq: int
    announced_at: datetime
    expires_at: datetime
    capabilities: tuple[dict[str, Any], ...]

    @property
    def accepted(self) -> bool:
        """有效容量：至少一条 ``max_qps > 0``（0 容量允许公告但**不接单**，fixture 口径）。"""
        return any(float(item.get("max_qps") or 0) > 0 for item in self.capabilities)

    def models(self) -> tuple[str, ...]:
        return tuple(sorted({str(item["model"]) for item in self.capabilities}))


def _now(now: datetime | None) -> datetime:
    return now.astimezone(timezone.utc) if now else clock.utcnow()


def _require_text(value: Any, *, field: str, max_len: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgument(f"{field} 必填", field=field)
    text = value.strip()
    if len(text) > max_len:
        raise InvalidArgument(f"{field} 超长（≤{max_len}）", field=field)
    return text


def _require_number(value: Any, *, field: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidArgument(f"{field} 必须是数字", field=field)
    number = float(value)
    if not math.isfinite(number) or number < minimum:
        raise InvalidArgument(f"{field} 必须 ≥ {minimum:g}", field=field)
    return number


def _optional_text(value: Any, *, field: str, max_len: int = 64) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidArgument(f"{field} 必须是字符串", field=field)
    text = value.strip()
    if not text:
        return None
    if len(text) > max_len:
        raise InvalidArgument(f"{field} 超长（≤{max_len}）", field=field)
    return text


def _normalize_entry(entry: Any, index: int) -> dict[str, Any]:
    if not isinstance(entry, Mapping):
        raise InvalidArgument(f"capacity[{index}] 必须是对象", field=f"capacity[{index}]")
    missing = [key for key in _ENTRY_FIELDS if entry.get(key) in (None, "")]
    if missing:
        raise InvalidArgument(f"capacity[{index}] 缺少 {','.join(missing)}",
                              field=f"capacity[{index}].{missing[0]}")
    access = entry.get("access")
    if access not in facts.ACCESS_TYPES:
        raise InvalidArgument(
            f"capacity[{index}].access 必须是 {'/'.join(facts.ACCESS_TYPES)} 之一",
            field=f"capacity[{index}].access")
    ask_price = entry.get("ask_price")
    if ask_price is not None:
        if not isinstance(ask_price, str) or not _DECIMAL_RE.match(ask_price.strip()):
            raise InvalidArgument(f"capacity[{index}].ask_price 必须是十进制字符串",
                                  field=f"capacity[{index}].ask_price")
        ask_price = ask_price.strip()
    ram_gb = entry.get("ram_gb")
    return {
        "kind": _require_text(entry.get("kind"), field=f"capacity[{index}].kind", max_len=32),
        "access": access,
        "model": _require_text(entry.get("model"), field=f"capacity[{index}].model"),
        "max_qps": _require_number(entry.get("max_qps"), field=f"capacity[{index}].max_qps"),
        "unit": _require_text(entry.get("unit"), field=f"capacity[{index}].unit", max_len=32),
        "ask_price": ask_price,
        "resource_level": _optional_text(entry.get("resource_level"),
                                         field=f"capacity[{index}].resource_level", max_len=32),
        "gpu": _optional_text(entry.get("gpu"), field=f"capacity[{index}].gpu"),
        "ram_gb": None if ram_gb is None else _require_number(
            ram_gb, field=f"capacity[{index}].ram_gb"),
    }


def normalize(entries: Sequence[Any]) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    """校验 + 归一化一批公告；返回 ``(有效条目, 被忽略的未知 kind)``。

    * 未知 ``kind`` **忽略不报错**（契约新增值时客户端不必同步升级）；
    * 同批内重复 ``(kind, model)`` 以**后者为准**（时序最新）。
    """
    if entries is None:
        return [], ()
    if not isinstance(entries, (list, tuple)):
        raise InvalidArgument("capacity 必须是数组", field="capacity")
    if len(entries) > facts.MAX_CAPABILITIES_PER_ANNOUNCEMENT:
        raise InvalidArgument(
            f"公告单批最多 {facts.MAX_CAPABILITIES_PER_ANNOUNCEMENT} 条", field="capacity")
    valid: dict[tuple[str, str], dict[str, Any]] = {}
    ignored: list[str] = []
    for index, entry in enumerate(entries):
        normalized = _normalize_entry(entry, index)
        if normalized["kind"] not in facts.CAPACITY_KINDS:
            ignored.append(normalized["kind"])
            continue
        valid[(normalized["kind"], normalized["model"])] = normalized
    return list(valid.values()), tuple(dict.fromkeys(ignored))


def next_seq(c, node_id: str) -> int:
    """原子分配下一个公告序号（同一节点内单调；库层唯一约束兜底 INV-07）。"""
    with c.cursor() as cur:
        cur.execute(
            "UPDATE nodes SET heartbeat_seq = heartbeat_seq + 1, updated_at = now() "
            "WHERE id = %s RETURNING heartbeat_seq", (node_id,))
        row = models._one(cur)
    if row is None:
        raise NodeNotFound("节点不存在", node_id=node_id)
    return int(row["heartbeat_seq"])


def record(c, *, node_id: str, entries: Sequence[Mapping[str, Any]], ttl_seconds: int,
           now: datetime | None = None) -> Announcement:
    """落一条公告快照（只追加；历史进快照，最新由 seq 决定）。"""
    moment = _now(now)
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise InvalidArgument("ttl_seconds 必须是正整数", field="ttl_seconds")
    seq = next_seq(c, node_id)
    identifier = models.uuid7(int(moment.timestamp() * 1_000_000))
    expires_at = moment + timedelta(seconds=ttl_seconds)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO capacity_announcements
                   (id, node_id, seq, announced_at, expires_at, capabilities)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (identifier, node_id, seq, moment, expires_at, Jsonb(list(entries))))
    log.info("supply.capacity.announced",
             extra={"event": "capacity.recorded", "node_id": node_id, "seq": seq,
                    "entries": len(entries)})
    return Announcement(id=identifier, node_id=node_id, seq=seq, announced_at=moment,
                        expires_at=expires_at,
                        capabilities=tuple(dict(item) for item in entries))


def latest(c, node_id: str) -> Announcement | None:
    """该节点最新一条公告（含已过期，用于「历史仍在」的核对）。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT id, node_id, seq, announced_at, expires_at, capabilities
                 FROM capacity_announcements WHERE node_id = %s
                ORDER BY seq DESC LIMIT 1""", (node_id,))
        row = models._one(cur)
    if row is None:
        return None
    return Announcement(id=row["id"], node_id=row["node_id"], seq=int(row["seq"]),
                        announced_at=row["announced_at"], expires_at=row["expires_at"],
                        capabilities=tuple(dict(item) for item in row["capabilities"]))


def snapshot(c, *, limit: int = 200) -> list[dict[str, Any]]:
    """M04 候选集快照（读 ``v_supply_capacity_latest``：已过滤过期与 0 容量）。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT node_id, announcement_id, seq, announced_at, expires_at, kind, access,
                      model, max_qps, ask_price, unit, resource_level, gpu, ram_gb
                 FROM v_supply_capacity_latest
                ORDER BY node_id, kind, model LIMIT %s""",
            (max(1, min(int(limit), 1000)),))
        return models._rows(cur)


__all__ = ["Announcement", "normalize", "next_seq", "record", "latest", "snapshot"]
