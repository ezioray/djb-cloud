# SPDX-License-Identifier: AGPL-3.0-or-later
"""M03 `/v1/models` 的可用性投影（C9 收尾 / spec 1.2.8）。

数据来源只有两个 **M02 只读视图**（不 join 基表、不写任何表）：

* ``v_supply_capacity_latest``：已过滤过期与 ``max_qps=0`` 的容量公告；
* ``v_supply_upstream_verified``：``state=verified`` 的上游 × 模型（含 ``verified_at``）。

判定顺序（与 M13 三态、C9b 门控口径一致）：

1. 该模型没有任何正容量公告 → ``no_capacity``；
2. 有容量但没有 verified 上游 → ``unverified``；
3. 最近一次 verified 超过新鲜窗口（默认 900 s）→ ``stale``；
4. 其余 → ``available=True``，``probe.verified_at`` 给最近时间。

**缺省即未知**：调用方拿不到本投影时，不得把 `available` 默认成 `True`（spec 1.2.8）。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.scheduling import clock

FRESH_S = 900
"""与 M02/M04 的 probe freshness 同口径（900 s）。"""


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class SupplyAvailability:
    """按模型返回 spec 1.2.8 的 ``available`` / ``probe`` 字段。"""

    def __init__(self, db: Any, *, freshness_s: int = FRESH_S) -> None:
        self._db = db
        self._freshness_s = int(freshness_s)

    def status(self, model: str, *, now: datetime | None = None) -> dict[str, Any]:
        moment = now or clock.utcnow()
        with self._db.connect() as conn:
            capacity = conn.execute(
                "SELECT 1 FROM v_supply_capacity_latest WHERE model = %s LIMIT 1", (model,)
            ).fetchone()
            if capacity is None:
                return self._payload(False, None, reason="no_capacity")
            row = conn.execute(
                "SELECT max(verified_at) FROM v_supply_upstream_verified WHERE model = %s",
                (model,),
            ).fetchone()
        verified_at = row[0] if row else None
        if verified_at is None:
            return self._payload(False, None, reason="unverified")
        fresh = (moment - verified_at) <= timedelta(seconds=self._freshness_s)
        if not fresh:
            return self._payload(False, verified_at, reason="stale")
        return self._payload(True, verified_at, reason=None)

    @staticmethod
    def _payload(available: bool, verified_at: datetime | None, *, reason: str | None
                 ) -> dict[str, Any]:
        return {
            "available": bool(available),
            "probe": {
                "level": None,                 # S2 尚不宣称 L3+；由 M17 服务端定级
                "verified_at": _iso(verified_at),
                "fresh": reason is None,
                "reason": reason,
            },
        }


__all__ = ["FRESH_S", "SupplyAvailability"]
