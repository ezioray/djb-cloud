# SPDX-License-Identifier: Apache-2.0
"""可注入时钟（与 ``app/supply/clock.py`` / ``app/identity/clock.py`` 同款约定）。

00-conventions §10 要求测试确定性，§4 要求「时间比较只用服务端时间」。
业务代码不直接调 ``datetime.now``；测试用 ``monkeypatch.setattr(clock, "utcnow", ...)`` 钉死时钟。

M04 额外提供 :func:`truncate`：``snapshot_ts`` 必须**可复现**（INV-03 的锚点之一），
所以对外暴露的快照时刻统一截断到秒（默认），避免微秒抖动把同一次决策拆成两条日志。
"""
from __future__ import annotations

from datetime import datetime, timezone

__all__ = ["utcnow", "truncate", "SNAPSHOT_RESOLUTION_S"]

#: 快照时刻分辨率（秒）：同秒内的并发请求共享同一个 ``snapshot_ts`` 锚点（INV-03）
SNAPSHOT_RESOLUTION_S = 1


def utcnow() -> datetime:
    """当前 UTC 时间（本模块唯一取时入口）。"""
    return datetime.now(timezone.utc)


def truncate(moment: datetime, resolution_s: int = SNAPSHOT_RESOLUTION_S) -> datetime:
    """把时刻截断到 ``resolution_s`` 秒（默认 1 s），并强制 UTC。

    决策锚点用截断后的时刻：同一秒内的并发请求得到同一个 ``snapshot_ts``，
    重放时也能用日志里的原值精确复现（INV-03）。
    """
    if resolution_s <= 0:
        raise ValueError("resolution_s 必须是正整数")
    utc = moment.astimezone(timezone.utc)
    epoch = int(utc.timestamp())
    floored = epoch - (epoch % resolution_s)
    return datetime.fromtimestamp(floored, tz=timezone.utc)
