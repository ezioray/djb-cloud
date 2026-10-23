# SPDX-License-Identifier: Apache-2.0
"""M12 时钟工具：一律 UTC + 显式注入（00-conventions §10：用例不依赖墙上时间）。

为什么单独一个文件：``created_at`` 同时参与**合并去重**（INV-03 的 ``dedupe_bucket``）、
分页游标、静默时段判定与保留期计算。只要有一处用 ``datetime.now()`` 直接取时间，
用例就不再可复现。因此：生产入口由 router 注入 ``now``，其余层一律要求显式传入。
"""
from __future__ import annotations

from datetime import datetime, timezone

__all__ = ["now", "to_utc", "isoformat", "from_epoch_s"]


def now() -> datetime:
    """当前 UTC 时刻（带时区）。生产唯一取值点；测试一律传 ``now=``。"""
    return datetime.now(timezone.utc)


def to_utc(value: datetime | None) -> datetime | None:
    """把任意时区的时间归一成 UTC；``naive`` 视为 UTC（不猜本地时区）。"""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def isoformat(value: datetime | None) -> str | None:
    """RFC 3339 输出（spec ``format: date-time``）：``2026-10-23T04:00:00+00:00``。"""
    normalized = to_utc(value)
    return None if normalized is None else normalized.isoformat()


def from_epoch_s(value: int | float) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)
