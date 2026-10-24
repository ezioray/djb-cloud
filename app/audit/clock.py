# SPDX-License-Identifier: AGPL-3.0-or-later
"""统一时钟（00-conventions §4：存储与 API 一律 UTC；测试可注入固定时刻）。"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """当前 UTC 时刻（带时区）。"""
    return datetime.now(timezone.utc)


def as_utc(moment: datetime) -> datetime:
    """把任意 datetime 归一到 UTC（naive 按 UTC 解释；不做本地时区猜测）。"""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def iso_micros(moment: datetime) -> str:
    """UTC ISO-8601，**固定 6 位微秒 + Z**（链哈希里的 ts 就长这样，必须确定）。

    例：``2026-10-23T08:00:00.000000Z``。定长是为了让 append 与 verify 两侧逐字节一致。
    """
    return as_utc(moment).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def day_of(moment: datetime) -> str:
    """UTC 日（``YYYY-MM-DD``）——Merkle 日用分区口径（00-conventions §4.2：周期按 UTC 日）。"""
    return as_utc(moment).date().isoformat()
