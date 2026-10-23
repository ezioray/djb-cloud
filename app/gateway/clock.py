# SPDX-License-Identifier: Apache-2.0
"""时钟与延迟测量（测试用 monkeypatch 钉死，00-conventions §10「测试必须确定性」）。"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """当前 UTC 时刻（秒级以下保留；用例 monkeypatch 本函数获取固定时钟）。"""
    return datetime.now(timezone.utc)


def monotonic_ms() -> int:
    """单调毫秒（只用于**时长**测量，不做跨进程比较）。"""
    import time

    return int(time.monotonic() * 1_000)


def elapsed_ms(started_at: int, *, now_ms: int | None = None) -> int:
    """``started_at`` → 现在 的毫秒差（负值夹到 0，避免时钟回拨出现负数延迟）。"""
    current = monotonic_ms() if now_ms is None else int(now_ms)
    return max(0, current - int(started_at))


def as_utc(moment: datetime) -> datetime:
    """统一到 UTC（naive 视为 UTC，与 ``timestamptz`` 落库口径一致）。"""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def iso(moment: datetime) -> str:
    """RFC 3339 UTC（spec 约定：``Amount`` 十进制字符串、时间 RFC 3339）。"""
    return as_utc(moment).isoformat().replace("+00:00", "Z")


__all__ = ["utcnow", "monotonic_ms", "elapsed_ms", "as_utc", "iso"]
