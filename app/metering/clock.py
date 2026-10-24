# SPDX-License-Identifier: AGPL-3.0-or-later
"""可注入时钟（00-conventions §4.4 / §10「测试必须确定性：固定时钟」）。

业务代码只调 :func:`utcnow`；测试用 ``monkeypatch.setattr(clock, "utcnow", lambda: NOW)``
或显式传 ``now=`` 参数，不依赖墙上时间。
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """当前 UTC 时间（带 tzinfo）。"""
    return datetime.now(timezone.utc)


def as_utc(moment: datetime) -> datetime:
    """统一成带时区的 UTC（naive 一律按 UTC 解释，不接受本地时区猜测）。"""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)
