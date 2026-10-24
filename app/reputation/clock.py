# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 时钟（00-conventions §4.4：时间比较只用服务端时间；测试注入固定时钟）。

业务日切按 UTC+4（§8.2「每日 00:30（UTC+4）全量重算」），但**存储与 API 一律 UTC**
（00-conventions §4.1）——本模块只提供 UTC now 与「业务日」换算，不把本地时区写进数据。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

__all__ = ["now", "as_utc", "business_day", "isoformat", "BUSINESS_TZ_OFFSET"]

#: 业务日切时区（UTC+4，00-conventions §4.2 / §8.2）
BUSINESS_TZ_OFFSET = timezone(timedelta(hours=4))


def now() -> datetime:
    """当前 UTC 时刻（路由与领域层默认时钟；测试用 ``now_provider`` 注入）。"""
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime:
    """把 unaware 时间按 UTC 处理（库里都是 timestamptz，读回来是 aware）。"""
    if value is None:
        return now()
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def business_day(moment: datetime) -> str:
    """业务日（UTC+4）的 ``YYYY-MM-DD``——只用于日切 / 报表口径，不落库。"""
    return as_utc(moment).astimezone(BUSINESS_TZ_OFFSET).date().isoformat()


def isoformat(moment: datetime | None) -> str | None:
    """ISO-8601 带 Z（00-conventions §4.1）；``None`` 原样返回。"""
    if moment is None:
        return None
    return as_utc(moment).isoformat().replace("+00:00", "Z")


def parse_datetime(raw: str | None) -> datetime | None:
    """解析 API 传入的 RFC 3339 / 日期字符串；非法返回 ``None``（由调用方翻 40001）。"""
    if raw in (None, ""):
        return None
    text = str(raw).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return as_utc(parsed)
