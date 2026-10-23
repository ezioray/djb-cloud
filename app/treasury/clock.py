# SPDX-License-Identifier: Apache-2.0
"""UTC 时钟与时间解析（M08 全模块统一口径：库里 timestamptz，序列化一律 UTC ISO）。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = ["utcnow", "as_utc", "iso", "iso_micros", "parse_datetime", "add_seconds",
           "add_days", "utc4_day_start"]

UTC4 = timezone(timedelta(hours=4))          # 业务日切按 UTC+4（00-conventions §4）


def utcnow() -> datetime:
    """当前 UTC 时间（测试通过 now_provider 注入固定值）。"""
    return datetime.now(timezone.utc)


def as_utc(moment: datetime) -> datetime:
    """naive 一律按 UTC 解释（不跟随宿主时区）。"""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def iso(moment: datetime | None) -> str | None:
    """序列化为 UTC ISO8601（毫秒精度，Z 结尾）；None 透传。"""
    if moment is None:
        return None
    return as_utc(moment).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def iso_micros(moment: datetime) -> str:
    """游标用的高精度 UTC ISO（微秒）。"""
    return as_utc(moment).isoformat(timespec="microseconds")


def parse_datetime(value: Any, *, field: str = "datetime") -> datetime:
    """解析 ISO8601 / datetime；非法 → BadRequest（延迟导入避免循环依赖）。"""
    from .errors import BadRequest

    if isinstance(value, datetime):
        return as_utc(value)
    if not isinstance(value, str) or not value.strip():
        raise BadRequest(f"{field} 必须是 ISO8601 时间", field=field)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return as_utc(datetime.fromisoformat(text))
    except ValueError as exc:
        raise BadRequest(f"{field} 必须是 ISO8601 时间", field=field) from exc


def add_seconds(moment: datetime, seconds: int) -> datetime:
    return as_utc(moment) + timedelta(seconds=int(seconds))


def add_days(moment: datetime, days: int) -> datetime:
    return as_utc(moment) + timedelta(days=int(days))


def utc4_day_start(moment: datetime) -> datetime:
    """业务日（UTC+4）起点，返回 UTC 时刻。"""
    local = as_utc(moment).astimezone(UTC4)
    return local.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)
