# SPDX-License-Identifier: AGPL-3.0-or-later
"""UTC 时钟与时间解析（M14 统一口径：库里 timestamptz，序列化 UTC ISO8601）。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

__all__ = ["utcnow", "as_utc", "iso", "iso_micros", "parse_datetime", "start_of_utc_day"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return as_utc(moment).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def iso_micros(moment: datetime) -> str:
    return as_utc(moment).isoformat(timespec="microseconds")


def start_of_utc_day(moment: datetime) -> datetime:
    moment = as_utc(moment)
    return moment.replace(hour=0, minute=0, second=0, microsecond=0)


def parse_datetime(value: Any, *, field: str = "datetime") -> datetime:
    """ISO8601 / datetime → UTC；非法抛 ``BadRequest``（延迟导入避免循环依赖）。"""
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
