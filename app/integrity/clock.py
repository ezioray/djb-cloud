# SPDX-License-Identifier: AGPL-3.0-or-later
"""UTC 时钟与时间序列化（与 M11/M02 同口径：库里一律 timestamptz，序列化一律 UTC ISO）。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

__all__ = ["utcnow", "as_utc", "iso", "iso_micros", "parse_datetime"]


def utcnow() -> datetime:
    """当前 UTC 时间（带时区；用例通过 monkeypatch 注入固定值）。"""
    return datetime.now(timezone.utc)


def as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def iso(moment: datetime | None) -> str | None:
    """UTC ISO8601（毫秒精度，``Z`` 结尾）；``None`` 透传。"""
    if moment is None:
        return None
    return as_utc(moment).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def iso_micros(moment: datetime) -> str:
    """游标用高精度 UTC ISO（微秒）。"""
    return as_utc(moment).isoformat(timespec="microseconds")


def parse_datetime(value: Any, *, field: str = "datetime") -> datetime:
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
