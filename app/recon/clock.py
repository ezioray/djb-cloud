# SPDX-License-Identifier: Apache-2.0
"""统一时钟（00-conventions §4：存储与 API 一律 UTC；测试可注入固定时刻）。"""
from __future__ import annotations

from datetime import datetime, timezone

__all__ = ["utcnow", "as_utc", "iso", "iso_micros", "day_of", "month_of", "month_bounds",
           "parse_datetime", "parse_month"]


def utcnow() -> datetime:
    """当前 UTC 时刻（带时区）。"""
    return datetime.now(timezone.utc)


def as_utc(moment: datetime) -> datetime:
    """把任意 datetime 归一到 UTC（naive 按 UTC 解释，不猜本地时区）。"""
    if not isinstance(moment, datetime):
        raise TypeError(f"需要 datetime，得到 {type(moment).__name__}")
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def iso_micros(moment: datetime) -> str:
    """UTC ISO-8601，固定 6 位微秒 + ``Z``（与 M16 同款，便于跨模块比对）。"""
    return as_utc(moment).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def iso(moment: datetime) -> str:
    """UTC ISO-8601（秒级，无微秒时省略）—— 人读 / 游标用。"""
    value = as_utc(moment)
    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def day_of(moment: datetime) -> str:
    """UTC 日（``YYYY-MM-DD``）：日结与账龄桶的日粒度口径（00-conventions §4.2）。"""
    return as_utc(moment).date().isoformat()


def month_of(moment: datetime) -> str:
    """UTC 自然月（``YYYY-MM``）：报表周期口径（spec ``ReportPeriod``）。"""
    return as_utc(moment).strftime("%Y-%m")


def parse_month(period: str) -> tuple[datetime, datetime]:
    """``YYYY-MM`` → [月初 00:00Z, 次月初 00:00Z) 半开区间。"""
    from .errors import BadRequest

    if not isinstance(period, str) or len(period) != 7 or period[4] != "-":
        raise BadRequest("period 必须是 YYYY-MM", field="period")
    try:
        year, month = int(period[:4]), int(period[5:])
    except ValueError as exc:                      # pragma: no cover - 长度已卡住
        raise BadRequest("period 必须是 YYYY-MM", field="period") from exc
    if not (1 <= month <= 12) or year < 1970:
        raise BadRequest("period 必须是合法的自然月（YYYY-MM）", field="period")
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = datetime(year + (1 if month == 12 else 0), 1 if month == 12 else month + 1, 1,
                   tzinfo=timezone.utc)
    return start, end


def month_bounds(period: str) -> tuple[datetime, datetime]:
    """``parse_month`` 的别名（语义更直白：报表区间）。"""
    return parse_month(period)


def parse_datetime(value: object, *, field: str) -> datetime:
    """RFC 3339 → UTC datetime（``Z`` 与 ``+08:00`` 都接受；naive 按 UTC）。"""
    from .errors import BadRequest

    if isinstance(value, datetime):
        return as_utc(value)
    if not isinstance(value, str) or not value.strip():
        raise BadRequest(f"{field} 必须是 RFC 3339 日期时间", field=field)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return as_utc(datetime.fromisoformat(text))
    except ValueError as exc:
        raise BadRequest(f"{field} 必须是 RFC 3339 日期时间", field=field) from exc
