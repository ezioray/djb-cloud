# SPDX-License-Identifier: AGPL-3.0-or-later
"""偏好读写与投递时效规则（INV-01：P0 不可退订 / 静默时段与摘要对 P0 无效）。

三条硬规则在本文件里落地：

1. **P0 不可退订**（INV-01）：``PUT`` 里出现 ``p0_opt_out: true`` → ``40902``，
   偏好**一个字都不改**（先校验后写库）；数据库 1205 还有 ``CHECK(p0_opt_out = false)`` 兜底；
2. **站内记录必留**（INV-02）：``in_app=false`` 只影响「是否产生未读提醒」，
   不影响记录落库（由 ``events.consume`` 预置 ``read_at`` 实现）；
3. **静默时段 / 摘要不作用于 P0**：:func:`apply_time_rules` 对 P0 直接返回立即投递。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, time
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import errors, facts
from .models import Preference, as_uuid
from .store import dict_cursor

__all__ = ["DEFAULTS", "parse_update", "get", "put", "apply_time_rules", "TimeDecision"]

#: 未设置过偏好时的默认值（§8.1 默认：digest=realtime，quiet_hours=null）
DEFAULTS = Preference.defaults()


@dataclass(frozen=True)
class TimeDecision:
    """一次「现在能不能发」的判定（P0 恒 immediate）。"""

    deferred: bool = False
    digest: str = "realtime"
    reason: str = "immediate"

    @property
    def immediate(self) -> bool:
        return not self.deferred


def _bool_field(body: Mapping[str, Any], key: str) -> bool:
    if key not in body:
        raise errors.InvalidArgument(f"缺字段 {key}（spec NotificationPreferences required）",
                                     field=key)
    value = body[key]
    if not isinstance(value, bool):
        raise errors.InvalidArgument(f"{key} 必须是布尔值", field=key)
    return value


def _parse_quiet_hours(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise errors.InvalidArgument("quiet_hours 必须是对象或 null", field="quiet_hours")
    unknown = set(value) - {"start", "end", "timezone"}
    if unknown:
        raise errors.InvalidArgument(f"quiet_hours 含未知字段：{sorted(unknown)}",
                                     field="quiet_hours")
    try:
        start = facts.normalize_hhmm(value.get("start"))
        end = facts.normalize_hhmm(value.get("end"))
    except ValueError as exc:
        raise errors.InvalidArgument(str(exc), field="quiet_hours") from exc
    raw_tz = value.get("timezone")
    timezone_name = "UTC" if raw_tz in (None, "") else str(raw_tz)
    if len(timezone_name) > 64:
        raise errors.InvalidArgument("quiet_hours.timezone 过长", field="quiet_hours")
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise errors.InvalidArgument("quiet_hours.timezone 不是合法时区名",
                                     field="quiet_hours") from exc
    return {"start": start, "end": end, "timezone": timezone_name}


def parse_update(body: Any) -> dict[str, Any]:
    """校验 ``PUT /preferences`` 请求体（覆盖式；未知字段容忍并忽略）。

    先校验后写库：任何一条不合法都**不改**已存偏好（含 P0 退订尝试）。
    """
    if not isinstance(body, Mapping):
        raise errors.InvalidArgument("请求体必须是 JSON 对象")
    parsed: dict[str, Any] = {
        "email": _bool_field(body, "email"),
        "in_app": _bool_field(body, "in_app"),
        "webhook": _bool_field(body, "webhook"),
        "quiet_hours": _parse_quiet_hours(body.get("quiet_hours")),
    }
    digest = body.get("digest", "realtime")
    if not isinstance(digest, str):
        raise errors.InvalidArgument("digest 必须是字符串", field="digest")
    try:
        parsed["digest"] = facts.validate_digest(digest)
    except ValueError as exc:
        raise errors.InvalidArgument(str(exc), field="digest") from exc
    # INV-01：P0 不可退订（先判，再写）
    if "p0_opt_out" in body:
        value = body["p0_opt_out"]
        if not isinstance(value, bool):
            raise errors.InvalidArgument("p0_opt_out 必须是布尔值", field="p0_opt_out")
        if value:
            raise errors.P0OptOutRejected(
                "P0 通知不可退订（INV-01）；如需停止接收请先处理账户状态",
                field="p0_opt_out")
    parsed["p0_opt_out"] = False
    return parsed


def get(conn: Any, account_id: uuid.UUID | str) -> Preference:
    """读取偏好；没有行时返回 §8.1 默认值（不写库，GET 是只读的）。"""
    with dict_cursor(conn) as cur:
        cur.execute(
            """SELECT account_id, email, in_app, webhook, quiet_hours, digest, p0_opt_out,
                      updated_at
                 FROM notification_preferences WHERE account_id = %s""",
            (as_uuid(account_id),))
        row = cur.fetchone()
    if row is None:
        return Preference.defaults(as_uuid(account_id))
    return Preference.from_row(row)


def put(conn: Any, account_id: uuid.UUID | str, body: Any, *,
        now: datetime) -> Preference:
    """覆盖式写入（UPSERT），返回落库后的偏好。"""
    parsed = parse_update(body)                      # 校验（含 INV-01）先行
    with dict_cursor(conn) as cur:
        cur.execute(
            """INSERT INTO notification_preferences
                   (account_id, email, in_app, webhook, quiet_hours, digest, p0_opt_out,
                    updated_at)
               VALUES (%s, %s, %s, %s, %s, %s, false, %s)
               ON CONFLICT (account_id) DO UPDATE
                   SET email = EXCLUDED.email,
                       in_app = EXCLUDED.in_app,
                       webhook = EXCLUDED.webhook,
                       quiet_hours = EXCLUDED.quiet_hours,
                       digest = EXCLUDED.digest,
                       p0_opt_out = false,
                       updated_at = EXCLUDED.updated_at
               RETURNING account_id, email, in_app, webhook, quiet_hours, digest,
                         p0_opt_out, updated_at""",
            (as_uuid(account_id), parsed["email"], parsed["in_app"], parsed["webhook"],
             _json_quiet(parsed["quiet_hours"]), parsed["digest"], now))
        row = cur.fetchone()
    return Preference.from_row(row)


def _json_quiet(value: Mapping[str, str] | None) -> Any:
    if value is None:
        return None
    from psycopg.types.json import Jsonb                 # 局部导入：纯函数用例不必装驱动

    return Jsonb(dict(value))


def _minutes(hhmm: str) -> int:
    hour, minute = hhmm.split(":")
    return int(hour) * 60 + int(minute)


def _in_quiet_window(preference: Mapping[str, str], at: datetime) -> bool:
    tz_name = preference.get("timezone") or "UTC"
    try:
        zone = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):           # pragma: no cover - 已在校验时拦住
        zone = ZoneInfo("UTC")
    local = at.astimezone(zone)
    start = _minutes(preference["start"])
    end = _minutes(preference["end"])
    if start == end:
        return False                                      # 零长度窗口 = 未启用
    current = local.hour * 60 + local.minute
    if start < end:
        return start <= current < end
    return current >= start or current < end              # 跨零点


def apply_time_rules(level: str, pref: Preference, at: datetime, *,
                     enforce: bool = True) -> TimeDecision:
    """P0 立即投递；P1/P2 受静默时段与摘要影响（INV-01 / §8.1）。

    ``enforce=False``（``notify.quiet_hours_enforced`` 关闭时）只保留判定能力，
    不改变投递行为——用于灰度和排障。
    """
    facts.validate_level(level)
    if level == "P0":
        return TimeDecision(deferred=False, digest="realtime", reason="p0_immediate")
    if not enforce:
        return TimeDecision(deferred=False, digest="realtime", reason="not_enforced")
    quiet = pref.quiet_hours
    if quiet and _in_quiet_window(quiet, at):
        return TimeDecision(deferred=True, digest=pref.digest, reason="quiet_hours")
    if pref.digest in ("daily", "weekly"):
        return TimeDecision(deferred=True, digest=pref.digest, reason=f"digest_{pref.digest}")
    return TimeDecision(deferred=False, digest=pref.digest, reason="immediate")


# 供外部按需构造时间点（例如报告 job 的 09:00 当地时刻）；不参与判定
def at_local(hhmm: str, *, zone: str = "UTC", on: datetime) -> datetime:
    hour, minute = facts.normalize_hhmm(hhmm).split(":")
    local_date = on.astimezone(ZoneInfo(zone)).date()
    return datetime.combine(local_date, time(int(hour), int(minute)),
                            tzinfo=ZoneInfo(zone))
