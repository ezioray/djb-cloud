# SPDX-License-Identifier: Apache-2.0
"""三源漂移（T4，M10 §6 流程 4 / §21.11.5）。

三源定义（product/v4/src/21-config-management.md §21.11.5）：

    A desired   配置仓（git）里声明的版本 —— 由调用方给出（S1 用 T5 的仓导出；本模块不读 git）
    B effective active 版本 —— 本模块自己拥有
    C running   消费端 applied_version —— 由 M02/M15 上报，调用方传入

本模块只做「比较 + 落 config_drifts（只追加）+ 发 config.drift_detected」，
**不拥有** running 数据，也不做节点侧收敛：
  · B≠C 收敛窗口 300s（节点侧 900s）是告警口径，由调度器判断（M10 §8.2 DRIFT_CONVERGE_S）；
  · A≠B 的纠正时限 24h（DRIFT_FIX_H）同理。
因此扫描函数把两个映射当参数，缺哪个源就不比较哪一对（至少给一个源，否则 47001）。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

import psycopg
from psycopg.types.json import Jsonb

from . import audit as audit_mod
from . import outbox, store
from .errors import ValidationFailed
from .registry import load as load_registry

__all__ = [
    "SourceKey",
    "normalize_source",
    "scan_drifts",
    "scan_effective_vs_running",
    "resolve_drift",
    "list_drifts",
    "open_drifts",
]

#: (key, scope, scope_id)
SourceKey = tuple[str, str, str]


def _rows(conn: psycopg.Connection, sql: str, params: Any = ()) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    columns = [desc.name for desc in cur.description or ()]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def _one(conn: psycopg.Connection, sql: str, params: Any = ()) -> dict[str, Any] | None:
    rows = _rows(conn, sql, params)
    return rows[0] if rows else None


def _now(now: datetime | None) -> datetime:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValidationFailed("now 必须带时区（UTC）")
    return moment.astimezone(timezone.utc)


def normalize_source(source: Mapping[Any, int], *, name: str) -> dict[SourceKey, int]:
    """把 ``{key: version}`` 或 ``{(key, scope, scope_id): version}`` 归一成后者。"""
    if not isinstance(source, Mapping):
        raise ValidationFailed(f"{name} 必须是映射：{source!r}")
    normalized: dict[SourceKey, int] = {}
    for raw_key, version in source.items():
        if isinstance(raw_key, tuple):
            if len(raw_key) != 3:
                raise ValidationFailed(f"{name} 的键必须是 (key, scope, scope_id)：{raw_key!r}")
            key, scope, scope_id = raw_key
        else:
            key, scope, scope_id = raw_key, "global", ""
        if not isinstance(key, str):
            raise ValidationFailed(f"{name} 的 key 必须是字符串：{key!r}")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ValidationFailed(f"{name} 的版本号必须是正整数：{key}={version!r}")
        scope, scope_id = store.normalize_scope(scope, scope_id)
        normalized[(key, scope, scope_id)] = version
    return normalized


def _existing_open_drift(conn: psycopg.Connection, *, key: str, scope: str, scope_id: str,
                         desired: int | None, effective: int | None,
                         running: int | None) -> bool:
    row = _one(conn,
               """SELECT 1 FROM config_drifts
                   WHERE key = %s AND scope = %s AND scope_id = %s
                     AND desired_version IS NOT DISTINCT FROM %s
                     AND effective_version IS NOT DISTINCT FROM %s
                     AND running_version IS NOT DISTINCT FROM %s
                     AND resolved_at IS NULL LIMIT 1""",
               (key, scope, scope_id, desired, effective, running))
    return row is not None


def _record_drift(conn: psycopg.Connection, *, key: str, scope: str, scope_id: str,
                  desired: int | None, effective: int | None, running: int | None,
                  expected: Any, actual: Any, detected_at: datetime,
                  trace_id: str | None,
                  audit: "audit_mod.AuditSink | None" = None) -> dict[str, Any] | None:
    if _existing_open_drift(conn, key=key, scope=scope, scope_id=scope_id,
                            desired=desired, effective=effective, running=running):
        return None                                    # 同一组版本已有未解决漂移：不重复落
    row = _one(conn,
               """INSERT INTO config_drifts
                    (namespace, key, scope, scope_id, desired_version, effective_version,
                     running_version, expected, actual, detected_at)
                  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                  RETURNING *""",
               (key.split(".", 1)[0], key, scope, scope_id, desired, effective, running,
                Jsonb(expected), Jsonb(actual), detected_at))
    assert row is not None
    event = outbox.drift_detected_event(
        namespace=key.split(".", 1)[0], key=key, expected=expected, actual=actual,
        detected_at=detected_at, scope=scope, scope_id=scope_id, trace_id=trace_id,
        occurred_at=detected_at)
    outbox.append_event(conn, event)
    audit_mod.emit(audit, audit_mod.build_event(
        "config.drift.detected", actor="system:drift_scan", key=key, scope=scope,
        scope_id=scope_id, trace_id=trace_id, occurred_at=detected_at,
        before=expected, after=actual,
        metadata={"desired_version": desired, "effective_version": effective,
                  "running_version": running}))
    return row


def scan_drifts(
    conn: psycopg.Connection,
    *,
    desired: Mapping[Any, int] | None = None,
    running: Mapping[Any, int] | None = None,
    now: datetime | None = None,
    trace_id: str | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> list[dict[str, Any]]:
    """扫描一次：A≠B（desired vs effective）与 B≠C（effective vs running），只写不一致项。"""
    if desired is None and running is None:
        raise ValidationFailed("漂移扫描至少需要一个源（desired 或 running）")
    moment = _now(now)
    reg = load_registry()
    desired_map = normalize_source(desired, name="desired") if desired is not None else {}
    running_map = normalize_source(running, name="running") if running is not None else {}

    keys = sorted(set(desired_map) | set(running_map))
    drift_rows: list[dict[str, Any]] = []
    for key, scope, scope_id in keys:
        reg.require(key)                               # 未注册 key 一律拒绝（不静默跳过）
        active = store.active_version(conn, key=key, scope=scope, scope_id=scope_id)
        effective = active["version"] if active else None

        if desired is not None:
            want = desired_map.get((key, scope, scope_id))
            if want is not None and want != effective:
                row = _record_drift(
                    conn, key=key, scope=scope, scope_id=scope_id,
                    desired=want, effective=effective, running=None,
                    expected={"source": "desired", "version": want},
                    actual={"source": "effective", "version": effective},
                    detected_at=moment, trace_id=trace_id, audit=audit)
                if row is not None:
                    drift_rows.append(row)

        if running is not None:
            reported = running_map.get((key, scope, scope_id))
            if reported is not None and reported != effective:
                row = _record_drift(
                    conn, key=key, scope=scope, scope_id=scope_id,
                    desired=None, effective=effective, running=reported,
                    expected={"source": "effective", "version": effective},
                    actual={"source": "running", "version": reported},
                    detected_at=moment, trace_id=trace_id, audit=audit)
                if row is not None:
                    drift_rows.append(row)
    return drift_rows


def scan_effective_vs_running(
    conn: psycopg.Connection,
    running: Mapping[Any, int],
    *,
    now: datetime | None = None,
    trace_id: str | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> list[dict[str, Any]]:
    """发布后收敛检查的便捷入口（B≠C）。"""
    return scan_drifts(conn, running=running, now=now, trace_id=trace_id, audit=audit)


def resolve_drift(conn: psycopg.Connection, drift_id: str, *, resolution: str,
                  now: datetime | None = None,
                  audit: "audit_mod.AuditSink | None" = None) -> dict[str, Any]:
    """标记已解决（只能由 NULL 置一次；1004 触发器保证不可撤销、不可改结论）。"""
    moment = _now(now)
    resolution = resolution.strip()
    if not 2 <= len(resolution) <= 256:
        raise ValidationFailed(f"resolution 必须是 2–256 字符：{resolution!r}")
    row = _one(conn,
               """UPDATE config_drifts
                     SET resolved_at = %s, resolution = %s
                   WHERE drift_id = %s AND resolved_at IS NULL
               RETURNING *""",
               (moment, resolution, drift_id))
    if row is None:
        raise ValidationFailed(f"漂移 {drift_id} 不存在或已解决")
    audit_mod.emit(audit, audit_mod.build_event(
        "config.drift.resolved", actor="operator", key=row["key"], scope=row["scope"],
        scope_id=row["scope_id"], reason=resolution, occurred_at=moment,
        metadata={"drift_id": str(drift_id)}))
    return row


def list_drifts(conn: psycopg.Connection, *, resolved: bool | None = None,
                limit: int = 50) -> list[dict[str, Any]]:
    if not 1 <= limit <= 200:
        raise ValidationFailed(f"limit 越界 1..200：{limit}")
    where = ""
    if resolved is True:
        where = "WHERE resolved_at IS NOT NULL"
    elif resolved is False:
        where = "WHERE resolved_at IS NULL"
    return _rows(conn, f"""SELECT * FROM config_drifts {where}
                            ORDER BY detected_at DESC LIMIT %s""", (limit,))


def open_drifts(conn: psycopg.Connection, *, limit: int = 50) -> list[dict[str, Any]]:
    return list_drifts(conn, resolved=False, limit=limit)
