# SPDX-License-Identifier: Apache-2.0
"""Ops 只读面：七块健康总览 / 变更日历 / 操作回放（审计时间线）。

INV-01：只读聚合。数据来源只有两类——
  1) 各 Owner 暴露的只读视图 ``v_<module>_*``（recon / ledger / wallet 已接；其余块未接线
     时状态为 **yellow + probe_not_wired**，绝不假装 green）；
  2) M16 审计链 ``audit_log``（M14 §5 明确的只读依赖）与**本模块** outbox。
不 join 他域基表、不写账、不签名。

红黄绿判定：红 > 黄 > 绿；"未知 / 未接线" 归为 yellow（fail-safe，不把缺数据当健康）。
探针可由 Lead 在接线时用 ``probes=`` 注入（Owner API 适配器），无需改本模块。
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock, errors, facts, models, store

__all__ = [
    "HealthProbe", "DEFAULT_PROBES", "health", "changes", "audit_replay",
    "AUDIT_RANK", "OUTBOX_RANK",
]

AUDIT_RANK = 0
OUTBOX_RANK = 1

#: 回放 / 健康明细里一律脱敏的键（INV-10：不展示凭据 / 完整签名 / PII）
_SENSITIVE_KEY_RE = re.compile(
    r"(secret|token|password|passwd|private|mnemonic|signature|sig|api[_-]?key|"
    r"card|pan|email|phone|id_card)", re.IGNORECASE)

HealthProbe = Callable[[Any, datetime], Mapping[str, Any]]


# ═══════════════════════════════════════════════════════════ 默认探针（只读视图）
def _probe_recon(connection: Any, now: datetime) -> Mapping[str, Any]:
    run = store.latest_recon_run(connection)
    if run is None:
        return {"status": "yellow", "reason": "no_recon_run",
                "detail": "无对账批次（v_m09_run_diff 未接线或无数据）"}
    p0 = int(run.get("open_p0") or 0)
    p1 = int(run.get("open_p1") or 0)
    p2 = int(run.get("open_p2") or 0)
    status = "red" if p0 else ("yellow" if p1 else "green")
    return {
        "status": status,
        "reason": "open_p0" if p0 else ("open_p1" if p1 else "clean"),
        "detail": f"最近对账批次 {run.get('scope')}：P0={p0} P1={p1} P2={p2}",
        "metrics": {"run_id": str(run.get("run_id")) if run.get("run_id") else None,
                    "status": run.get("status"), "open_p0": p0, "open_p1": p1,
                    "open_p2": p2},
    }


def _probe_ledger(connection: Any, now: datetime) -> Mapping[str, Any]:
    last = store.latest_balance_ts(connection)
    if last is None:
        return {"status": "yellow", "reason": "no_balance_snapshot",
                "detail": "account_balances_latest 无快照（M06 未接线 / 未落账）"}
    age_h = (clock.as_utc(now) - clock.as_utc(last)).total_seconds() / 3600.0
    if age_h <= facts.HEALTH_LEDGER_STALE_H:
        status = "green"
    elif age_h <= facts.HEALTH_LEDGER_RED_H:
        status = "yellow"
    else:
        status = "red"
    return {"status": status,
            "reason": "fresh" if status == "green" else "stale_snapshot",
            "detail": f"最新余额快照 {age_h:.1f} 小时前",
            "metrics": {"stale_hours": round(age_h, 2),
                        "last_snapshot_at": clock.iso(last)}}


def _probe_wallet(connection: Any, now: datetime) -> Mapping[str, Any]:
    stuck = store.count_stuck_chain_tx(connection, facts.HEALTH_WALLET_STUCK_MIN)
    if stuck is None:
        return {"status": "yellow", "reason": "chain_view_unavailable",
                "detail": "chain_tx_state 只读视图不可用（M08 未接线）"}
    if stuck == 0:
        status = "green"
    elif stuck < facts.HEALTH_WALLET_RED_COUNT:
        status = "yellow"
    else:
        status = "red"
    return {"status": status,
            "reason": "stuck_chain_tx" if stuck else "clean",
            "detail": f"{facts.HEALTH_WALLET_STUCK_MIN} 分钟未确认的链上交易：{stuck} 笔",
            "metrics": {"stuck_count": stuck,
                        "threshold_minutes": facts.HEALTH_WALLET_STUCK_MIN}}


DEFAULT_PROBES: dict[str, HealthProbe] = {
    "recon": _probe_recon,
    "ledger": _probe_ledger,
    "wallet": _probe_wallet,
}


# ═══════════════════════════════════════════════════════════ 健康总览
def _last_change(connection: Any, block: str) -> dict | None:
    row = store.latest_audit_change(connection, facts.HEALTH_CHANGE_PATTERNS[block])
    if row is None:
        return None
    return {"action": row["action"], "actor": row["actor"], "at": clock.iso(row["ts"])}


def health(connection: Any, *, now: datetime,
           probes: Mapping[str, HealthProbe] | None = None) -> dict:
    merged: dict[str, HealthProbe] = {**DEFAULT_PROBES, **dict(probes or {})}
    blocks: list[dict[str, Any]] = []
    for block in facts.HEALTH_BLOCKS:
        probe = merged.get(block)
        if probe is None:
            entry = {"block": block, "status": "yellow", "reason": "probe_not_wired",
                     "detail": "Owner 只读 API / v_<module>_* 视图未接线（S1 只做只读聚合）"}
        else:
            try:
                result = probe(connection, now) or {}
            except Exception as exc:                 # noqa: BLE001 - 探针异常不放大成 5xx
                entry = {"block": block, "status": "yellow", "reason": "probe_error",
                         "detail": f"探针异常：{type(exc).__name__}"}
            else:
                status = result.get("status")
                entry = {
                    "block": block,
                    "status": status if status in facts.HEALTH_STATUSES else "yellow",
                    "reason": result.get("reason") or ("unavailable" if status
                                                       not in facts.HEALTH_STATUSES else None),
                    "detail": result.get("detail"),
                }
                if result.get("metrics"):
                    entry["metrics"] = dict(result["metrics"])
        entry["checked_at"] = clock.iso(now)
        last_change = _last_change(connection, block)
        if last_change is not None:
            entry["last_change"] = last_change
        blocks.append(entry)
    overall = max(blocks, key=lambda item: facts.HEALTH_RANK[item["status"]])["status"]
    return {"data": blocks, "overall": overall, "observed_at": clock.iso(now),
            "block_count": len(blocks)}


# ═══════════════════════════════════════════════════════════ 变更日历
def _change_kind(action: str) -> str:
    if action.startswith("config.publish"):
        return "config_publish"
    if action.startswith("config.rollback"):
        return "config_rollback"
    if action.startswith("deploy."):
        return "deploy"
    if action.startswith("backup."):
        return "backup"
    if action.startswith("upgrade."):
        return "upgrade"
    return "release"


def _change_status(action: str) -> str:
    if action.endswith((".completed", ".done")):
        return "completed"
    if action.endswith((".failed",)):
        return "failed"
    if "rollback" in action or action.endswith(".rolled_back"):
        return "rolled_back"
    if action.endswith((".started", ".start")):
        return "in_progress"
    return "recorded"


def _safe_ts(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return clock.iso(clock.parse_datetime(value, field="ts"))
    except errors.BadRequest:
        return None


def _change_entry(row: Mapping[str, Any]) -> dict[str, Any]:
    action = str(row["action"])
    after = row.get("after") if isinstance(row.get("after"), Mapping) else {}
    start = _safe_ts(after.get("window_start")) or clock.iso(row["ts"])
    end = _safe_ts(after.get("window_end")) or start
    rollback = after.get("rollback_plan")
    impact = after.get("impact_scope")
    return {
        "change_id": str(row["entry_id"]),
        "kind": _change_kind(action),
        "action": action,
        "status": _change_status(action),
        "actor": row["actor"],
        "target": row["target"],
        "window": {"start": start, "end": end},
        "rollback_plan": rollback if isinstance(rollback, str) and rollback.strip()
        else "未登记：以 M16 发布单为准",
        "impact_scope": impact if isinstance(impact, str) and impact.strip()
        else row["target"],
        "occurred_at": clock.iso(row["ts"]),
        "ticket": row.get("ticket"),
        "evidence": row.get("evidence"),
    }


def changes(connection: Any, *, from_at: datetime | None = None,
            to_at: datetime | None = None, cursor: str | None = None,
            limit: int = facts.DEFAULT_PAGE_SIZE, now: datetime | None = None) -> dict:
    rows, has_more, next_cursor = store.list_audit_changes(
        connection, from_at=from_at, to_at=to_at, cursor=cursor, limit=limit)
    return {
        "data": [_change_entry(row) for row in rows],
        "page": models.page_payload(cursor=cursor, has_more=has_more,
                                    next_cursor=next_cursor),
        "source": {"audit_log": "ok" if store.audit_log_available(connection)
                   else "unavailable"},
        "observed_at": clock.iso(now or clock.utcnow()),
    }


# ═══════════════════════════════════════════════════════════ 操作回放（只读时间线）
def _safe_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 3:
        return None
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, child in value.items():
            if _SENSITIVE_KEY_RE.search(str(key)):
                continue
            cleaned[str(key)[:64]] = _safe_value(child, depth=depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [_safe_value(child, depth=depth + 1) for child in list(value)[:20]]
    if isinstance(value, str):
        return value[:200]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:200]


def _replay_audit_item(row: Mapping[str, Any], *, trace_id: str | None) -> dict[str, Any]:
    item = {
        "occurred_at": clock.iso(row["ts"]),
        "source": "audit",
        "trace_id": trace_id,
        "owner_id": row["actor"],
        "action": row["action"],
        "target": row["target"],
        "reason_code": row.get("reason_code"),
        "evidence": row.get("evidence"),
        "_ts": clock.as_utc(row["ts"]),
        "_rank": AUDIT_RANK,
        "_id": int(row["seq"]),
    }
    detail = _safe_value(row.get("after"))
    if isinstance(detail, Mapping):
        item["detail"] = dict(detail)
    return item


def _replay_event_item(row: Mapping[str, Any], *, trace_id: str | None) -> dict[str, Any]:
    return {
        "occurred_at": clock.iso(row["occurred_at"]),
        "source": "event",
        "trace_id": row["trace_id"],
        "owner_id": None,
        "action": row["type"],
        "target": row["aggregate_id"],
        "event_id": str(row["event_id"]),
        "aggregate_type": row["aggregate_type"],
        "state": row.get("state"),
        "payload": _safe_value(row.get("payload")),
        "_ts": clock.as_utc(row["occurred_at"]),
        "_rank": OUTBOX_RANK,
        "_id": int(row["id"]),
    }


def _decode_replay_cursor(cursor: str | None) -> tuple[Any, Any, Any]:
    decoded = models.decode_cursor(cursor)
    if decoded is None:
        return None, None, None
    moment, tag = decoded
    try:
        rank_text, identifier_text = tag.split(":", 1)
        rank = int(rank_text)
        identifier = int(identifier_text)
    except (ValueError, TypeError):
        raise errors.BadRequest("cursor 不合法", field="cursor") from None
    if rank not in (AUDIT_RANK, OUTBOX_RANK):
        raise errors.BadRequest("cursor 不合法", field="cursor")
    return moment, rank, identifier


def audit_replay(connection: Any, *, trace_id: str | None = None,
                 owner_id: str | None = None, action: str | None = None,
                 from_at: datetime | None = None, to_at: datetime | None = None,
                 cursor: str | None = None, limit: int = facts.DEFAULT_PAGE_SIZE,
                 now: datetime | None = None) -> dict:
    if not any((trace_id, owner_id, action)):
        raise errors.BadRequest(
            "至少提供 trace_id / owner_id / action 之一（回放必须有过滤条件）")
    if trace_id is not None:
        trace_id = models.require_text(trace_id, field="trace_id", max_len=128)
    if owner_id is not None:
        owner_id = models.require_text(owner_id, field="owner_id", max_len=128)
    if action is not None:
        action = models.require_action(action, field="action")
    moment, rank, identifier = _decode_replay_cursor(cursor)
    audit_rows = store.audit_entries_for_replay(
        connection, actor=owner_id, action_prefix=action, from_at=from_at, to_at=to_at,
        cursor_ts=moment, cursor_rank=rank, cursor_id=identifier, limit=limit + 1)
    event_rows = store.outbox_events_for_replay(
        connection, trace_id=trace_id, event_type_prefix=action, from_at=from_at,
        to_at=to_at, cursor_ts=moment, cursor_rank=rank, cursor_id=identifier,
        limit=limit + 1)
    items = [_replay_audit_item(row, trace_id=trace_id) for row in audit_rows]
    items.extend(_replay_event_item(row, trace_id=trace_id) for row in event_rows)
    items.sort(key=lambda item: (-item["_ts"].timestamp(), item["_rank"], -item["_id"]))
    has_more = len(items) > limit
    items = items[:limit]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = models.encode_cursor(last["_ts"], f"{last['_rank']}:{last['_id']}")
    for item in items:
        item.pop("_ts", None)
        item.pop("_rank", None)
        item.pop("_id", None)
    return {
        "data": items,
        "page": models.page_payload(cursor=cursor, has_more=has_more,
                                    next_cursor=next_cursor),
        "source": {"audit_log": "ok" if store.audit_log_available(connection)
                   else "unavailable", "outbox": "ok"},
        "observed_at": clock.iso(now or clock.utcnow()),
    }
