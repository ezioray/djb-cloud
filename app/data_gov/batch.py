# SPDX-License-Identifier: AGPL-3.0-or-later
"""批量操作五步（INV-03）：预览 → 二次认证 → 双人复核 → 执行（≤200）→ 10 分钟撤销。

硬规则（M14 §6 流程 3）::

    · 预览：影响清单 + 数量 + **随机 10 条**逐条确认；无预览一律禁止执行；
    · 二次认证（step-up ≤5 分钟）在路由层校验（424 / 42401）；
    · 单次 >50 条或涉资金 / 冻结 → **由另一位管理员执行**（双人复核，审批人 ≠ 发起人）；
    · 单次硬上限 200 条（201 条直接拒绝并提示拆分）；
    · 执行后 **10 分钟撤销窗口**：一键反向，撤销同样留痕；
    · 每一步都写审计（未接线 M16 时返回 False，但步骤状态与结果仍落库/在会话内可查）。

状态存放在注入的 ``store``（默认进程内 ``InMemoryBatchStore``）。**不是**业务表：
批量操作本身是"对 Owner API 的提案"，M14 不写任何业务表；持久化批次状态需要一张
自有表或 M16 内部工具接口，S2 接线（证据遗留项）。
"""
from __future__ import annotations

import random
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping, Sequence

from . import audit as audit_hook
from . import clock, errors, facts, ids, models, policy

__all__ = [
    "BatchOp", "InMemoryBatchStore", "BatchStore", "BatchProbe", "BatchExecutor",
    "preview", "execute", "undo", "open_sandbox", "batch_payload", "BATCH_TARGETS",
]

#: 批量目标对象（内部工具，非对外契约；执行一律调 Owner API）
BATCH_TARGETS: tuple[str, ...] = ("account", "node", "key", "wallet", "ticket", "config")

#: Owner 查询适配器：``target -> [id, ...]``（未接线的过滤条件不能"猜"）
BatchProbe = Callable[[Mapping[str, Any]], Sequence[str] | None]
#: Owner 执行 / 撤销适配器：``(action_type, item_id, target) -> {status, error_code}``
BatchExecutor = Callable[[str, str, Mapping[str, Any]], Mapping[str, Any] | None]

#: OpsBatchOpRequest 允许的键（spec 1.2.5 单对象描述多步骤；与本步无关的键忽略）
_REQUEST_KEYS = frozenset({"step", "action_type", "target", "reason", "labels", "batch_id"})
_SAMPLE_SIZE = facts.BATCH_SAMPLE_SIZE


@dataclass
class BatchOp:
    batch_id: str
    initiator: str
    tenant_id: str
    action_type: str
    target: dict[str, Any]
    reason: str
    ids: tuple[str, ...]
    labels: dict[str, str]
    sample: tuple[str, ...]
    dual_required: bool
    previewed_at: datetime
    state: str = "previewed"
    executed_at: datetime | None = None
    undo_deadline: datetime | None = None
    approver: str | None = None
    results: list[dict[str, Any]] = field(default_factory=list)
    undo_results: list[dict[str, Any]] = field(default_factory=list)
    execute_key: str | None = None
    undo_key: str | None = None
    preview_key: str | None = None
    trace_id: str = ""

    def succeeded(self) -> list[str]:
        return [item["id"] for item in self.results if item.get("status") == "succeeded"]

    def sample_payload(self) -> list[str]:
        # spec OpsBatchOp.sample：随机抽样 id 列表（≤10 条，逐条确认）
        return list(self.sample)


class BatchStore:
    """批量批次存储协议（默认进程内实现；S2 换持久化实现不需要改服务层）。"""

    def get(self, batch_id: str) -> BatchOp | None:      # pragma: no cover - 协议
        raise NotImplementedError

    def put(self, operation: BatchOp) -> None:           # pragma: no cover - 协议
        raise NotImplementedError

    def find_by_idempotency(self, key: str | None) -> BatchOp | None:
        return None                                      # 默认不持久化幂等索引


class InMemoryBatchStore(BatchStore):
    def __init__(self) -> None:
        self._items: dict[str, BatchOp] = {}
        self._keys: dict[str, str] = {}
        self._lock = threading.Lock()

    def get(self, batch_id: str) -> BatchOp | None:
        with self._lock:
            return self._items.get(batch_id)

    def put(self, operation: BatchOp) -> None:
        with self._lock:
            self._items[operation.batch_id] = operation
            if operation.preview_key:
                self._keys[operation.preview_key] = operation.batch_id

    def find_by_idempotency(self, key: str | None) -> BatchOp | None:
        if not key:
            return None
        with self._lock:
            batch_id = self._keys.get(key)
            return self._items.get(batch_id) if batch_id else None

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._keys.clear()


def _audit(sink: audit_hook.AuditSink | None, *, action: str, batch_id: str, actor: str,
           reason: str, now: datetime, **details: Any) -> None:
    audit_hook.emit(sink, audit_hook.AuditRecord(
        action=action, object_type="ops_batch", object_id=batch_id, actor=actor,
        reason=reason, occurred_at=now, details=details))


def _reject_unknown(body: Mapping[str, Any], allowed: frozenset[str]) -> None:
    unknown = sorted(set(body) - allowed)
    if unknown:
        raise errors.BadRequest(f"未知字段：{unknown}", fields=unknown)


def _parse_target(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise errors.BadRequest("target 必须是对象", field="target")
    unknown = sorted(set(raw) - {"object", "ids", "filter"})
    if unknown:
        raise errors.BadRequest(f"target 未知字段：{unknown}", fields=unknown)
    target: dict[str, Any] = {
        "object": models.require_enum(raw.get("object"), field="target.object",
                                      allowed=BATCH_TARGETS),
    }
    filter_value = raw.get("filter")
    if filter_value is not None:
        if not isinstance(filter_value, Mapping):
            raise errors.BadRequest("target.filter 必须是对象", field="target.filter")
        target["filter"] = dict(filter_value)
    ids = raw.get("ids")
    if ids is not None:
        if not isinstance(ids, Sequence) or isinstance(ids, (str, bytes, bytearray)):
            raise errors.BadRequest("target.ids 必须是字符串数组", field="target.ids")
        resolved: list[str] = []
        for item in ids:
            identifier = models.require_text(item, field="target.ids[]",
                                             max_len=facts.MAX_ACTOR_LEN)
            if identifier not in resolved:
                resolved.append(identifier)
        target["ids"] = resolved
    return target


def _sample(ids_list: Sequence[str], seed: str) -> tuple[str, ...]:
    if not ids_list:
        return ()
    rng = random.Random(int.from_bytes(seed.encode("utf-8")[:16].ljust(16, b"0"), "big")
                        ^ secrets.randbits(64))
    return tuple(rng.sample(list(ids_list), min(_SAMPLE_SIZE, len(ids_list))))


def preview(store: BatchStore, *, body: Mapping[str, Any], actor: str, tenant_id: str,
            now: datetime, probe: BatchProbe | None = None,
            audit_sink: audit_hook.AuditSink | None = None,
            trace_id: str = "", idempotency_key: str | None = None) -> dict:
    _reject_unknown(body, _REQUEST_KEYS)
    action_type = models.require_enum(body.get("action_type"), field="action_type",
                                      allowed=facts.BATCH_ACTIONS)
    target = _parse_target(body.get("target"))
    reason = models.optional_text(body.get("reason"), field="reason",
                                  max_len=facts.MAX_REASON_LEN) or "批量操作（未提供理由）"
    labels_raw = body.get("labels")
    labels: dict[str, str] = {}
    if labels_raw is not None:
        if not isinstance(labels_raw, Mapping):
            raise errors.BadRequest("labels 必须是对象", field="labels")
        for key, value in labels_raw.items():
            labels[str(key)] = models.require_text(value, field="labels[]", max_len=64)
    if idempotency_key:
        replay = store.find_by_idempotency(idempotency_key)
        if replay is not None:
            if (replay.action_type != action_type or replay.reason != reason
                    or list(replay.ids) != list(target.get("ids") or replay.ids)):
                raise errors.Conflict("幂等键已用于不同载荷（批量预览）",
                                      reason="idempotency_key_reused")
            return batch_payload(replay)
    ids_list = list(target.get("ids") or [])
    if not ids_list:
        if probe is None:
            raise errors.BadRequest(
                "必须提供 target.ids，或接线 Owner 查询适配器（不猜影响面）",
                field="target.ids")
        resolved = probe(target)
        if resolved is None:
            raise errors.Conflict("Owner 查询适配器未接线：无法确定影响面",
                                  reason="owner_probe_unavailable")
        for item in resolved:
            identifier = models.require_text(item, field="target.ids[]",
                                             max_len=facts.MAX_ACTOR_LEN)
            if identifier not in ids_list:
                ids_list.append(identifier)
    if not ids_list:
        raise errors.BadRequest("影响清单为空：拒绝创建批量操作", field="target.ids")
    if len(ids_list) > facts.BATCH_MAX_ITEMS:
        raise errors.ExportTooLarge(
            f"单次批量 {len(ids_list)} 条超过上限 {facts.BATCH_MAX_ITEMS}：请拆分后重试",
            reason="batch_too_large", max_items=facts.BATCH_MAX_ITEMS)
    batch_id = str(ids.uuid7())
    operation = BatchOp(
        batch_id=batch_id, initiator=actor, tenant_id=tenant_id, action_type=action_type,
        target=target, reason=reason, ids=tuple(ids_list), labels=labels,
        sample=_sample(ids_list, batch_id),
        dual_required=policy.batch_dual_review_required(len(ids_list), action_type),
        previewed_at=now, preview_key=idempotency_key, trace_id=trace_id)
    store.put(operation)
    _audit(audit_sink, action=facts.AUDIT_BATCH_PREVIEWED, batch_id=batch_id, actor=actor,
           reason=reason, now=now, action_type=action_type, count=len(ids_list),
           dual_review_required=operation.dual_required, trace_id=trace_id)
    return batch_payload(operation)


def execute(store: BatchStore, *, body: Mapping[str, Any], actor: str, tenant_id: str,
            now: datetime, executor: BatchExecutor | None = None,
            audit_sink: audit_hook.AuditSink | None = None,
            trace_id: str = "", idempotency_key: str | None = None) -> dict:
    _reject_unknown(body, _REQUEST_KEYS)
    batch_id = models.require_uuid(body.get("batch_id"), field="batch_id")
    operation = store.get(batch_id)
    if operation is None or operation.tenant_id != tenant_id:
        raise errors.NotFound("批量操作不存在（无预览不得执行）")
    if idempotency_key and operation.execute_key == idempotency_key:
        return batch_payload(operation, step="execute")
    if operation.state != "previewed":
        raise errors.Conflict(f"当前状态 {operation.state} 不可执行（无预览不得执行）",
                              reason="illegal_transition")
    if operation.dual_required and actor == operation.initiator:
        raise errors.Conflict(
            "该批次 >50 条或涉资金 / 冻结：需另一位管理员复核后执行",
            reason="review_required")
    if executor is None:
        raise errors.Conflict("Owner 执行 API 未接线（fail-closed，不产生假执行）",
                              reason="owner_api_unavailable")
    results: list[dict[str, Any]] = []
    for item in operation.ids:
        try:
            receipt = executor(operation.action_type, item, operation.target)
        except Exception as exc:                       # noqa: BLE001 - 逐条回执，不中断
            results.append({"id": item, "status": "failed",
                            "error_code": type(exc).__name__})
            continue
        status = "succeeded"
        error_code = None
        if isinstance(receipt, Mapping):
            status = str(receipt.get("status") or "succeeded")
            error_code = receipt.get("error_code")
        if status not in ("succeeded", "failed"):
            status = "failed"
        entry = {"id": item, "status": status}
        if error_code:
            entry["error_code"] = str(error_code)
        results.append(entry)
    succeeded = [entry for entry in results if entry["status"] == "succeeded"]
    operation.results = results
    operation.executed_at = clock.as_utc(now)
    operation.undo_deadline = clock.as_utc(now) + timedelta(seconds=facts.BATCH_UNDO_WINDOW_S)
    operation.state = "executed" if succeeded else "failed"
    operation.approver = actor if operation.dual_required else None
    operation.execute_key = idempotency_key
    store.put(operation)
    _audit(audit_sink, action=facts.AUDIT_BATCH_EXECUTED, batch_id=batch_id, actor=actor,
           reason=operation.reason, now=now, action_type=operation.action_type,
           count=len(results), succeeded=len(succeeded),
           failed=len(results) - len(succeeded), approver=operation.approver,
           undo_deadline=clock.iso(operation.undo_deadline), trace_id=trace_id)
    return batch_payload(operation, step="execute")


def undo(store: BatchStore, *, body: Mapping[str, Any], actor: str, tenant_id: str,
         now: datetime, undoer: BatchExecutor | None = None,
         audit_sink: audit_hook.AuditSink | None = None,
         trace_id: str = "", idempotency_key: str | None = None) -> dict:
    _reject_unknown(body, _REQUEST_KEYS)
    batch_id = models.require_uuid(body.get("batch_id"), field="batch_id")
    operation = store.get(batch_id)
    if operation is None or operation.tenant_id != tenant_id:
        raise errors.NotFound("批量操作不存在")
    if idempotency_key and operation.undo_key == idempotency_key:
        return batch_payload(operation, step="undo")
    if operation.state != "executed":
        raise errors.Conflict(f"当前状态 {operation.state} 不可撤销",
                              reason="illegal_transition")
    deadline = operation.undo_deadline
    if deadline is None or clock.as_utc(now) > clock.as_utc(deadline):
        raise errors.Conflict("撤销窗口已关闭（执行后 10 分钟）",
                              reason="undo_window_closed")
    if undoer is None:
        raise errors.Conflict("Owner 撤销 API 未接线（fail-closed）",
                              reason="owner_api_unavailable")
    undo_results: list[dict[str, Any]] = []
    for item in operation.succeeded():
        try:
            receipt = undoer(operation.action_type, item, operation.target)
        except Exception as exc:                       # noqa: BLE001
            undo_results.append({"id": item, "status": "failed",
                                 "error_code": type(exc).__name__})
            continue
        status = "succeeded"
        error_code = None
        if isinstance(receipt, Mapping):
            status = str(receipt.get("status") or "succeeded")
            error_code = receipt.get("error_code")
        entry = {"id": item, "status": status if status in ("succeeded", "failed")
                 else "failed"}
        if error_code:
            entry["error_code"] = str(error_code)
        undo_results.append(entry)
    operation.undo_results = undo_results
    operation.state = "undone"
    operation.undo_key = idempotency_key
    store.put(operation)
    _audit(audit_sink, action=facts.AUDIT_BATCH_UNDONE, batch_id=batch_id, actor=actor,
           reason=operation.reason, now=now, action_type=operation.action_type,
           reversed_count=len(undo_results), trace_id=trace_id)
    return batch_payload(operation, step="undo")


def open_sandbox(*, actor: str, now: datetime, ttl_s: int | None = None,
                 audit_sink: audit_hook.AuditSink | None = None,
                 trace_id: str = "") -> dict:
    """只读沙箱会话（≤4h，全程录制、不得回写生产；INV-09）。"""
    expires_at = policy.sandbox_expires_at(now, ttl_s)
    session = {
        "session_id": str(ids.uuid7()),
        "actor": actor,
        "read_only": True,
        "recording": True,
        "created_at": clock.iso(now),
        "expires_at": clock.iso(expires_at),
        "max_seconds": facts.SANDBOX_MAX_S,
        "ttl_s": int((expires_at - clock.as_utc(now)).total_seconds()),
    }
    _audit(audit_sink, action=facts.AUDIT_SANDBOX_OPENED, batch_id=session["session_id"],
           actor=actor, reason="只读沙箱会话（≤4h）", now=now, trace_id=trace_id)
    return session


def batch_payload(operation: BatchOp, *, step: str | None = None) -> dict:
    payload: dict[str, Any] = {
        "batch_id": operation.batch_id,
        "state": operation.state,
        "step": step or ("preview" if operation.state == "previewed" else operation.state),
        "action_type": operation.action_type,
        "target": operation.target,
        "reason": operation.reason,
        "count": len(operation.ids),
        "impact": [{"id": identifier, "label": operation.labels.get(identifier)}
                   for identifier in operation.ids],
        "sample": operation.sample_payload(),
        "sample_size": min(_SAMPLE_SIZE, len(operation.ids)),
        "dual_review_required": operation.dual_required,
        "max_items": facts.BATCH_MAX_ITEMS,
        "undo_window_s": facts.BATCH_UNDO_WINDOW_S,
        "initiator": operation.initiator,
        "approver": operation.approver,
        "previewed_at": clock.iso(operation.previewed_at),
        "executed_at": clock.iso(operation.executed_at),
        "undo_deadline": clock.iso(operation.undo_deadline),
        "results": list(operation.results),
        "undo_results": list(operation.undo_results),
        "succeeded_count": len(operation.succeeded()),
        "failed_count": sum(1 for item in operation.results
                            if item.get("status") == "failed"),
    }
    return payload
