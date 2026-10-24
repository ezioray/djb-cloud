# SPDX-License-Identifier: AGPL-3.0-or-later
"""慢任务（批次）领域服务（T4 / M03 §6 流程 3 / §3.1 状态机 / INV-M03-06 / INV-M03-09）。

覆盖的端点语义（HTTP 层在 :mod:`app.gateway.router`）：

| 操作 | spec | 口径 |
| --- | --- | --- |
| 提交 | ``POST /v1/batches`` → 202 | 幂等 24h（CR-10 中间件）→ 校验 → M04 批量报价（ETA/成本）→ >10 USD 先确认 → 落 ``batch_jobs`` + ``batch_items`` + ``batch.queued`` webhook |
| 轮询 | ``GET /v1/batches/{id}`` → 200 | 进度 / ETA / 检查点 / ``results_ref``（≤15 分钟，过期自动重签）/ 实际成本 |
| 取消 | ``POST /v1/batches/{id}/cancel`` → 200 | **幂等**：终态返回当前状态；非终态 → canceled（DB 触发器补 ``canceled_at``） |
| 推进（内部） | — | 执行 worker（M16 调度）调用 :func:`advance` 做 queued→running→终态 + webhook |

边界：

* **正文不落库**：``batch_items`` 只存 ``custom_id`` 与序号；``input`` 只做校验与计数，
  不进数据库、不进日志、不进事件（INV-M03-02）。
* **金额**：``cost_estimate`` / ``cost`` 用 ``Amount``（十进制字符串）对外，
  库内一律 ``*_minor`` 整数分（00-conventions §3.1）；结算以 M05 收据与账本为准。
* **越权统一 404**：不属于该账户的批次一律 ``404 / 40401``，不泄露存在性。
* **终态不可逆**：DB 触发器（302/306）与应用层双重保证；取消幂等不报错。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from . import (clock, errors, facts, features, idempotency, models, providers, ratelimit,
               store, webhook)

log = logging.getLogger("djb.gateway.batches")

__all__ = ["BatchSubmit", "validate_batch", "submit", "get", "cancel", "advance",
           "batch_payload", "item_payload"]


# --------------------------------------------------------------------------- 校验
def _require_text(value: Any, *, field_name: str, max_length: int | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise errors.GatewayError("bad_request", f"{field_name} 必填且不能为空",
                                  details={"field": field_name})
    text = value.strip()
    if max_length is not None and len(text) > max_length:
        raise errors.GatewayError("bad_request", f"{field_name} 超过 {max_length} 字符",
                                  details={"field": field_name})
    return text


def _validate_items(value: Any) -> tuple[models.BatchItemDraft, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise errors.GatewayError("bad_request", "items 必须是数组", details={"field": "items"})
    items = list(value)
    if not items:
        raise errors.GatewayError("bad_request", "items 至少 1 条", details={"field": "items"})
    if len(items) > facts.BATCH_MAX_ITEMS:
        raise errors.GatewayError(
            "payload_too_large", f"单批次最多 {facts.BATCH_MAX_ITEMS} 条",
            details={"max_items": facts.BATCH_MAX_ITEMS})
    out: list[models.BatchItemDraft] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise errors.GatewayError("bad_request", f"items[{index}] 必须是对象",
                                      details={"field": f"items[{index}]"})
        custom_id = _require_text(item.get("custom_id"), field_name=f"items[{index}].custom_id",
                                  max_length=128)
        if custom_id in seen:
            raise errors.GatewayError("bad_request",
                                      f"items[{index}].custom_id 重复：{custom_id}",
                                      details={"field": f"items[{index}].custom_id"})
        seen.add(custom_id)
        body = item.get("input")
        if body is not None and not isinstance(body, Mapping):
            raise errors.GatewayError("bad_request", f"items[{index}].input 必须是对象",
                                      details={"field": f"items[{index}].input"})
        out.append(models.BatchItemDraft(custom_id=custom_id,
                                         body=dict(body) if body is not None else None))
    return tuple(out)


def validate_batch(body: Mapping[str, Any]) -> models.BatchDraft:
    """校验 ``BatchCreateRequest``（spec 1.2.x）。"""
    if not isinstance(body, Mapping):
        raise errors.GatewayError("bad_request", "请求体必须是 JSON 对象")
    kind = body.get("kind")
    if kind not in facts.BATCH_KINDS:
        raise errors.GatewayError("bad_request", f"kind 必须是 {facts.BATCH_KINDS} 之一",
                                  details={"field": "kind"})
    model = _require_text(body.get("model"), field_name="model",
                          max_length=facts.MODEL_SLUG_MAX_LENGTH)
    items = _validate_items(body.get("items"))

    deadline = body.get("deadline_seconds")
    if deadline is not None:
        if isinstance(deadline, bool) or not isinstance(deadline, int) or deadline < 60:
            raise errors.GatewayError("bad_request", "deadline_seconds 必须是 ≥60 的整数",
                                      details={"field": "deadline_seconds"})

    webhook_url = body.get("webhook_url")
    if webhook_url is not None:
        webhook_url = _require_text(webhook_url, field_name="webhook_url", max_length=2048)
        parsed = urlparse(webhook_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise errors.GatewayError("bad_request", "webhook_url 必须是 http(s) URL",
                                      details={"field": "webhook_url"})

    metadata = body.get("metadata")
    if metadata is not None and not isinstance(metadata, Mapping):
        raise errors.GatewayError("bad_request", "metadata 必须是对象",
                                  details={"field": "metadata"})
    metadata = dict(metadata or {})
    confirm = bool(metadata.pop("confirm_cost", False))

    known = {"kind", "model", "items", "deadline_seconds", "webhook_url", "metadata"}
    extras = [key for key in body.keys() if key not in known]
    if extras:
        log.info("gateway.batches.unknown_fields",
                 extra={"event": "batches.unknown_fields", "count": len(extras)})
    return models.BatchDraft(kind=str(kind), model=model, items=items,
                             deadline_seconds=None if deadline is None else int(deadline),
                             webhook_url=webhook_url, metadata=metadata,
                             confirm_cost=confirm)


# --------------------------------------------------------------------------- 读侧视图
def batch_payload(batch: models.BatchView, *, now: datetime) -> dict[str, Any]:
    """spec ``Batch``（``progress`` / ``cost`` / ``results_ref`` 按需出现）。"""
    payload: dict[str, Any] = {
        "batch_id": batch.batch_id,
        "status": batch.status,
        "progress": {"completed": int(batch.completed_items),
                     "total": int(batch.total_items)},
        "checkpoint_resumes": int(batch.checkpoint_resumes),
        "created_at": clock.iso(batch.created_at) if batch.created_at else None,
        "updated_at": clock.iso(batch.updated_at) if batch.updated_at else None,
    }
    if batch.eta_seconds is not None:
        payload["eta_seconds"] = int(batch.eta_seconds)
    if batch.error_code is not None:
        payload["error_code"] = int(batch.error_code)
    cost: dict[str, Any] = {}
    if batch.cost_estimate_minor is not None:
        cost["estimated"] = {"amount": models.format_amount_minor(batch.cost_estimate_minor),
                             "unit": "USD"}
    if batch.cost_actual_minor is not None:
        cost["actual"] = {"amount": models.format_amount_minor(batch.cost_actual_minor),
                          "unit": "USD"}
    if cost:
        payload["cost"] = cost
    if batch.cost_estimate_minor is not None:
        payload["cost_estimate"] = {
            "amount": models.format_amount_minor(batch.cost_estimate_minor), "unit": "USD"}
    if batch.completed_at is not None:
        payload["completed_at"] = clock.iso(batch.completed_at)
    if batch.canceled_at is not None:
        payload["canceled_at"] = clock.iso(batch.canceled_at)
    if batch.results_ref is not None:
        payload["results_ref"] = batch.results_ref
    return payload


def item_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"custom_id": row.get("custom_id"), "status": row.get("status"),
                               "seq": int(row.get("seq") or 0)}
    if row.get("usage_id"):
        payload["usage_id"] = row["usage_id"]
    if row.get("amount_minor") is not None:
        payload["cost"] = {"amount": models.format_amount_minor(int(row["amount_minor"])),
                           "unit": "USD"}
    if row.get("error_code") is not None:
        payload["error_code"] = int(row["error_code"])
    return payload


# --------------------------------------------------------------------------- 提交
@dataclass(frozen=True)
class BatchSubmit:
    """提交结果（``status_code`` 202；``needs_confirm`` 时是 45202 的确认态）。"""

    status_code: int
    payload: dict[str, Any]
    headers: dict[str, str]
    replayed: bool = False
    needs_confirm: bool = False
    batch: models.BatchView | None = None


def _results_ref(batch: models.BatchView, *, now: datetime,
                 signed: str | None = None) -> tuple[str | None, datetime | None]:
    """结果引用：未过期沿用；过期或未签发则重新签发（INV-M03-09「过期重新签发」）。"""
    if batch.results_ref and batch.results_expires_at and batch.results_expires_at > now:
        return batch.results_ref, batch.results_expires_at
    expires_at = now + timedelta(seconds=facts.BATCH_RESULT_URL_TTL_S)
    url = signed or providers.sign_result(batch.batch_id, expires_at)
    if url is None:
        return batch.results_ref, batch.results_expires_at
    return url, expires_at


def submit(c: Any, *, principal: models.Principal, body: Mapping[str, Any], request_id: str,
           trace_id: str, idempotency_key: str | None = None, now: datetime | None = None,
           limiter: ratelimit.SlidingWindowLimiter | None = None) -> BatchSubmit:
    """提交慢任务（202）。失败抛 :class:`app.gateway.errors.GatewayError`。"""
    moment = clock.as_utc(now or clock.utcnow())
    _, _, _ = ratelimit.precheck(principal, now=moment, bucket=limiter)
    draft = validate_batch(body)

    guard = idempotency.WriteGuard(c, principal=principal, method="POST", path="/v1/batches",
                                   key=idempotency_key, body=dict(body), now=moment)
    replay = guard.replay()
    if replay is not None:
        if replay.payload.get("confirm_required"):
            return BatchSubmit(status_code=replay.status_code, payload=dict(replay.payload),
                               headers={facts.IDEMPOTENT_REPLAY_HEADER: "true"},
                               replayed=True, needs_confirm=True)
        return BatchSubmit(status_code=replay.status_code, payload=dict(replay.payload),
                           headers={facts.IDEMPOTENT_REPLAY_HEADER: "true",
                                    facts.LOCATION_HEADER:
                                        f"/v1/batches/{replay.payload.get('batch_id')}"},
                           replayed=True)

    # M04 批量报价（eta / 单价）；无路由 → 503 / 50901（不自行猜节点）
    decision = providers.route(models.RouteRequest(
        model=draft.model, kind="batch", tenant_id=principal.tenant_id,
        account_id=principal.account_id, request_id=request_id, trace_id=trace_id,
        attempt_no=1, deadline_seconds=draft.deadline_seconds))
    eta_seconds = int(decision.eta_seconds or 0)
    unit_minor = decision.price_minor
    cost_estimate_minor = (None if unit_minor is None
                           else unit_minor * len(draft.items))

    # > 10 USD 先确认（M03 §6.3 / §4.4：202 + 45202，确认后计）
    if (cost_estimate_minor is not None
            and cost_estimate_minor > facts.BATCH_COST_CONFIRM_MINOR
            and not draft.confirm_cost):
        exc = errors.GatewayError(
            "cost_confirm_required",
            f"预估成本超过 {facts.BATCH_COST_CONFIRM_USD} USD：请在 metadata.confirm_cost=true 后重试",
            details={"cost_estimate": {"amount": models.format_amount_minor(cost_estimate_minor),
                                       "unit": "USD"},
                     "confirm_required": True})
        payload = errors.error_body(exc, request_id)["error"]
        payload["confirm_required"] = True
        body_payload = {"error": payload}
        guard.remember(status_code=exc.http_status, payload=body_payload)
        return BatchSubmit(status_code=exc.http_status, payload=body_payload,
                           headers={}, needs_confirm=True)

    batch_id = str(models.uuid7(int(moment.timestamp() * 1_000_000)))
    store.insert_batch(c, batch_id=batch_id, account_id=principal.account_id,
                       tenant_id=principal.tenant_id, api_key_id=principal.api_key_id,
                       kind=draft.kind, model=draft.model, status="queued",
                       request_id=request_id, idempotency_key=idempotency_key,
                       total_items=len(draft.items), eta_seconds=eta_seconds,
                       cost_estimate_minor=cost_estimate_minor,
                       deadline_seconds=draft.deadline_seconds,
                       webhook_url=draft.webhook_url, metadata=draft.metadata, now=moment)
    store.insert_batch_items(c, batch_id=batch_id,
                             custom_ids=[item.custom_id for item in draft.items], now=moment)

    payload = {"batch_id": batch_id, "status": "queued", "eta_seconds": eta_seconds,
               "created_at": clock.iso(moment)}
    if cost_estimate_minor is not None:
        payload["cost_estimate"] = {"amount": models.format_amount_minor(cost_estimate_minor),
                                    "unit": "USD"}
    headers = {facts.LOCATION_HEADER: f"/v1/batches/{batch_id}"}
    guard.remember(status_code=202, payload=payload)
    batch = store.get_batch(c, batch_id=batch_id)
    if batch is not None:
        _notify(c, event_type="batch.queued", batch=batch, now=moment)
    return BatchSubmit(status_code=202, payload=payload, headers=headers, batch=batch)


# --------------------------------------------------------------------------- 轮询 / 取消
def _owned(c: Any, *, principal: models.Principal, batch_id: str) -> models.BatchView:
    batch = store.get_batch(c, batch_id=batch_id)
    if batch is None or batch.account_id != principal.account_id:
        raise errors.GatewayError("not_found", "批次不存在或不可见")
    return batch


def get(c: Any, *, principal: models.Principal, batch_id: str,
        now: datetime | None = None) -> dict[str, Any]:
    """轮询批次状态（200）；``results_ref`` 过期自动重签。"""
    moment = clock.as_utc(now or clock.utcnow())
    batch = _owned(c, principal=principal, batch_id=batch_id)
    if batch.status in {"succeeded"}:
        url, expires_at = _results_ref(batch, now=moment)
        if url and url != batch.results_ref:
            store.update_batch(c, batch_id=batch.batch_id,
                               values={"results_ref": url, "results_expires_at": expires_at})
            batch = store.get_batch(c, batch_id=batch.batch_id) or batch
    payload = batch_payload(batch, now=moment)
    rows = store.list_batch_items(c, batch_id=batch.batch_id)
    if rows:
        payload["items"] = [item_payload(row) for row in rows]
    return payload


def cancel(c: Any, *, principal: models.Principal, batch_id: str,
           now: datetime | None = None, idempotency_key: str | None = None) -> dict[str, Any]:
    """取消（幂等）：终态返回当前状态；非终态迁移到 canceled。

    幂等中间件（CR-10）：带 ``X-DJB-Idempotency-Key`` 时，重复提交回放首次响应；
    不带键时靠**状态机幂等**（终态不迁移、不报错，INV-M03-06）。
    """
    moment = clock.as_utc(now or clock.utcnow())
    batch = _owned(c, principal=principal, batch_id=batch_id)
    guard = idempotency.WriteGuard(
        c, principal=principal, method="POST", path=f"/v1/batches/{batch_id}/cancel",
        key=idempotency_key, body={"batch_id": batch_id}, now=moment)
    replay = guard.replay() if idempotency_key else None
    if replay is not None:
        return dict(replay.payload)
    if batch.terminal:
        payload = {"batch_id": batch.batch_id, "status": batch.status}
        if batch.canceled_at is not None:
            payload["canceled_at"] = clock.iso(batch.canceled_at)
        if idempotency_key:
            guard.remember(status_code=200, payload=payload)
        return payload
    updated = store.cancel_batch(c, batch_id=batch_id, now=moment)
    if updated is None:                                     # pragma: no cover - 并发删除
        raise errors.GatewayError("not_found", "批次不存在或不可见")
    payload = {"batch_id": updated.batch_id, "status": updated.status}
    if updated.canceled_at is not None:
        payload["canceled_at"] = clock.iso(updated.canceled_at)
    # M03 §4.3 的 webhook 事件目录没有 canceled：取消不回 webhook（客户端由轮询得知）
    if idempotency_key:
        guard.remember(status_code=200, payload=payload)
    return payload


# --------------------------------------------------------------------------- 执行推进（worker）
def advance(c: Any, *, batch_id: str, status: str, now: datetime | None = None,
            completed: int | None = None, failed: int | None = None,
            eta_seconds: int | None = None, cost_actual_minor: int | None = None,
            error_code: int | None = None, checkpoint_resumes: int | None = None,
            account_id: str | None = None) -> models.BatchView:
    """执行 worker 调用：queued → running → succeeded / failed（终态不可逆）。

    ``account_id`` 给定时用于校验归属（worker 侧通常已知）；终态会顺带签发 ``results_ref``
    并投递 webhook。
    """
    moment = clock.as_utc(now or clock.utcnow())
    batch = store.get_batch(c, batch_id=batch_id)
    if batch is None or (account_id is not None and batch.account_id != account_id):
        raise errors.GatewayError("not_found", "批次不存在或不可见")
    if status not in facts.BATCH_STATUSES:
        raise ValueError(f"非法状态：{status!r}（M03 §3.1）")
    if batch.terminal and status != batch.status:
        raise errors.GatewayError("conflict", f"批次已处于终态 {batch.status}，不可再迁移",
                                  details={"status": batch.status})
    values: dict[str, Any] = {"status": status}
    if completed is not None:
        values["completed_items"] = int(completed)
    if failed is not None:
        values["failed_items"] = int(failed)
    if eta_seconds is not None:
        values["eta_seconds"] = int(eta_seconds)
    if cost_actual_minor is not None:
        values["cost_actual_minor"] = int(cost_actual_minor)
    if error_code is not None:
        values["error_code"] = int(error_code)
    if checkpoint_resumes is not None:
        values["checkpoint_resumes"] = int(checkpoint_resumes)
    if status == "succeeded":
        expires_at = moment + timedelta(seconds=facts.BATCH_RESULT_URL_TTL_S)
        url = providers.sign_result(batch_id, expires_at)
        if url is not None:
            values["results_ref"] = url
            values["results_expires_at"] = expires_at
    store.update_batch(c, batch_id=batch_id, values=values)
    updated = store.get_batch(c, batch_id=batch_id)
    assert updated is not None
    event_map = {"running": "batch.started", "succeeded": "batch.completed",
                 "failed": "batch.failed", "queued": "batch.eta_updated"}
    event_type = event_map.get(status)
    if event_type and (checkpoint_resumes or 0) > int(batch.checkpoint_resumes):
        event_type = "batch.checkpoint_restored"
    if event_type:
        _notify(c, event_type=event_type, batch=updated, now=moment)
    return updated


def _notify(c: Any, *, event_type: str, batch: models.BatchView, now: datetime) -> None:
    """对外 webhook（闸门 ``gateway.batch_webhook_delivery`` 默认关闭 → 只落库不投递）。"""
    if not batch.webhook_url:
        return
    if not features.enabled("gateway.batch_webhook_delivery"):
        log.info("gateway.batches.webhook_gated",
                 extra={"event": "batches.webhook_gated", "batch_id": batch.batch_id,
                        "event_type": event_type})
        return
    try:
        webhook.deliver(c, event_type=event_type, batch=batch, now=now)
    except Exception:                                       # pragma: no cover - 防御
        log.warning("gateway.batches.webhook_failed",
                    extra={"event": "batches.webhook_failed", "batch_id": batch.batch_id})
