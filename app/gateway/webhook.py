# SPDX-License-Identifier: AGPL-3.0-or-later
"""对外批次 Webhook（T4 / M03 §4.3「属对客户的外部投递，不走内部事件总线」）。

契约（本模块定义，写入 ``app/gateway/WIRING.md``）：

* **事件**：``batch.queued`` / ``batch.started`` / ``batch.checkpoint_restored`` /
  ``batch.completed`` / ``batch.failed`` / ``batch.eta_updated``（``facts.WEBHOOK_EVENTS``）。
* **载荷**：``{event, batch_id, account_id, status, progress{completed,total}, eta_seconds,
  checkpoint_resumes, cost{estimated,actual}, occurred_at}``——只含元数据与金额，
  **不含** prompt / response / 凭据（INV-M03-02）。键集合与 ``contracts/02-events.md``
  的 M03 行对齐（``cost_estimate/actual`` 落成嵌套 ``cost.estimated`` / ``cost.actual``），
  由 ``tests/gateway/test_contract_events.py`` 守卫。
* **签名**：``X-DJB-Signature: hmac-sha256=<hex>``，签名对象是
  ``f"{X-DJB-Timestamp}.{raw_body}"``；客户端必须校验时间窗 ±300s 防重放。
  密钥按账户从注入的 :class:`app.gateway.providers.WebhookSecretProvider` 取**引用**；
  取不到密钥 → 不投递（``skipped``），绝不发未签名回调。
* **重试**：最多 ``facts.WEBHOOK_MAX_ATTEMPTS``（3）次，退避 ``1s/5s/30s``；失败只记台账，
  **不影响**批次状态（投递是通知，不是业务事务）。
* **台账**：写 ``batch_jobs.webhook_state`` / ``webhook_attempts`` / ``webhook_last_error`` /
  ``webhook_delivered_at``（迁移 306）。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock, facts, models, providers, store

log = logging.getLogger("djb.gateway.webhook")

__all__ = ["DELIVERED", "FAILED", "SKIPPED", "deliver", "build_payload", "sign", "headers",
           "coerce_status"]

DELIVERED = "delivered"
FAILED = "failed"
SKIPPED = "skipped"


def coerce_status(value: Any) -> int | None:
    """把 sender 的返回值规整成 HTTP 状态码（None = 未知）。"""
    if value is None:
        return None
    if isinstance(value, bool):
        return 200 if value else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_payload(*, event_type: str, batch: models.BatchView, occurred_at: datetime,
                  extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """webhook 载荷（只元数据 + 金额；``Amount`` 用十进制字符串）。"""
    if event_type not in facts.WEBHOOK_EVENTS:
        raise ValueError(f"未登记的 webhook 事件：{event_type!r}（M03 §4.3）")
    payload: dict[str, Any] = {
        "event": event_type,
        "batch_id": batch.batch_id,
        "account_id": batch.account_id,          # 02-events §3 登记的必含键（M14 消费侧路由用）
        "status": batch.status,
        "progress": {"completed": int(batch.completed_items),
                     "total": int(batch.total_items)},
        "eta_seconds": None if batch.eta_seconds is None else int(batch.eta_seconds),
        "checkpoint_resumes": int(batch.checkpoint_resumes),
        "occurred_at": clock.iso(occurred_at),
    }
    cost: dict[str, Any] = {}
    if batch.cost_estimate_minor is not None:
        cost["estimated"] = {"amount": models.format_amount_minor(batch.cost_estimate_minor),
                             "unit": "USD"}
    if batch.cost_actual_minor is not None:
        cost["actual"] = {"amount": models.format_amount_minor(batch.cost_actual_minor),
                          "unit": "USD"}
    if cost:
        payload["cost"] = cost
    if extra:
        payload.update(dict(extra))
    return payload


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """``hmac-sha256`` over ``f"{timestamp}." + body``（十六进制小写）。"""
    message = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def headers(*, event_type: str, timestamp: str, signature: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        facts.WEBHOOK_EVENT_HEADER: event_type,
        facts.WEBHOOK_TIMESTAMP_HEADER: timestamp,
        facts.WEBHOOK_SIGNATURE_HEADER: f"{facts.WEBHOOK_SIGNATURE_ALGORITHM}={signature}",
    }


@dataclass(frozen=True)
class DeliveryResult:
    state: str
    attempts: int
    last_status: int | None = None
    last_error: str | None = None


def deliver(c: Any, *, event_type: str, batch: models.BatchView, now: datetime,
            payload_extra: Mapping[str, Any] | None = None,
            sleep: Callable[[float], None] | None = None,
            sender: Callable[[str, bytes, Mapping[str, str]], Any] | None = None,
            secret_provider: Callable[[str], Any] | None = None) -> DeliveryResult:
    """投递一次 webhook（带重试与台账）；未配置 URL / 未接线 / 无密钥 → ``skipped``。"""
    url = batch.webhook_url
    if not url:
        return DeliveryResult(SKIPPED, 0)
    send = sender or providers.send_webhook
    secret_lookup = secret_provider or providers.webhook_secret
    secret = models.str_or_none(secret_lookup(batch.account_id))
    if not secret:
        log.warning("gateway.webhook.no_secret",
                    extra={"event": "webhook.no_secret", "batch_id": batch.batch_id})
        store.update_batch_webhook(c, batch_id=batch.batch_id, state=SKIPPED, attempts=0,
                                   last_error="no secret configured", delivered_at=None)
        return DeliveryResult(SKIPPED, 0, last_error="no secret configured")

    body = json.dumps(build_payload(event_type=event_type, batch=batch, occurred_at=now,
                                    extra=payload_extra),
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(clock.as_utc(now).timestamp()))
    signature = sign(secret, timestamp, body)
    request_headers = headers(event_type=event_type, timestamp=timestamp, signature=signature)
    pause = sleep or time.sleep
    attempts = 0
    last_status: int | None = None
    last_error: str | None = None
    for index in range(facts.WEBHOOK_MAX_ATTEMPTS):
        attempts += 1
        try:
            result = send(url, body, request_headers)
        except Exception as exc:                            # 投递侧异常：退避重试
            last_error = f"{type(exc).__name__}: {exc}"[:200]
            result = None
        if result is not None:
            last_status = coerce_status(result)
            if last_status is not None and 200 <= last_status < 300:
                store.update_batch_webhook(c, batch_id=batch.batch_id, state=DELIVERED,
                                           attempts=attempts, last_error=None,
                                           delivered_at=now)
                return DeliveryResult(DELIVERED, attempts, last_status=last_status)
            last_error = f"http {last_status}" if last_status is not None else "no sender"
        if index + 1 < facts.WEBHOOK_MAX_ATTEMPTS:
            backoff = facts.WEBHOOK_BACKOFF_S[min(index, len(facts.WEBHOOK_BACKOFF_S) - 1)]
            try:
                pause(backoff)
            except Exception:                               # pragma: no cover - 防御
                break
    store.update_batch_webhook(c, batch_id=batch.batch_id, state=FAILED, attempts=attempts,
                               last_error=last_error, delivered_at=None)
    log.warning("gateway.webhook.failed",
                extra={"event": "webhook.failed", "batch_id": batch.batch_id,
                       "attempts": attempts, "status": last_status})
    return DeliveryResult(FAILED, attempts, last_status=last_status, last_error=last_error)
