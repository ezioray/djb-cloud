# SPDX-License-Identifier: Apache-2.0
"""消费 M03 / M04 的事件（M05 §4.2 的「消费」四行）：request.completed / request.failed /
booking.created / config.published。

幂等策略（02-events §5「消费与本地状态同一事务；幂等」）——**不新增收件箱表**：

* ``request.completed``：估算落库走 ``usage_records`` 的天然唯一键
  ``(request_id, attempt_no)``，重复消费不会产生第二条用量；
* ``request.failed``：**不产生任何写**（失败不计费，INV-04）；若已存在 estimated 用量，
  返回 ``needs_correction`` 交给 T4 的校正（append-only，绝不修改原值）；
* ``booking.created``：只做金额核对（读），不落价、不改历史，天然幂等；
* ``config.published``：配置由 M10 注入的 provider 提供（``config_source``），
  本函数只校验 namespace 与版本单调，不写库。

因此本模块的消费逻辑可以在至少一次投递下重复执行：重复 = 无副作用。
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from . import amounts, clock, config_source, errors, events, facts, features, models, outbox

log = logging.getLogger("djb.metering.consumers")

#: 成交价只读 provider（M04）：``(request_id, model, access) -> {in_price_micro, out_price_micro}``
PriceProvider = Callable[[str, str, str], "Mapping[str, Any] | None"]


# --------------------------------------------------------------------------- 公共小工具
def _payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = event.get("payload")
    if not isinstance(payload, Mapping):
        raise errors.InvalidArgument("事件 payload 必须是对象", field="payload")
    return payload


def _text(payload: Mapping[str, Any], field: str, *, required: bool = True,
          max_len: int = facts.MAX_ID_LEN) -> str | None:
    value = payload.get(field)
    if value is None:
        if required:
            raise errors.InvalidArgument(f"事件缺 {field}", field=field)
        return None
    text = str(value).strip()
    if not text or len(text) > max_len:
        raise errors.InvalidArgument(f"事件字段 {field} 长度非法", field=field)
    return text


def _find_usage(c: Any, request_id: str, attempt_no: int = 1) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT usage_id, amount_minor, state, usage_source, receipt_id
                 FROM usage_records WHERE request_id = %s AND attempt_no = %s""",
            (request_id, attempt_no))
        row = cur.fetchone()
    if row is None:
        return None
    return {"usage_id": str(row[0]), "amount_minor": int(row[1]), "state": row[2],
            "usage_source": row[3], "receipt_id": row[4]}


def _insert_estimated(c: Any, *, request_id: str, attempt_no: int, account_id: str,
                      node_id: str, model: str, access: str, tokens_in: int, tokens_out: int,
                      amount_minor: int, usage_unit: str, now: Any,
                      trace_id: str) -> str | None:
    """落一条 ``usage_source=estimated`` 的用量（无收据路径）；重复消费返回 None。"""
    usage_id = str(models.uuid7(now))
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO usage_records
                 (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                  tokens_in, tokens_out, usage_amount, usage_unit, amount_minor, usage_source,
                  state, receipt_id, recorded_at, trace_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'estimated','recorded',NULL,%s,%s)
               ON CONFLICT (request_id, attempt_no) DO NOTHING""",
            (usage_id, request_id, attempt_no, account_id, node_id, model, access, tokens_in,
             tokens_out, str(tokens_in + tokens_out), usage_unit, amount_minor, now, trace_id))
        if cur.rowcount != 1:
            return None
    return usage_id


# --------------------------------------------------------------------------- request.completed
def on_request_completed(c: Any, event: Mapping[str, Any], *, now: Any = None,
                         price_provider: PriceProvider | None = None,
                         config: config_source.MeteringConfig | None = None) -> dict[str, Any]:
    """网关请求完成（元数据）：有收据则以收据为准；无收据时按开关落 ``estimated``。"""
    moment = clock.as_utc(now or clock.utcnow())
    payload = _payload(event)
    request_id = _text(payload, "request_id")
    attempt_no = int(payload.get("attempt_no") or 1)
    existing = _find_usage(c, request_id, attempt_no)
    if existing is not None:
        return {"action": "exists", "request_id": request_id, "usage_id": existing["usage_id"],
                "usage_source": existing["usage_source"]}
    if not features.enabled("metering.estimated_usage_from_gateway"):
        return {"action": "skipped", "reason": "switch_off", "request_id": request_id}
    snapshot = config or config_source.snapshot()
    account_id = _text(payload, "account_id")
    node_id = _text(payload, "node_id")
    model = _text(payload, "model")
    access = str(payload.get("access") or "A1").strip()
    if access not in facts.ACCESS_MODES:
        raise errors.InvalidArgument("access 取值非法", field="access")
    tokens_in = int(payload.get("tokens_in") or 0)
    tokens_out = int(payload.get("tokens_out") or 0)
    provider = price_provider
    prices = provider(request_id, model, access) if provider is not None else None
    if not prices:
        return {"action": "skipped", "reason": "price_unavailable", "request_id": request_id}
    try:
        amount_minor = amounts.compute_amount_minor(
            tokens_in=tokens_in, tokens_out=tokens_out,
            in_price_micro=int(prices.get("in_price_micro", 0)),
            out_price_micro=int(prices.get("out_price_micro", 0)))
    except amounts.AmountError as exc:
        raise errors.AmountPrecisionRejected(f"估算金额失败：{exc}") from exc
    usage_unit = str(payload.get("unit") or "token")
    trace_id = str(event.get("trace_id") or request_id)
    with c.transaction():
        usage_id = _insert_estimated(
            c, request_id=request_id, attempt_no=attempt_no, account_id=account_id,
            node_id=node_id, model=model, access=access, tokens_in=tokens_in,
            tokens_out=tokens_out, amount_minor=amount_minor, usage_unit=usage_unit,
            now=moment, trace_id=trace_id)
        if usage_id is not None:
            outbox.append(c, events.usage_recorded_event(
                usage_id=usage_id, account_id=account_id, request_id=request_id,
                amount_minor=amount_minor, source="estimated", trace_id=trace_id,
                occurred_at=moment, causation_id=str(event.get("event_id") or "") or None))
    if usage_id is None:
        current = _find_usage(c, request_id, attempt_no)
        return {"action": "exists", "request_id": request_id,
                "usage_id": current["usage_id"] if current else None,
                "usage_source": current["usage_source"] if current else None}
    return {"action": "recorded", "request_id": request_id, "usage_id": usage_id,
            "amount_minor": amount_minor, "usage_source": "estimated",
            "tolerance_pct": snapshot.overbill_tolerance_pct}


# --------------------------------------------------------------------------- request.failed
def on_request_failed(c: Any, event: Mapping[str, Any]) -> dict[str, Any]:
    """请求失败（不计费，INV-04）：不写库；若已有 estimated 用量则交给 T4 校正。"""
    payload = _payload(event)
    request_id = _text(payload, "request_id")
    attempt_no = int(payload.get("attempt_no") or 1)
    existing = _find_usage(c, request_id, attempt_no)
    if existing is None:
        return {"action": "noop", "request_id": request_id}
    if existing["usage_source"] == "estimated":
        return {"action": "needs_correction", "request_id": request_id,
                "usage_id": existing["usage_id"], "reason_code": "estimate_fix",
                "amount_minor": existing["amount_minor"]}
    return {"action": "noop", "request_id": request_id, "usage_id": existing["usage_id"],
            "usage_source": existing["usage_source"]}


# --------------------------------------------------------------------------- booking.created
def on_booking_created(c: Any, event: Mapping[str, Any], *,
                       price_provider: PriceProvider | None = None) -> dict[str, Any]:
    """取成交价做金额校验（M05 §4.2 消费行）：只读核对，不改历史、不落价。"""
    payload = _payload(event)
    booking_id = _text(payload, "booking_id")
    request_id = _text(payload, "request_id", required=False)
    if request_id is None:
        return {"action": "noop", "booking_id": booking_id, "reason": "no_request_id"}
    existing = _find_usage(c, request_id, int(payload.get("attempt_no") or 1))
    if existing is None:
        return {"action": "noop", "booking_id": booking_id, "reason": "no_usage"}
    provider = price_provider
    prices = provider(request_id, str(payload.get("model") or ""),
                      str(payload.get("access") or "A1")) if provider is not None else None
    if not prices:
        return {"action": "checked", "booking_id": booking_id, "match": None,
                "reason": "price_unavailable"}
    return {"action": "checked", "booking_id": booking_id,
            "usage_id": existing["usage_id"], "amount_minor": existing["amount_minor"],
            "in_price_micro": prices.get("in_price_micro"),
            "out_price_micro": prices.get("out_price_micro")}


# --------------------------------------------------------------------------- config.published
def on_config_published(event: Mapping[str, Any], *,
                        current_version: int | None = None) -> dict[str, Any]:
    """配置发布（M05 §4.2）：只校验 namespace 与版本单调；生效值由 M10 provider 提供。"""
    payload = _payload(event)
    namespace = _text(payload, "namespace", max_len=32)
    if namespace != facts.CONFIG_NAMESPACE:
        return {"action": "ignored", "namespace": namespace}
    version = payload.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise errors.InvalidArgument("config.published 的 version 必须是正整数", field="version")
    if current_version is not None and version <= current_version:
        return {"action": "ignored", "namespace": namespace, "reason": "stale_version"}
    return {"action": "applied", "namespace": namespace, "version": version}


# --------------------------------------------------------------------------- 分发
_CONSUMERS = {
    "request.completed": on_request_completed,
    "request.failed": on_request_failed,
    "booking.created": on_booking_created,
    "config.published": on_config_published,
}


def consume(c: Any, event: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
    """按 ``type`` 分发（tolerant reader：未知类型忽略并记日志，不让分区卡住）。"""
    event_type = str(event.get("type") or "")
    handler = _CONSUMERS.get(event_type)
    if handler is None:
        log.warning("metering.consumer.unknown_type", extra={"type": event_type})
        return {"action": "ignored", "type": event_type}
    if event_type == "config.published":
        return handler(event, **kwargs)
    return handler(c, event, **kwargs)


__all__ = ["PriceProvider", "on_request_completed", "on_request_failed", "on_booking_created",
           "on_config_published", "consume"]
