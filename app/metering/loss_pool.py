# SPDX-License-Identifier: AGPL-3.0-or-later
"""亏损池（M05 §3 INV-09 / §5 / §6 流程 3 第 3 步）：只记「上游已消耗、用户未计费」。

铁律：

* 只追加（DDL 触发器拒绝 UPDATE/DELETE/TRUNCATE）；
* 同一 ``(request_id, attempt_no)`` 只能一条（重复入池 = 重复计成本）；
* 金额必须 > 0；**不冲减 4101**、不写 usage、不做任何计费侧的补偿；
* 与 M06 的衔接走**注入 sink**（``set_loss_pool_sink``）：M06 消费后落 E15（借 5104 / 贷 1109）。
  02-events 目前没有登记 loss_pool 事件（M05 §4.2 只登记 3 个生产事件），所以这里不虚构事件类型，
  由 Lead 决定是走 sink 直连还是先补登记事件（证据 §未做项 已登记）。
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Mapping

from . import clock, errors, facts, models

log = logging.getLogger("djb.metering.loss_pool")

#: ``sink(entry: Mapping) -> Any``：由 Lead 接到 M06（或后续事件发布）
LossPoolSink = Callable[[Mapping[str, Any]], Any]

_sink: LossPoolSink | None = None


def set_loss_pool_sink(sink: LossPoolSink | None) -> None:
    global _sink
    _sink = sink


def current_sink() -> LossPoolSink | None:
    return _sink


def load(c: Any, entry_id: str) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT entry_id, request_id, attempt_no, amount_minor, reason, evidence_ref,
                      recorded_at FROM loss_pool_entries WHERE entry_id = %s""", (entry_id,))
        row = cur.fetchone()
    if row is None:
        return None
    keys = ("entry_id", "request_id", "attempt_no", "amount_minor", "reason", "evidence_ref",
            "recorded_at")
    item = dict(zip(keys, row))
    item["entry_id"] = str(item["entry_id"])
    return item


def find(c: Any, request_id: str, attempt_no: int = 1) -> dict[str, Any] | None:
    with c.cursor() as cur:
        cur.execute(
            """SELECT entry_id FROM loss_pool_entries WHERE request_id = %s AND attempt_no = %s""",
            (request_id, attempt_no))
        row = cur.fetchone()
    return load(c, str(row[0])) if row else None


def record(c: Any, *, request_id: Any, amount_minor: Any, reason: Any,
           attempt_no: int = 1, evidence_ref: Any = None, now: Any = None,
           sink: LossPoolSink | None = None) -> dict[str, Any]:
    """记一条亏损：幂等（同 request/attempt 返回首次结果），可选调用注入 sink。"""
    moment = clock.as_utc(now or clock.utcnow())
    if not isinstance(request_id, str) or not (1 <= len(request_id.strip()) <= facts.MAX_ID_LEN):
        raise errors.InvalidArgument(f"request_id 长度必须是 1..{facts.MAX_ID_LEN}",
                                     field="request_id")
    if isinstance(attempt_no, bool) or not isinstance(attempt_no, int) or attempt_no < 1:
        raise errors.InvalidArgument("attempt_no 从 1 开始", field="attempt_no")
    if isinstance(amount_minor, bool) or not isinstance(amount_minor, int) or amount_minor <= 0:
        raise errors.InvalidArgument("amount_minor 必须是正整数（分）", field="amount_minor")
    if reason not in facts.LOSS_POOL_REASONS:
        raise errors.InvalidArgument("reason 取值非法", field="reason",
                                     allowed=list(facts.LOSS_POOL_REASONS))
    if evidence_ref is not None and (not isinstance(evidence_ref, str)
                                     or not (1 <= len(evidence_ref) <= facts.MAX_EVIDENCE_LEN)):
        raise errors.InvalidArgument(
            f"evidence_ref 长度必须是 1..{facts.MAX_EVIDENCE_LEN}", field="evidence_ref")

    request_text = request_id.strip()
    entry_id = str(models.uuid7(moment))
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO loss_pool_entries
                 (entry_id, request_id, attempt_no, amount_minor, reason, evidence_ref,
                  recorded_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (request_id, attempt_no) DO NOTHING""",
            (entry_id, request_text, attempt_no, int(amount_minor), reason, evidence_ref,
             moment))
        inserted = cur.rowcount == 1
    if not inserted:
        existing = find(c, request_text, attempt_no)
        return {"created": False, "entry": existing}
    entry = load(c, entry_id)
    active = sink if sink is not None else _sink
    if active is not None:
        active(entry)
    log.info("metering.loss_pool.recorded",
             extra={"entry_id": entry_id, "request_id": request_text,
                    "amount_minor": int(amount_minor), "reason": reason})
    return {"created": True, "entry": entry}


__all__ = ["LossPoolSink", "set_loss_pool_sink", "current_sink", "load", "find", "record"]
