# SPDX-License-Identifier: AGPL-3.0-or-later
"""收据受理：双签验签 + 24h 窗口 + 幂等 + 同事务落 ``metering_receipts`` / ``usage_records``。

对应 M05 §6 流程 1（同步）与 §7 失败矩阵：

1. 形态校验（缺字段 / 金额超精度 → 单条 ``rejected 40001``，不回滚整批，INV-02）；
2. 幂等（INV-03）：``receipt_id`` 命中**已受理**收据 → 直接返回首次结果（``duplicate``），
   不重复计量；同一 ``(request_id, attempt_no)`` 已有计费用量 → 单条拒收（INV-04）；
3. 归属（安全）：收据声明的 ``node_id`` 必须与鉴权主体一致，且节点必须在 M02 只读视图里；
4. 窗口：``now - reported_at > metering.receipt_late_h`` → ``expired``（默认 24h）；
5. 双签（INV-01）：两侧密钥独立，缺一 / 算法不符 / 摘要不符 → ``46001``；
6. 金额（INV-05）：若注入了成交价 provider，用整数精确复算并与 ``price_amount`` 比对；
7. 落库：收据 + 用量 + **outbox 事件**同一事务（CR-5，迁移 506）；被拒收据也留痕
   （append-only），供节点自查与失败率告警。

**不与 M06/M02 共享事务、不 import 其它模块**：节点存在性只读 ``v_supply_node_snapshot``，
账户与成交价只经注入 provider（T3 接线）。事件信封在 :mod:`app.metering.events`（T3 投递）。
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Callable, Mapping, Sequence

import psycopg

from . import (amounts, clock, config_source, errors, events, facts, models, outbox,
               signing)

log = logging.getLogger("djb.metering.receipts")

#: ``provider(request_id, model, access) -> {"in_price_micro": int, "out_price_micro": int} | None``
PriceProvider = Callable[[str, str, str], "Mapping[str, Any] | None"]

_price_provider: PriceProvider | None = None


def set_price_provider(provider: PriceProvider | None) -> None:
    """注入成交价（M04 booking）只读 provider；T1/T2 默认 None（不校验金额，只记事实）。"""
    global _price_provider
    _price_provider = provider


def current_price_provider() -> PriceProvider | None:
    return _price_provider


# ───────────────────────────────────────────────────────────────────── 只读探测
def node_in_snapshot(c: Any, node_id: str) -> bool:
    """节点存在性只经 M02 只读视图（01-ownership §2 / 00-conventions §7.4）。"""
    with c.cursor() as cur:
        cur.execute(f"SELECT 1 FROM {facts.NODE_SNAPSHOT_VIEW} WHERE node_id = %s", (node_id,))
        return cur.fetchone() is not None


def find_accepted(c: Any, receipt_id: str) -> dict[str, Any] | None:
    """按 receipt_id 找**已受理**行（幂等返回首次结果用）。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT r.receipt_id, r.node_id, r.usage_id, r.received_at,
                      u.state, u.settled_at, u.corrected_at
                 FROM metering_receipts r
                 LEFT JOIN usage_records u ON u.usage_id = r.usage_id
                WHERE r.receipt_id = %s AND r.state = 'accepted'""", (receipt_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return {"receipt_id": row[0], "node_id": row[1], "usage_id": str(row[2]), "received_at": row[3],
            "usage_state": row[4], "settled_at": row[5], "corrected_at": row[6]}


def candidate_amount_minor(request_id: str, model: str, access: str,
                           draft: models.ReceiptDraft) -> int | None:
    """按注入的成交价复算金额（INV-05）；未接线 / 非 token 计量 → None（不校验）。"""
    provider = _price_provider
    if provider is None or draft.usage_unit != "token":
        return None
    if draft.tokens_in + draft.tokens_out == 0:
        return None
    try:
        prices = provider(request_id, model, access)
    except Exception:                                    # pragma: no cover - provider 故障
        log.warning("metering.receipt.price_provider_failed")
        return None
    if not prices:
        return None
    return amounts.compute_amount_minor(
        tokens_in=draft.tokens_in, tokens_out=draft.tokens_out,
        in_price_micro=int(prices.get("in_price_micro", 0)),
        out_price_micro=int(prices.get("out_price_micro", 0)))


# ───────────────────────────────────────────────────────────────────── 落库
def _insert_accepted(c: Any, draft: models.ReceiptDraft, *, node_id: str, account_id: str,
                     usage_id: str, now: Any, trace_id: str | None = None) -> None:
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO metering_receipts
                   (submission_id, receipt_id, usage_id, node_id, task_id, access,
                    usage_amount, usage_unit, price_amount, price_minor, signature_alg,
                    sig_provider, sig_consumer, state, rejected_code, reject_reason,
                    reported_at, received_at, trace_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'accepted',NULL,NULL,%s,%s,%s)""",
            (models.uuid7(now), draft.receipt_id, usage_id, node_id, draft.task_id, draft.access,
             draft.usage_amount, draft.usage_unit, draft.price_amount, draft.price_minor,
             facts.SIGNATURE_ALG, draft.sig_provider, draft.sig_consumer,
             draft.reported_at, now, trace_id))
        cur.execute(
            """INSERT INTO usage_records
                   (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                    tokens_in, tokens_out, usage_amount, usage_unit, amount_minor,
                    usage_source, state, receipt_id, recorded_at, trace_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'recorded',%s,%s,%s)""",
            (usage_id, draft.request_id, draft.attempt_no, account_id, node_id, draft.model,
             draft.access, draft.tokens_in, draft.tokens_out, draft.usage_amount,
             draft.usage_unit, draft.price_minor, draft.usage_source, draft.receipt_id,
             draft.reported_at, trace_id))


def _insert_rejected(c: Any, draft: models.ReceiptDraft, *, node_id: str | None, state: str,
                     code: int, reason: str, now: Any, trace_id: str | None = None) -> None:
    """被拒 / 过期也要留痕（append-only）：节点自查与「签名失败率 >5% P1」告警的输入。"""
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO metering_receipts
                   (submission_id, receipt_id, usage_id, node_id, task_id, access,
                    usage_amount, usage_unit, price_amount, price_minor, signature_alg,
                    sig_provider, sig_consumer, state, rejected_code, reject_reason,
                    reported_at, received_at, trace_id)
               VALUES (%s,%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (models.uuid7(now), draft.receipt_id, node_id or draft.node_id or "unknown",
             draft.task_id, draft.access, draft.usage_amount, draft.usage_unit,
             draft.price_amount, draft.price_minor, facts.SIGNATURE_ALG,
             draft.sig_provider, draft.sig_consumer, state, code, reason,
             draft.reported_at, now, trace_id))


def _reject(draft: models.ReceiptDraft, exc: errors.MeteringError, *, node_id: str | None,
            c: Any, now: Any, state: str = "rejected",
            trace_id: str | None = None
            ) -> tuple[models.ReceiptVerdict, list[dict[str, Any]]]:
    """拒收：留痕 + 返回 (结论, 无事件)——与接受路径同一返回形状，便于逐条拼装。"""
    code = int(exc.code) if exc.code.isdigit() else 40001
    try:
        # 保存点：留痕失败（如 receipt_id 形态非法）不能把外层事务打成 aborted
        with c.transaction():
            _insert_rejected(c, draft, node_id=node_id, state=state, code=code,
                             reason=str(exc.reason)[:facts.MAX_REASON_LEN], now=now,
                             trace_id=trace_id)
    except Exception:                                     # pragma: no cover - 留痕失败不掩盖原错误
        log.warning("metering.receipt.reject_trace_failed",
                    extra={"receipt_id": draft.receipt_id, "reason": exc.reason})
    verdict = models.ReceiptVerdict(receipt_id=draft.receipt_id, state=state, code=code,
                                    reason=exc.reason, message=exc.message)
    return verdict, []


# ───────────────────────────────────────────────────────────────────── 单条受理
def _accept_one(c: Any, raw: Any, *, node_id: str | None, keys: signing.SignatureKeys,
                config: config_source.MeteringConfig, now: Any, trace_id: str = "",
                check_node: bool = True) -> tuple[models.ReceiptVerdict, list[dict[str, Any]]]:
    """受理一条：返回 (结论, 事件信封列表)。异常一律转成**单条拒收**（INV-02）。"""
    row_trace = None
    if isinstance(raw, Mapping):
        raw_trace = raw.get("trace_id")
        row_trace = str(raw_trace)[:facts.MAX_TRACE_LEN] if raw_trace else None
    try:
        draft = models.parse_receipt(raw, now=now)
    except errors.MeteringError as exc:
        return models.ReceiptVerdict(receipt_id=_raw_receipt_id(raw), state="rejected",
                                     code=int(exc.code), reason=exc.reason,
                                     message=exc.message), []
    except (ValueError, TypeError, KeyError) as exc:        # pragma: no cover - 防御
        log.warning("metering.receipt.parse_failed",
                    extra={"error": type(exc).__name__})
        return models.ReceiptVerdict(receipt_id=_raw_receipt_id(raw), state="rejected",
                                     code=40001, reason="malformed_receipt",
                                     message="收据形态非法"), []

    row_trace = trace_id or row_trace or draft.receipt_id

    # 1) 幂等（INV-03）：已受理 → 返回首次结果，不重复计量
    existing = find_accepted(c, draft.receipt_id)
    if existing is not None:
        if node_id and existing["node_id"] != node_id:
            # 不暴露他人收据是否存在（安全用例：越权提交他人节点收据）
            return _reject(draft, errors.NodeIdentityMismatch("无权查询该收据"),
                           node_id=node_id, c=c, now=now, trace_id=row_trace)
        return models.ReceiptVerdict(receipt_id=draft.receipt_id, state="accepted",
                                     usage_id=existing["usage_id"], duplicate=True), []

    # 2) 归属：收据不得代表他人节点（fail-closed）
    effective_node = node_id or draft.node_id
    if draft.node_id and node_id and draft.node_id != node_id:
        return _reject(draft, errors.NodeIdentityMismatch("收据声明的 node_id 与鉴权主体不一致"),
                       node_id=node_id, c=c, now=now, trace_id=row_trace)
    if not effective_node:
        return _reject(draft, errors.InvalidArgument("缺 node_id（收据与鉴权主体都没有）",
                                                     field="node_id"),
                       node_id=node_id, c=c, now=now, trace_id=row_trace)
    if check_node and not node_in_snapshot(c, effective_node):
        return _reject(draft, errors.InvalidArgument("节点不在只读快照里", field="node_id"),
                       node_id=node_id, c=c, now=now, trace_id=row_trace)

    # 3) 需方账户（T1/T2 由收据显式携带；T3 从 request.completed / booking 解析）
    if not draft.account_id:
        return _reject(draft, errors.InvalidArgument("缺 account_id（需方账户未解析）",
                                                     field="account_id"),
                       node_id=node_id, c=c, now=now, trace_id=row_trace)

    # 4) 24h 窗口（M05 §8.1 metering.receipt_late_h；边界含端点）
    late = timedelta(hours=config.receipt_late_h)
    if now - draft.reported_at > late:
        return _reject(draft, errors.ReceiptWindowExceeded(
            f"收据超出受理窗口（{config.receipt_late_h:g}h）"), node_id=node_id, c=c, now=now,
            trace_id=row_trace, state="expired")

    # 5) 双签（INV-01）
    check = signing.verify_pair(draft.canonical_fields(), sig_provider=draft.sig_provider,
                                sig_consumer=draft.sig_consumer, keys=keys)
    if not check.ok:
        return _reject(draft, errors.SignatureMismatch(
            "收据双签校验未通过（缺签 / 算法不符 / 摘要不匹配）",
            reason=check.reason, **check.as_detail()), node_id=node_id, c=c, now=now,
            trace_id=row_trace)

    # 6) 金额复算（INV-05；仅注入了成交价时启用）
    try:
        expected = candidate_amount_minor(draft.request_id, draft.model, draft.access, draft)
    except amounts.AmountError as exc:
        return _reject(draft, errors.AmountPrecisionRejected(f"成交价复算失败：{exc}"),
                       node_id=node_id, c=c, now=now, trace_id=row_trace)
    if expected is not None and expected != draft.price_minor:
        return _reject(draft, errors.AmountMismatch(
            "收据金额与成交价复算不一致", expected_minor=expected,
            received_minor=draft.price_minor), node_id=node_id, c=c, now=now,
            trace_id=row_trace)

    # 7) 同事务落库 + 同事务写 outbox（CR-5：事件与 usage/receipt 一个事务）
    usage_id = str(models.uuid7(now))
    signature_ref = signing.signature_ref(draft.sig_provider, draft.sig_consumer)
    envelopes = [
        events.receipt_signed_event(draft=draft, usage_id=usage_id, signature_ref=signature_ref,
                                    trace_id=row_trace, occurred_at=now),
        events.usage_recorded_event(usage_id=usage_id, account_id=draft.account_id,
                                    request_id=draft.request_id, amount_minor=draft.price_minor,
                                    source=draft.usage_source, trace_id=row_trace,
                                    occurred_at=now),
    ]
    try:
        with c.transaction():
            _insert_accepted(c, draft, node_id=effective_node, account_id=draft.account_id,
                             usage_id=usage_id, now=now, trace_id=row_trace)
            outbox.append_all(c, envelopes)
    except psycopg.errors.UniqueViolation as exc:
        return _resolve_conflict(c, draft, exc, node_id=node_id, now=now, trace_id=row_trace)
    except psycopg.errors.Error as exc:                   # pragma: no cover - 传染性故障
        log.warning("metering.receipt.persist_failed",
                    extra={"receipt_id": draft.receipt_id, "error": type(exc).__name__})
        return _reject(draft, errors.StoreUnavailable("收据落库失败，请稍后重试"),
                       node_id=node_id, c=c, now=now, trace_id=row_trace)
    return models.ReceiptVerdict(receipt_id=draft.receipt_id, state="accepted",
                                 usage_id=usage_id), envelopes


def _resolve_conflict(c: Any, draft: models.ReceiptDraft, exc: Exception, *, node_id: str | None,
                      now: Any, trace_id: str | None = None
                      ) -> tuple[models.ReceiptVerdict, list[dict[str, Any]]]:
    """唯一键冲突的两种语义：同一个 receipt_id（→ duplicate）或同一请求尝试已被计费（→ 拒收）。"""
    log.info("metering.receipt.unique_conflict",
             extra={"receipt_id": draft.receipt_id, "constraint": getattr(
                 getattr(exc, "diag", None), "constraint_name", None)})
    existing = find_accepted(c, draft.receipt_id)
    if existing is not None and (not node_id or existing["node_id"] == node_id):
        return models.ReceiptVerdict(receipt_id=draft.receipt_id, state="accepted",
                                     usage_id=existing["usage_id"], duplicate=True), []
    return _reject(draft, errors.DuplicateRequestAttempt(
        "同一 (request_id, attempt_no) 已有计费用量（INV-04）"), node_id=node_id, c=c, now=now,
        trace_id=trace_id)


def _raw_receipt_id(raw: Any) -> str:
    if isinstance(raw, Mapping):
        value = raw.get("receipt_id")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


# ───────────────────────────────────────────────────────────────────── 批量受理
def accept_batch(c: Any, receipts: Sequence[Any], *, node_id: str | None = None,
                 trace_id: str = "", now: Any = None, keys: signing.SignatureKeys | None = None,
                 config: config_source.MeteringConfig | None = None,
                 check_node: bool = True) -> models.BatchOutcome:
    """逐条受理（INV-02）；密钥 / 配置只取一次，避免批内漂移。"""
    batch = list(receipts)
    if len(batch) < facts.BATCH_MIN:
        raise errors.InvalidArgument("receipts 不能为空（spec minItems=1）", field="receipts")
    if len(batch) > facts.BATCH_MAX:
        raise errors.BatchTooLarge(
            f"收据批最多 {facts.BATCH_MAX} 条（收到 {len(batch)}，spec maxItems=500）")
    moment = clock.as_utc(now or clock.utcnow())
    resolved_keys = keys or signing.resolve_keys()
    snapshot = config or config_source.snapshot()

    accepted: list[str] = []
    duplicates: list[str] = []
    verdicts: list[models.ReceiptVerdict] = []
    rejected: list[models.ReceiptVerdict] = []
    envelopes: list[dict[str, Any]] = []

    for raw in batch:
        verdict, row_events = _accept_one(c, raw, node_id=node_id, keys=resolved_keys,
                                          config=snapshot, now=moment, trace_id=trace_id,
                                          check_node=check_node)
        verdicts.append(verdict)
        if verdict.accepted:
            if verdict.duplicate:
                duplicates.append(verdict.receipt_id)
            else:
                accepted.append(verdict.receipt_id)
            envelopes.extend(row_events)
        else:
            rejected.append(verdict)

    log.info("metering.receipts.batch",
             extra={"trace_id": trace_id, "accepted": len(accepted),
                    "duplicates": len(duplicates), "rejected": len(rejected)})
    return models.BatchOutcome(accepted=tuple(accepted), rejected=tuple(rejected),
                               duplicates=tuple(duplicates), events=tuple(envelopes),
                               verdicts=tuple(verdicts))


# ───────────────────────────────────────────────────────────────────── 节点自查
def receipt_status(c: Any, *, receipt_id: str, node_id: str | None) -> dict[str, Any] | None:
    """单条受理结果（spec ``ReceiptStatus``）；跨节点一律 None（路由层转 404，不泄露存在性）。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT r.node_id, r.state, r.rejected_code, r.reject_reason, r.received_at,
                      u.state, u.settled_at
                 FROM metering_receipts r
                 LEFT JOIN usage_records u ON u.usage_id = r.usage_id
                WHERE r.receipt_id = %s
                ORDER BY (r.state = 'accepted') DESC, r.received_at DESC
                LIMIT 1""", (receipt_id,))
        row = cur.fetchone()
    if row is None:
        return None
    owner, state, code, reason, received_at, usage_state, settled_at = row
    if node_id is not None and owner != node_id:
        return None                                        # 不泄露他人收据是否存在
    payload: dict[str, Any] = {"receipt_id": receipt_id, "state": state,
                               "received_at": models.iso(received_at)}
    if state != "accepted":
        payload["code"] = int(code) if code is not None else 40001
        payload["message"] = reason or "收据未受理"
    if usage_state in ("settled", "corrected"):
        payload["settled_at"] = models.iso(settled_at)
    return payload


__all__ = ["PriceProvider", "set_price_provider", "current_price_provider", "node_in_snapshot",
           "find_accepted", "candidate_amount_minor", "accept_batch", "receipt_status"]
