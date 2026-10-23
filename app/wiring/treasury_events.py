# SPDX-License-Identifier: Apache-2.0
"""M08 outbox → M06 账本消费端（S2 资金闭环的 E9 / E8 / E11 落地）。

职责
----
把 M08 已登记的资金事件从 `m08_outbox` 消费到 M06 账本，并把投递状态推进到
published / dead（02-events §2 的状态机仍由 M08 的 `events.mark_failed` 维护）：

    sweep.completed   → E9  归集（热 → 温）：借 1102 + 5102 / 贷 1101 + 1140
    payout.paid       → E8  分润计提 + 2a/2b/2c（§20.3.3 三步）
    refund.completed  → E11 退款两步：受理 2101/2203；打款 2203+5102/1102

其余 6 个已登记事件（payment.created / payment.paid / payment.failed / wallet.switched /
signing.requested / signing.signed）**没有账本动作**：E3 由 M08 自己的 order 流程在同一
业务事务里同步记账（`app/treasury/order.py::handle_webhook` → `ledger.post_one`），
消费端只推进投递状态并计数；未登记事件按毒消息处理（推进投递状态 + 计数，不阻塞分区，
02-events §5）。

边界
----
* 读：M08 拥有的 `m08_outbox` / `wallet_transfers` / `payout_batches` / `payout_items` /
  `refund_requests`（只读字段）；
* 写：只经 M06 `post_journal` 写 `journal_*`（凭证 + 行 + 分录 + 余额 + m06_outbox 同事务），
  以及 M08 `events.mark_published` / `events.mark_failed` 推进投递状态；
* 金额一律 **micro-USD 整数**（03-facts §6 / §20.3）：M08 业务表是 USD 分（unit_scale=2），
  边界统一 ×10,000（`MICRO_PER_MINOR`），不做浮点、不做四舍五入。

幂等（INV-06 / I-8 / 02-events §2.1、§2.5）
-------------------------------------------
M06 的唯一键是 `(source_type, source_id, event_seq)`；事件信封的 `idempotency_key`
作为 `JournalDraft.idempotency_key` 参与审计（M06 落账按业务键去重）。各事件固定键：

    sweep.completed   wallet_transfer / transfer_id(=aggregate_id) / 1
    payout.paid       payout_accrual  / batch_id(=aggregate_id)    / 1   （计提：5501 / 2201）
                      payout_item     / item_id                    / 2   （2a gas：5102 / 1109）
                                                                   / 3   （2b 出款：2201 / 1102+5102）
                                                                   / 4   （2c 划转：1109 / 1102）
    refund.completed  refund          / refund_request_id(=aggregate_id) / 1（受理）
                                                                        / 2（打款）

重复消费（含 02-events §2.5 的「回放事件保留原 event_id」）→ M06 返回既有凭证，不新增行。

已知缺口（报 Lead，不在本文件自行发明数据）
------------------------------------------
1. §20.3.1 的 E8 计提幂等键写「`payout_accrual` / **原 journal** / 1」，但 `payout.paid`
   信封与 `payout_batches` 都没有「原消费 journal」引用 → 这里取 `batch_id` 作 source_id
   （批次是唯一稳定锚）。要严格对齐需 M08 在事件 / 表上补引用（CR）。
2. §20.3.1 的 E11② 打款要记「5102 gas」，但 `refund_requests` 没有 gas 字段、`refund.completed`
   信封也没有 → 由调用方注入 `gas_resolver`（生产应取链上广播的实付 gas）；未注入按 0
   （两行凭证仍平衡）。演示脚本按 runbook 场景注入 0.20 USD。
3. `partial` 批次：只对 `status='sent'` 的明细记 2a/2b/2c，失败明细的 2201 保留为应付
   （不伪造冲正）；本 demo 走 settled 单笔，残差为 0。
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from psycopg.rows import dict_row

from app.ledger import gateway as ledger_gateway
from app.ledger.validate import JournalDraft, JournalLine
from app.treasury import events as m08_events
from app.treasury import facts as m08_facts
from app.treasury import store as m08_store

log = logging.getLogger("djb.wiring.treasury_events")

__all__ = [
    "DEFAULT_POLICY_VERSION",
    "CONSUMED_EVENTS",
    "REGISTERED_NO_LEDGER",
    "consume",
    "build_journals",
]

#: M08 凭证/批次落库的默认策略版本（demo / 未注入 M10 配置时）
DEFAULT_POLICY_VERSION = "m08-pool-default"

#: 有账本动作的事件
CONSUMED_EVENTS: tuple[str, ...] = ("sweep.completed", "payout.paid", "refund.completed")

#: 已登记但无账本动作的事件（E3 由 M08 同步记账；其余为通知类）
REGISTERED_NO_LEDGER: frozenset[str] = frozenset({
    m08_facts.EVENT_PAYMENT_CREATED, m08_facts.EVENT_PAYMENT_PAID,
    m08_facts.EVENT_PAYMENT_FAILED, m08_facts.EVENT_WALLET_SWITCHED,
    m08_facts.EVENT_SIGNING_REQUESTED, m08_facts.EVENT_SIGNING_SIGNED,
})

#: 平台级科目账户（M06 约定 coa:<code>）
def _coa(code: str) -> str:
    return f"coa:{code}"


#: 主体账户（M06 约定 acct:<subject>）
def _acct(subject: str) -> str:
    return f"acct:{subject}"


def _to_micro(amount_minor: int) -> int:
    """USD 分 → micro-USD（03-facts §6；整数运算）。"""
    return int(amount_minor) * int(m08_facts.MICRO_PER_MINOR)


def _line(account_id: str, coa_code: str, dc: str, amount_micro: int, entry_type: str,
          *, qty_micro: int | None = None) -> JournalLine:
    if int(amount_micro) <= 0:
        raise ValueError(f"账本行金额必须 > 0（{coa_code} {dc} {amount_micro}）")
    return JournalLine(
        account_id=account_id, coa_code=coa_code, dc=dc,
        amount_minor=int(amount_micro), entry_type=entry_type,
        qty_minor=None if qty_micro is None else int(qty_micro),
        unit_scale=int(m08_facts.LEDGER_UNIT_SCALE))


def _draft(*, event_type: str, source_type: str, source_id: str, event_seq: int,
           lines: Iterable[JournalLine], occurred_at: datetime, policy_version: str,
           idempotency_key: str, trace_id: str | None, correlation_id: str | None,
           ref_id: str | None) -> JournalDraft:
    return JournalDraft(
        event_type=event_type, unit_type="USD", source_type=source_type,
        source_id=str(source_id), event_seq=int(event_seq),
        policy_version=policy_version, lines=tuple(lines),
        ts=occurred_at, idempotency_key=idempotency_key,
        trace_id=trace_id, correlation_id=correlation_id, ref_id=ref_id)


def _occurred(event: Mapping[str, Any]) -> datetime:
    value = event.get("occurred_at")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def _journal_key(event: Mapping[str, Any], suffix: str) -> str:
    """信封 idempotency_key + 步骤后缀（审计用；M06 去重仍按业务键）。"""
    base = str(event.get("idempotency_key") or event.get("event_id") or "")
    return f"{base}#{suffix}"[:200]


# ═══════════════════════════════════════════════════════════ E9（归集）
def _sweep_journals(conn: Any, event: Mapping[str, Any], *,
                    policy_version: str) -> list[JournalDraft]:
    payload = dict(event.get("payload") or {})
    transfer_id = str(event.get("aggregate_id") or "")
    transfer = m08_store.get_transfer(conn, transfer_id)
    if transfer is None:
        raise RuntimeError(f"归集转账不存在：{transfer_id}（事件与 M08 数据不一致）")
    if str(transfer.get("kind")) != "sweep":
        raise RuntimeError(f"wallet_transfer {transfer_id} 不是归集（kind={transfer.get('kind')}）")
    if str(transfer.get("batch_no") or "") != str(payload.get("batch_no") or ""):
        raise RuntimeError("sweep.completed 的 batch_no 与 wallet_transfers 不一致")
    if str(transfer.get("from_wallet_id")) != str(payload.get("from_wallet") or ""):
        raise RuntimeError("sweep.completed 的 from_wallet 与 wallet_transfers 不一致")
    if str(transfer.get("to_wallet_id")) != str(payload.get("to_wallet") or ""):
        raise RuntimeError("sweep.completed 的 to_wallet 与 wallet_transfers 不一致")
    amount_micro = int(payload.get("amount_minor") or 0)
    if amount_micro <= 0 or amount_micro != int(transfer.get("amount_minor") or 0):
        raise RuntimeError("sweep.completed 的 amount_minor 与 wallet_transfers.amount_minor 不一致")
    gas_micro = int(transfer.get("gas_fee_minor") or 0)
    lines = [
        _line(_coa("1102"), "1102", "D", amount_micro, "transfer", qty_micro=amount_micro),
        _line(_coa("1101"), "1101", "C", amount_micro, "transfer", qty_micro=amount_micro),
    ]
    if gas_micro > 0:
        lines.insert(1, _line(_coa("5102"), "5102", "D", gas_micro, "gas"))
        lines.append(_line(_coa("1140"), "1140", "C", gas_micro, "gas"))
    return [_draft(
        event_type="E9", source_type="wallet_transfer", source_id=transfer_id, event_seq=1,
        lines=lines, occurred_at=_occurred(event), policy_version=policy_version,
        idempotency_key=_journal_key(event, "E9"),
        trace_id=event.get("trace_id"), correlation_id=event.get("correlation_id"),
        ref_id=transfer_id)]


# ═══════════════════════════════════════════════════════════ E8（分润）
def _payout_journals(conn: Any, event: Mapping[str, Any], *,
                     policy_version: str) -> list[JournalDraft]:
    payload = dict(event.get("payload") or {})
    batch_id = str(event.get("aggregate_id") or "")
    batch = m08_store.get_payout_batch(conn, batch_id)
    if batch is None:
        raise RuntimeError(f"出款批次不存在：{batch_id}（事件与 M08 数据不一致）")
    batch_id = str(batch["batch_id"])
    items = m08_store.list_payout_items(conn, batch_id)
    billed = [item for item in items if str(item.get("status")) == "sent"]
    if not billed:
        raise RuntimeError(f"出款批次 {batch_id} 没有已发送明细（payout.paid 不应出现）")
    gross_total = sum(int(item.get("gross_minor") or 0) for item in billed)
    fee_total = sum(int(item.get("fee_minor") or 0) for item in billed)
    net_total = sum(int(item.get("net_minor") or 0) for item in billed)
    if int(batch.get("total_gross_minor") or 0) != gross_total \
            or int(batch.get("total_fee_minor") or 0) != fee_total \
            or int(batch.get("total_net_minor") or 0) != net_total:
        raise RuntimeError("payout.paid 与 payout_items 合计不一致（批次明细被改？）")
    if int(payload.get("total_minor") or 0) != net_total:
        raise RuntimeError("payout.paid 的 total_minor 与明细净额不一致")
    gross_micro, fee_micro, net_micro = _to_micro(gross_total), _to_micro(fee_total), \
        _to_micro(net_total)
    occurred = _occurred(event)
    version = str(batch.get("policy_version") or policy_version)
    trace_id = event.get("trace_id")
    correlation_id = str(batch.get("batch_no") or event.get("correlation_id") or "")
    drafts: list[JournalDraft] = []
    # ① 计提：借 5501 分润成本 / 贷 2201 应付共享方分润（§20.3.2 毛额法）
    drafts.append(_draft(
        event_type="E8", source_type="payout_accrual", source_id=batch_id, event_seq=1,
        lines=(
            _line(_coa("5501"), "5501", "D", gross_micro, "payout"),
            _line(_coa("2201"), "2201", "C", gross_micro, "payout"),
        ),
        occurred_at=occurred, policy_version=version,
        idempotency_key=_journal_key(event, "E8-accrual"), trace_id=trace_id,
        correlation_id=correlation_id, ref_id=batch_id))
    for item in billed:
        item_id = str(item["item_id"])
        item_gross = _to_micro(int(item.get("gross_minor") or 0))
        item_fee = _to_micro(int(item.get("fee_minor") or 0))
        item_net = _to_micro(int(item.get("net_minor") or 0))
        if item_gross != item_fee + item_net:
            raise RuntimeError(f"明细 {item_id} 净额不平：{item_gross} != {item_fee} + {item_net}")
        # ②a 平台先垫 gas：借 5102 / 贷 1109
        if item_fee > 0:
            drafts.append(_draft(
                event_type="E8", source_type="payout_item", source_id=item_id, event_seq=2,
                lines=(
                    _line(_coa("5102"), "5102", "D", item_fee, "gas"),
                    _line(_coa("1109"), "1109", "C", item_fee, "gas"),
                ),
                occurred_at=occurred, policy_version=version,
                idempotency_key=_journal_key(event, f"E8-2a-{item_id}"), trace_id=trace_id,
                correlation_id=correlation_id, ref_id=item_id))
        # ②b 出款（净额 + 扣减）：借 2201 / 贷 1102（净额）+ 5102（fee）
        lines_b = [_line(_coa("2201"), "2201", "D", item_gross, "payout"),
                   _line(_coa("1102"), "1102", "C", item_net, "payout", qty_micro=item_net)]
        if item_fee > 0:
            lines_b.append(_line(_coa("5102"), "5102", "C", item_fee, "gas"))
        drafts.append(_draft(
            event_type="E8", source_type="payout_item", source_id=item_id, event_seq=3,
            lines=lines_b, occurred_at=occurred, policy_version=version,
            idempotency_key=_journal_key(event, f"E8-2b-{item_id}"), trace_id=trace_id,
            correlation_id=correlation_id, ref_id=item_id))
        # ②c 手续费留存划转：借 1109 / 贷 1102
        if item_fee > 0:
            drafts.append(_draft(
                event_type="E8", source_type="payout_item", source_id=item_id, event_seq=4,
                lines=(
                    _line(_coa("1109"), "1109", "D", item_fee, "transfer"),
                    _line(_coa("1102"), "1102", "C", item_fee, "transfer", qty_micro=item_fee),
                ),
                occurred_at=occurred, policy_version=version,
                idempotency_key=_journal_key(event, f"E8-2c-{item_id}"), trace_id=trace_id,
                correlation_id=correlation_id, ref_id=item_id))
    return drafts


# ═══════════════════════════════════════════════════════════ E11（退款）
def _refund_journals(conn: Any, event: Mapping[str, Any], *,
                     policy_version: str,
                     gas_resolver: Callable[[Mapping[str, Any], Any], int] | None
                     ) -> list[JournalDraft]:
    payload = dict(event.get("payload") or {})
    refund_id = str(event.get("aggregate_id") or "")
    refund = m08_store.get_refund(conn, refund_id)
    if refund is None:
        raise RuntimeError(f"退款申请不存在：{refund_id}（事件与 M08 数据不一致）")
    refund_id = str(refund["refund_request_id"])
    account_id = str(refund.get("account_id") or "")
    if not account_id:
        raise RuntimeError("退款申请缺 account_id（无法确定 2101 主体账户）")
    amount = int(payload.get("amount_minor") or 0)
    if amount <= 0 or amount != int(refund.get("amount_minor") or 0):
        raise RuntimeError("refund.completed 的 amount_minor 与 refund_requests 不一致")
    amount_micro = _to_micro(amount)
    gas_micro = 0
    if gas_resolver is not None:
        raw = gas_resolver(event, conn)
        if raw is None:
            raw = 0
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise RuntimeError(f"gas_resolver 返回非法值：{raw!r}")
        gas_micro = int(raw)
    occurred = _occurred(event)
    trace_id = event.get("trace_id")
    correlation_id = str(refund.get("refund_no") or event.get("correlation_id") or "")
    step1 = _draft(
        event_type="E11", source_type="refund", source_id=refund_id, event_seq=1,
        lines=(
            _line(_acct(account_id), "2101", "D", amount_micro, "refund"),
            _line(_coa("2203"), "2203", "C", amount_micro, "refund"),
        ),
        occurred_at=occurred, policy_version=policy_version,
        idempotency_key=_journal_key(event, "E11-accept"), trace_id=trace_id,
        correlation_id=correlation_id, ref_id=refund_id)
    lines2 = [_line(_coa("2203"), "2203", "D", amount_micro, "refund")]
    if gas_micro > 0:
        lines2.append(_line(_coa("5102"), "5102", "D", gas_micro, "gas"))
    lines2.append(_line(_coa("1102"), "1102", "C", amount_micro + gas_micro, "refund",
                        qty_micro=amount_micro + gas_micro))
    step2 = _draft(
        event_type="E11", source_type="refund", source_id=refund_id, event_seq=2,
        lines=lines2, occurred_at=occurred, policy_version=policy_version,
        idempotency_key=_journal_key(event, "E11-execute"), trace_id=trace_id,
        correlation_id=correlation_id, ref_id=refund_id)
    return [step1, step2]


def build_journals(conn: Any, event: Mapping[str, Any], *,
                   policy_version: str = DEFAULT_POLICY_VERSION,
                   gas_resolver: Callable[[Mapping[str, Any], Any], int] | None = None
                   ) -> list[JournalDraft]:
    """把一条 M08 事件转换成 M06 凭证草稿（纯构造；落账由 consume 在同一事务里做）。"""
    event_type = str(event.get("type") or "")
    if event_type == "sweep.completed":
        return _sweep_journals(conn, event, policy_version=policy_version)
    if event_type == "payout.paid":
        return _payout_journals(conn, event, policy_version=policy_version)
    if event_type == "refund.completed":
        return _refund_journals(conn, event, policy_version=policy_version,
                                gas_resolver=gas_resolver)
    raise ValueError(f"事件 {event_type!r} 没有账本映射")


# ═══════════════════════════════════════════════════════════ 消费入口
def _post_and_publish(conn: Any, event: Mapping[str, Any], drafts: list[JournalDraft],
                      poster: Callable[[Any, JournalDraft], Any] | None = None
                      ) -> list[dict[str, Any]]:
    """同一事务：落全部凭证 + 推进投递状态（失败整体回滚，不标记 published）。

    `poster` 是测试 / 演练用的失败注入点（默认直接走 M06 `post_journal`）。
    """
    post = poster or ledger_gateway.post_journal
    posted: list[dict[str, Any]] = []
    with conn.transaction():
        for draft in drafts:
            result = post(conn, draft)
            posted.append({
                "event_type": draft.event_type,
                "source_type": draft.source_type,
                "source_id": draft.source_id,
                "event_seq": int(draft.event_seq),
                "journal_id": str(result.journal_id),
                "idempotent": bool(result.idempotent),
                "debit_minor": int(result.total_debit_minor),
                "line_count": int(result.line_count),
            })
        m08_events.mark_published(conn, str(event["event_id"]))
    return posted


def _mark_only(conn: Any, event: Mapping[str, Any]) -> None:
    with conn.transaction():
        m08_events.mark_published(conn, str(event["event_id"]))


def _mark_failed(conn: Any, event: Mapping[str, Any], error: str) -> str:
    with conn.transaction():
        return m08_events.mark_failed(conn, str(event["event_id"]), error)


def _dead_total(conn: Any) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM m08_outbox WHERE status = 'dead'")
        return int(cur.fetchone()[0])


def consume(conn: Any, *, limit: int = 100,
            policy_version: str = DEFAULT_POLICY_VERSION,
            gas_resolver: Callable[[Mapping[str, Any], Any], int] | None = None,
            poster: Callable[[Any, JournalDraft], Any] | None = None,
            ) -> dict[str, Any]:
    """消费 pending 事件（调用方给非 autocommit 连接；每条事件一个独立事务）。

    返回摘要：处理条数 / 各类型计数 / 凭证清单 / 失败与 dead 数。失败的事件**不标记
    published**：M08 `mark_failed` 按 1s/5s/30s/5min/30min 退避重试，第 8 次进 dead。
    """
    if getattr(conn, "autocommit", False):
        raise ValueError("consume 需要非 autocommit 连接（M06 记账要持有显式事务）")
    events = m08_events.pending(conn, limit=limit)
    summary: dict[str, Any] = {
        "scanned": len(events),
        "published": 0,
        "consumed": {},
        "skipped": {},
        "unknown": 0,
        "failed": 0,
        "retry": 0,
        "dead": 0,
        "dead_total": 0,
        "journals": [],
        "errors": [],
    }
    for event in events:
        event_type = str(event.get("type") or "")
        if event_type in CONSUMED_EVENTS:
            try:
                drafts = build_journals(conn, event, policy_version=policy_version,
                                        gas_resolver=gas_resolver)
                posted = _post_and_publish(conn, event, drafts, poster)
            except Exception as exc:                       # noqa: BLE001 - 逐条隔离
                log.warning("treasury.event_consume_failed event=%s type=%s err=%s",
                            event.get("event_id"), event_type, exc)
                outcome = _mark_failed(conn, event, f"{type(exc).__name__}: {exc}")
                summary["failed"] += 1
                if outcome == "dead":
                    summary["dead"] += 1
                else:
                    summary["retry"] += 1
                summary["errors"].append({
                    "event_id": str(event.get("event_id")), "type": event_type,
                    "outcome": outcome, "error": f"{type(exc).__name__}: {exc}"[:256]})
                continue
            summary["published"] += 1
            summary["consumed"][event_type] = summary["consumed"].get(event_type, 0) + 1
            summary["journals"].append({
                "event_id": str(event.get("event_id")), "type": event_type,
                "aggregate_id": str(event.get("aggregate_id") or ""),
                "journals": posted})
            continue
        if event_type in REGISTERED_NO_LEDGER:
            _mark_only(conn, event)
            summary["published"] += 1
            summary["skipped"][event_type] = summary["skipped"].get(event_type, 0) + 1
            continue
        # 未登记事件：毒消息，不阻塞分区（02-events §5）——推进投递状态并计数
        _mark_only(conn, event)
        summary["published"] += 1
        summary["unknown"] += 1
        summary["errors"].append({"event_id": str(event.get("event_id")),
                                  "type": event_type, "outcome": "unknown_skipped"})
    summary["dead_total"] = _dead_total(conn)
    return summary
