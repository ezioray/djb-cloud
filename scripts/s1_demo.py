#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""S1 端到端 demo：一次聊天请求 → 双签收据 → usage → E6 账本 → 复算 0。

只使用 M03 网关的 ``chat.complete`` 入口；收据由 M05 的受理函数生成，
不允许脚本自行拼一张“看起来像收据”的记录。

运行（独立 schema，结束自动 DROP）::

    PYTHONPATH=. python scripts/s1_demo.py
    PYTHONPATH=. python scripts/s1_demo.py --keep-schema
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from app.gateway import chat, models as gateway_models, providers
from app.ledger.balances import check_negative_liabilities
from app.ledger.verify import verify_ledger
from app.metering import signing
from app.wiring import Database, install, provision_account, seed_market
from app.wiring.ledger import post_topup

EVENT_TYPES = ("receipt.signed", "usage.recorded", "usage.settled")


def _query_one(conn, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        if row is None:
            return None
        keys = [desc.name for desc in cur.description]
        return dict(zip(keys, row))


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    return str(value)


def run(*, keep_schema: bool = False) -> dict[str, Any]:
    schema = f"s1_demo_{os.getpid()}_{int(time.time())}"
    db = Database.create(schema)
    applied: list[str] = []
    try:
        applied = db.migrate()
        wiring = install(db)
        account = provision_account(db)
        market = seed_market(db)

        now = datetime.now(timezone.utc)
        request_id = f"req_s1_{uuid.uuid4().hex}"
        trace_id = f"trace_s1_{uuid.uuid4().hex}"
        topup = post_topup(
            db,
            account_id=str(account.account_id),
            amount_minor=1000,
            policy_version=account.policy_version or "s1-demo",
            trace_id=trace_id,
        )
        raw_key = account.raw_key
        principal = providers.authenticate(
            raw_key,
            now=now,
            client_ip="127.0.0.1",
            trace_id=trace_id,
        )
        body = {
            "model": "demo-model",
            "messages": [{"role": "user", "content": "S1 demo: 2+2?"}],
            "max_tokens": 64,
        }
        with db.connect() as conn:
            outcome = chat.complete(
                conn,
                principal=principal,
                body=body,
                request_id=request_id,
                trace_id=trace_id,
                idempotency_key=f"idem_{request_id}",
                client_ip="127.0.0.1",
                now=now,
            )

        with db.connect() as conn:
            usage = _query_one(
                conn,
                """SELECT usage_id, request_id, account_id, node_id, model, access,
                          tokens_in, tokens_out, amount_minor, state, receipt_id
                     FROM usage_records WHERE request_id = %s""",
                (request_id,),
            )
            if usage is None:
                raise AssertionError("usage_records 未落库（网关 → M05 接线失败）")
            receipt = _query_one(
                conn,
                """SELECT receipt_id, usage_id, node_id, task_id, access,
                          usage_amount, usage_unit, price_amount, price_minor, state,
                          sig_provider, sig_consumer
                     FROM metering_receipts WHERE receipt_id = %s""",
                (usage["receipt_id"],),
            )
            if receipt is None:
                raise AssertionError("metering_receipts 未落库")
            if receipt["state"] != "accepted":
                raise AssertionError(f"收据状态不是 accepted：{receipt['state']}")
            if receipt["usage_id"] != usage["usage_id"]:
                raise AssertionError("收据与 usage 的 usage_id 不一致")
            if int(receipt["price_minor"]) != int(usage["amount_minor"]):
                raise AssertionError("收据金额与 usage.amount_minor 不一致")
            signature = signing.verify_pair(
                {
                    "receipt_id": receipt["receipt_id"],
                    "task_id": receipt["task_id"],
                    "access": receipt["access"],
                    "usage_amount": receipt["usage_amount"],
                    "usage_unit": receipt["usage_unit"],
                    "price_amount": receipt["price_amount"],
                },
                sig_provider=receipt["sig_provider"],
                sig_consumer=receipt["sig_consumer"],
                keys=wiring.keys,
            )
            if not signature.ok:
                raise AssertionError(f"双签校验失败：{signature.reason}")

        # 重复提交同一 request_id + 幂等键：必须只回放，不再写 usage（唯一计费）
        with db.connect() as conn:
            replay = chat.complete(
                conn,
                principal=principal,
                body=body,
                request_id=request_id,
                trace_id=trace_id,
                idempotency_key=f"idem_{request_id}",
                client_ip="127.0.0.1",
                now=now,
            )
        if not replay.replayed:
            raise AssertionError("同一幂等键的重复请求没有被回放")
        with db.connect() as conn:
            usage_count_after_replay = _query_one(
                conn,
                """SELECT count(*) AS n FROM usage_records WHERE request_id = %s""",
                (request_id,),
            )
        if int(usage_count_after_replay["n"]) != 1:
            raise AssertionError("重复请求产生了额外 usage（唯一计费失败）")

        policy_version = principal.policy_version or account.policy_version
        settlement, published = wiring.settle(
            usage["usage_id"], policy_version=policy_version, trace_id=trace_id
        )
        provider_result = settlement.get("provider_result") or {}
        journal_id = provider_result.get("journal_id")
        amount_micro = int(settlement["amount_micro"])

        with db.connect() as conn:
            verify = verify_ledger(conn)
            journal = _query_one(
                conn,
                """SELECT journal_id, event_type, source_type, source_id, unit_type,
                          status, hash
                     FROM journal_entry WHERE journal_id = %s""",
                (journal_id,),
            )
            if journal is None:
                raise AssertionError("E6 凭证未落库")
            balance = _query_one(
                conn,
                """SELECT COALESCE(sum(CASE WHEN dc = 'D' THEN amount_minor ELSE 0 END), 0) AS debit,
                          COALESCE(sum(CASE WHEN dc = 'C' THEN amount_minor ELSE 0 END), 0) AS credit
                     FROM journal_line WHERE journal_id = %s""",
                (journal_id,),
            )
            event_rows = conn.execute(
                """SELECT type, count(*) FROM metering_outbox
                    WHERE type = ANY(%s) GROUP BY type ORDER BY type""",
                (list(EVENT_TYPES),),
            ).fetchall()
            events = {row[0]: int(row[1]) for row in event_rows}
            usage_count = _query_one(
                conn,
                """SELECT count(*) AS n FROM usage_records WHERE request_id = %s""",
                (request_id,),
            )
            balance_2101 = _query_one(
                conn,
                """SELECT COALESCE(sum(CASE WHEN dc = 'C' THEN amount_minor ELSE -amount_minor END), 0)
                          AS normal_balance_micro
                     FROM journal_line
                    WHERE account_id = %s AND coa_code = '2101'""",
                (str(account.account_id),),
            )
            i4_violations = check_negative_liabilities(
                conn, account_ids=[str(account.account_id)]
            )

        missing = [name for name in EVENT_TYPES if events.get(name, 0) < 1]
        if missing:
            raise AssertionError(f"M05 outbox 缺事件：{missing}（实际 {events}）")
        if int(balance_2101["normal_balance_micro"]) < 0 or i4_violations:
            raise AssertionError(
                f"I-4 失败：2101 正常方向余额为负 {balance_2101['normal_balance_micro']}，"
                f"violations={i4_violations}（充值 {topup['amount_minor']} 分未覆盖）"
            )
        if int(balance["debit"]) != int(balance["credit"]):
            raise AssertionError(f"凭证借贷不平：{balance}")
        if amount_micro != int(usage["amount_minor"]) * 10_000:
            raise AssertionError("E6 金额与 usage 金额不一致（分→micro 换算错误）")
        if amount_micro != int(balance["debit"]):
            raise AssertionError("E6 请求金额与凭证行金额不一致")
        if int(verify["diff"]) != 0:
            raise AssertionError(f"账本复算 diff != 0：{verify}")
        if outcome.status_code != 200:
            raise AssertionError(f"网关返回 {outcome.status_code}")

        return {
            "schema": schema,
            "migrations": len(applied),
            "request_id": request_id,
            "trace_id": trace_id,
            "account_id": str(account.account_id),
            "tenant_id": str(account.tenant_id),
            "node_id": market.node_id,
            "receipt_id": receipt["receipt_id"],
            "usage_id": usage["usage_id"],
            "usage_count": int(usage_count["n"]) if usage_count else 0,
            "receipt_dual_signature": True,
            "idempotent_replay": True,
            "amount_minor": int(usage["amount_minor"]),
            "amount_micro": amount_micro,
            "topup_amount_minor": int(topup["amount_minor"]),
            "topup_journal_id": str(topup["journal_id"]),
            "balance_2101_normal_minor": int(balance_2101["normal_balance_micro"]) // 10_000,
            "balance_2101_normal_micro": int(balance_2101["normal_balance_micro"]),
            "i4_violations": len(i4_violations),
            "journal_id": journal_id,
            "journal_event_type": journal["event_type"],
            "journal_balanced": {
                "debit": int(balance["debit"]),
                "credit": int(balance["credit"]),
            },
            "events": events,
            "published": published,
            "recompute_diff": int(verify["diff"]),
            "chain": verify.get("chain"),
            "balances": verify.get("balances"),
        }
    finally:
        if not keep_schema:
            db.drop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DJB S1 end-to-end demo")
    parser.add_argument("--keep-schema", action="store_true", help="保留 demo schema 供排查")
    args = parser.parse_args(argv)
    try:
        summary = run(keep_schema=args.keep_schema)
    except Exception as exc:  # noqa: BLE001 - demo 入口：打印类型与摘要，不吞栈
        print(json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        raise
    print(json.dumps({"ok": True, **summary}, ensure_ascii=False, indent=2,
                     default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
