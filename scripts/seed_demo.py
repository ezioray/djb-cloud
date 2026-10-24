# SPDX-License-Identifier: AGPL-3.0-or-later
"""写入 1 条双签收据 + 2 条分录（demo）。"""
import hashlib, uuid
from datetime import datetime, timedelta, timezone

from app import db
from app.ledger import post_entry


def sig(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()


def main():
    now = datetime.now(timezone.utc)
    rid = str(uuid.uuid4())
    req = f"demo-{uuid.uuid4().hex[:12]}"
    consumer, node, platform = "user:demo-001", "node:demo-001", "platform:fee"
    amount = 1_250_000  # 1.25 COIN（微单位）
    fee = amount // 100  # 1% 平台费

    with db.conn() as c, c.cursor() as cur:
        cur.execute("""INSERT INTO accounts (id, kind) VALUES (%s,'user'),(%s,'node'),(%s,'platform'),(%s,'pool')
                       ON CONFLICT (id) DO NOTHING""",
                    (consumer, node, platform, "pool:loss"))
        cur.execute("""INSERT INTO receipts (id,node_id,consumer_id,request_id,model,tokens_in,tokens_out,
                       amount_micro,sig_supplier,sig_consumer,ts_start,ts_end)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (rid, node, consumer, req, "djb/chat-lite", 800, 1200, amount,
                     sig(rid, "supplier"), sig(rid, "consumer"), now - timedelta(seconds=3), now))
    with db.conn() as c:
        post_entry(c, debit=consumer, credit=node, amount_micro=amount - fee, memo="usage settle", receipt_id=rid)
        post_entry(c, debit=consumer, credit=platform, amount_micro=fee, memo="platform fee", receipt_id=rid)
    print(f"seeded receipt={rid} request={req} amount_micro={amount} fee_micro={fee}")


if __name__ == "__main__":
    main()
