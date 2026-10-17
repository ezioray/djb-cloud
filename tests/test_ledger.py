# SPDX-License-Identifier: Apache-2.0
import os, uuid

import pytest

os.environ.setdefault("DJB_DSN", "postgresql:///djb_dev")  # 真值从环境注入，测试文件不含凭据

from app import db  # noqa: E402
from app.ledger import post_entry, recompute, entry_hash  # noqa: E402


def _two_accounts(c, tag):
    a, b = f"user:t-{tag}", f"node:t-{tag}"
    with c.cursor() as cur:
        cur.execute("INSERT INTO accounts (id,kind) VALUES (%s,'user'),(%s,'node') ON CONFLICT DO NOTHING", (a, b))
    return a, b


def test_chain_and_balances_recompute_to_zero():
    tag = uuid.uuid4().hex[:8]
    with db.conn() as c:
        a, b = _two_accounts(c, tag)
        post_entry(c, a, b, 1000, memo=f"t1-{tag}")
        post_entry(c, a, b, 2500, memo=f"t2-{tag}")
    with db.conn() as c:
        r = recompute(c)
    assert r["diff"] == 0, r


def test_ledger_is_append_only():
    tag = uuid.uuid4().hex[:8]
    with db.conn() as c:
        a, b = _two_accounts(c, tag)
        post_entry(c, a, b, 777, memo=f"t3-{tag}")
    with pytest.raises(Exception) as ei:
        with db.conn() as c, c.cursor() as cur:
            cur.execute("UPDATE ledger_entries SET amount_micro = amount_micro + 1 WHERE memo = %s", (f"t3-{tag}",))
    assert "append-only" in str(ei.value).lower()
