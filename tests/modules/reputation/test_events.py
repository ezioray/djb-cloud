# SPDX-License-Identifier: Apache-2.0
"""事件消费与重算测试（§4.2 / §6.1 / §6.2 / §7 / §4.3）。

覆盖验收 3 的「同一 ``usage.settled`` 重放 10 次 → COP 只增一次」与 §9 的 ①「结算 100 USD →
被邀请人按 ``points.invite_bps`` 计提，inviter 再得该笔的 4%，两条分录均可回溯 usage_id」。
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.reputation import cop, errors, events, invites, score, store
from repukit import NOW, count, event as make_event, seed_account_on

AMOUNT_MINOR = 10_000            # 100 USD → 10,000 COP（1 USD = 100 COP）


def _settle(conn, account, usage_id="usage-evt-1", amount_minor=AMOUNT_MINOR, **kwargs):
    envelope = make_event("usage.settled", account_id=account, occurred_at=NOW,
                          usage_id=usage_id, final_amount_minor=amount_minor, **kwargs)
    return events.consume_usage_settled(conn, envelope, now=NOW)


# --------------------------------------------------------------------------- 计提
def test_usage_settled_accrues_locked_cop(conn):
    account = seed_account_on(conn)
    result = _settle(conn, account)
    assert result["status"] == "settled" and result["units"] == AMOUNT_MINOR
    balance = cop.balance(conn, account, now=NOW)
    assert balance.locked == AMOUNT_MINOR and balance.available == 0     # §6.1 锁定期
    assert result["lock_until"] is not None

    # 指标事实落库（可复算）
    rows = store.latest_events(conn, account)
    assert [row.metric for row in rows] == ["usage_settled"]
    assert int(rows[0].value) == AMOUNT_MINOR
    # 事件已入 outbox
    assert count(conn, "reputation_outbox", "type = 'cop.earned'") == 1


def test_usage_settled_replay_only_accrues_once(conn):
    """§9 验收 ⑤：同一 ``usage.settled`` 重放 10 次 → COP 只增一次。"""
    account = seed_account_on(conn)
    first = _settle(conn, account)
    for _ in range(9):
        replay = _settle(conn, account)
        assert replay["status"] == "duplicate"
    assert cop.balance(conn, account, now=NOW).locked == first["units"]
    assert count(conn, "points_journal", "account_id = %s", (account,)) == 1
    assert count(conn, "reputation_events", "account_id = %s", (account,)) == 1
    assert count(conn, "reputation_outbox") == 1


def test_usage_settled_requires_business_keys(conn):
    account = seed_account_on(conn)
    bad = make_event("usage.settled", account_id=account, occurred_at=NOW,
                     final_amount_minor=100)                        # 缺 usage_id
    with pytest.raises(errors.InvalidArgument):
        events.consume_usage_settled(conn, bad, now=NOW)
    bad_amount = make_event("usage.settled", account_id=account, occurred_at=NOW,
                            usage_id="u-bad", final_amount_minor="abc")
    with pytest.raises(errors.InvalidArgument):
        events.consume_usage_settled(conn, bad_amount, now=NOW)


def test_zero_amount_settles_without_accrual(conn):
    account = seed_account_on(conn)
    result = _settle(conn, account, usage_id="usage-zero", amount_minor=0)
    assert result["units"] == 0
    assert cop.balance(conn, account, now=NOW).total_earned == 0
    assert count(conn, "reputation_events", "account_id = %s", (account,)) == 1


# --------------------------------------------------------------------------- 邀请奖励
def test_invite_reward_is_percentage_of_invitee_cop(conn):
    """§9 ①：inviter 再得被邀请人该笔 COP 的 4%（``points.invite_bps=400``）。"""
    inviter = seed_account_on(conn)
    invitee = seed_account_on(conn)
    invites.bind(conn, invites.issue(conn, inviter, now=NOW).code, invitee, now=NOW)

    result = _settle(conn, invitee)
    assert result["invite_units"] == AMOUNT_MINOR * 400 // 10_000 == 400
    assert result["inviter_id"] == inviter
    inviter_balance = cop.balance(conn, inviter, now=NOW)
    assert inviter_balance.available == 400                     # 奖励直接可用（不锁）

    # 两条分录都能回溯到同一个 usage_id（P1 验收点）
    with conn.cursor() as cur:
        cur.execute("""SELECT account_id, direction, amount, source, ref_id FROM v_m07_cop_ledger
                        WHERE ref_id = %s ORDER BY source""", ("usage-evt-1",))
        rows = cur.fetchall()
    assert [(row[0], row[3]) for row in rows] == [(inviter, "invite"), (invitee, "usage")]
    assert all(row[4] == "usage-evt-1" for row in rows)
    assert count(conn, "reputation_outbox", "type = 'cop.earned'") == 2


def test_invite_reward_stops_after_window(conn):
    """§6.2：绑定日 + ``points.invite_months`` 之后不再计提，也不追溯。"""
    inviter = seed_account_on(conn)
    invitee = seed_account_on(conn)
    long_ago = NOW - timedelta(days=400)                        # > 12 个月
    invites.bind(conn, invites.issue(conn, inviter, now=long_ago).code, invitee, now=long_ago)
    result = _settle(conn, invitee)
    assert result["invite_units"] == 0
    assert cop.balance(conn, inviter, now=NOW).total_earned == 0


# --------------------------------------------------------------------------- 账户状态
def test_account_state_changed_blocks_redemption(conn):
    account = seed_account_on(conn)
    _settle(conn, account, usage_id="usage-frz", amount_minor=5_000)
    envelope = make_event("account.state.changed", account_id=account, occurred_at=NOW,
                          **{"from": "normal", "to": "frozen"})
    result = events.consume_account_state_changed(conn, envelope)
    assert result["state"] == "frozen"
    balance_before = cop.balance(conn, account, now=NOW)
    with pytest.raises(errors.AccountUnavailable) as info:
        cop.redeem(conn, account, 10, request_id="req-frz-2", actor="user:test", now=NOW)
    assert (info.value.status_code, info.value.code) == (409, "40902")
    # 已得 COP 保留（只拒绝写入，不扣减）
    assert cop.balance(conn, account, now=NOW).locked == balance_before.locked


def test_account_state_changed_validates_state(conn):
    account = seed_account_on(conn)
    bad = make_event("account.state.changed", account_id=account, occurred_at=NOW, to="zombie")
    with pytest.raises(errors.InvalidArgument):
        events.consume_account_state_changed(conn, bad)


# --------------------------------------------------------------------------- 重算
def test_refresh_score_promotes_and_emits_event(conn):
    account = seed_account_on(conn)
    _settle(conn, account, usage_id="usage-l2", amount_minor=AMOUNT_MINOR)   # 累计 10000
    events.record_metrics(conn, account, {"online_rate": 960, "success_rate": 900,
                                          "latency_ok_rate": 900, "yield_response": 900},
                          ref_id="metrics-1", occurred_at=NOW)
    row = events.refresh_score(conn, account, now=NOW)
    assert row.tier == "L2"
    assert row.score > 0
    assert count(conn, "reputation_outbox", "type = 'reputation.changed'") == 1
    with conn.cursor() as cur:
        cur.execute("""SELECT payload FROM reputation_outbox
                        WHERE type = 'reputation.changed' LIMIT 1""")
        payload = cur.fetchone()[0]
    assert payload["reasons"] and payload["policy_version"]      # INV-07
    assert payload["tier"] == "L2"
    assert not any(char.isdigit() for reason in payload["reasons"] for char in reason)


def test_refresh_score_demotes_when_conditions_lost(conn):
    account = seed_account_on(conn)
    _settle(conn, account, usage_id="usage-l2b", amount_minor=AMOUNT_MINOR)
    events.record_metrics(conn, account, {"online_rate": 960}, ref_id="metrics-2", occurred_at=NOW)
    assert events.refresh_score(conn, account, now=NOW).tier == "L2"

    events.record_metrics(conn, account, {"online_rate": 100}, ref_id="metrics-3",
                          occurred_at=NOW + timedelta(hours=1))
    row = events.refresh_score(conn, account, now=NOW + timedelta(hours=1))
    assert row.tier == "L1"                                      # 掉级即时生效
    assert "tier_demoted" in row.reasons


def test_refresh_score_is_stable_when_nothing_changes(conn):
    account = seed_account_on(conn)
    events.record_metrics(conn, account, {"online_rate": 700}, ref_id="metrics-4", occurred_at=NOW)
    first = events.refresh_score(conn, account, now=NOW)
    before = count(conn, "reputation_outbox")
    second = events.refresh_score(conn, account, now=NOW + timedelta(minutes=5))
    assert second.tier == first.tier and second.score == first.score
    assert count(conn, "reputation_outbox") == before             # 不变就不发事件
    assert second.tier_since == first.tier_since                  # 连续天数不被重置


def test_recompute_account_returns_summary(conn):
    account = seed_account_on(conn)
    events.record_metrics(conn, account, {"online_rate": 800}, ref_id="metrics-5", occurred_at=NOW)
    summary = events.recompute_account(conn, account, now=NOW)
    assert summary["account_id"] == account
    assert summary["tier"] in ("L1", "L2", "L3", "L4", "L5")
    assert store.get_score(conn, account) is not None


def test_record_metrics_and_penalties(conn):
    account = seed_account_on(conn)
    written = events.record_metrics(conn, account,
                                    {"success_rate": 950, "online_rate": 970},
                                    ref_id="metrics-6", occurred_at=NOW)
    assert written == 4                                          # 四项各一条
    assert events.record_metrics(conn, account, {"success_rate": 950}, ref_id="metrics-6",
                                 occurred_at=NOW) == 0            # 同 ref 幂等
    assert events.latest_metrics(conn, account)["online_rate"] == 970

    with conn.cursor() as cur:
        cur.execute("""INSERT INTO reputation_events
                         (id, account_id, metric, value, weight, delta, ref_id, occurred_at)
                       VALUES (gen_random_uuid(), %s, 'penalty', 2, 0, -400, 'violation:case-1', %s)""",
                    (account, NOW))
    assert events.penalties_from_events(conn, account) == {"violation": 2}


def test_manual_l5_is_kept_by_refresh(conn):
    account = seed_account_on(conn)
    events.record_metrics(conn, account, {"online_rate": 800}, ref_id="metrics-7", occurred_at=NOW)
    events.refresh_score(conn, account, now=NOW, manual_tier=True)
    row = events.refresh_score(conn, account, now=NOW + timedelta(days=1), manual_tier=True)
    assert row.tier == "L5" and row.manual_tier is True           # L5 只有人工能给 / 能撤
    demoted = events.refresh_score(conn, account, now=NOW + timedelta(days=2), manual_tier=False)
    assert demoted.tier in ("L1", "L2", "L3", "L4")


def test_cumulative_cop_excludes_transfers(conn):
    """L2 门槛的「累计 COP」只算产出（usage / invite），转让与人工授予不算。"""
    account = seed_account_on(conn)
    other = seed_account_on(conn)
    cop.post_earn(conn, account, 5_000, source="reward", ref_id="grant-x",
                  request_id="req-cum-1", now=NOW)
    events.record_metrics(conn, account, {"online_rate": 999}, ref_id="metrics-8", occurred_at=NOW)
    assert events.refresh_score(conn, account, now=NOW).tier == "L1"
    cop.post_earn(conn, account, 10_000, source="usage", ref_id="usage-cum",
                  request_id="req-cum-2", now=NOW)
    assert events.refresh_score(conn, other, now=NOW).tier == "L1"
    assert events.refresh_score(conn, account, now=NOW).tier == "L2"


def test_score_thresholds_come_from_injected_config(conn):
    from app.reputation import facts

    account = seed_account_on(conn)
    cop.post_earn(conn, account, 100, source="usage", ref_id="usage-cfg",
                  request_id="req-cfg-1", now=NOW)
    events.record_metrics(conn, account, {"online_rate": 960}, ref_id="metrics-9", occurred_at=NOW)
    strict = facts.ReputationConfig(l2_cumulative_cop=10_000, l2_online_rate=950).validated()
    assert events.refresh_score(conn, account, now=NOW, config=strict).tier == "L1"
    loose = facts.ReputationConfig(l2_cumulative_cop=1, l2_online_rate=900).validated()
    row = events.refresh_score(conn, account, now=NOW, config=loose)
    assert row.tier == "L2"
    assert row.policy_version == loose.policy_version


def test_outbox_pending_roundtrip(conn):
    """outbox 投递往返：待投递 → 标记已发布（唯一允许的 UPDATE）。"""
    from app.reputation import outbox

    account = seed_account_on(conn)
    _settle(conn, account, usage_id="usage-outbox")
    later = NOW + timedelta(days=1)                 # next_attempt_at 用库内 now() 初始化
    rows = outbox.pending(conn, limit=10, now=later)
    assert rows and rows[0]["type"] == "cop.earned"
    outbox.mark_published(conn, rows[0]["id"], now=later)
    assert outbox.pending(conn, limit=10, now=later) == []
    with conn.cursor() as cur:
        cur.execute("SELECT attempts, published_at IS NOT NULL FROM reputation_outbox")
        attempts, published = cur.fetchone()
    assert attempts == 1 and published is True


def test_score_module_is_pure():
    """重算引擎不 import 数据库层（可单测到每个分支）。"""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(score))          # 只看真实 import，不看文档字符串
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert "psycopg" not in imported, imported
    assert "app" not in imported, imported
