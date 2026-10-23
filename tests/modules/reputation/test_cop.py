# SPDX-License-Identifier: Apache-2.0
"""COP 台账适配测试（薄封装既有 points_* 台账）：INV-01 / INV-02 / INV-05 / INV-06 + 兑换与转让。

对应任务卡验收 3：

* 余额 ≥0 且 = available + locked；
* 只追加（UPDATE / DELETE 被 DB 拒绝——见 test_migrations）；
* 每条分录带 source / ref_id（视图映射到 INV-05 的七值枚举）；
* 兑换只扣 available（余不足 402 / 40201）；
* 转让开关关 409 / 40902；锁定期 / 超限 / 自转 422 / 42240。
"""
from __future__ import annotations

from datetime import timedelta

import psycopg
import pytest

from app import points
from app.reputation import cop, errors
from repukit import NOW, count, scalar, seed_account_on


def _policy_on(conn, **changes):
    return points.update_policy(conn, actor="ops:test", reason="DEV-M07 测试", **changes)


# --------------------------------------------------------------------------- 余额与守恒
def test_new_account_has_zero_balance(conn):
    account = seed_account_on(conn)
    balance = cop.balance(conn, account, now=NOW)
    assert (balance.available, balance.locked, balance.total_earned) == (0, 0, 0)
    assert balance.as_dict()["unit"] == "COP"
    assert balance.as_dict()["total"] == 0


def test_balance_is_available_plus_locked(conn):
    account = seed_account_on(conn)
    earned = cop.post_earn(conn, account, 500, source="usage", ref_id="usage-bal-1",
                           request_id="req-bal-1", lock_days=7, now=NOW)
    assert earned["units"] == 500
    balance = cop.balance(conn, account, now=NOW)
    assert balance.locked == 500 and balance.available == 0
    assert balance.as_dict()["total"] == balance.available + balance.locked == 500

    # 锁定到期（把时钟推到 8 天后）→ 全部可用，总量守恒
    points.release_due(conn, now=NOW + timedelta(days=8), account_id=account)
    after = cop.balance(conn, account, now=NOW + timedelta(days=8))
    assert (after.available, after.locked) == (500, 0)
    assert after.available + after.locked == 500


def test_ledger_view_covers_inv07_sources(conn):
    """INV-05：每条用户可见分录都带 source（七值枚举内）与 ref_id。"""
    account = seed_account_on(conn)
    other = seed_account_on(conn)
    _policy_on(conn, transfer_enabled=True)
    cop.post_earn(conn, account, 300, source="usage", ref_id="usage-src-1",
                  request_id="req-src-1", now=NOW)
    cop.post_earn(conn, account, 50, source="invite", ref_id="usage-src-2",
                  request_id="req-src-2", now=NOW)
    cop.redeem(conn, account, 40, request_id="req-src-3", actor="user:test", now=NOW)
    cop.transfer(conn, account, other, 30, request_id="req-src-4", now=NOW)

    entries, _ = cop.ledger_page(conn, account, limit=50)
    sources = {entry.source for entry in entries}
    assert {"usage", "invite", "redeem", "transfer_out"} <= sources
    allowed = {"usage", "invite", "reward", "transfer_in", "transfer_out", "redeem", "revoke"}
    for entry in entries:
        assert entry.source in allowed
        assert entry.ref_id                       # INV-05：ref_id 必填
        assert entry.direction in ("credit", "debit")
        assert entry.amount > 0
        assert entry.status in ("pending", "locked", "available", "spent", "revoked")


# --------------------------------------------------------------------------- 兑换
def test_redeem_only_consumes_available(conn):
    account = seed_account_on(conn)
    cop.post_earn(conn, account, 200, source="usage", ref_id="usage-red-1",
                  request_id="req-red-1", lock_days=0, now=NOW)
    redemption = cop.redeem(conn, account, 80, request_id="req-red-2", actor="user:test", now=NOW)
    assert redemption.units == 80 and redemption.state == "posted"
    balance = cop.balance(conn, account, now=NOW)
    assert balance.available == 120
    # 兑换单可回查（没有独立表：就是那条 redeem journal）
    found = cop.redemption(conn, account, redemption.redemption_id)
    assert found.units == 80 and found.state == "posted"


def test_redeem_cannot_touch_locked_units(conn):
    account = seed_account_on(conn)
    cop.post_earn(conn, account, 500, source="usage", ref_id="usage-red-2",
                  request_id="req-red-3", lock_days=7, now=NOW)
    with pytest.raises(errors.InsufficientBalance) as info:
        cop.redeem(conn, account, 100, request_id="req-red-4", actor="user:test", now=NOW)
    assert (info.value.status_code, info.value.code) == (402, "40201")
    # 锁定部分不变
    assert cop.balance(conn, account, now=NOW).locked == 500


def test_redeem_input_validation(conn):
    account = seed_account_on(conn)
    for bad in (0, -5, "abc"):
        with pytest.raises(errors.InvalidArgument) as info:
            cop.redeem(conn, account, bad, request_id=None, actor="user:test", now=NOW)
        assert (info.value.status_code, info.value.code) == (400, "40001")
    with pytest.raises(errors.InvalidArgument):
        cop.redeem(conn, account, 1, request_id=None, actor="user:test", now=NOW,
                   target="cash")


def test_redeem_is_idempotent_by_request_key(conn):
    account = seed_account_on(conn)
    cop.post_earn(conn, account, 200, source="usage", ref_id="usage-red-3",
                  request_id="req-red-5", lock_days=0, now=NOW)
    first = cop.redeem(conn, account, 50, request_id="req-red-6", actor="user:test", now=NOW)
    again = cop.redeem(conn, account, 50, request_id="req-red-6", actor="user:test", now=NOW)
    assert again.redemption_id == first.redemption_id
    assert cop.balance(conn, account, now=NOW).available == 150        # 只扣一次


def test_redemption_of_other_account_is_not_found(conn):
    owner = seed_account_on(conn)
    stranger = seed_account_on(conn)
    cop.post_earn(conn, owner, 100, source="usage", ref_id="usage-red-4",
                  request_id="req-red-7", lock_days=0, now=NOW)
    redemption = cop.redeem(conn, owner, 10, request_id="req-red-8", actor="user:test", now=NOW)
    with pytest.raises(errors.NotFound) as info:
        cop.redemption(conn, stranger, redemption.redemption_id)
    assert (info.value.status_code, info.value.code) == (404, "40401")


# --------------------------------------------------------------------------- 转让开关（K4）
def test_transfer_is_disabled_by_default(conn):
    """K4 / INV-06：``points.transfer_enabled=false`` → 409 / 40902，且不落任何分录。"""
    sender = seed_account_on(conn)
    receiver = seed_account_on(conn)
    _policy_on(conn, transfer_enabled=False)               # 显式复位：同 schema 内其它用例会开开关
    cop.post_earn(conn, sender, 100, source="usage", ref_id="usage-tr-0",
                  request_id="req-tr-0", lock_days=0, now=NOW)
    before = count(conn, "points_ledger")
    with pytest.raises(errors.TransferDisabled) as info:
        cop.transfer(conn, sender, receiver, 10, request_id="req-tr-1", now=NOW)
    assert (info.value.status_code, info.value.code) == (409, "40902")
    assert count(conn, "points_ledger") == before
    assert count(conn, "points_transfer") == 0


def test_transfer_posts_two_legs_and_locks_receiver(conn):
    sender = seed_account_on(conn)
    receiver = seed_account_on(conn)
    _policy_on(conn, transfer_enabled=True, lock_days=7)
    cop.post_earn(conn, sender, 500, source="usage", ref_id="usage-tr-1",
                  request_id="req-tr-2", lock_days=0, now=NOW)

    result = cop.transfer(conn, sender, receiver, 120, request_id="req-tr-3", now=NOW)
    assert result.state == "posted" and result.units == 120
    assert result.locked_until is not None
    assert result.locked_until >= NOW + timedelta(days=7)

    assert cop.balance(conn, sender, now=NOW).available == 380
    receiver_balance = cop.balance(conn, receiver, now=NOW)
    assert (receiver_balance.available, receiver_balance.locked) == (0, 120)

    # 两条等额分录（transfer_out / transfer_in）同属一个 journal
    with conn.cursor() as cur:
        cur.execute(
            """SELECT direction, amount, source FROM v_m07_cop_ledger
                WHERE account_id IN (%s, %s) AND source LIKE 'transfer%%'
                ORDER BY created_at""", (sender, receiver))
        rows = cur.fetchall()
    assert sorted((row[0], int(row[1]), row[2]) for row in rows) == [
        ("credit", 120, "transfer_in"), ("debit", 120, "transfer_out")]


def test_transfer_replay_returns_same_transfer(conn):
    sender = seed_account_on(conn)
    receiver = seed_account_on(conn)
    _policy_on(conn, transfer_enabled=True)
    cop.post_earn(conn, sender, 500, source="usage", ref_id="usage-tr-2",
                  request_id="req-tr-4", lock_days=0, now=NOW)
    first = cop.transfer(conn, sender, receiver, 50, request_id="req-tr-5", now=NOW)
    again = cop.transfer(conn, sender, receiver, 50, request_id="req-tr-5", now=NOW)
    assert again.transfer_id == first.transfer_id
    assert count(conn, "points_transfer") == 1
    assert cop.balance(conn, sender, now=NOW).available == 450


def test_transfer_validation_failures_are_42240(conn):
    sender = seed_account_on(conn)
    receiver = seed_account_on(conn)
    _policy_on(conn, transfer_enabled=True, per_transfer_max_units=100,
               daily_out_max_units=150, lock_days=7)
    cop.post_earn(conn, sender, 1000, source="usage", ref_id="usage-tr-3",
                  request_id="req-tr-6", lock_days=0, now=NOW)

    # 自转
    with pytest.raises(errors.ValidationFailed) as info:
        cop.transfer(conn, sender, sender, 10, request_id="req-tr-7", now=NOW)
    assert (info.value.status_code, info.value.code) == (422, "42240")
    assert info.value.reason == "self_transfer"

    # 单笔超限（>100）
    with pytest.raises(errors.ValidationFailed) as info:
        cop.transfer(conn, sender, receiver, 101, request_id="req-tr-8", now=NOW)
    assert info.value.reason == "per_transfer_limit"

    # 单日转出超限（100 + 100 > 150）
    cop.transfer(conn, sender, receiver, 100, request_id="req-tr-9", now=NOW)
    with pytest.raises(errors.ValidationFailed) as info:
        cop.transfer(conn, sender, receiver, 100, request_id="req-tr-10", now=NOW)
    assert info.value.reason == "daily_out_limit"

    # 闸门关闭：显式关掉开关后立刻拒绝（P0 配置「关闭即停新转让」）
    _policy_on(conn, transfer_enabled=False)
    with pytest.raises(errors.TransferDisabled):
        cop.transfer(conn, sender, receiver, 10, request_id="req-tr-11", now=NOW)


def test_transfer_requires_available_not_locked(conn):
    """锁定期内的积分不可转出（收到转让 7 天内不可再转出 / 抵扣）。"""
    sender = seed_account_on(conn)
    middle = seed_account_on(conn)
    receiver = seed_account_on(conn)
    _policy_on(conn, transfer_enabled=True, lock_days=7)
    cop.post_earn(conn, sender, 300, source="usage", ref_id="usage-tr-4",
                  request_id="req-tr-12", lock_days=0, now=NOW)
    cop.transfer(conn, sender, middle, 200, request_id="req-tr-13", now=NOW)   # middle 收到即锁定
    with pytest.raises(errors.ValidationFailed) as info:
        cop.transfer(conn, middle, receiver, 50, request_id="req-tr-14", now=NOW)
    assert (info.value.status_code, info.value.code) == (422, "42240")
    assert info.value.reason == "insufficient_points"


def test_transfer_of_unverified_account_is_rejected(conn):
    sender = seed_account_on(conn, verified=False)
    receiver = seed_account_on(conn)
    _policy_on(conn, transfer_enabled=True)
    cop.post_earn(conn, sender, 100, source="usage", ref_id="usage-tr-5",
                  request_id="req-tr-15", lock_days=0, now=NOW)
    with pytest.raises(errors.AccountUnavailable) as info:
        cop.transfer(conn, sender, receiver, 10, request_id="req-tr-16", now=NOW)
    assert (info.value.status_code, info.value.code) == (409, "40902")


def test_ensure_account_never_overwrites_verification(conn):
    account = seed_account_on(conn, verified=True, device_cluster="dev-1")
    cop.ensure_account(conn, account)
    with conn.cursor() as cur:
        cur.execute("SELECT verified, device_cluster FROM points_account WHERE account_id = %s",
                    (account,))
        verified, cluster = cur.fetchone()
    assert verified is True and cluster == "dev-1"


# --------------------------------------------------------------------------- 分页与复算
def test_ledger_pagination_is_keyset(conn):
    account = seed_account_on(conn)
    for index in range(5):
        cop.post_earn(conn, account, 10, source="usage", ref_id=f"usage-page-{index}",
                      request_id=f"req-page-{index}", lock_days=0,
                      now=NOW + timedelta(minutes=index))
    first, cursor = cop.ledger_page(conn, account, limit=2)
    assert len(first) == 2 and cursor
    second, cursor2 = cop.ledger_page(conn, account, limit=2, cursor=cursor)
    assert len(second) == 2 and cursor2
    third, cursor3 = cop.ledger_page(conn, account, limit=2, cursor=cursor2)
    assert len(third) == 1 and cursor3 is None
    ids = [entry.id for entry in first + second + third]
    assert len(set(ids)) == 5


def test_ledger_rejects_bad_limit(conn):
    account = seed_account_on(conn)
    with pytest.raises(errors.InvalidArgument):
        cop.ledger_page(conn, account, limit="abc")
    with pytest.raises(errors.InvalidArgument):
        cop.ledger_page(conn, account, limit=0)


def test_cop_ledger_reconciliation_has_no_diff(conn):
    """账本复算：视图净额 == available + locked，且从不出现负数（INV-01）。"""
    account = seed_account_on(conn)
    cop.post_earn(conn, account, 400, source="usage", ref_id="usage-rec-1",
                  request_id="req-rec-1", lock_days=0, now=NOW)
    cop.post_earn(conn, account, 100, source="invite", ref_id="usage-rec-2",
                  request_id="req-rec-2", lock_days=0, now=NOW)
    cop.redeem(conn, account, 50, request_id="req-rec-3", actor="user:test", now=NOW)

    net = int(scalar(conn, """SELECT COALESCE(SUM(CASE WHEN direction = 'credit' THEN amount
                                                        ELSE -amount END), 0)
                                FROM v_m07_cop_ledger WHERE account_id = %s""", (account,)))
    balance = cop.balance(conn, account, now=NOW)
    assert net == balance.available + balance.locked
    assert balance.available >= 0 and balance.locked >= 0
    # 本模块自己的复算口径也必须是 0 差异
    report = points.recompute(conn)
    assert report["diff"] == 0
    with conn.cursor() as cur:
        cur.execute("""SELECT usable_units, locked_units FROM points_holding
                        WHERE account_id = %s""", (account,))
        usable, locked = (int(value) for value in cur.fetchone())
    assert usable >= 0 and locked >= 0


def test_frozen_account_cannot_redeem(conn):
    account = seed_account_on(conn, state="frozen")
    with pytest.raises(errors.AccountUnavailable) as info:
        cop.redeem(conn, account, 1, request_id="req-frz-1", actor="user:test", now=NOW)
    assert (info.value.status_code, info.value.code) == (409, "40902")
