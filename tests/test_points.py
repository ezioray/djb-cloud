# SPDX-License-Identifier: Apache-2.0
"""DEV-0003 COP 积分台账与转让开关（K4 / v4 §4.5 §6.6 §9.1 §20.1 §20.4.4）。

覆盖验收：
① points.transfer_enabled 默认 false，关闭时转让 403；
② 单日 / 单笔上限、7 天到账锁定、自转拒绝、冻结（及未验证 / 注销）账户拒绝；
③ 转让只在平台内记账：不产生 USD 分录、不触链；
④ COP 不进 PoR 分子分母；
⑤ 抵扣服务费按配置比例且留审计。

另覆盖：六值动作与 journal 平衡、adjust 双人复核、void 冲正、request_id 幂等、
只追加、读路径拒绝未登记 action、以及「源码里不出现现金账户类命名」的红线自检。

事务约定：预期失败的调用一律用独立事务（`_expect`），避免把已经准备好的账户/策略
一起回滚掉 —— 这也正是被拒绝的请求在真实系统里的行为（整笔回滚、不留半条分录）。

DB：`DJB_DSN` 指向开发库；无库整文件 skip。
"""
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app import db
from app import points as pts
from app.config import dsn
from app.ledger import recompute as usd_recompute

NOW = datetime(2026, 10, 22, 4, 0, tzinfo=timezone.utc)
MIGRATION = os.path.join(os.path.dirname(__file__), "..", "migrations", "006_points.sql")
SOURCE = os.path.join(os.path.dirname(__file__), "..", "app", "points.py")


# --------------------------------------------------------------------------- 基础设施
@pytest.fixture(scope="module", autouse=True)
def _schema():
    if not os.environ.get("DJB_DSN"):
        pytest.skip("缺 DJB_DSN：开发库未注入")
    try:
        conn = psycopg.connect(dsn(), autocommit=True)
    except psycopg.OperationalError as exc:      # pragma: no cover - 环境缺库
        pytest.skip(f"开发库不可达：{exc}")
    with conn:
        conn.execute(open(MIGRATION, encoding="utf-8").read())


@pytest.fixture(autouse=True)
def _reset_policy():
    """每个用例从默认策略（转让关闭）开始。points_transfer 只追加，故不做删除。"""
    with db.conn() as c, c.cursor() as cur:
        cur.execute(
            """UPDATE points_policy
                  SET transfer_enabled = FALSE, per_transfer_max_units = 1000,
                      daily_out_max_units = 10000, daily_in_max_units = 10000,
                      lock_days = 7, redeem_cop_per_usd = 100, redeem_max_share_bps = 2000,
                      policy_version = 'v4.0'
                WHERE policy_key = 'default'""")


def _tx(fn):
    """成功路径：独立事务。"""
    with db.conn() as c:
        return fn(c)


def _expect(exc, fn):
    """失败路径：独立事务，断言异常后整笔回滚、不留分录。"""
    with pytest.raises(exc) as ei:
        with db.conn() as c:
            fn(c)
    return ei.value


def _new_account(**kw) -> str:
    tag = uuid.uuid4().hex[:8]
    account_id = f"user:cop-{tag}"
    _tx(lambda c: pts.open_account(c, account_id, **kw))
    return account_id


def _enable(**changes):
    _tx(lambda c: pts.update_policy(c, actor="ops:test", reason="case setup",
                                    transfer_enabled=True, **changes))


def _grant(account_id: str, units: int):
    _tx(lambda c: pts.earn(c, account_id, units, reason_code="invite_reward", ref_id="case"))


def _rid(prefix: str = "test") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- ① 开关
def test_transfer_disabled_by_default_is_403():
    policy = _tx(pts.load_policy)
    assert policy.transfer_enabled is False
    assert pts.capabilities(policy)["transferable"] is False
    assert pts.capabilities()["withdrawable"] is False
    assert pts.capabilities()["custodial"] is False

    a, b = _new_account(), _new_account()
    _grant(a, 500)
    rid = _rid("test-off")
    err = _expect(pts.TransferDisabled,
                  lambda c: pts.transfer(c, a, b, 100, request_id=rid, now=NOW))
    assert err.status_code == 403 and err.code == "40303"
    assert err.as_dict()["reason"] == "feature_not_open"
    assert err.as_dict()["open_phase"]

    # 被拒绝的请求不留任何痕迹
    assert _tx(lambda c: pts.holding(c, b))["total_units"] == 0
    assert _tx(lambda c: pts.holding(c, a))["usable_units"] == 500
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM points_transfer WHERE request_id = %s", (rid,))
        assert cur.fetchone()[0] == 0


def test_switch_off_stops_new_transfers_but_keeps_past_ones():
    a, b = _new_account(), _new_account()
    _grant(a, 500)
    _enable()
    res = _tx(lambda c: pts.transfer(c, a, b, 100, request_id=_rid("test-on"), now=NOW))
    assert res["idempotent"] is False and res["amount_units"] == 100

    _tx(lambda c: pts.update_policy(c, actor="ops:test", reason="rollback",
                                    transfer_enabled=False))
    _expect(pts.TransferDisabled,
            lambda c: pts.transfer(c, a, b, 100, request_id=_rid("test-off2"), now=NOW))

    # 已转让积分保留、不回溯扣回
    assert _tx(lambda c: pts.holding(c, b))["total_units"] == 100
    assert _tx(lambda c: pts.holding(c, a))["usable_units"] == 400


# --------------------------------------------------------------------------- ② 转让规则
def test_self_transfer_and_limits_are_rejected():
    a, b = _new_account(), _new_account()
    _grant(a, 5_000)
    _enable(per_transfer_max_units=100, daily_out_max_units=150)

    err = _expect(pts.TransferRejected,
                  lambda c: pts.transfer(c, a, a, 10, request_id=_rid("test-self"), now=NOW))
    assert err.as_dict()["reason"] == "self_transfer"

    err = _expect(pts.TransferRejected,
                  lambda c: pts.transfer(c, a, b, 101, request_id=_rid("test-per"), now=NOW))
    assert err.as_dict()["reason"] == "per_transfer_limit"

    _tx(lambda c: pts.transfer(c, a, b, 100, request_id=_rid("test-t1"), now=NOW))
    err = _expect(pts.TransferRejected,
                  lambda c: pts.transfer(c, a, b, 100, request_id=_rid("test-t2"), now=NOW))
    assert err.as_dict()["reason"] == "daily_out_limit"       # 100 + 100 > 150

    # 收款侧单日上限
    _enable(per_transfer_max_units=100, daily_out_max_units=10_000, daily_in_max_units=150)
    src, dst = _new_account(), _new_account()
    _grant(src, 1_000)
    _tx(lambda c: pts.transfer(c, src, dst, 100, request_id=_rid("test-in1"), now=NOW))
    err = _expect(pts.TransferRejected,
                  lambda c: pts.transfer(c, src, dst, 100, request_id=_rid("test-in2"), now=NOW))
    assert err.as_dict()["reason"] == "daily_in_limit"


def test_received_points_are_locked_for_7_days():
    a, b, x = _new_account(), _new_account(), _new_account()
    _grant(a, 1_000)
    _enable()

    _tx(lambda c: pts.transfer(c, a, b, 400, request_id=_rid("test-lock"), now=NOW))
    h = _tx(lambda c: pts.holding(c, b))
    assert (h["usable_units"], h["locked_units"]) == (0, 400)

    # 锁定期内不可再转出、不可抵扣
    err = _expect(pts.InsufficientHolding,
                  lambda c: pts.transfer(c, b, x, 100, request_id=_rid("test-lock2"), now=NOW))
    assert err.as_dict()["reason"] == "insufficient_points"
    err = _expect(pts.InsufficientHolding,
                  lambda c: pts.redeem_service_fee(c, b, usd_minor=100, now=NOW))
    assert err.as_dict()["reason"] == "insufficient_points"

    # 差 1 分钟仍锁定；满 7 天释放
    assert _tx(lambda c: pts.release_due(c, now=NOW + timedelta(days=7) - timedelta(minutes=1),
                                        account_id=b)) == []
    released = _tx(lambda c: pts.release_due(c, now=NOW + timedelta(days=7), account_id=b))
    assert len(released) == 1 and released[0]["units"] == 400
    h = _tx(lambda c: pts.holding(c, b))
    assert (h["usable_units"], h["locked_units"]) == (400, 0)

    # 释放后可正常转出
    res = _tx(lambda c: pts.transfer(c, b, x, 100, request_id=_rid("test-lock3"),
                                     now=NOW + timedelta(days=7)))
    assert res["amount_units"] == 100


def test_ineligible_accounts_are_rejected():
    _enable()
    good = _new_account()
    _grant(good, 500)

    for state in ("frozen", "closing", "closed"):
        bad = _new_account(state=state)
        err = _expect(pts.TransferRejected,
                      lambda c, bad=bad: pts.transfer(c, good, bad, 10,
                                                      request_id=_rid("test-st")))
        assert err.as_dict()["reason"] == "account_state"

    unverified = _new_account(verified=False)
    err = _expect(pts.TransferRejected,
                  lambda c: pts.transfer(c, good, unverified, 10, request_id=_rid("test-uv")))
    assert err.as_dict()["reason"] == "account_unverified"

    # 转出方被冻结同样拒绝
    frozen = _new_account()
    _grant(frozen, 100)
    _tx(lambda c: pts.set_account_state(c, frozen, "frozen", actor="ops:test"))
    err = _expect(pts.TransferRejected,
                  lambda c: pts.transfer(c, frozen, good, 10, request_id=_rid("test-fz")))
    assert err.as_dict()["reason"] == "account_state"


def test_same_device_or_payment_cluster_is_rejected():
    _enable()
    a = _new_account(device_cluster="dev-1", payment_cluster="card-1")
    b = _new_account(device_cluster="dev-1")
    d = _new_account(payment_cluster="card-1")
    e = _new_account(device_cluster="dev-2", payment_cluster="card-2")
    _grant(a, 500)

    err = _expect(pts.TransferRejected,
                  lambda c: pts.transfer(c, a, b, 50, request_id=_rid("test-dc")))
    assert err.as_dict()["reason"] == "same_device_cluster"
    err = _expect(pts.TransferRejected,
                  lambda c: pts.transfer(c, a, d, 50, request_id=_rid("test-pc")))
    assert err.as_dict()["reason"] == "same_payment_cluster"

    res = _tx(lambda c: pts.transfer(c, a, e, 50, request_id=_rid("test-ok"), now=NOW))
    assert res["amount_units"] == 50


# --------------------------------------------------------------------------- ③ 不碰 USD 账本 / 不触链
def test_transfer_writes_only_points_ledger_and_no_usd_entries():
    with db.conn() as c:
        before = pts.usd_ledger_fingerprint(c)
        usd_diff_before = usd_recompute(c)["diff"]

    a, b = _new_account(), _new_account()
    _grant(a, 2_000)
    _enable()
    res = _tx(lambda c: pts.transfer(c, a, b, 300, request_id=_rid("test-usd"), now=NOW))

    with db.conn() as c:
        after = pts.usd_ledger_fingerprint(c)
        assert after == before, (before, after)
        assert usd_recompute(c)["diff"] == usd_diff_before == 0
        assert res["on_chain"] is False and res["usd_entries"] == 0
        assert res["fee_units"] == 0          # 平台不收转让费
        assert res["in_por"] is False

        report = pts.recompute(c)
        assert report["diff"] == 0
        assert report["non_cop_entries"] == 0
        with c.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ledger_entries WHERE unit_type = 'COP'")
            assert cur.fetchone()[0] == 0


# --------------------------------------------------------------------------- ④ PoR
def test_cop_is_excluded_from_proof_of_reserves():
    assert pts.por_contribution() == {
        "numerator_minor": 0, "denominator_minor": 0, "excluded": True,
        "unit_type": "COP", "reason": "COP 是非货币积分，不计入 PoR 分子或分母"}
    a = _new_account()
    _grant(a, 10_000)
    with db.conn() as c:
        # 发放 COP 不改变 PoR 的取数面（USD 账本）
        assert pts.usd_ledger_fingerprint(c)["non_usd_entries"] == 0


# --------------------------------------------------------------------------- ⑤ 六值动作与抵扣
def test_six_value_actions_keep_journals_balanced():
    a = _new_account()
    with db.conn() as c:
        earn_j = pts.earn(c, a, 1_000, reason_code="invite_reward", ref_id="r1")
        assert pts.holding(c, a)["usable_units"] == 1_000

        freeze_j = pts.freeze(c, a, 400, reason_code="risk_hold", actor="ops:risk")
        h = pts.holding(c, a)
        assert (h["usable_units"], h["locked_units"]) == (600, 400)

        unfreeze_j = pts.unfreeze(c, a, 100, reason_code="manual_release", actor="ops:risk")
        h = pts.holding(c, a)
        assert (h["usable_units"], h["locked_units"]) == (700, 300)

        adj_j = pts.adjust(c, a, -50, reason_code="clawback", approved_by="ops:reviewer",
                           actor="ops:ops")
        assert pts.holding(c, a)["usable_units"] == 650

        redeem_j = pts.redeem_service_fee(c, a, usd_minor=100, ref_id="bill-1", now=NOW)
        assert redeem_j["cop_used"] == 20 and redeem_j["redeem_cop_per_usd"] == 100  # 默认 20% 抵扣上限
        assert pts.holding(c, a)["usable_units"] == 630

        void_j = pts.void(c, adj_j["journal_id"], reason_code="misclick", actor="ops:ops")
        assert pts.holding(c, a)["usable_units"] == 680

        for j in (earn_j, freeze_j, unfreeze_j, adj_j, redeem_j, void_j):
            assert sum(leg["delta"] for leg in j["legs"]) == 0, j["journal_id"]
        assert {j["action"] for j in (earn_j, freeze_j, unfreeze_j, adj_j, redeem_j, void_j)} == {
            "earn", "freeze", "unfreeze", "adjust", "redeem", "void"}
        assert pts.recompute(c)["diff"] == 0


def test_adjust_requires_reason_and_second_reviewer():
    a = _new_account()
    _grant(a, 100)
    err = _expect(pts.PointsError,
                  lambda c: pts.adjust(c, a, 10, reason_code="", approved_by="ops:reviewer",
                                       actor="ops:ops"))
    assert err.as_dict()["reason"] == "reason_required"
    err = _expect(pts.PointsError,
                  lambda c: pts.adjust(c, a, 10, reason_code="gift", approved_by="ops:ops",
                                       actor="ops:ops"))
    assert err.as_dict()["reason"] == "sod_violation"
    _expect(pts.PointsError,
            lambda c: pts.adjust(c, a, 10, reason_code="gift", approved_by="", actor="ops:ops"))


def test_void_marks_reverse_of_and_cannot_repeat():
    a = _new_account()
    j = _tx(lambda c: pts.earn(c, a, 300, reason_code="invite_reward"))
    v = _tx(lambda c: pts.void(c, j["journal_id"], reason_code="wrong_account", actor="ops:ops"))
    assert all(leg["reverse_of"] for leg in v["legs"])
    assert _tx(lambda c: pts.holding(c, a))["total_units"] == 0
    err = _expect(pts.PointsError,
                  lambda c: pts.void(c, j["journal_id"], reason_code="again", actor="ops:ops"))
    assert err.as_dict()["reason"] == "already_voided"


def test_redeem_uses_configured_ratio_and_caps_share():
    a = _new_account()
    _grant(a, 10_000)

    # 默认 20% 上限：1 USD 账单最多用 20 COP
    capped = _tx(lambda c: pts.redeem_service_fee(c, a, usd_minor=100, now=NOW))
    assert capped["cop_used"] == 20 and capped["max_share_bps"] == 2000

    # 放开到 100%，并把换算比例改为 1 USD = 50 COP
    _tx(lambda c: pts.update_policy(c, actor="ops:test", reason="case",
                                    redeem_cop_per_usd=50, redeem_max_share_bps=10_000))
    full = _tx(lambda c: pts.redeem_service_fee(c, a, usd_minor=100, now=NOW))
    assert full["cop_used"] == 50 and full["redeem_cop_per_usd"] == 50
    # 审计字段齐全（动作 / 原因 / 策略版本 / 操作者 / 被抵扣对象）
    assert full["action"] == "redeem" and full["reason_code"] == "service_fee"
    assert full["policy_version"] == "v4.0" and full["actor"] == "system:points"
    assert full["ref_id"] is None
    assert _tx(lambda c: pts.holding(c, a))["usable_units"] == 10_000 - 20 - 50


# --------------------------------------------------------------------------- 幂等 / 只追加 / 红线
def test_transfer_is_idempotent_per_request_id():
    a, b = _new_account(), _new_account()
    _grant(a, 1_000)
    _enable()
    rid = _rid("test-idem")
    first = _tx(lambda c: pts.transfer(c, a, b, 200, request_id=rid, now=NOW))
    second = _tx(lambda c: pts.transfer(c, a, b, 200, request_id=rid, now=NOW))
    assert second["idempotent"] is True
    assert second["transfer_id"] == first["transfer_id"]
    assert _tx(lambda c: pts.holding(c, a))["usable_units"] == 800
    assert _tx(lambda c: pts.holding(c, b))["total_units"] == 200
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM points_transfer WHERE request_id = %s", (rid,))
        assert cur.fetchone()[0] == 1


def test_points_ledger_is_append_only():
    a = _new_account()
    j = _tx(lambda c: pts.earn(c, a, 10, reason_code="invite_reward"))
    with pytest.raises(psycopg.errors.RaiseException):
        with db.conn() as c, c.cursor() as cur:
            cur.execute("UPDATE points_ledger SET delta = delta + 1 WHERE journal_id = %s",
                        (j["journal_id"],))


def test_unknown_action_is_rejected_on_read_path():
    with pytest.raises(pts.UnknownAction):
        pts._check_action("gift")
    # 写入侧也有 DB CHECK 兜底：绕过代码直插未知 action 会失败
    with pytest.raises(psycopg.errors.CheckViolation):
        with db.conn() as c, c.cursor() as cur:
            cur.execute(
                """INSERT INTO points_journal (action, account_id, units, actor)
                   VALUES ('gift', 'system:cop', 1, 'test')""")
    assert pts.ACTIONS == ("earn", "redeem", "adjust", "freeze", "unfreeze", "void", "transfer")
    assert pts.SIX_VALUE_ACTIONS == ("earn", "redeem", "adjust", "freeze", "unfreeze", "void")


def test_no_cash_account_naming_in_source():
    """红线自检：源码里不出现「充值 / 提现 / 余额」这类命名。"""
    banned = ("充值", "提现", "余额")
    source = open(SOURCE, encoding="utf-8").read()
    hits = {word: len(re.findall(word, source)) for word in banned if word in source}
    assert hits == {}, f"app/points.py 出现禁用命名：{hits}"
