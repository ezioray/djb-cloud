# SPDX-License-Identifier: AGPL-3.0-or-later
"""DEV-0001 钱包池自动扩容（§19.4.3 / §19.4.10，决策 K5）。

覆盖：14 天滚动预测与 2× 目标、>60% 预生成、min_spare、池空不停收款、批次 24h 过期作废、
批次不夹带转账、并发幂等、2/3 签激活≠可用、max_active 只自动上调、预测为 0、
批次失败地址不复用、账本零改动。

数据库：用 `DJB_DSN` 指向的开发库；库不可达时整文件 skip（本地不阻断）。
"""
from __future__ import annotations

import os
import pathlib
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app import db
from app import wallet_pool as wp
from app.config import dsn

MIGRATION = pathlib.Path(__file__).resolve().parents[1] / "migrations" / "004_wallet_pool.sql"
POOL = wp.POOL_ID_CUSTOMER_HOT           # polygon:hot:customer
NOW = datetime(2026, 10, 20, 4, 0, tzinfo=timezone.utc)
STEADY = [10_000] * 14                   # 每天 100 USD


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
        conn.execute(MIGRATION.read_text(encoding="utf-8"))


@pytest.fixture()
def clean():
    """每个用例从「一期 3 池、零钱包」的干净状态开始（只动钱包池表，不碰账本）。"""
    with db.conn() as c:
        with c.cursor() as cur:
            cur.execute("TRUNCATE wallet_pool_event, wallet_activation, wallet_provision_batch, "
                        "wallet, wallet_pool RESTART IDENTITY CASCADE")
        wp.ensure_pools(c)
    yield


def _add_wallets(pool_id=POOL, n=0, *, status="active", gas_ok=True, balance_minor=0,
                 switch_state="standby") -> list[str]:
    role, fund_class = pool_id.split(":")[1], pool_id.split(":")[2]
    ids = []
    with db.conn() as c, c.cursor() as cur:
        for i in range(n):
            wid = f"{pool_id}-w{i}-{secrets.token_hex(4)}"
            cur.execute(
                """INSERT INTO wallet (wallet_id, chain_id, address, pool_id, pool_role, fund_class,
                                       custody_kind, status, switch_state, balance_minor, gas_ok)
                   VALUES (%s,'polygon',%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (wid, "0x" + secrets.token_hex(20), pool_id, role, fund_class,
                 "self_custody_hot" if role == "hot" else "self_custody_warm",
                 status, switch_state if status == "active" else None,
                 balance_minor, gas_ok),
            )
            ids.append(wid)
    return ids


def _run(daily=STEADY, *, pool_id=POOL, now=NOW, **kw):
    with db.conn() as c:
        return wp.run_expansion(c, pool_id, daily, now=now, **kw)


def _batch_rows():
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT batch_id, status, wallet_count, expires_at, contains_transfer, nonce "
                    "FROM wallet_provision_batch ORDER BY created_at")
        return cur.fetchall()


# --------------------------------------------------------------------------- ① 预测 / 2×
def test_forecast_is_14_day_rolling_and_target_is_2x():
    fc = wp.rolling_forecast(STEADY)
    assert fc.source == "rolling_14d" and fc.history_days == 14
    assert fc.predicted_minor == 70_000          # 100 USD/天 × 7 天

    # 只取最近 14 天：前 6 天的异常高值不进窗口
    history = [10 ** 7] * 6 + STEADY
    assert wp.rolling_forecast(history).predicted_minor == 70_000

    snap = wp.PoolSnapshot(POOL, "hot", 8, 3, 4, 70, wp.POOL_CAP_USD_MINOR)
    cap = wp.cap_per_wallet_minor(snap, fc)
    assert cap == 50_000                          # min(10,000 USD, 5 天预测 500 USD)
    assert wp.target_active_wallets(fc, cap) == 3  # ceil(2 × 700 USD / 500 USD)
    # 目标容量 ≥2× 7 天预测
    assert wp.target_active_wallets(fc, cap) * cap >= 2 * fc.predicted_minor


def test_forecast_anomaly_and_insufficient_history_fall_back_to_actual():
    collapse = [100_000] * 7 + [1_000] * 7        # 断崖：前 7 天 vs 近 7 天 >3 倍
    fc = wp.rolling_forecast(collapse)
    assert fc.anomaly is True and fc.source == "fallback_trailing_7d"
    assert fc.predicted_minor == 7_000            # 近 7 天实测兜底

    short = wp.rolling_forecast([10_000, 10_000])
    assert short.source == "fallback_trailing_7d" and short.predicted_minor == 20_000

    empty = wp.rolling_forecast([])
    assert empty.source == "no_data" and empty.predicted_minor == 0


def test_cap_is_lowered_by_pool_cap_but_not_below_floor():
    fc = wp.rolling_forecast(STEADY)
    # 池上限压到 1,200 USD、在用 3 只 → 每只 400 USD，触发「不低于 1,000 USD」下限
    tiny = wp.PoolSnapshot(POOL, "hot", 8, 3, 4, 70, 120_000, active_count=3)
    assert wp.cap_per_wallet_minor(tiny, fc) == wp.MIN_WALLET_CAP_MINOR


# --------------------------------------------------------------------------- 决策表
def test_expansion_when_target_above_current_slots(clean):
    # 3 只可用 + 预测 3,500 USD/7天；单钱包 cap 触到 10,000 USD 硬顶 → 目标 7 只 > 现有 3 只
    _add_wallets(n=3, switch_state="in_service", balance_minor=0)
    res = _run([500_000] * 14, flag=True)
    assert res["reason"] == "forecast_2x_target"
    assert res["plan"]["target_wallets"] == 7 and res["batch"]["wallet_count"] == 4
    assert res["plan"]["stop_collection"] is False


def test_utilization_above_60pct_pre_generates_before_hitting_ceiling(clean):
    # 4 只在用、每只余额 30% cap；叠加 7 天预测后利用率 65% > 60% → 不等触顶，预生成
    _add_wallets(n=4, switch_state="in_service", balance_minor=1_200_000)
    res = _run([200_000] * 14, flag=True)
    assert res["plan"]["projected_utilization_pct"] > wp.UTILIZATION_PREGEN_PCT
    assert res["action"] == "provision"
    assert res["batch"]["wallet_count"] == wp.ACTIVATE_BATCH_SIZE


def test_min_spare_shortfall_and_forecast_zero(clean):
    # min_spare = 3：只有 2 只可用 → 补 1 只
    res = _run(flag=True)
    assert res["reason"] == "pool_empty_urgent" and res["batch"]["wallet_count"] == 4

    # 预测为 0（无历史）：池深够 → 不按 2× 扩容，只维持 min_spare 底线
    with db.conn() as c, c.cursor() as cur:
        cur.execute("TRUNCATE wallet_activation, wallet_provision_batch, wallet CASCADE")
    _add_wallets(n=3)
    res = _run([], flag=True, now=NOW + timedelta(hours=1))
    assert res["action"] == "no_action" and res["reason"] == "forecast_no_data"

    with db.conn() as c, c.cursor() as cur:
        cur.execute("TRUNCATE wallet_activation, wallet_provision_batch, wallet CASCADE")
    _add_wallets(n=1)
    res = _run([], flag=True, now=NOW + timedelta(hours=2))
    assert res["reason"] == "min_spare_floor_no_forecast" and res["batch"]["wallet_count"] == 2


def test_pool_empty_keeps_collecting_and_spreads(clean):
    _add_wallets(n=2, switch_state="in_service", balance_minor=0, gas_ok=False)
    res = _run(flag=True)
    assert res["reason"] == "pool_empty_urgent" and res["plan"]["p_level"] == "P0"
    # 池空不得停收款：先摊量到现有钱包，同时自动扩容
    assert res["plan"]["new_address_allocation"] == "spread_existing"
    assert res["plan"]["stop_collection"] is False


def test_max_active_auto_up_by_4_up_to_hard_cap(clean):
    # 8 只在用（已在 max_active=8 上限），利用率 68.75% > 60% → 需要再加一批
    _add_wallets(n=8, switch_state="in_service", balance_minor=250_000)

    # 开关关闭：触顶只报人工复核，仍继续摊量，不停收款
    res = _run([500_000] * 14, flag=True, auto_max_active=False)
    assert res["action"] == "no_action" and res["reason"] == "max_active_reached"
    assert res["plan"]["needs_manual_review"] is True
    assert res["plan"]["new_address_allocation"] == "spread_existing"
    assert res["plan"]["stop_collection"] is False

    # 开关打开：+4 → 12，并建一批
    res = _run([500_000] * 14, flag=True, auto_max_active=True, now=NOW + timedelta(hours=1))
    assert res["action"] == "provision"
    assert (res["plan"]["max_active_before"], res["plan"]["max_active_after"]) == (8, 12)
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT max_active_count FROM wallet_pool WHERE pool_id = %s", (POOL,))
        assert cur.fetchone()[0] == 12

    # 已到硬顶 20：反复上调也不会越过 20（纯函数判定，避免依赖库内状态）
    cap_snap = wp.PoolSnapshot(POOL, "hot", 20, 3, 4, 70, wp.POOL_CAP_USD_MINOR,
                               active_count=20, ready_count=20, in_use_balance_minor=19_000_000)
    plan = wp.plan_expansion(cap_snap, wp.rolling_forecast([500_000] * 14),
                             flag_enabled=True, auto_max_active=True)
    assert wp.MAX_ACTIVE_HARD_CAP == 20
    assert plan.max_active_after == 20 and plan.action == "no_action"
    assert plan.needs_manual_review is True


def test_never_shrinks_automatically(clean):
    _add_wallets(n=6, switch_state="in_service", balance_minor=0)
    res = _run(STEADY, flag=True)
    assert res["action"] == "no_action"
    assert res["reason"] == "shrink_needs_manual_review" and res["plan"]["needs_manual_review"]


# --------------------------------------------------------------------------- ③ 批次过期 / 不夹带转账
def test_batch_expires_after_24h_and_is_voided(clean):
    res = _run(flag=True)
    batch_id = res["batch"]["batch_id"]
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT created_at, expires_at FROM wallet_provision_batch WHERE batch_id = %s",
                    (batch_id,))
        c_at, e_at = cur.fetchone()
    assert e_at - c_at == timedelta(hours=wp.BATCH_TTL_H) <= timedelta(hours=24)

    # 24h 内可签；超过 24h 直接作废
    with db.conn() as c:
        expired = wp.expire_batches(c, now=NOW + timedelta(hours=25))
    assert expired == [batch_id]

    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM wallet_provision_batch WHERE batch_id = %s", (batch_id,))
        assert cur.fetchone()[0] == "expired"
        cur.execute("SELECT COUNT(*) FROM wallet WHERE status = 'provisioning_failed'")
        assert cur.fetchone()[0] == wp.ACTIVATE_BATCH_SIZE
        cur.execute("SELECT COUNT(*) FROM wallet_activation WHERE status = 'void'")
        assert cur.fetchone()[0] == wp.ACTIVATE_BATCH_SIZE

    # 过期批次不能再签（需重新生成描述符）
    with db.conn() as c:
        with pytest.raises(wp.BatchExpired):
            wp.activate_batch(c, batch_id, owner_signed_at=NOW, reviewer_attested_at=NOW,
                              hsm_verified_at=NOW, now=NOW + timedelta(hours=26))


def test_provision_batch_rejects_transfer_instructions():
    base = {"wallet_id": "w1", "chain_id": "polygon", "address": "0xa", "address_source": "hsm_derived",
            "role": "hot", "fund_class": "customer", "signer_set_ref": "s", "threshold": 2,
            "signers_total": 3, "cap_applied_minor": 100000}
    wp.assert_no_transfer([base])                       # 干净描述符通过

    for bad in ({"amount": 100}, {"to_address": "0xdead"}, {"transfers": []}, {"raw_tx": "0x01"}):
        with pytest.raises(wp.TransferNotAllowed):
            wp.assert_no_transfer([{**base, **bad}])


def test_merkle_root_is_deterministic_and_order_sensitive():
    a = {"wallet_id": "w1", "address": "0xa"}
    b = {"wallet_id": "w2", "address": "0xb"}
    ra = wp.merkle_root([wp.descriptor_hash(a), wp.descriptor_hash(b)])
    rb = wp.merkle_root([wp.descriptor_hash(b), wp.descriptor_hash(a)])
    assert ra.startswith("sha256:") and len(ra) == 71
    assert ra == wp.merkle_root([wp.descriptor_hash(a), wp.descriptor_hash(b)])
    # 单只批次与多只批次不同根
    assert ra != wp.merkle_root([wp.descriptor_hash(a)])


# --------------------------------------------------------------------------- ④ 并发幂等
def test_concurrent_expansion_creates_exactly_one_batch(clean):
    results: list = [None] * 4

    def worker(idx: int) -> None:
        try:
            with db.conn() as c:
                results[idx] = wp.run_expansion(c, POOL, STEADY, now=NOW, flag=True)
        except Exception as exc:              # noqa: BLE001 - 线程内异常要带回主线程断言
            results[idx] = exc

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(worker, range(4)))

    for r in results:
        assert not isinstance(r, Exception), r
    rows = _batch_rows()
    assert len(rows) == 1, rows
    assert rows[0][2] == wp.ACTIVATE_BATCH_SIZE
    assert sum(1 for r in results if r["batch"] and r["batch"].get("created")) == 1
    created_actions = [r for r in results if r["action"] == "provision"]
    assert len(created_actions) == 1
    # 其余请求看到在签批次 → 幂等抑制
    assert {r["reason"] for r in results if r["action"] == "no_action"} <= {
        "batch_pending_sign", "capacity_sufficient"}


def test_second_run_is_idempotent_while_batch_pending(clean):
    first = _run(flag=True)
    assert first["batch"]["created"] is True
    second = _run(STEADY, flag=True, now=NOW + timedelta(minutes=5))
    assert second["action"] == "no_action" and second["reason"] == "batch_pending_sign"
    assert second["batch"]["batch_id"] == first["batch"]["batch_id"]
    assert len(_batch_rows()) == 1


# --------------------------------------------------------------------------- 激活：2/3 签、激活≠可用
def test_activation_requires_2of3_and_is_not_availability(clean):
    batch_id = _run(flag=True)["batch"]["batch_id"]

    with db.conn() as c:
        with pytest.raises(wp.SignatureIncomplete):
            wp.activate_batch(c, batch_id, owner_signed_at=NOW, now=NOW)

    with db.conn() as c:
        out = wp.activate_batch(c, batch_id, owner_signed_at=NOW,
                                reviewer_attested_at=NOW, hsm_verified_at=NOW, now=NOW)
    assert len(out["activated"]) == wp.ACTIVATE_BATCH_SIZE and out["already"] is False
    assert out["auth_hash"].startswith("sha256:")

    # 激活 ≠ 可用：gas 未到位 → depth_ready 仍为 0
    with db.conn() as c:
        snap = wp.load_snapshot(c, POOL)
    assert snap.active_count == 4 and snap.ready_count == 0 and snap.depth_available == 0

    with db.conn() as c, c.cursor() as cur:
        cur.execute("UPDATE wallet SET gas_ok = TRUE, switch_state = 'in_service' WHERE pool_id = %s",
                    (POOL,))
    with db.conn() as c:
        snap = wp.load_snapshot(c, POOL)
    assert snap.ready_count == 4 and snap.depth_available == 4

    # 重复激活幂等
    with db.conn() as c:
        again = wp.activate_batch(c, batch_id, owner_signed_at=NOW, reviewer_attested_at=NOW,
                                  hsm_verified_at=NOW, now=NOW)
    assert again["already"] is True and len(again["activated"]) == 4


# --------------------------------------------------------------------------- ⑤ 批次失败
def test_failed_batch_voids_wallets_and_addresses_are_not_reused(clean):
    first = _run(flag=True)
    batch_id, addrs = first["batch"]["batch_id"], [d["address"] for d in first["batch"]["descriptors"]]
    with db.conn() as c:
        out = wp.fail_batch(c, batch_id, "HSM 派生失败", now=NOW)
    assert out["status"] == "failed"

    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM wallet WHERE status = 'provisioning_failed'")
        assert cur.fetchone()[0] == 4
    with db.conn() as c:
        with pytest.raises(wp.BatchExpired):
            wp.activate_batch(c, batch_id, owner_signed_at=NOW, reviewer_attested_at=NOW,
                              hsm_verified_at=NOW, now=NOW + timedelta(minutes=1))

    # 重新扩容：旧地址不复用，新批次新地址
    second = _run(STEADY, flag=True, now=NOW + timedelta(minutes=2))
    new_addrs = [d["address"] for d in second["batch"]["descriptors"]]
    assert second["batch"]["created"] is True and not set(new_addrs) & set(addrs)
    assert second["batch"]["nonce"] > first["batch"]["nonce"]      # nonce 单调


# --------------------------------------------------------------------------- ⑥ 账本零改动 / 开关
def test_ledger_is_untouched_by_expansion(clean):
    with db.conn() as c:
        before = wp.ledger_fingerprint(c)
    assert before["recompute_diff"] == 0

    res = _run(flag=True)
    with db.conn() as c:
        wp.activate_batch(c, res["batch"]["batch_id"], owner_signed_at=NOW,
                          reviewer_attested_at=NOW, hsm_verified_at=NOW, now=NOW)
        after = wp.ledger_fingerprint(c)

    assert after == before, (before, after)
    assert after["recompute_diff"] == 0


def test_feature_flag_defaults_to_off(clean, monkeypatch):
    monkeypatch.delenv(wp.FEATURE_FLAGS["wallet_pool_v2"].env_var, raising=False)
    monkeypatch.setenv("DJB_ENV", "dev")
    assert wp.flag_enabled("wallet_pool_v2") is False

    res = _run(flag=None)                     # 不显式覆盖 → 走开关（关闭）
    assert res["action"] == "no_action" and res["reason"] == "flag_disabled"
    assert _batch_rows() == []


def test_feature_flag_declares_three_required_fields():
    for flag in wp.FEATURE_FLAGS.values():
        assert flag.owner and flag.expire_at and flag.rollback_rule
        assert flag.default is False


# --------------------------------------------------------------------------- 结构不变量
def test_phase1_has_three_pools_and_no_platform_hot(clean):
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT pool_id, role, fund_class, min_spare_count, max_active_count, "
                    "switch_threshold_pct, activate_batch_size, provision_lead_time_h, pool_cap_minor "
                    "FROM wallet_pool ORDER BY pool_id")
        rows = cur.fetchall()
    assert [r[0] for r in rows] == list(wp.PHASE1_POOL_IDS)
    assert wp.POOL_ID_PLATFORM_HOT not in {r[0] for r in rows}
    by_id = {r[0]: r for r in rows}
    hot, warm = by_id[wp.POOL_ID_CUSTOMER_HOT], by_id[wp.POOL_ID_CUSTOMER_WARM]
    assert (hot[3], hot[4], hot[5], hot[6], hot[7]) == (3, 8, 70, 4, 12)
    assert (warm[3], warm[4], warm[5], warm[6], warm[7]) == (3, 4, 70, 4, 12)
    assert hot[8] == wp.POOL_CAP_USD_MINOR


def test_wallet_pool_binding_is_immutable(clean):
    wid = _add_wallets(pool_id=wp.POOL_ID_CUSTOMER_WARM, n=1)[0]
    with db.conn() as c:
        with pytest.raises(psycopg.errors.RaiseException):
            with c.cursor() as cur:
                cur.execute("UPDATE wallet SET pool_id = %s WHERE wallet_id = %s", (POOL, wid))


def test_invariants_are_clean_after_a_full_cycle(clean):
    res = _run(flag=True)
    with db.conn() as c:
        wp.activate_batch(c, res["batch"]["batch_id"], owner_signed_at=NOW,
                          reviewer_attested_at=NOW, hsm_verified_at=NOW, now=NOW)
        with c.cursor() as cur:
            cur.execute("UPDATE wallet SET gas_ok = TRUE WHERE pool_id = %s", (POOL,))
        report = wp.check_invariants(c)
    assert report["problems"] == [] and report["pools"] == 3
