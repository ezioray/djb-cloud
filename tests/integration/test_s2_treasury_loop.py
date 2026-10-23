# SPDX-License-Identifier: Apache-2.0
"""S2 资金闭环回归（M08 → M06/M09）：把 runbook 十二步的 Step 3–12 固化成**一条**用例。

只跑这一条（独立 schema，跑完自动 DROP）::

    PYTHONPATH=. python -m pytest tests/integration/test_s2_treasury_loop.py -q

不跑全量：本文件只有一个用例，走 `scripts/s2_treasury_demo.py::run()`（含 001…1403 全链迁移）。

覆盖链条（runbook §2 十二步 / §5 通过判据）：

* Step 3–4：下单 100.00 USD → 签名回调 → credited；4 条回调负例（40910/40911/40001/40401）；
* Step 5–7：E3（1120/2101）→ E4 两步 → E5 两步，五张支付凭证借贷平、1120/1121/1910 归零；
* Step 8：归集 → `sweep.completed` → E9（1102+5102 / 1101+1140）；
* Step 9：attestation 前置 → 分润批次复核 / 2-of-3 签名 / 广播 / settled → E8 四步；
* Step 10：退款 14 天窗口 + 原路 + 双人 24h 冷却 → E11 两步；
* Step 11：daily_close 对账 + 双人 sign-off + attestation + validate（放款闸门）；
* Step 12：verify diff=0 / Σ借=Σ贷 / outbox dead=0 / 回放消费不重复入账；
* 另外 4 条负例（40919 / 40916 / 42210 / 40919）合计 8 条按契约码返回。
"""
from __future__ import annotations

import os
import pathlib
import runpy

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO = ROOT / "scripts" / "s2_treasury_demo.py"

pytestmark = pytest.mark.skipif(
    not os.environ.get("DJB_DSN"),
    reason="需要 DJB_DSN（demo 使用独立 schema，跑完 DROP）",
)


def test_s2_treasury_loop() -> None:
    namespace = runpy.run_path(str(DEMO), run_name="s2_treasury_demo_test")
    summary = namespace["run"]()

    assert summary["ok"] is True
    assert summary["migrations"] >= 40, summary["migrations"]
    assert [item["step"] for item in summary["steps"]] == list(range(13))

    # ── Step 3 / 4：订单 credited + 签名回调 + 负例
    assert summary["steps"][3]["detail"]["status"] == "created"
    assert summary["steps"][4]["detail"]["status"] == "credited"
    assert summary["states"]["order"] == "credited"
    assert summary["outbox"]["by_type"]["payment.paid"]["published"] == 1

    # ── Step 5–7：E3 / E4 两步 / E5 两步
    by_event = summary["journals"]["by_event_type"]
    assert by_event == {"E2": 1, "E3": 1, "E4": 2, "E5": 2, "E8": 4, "E9": 1, "E11": 2}
    assert summary["journals"]["count"] == 13
    assert summary["journals"]["all_balanced"] is True
    assert summary["journals"]["trial"]["debit"] == summary["journals"]["trial"]["credit"] > 0
    assert summary["journals"]["trial"]["diff"] == 0

    # ── 归零：1120 / 1121 / 1910（支付链闭合）+ 1101 / 2201 / 2203
    zero = summary["zero_accounts"]
    for code in ("1101", "1120", "1121", "1910", "2201", "2203"):
        assert zero[code] is True, (code, summary["balances_micro"]["coa"])

    # ── runbook §3 期望余额（micro-USD）
    coa = summary["balances_micro"]["coa"]
    assert coa["1102"] == 14_800_000      # 归集 +50 / 出款 -84.5 / 2c -0.5 / 退款 -50.2
    assert coa["1109"] == -1_700_000      # E4② 1.5 + E5② 0.2 + 2a 0.5 - 2c 0.5
    assert coa["1140"] == -30_000         # 归集 gas 0.03
    assert coa["5102"] == 230_000         # 0.03 + 0.5 - 0.5 + 0.2
    assert coa["5103"] == 1_500_000       # PSP 手续费 1.50
    assert coa["5106"] == 200_000         # 兑换费 0.20
    assert coa["5501"] == 85_000_000      # 分润成本 85.00
    assert summary["balances_micro"]["deviations"] == {}
    # R1：runbook §3 写「acct:<demo> -150M」，但 §20.3.1/§20.3.4 口径下 E11① 借 2101 必须
    # 落在同一主体账户（否则 coa:2101 出现借方余额，违反 I-4）→ 实际 -100M（贷方 150M - 借方 50M）。
    assert summary["balances_micro"]["accounts"]["acct:demo"] == -100_000_000
    assert summary["i4_violations"] == []
    assert summary["payable_total_micro"] == 100_000_000

    # ── Step 8：归集终态 + sweep.completed 已消费
    assert summary["states"]["sweep_transfer"] == "confirmed"
    assert summary["outbox"]["by_type"]["sweep.completed"]["published"] == 1

    # ── Step 9：分润终态 + payout.paid 已消费
    assert summary["states"]["payout_batch"] == "settled"
    assert summary["outbox"]["by_type"]["payout.paid"]["published"] == 1

    # ── Step 10：退款终态 + refund.completed 已消费（含失败退避重试 drill）
    assert summary["states"]["refund"] == "succeeded"
    assert summary["outbox"]["by_type"]["refund.completed"]["published"] == 1
    retry_drill = summary["steps"][10]["detail"]["retry_drill"]
    assert retry_drill["state"] == "pending" and retry_drill["attempts"] == 1

    # ── Step 11：对账 + attestation + validate（放款闸门）
    gate = summary["recon"]["payout_gate"]
    assert gate["attestation"]["valid"] is True
    assert gate["attestation"]["reviewer_id"] == "recon-reviewer"
    assert gate["attestation"]["maker_id"] == "recon-maker"
    assert set(gate["validate"]) <= {"valid", "status", "checked_at", "reasons"}
    final = summary["recon"]["final"]
    assert final["run"]["status"] == "signed_off"
    assert final["run"]["unmatched_count"] == 0
    assert final["attestation"]["valid"] is True

    # ── Step 12：复算 / 发件箱 / 幂等回放
    assert summary["verify"] == {
        "diff": 0, "chain_diff": 0, "balance_diff": 0, "net_minor": 0,
        "journals": 13, "chain_bad": 0, "hash_bad": 0,
    }
    assert summary["outbox"]["dead"] == 0
    assert summary["outbox"]["pending"] == 0
    assert summary["consumer"]["replay_idempotent"] is True
    assert summary["consumer"]["journals_delta_on_replay"] == 0

    # ── 8 条负例按契约码返回（40910 / 40911 / 40001 / 40401 / 40919 / 40916 / 42210 / 40919）
    cases = summary["negative_cases"]
    assert len(cases) == 8
    assert {item["expected"] for item in cases} == {
        40910, 40911, 40001, 40401, 40916, 40919, 42210}
    assert all(item["ok"] and item["actual"] == item["expected"] for item in cases)
    assert [item["case"] for item in cases] == [
        "webhook 金额不符", "webhook 验签失败", "webhook 订单不存在", "webhook 重复回调",
        "出款复核人=制单人", "出款缺 attestation", "出款收款地址未准入", "退款 24h 冷却未到",
    ]
