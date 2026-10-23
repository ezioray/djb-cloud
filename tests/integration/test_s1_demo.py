# SPDX-License-Identifier: Apache-2.0
"""S1 端到端 demo 的可执行断言（独立 schema，结束自动 DROP）。"""
from __future__ import annotations

import os
import pathlib
import runpy

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO = ROOT / "scripts" / "s1_demo.py"


pytestmark = pytest.mark.skipif(
    not os.environ.get("DJB_DSN"),
    reason="需要 DJB_DSN（demo 使用独立 schema，跑完 DROP）",
)


def test_s1_end_to_end_request_receipt_ledger() -> None:
    namespace = runpy.run_path(str(DEMO), run_name="s1_demo_test")
    summary = namespace["run"]()

    assert summary["receipt_dual_signature"] is True
    assert summary["idempotent_replay"] is True
    assert summary["usage_count"] == 1
    assert summary["amount_minor"] > 0
    assert summary["amount_micro"] == summary["amount_minor"] * 10_000
    assert summary["journal_event_type"] == "E6"
    assert summary["journal_balanced"]["debit"] == summary["journal_balanced"]["credit"]
    assert summary["journal_balanced"]["debit"] == summary["amount_micro"]
    assert summary["recompute_diff"] == 0
    assert summary["chain"]["diff"] == 0
    assert summary["balances"]["diff"] == 0
    assert summary["topup_amount_minor"] == 1000
    assert summary["balance_2101_normal_minor"] == 100
    assert summary["balance_2101_normal_minor"] >= 0
    assert summary["i4_violations"] == 0
    for event_type in ("receipt.signed", "usage.recorded", "usage.settled"):
        assert summary["events"].get(event_type, 0) >= 1
    assert set(summary["published"]) >= {"receipt.signed", "usage.recorded", "usage.settled"}
