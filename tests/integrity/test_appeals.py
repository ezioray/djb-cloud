# SPDX-License-Identifier: AGPL-3.0-or-later
"""C14 申诉通道 + M08 扣留桥用例（M17 §6.1，S2 只冻结不罚没）。

覆盖：7 天窗口（边界 / 过期）/ 一条 hold 仅一次申诉 / uphold 保持 active /
release 复用双人复核与高级别 scope（不能绕过）/ 申诉到期翻状态 / 账本 diff=0 /
开关关闭 fail-closed；M08 扣留预览默认关闭、开启后 min(冻结, 应付)。
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.integrity import facts, holds
from app.integrity.errors import Conflict, FeatureUnavailable, Forbidden
from app.treasury import withholding

from kit import hold_args, ledger_snapshot

NODE = "node-alpha"
MODEL = "openai/gpt-4o"
BEFORE_TABLES = ("supplier_integrity_holds", "supplier_integrity_appeals")


def _hold(conn, now, *, level="I2"):
    return holds.create_or_escalate(conn, **hold_args(level=level), now=now)["hold"]


def _appeal(conn, hold, now, *, reason="判定依据有误，申请复核"):
    return holds.submit_appeal(conn, hold["id"], appellant="node-alpha",
                               reason=reason, now=now)["appeal"]


def _count(conn, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


# ───────────────────────────────────────────────────────── 提交 / 窗口
def test_submit_appeal_keeps_hold_active_and_ledger_untouched(conn, now, feature_on):
    hold = _hold(conn, now)
    before = ledger_snapshot(conn, ("ledger_entries",))
    result = holds.submit_appeal(conn, hold["id"], appellant="node-alpha",
                                 reason="判定依据有误，申请复核", now=now)
    assert result["action"] == "appealed"
    appeal = result["appeal"]
    assert appeal["state"] == "open"
    deadline = datetime.fromisoformat(appeal["deadline_at"])
    created = datetime.fromisoformat(hold["created_at"])
    assert deadline - created == timedelta(days=7)
    assert appeal["hold_id"] == hold["id"]
    assert holds.get_hold(conn, hold["id"])["state"] == "active"
    assert _count(conn, "supplier_integrity_appeals") == 1
    # 1910 事件表不因申诉而变化（枚举保持原样）
    assert _count(conn, "supplier_integrity_events") == 1
    assert ledger_snapshot(conn, ("ledger_entries",)) == before


def test_appeal_window_is_seven_days(conn, now, feature_on):
    hold = _hold(conn, now, level="I2")
    edge = now + timedelta(days=7)
    appeal = _appeal(conn, hold, edge)
    assert appeal["state"] == "open"

    other = holds.create_or_escalate(conn, **hold_args(node_id="node-beta", level="I2"),
                                     now=now)["hold"]
    late = now + timedelta(days=7, seconds=1)
    with pytest.raises(Conflict) as excinfo:
        holds.submit_appeal(conn, other["id"], appellant="node-beta", reason="太晚了",
                            now=late)
    assert excinfo.value.reason == "appeal_window_closed"


def test_second_appeal_is_rejected(conn, now, feature_on):
    hold = _hold(conn, now)
    _appeal(conn, hold, now)
    with pytest.raises(Conflict) as excinfo:
        _appeal(conn, hold, now + timedelta(hours=1))
    assert excinfo.value.reason == "appeal_exists"


def test_released_hold_cannot_be_appealed(conn, now, feature_on):
    hold = _hold(conn, now, level="I1")
    holds.release(conn, hold["id"], reviewers=["checker"], reason="误判", actor="checker",
                  now=now + timedelta(hours=1))
    with pytest.raises(Conflict) as excinfo:
        _appeal(conn, hold, now + timedelta(hours=2))
    assert excinfo.value.reason == "hold_not_active"


# ───────────────────────────────────────────────────────── 复核
def test_uphold_keeps_hold_active(conn, now, feature_on):
    hold = _hold(conn, now)
    appeal = _appeal(conn, hold, now)
    result = holds.review_appeal(conn, appeal["id"], decision="uphold",
                                 reviewers=["reviewer-a"], reason="证据充分，维持",
                                 actor="reviewer-a", now=now + timedelta(days=1))
    assert result["action"] == "upheld"
    assert result["appeal"]["state"] == "upheld"
    assert result["appeal"]["resolution"] == "upheld"
    assert result["hold"]["state"] == "active"


def test_release_via_appeal_reuses_two_reviewer_rule(conn, now, feature_on):
    hold = _hold(conn, now, level="I2")
    appeal = _appeal(conn, hold, now)
    with pytest.raises(Conflict) as excinfo:
        holds.review_appeal(conn, appeal["id"], decision="release",
                            reviewers=["only-one"], reason="误判", actor="only-one",
                            now=now + timedelta(days=1))
    assert excinfo.value.reason == "reviewers_insufficient"

    result = holds.review_appeal(conn, appeal["id"], decision="release",
                                 reviewers=["reviewer-a", "reviewer-b"],
                                 reason="复核确认误判", actor="reviewer-a",
                                 now=now + timedelta(days=1))
    assert result["action"] == "released"
    assert result["hold"]["state"] == "released"
    assert result["appeal"]["state"] == "released"
    assert _count(conn, "supplier_integrity_appeals") == 1


def test_high_level_appeal_release_needs_scope(conn, now, feature_on):
    hold = _hold(conn, now, level="I3")
    appeal = _appeal(conn, hold, now)
    with pytest.raises(Forbidden) as excinfo:
        holds.review_appeal(conn, appeal["id"], decision="release",
                            reviewers=["reviewer-a", "reviewer-b"], reason="误判",
                            actor="reviewer-a", now=now + timedelta(days=1))
    assert excinfo.value.reason == "scope_required"

    result = holds.review_appeal(conn, appeal["id"], decision="release",
                                 reviewers=["reviewer-a", "reviewer-b"], reason="误判",
                                 actor="reviewer-a", now=now + timedelta(days=1),
                                 scopes=[facts.HIGH_RELEASE_SCOPE])
    assert result["hold"]["state"] == "released"


def test_review_after_window_is_rejected(conn, now, feature_on):
    hold = _hold(conn, now)
    appeal = _appeal(conn, hold, now)
    with pytest.raises(Conflict) as excinfo:
        holds.review_appeal(conn, appeal["id"], decision="uphold",
                            reviewers=["reviewer-a"], reason="迟到的复核",
                            actor="reviewer-a", now=now + timedelta(days=8))
    assert excinfo.value.reason == "appeal_window_closed"


def test_expire_appeals_flips_only_appeal_state(conn, now, feature_on):
    hold = _hold(conn, now)
    appeal = _appeal(conn, hold, now)
    expired = holds.expire_appeals(conn, now + timedelta(days=8))
    assert [item["id"] for item in expired] == [appeal["id"]]
    assert expired[0]["state"] == "expired"
    assert holds.get_hold(conn, hold["id"])["state"] == "active"
    assert holds.appeal_of(conn, hold["id"])["state"] == "expired"


def test_feature_off_blocks_appeal_but_reads_work(conn, now, monkeypatch):
    monkeypatch.delenv("DJB_INTEGRITY_FREEZE", raising=False)
    with pytest.raises(FeatureUnavailable):
        holds.submit_appeal(conn, "00000000-0000-7000-8000-000000000000",
                            appellant="node-alpha", reason="x", now=now)


# ───────────────────────────────────────────────────────── M08 扣留桥
def test_withholding_default_off(conn, now, feature_on, monkeypatch):
    monkeypatch.delenv(withholding.ENV_SWITCH, raising=False)
    hold = _hold(conn, now, level="I2")          # 冻结 80 万 micro
    result = withholding.preview(conn, node_id=NODE, gross_micro=1_000_000, now=now)
    assert result == {"enabled": False, "withheld_micro": 0,
                      "payable_micro": 1_000_000, "hold_ids": []}
    assert hold["frozen_amount_micro"] == 800_000


def test_withholding_caps_at_gross_and_never_writes(conn, now, feature_on, monkeypatch):
    monkeypatch.setenv(withholding.ENV_SWITCH, "1")
    hold = _hold(conn, now, level="I3")          # 100% = 100 万
    before = ledger_snapshot(conn, ("ledger_entries",))
    result = withholding.preview(conn, node_id=NODE, gross_micro=600_000, now=now)
    assert result["enabled"] is True
    assert result["withheld_micro"] == 600_000        # min(冻结, 应付)
    assert result["payable_micro"] == 0
    assert result["hold_ids"] == [hold["id"]]
    assert ledger_snapshot(conn, ("ledger_entries",)) == before

    batch = withholding.apply_to_items(
        conn, [{"payee_account_id": NODE, "gross_micro": 2_000_000}], now=now)
    assert batch[0]["withholding"]["withheld_micro"] == 1_000_000
    assert batch[0]["withholding"]["payable_micro"] == 1_000_000


def test_withholding_flag_has_three_fields():
    spec = withholding.flag_spec()
    assert spec["owner"] and spec["expire_at"] and spec["rollback_rule"]
    assert spec["default"] is False


def test_withholding_module_has_no_ledger_write():
    import inspect
    source = inspect.getsource(withholding).split('"""', 2)[-1]
    for token in ("INSERT INTO ledger", "UPDATE ledger"):
        assert token not in source
