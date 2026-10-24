# SPDX-License-Identifier: AGPL-3.0-or-later
"""C14 待分润冻结服务用例（M17 §6.1，S2 只冻结不罚没）。

覆盖：等级比例 / 金额取整 / I0 不建 hold / I1 7 天到期 / I2 80% / I3=I4=100% /
只升不降 / active 唯一 / 双人复核（同人拒绝、人数不足拒绝）/ I3 scope 校验 /
release 幂等 / 账本前后 diff=0 / 开关关闭 fail-closed。
"""
from __future__ import annotations

from datetime import timedelta

import psycopg
import pytest

from app.integrity import facts, features, holds, models
from app.integrity.errors import BadRequest, Conflict, FeatureUnavailable, Forbidden, NotFound

from kit import FIXED_NOW, hold_args, ledger_snapshot

NODE = "node-alpha"
MODEL = "openai/gpt-4o"


def _count(conn, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


# ───────────────────────────────────────────────────────── 比例 / 金额
def test_level_ratio_table_matches_decision():
    assert facts.LEVEL_RATIO_BP == {"I0": 0, "I1": 5000, "I2": 8000, "I3": 10000, "I4": 10000}
    assert facts.REVIEWERS_REQUIRED == {"I0": 1, "I1": 1, "I2": 2, "I3": 2, "I4": 2}
    assert facts.HIGH_LEVELS == ("I3", "I4")
    assert facts.I1_TTL == timedelta(days=7)


def test_frozen_amount_uses_integer_floor():
    assert holds.frozen_amount(1_000_000, 5000) == 500_000
    assert holds.frozen_amount(999_999, 5000) == 499_999      # 499999.5 → 向下取整
    assert holds.frozen_amount(999_999, 8000) == 799_999      # 799999.2 → 向下取整
    assert holds.frozen_amount(1, 10000) == 1
    assert holds.frozen_amount(0, 10000) == 0
    with pytest.raises(ValueError):
        holds.frozen_amount(-1, 5000)


def test_level_normalisation():
    assert models.normalize_level(" i2 ") == "I2"
    with pytest.raises(BadRequest):
        models.normalize_level("I9")
    with pytest.raises(BadRequest):
        models.normalize_level(None)


# ───────────────────────────────────────────────────────── I0 / 创建
def test_i0_creates_no_hold_but_records_event(conn, now, feature_on):
    result = holds.create_or_escalate(conn, **hold_args(level="I0"), now=now)
    assert result["action"] == "noted"
    assert result["hold"] is None
    assert result["event"]["event"] == "created"
    assert result["event"]["to_level"] == "I0"
    assert result["event"]["hold_id"] is None
    assert _count(conn, "supplier_integrity_holds") == 0
    assert _count(conn, "supplier_integrity_events") == 1


def test_i1_hold_half_ratio_with_seven_day_expiry(conn, now, feature_on):
    result = holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)
    hold = result["hold"]
    assert result["action"] == "created"
    assert hold["state"] == "active"
    assert hold["ratio_bp"] == 5000
    assert hold["frozen_amount_micro"] == 500_000
    assert hold["version"] == 1
    expires = conn.execute(
        "SELECT expires_at FROM supplier_integrity_holds WHERE id = %s",
        (hold["id"],)).fetchone()[0]
    assert expires - now == timedelta(days=7)
    assert result["event"]["event"] == "created"
    assert result["event"]["to_level"] == "I1"


def test_i2_hold_eighty_percent_without_expiry(conn, now, feature_on):
    hold = holds.create_or_escalate(conn, **hold_args(level="I2"), now=now)["hold"]
    assert hold["ratio_bp"] == 8000
    assert hold["frozen_amount_micro"] == 800_000
    assert hold["expires_at"] is None


@pytest.mark.parametrize("level,ratio", [("I3", 10000), ("I4", 10000)])
def test_i3_i4_full_ratio(conn, now, feature_on, level, ratio):
    hold = holds.create_or_escalate(conn, **hold_args(level=level), now=now)["hold"]
    assert hold["ratio_bp"] == ratio
    assert hold["frozen_amount_micro"] == 1_000_000
    assert hold["expires_at"] is None


# ───────────────────────────────────────────────────────── 升级 / 唯一
def test_escalation_updates_same_row_and_keeps_single_active(conn, now, feature_on):
    first = holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)["hold"]
    second = holds.create_or_escalate(
        conn, **hold_args(level="I3", base_amount_micro=2_000_000), now=now)
    hold = second["hold"]
    assert second["action"] == "escalated"
    assert hold["id"] == first["id"]
    assert hold["version"] == 2
    assert hold["level"] == "I3"
    assert hold["ratio_bp"] == 10000
    assert hold["frozen_amount_micro"] == 2_000_000
    assert hold["expires_at"] is None                       # I1 → I3 去掉自动到期
    assert _count(conn, "supplier_integrity_holds") == 1    # 不新建第二条
    events = conn.execute(
        "SELECT event, from_level, to_level FROM supplier_integrity_events"
        " ORDER BY event").fetchall()
    assert [tuple(row) for row in events] == [("created", None, "I1"),
                                             ("escalated", "I1", "I3")]


def test_same_level_is_not_escalation(conn, now, feature_on):
    holds.create_or_escalate(conn, **hold_args(level="I2"), now=now)
    with pytest.raises(Conflict) as excinfo:
        holds.create_or_escalate(conn, **hold_args(level="I2"), now=now)
    assert excinfo.value.code == 40919
    assert excinfo.value.reason == "not_escalation"


def test_downgrade_is_rejected_and_row_unchanged(conn, now, feature_on):
    created = holds.create_or_escalate(conn, **hold_args(level="I3"), now=now)["hold"]
    with pytest.raises(Conflict) as excinfo:
        holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)
    assert excinfo.value.reason == "downgrade_rejected"
    row = conn.execute("SELECT level, version FROM supplier_integrity_holds").fetchone()
    assert tuple(row) == ("I3", 1)
    assert created["id"]


def test_partial_unique_index_blocks_second_active(conn, now, feature_on):
    holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.transaction():
            conn.execute(
                """
                INSERT INTO supplier_integrity_holds
                  (id, node_id, upstream_id, model, level, ratio_bp, base_amount_micro,
                   frozen_amount_micro, state, reason, evidence_ref, created_at, expires_at)
                VALUES (gen_random_uuid(), %s, NULL, %s, 'I2', 8000, 1000, 800, 'active',
                        'duplicate', 'risk-case-2', now(), NULL)
                """, (NODE, MODEL))


# ───────────────────────────────────────────────────────── 到期
def test_i1_expiry_flips_state_and_frees_the_slot(conn, now, feature_on):
    first = holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)["hold"]
    later = now + timedelta(days=7, seconds=1)
    expired = holds.expire_due(conn, now=later)
    assert [item["id"] for item in expired] == [first["id"]]
    assert expired[0]["state"] == "expired"
    assert holds.is_frozen(conn, NODE, MODEL, now=later) is False
    assert holds.frozen_total(conn, NODE, now=later) == 0
    events = conn.execute(
        "SELECT event FROM supplier_integrity_events ORDER BY event").fetchall()
    assert [row[0] for row in events] == ["created", "expired"]
    # 到期后同一 (node, model) 可以重建冻结（部分唯一索引只看 active）
    again = holds.create_or_escalate(conn, **hold_args(level="I1"), now=later)
    assert again["action"] == "created"
    assert again["hold"]["id"] != first["id"]
    assert holds.is_frozen(conn, NODE, MODEL, now=later) is True


def test_release_on_expired_hold_conflicts(conn, now, feature_on):
    hold = holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)["hold"]
    later = now + timedelta(days=7, seconds=1)
    holds.expire_due(conn, now=later)
    with pytest.raises(Conflict) as excinfo:
        holds.release(conn, hold["id"], reviewers=["rev-1"], reason="too late",
                      actor="risk-1", now=later)
    assert excinfo.value.reason == "hold_expired"


def test_expire_due_is_noop_when_nothing_due(conn, now, feature_on):
    holds.create_or_escalate(conn, **hold_args(level="I2"), now=now)
    assert holds.expire_due(conn, now=now + timedelta(days=30)) == []


# ───────────────────────────────────────────────────────── 解除 / 双人复核
def test_release_i1_single_reviewer_and_idempotent(conn, now, feature_on):
    hold = holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)["hold"]
    out = holds.release(conn, hold["id"], reviewers=["rev-1"], reason="clean for 7d",
                        actor="risk-1", now=now)
    assert out["action"] == "released"
    assert out["hold"]["state"] == "released"
    assert out["hold"]["reviewer_a"] == "rev-1"
    assert out["hold"]["reviewer_b"] is None
    assert out["hold"]["version"] == 2
    assert out["event"]["event"] == "released"
    assert holds.frozen_total(conn, NODE, now=now) == 0
    # 幂等：再次 release 不改状态、不写事件
    again = holds.release(conn, hold["id"], reviewers=["rev-2"], reason="again",
                          actor="risk-1", now=now)
    assert again["action"] == "unchanged"
    assert again["event"] is None
    assert _count(conn, "supplier_integrity_events") == 2    # created + released


def test_release_i2_requires_two_distinct_reviewers(conn, now, feature_on):
    hold = holds.create_or_escalate(conn, **hold_args(level="I2"), now=now)["hold"]
    with pytest.raises(Conflict) as excinfo:
        holds.release(conn, hold["id"], reviewers=["rev-1"], reason="one person",
                      actor="risk-1", now=now)
    assert excinfo.value.reason == "reviewers_insufficient"
    with pytest.raises(BadRequest):
        holds.release(conn, hold["id"], reviewers=["rev-1", "rev-1"], reason="same person",
                      actor="risk-1", now=now)
    out = holds.release(conn, hold["id"], reviewers=["rev-1", "rev-2"], reason="reviewed",
                        actor="risk-1", now=now)
    assert out["action"] == "released"
    assert (out["hold"]["reviewer_a"], out["hold"]["reviewer_b"]) == ("rev-1", "rev-2")


@pytest.mark.parametrize("level", ["I3", "I4"])
def test_high_level_release_requires_scope(conn, now, feature_on, level):
    hold = holds.create_or_escalate(conn, **hold_args(level=level), now=now)["hold"]
    with pytest.raises(Forbidden) as excinfo:
        holds.release(conn, hold["id"], reviewers=["rev-1", "rev-2"], reason="reviewed",
                      actor="risk-1", now=now)
    assert excinfo.value.reason == "scope_required"
    assert excinfo.value.code == 40301
    out = holds.release(conn, hold["id"], reviewers=["rev-1", "rev-2"], reason="reviewed",
                        actor="risk-1", now=now,
                        scopes=["integrity.write", facts.HIGH_RELEASE_SCOPE])
    assert out["action"] == "released"


def test_release_unknown_hold_is_404(conn, now, feature_on):
    with pytest.raises(NotFound):
        holds.release(conn, "00000000-0000-7000-8000-000000000000", reviewers=["rev-1"],
                      reason="nope", actor="risk-1", now=now)


def test_frozen_total_counts_active_only(conn, now, feature_on):
    first = holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)["hold"]
    holds.create_or_escalate(conn, **hold_args(model="openai/gpt-4o-mini", level="I2"),
                             now=now)
    holds.create_or_escalate(conn, **hold_args(node_id="node-beta", level="I3"), now=now)
    assert holds.frozen_total(conn, NODE, now=now) == 500_000 + 800_000
    assert holds.frozen_total(conn, "node-beta", now=now) == 1_000_000
    assert holds.frozen_total(conn, "node-gamma", now=now) == 0
    holds.release(conn, first["id"], reviewers=["rev-1"], reason="released",
                  actor="risk-1", now=now)
    assert holds.frozen_total(conn, NODE, now=now) == 800_000
    assert holds.is_frozen(conn, NODE, "openai/gpt-4o", now=now) is False
    assert holds.is_frozen(conn, NODE, "openai/gpt-4o-mini", now=now) is True


# ───────────────────────────────────────────────────────── 账本边界
def test_release_never_touches_ledger(conn, now, feature_on):
    """冻结 / 升级 / 解除全程：账本族表行数与全文摘要完全不变。"""
    before = ledger_snapshot(conn, facts.LEDGER_TABLES)
    hold = holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)["hold"]
    holds.create_or_escalate(conn, **hold_args(level="I3", base_amount_micro=3_000_000),
                             now=now)
    holds.release(conn, hold["id"], reviewers=["rev-1", "rev-2"], reason="released",
                  actor="risk-1", now=now, scopes=[facts.HIGH_RELEASE_SCOPE])
    after = ledger_snapshot(conn, facts.LEDGER_TABLES)
    assert before == after
    assert all(item["count"] == 0 for item in after.values())


def test_module_source_has_no_ledger_write_sql():
    """静态证据：app/integrity 里没有任何账本写 SQL（INSERT/UPDATE/DELETE ledger 族）。"""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[2] / "app" / "integrity"
    forbidden = re.compile(
        r"(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+"
        r"(journal_entry|journal_line|ledger_entry|account_balances|accounts|"
        r"merkle_commitments|m06_outbox|loss_pool_entries)", re.IGNORECASE)
    hits = [path.name for path in root.glob("*.py")
            if forbidden.search(path.read_text(encoding="utf-8"))]
    assert hits == []


# ───────────────────────────────────────────────────────── 入参 / 开关
@pytest.mark.parametrize("overrides,field", [
    ({"level": "I9"}, "level"),
    ({"base_amount_micro": -1}, "base_amount_micro"),
    ({"base_amount_micro": facts.BASE_AMOUNT_MAX_MICRO + 1}, "base_amount_micro"),
    ({"reason": ""}, "reason"),
    ({"evidence_ref": ""}, "evidence_ref"),
    ({"node_id": ""}, "node_id"),
    ({"model": "line\nbreak"}, "model"),
    ({"actor": ""}, "actor"),
])
def test_invalid_input_is_rejected(conn, now, feature_on, overrides, field):
    with pytest.raises(BadRequest) as excinfo:
        holds.create_or_escalate(conn, **hold_args(**overrides), now=now)
    assert excinfo.value.code == 40001
    assert excinfo.value.details.get("field") == field
    assert _count(conn, "supplier_integrity_holds") == 0


def test_feature_switch_off_fails_closed_but_reads_work(conn, now, monkeypatch):
    monkeypatch.setattr(features, "enabled", lambda name: False)
    with pytest.raises(FeatureUnavailable) as excinfo:
        holds.create_or_escalate(conn, **hold_args(level="I1"), now=now)
    assert excinfo.value.status_code == 503
    assert excinfo.value.code == 50001
    assert excinfo.value.reason == "feature_disabled"
    # 读路径保持只读可用（rollback_rule：已有冻结保留可查）
    assert holds.list_holds(conn, state="all", now=now)["items"] == []
    assert holds.frozen_total(conn, NODE, now=now) == 0
    assert holds.is_frozen(conn, NODE, MODEL, now=now) is False


def test_feature_switch_default_is_off_and_has_three_fields():
    assert features.enabled(facts.FEATURE_NAME) is False
    spec = features.get(facts.FEATURE_NAME)
    assert spec.owner == "risk-seat"
    assert spec.expire_at.isoformat() == "2026-12-31"
    assert spec.default is False
    assert "不改账本" in spec.rollback_rule
    assert features.WRITE_SURFACE == ()
    assert features.describe()["all_default_off"] is True


def test_list_holds_filters_and_cursor(conn, now, feature_on):
    for index in range(3):
        holds.create_or_escalate(
            conn, **hold_args(node_id=f"node-{index}", level="I1"), now=now)["hold"]
    page1 = holds.list_holds(conn, state="active", limit=2, now=now)
    assert len(page1["items"]) == 2 and page1["has_more"] is True
    page2 = holds.list_holds(conn, state="active", limit=2, cursor=page1["next_cursor"],
                             now=now)
    assert len(page2["items"]) == 1 and page2["has_more"] is False
    by_node = holds.list_holds(conn, state="all", node_id="node-1", now=now)
    assert [item["node_id"] for item in by_node["items"]] == ["node-1"]
    by_level = holds.list_holds(conn, state="all", level="I3", now=now)
    assert by_level["items"] == []
    with pytest.raises(BadRequest):
        holds.list_holds(conn, state="bogus", now=now)
