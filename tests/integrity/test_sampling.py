# SPDX-License-Identifier: AGPL-3.0-or-later
"""C14b 可验证随机抽检 · 服务层用例（M17 §5.10 / §5.11）。

覆盖：commit-reveal 一致/不一致、seed 不落库、确定性复算、权重 0 不抽、权重大命中多、
无放回、重复 reveal、draw 唯一、L3→passed / L2→failed / 过期→missed、escalate 阈值、
账本 diff=0、静态无账本 SQL。
"""
from __future__ import annotations

import hashlib
from datetime import timedelta

import psycopg
import pytest

from app.integrity import facts, features, sampling
from app.integrity.errors import BadRequest, Conflict, FeatureUnavailable, NotFound
from app.integrity.sampling import Contribution

from kit import FIXED_NOW, ledger_snapshot, sampling_contributions

NODE = "node-alpha"
MODEL = "openai/gpt-4o"


def _open(conn, now, *, epoch_no=1, contributions=None, draw_count=2):
    return sampling.open_epoch(
        conn, epoch_no=epoch_no,
        contributions=contributions or sampling_contributions((NODE, MODEL, 100),
                                                             ("node-beta", MODEL, 50)),
        draw_count=draw_count, now=now)


def _reveal(conn, now, opened):
    return sampling.reveal_epoch(conn, epoch_id=opened["epoch"]["id"],
                                 seed=opened["seed"], now=now)


def _dump(conn) -> str:
    parts = []
    for table in ("sampling_epochs", "sampling_draws", "sampling_events"):
        for row in conn.execute(f"SELECT t::text FROM {table} t").fetchall():
            parts.append(row[0])
    return "\n".join(parts)


# ───────────────────────────────────────────────────────── 开关 / 纯函数
def test_switch_default_off_three_fields_and_env_activation(monkeypatch):
    assert sampling.feature_enabled() is False
    spec = features.get("supply.sampling.enabled")
    assert spec.owner == "lead"
    assert spec.expire_at.isoformat() == "2026-12-31"
    assert spec.default is False
    assert "只读" in spec.rollback_rule and "账本" in spec.rollback_rule
    monkeypatch.setenv("DJB_SAMPLING", "1")
    assert sampling.feature_enabled() is True
    monkeypatch.setenv("DJB_SAMPLING", "0")
    assert sampling.feature_enabled() is False


def test_feature_off_write_paths_fail_closed(conn, now):
    with pytest.raises(FeatureUnavailable) as excinfo:
        _open(conn, now)
    assert excinfo.value.status_code == 503
    assert excinfo.value.code == 50001
    assert excinfo.value.reason == "feature_disabled"
    assert sampling.list_epochs(conn)["items"] == []


def test_drawing_is_deterministic_and_weighted():
    items = [Contribution("node-a", "m", 90), Contribution("node-b", "m", 10),
             Contribution("node-c", "m", 0)]
    seed = "ab" * 32
    first = sampling.drawing(seed, 7, items, 2)
    second = sampling.drawing(seed, 7, items, 2)
    assert first == second
    assert [row["rank"] for row in first] == [1, 2]
    assert all(row["node_id"] != "node-c" for row in first)       # 权重 0 不抽
    assert sampling.compare_drawings(first, second) is True
    assert sampling.compare_drawings(first, list(reversed(second))) is False


def test_weight_bias_over_many_seeds():
    items = [Contribution("node-a", "m", 90), Contribution("node-b", "m", 10),
             Contribution("node-c", "m", 0)]
    hits = {"node-a": 0, "node-b": 0, "node-c": 0}
    for index in range(300):
        seed = hashlib.sha256(f"seed-{index}".encode()).hexdigest()
        selected = sampling.drawing(seed, 1, items, 1)
        hits[selected[0]["node_id"]] += 1
    assert hits["node-c"] == 0
    assert hits["node-a"] > hits["node-b"] * 3                    # 90:10 的强偏置
    assert hits["node-a"] + hits["node-b"] == 300


def test_drawing_without_replacement():
    items = [Contribution(f"node-{index}", "m", 10) for index in range(5)]
    picked = sampling.drawing("cd" * 32, 3, items, 5)
    assert len(picked) == 5
    assert len({row["node_id"] for row in picked}) == 5
    assert [row["rank"] for row in picked] == [1, 2, 3, 4, 5]


@pytest.mark.parametrize("contributions,draw_count,field", [
    ([], 1, "contributions"),
    (sampling_contributions((NODE, MODEL, 10), (NODE, MODEL, 20)), 1, "contributions"),
    (sampling_contributions((NODE, MODEL, -1)), 1, "contributions"),
    (sampling_contributions((NODE, MODEL, 10)), 1001, "draw_count"),
    ([{"node_id": NODE, "model": MODEL, "weight": 1, "extra": 1}], 1, "contributions"),
    (sampling_contributions(("", MODEL, 10)), 1, "node_id"),
])
def test_open_validation(conn, now, feature_on, contributions, draw_count, field):
    with pytest.raises(BadRequest) as excinfo:
        sampling.open_epoch(conn, epoch_no=1, contributions=contributions,
                            draw_count=draw_count, now=now)
    assert excinfo.value.code == 40001
    assert excinfo.value.details.get("field") == field


# ───────────────────────────────────────────────────────── commit（承诺）
def test_open_commits_seed_without_storing_it(conn, now, feature_on):
    opened = _open(conn, now, epoch_no=11)
    epoch = opened["epoch"]
    seed = opened["seed"]
    assert len(seed) == 64 and set(seed) <= set("0123456789abcdef")
    assert epoch["state"] == "committed"
    assert epoch["seed_reveal"] is None and epoch["revealed_at"] is None
    assert epoch["seed_commit"] == hashlib.sha256(bytes.fromhex(seed)).hexdigest()
    assert epoch["contributions"] == sampling_contributions((NODE, MODEL, 100),
                                                            ("node-beta", MODEL, 50))
    dump = _dump(conn)
    assert seed not in dump                                      # **seed 不落库**
    assert epoch["seed_commit"] in dump                          # 承诺在库里
    events = [row[0] for row in conn.execute(
        "SELECT event FROM sampling_events").fetchall()]
    assert events == ["committed"]
    detail = conn.execute("SELECT detail FROM sampling_events").fetchone()[0]
    assert seed not in str(detail)


def test_open_duplicate_epoch_no_conflicts(conn, now, feature_on):
    _open(conn, now, epoch_no=5)
    with pytest.raises(Conflict) as excinfo:
        _open(conn, now, epoch_no=5)
    assert excinfo.value.reason == "epoch_exists"


# ───────────────────────────────────────────────────────── reveal（揭示）
def test_reveal_wrong_seed_conflicts_and_keeps_commitment(conn, now, feature_on):
    opened = _open(conn, now, epoch_no=21)
    with pytest.raises(Conflict) as excinfo:
        sampling.reveal_epoch(conn, epoch_id=opened["epoch"]["id"],
                              seed="00" * 32, now=now)
    assert excinfo.value.code == 40919
    assert excinfo.value.reason == "seed_mismatch"
    row = conn.execute("SELECT state, seed_reveal FROM sampling_epochs").fetchone()
    assert tuple(row) == ("committed", None)
    assert conn.execute("SELECT COUNT(*) FROM sampling_draws").fetchone()[0] == 0


def test_reveal_creates_pending_draws_with_challenges(conn, now, feature_on,
                                                     fixed_tokenizer):
    contributions = sampling_contributions((NODE, MODEL, 100), ("node-beta", MODEL, 50),
                                           ("node-gamma", MODEL, 25))
    opened = _open(conn, now, epoch_no=22, contributions=contributions, draw_count=2)
    revealed = _reveal(conn, now, opened)
    assert revealed["epoch"]["state"] == "revealed"
    assert revealed["epoch"]["seed_reveal"] == opened["seed"]
    assert len(revealed["draws"]) == 2
    assert [draw["rank"] for draw in revealed["draws"]] == [1, 2]
    assert all(draw["status"] == "pending" for draw in revealed["draws"])
    assert all(draw["challenge_id"] for draw in revealed["draws"])
    challenges = conn.execute(
        "SELECT COUNT(*) FROM attestation_challenges").fetchone()[0]
    assert challenges == 2
    events = [row[0] for row in conn.execute(
        "SELECT event FROM sampling_events ORDER BY event").fetchall()]
    assert events == ["committed", "drawn", "drawn", "revealed"]


def test_reveal_is_idempotent_for_same_seed(conn, now, feature_on, fixed_tokenizer):
    opened = _open(conn, now, epoch_no=23)
    first = _reveal(conn, now, opened)
    second = _reveal(conn, now, opened)
    assert second["idempotent"] is True
    assert len(second["draws"]) == len(first["draws"])
    assert conn.execute("SELECT COUNT(*) FROM sampling_draws").fetchone()[0] == len(
        first["draws"])
    events = conn.execute("SELECT COUNT(*) FROM sampling_events").fetchone()[0]
    assert events == 2 + len(first["draws"])                     # 不重复写事件


def test_reveal_after_expired_conflicts(conn, now, feature_on):
    opened = _open(conn, now, epoch_no=24)
    conn.execute("UPDATE sampling_epochs SET state = 'expired'")
    with pytest.raises(Conflict) as excinfo:
        _reveal(conn, now, opened)
    assert excinfo.value.reason == "epoch_expired"


def test_draw_unique_per_epoch(conn, now, feature_on, fixed_tokenizer):
    opened = _open(conn, now, epoch_no=25, draw_count=1)
    revealed = _reveal(conn, now, opened)
    draw = revealed["draws"][0]
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.transaction():
            conn.execute(
                """
                INSERT INTO sampling_draws
                  (id, epoch_id, node_id, model, weight, rank, challenge_id, status,
                   level, detail, created_at, resolved_at)
                VALUES (gen_random_uuid(), %s, %s, %s, 10, 9, NULL, 'pending', NULL,
                        '{}'::jsonb, now(), NULL)
                """, (draw["epoch_id"], draw["node_id"], draw["model"]))


# ───────────────────────────────────────────────────────── 结果回填
def _evidence(draw, *, usage, result="tokenizer_match"):
    return {"challenge_id": draw["challenge_id"], "model": draw["model"],
            "result": result, "usage_prompt_tokens": usage}


def test_record_result_passed_and_failed(conn, now, feature_on, fixed_tokenizer):
    opened = _open(conn, now, epoch_no=31, draw_count=1,
                   contributions=sampling_contributions((NODE, MODEL, 100)))
    draw = _reveal(conn, now, opened)["draws"][0]
    passed = sampling.record_result(conn, draw_id=draw["id"],
                                    evidence=_evidence(draw, usage=100), now=now)
    assert passed["draw"]["status"] == "passed"
    assert passed["draw"]["level"] == "L3"
    assert passed["attestation"]["level"] == "L3"

    opened2 = _open(conn, now, epoch_no=32, draw_count=1,
                    contributions=sampling_contributions(("node-beta", MODEL, 100)))
    draw2 = _reveal(conn, now, opened2)["draws"][0]
    failed = sampling.record_result(conn, draw_id=draw2["id"],
                                    evidence=_evidence(draw2, usage=160), now=now)
    assert failed["draw"]["status"] == "failed"
    assert failed["draw"]["level"] == "L2"
    events = [row[0] for row in conn.execute(
        "SELECT event FROM sampling_events WHERE event IN ('passed','failed')"
        " ORDER BY event").fetchall()]
    assert events == ["failed", "passed"]


def test_record_result_guards(conn, now, feature_on, fixed_tokenizer):
    opened = _open(conn, now, epoch_no=33, draw_count=1,
                   contributions=sampling_contributions((NODE, MODEL, 100)))
    draw = _reveal(conn, now, opened)["draws"][0]
    with pytest.raises(BadRequest):
        sampling.record_result(conn, draw_id=draw["id"],
                               evidence={"challenge_id": "00000000-0000-7000-8000-"
                                                       "000000000000", "model": MODEL,
                                         "result": "tokenizer_match"}, now=now)
    sampling.record_result(conn, draw_id=draw["id"], evidence=_evidence(draw, usage=100),
                           now=now)
    with pytest.raises(Conflict) as excinfo:
        sampling.record_result(conn, draw_id=draw["id"],
                               evidence=_evidence(draw, usage=100), now=now)
    assert excinfo.value.reason == "draw_resolved"
    with pytest.raises(NotFound):
        sampling.record_result(conn, draw_id="00000000-0000-7000-8000-000000000000",
                               evidence=_evidence(draw, usage=100), now=now)


def test_expire_due_marks_missed(conn, now, feature_on, fixed_tokenizer):
    opened = _open(conn, now, epoch_no=34, draw_count=1,
                   contributions=sampling_contributions((NODE, MODEL, 100)))
    _reveal(conn, now, opened)
    later = now + facts.CHALLENGE_TTL + timedelta(seconds=1)
    assert sampling.expire_due(conn, now=later)["draws"] == 1
    row = conn.execute("SELECT status, resolved_at FROM sampling_draws").fetchone()
    assert row[0] == "missed" and row[1] is not None
    events = [item[0] for item in conn.execute(
        "SELECT event FROM sampling_events WHERE event = 'missed'").fetchall()]
    assert events == ["missed"]
    # 已 missed 的不会重复翻
    assert sampling.expire_due(conn, now=later)["draws"] == 0


# ───────────────────────────────────────────────────────── 升级建议
def _seed_failure(conn, now, *, epoch_no, node, model, status, resolved_at):
    opened = sampling.open_epoch(conn, epoch_no=epoch_no,
                                 contributions=sampling_contributions((node, model, 10)),
                                 draw_count=1, now=now)
    conn.execute(
        """
        INSERT INTO sampling_draws
          (id, epoch_id, node_id, model, weight, rank, challenge_id, status, level,
           detail, created_at, resolved_at)
        VALUES (gen_random_uuid(), %s, %s, %s, 10, 1, NULL, %s, 'L2', '{}'::jsonb, %s, %s)
        """, (opened["epoch"]["id"], node, model, status, now, resolved_at))


def test_escalate_thresholds(conn, now, feature_on):
    assert sampling.escalate(conn, node_id=NODE, model=MODEL, now=now)["suggested_level"] \
        is None
    _seed_failure(conn, now, epoch_no=41, node=NODE, model=MODEL, status="failed",
                  resolved_at=now - timedelta(hours=2))
    first = sampling.escalate(conn, node_id=NODE, model=MODEL, now=now)
    assert first["suggested_level"] == "I0"
    assert first["failures_24h"] == 1

    _seed_failure(conn, now, epoch_no=42, node=NODE, model=MODEL, status="missed",
                  resolved_at=now - timedelta(hours=1))
    second = sampling.escalate(conn, node_id=NODE, model=MODEL, now=now)
    assert second["suggested_level"] == "I1"
    assert second["failures_24h"] == 2

    _seed_failure(conn, now, epoch_no=43, node=NODE, model=MODEL, status="failed",
                  resolved_at=now - timedelta(days=2))
    third = sampling.escalate(conn, node_id=NODE, model=MODEL, now=now)
    assert third["suggested_level"] == "I2"
    assert third["failures_7d"] == 3
    assert third["failures_24h"] == 2
    # 只给建议：不建 hold、不动账本
    assert conn.execute("SELECT COUNT(*) FROM supplier_integrity_holds").fetchone()[0] == 0


# ───────────────────────────────────────────────────────── 复算 / 查询 / 账本
def test_verify_epoch_recomputes_consistently(conn, now, feature_on, fixed_tokenizer):
    contributions = sampling_contributions((NODE, MODEL, 100), ("node-beta", MODEL, 50),
                                           ("node-gamma", MODEL, 25))
    opened = _open(conn, now, epoch_no=51, contributions=contributions, draw_count=2)
    with pytest.raises(Conflict) as excinfo:
        sampling.verify_epoch(conn, opened["epoch"]["id"])
    assert excinfo.value.reason == "epoch_not_revealed"
    _reveal(conn, now, opened)
    verified = sampling.verify_epoch(conn, opened["epoch"]["id"])
    assert verified["consistent"] is True
    assert verified["commit_ok"] is True
    assert len(verified["expected"]) == 2
    assert verified["actual"] == [{"node_id": row["node_id"], "model": row["model"],
                                   "rank": row["rank"]} for row in verified["expected"]]
    # 复算用的 draw_count / 抽样框来自库内快照
    assert verified["draw_count"] == 2


def test_verify_detects_tampered_drawing(conn, now, feature_on, fixed_tokenizer):
    contributions = sampling_contributions((NODE, MODEL, 100), ("node-beta", MODEL, 50))
    opened = _open(conn, now, epoch_no=52, contributions=contributions, draw_count=2)
    _reveal(conn, now, opened)
    verified = sampling.verify_epoch(conn, opened["epoch"]["id"])
    tampered = [dict(row) for row in verified["expected"]]
    tampered[0]["node_id"] = "node-evil"
    assert sampling.compare_drawings(verified["expected"], tampered) is False


def test_list_epochs_and_draws_filters(conn, now, feature_on, fixed_tokenizer):
    first = _open(conn, now, epoch_no=61)
    _open(conn, now, epoch_no=62)
    revealed = _reveal(conn, now, first)
    listed = sampling.list_epochs(conn, limit=1)
    assert len(listed["items"]) == 1 and listed["has_more"] is True
    assert listed["items"][0]["epoch_no"] == 62                   # epoch_no DESC
    page2 = sampling.list_epochs(conn, limit=1, cursor=listed["next_cursor"])
    assert page2["items"][0]["epoch_no"] == 61
    assert sampling.list_epochs(conn, state="revealed")["items"][0]["epoch_no"] == 61
    with pytest.raises(BadRequest):
        sampling.list_epochs(conn, state="bogus")
    draws = sampling.list_draws(conn, epoch_id=first["epoch"]["id"])
    assert len(draws["items"]) == len(revealed["draws"])
    assert sampling.list_draws(conn, status="pending")["items"]
    assert sampling.list_draws(conn, status="passed")["items"] == []
    detail = sampling.get_epoch(conn, first["epoch"]["id"])
    assert detail is not None and len(detail["draws"]) == len(revealed["draws"])
    assert sampling.get_epoch(conn, "00000000-0000-7000-8000-000000000000") is None


def test_ledger_untouched_by_sampling_flow(conn, now, feature_on, fixed_tokenizer):
    before = ledger_snapshot(conn, facts.LEDGER_TABLES)
    opened = _open(conn, now, epoch_no=71, draw_count=1,
                   contributions=sampling_contributions((NODE, MODEL, 100)))
    draw = _reveal(conn, now, opened)["draws"][0]
    sampling.record_result(conn, draw_id=draw["id"], evidence=_evidence(draw, usage=100),
                           now=now)
    sampling.expire_due(conn, now=now + timedelta(days=1))
    sampling.escalate(conn, node_id=NODE, model=MODEL, now=now)
    after = ledger_snapshot(conn, facts.LEDGER_TABLES)
    assert before == after
    assert all(item["count"] == 0 for item in after.values())


def test_module_has_no_ledger_write_sql():
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[2] / "app" / "integrity"
    forbidden = re.compile(
        r"(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+"
        r"(journal_entry|journal_line|ledger_entry|account_balances|accounts|"
        r"merkle_commitments|m06_outbox|loss_pool_entries)", re.IGNORECASE)
    hits = [path.name for path in root.glob("sampling*.py")
            if forbidden.search(path.read_text(encoding="utf-8"))]
    assert hits == []
