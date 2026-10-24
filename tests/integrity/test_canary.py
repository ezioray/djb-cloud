# SPDX-License-Identifier: AGPL-3.0-or-later
"""C13 canary / L4 行为指纹 · 服务层用例（M17 §5.2 / §5.4）。

覆盖：5 条内置题面、exact/contains/regex 匹配（大小写/标点归一化）、错误响应失败、
120s 过期、重放/跨节点、同 node/model 单 issued、响应正文不落库、stats、连续 3 次 pass→L4 线索、
开关默认关、账本 diff=0。
"""
from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest

from app.integrity import canary, facts, features
from app.integrity.errors import BadRequest, Conflict, FeatureUnavailable, NotFound

from kit import FIXED_NOW, ledger_snapshot

NODE = "node-alpha"
MODEL = "openai/gpt-4o"
#: 各题面的正确答案（与 1740 迁移里写死的 expected 对应）
ANSWERS = {
    "arith.2plus2": "4",
    "capital.france": "Paris",
    "echo.token": "Sure — CANARY-7F3A.",
    "sequence.evens": "2, 4, 6, 8",
    "color.hex": "#FF0000",
}


def _issue(conn, now, *, node=NODE, model=MODEL, upstream=None):
    return canary.issue_run(conn, node_id=node, model=model, upstream_id=upstream, now=now)


def _answer_for_prompt(conn, run):
    key = run["prompt_key"]
    return ANSWERS[key]


def _pass_run(conn, now, *, node=NODE, model=MODEL):
    run = _issue(conn, now, node=node, model=model)
    answer = _answer_for_prompt(conn, run)
    return canary.submit_response(conn, run_id=run["run_id"], node_id=node,
                                  response_text=answer, now=now)


# ───────────────────────────────────────────────────────── 开关 / 归一化 / 匹配
def test_switch_default_off_three_fields_and_env_activation(monkeypatch):
    assert canary.feature_enabled() is False
    spec = features.get("supply.canary.enabled")
    assert spec.owner == "risk-seat"
    assert spec.expire_at.isoformat() == "2026-12-31"
    assert spec.default is False
    assert "只读" in spec.rollback_rule and "账本" in spec.rollback_rule
    monkeypatch.setenv("DJB_CANARY", "1")
    assert canary.feature_enabled() is True
    monkeypatch.setenv("DJB_CANARY", "0")
    assert canary.feature_enabled() is False


def test_feature_off_write_paths_fail_closed(conn, now):
    with pytest.raises(FeatureUnavailable) as excinfo:
        _issue(conn, now)
    assert excinfo.value.status_code == 503
    assert excinfo.value.code == 50001
    assert excinfo.value.reason == "feature_disabled"
    assert canary.list_runs(conn)["items"] == []
    assert canary.stats(conn, node_id=NODE, model=MODEL)["total"] == 0


def test_normalisation_and_matchers():
    assert canary.normalize_answer("  4. ") == "4"
    assert canary.normalize_answer("The answer is 4.") == "the answer is 4"
    assert canary.normalize_answer("2, 4, 6, 8") == "2 4 6 8"
    assert canary.normalize_regex_text(" #FF0000 ") == "#ff0000"
    assert canary.match_response("exact", "4", " 4. ")["passed"] is True
    assert canary.match_response("exact", "4", "four")["passed"] is False
    assert canary.match_response("exact", "paris", "PARIS!")["passed"] is True
    assert canary.match_response("contains", "canary-7f3a", "ok: CANARY-7F3A.")["passed"] is True
    assert canary.match_response("contains", "canary-7f3a", "something else")["passed"] is False
    assert canary.match_response("regex", "^#[0-9a-f]{6}$", "#ff0000")["passed"] is True
    assert canary.match_response("regex", "^#[0-9a-f]{6}$", "red")["passed"] is False
    with pytest.raises(BadRequest):
        canary.match_response("fuzzy", "x", "x")


def test_five_builtin_prompts_seeded(conn, now):
    rows = conn.execute(
        "SELECT prompt_key, expected_kind, state FROM canary_prompts ORDER BY prompt_key"
    ).fetchall()
    keys = [row[0] for row in rows]
    assert keys == sorted(facts.CANARY_PROMPT_KEYS)
    kinds = {row[1] for row in rows}
    assert kinds == {"exact", "contains", "regex"}
    assert all(row[2] == "active" for row in rows)
    assert conn.execute("SELECT COUNT(*) FROM canary_prompts").fetchone()[0] == 5


def test_prompt_selection_is_recomputable(conn, now, feature_on):
    run = _issue(conn, now)
    seed = canary.selection_seed(NODE, MODEL, run["run_id"])
    expected_key = canary.pick_prompt_key(NODE, MODEL, seed, facts.CANARY_PROMPT_KEYS)
    assert run["prompt_key"] == expected_key
    assert run["selection"] == seed
    # 每次运行的 run_id 不同 → 选题种子不同（不再按时间窗固定同一题）
    other = _issue(conn, now, node="node-other")
    assert other["selection"] != run["selection"]
    assert run["prompt"].startswith(conn.execute(
        "SELECT prompt FROM canary_prompts WHERE prompt_key = %s",
        (expected_key,)).fetchone()[0])
    # 同一 run 的选题可被任何人用 (node, model, run_id) 复算
    assert canary.pick_prompt_key(NODE, MODEL, seed, facts.CANARY_PROMPT_KEYS) == expected_key


# ───────────────────────────────────────────────────────── issue
def test_issue_shape_and_deadline(conn, now, feature_on):
    run = _issue(conn, now, upstream="up-1")
    assert set(run) == {"run_id", "node_id", "upstream_id", "model", "prompt_key",
                        "selection", "prompt", "nonce", "max_tokens", "issued_at",
                        "deadline_at", "status"}
    assert run["status"] == "issued"
    assert run["deadline_at"] == "2026-10-24T00:02:00.000Z"        # 120s
    assert run["nonce"] in run["prompt"]
    assert run["upstream_id"] == "up-1"
    row = conn.execute("SELECT status, response_hash, score FROM canary_runs").fetchone()
    assert tuple(row) == ("issued", None, None)
    events = [item[0] for item in conn.execute(
        "SELECT event FROM canary_events").fetchall()]
    assert events == ["issued"]


def test_single_issued_run_per_node_model(conn, now, feature_on):
    _issue(conn, now)
    with pytest.raises(Conflict) as excinfo:
        _issue(conn, now)
    assert excinfo.value.code == 40919
    assert excinfo.value.reason == "run_pending"


def test_issue_prompt_has_no_user_data_markers(conn, now, feature_on):
    prompt = _issue(conn, now)["prompt"].lower()
    for marker in ("@", "email", "phone", "api_key", "sk-", "password", "secret"):
        assert marker not in prompt
    assert len(prompt) <= facts.PROMPT_MAX_LEN


# ───────────────────────────────────────────────────────── 回填 / 匹配
def test_pass_stores_hash_not_body(conn, now, feature_on, monkeypatch):
    monkeypatch.setattr(canary, "pick_prompt_key", lambda *args, **kwargs: "echo.token")
    run = _issue(conn, now)
    answer = "Sure: CANARY-7F3A (probe-marker-9c1d)."        # 唯一标记，便于断言正文未落库
    result = canary.submit_response(conn, run_id=run["run_id"], node_id=NODE,
                                    response_text=answer, usage_prompt_tokens=12,
                                    latency_ms=34, now=now)
    assert result["run"]["status"] == "passed"
    assert result["run"]["score"] == 1.0
    assert result["match"]["response_hash"] == hashlib.sha256(
        answer.encode("utf-8")).hexdigest()
    dump = "\n".join(row[0] for table in ("canary_runs", "canary_events")
                     for row in conn.execute(f"SELECT t::text FROM {table} t").fetchall())
    assert answer not in dump                                   # **正文不落库**
    assert result["match"]["response_hash"] in dump
    detail = conn.execute("SELECT detail FROM canary_runs").fetchone()[0]
    assert set(detail) <= {"match", "reason", "answer_len", "usage_prompt_tokens",
                          "latency_ms", "prompt_key"}
    assert detail["answer_len"] == len(answer)


@pytest.mark.parametrize("prompt_key,good,bad", [
    ("arith.2plus2", "4", "5"),
    ("capital.france", "paris", "london"),
    ("echo.token", "CANARY-7F3A", "CANARY-0000"),
    ("sequence.evens", "2 4 6 8", "1 3 5 7"),
    ("color.hex", "#00ff00", "green"),
])
def test_all_prompt_kinds_match(conn, now, feature_on, monkeypatch, prompt_key, good, bad):
    # 固定题面选择，逐条覆盖 exact / contains / regex
    monkeypatch.setattr(canary, "pick_prompt_key", lambda *args, **kwargs: prompt_key)
    run = _issue(conn, now)
    assert run["prompt_key"] == prompt_key
    result = canary.submit_response(conn, run_id=run["run_id"], node_id=NODE,
                                    response_text=good, now=now)
    assert result["run"]["status"] == "passed"

    second_node = "node-" + prompt_key.replace(".", "-")
    bad_run = _issue(conn, now, node=second_node)
    failed = canary.submit_response(conn, run_id=bad_run["run_id"], node_id=second_node,
                                    response_text=bad, now=now)
    assert failed["run"]["status"] == "failed"
    assert failed["run"]["score"] == 0.0


def test_replay_and_cross_node_rejected(conn, now, feature_on):
    run = _issue(conn, now)
    with pytest.raises(NotFound):
        canary.submit_response(conn, run_id=run["run_id"], node_id="node-beta",
                               response_text="4", now=now)
    with pytest.raises(NotFound):
        canary.submit_response(conn, run_id="00000000-0000-7000-8000-000000000000",
                               node_id=NODE, response_text="4", now=now)
    canary.submit_response(conn, run_id=run["run_id"], node_id=NODE, response_text="4",
                           now=now)
    with pytest.raises(Conflict) as excinfo:
        canary.submit_response(conn, run_id=run["run_id"], node_id=NODE,
                               response_text="4", now=now)
    assert excinfo.value.reason == "run_resolved"


def test_expired_run_is_missed_and_rejects(conn, now, feature_on):
    run = _issue(conn, now)
    later = now + facts.CANARY_DEADLINE + timedelta(seconds=1)
    with pytest.raises(Conflict) as excinfo:
        canary.submit_response(conn, run_id=run["run_id"], node_id=NODE,
                               response_text="4", now=later)
    assert excinfo.value.reason == "run_expired"
    row = conn.execute("SELECT status, resolved_at FROM canary_runs").fetchone()
    assert row[0] == "missed" and row[1] is not None
    events = [item[0] for item in conn.execute(
        "SELECT event FROM canary_events ORDER BY event").fetchall()]
    assert events == ["issued", "missed"]


def test_expire_due_is_idempotent(conn, now, feature_on):
    _issue(conn, now)
    later = now + facts.CANARY_DEADLINE + timedelta(seconds=1)
    assert canary.expire_due(conn, now=later)["runs"] == 1
    assert canary.expire_due(conn, now=later)["runs"] == 0
    assert conn.execute("SELECT status FROM canary_runs").fetchone()[0] == "missed"


def test_response_validation(conn, now, feature_on):
    run = _issue(conn, now)
    with pytest.raises(BadRequest):
        canary.submit_response(conn, run_id=run["run_id"], node_id=NODE,
                               response_text=None, now=now)
    with pytest.raises(BadRequest):
        canary.submit_response(conn, run_id=run["run_id"], node_id=NODE,
                               response_text="x" * (facts.CANARY_RESPONSE_MAX_LEN + 1),
                               now=now)
    with pytest.raises(BadRequest):
        canary.submit_response(conn, run_id=run["run_id"], node_id=NODE,
                               response_text="4", usage_prompt_tokens=-1, now=now)
    with pytest.raises(BadRequest):
        canary.submit_response(conn, run_id="not-a-uuid", node_id=NODE,
                               response_text="4", now=now)


# ───────────────────────────────────────────────────────── 统计 / L4 线索
def test_stats_counts(conn, now, feature_on):
    _pass_run(conn, now)
    second = _issue(conn, now, node="node-b")
    canary.submit_response(conn, run_id=second["run_id"], node_id="node-b",
                           response_text="definitely wrong", now=now)
    third = _issue(conn, now, node="node-c")
    canary.expire_due(conn, now=now + facts.CANARY_DEADLINE + timedelta(seconds=1))
    stats = canary.stats(conn, node_id=NODE, model=MODEL)
    assert stats["passed"] == 1 and stats["failed"] == 0 and stats["missed"] == 0
    assert stats["pass_rate"] == 1.0
    stats_b = canary.stats(conn, node_id="node-b", model=MODEL)
    assert stats_b["failed"] == 1 and stats_b["pass_rate"] == 0.0
    stats_c = canary.stats(conn, node_id="node-c", model=MODEL)
    assert stats_c["missed"] == 1
    with pytest.raises(BadRequest):
        canary.stats(conn, node_id=NODE, model=MODEL, window=0)


def test_behavioral_l4_requires_three_consecutive_passes(conn, now, feature_on):
    evidence = canary.behavioral_evidence(conn, node_id=NODE, model=MODEL)
    assert evidence["pass"] is False and evidence["reason"] == "insufficient_runs"
    for _ in range(3):
        _pass_run(conn, now)
    evidence = canary.behavioral_evidence(conn, node_id=NODE, model=MODEL)
    assert evidence["level"] == "L4" and evidence["pass"] is True
    assert evidence["streak"] == 3 and evidence["source"] == "canary"
    # 线索不直接改 M17 定级：model_attestations 里没有任何记录
    assert conn.execute("SELECT COUNT(*) FROM model_attestations").fetchone()[0] == 0


def test_behavioral_streak_broken_by_failure_or_miss(conn, now, feature_on):
    _pass_run(conn, now)
    _pass_run(conn, now)
    run = _issue(conn, now)
    canary.submit_response(conn, run_id=run["run_id"], node_id=NODE,
                           response_text="wrong", now=now)
    evidence = canary.behavioral_evidence(conn, node_id=NODE, model=MODEL)
    assert evidence["pass"] is False and evidence["reason"] == "streak_broken"
    assert evidence["streak"] == 0
    # 再连续 3 次 pass → 重新到 L4
    for _ in range(3):
        _pass_run(conn, now)
    assert canary.behavioral_evidence(conn, node_id=NODE, model=MODEL)["pass"] is True


def test_list_runs_filters_and_pagination(conn, now, feature_on):
    for index, node in enumerate(("node-a", "node-b", "node-c")):
        _pass_run(conn, now, node=node)
    page1 = canary.list_runs(conn, limit=2)
    assert len(page1["items"]) == 2 and page1["has_more"] is True
    page2 = canary.list_runs(conn, limit=2, cursor=page1["next_cursor"])
    assert len(page2["items"]) == 1 and page2["has_more"] is False
    assert canary.list_runs(conn, node_id="node-b")["items"][0]["node_id"] == "node-b"
    assert canary.list_runs(conn, status="passed")["items"] == \
        canary.list_runs(conn, status="passed")["items"]
    assert canary.list_runs(conn, status="failed")["items"] == []
    with pytest.raises(BadRequest):
        canary.list_runs(conn, status="bogus")
    detail = canary.get_run(conn, page1["items"][0]["id"])
    assert detail is not None and detail["events"]


def test_ledger_untouched_by_canary_flow(conn, now, feature_on):
    before = ledger_snapshot(conn, facts.LEDGER_TABLES)
    _pass_run(conn, now)
    run = _issue(conn, now, node="node-x")
    canary.submit_response(conn, run_id=run["run_id"], node_id="node-x",
                           response_text="wrong", now=now)
    canary.expire_due(conn, now=now + facts.CANARY_DEADLINE + timedelta(seconds=1))
    canary.behavioral_evidence(conn, node_id=NODE, model=MODEL)
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
    hits = [path.name for path in root.glob("canary*.py")
            if forbidden.search(path.read_text(encoding="utf-8"))]
    assert hits == []
