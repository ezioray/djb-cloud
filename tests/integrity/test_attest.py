# SPDX-License-Identifier: AGPL-3.0-or-later
"""C12 服务端证明核心用例（M17 §5.1–5.3 / §5.7）。

覆盖：容差边界 / 挑战 TTL 与一次性 / 跨 node·model 拒绝 / prompt 不含用户数据 /
tokenizer match→L3、mismatch→L2+事件、无 usage→L2、failed→L0 / 只升不降 /
TTL 24h·7d 与过期 / 开关默认关 + DJB_ATTEST=1 / 账本 diff=0 / 无正文落库。
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.integrity import attest, facts, features, providers
from app.integrity.errors import (BadRequest, Conflict, FeatureUnavailable, NotFound,
                                  TokenizerUnavailable)

from kit import FIXED_NOW, ledger_snapshot

NODE = "node-alpha"
MODEL = "openai/gpt-4o"


def _issue(conn, now, *, node=NODE, model=MODEL, upstream=None):
    return attest.issue_challenge(conn, node_id=node, upstream_id=upstream, model=model,
                                  now=now)


def _submit(conn, now, challenge, *, node=NODE, model=MODEL, result="tokenizer_match",
            usage=None, **extra):
    body = {"challenge_id": challenge["challenge_id"], "model": model, "result": result}
    if usage is not None:
        body["usage_prompt_tokens"] = usage
    body.update(extra)
    return attest.submit_evidence(conn, node_id=node, payload=body, now=now)


# ───────────────────────────────────────────────────────── 纯函数 / 开关
def test_tolerance_and_compare_boundaries():
    assert attest.tolerance_for(100) == 1
    assert attest.tolerance_for(1000) == 10
    assert attest.tolerance_for(50) == 1
    assert attest.tolerance_for(1) == 1
    assert attest.compare_tokens(1000, 1010)["match"] is True
    assert attest.compare_tokens(1000, 1011)["match"] is False
    assert attest.compare_tokens(100, 101)["match"] is True
    assert attest.compare_tokens(100, 102)["match"] is False
    missing = attest.compare_tokens(100, None)
    assert missing["match"] is False and missing["insufficient"] is True
    assert attest.compare_tokens(100, 0)["insufficient"] is True
    with pytest.raises(BadRequest):
        attest.tolerance_for(0)


def test_switch_default_off_three_fields_and_env_activation(monkeypatch):
    assert attest.feature_enabled() is False
    spec = features.get("supply.attestation.enabled")
    assert spec.owner == "lead"
    assert spec.expire_at.isoformat() == "2026-12-31"
    assert spec.default is False
    assert "只读" in spec.rollback_rule and "账本" in spec.rollback_rule
    assert features.WRITE_SURFACE == ()
    monkeypatch.setenv("DJB_ATTEST", "1")
    assert attest.feature_enabled() is True
    monkeypatch.setenv("DJB_ATTEST", "0")
    assert attest.feature_enabled() is False


def test_feature_off_write_paths_fail_closed(conn, now, fixed_tokenizer):
    with pytest.raises(FeatureUnavailable) as excinfo:
        _issue(conn, now)
    assert excinfo.value.status_code == 503
    assert excinfo.value.code == 50001
    assert excinfo.value.reason == "feature_disabled"
    # 读接口只读可用
    assert attest.list_attestations(conn, now=now)["items"] == []
    assert attest.is_attested(conn, NODE, MODEL, now=now) is False


def test_tokenizer_unwired_fails_closed(conn, now, feature_on):
    with pytest.raises(TokenizerUnavailable) as excinfo:
        _issue(conn, now)
    assert excinfo.value.status_code == 503
    assert excinfo.value.code == 50001
    assert excinfo.value.reason == "tokenizer_unavailable"
    assert providers.is_wired() is False


def test_tokenizer_invalid_return_is_rejected(conn, now, feature_on):
    providers.set_token_counter(lambda prompt, model: 0, version="bad-1")
    with pytest.raises(TokenizerUnavailable):
        _issue(conn, now)
    providers.set_token_counter(lambda prompt, model: "12", version="bad-2")  # type: ignore[arg-type,return-value]
    with pytest.raises(TokenizerUnavailable):
        _issue(conn, now)


# ───────────────────────────────────────────────────────── 挑战
def test_issue_challenge_shape_ttl_and_synthetic_prompt(conn, now, feature_on,
                                                       fixed_tokenizer):
    payload = _issue(conn, now)
    assert set(payload) == {"challenge_id", "model", "upstream_id", "prompt", "nonce",
                            "expires_at"}
    assert payload["model"] == MODEL
    assert payload["upstream_id"] is None
    assert payload["expires_at"] == "2026-10-24T00:05:00.000Z"
    assert payload["nonce"] in payload["prompt"]
    assert any(payload["prompt"].startswith(item) for item in facts.SYNTHETIC_PROMPTS)
    row = conn.execute(
        "SELECT prompt_tokens, state, expires_at - created_at FROM attestation_challenges"
    ).fetchone()
    assert row[0] == 100 and row[1] == "issued" and row[2] == timedelta(minutes=5)
    event = conn.execute("SELECT event, actor FROM attestation_events").fetchone()
    assert tuple(event) == ("challenge_issued", "node:" + NODE)


def test_challenges_are_unique_per_issue(conn, now, feature_on, fixed_tokenizer):
    first = _issue(conn, now)
    second = _issue(conn, now)
    assert first["challenge_id"] != second["challenge_id"]
    assert first["nonce"] != second["nonce"]
    assert first["prompt"] != second["prompt"]


def test_prompt_contains_no_user_data_markers(conn, now, feature_on, fixed_tokenizer):
    prompt = _issue(conn, now)["prompt"]
    lowered = prompt.lower()
    # 真正的泄漏信号（邮箱 / 电话 / 凭据形态）；"no user data" 是探针自述，不算泄漏
    for marker in ("@", "email", "phone", "api_key", "sk-", "password", "secret"):
        assert marker not in lowered
    assert len(prompt) <= facts.PROMPT_MAX_LEN


# ───────────────────────────────────────────────────────── 证据 → 定级
def test_server_verified_match_grades_l3(conn, now, feature_on, fixed_tokenizer):
    challenge = _issue(conn, now)
    out = _submit(conn, now, challenge, usage=100)
    hold = out["attestation"]
    assert set(hold) == {"id", "node_id", "upstream_id", "model", "level", "state",
                         "source", "tokenizer_version", "evidence_ref", "verified_at",
                         "expires_at"}
    assert hold["level"] == "L3" and hold["state"] == "active"
    assert hold["source"] == "server_challenge"
    assert hold["tokenizer_version"] == "fixed-1"
    assert hold["evidence_ref"] == "challenge:" + challenge["challenge_id"]
    assert hold["expires_at"] == "2026-10-31T00:00:00.000Z"        # L3 TTL 7d
    assert set(out["event"]) == {"event_id", "event", "level", "created_at"}
    assert out["event"]["event"] == "level_up" and out["event"]["level"] == "L3"
    assert attest.attestation_level(conn, NODE, MODEL, now=now) == "L3"
    assert attest.is_attested(conn, NODE, MODEL, now=now) is True


def test_tolerance_boundary_l3_vs_l2(conn, now, feature_on, fixed_tokenizer):
    first = _issue(conn, now)
    out = _submit(conn, now, first, usage=101)                     # 边界内（容差 1）
    assert out["attestation"]["level"] == "L3"

    second = _issue(conn, now, node="node-boundary")
    out = _submit(conn, now, second, usage=102, node="node-boundary",
                  model=MODEL)                                     # 超容差 → L2
    assert out["attestation"]["level"] == "L2"
    assert out["event"]["event"] == "tokenizer_mismatch"
    detail = conn.execute(
        "SELECT detail FROM attestation_events WHERE event = 'tokenizer_mismatch'"
    ).fetchone()[0]
    assert detail["prompt_tokens"] == 100 and detail["usage_prompt_tokens"] == 102
    assert detail["diff"] == 2 and detail["tolerance"] == 1
    assert detail["reason"] == "tokenizer_mismatch"


def test_client_cannot_self_claim_l3(conn, now, feature_on, fixed_tokenizer):
    challenge = _issue(conn, now)
    out = _submit(conn, now, challenge, result="tokenizer_match", usage=140)
    assert out["attestation"]["level"] == "L2"                     # 服务端比对说了算
    assert out["event"]["event"] == "tokenizer_mismatch"


def test_missing_usage_grades_l2_and_l1(conn, now, feature_on, fixed_tokenizer):
    inference = _issue(conn, now)
    out = _submit(conn, now, inference, result="inference_ok", usage=None)
    assert out["attestation"]["level"] == "L2"
    assert out["attestation"]["expires_at"] == "2026-10-25T00:00:00.000Z"   # L2 24h
    assert out["event"]["event"] == "level_up"       # 首次定级（从无到 L2）即 level_up

    reachable = _issue(conn, now, node="node-l1")
    out = _submit(conn, now, reachable, node="node-l1", result="reachable", usage=None)
    assert out["attestation"]["level"] == "L1"


def test_failed_result_registers_l0(conn, now, feature_on, fixed_tokenizer):
    challenge = _issue(conn, now)
    out = _submit(conn, now, challenge, result="failed", usage=None,
                  error_class="upstream_5xx")
    assert out["attestation"]["level"] == "L0"
    assert out["attestation"]["verified_at"] is None
    assert out["event"]["event"] == "failed"
    assert attest.is_attested(conn, NODE, MODEL, now=now) is False


def test_level_only_moves_up(conn, now, feature_on, fixed_tokenizer):
    first = _issue(conn, now)
    _submit(conn, now, first, usage=100)                            # L3
    second = _issue(conn, now)
    out = _submit(conn, now, second, usage=140)                     # 超容差，但不得降级
    assert out["attestation"]["level"] == "L3"
    assert out["event"]["event"] == "tokenizer_mismatch"
    rows = conn.execute(
        "SELECT count(*) FROM model_attestations WHERE state = 'active'").fetchone()[0]
    assert rows == 1


# ───────────────────────────────────────────────────────── 挑战安全
def test_replay_is_rejected(conn, now, feature_on, fixed_tokenizer):
    challenge = _issue(conn, now)
    _submit(conn, now, challenge, usage=100)
    with pytest.raises(Conflict) as excinfo:
        _submit(conn, now, challenge, usage=100)
    assert excinfo.value.code == 40919
    assert excinfo.value.reason == "challenge_consumed"


def test_cross_node_and_cross_model_are_rejected(conn, now, feature_on, fixed_tokenizer):
    challenge = _issue(conn, now)
    with pytest.raises(NotFound):
        _submit(conn, now, challenge, node="node-beta", usage=100)
    with pytest.raises(Conflict) as excinfo:
        _submit(conn, now, challenge, model="openai/gpt-4o-mini", usage=100)
    assert excinfo.value.reason == "challenge_model_mismatch"
    # 跨 node/model 都不应消费掉原挑战
    out = _submit(conn, now, challenge, usage=100)
    assert out["attestation"]["level"] == "L3"


def test_expired_challenge_is_rejected(conn, now, feature_on, fixed_tokenizer):
    challenge = _issue(conn, now)
    later = now + facts.CHALLENGE_TTL + timedelta(seconds=1)
    with pytest.raises(Conflict) as excinfo:
        _submit(conn, later, challenge, usage=100)
    assert excinfo.value.reason == "challenge_expired"
    state = conn.execute("SELECT state FROM attestation_challenges").fetchone()[0]
    assert state == "expired"


@pytest.mark.parametrize("overrides,field", [
    ({"challenge_id": "not-a-uuid"}, "challenge_id"),
    ({"model": ""}, "model"),
    ({"result": "whatever"}, "result"),
    ({"usage_prompt_tokens": -3}, "usage_prompt_tokens"),
    ({"response_hash": "abc"}, "response_hash"),
    ({"latency_ms": -1}, "latency_ms"),
])
def test_evidence_validation(conn, now, feature_on, fixed_tokenizer, overrides, field):
    challenge = _issue(conn, now)
    body = {"challenge_id": challenge["challenge_id"], "model": MODEL,
            "result": "tokenizer_match", "usage_prompt_tokens": 100}
    body.update(overrides)
    with pytest.raises(BadRequest) as excinfo:
        attest.submit_evidence(conn, node_id=NODE, payload=body, now=now)
    assert excinfo.value.code == 40001
    assert excinfo.value.details.get("field") == field


# ───────────────────────────────────────────────────────── TTL / 查询
def test_ttl_expiry_blocks_service_and_records_event(conn, now, feature_on,
                                                     fixed_tokenizer):
    challenge = _issue(conn, now)
    _submit(conn, now, challenge, result="inference_ok", usage=None)  # L2 24h
    assert attest.is_attested(conn, NODE, MODEL, now=now) is False     # L2 < L3
    later = now + timedelta(hours=25)
    assert attest.is_attested(conn, NODE, MODEL, now=later) is False
    result = attest.expire_due(conn, now=later)
    assert result["attestations"] == 1
    state = conn.execute("SELECT state FROM model_attestations").fetchone()[0]
    assert state == "expired"
    assert attest.attestation_level(conn, NODE, MODEL, now=later) is None
    events = [row[0] for row in conn.execute(
        "SELECT event FROM attestation_events ORDER BY event").fetchall()]
    assert events == ["challenge_issued", "expired", "level_up"]


def test_list_attestations_filters_and_pagination(conn, now, feature_on, fixed_tokenizer):
    for index, node in enumerate(("node-a", "node-b", "node-c")):
        challenge = _issue(conn, now, node=node)
        _submit(conn, now, challenge, node=node, usage=100)
    page1 = attest.list_attestations(conn, limit=2, now=now)
    assert len(page1["items"]) == 2 and page1["has_more"] is True
    page2 = attest.list_attestations(conn, limit=2, cursor=page1["next_cursor"], now=now)
    assert len(page2["items"]) == 1 and page2["has_more"] is False
    by_node = attest.list_attestations(conn, node_id="node-b", now=now)
    assert [item["node_id"] for item in by_node["items"]] == ["node-b"]
    by_level = attest.list_attestations(conn, level="L2", now=now)
    assert by_level["items"] == []
    assert set(page1["items"][0]) == {"id", "node_id", "upstream_id", "model", "level",
                                     "state", "source", "tokenizer_version",
                                     "evidence_ref", "verified_at", "expires_at"}


# ───────────────────────────────────────────────────────── 隐私 / 账本边界
def test_events_store_no_prompt_or_body(conn, now, feature_on, fixed_tokenizer):
    challenge = _issue(conn, now)
    _submit(conn, now, challenge, usage=100, response_hash="a" * 64, latency_ms=12)
    detail = conn.execute("SELECT detail FROM attestation_events WHERE event = 'level_up'"
                          ).fetchone()[0]
    allowed = {"result", "prompt_tokens", "usage_prompt_tokens", "diff", "tolerance",
               "insufficient", "response_hash", "latency_ms", "error_class", "reason",
               "action", "tokenizer_version"}
    assert set(detail) <= allowed
    serialized = str(detail)
    assert challenge["prompt"] not in serialized
    assert "challenge nonce" not in serialized
    # 挑战表里的 prompt 是**合成探针**，不是用户正文：长度受限且不含共享前缀以外的内容
    prompt = conn.execute("SELECT prompt FROM attestation_challenges").fetchone()[0]
    assert prompt.startswith(tuple(facts.SYNTHETIC_PROMPTS))


def test_ledger_untouched_by_attestation_flow(conn, now, feature_on, fixed_tokenizer):
    before = ledger_snapshot(conn, facts.LEDGER_TABLES)
    challenge = _issue(conn, now)
    _submit(conn, now, challenge, usage=100)
    _issue(conn, now, node="node-2")                     # 多签发一条挑战
    attest.expire_due(conn, now=now + timedelta(days=8))
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
    hits = [path.name for path in root.glob("*.py")
            if forbidden.search(path.read_text(encoding="utf-8"))]
    assert hits == []
