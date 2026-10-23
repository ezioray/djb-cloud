# SPDX-License-Identifier: Apache-2.0
"""scope=receipt 对账引擎（M09 §6.3）：四类差异 + 重复入账 + 宽限期 + INV-04 幂等。

验收锚点：书侧 100 / 外部 97 → 1 条差异 3，``run.diff_minor = 3``。
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.recon import engine, facts
from reconkit import (FIXED_NOW, fetch_exceptions, fetch_run, list_all_runs, receipt_spec,
                      seed_receipt, seed_usage)


def _run(conn, spec=None, *, deps=None, now=FIXED_NOW):
    results = engine.run(conn, spec or receipt_spec(), deps=deps, now=now)
    assert len(results) == 1
    return results[0]


def test_book_100_external_97_yields_single_exception_of_3(conn) -> None:
    """验收：书 100 / 外部 97 → 1 条差异 3，diff_minor=3（有符号）。"""
    seed_usage(conn, task_id="task-1", amount_minor=100, recorded_at=FIXED_NOW - timedelta(hours=1))
    seed_receipt(conn, task_id="task-1", price_minor=97, receipt_id="rcpt-1",
                 reported_at=FIXED_NOW - timedelta(minutes=50))

    result = engine.run(conn, receipt_spec(), now=FIXED_NOW)[0]
    run = result["run"]
    assert result["duplicate"] is False
    assert run["book_minor"] == 100
    assert run["external_minor"] == 97
    assert run["diff_minor"] == 3
    assert run["status"] == facts.RUN_STATUS_EXCEPTIONS_OPEN
    assert run["matched_count"] == 1
    assert run["unmatched_count"] == 1

    exceptions = fetch_exceptions(conn, str(run["run_id"]))
    assert len(exceptions) == 1
    only = exceptions[0]
    assert only["kind"] == "amount_mismatch"
    assert only["diff_minor"] == 3
    assert only["severity"] == "P2"                     # 3 分 < 100 USD → P2
    assert only["ref_type"] == "task" and only["ref_id"] == "task-1"
    assert only["status"] == "open"
    assert only["sla_due"] == FIXED_NOW + timedelta(days=1)     # P2 = 1 天（facts §7）
    assert run["metrics"]["diff_rate_bps"] == 5000              # 1/2 条 → 50%（S1 指标）
    assert run["metrics"]["diff_rate_target_bps"] == facts.RECEIPT_DIFF_RATE_TARGET_BPS


def test_matched_run_when_amounts_agree(conn) -> None:
    seed_usage(conn, task_id="task-2", amount_minor=5_000, recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(conn, task_id="task-2", price_minor=5_000, receipt_id="rcpt-2",
                 reported_at=FIXED_NOW - timedelta(hours=1))
    result = _run(conn)
    assert result["run"]["status"] == facts.RUN_STATUS_MATCHED
    assert result["run"]["diff_minor"] == 0
    assert result["exception_ids"] == []


def test_only_platform_past_grace_opens_exception(conn) -> None:
    seed_usage(conn, task_id="task-3", amount_minor=50_000,  # 500.00 USD → P1
               recorded_at=FIXED_NOW - timedelta(hours=1))
    result = _run(conn)
    exceptions = fetch_exceptions(conn, str(result["run"]["run_id"]))
    assert [item["kind"] for item in exceptions] == ["only_platform"]
    assert exceptions[0]["diff_minor"] == 50_000
    assert exceptions[0]["severity"] == "P1"             # 100–1,000 USD
    assert exceptions[0]["sla_due"] == FIXED_NOW + timedelta(hours=1)
    assert result["run"]["diff_minor"] == 50_000


def test_only_platform_within_grace_is_in_transit(conn) -> None:
    """宽限期内的「平台有、节点未上报」算在途，不计差异（M09 §6.3）。"""
    seed_usage(conn, task_id="task-4", amount_minor=9_999,
               recorded_at=FIXED_NOW - timedelta(seconds=60))     # grace=300s
    result = _run(conn)
    run = result["run"]
    assert run["status"] == facts.RUN_STATUS_MATCHED
    assert run["diff_minor"] == 0
    assert run["metrics"]["pending_upload"] == 1
    assert fetch_exceptions(conn, str(run["run_id"])) == []


def test_grace_seconds_from_spec_is_honoured(conn) -> None:
    seed_usage(conn, task_id="task-5", amount_minor=100,
               recorded_at=FIXED_NOW - timedelta(minutes=30))
    result = _run(conn, receipt_spec(grace_seconds=3_600))   # 1h 宽限 → 仍在途
    assert result["run"]["status"] == facts.RUN_STATUS_MATCHED
    assert fetch_exceptions(conn, str(result["run"]["run_id"])) == []


def test_only_node_is_structural_p0(conn) -> None:
    """节点上报、平台完全没有 → 平台漏记 / 伪造，结构性 P0（INV-02）。"""
    seed_receipt(conn, task_id="task-6", price_minor=3, receipt_id="rcpt-6",
                 reported_at=FIXED_NOW - timedelta(hours=1))
    result = _run(conn)
    exceptions = fetch_exceptions(conn, str(result["run"]["run_id"]))
    assert [item["kind"] for item in exceptions] == ["only_node"]
    assert exceptions[0]["severity"] == "P0"             # 金额只有 3 分，仍然 P0
    assert exceptions[0]["diff_minor"] == -3
    assert result["run"]["diff_minor"] == -3


def test_duplicate_receipt_is_structural_p0(conn) -> None:
    """同一 task 两张收据 = 重复入账 → P0（库层 CHECK 也钉住 kind→P0）。"""
    seed_usage(conn, task_id="task-7", amount_minor=1_000, recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(conn, task_id="task-7", price_minor=1_000, receipt_id="rcpt-7a",
                 reported_at=FIXED_NOW - timedelta(hours=1))
    seed_receipt(conn, task_id="task-7", price_minor=1_000, receipt_id="rcpt-7b",
                 reported_at=FIXED_NOW - timedelta(minutes=55))
    result = _run(conn)
    kinds = {item["kind"]: item for item in fetch_exceptions(conn, str(result["run"]["run_id"]))}
    assert set(kinds) == {"duplicate_receipt"}
    assert kinds["duplicate_receipt"]["severity"] == "P0"
    assert kinds["duplicate_receipt"]["diff_minor"] == -1_000


def test_signature_bad_is_structural_p0_and_not_double_counted(conn) -> None:
    """签名不可验 → P0；金额不再另计差异（避免同一笔双计）。"""
    seed_usage(conn, task_id="task-8", amount_minor=1_000, recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(conn, task_id="task-8", price_minor=1_000, receipt_id="rcpt-8",
                 reported_at=FIXED_NOW - timedelta(hours=1))

    def verifier(receipt) -> bool:
        return receipt["receipt_id"] != "rcpt-8"

    result = _run(conn, deps=engine.EngineDeps(signature_verifier=verifier))
    exceptions = fetch_exceptions(conn, str(result["run"]["run_id"]))
    assert [item["kind"] for item in exceptions] == ["signature_bad"]
    assert exceptions[0]["severity"] == "P0"
    assert exceptions[0]["diff_minor"] == 0
    assert exceptions[0]["ref_id"] == "rcpt-8"


def test_default_signature_check_rejects_malformed_shape(conn) -> None:
    """默认校验器只做形态检查（M09 不持有 M05 密钥），畸形签名即 P0。"""
    assert engine.default_signature_check({"sig_provider": "hmac-sha256:" + "0" * 64,
                                           "sig_consumer": "hmac-sha256:" + "1" * 64}) is True
    assert engine.default_signature_check({"sig_provider": "bad", "sig_consumer": "bad"}) is False
    assert engine.default_signature_check({}) is False


def test_inv04_replay_returns_existing_run(conn) -> None:
    seed_usage(conn, task_id="task-9", amount_minor=100, recorded_at=FIXED_NOW - timedelta(hours=1))
    seed_receipt(conn, task_id="task-9", price_minor=97, receipt_id="rcpt-9",
                 reported_at=FIXED_NOW - timedelta(minutes=30))
    first = engine.run(conn, receipt_spec(), now=FIXED_NOW)[0]
    second = engine.run(conn, receipt_spec(), now=FIXED_NOW)[0]
    assert second["duplicate"] is True
    assert second["run"]["run_id"] == first["run"]["run_id"]
    assert len(list_all_runs(conn)) == 1
    assert len(fetch_exceptions(conn, str(first["run"]["run_id"]))) == 1


def test_trigger_event_id_replay_returns_existing_run(conn) -> None:
    """同一 trigger_event_id 第二次触发 → 返回既有批次（事件重放幂等）。"""
    seed_usage(conn, task_id="task-10", amount_minor=100, recorded_at=FIXED_NOW - timedelta(hours=1))
    first = engine.run(conn, receipt_spec(trigger_event_id="evt-1"), now=FIXED_NOW)[0]
    # 换一个 cutoff 会让 INV-04 键变新；但 unique(trigger_event_id) 仍应挡住重复落库
    other = receipt_spec(cutoff=FIXED_NOW + timedelta(minutes=5), trigger_event_id="evt-1")
    second = engine.run(conn, other, now=FIXED_NOW + timedelta(minutes=5))[0]
    assert second["duplicate"] is True
    assert str(second["run"]["run_id"]) == str(first["run"]["run_id"])
    assert len(list_all_runs(conn)) == 1


def test_all_five_scopes_are_registered(conn) -> None:
    """S2：chain / psp / bank 已实现（不再 deferred），五个 scope 都有 planner。"""
    assert facts.SCOPES_DEFERRED == ()
    assert set(facts.SCOPES_IMPLEMENTED) == set(facts.SCOPES)
    assert set(engine.SCOPE_PLANNERS) == set(facts.SCOPES)
    # 空 schema 的 chain 扫描是纯读、可落 run：不抛 ScopeNotImplemented、不返回假数据
    from app.recon import models

    spec = models.RunSpec(scope="chain", period_start=FIXED_NOW - timedelta(days=1),
                          period_end=FIXED_NOW, cutoff_at=FIXED_NOW)
    results = engine.run(conn, spec, now=FIXED_NOW)
    assert len(results) == 1
    assert results[0]["run"]["scope"] == "chain"
    assert results[0]["run"]["status"] == facts.RUN_STATUS_MATCHED


def test_period_bounds_exclude_outside_rows(conn) -> None:
    """期间是半开区间 [start, end)：区间外的用量 / 收据不参与本次对账。"""
    seed_usage(conn, task_id="task-11", amount_minor=999,
               recorded_at=FIXED_NOW - timedelta(days=2))    # 期间外
    seed_usage(conn, task_id="task-12", amount_minor=100,
               recorded_at=FIXED_NOW - timedelta(hours=1))
    seed_receipt(conn, task_id="task-12", price_minor=100, receipt_id="rcpt-12",
                 reported_at=FIXED_NOW - timedelta(minutes=30))
    result = _run(conn)
    assert result["run"]["book_minor"] == 100
    assert result["run"]["status"] == facts.RUN_STATUS_MATCHED
    assert result["exception_ids"] == []


def test_scan_is_pure_read(conn) -> None:
    """``engine.plan`` 只读：扫描不写任何 M09 表。"""
    seed_usage(conn, task_id="task-13", amount_minor=100, recorded_at=FIXED_NOW - timedelta(hours=1))
    plans = engine.plan(conn, receipt_spec(), now=FIXED_NOW)
    assert len(plans) == 1
    assert plans[0].observation.unmatched_count == 1
    assert list_all_runs(conn) == []
