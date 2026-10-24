# SPDX-License-Identifier: AGPL-3.0-or-later
"""verify / seal（需要 DJB_DSN）：篡改必报、不修链、日根幂等、断链拒绝封盘。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.audit import clock, errors, facts, merkle, models, store, verify
from infrakit import scalar

NOW = datetime(2026, 10, 23, 9, 0, 0, tzinfo=timezone.utc)


def draft(**overrides):
    body = {"actor": "infra-seat", "actor_type": "agent", "role": "INFRA",
            "action": "read.report", "target": "nas/guard"}
    body.update(overrides)
    return models.draft_from_request(body, now=NOW)


def append(connection, key_provider, *, now=NOW, **overrides):
    return store.append(connection, draft(**overrides), key_provider=key_provider, now=now,
                        trace_id="test-trace")


def tamper(connection, sql: str, params: tuple = ()) -> None:
    """模拟"有库权限的人"篡改：临时关掉护栏触发器改一行（verify 必须发现）。"""
    connection.execute("ALTER TABLE audit_log DISABLE TRIGGER USER")
    connection.execute(sql, params)
    connection.execute("ALTER TABLE audit_log ENABLE TRIGGER USER")


# --------------------------------------------------------------------------- 干净链
def test_verify_empty_chain_is_ok(conn, key_provider):
    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW)
    assert result["ok"] is True
    assert result["entries"] == 0
    assert result["merkle_root"] == merkle.EMPTY_ROOT
    assert result["sealed"] is False
    assert result["broken_seq"] is None
    assert result["period"] == "2026-10-23"
    assert result["alg"] == facts.ALG


def test_verify_clean_chain_reports_merkle_root(conn, key_provider):
    hashes = [append(conn, key_provider, target=f"t{index}")["entry"]["hash"]
              for index in range(3)]
    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW)
    assert result["ok"] is True
    assert result["entries"] == 3
    assert result["period_entries"] == 3
    assert result["merkle_root"] == merkle.merkle_root(hashes)
    assert result["problems"] == []


# --------------------------------------------------------------------------- 篡改必报
def test_tampered_entry_is_reported_and_not_repaired(conn, key_provider):
    for index in range(3):
        append(conn, key_provider, target=f"t{index}")
    tamper(conn, "UPDATE audit_log SET target = 'rewritten' WHERE seq = 2")

    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW)
    assert result["ok"] is False
    assert result["broken_seq"] == 2
    assert any("哈希不匹配" in problem for problem in result["problems"])
    # 不修链：被改的那一行必须原样保留（verify 只读）
    assert scalar(conn, "SELECT target FROM audit_log WHERE seq = 2") == "rewritten"
    assert scalar(conn, "SELECT hash FROM audit_log WHERE seq = 2") is not None


def test_tampered_prev_hash_is_reported(conn, key_provider):
    for index in range(2):
        append(conn, key_provider, target=f"t{index}")
    tamper(conn, "UPDATE audit_log SET prev_hash = %s WHERE seq = 2", ("0" * 64,))
    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW)
    assert result["ok"] is False
    assert result["broken_seq"] == 2


def test_deleted_row_breaks_the_chain(conn, key_provider):
    for index in range(3):
        append(conn, key_provider, target=f"t{index}")
    tamper(conn, "DELETE FROM audit_log WHERE seq = 2")
    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW)
    assert result["ok"] is False
    assert result["broken_seq"] == 3
    assert any("prev_hash 断链" in problem for problem in result["problems"])


def test_algorithm_relabelled_is_reported(conn, key_provider):
    append(conn, key_provider)
    # 库约束本身也挡降级（下面会验证）；这里模拟"有 DDL 权限的攻击者先把约束摘了"
    conn.execute("ALTER TABLE audit_log DROP CONSTRAINT audit_log_alg_ck")
    tamper(conn, "UPDATE audit_log SET alg = 'sha256' WHERE seq = 1")
    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW)
    assert result["ok"] is False
    assert any("算法不一致" in problem for problem in result["problems"])


# --------------------------------------------------------------------------- 密钥缺失
def test_missing_key_does_not_silently_pass(conn, key_provider):
    from app.audit import StaticKeyProvider

    append(conn, key_provider)
    result = verify.verify_chain(conn, key_provider=StaticKeyProvider(None), now=NOW)
    assert result["ok"] is False
    assert result["entries"] == 1                       # 条目数照报
    assert any("密钥不可用" in problem for problem in result["problems"])
    assert result["sealed"] is False


# --------------------------------------------------------------------------- 封盘
def test_seal_writes_anchor_and_is_idempotent(conn, key_provider):
    hashes = [append(conn, key_provider, target=f"t{index}")["entry"]["hash"]
              for index in range(2)]
    first = verify.verify_chain(conn, key_provider=key_provider, now=NOW, seal=True)
    assert first["sealed"] is True
    assert first["merkle_root"] == merkle.merkle_root(hashes)
    anchor = store.get_anchor(conn, "2026-10-23")
    assert anchor["merkle_root"] == first["merkle_root"]
    assert anchor["entry_count"] == 2
    assert anchor["first_seq"] == 1 and anchor["last_seq"] == 2
    assert anchor["alg"] == facts.ALG

    second = verify.verify_chain(conn, key_provider=key_provider, now=NOW + timedelta(hours=1),
                                 seal=True)
    assert second["sealed"] is True
    assert second["merkle_root"] == first["merkle_root"]     # 同日返回同一根
    assert scalar(conn, "SELECT count(*) FROM audit_anchors") == 1


def test_seal_uses_utc_day_boundary(conn, key_provider):
    early = datetime(2026, 10, 20, 23, 59, 59, tzinfo=timezone.utc)
    late = datetime(2026, 10, 21, 0, 0, 1, tzinfo=timezone.utc)
    first = append(conn, key_provider, now=early, target="day-1")
    second = append(conn, key_provider, now=late, target="day-2")

    day_one = verify.verify_chain(conn, key_provider=key_provider, period="2026-10-20",
                                  now=NOW, seal=True)
    assert day_one["sealed"] is True
    assert day_one["period"] == "2026-10-20"
    assert day_one["period_entries"] == 1
    assert day_one["merkle_root"] == first["entry"]["hash"]   # 单叶 = 叶子本身

    empty_day = verify.verify_chain(conn, key_provider=key_provider, period="2026-10-19",
                                    now=NOW, seal=True)
    assert empty_day["sealed"] is True
    assert empty_day["merkle_root"] == merkle.EMPTY_ROOT
    assert store.get_anchor(conn, "2026-10-19")["entry_count"] == 0

    day_two = verify.verify_chain(conn, key_provider=key_provider, period="2026-10-21",
                                  now=NOW, seal=True)
    assert day_two["merkle_root"] == second["entry"]["hash"]


def test_seal_is_refused_when_chain_is_broken(conn, key_provider):
    append(conn, key_provider)
    tamper(conn, "UPDATE audit_log SET actor = 'intruder' WHERE seq = 1")
    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW, seal=True)
    assert result["ok"] is False
    assert result["sealed"] is False
    assert any("拒绝封盘" in problem for problem in result["problems"])
    assert scalar(conn, "SELECT count(*) FROM audit_anchors") == 0


def test_anchor_mismatch_is_reported_after_late_entries(conn, key_provider):
    append(conn, key_provider, target="first")
    sealed = verify.verify_chain(conn, key_provider=key_provider, now=NOW, seal=True)
    assert sealed["sealed"] is True

    append(conn, key_provider, target="late")            # 封盘后又来了一条（同日）
    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW, seal=True)
    assert result["ok"] is False
    assert result["sealed"] is False
    assert any("已封盘的 Merkle 根与重算不一致" in problem for problem in result["problems"])
    # 既有锚点不被覆盖
    assert store.get_anchor(conn, "2026-10-23")["merkle_root"] == sealed["merkle_root"]


# --------------------------------------------------------------------------- 参数与超时
@pytest.mark.parametrize("period", ["2026-13-01", "20261023", "2026-10-23T00:00:00Z", 20261023])
def test_bad_period_is_rejected(conn, key_provider, period):
    with pytest.raises(errors.InvalidArgument):
        verify.verify_chain(conn, key_provider=key_provider, period=period, now=NOW)


def test_expected_alg_downgrade_is_rejected(conn, key_provider):
    with pytest.raises(errors.InvalidArgument):
        verify.verify_chain(conn, key_provider=key_provider, expected_alg="sha256", now=NOW)


def test_pending_approval_timeout_is_reported(conn, key_provider):
    append(conn, key_provider, action="authorize.window", target="REL-0001",
           reason_code="R-OK", ticket="REL-0001", before={"a": 1}, after={"a": 2},
           status="pending_approval",
           approval_chain=[{"actor": "lead", "decision": "propose"},
                           {"actor": "release-manager", "decision": "approve"}])
    fresh = verify.verify_chain(conn, key_provider=key_provider,
                                now=NOW + timedelta(hours=1))
    assert fresh["ok"] is True
    assert fresh["expired_pending"] == 0

    late = verify.verify_chain(conn, key_provider=key_provider, now=NOW + timedelta(hours=5))
    assert late["ok"] is False
    assert late["expired_pending"] == 1
    assert any("超时" in problem for problem in late["problems"])


def test_checked_at_uses_injected_clock(conn, key_provider):
    result = verify.verify_chain(conn, key_provider=key_provider, now=NOW)
    assert result["checked_at"] == clock.iso_micros(NOW)


# --------------------------------------------------------------------------- 内部小工具
def test_as_datetime_accepts_datetimes_strings_and_rejects_garbage():
    from app.audit.verify import _as_datetime

    assert _as_datetime(NOW) == NOW
    assert _as_datetime("2026-10-23T09:00:00Z") == NOW
    assert _as_datetime("2026-10-23T17:00:00+08:00") == NOW
    assert _as_datetime("not-a-time") is None
    assert _as_datetime(None) is None


def test_event_payload_validation_rejects_missing_keys():
    from app.audit import events

    with pytest.raises(ValueError):
        events.validate_payload({"audit_id": "x"})
    events.validate_payload({"audit_id": "x", "actor": "a", "action": "b", "hash": "h", "seq": 1})
