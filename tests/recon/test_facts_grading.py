# SPDX-License-Identifier: AGPL-3.0-or-later
"""纯函数层：分级 / SLA / 账龄 / 请求解析 / 游标 / 幂等指纹（不需要 DJB_DSN）。"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.recon import clock, errors, facts, grading, models


# ───────────────────────────────────────────────────────────── 分级（03-facts §7）
@pytest.mark.parametrize("diff_minor,expected", [
    (0, "P2"),
    (1, "P2"),
    (9_999, "P2"),          # < 100 USD
    (10_000, "P1"),         # 100.00 整 → P1（「100–1,000」含下端点）
    (99_999, "P1"),
    (100_000, "P1"),        # 1,000.00 整 → P1（P0 是严格大于）
    (100_001, "P0"),        # > 1,000 USD
    (-100_001, "P0"),       # 有符号：绝对值跌破阈值同样 P0
    (-9_999, "P2"),
])
def test_classify_amount_tiers(diff_minor: int, expected: str) -> None:
    assert grading.classify(diff_minor, kind="amount_mismatch") == expected


@pytest.mark.parametrize("kind", sorted(facts.STRUCTURAL_KINDS))
def test_structural_kinds_are_p0_regardless_of_amount(kind: str) -> None:
    """INV-02：结构性差异一律 P0，与金额无关（0 分也是 P0）。"""
    assert grading.is_structural(kind) is True
    assert grading.classify(0, kind=kind) == "P0"
    assert grading.classify(-1, kind=kind) == "P0"


def test_non_structural_kind_is_not_p0_by_name() -> None:
    assert grading.is_structural("amount_mismatch") is False
    assert grading.classify(1, kind="amount_mismatch") == "P2"


def test_classify_rejects_non_integer() -> None:
    with pytest.raises(TypeError):
        grading.classify(1.5, kind="amount_mismatch")        # noqa: F841 - 显式拒绝浮点
    with pytest.raises(TypeError):
        grading.classify(True, kind="amount_mismatch")       # noqa: F841 - bool 不是整数


def test_sla_windows_follow_facts_seven() -> None:
    raised = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)
    assert grading.sla_due(raised, "P0") == raised + timedelta(minutes=15)
    assert grading.sla_due(raised, "P1") == raised + timedelta(hours=1)
    assert grading.sla_due(raised, "P2") == raised + timedelta(days=1)
    with pytest.raises(ValueError):
        grading.sla_due(raised, "P9")


def test_classify_and_schedule_is_consistent() -> None:
    raised = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)
    severity, due = grading.classify_and_schedule(150_000, kind="only_node", raised_at=raised)
    assert (severity, due) == ("P0", grading.sla_due(raised, "P0"))


def test_age_buckets() -> None:
    now = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)
    assert grading.age_bucket(now - timedelta(minutes=30), now) == "0-1"
    assert grading.age_bucket(now - timedelta(days=2), now) == "1-3"
    assert grading.age_bucket(now - timedelta(days=5), now) == "3-7"
    assert grading.age_bucket(now - timedelta(days=10), now) == "7-30"
    assert grading.age_bucket(now - timedelta(days=90), now) == "30+"
    assert grading.age_bucket(now + timedelta(days=1), now) == "0-1"     # 时钟回拨按 0 算


# ───────────────────────────────────────────────────────────── 时钟 / 周期
def test_clock_month_and_bounds() -> None:
    assert clock.month_of(datetime(2026, 10, 23, tzinfo=timezone.utc)) == "2026-10"
    assert clock.day_of(datetime(2026, 10, 23, 23, 59, tzinfo=timezone.utc)) == "2026-10-23"
    start, end = clock.parse_month("2026-12")
    assert start == datetime(2026, 12, 1, tzinfo=timezone.utc)
    assert end == datetime(2027, 1, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("bad", ["2026-13", "2026-00", "26-10", "2026/10", "2026-1", "", "abcd-ef"])
def test_parse_month_rejects_garbage(bad: str) -> None:
    with pytest.raises(errors.BadRequest):
        clock.parse_month(bad)


def test_parse_datetime_accepts_z_and_offset() -> None:
    assert clock.parse_datetime("2026-10-23T09:00:00Z", field="t") == \
        datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)
    assert clock.parse_datetime("2026-10-23T17:00:00+08:00", field="t") == \
        datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)
    with pytest.raises(errors.BadRequest):
        clock.parse_datetime("not-a-date", field="t")
    with pytest.raises(errors.BadRequest):
        clock.parse_datetime(None, field="t")


def test_iso_formats_are_stable() -> None:
    moment = datetime(2026, 10, 23, 9, 0, 0, 123456, tzinfo=timezone.utc)
    assert clock.iso_micros(moment) == "2026-10-23T09:00:00.123456Z"
    assert clock.iso(moment.replace(microsecond=0)) == "2026-10-23T09:00:00Z"


# ───────────────────────────────────────────────────────────── 请求解析
def test_parse_run_spec_defaults() -> None:
    spec = models.parse_run_spec({
        "scope": "receipt",
        "period_start": "2026-10-22T00:00:00Z",
        "period_end": "2026-10-23T00:00:00Z",
    })
    assert spec.scope == "receipt"
    assert spec.grace_seconds == facts.DEFAULT_GRACE_SECONDS
    assert spec.rule_version == facts.RULE_VERSION
    # cutoff_at 缺省 = 触发时刻（不是 period_end）：显式给了才用给的
    fixed = models.parse_run_spec({
        "scope": "receipt",
        "period_start": "2026-10-22T00:00:00Z",
        "period_end": "2026-10-23T00:00:00Z",
        "cutoff_at": "2026-10-23T00:00:00Z",
    })
    assert fixed.cutoff_at == datetime(2026, 10, 23, tzinfo=timezone.utc)
    assert spec.cutoff_at >= fixed.cutoff_at


def test_parse_run_spec_rejects_bad_scope_and_period() -> None:
    base = {"scope": "receipt", "period_start": "2026-10-22T00:00:00Z",
            "period_end": "2026-10-23T00:00:00Z"}
    with pytest.raises(errors.BadRequest):
        models.parse_run_spec({**base, "scope": "chain2"})
    with pytest.raises(errors.BadRequest):
        models.parse_run_spec({**base, "period_end": "2026-10-21T00:00:00Z"})
    with pytest.raises(errors.BadRequest):
        models.parse_run_spec({**base, "cutoff_at": "2026-10-01T00:00:00Z"})
    with pytest.raises(errors.BadRequest):
        models.parse_run_spec({**base, "grace_seconds": facts.MAX_GRACE_SECONDS + 1})


def test_require_int_rejects_float_and_bool() -> None:
    with pytest.raises(errors.BadRequest):
        models.require_int(1.0, field="x")
    with pytest.raises(errors.BadRequest):
        models.require_int(True, field="x")
    assert models.require_int("12", field="x") == 12
    assert models.require_int(None, field="x", required=False) is None
    with pytest.raises(errors.BadRequest):
        models.require_int(3, field="x", minimum=5)


def test_parse_sign_off_and_resolve() -> None:
    assert models.parse_sign_off(None).attestation_id is None
    assert models.parse_sign_off({"reviewer_note": " ok "}).reviewer_note == "ok"
    resolved = models.parse_resolve({"resolution_code": "external_fix",
                                     "root_cause": "bank typo"})
    assert resolved.resolution_code == "external_fix"
    assert resolved.resolution_journal_id is None
    with pytest.raises(errors.BadRequest):
        models.parse_resolve({"resolution_code": "unknown"})


def test_parse_attestation_validates_shapes() -> None:
    payload = {
        "period_start": "2026-10-01T00:00:00Z",
        "period_end": "2026-10-31T00:00:00Z",
        "ledger_root": "a" * 64,
        "batch_hash": "b" * 32,
        "payable_total_minor": 1234,
        "signature_ref": "hsm:key-1:0001",
    }
    draft = models.parse_attestation(payload, idempotency_key="k" * 16)
    assert draft.payable_total_minor == 1234
    assert draft.idempotency_key == "k" * 16

    with pytest.raises(errors.BadRequest):
        models.parse_attestation({**payload, "ledger_root": "not-hex"})
    with pytest.raises(errors.BadRequest):
        models.parse_attestation({**payload, "batch_hash": "zz"})
    with pytest.raises(errors.BadRequest):
        models.parse_attestation({**payload, "payable_total_minor": -1})
    with pytest.raises(errors.BadRequest):
        models.parse_attestation({**payload, "period_end": payload["period_start"]})


def test_require_idempotency_key_length_bounds() -> None:
    assert models.require_idempotency_key(None) is None
    assert models.require_idempotency_key("   ") is None
    assert models.require_idempotency_key("k" * 16) == "k" * 16
    with pytest.raises(errors.BadRequest):
        models.require_idempotency_key("short")
    with pytest.raises(errors.BadRequest):
        models.require_idempotency_key("k" * 200)


# ───────────────────────────────────────────────────────────── 游标 / 指纹 / 标识
def test_cursor_roundtrip() -> None:
    moment = datetime(2026, 10, 23, 9, 0, 0, 500000, tzinfo=timezone.utc)
    identity = str(uuid.uuid4())
    cursor = models.encode_cursor(moment, identity)
    assert models.decode_cursor(cursor) == (moment, identity)
    assert models.decode_cursor(None) is None
    assert models.decode_cursor("") is None


def test_cursor_rejects_garbage() -> None:
    with pytest.raises(errors.BadRequest):
        models.decode_cursor("!!!!")
    with pytest.raises(errors.BadRequest):
        models.decode_cursor("a" * 600)
    with pytest.raises(errors.BadRequest):
        models.decode_cursor(models._b64encode(b"no-separator"))


def test_fingerprint_is_stable_within_bucket() -> None:
    body = {"a": 1, "b": [2, 3]}
    now = datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc)
    first = models.fingerprint(body, now=now)
    second = models.fingerprint(json.loads(json.dumps(body)), now=now + timedelta(seconds=30))
    different = models.fingerprint(body, now=now + timedelta(seconds=400))
    assert first == second
    assert first != different
    assert first.startswith("fp:")


def test_uuid7_is_time_ordered() -> None:
    early = models.uuid7(datetime(2026, 10, 23, 9, 0, tzinfo=timezone.utc))
    late = models.uuid7(datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc))
    assert early.version == 7 and late.version == 7
    assert str(early) < str(late)
