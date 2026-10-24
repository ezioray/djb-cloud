# SPDX-License-Identifier: AGPL-3.0-or-later
"""用量汇总 / 明细：口径、分页、过滤（需要 DJB_DSN）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from app.metering import errors, facts, models, usage
from meterkit import NOW, connect, fetch_all


def _seed_usage(schema: str, *, account_id, model: str = "m1", amount_minor: int = 125,
                tokens_in: int = 1000, tokens_out: int = 500, recorded_at=NOW,
                state: str = "recorded", attempt_no: int = 1, access: str = "A1") -> str:
    """直接落一条 usage（批量造数用；生产路径见 test_receipts）。"""
    usage_id = str(models.uuid7(recorded_at))
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    receipt_id = f"rcpt_{uuid.uuid4().hex[:12]}"
    with connect(schema) as conn:
        # 新行只能 state=recorded（insert 护栏），终态必须经状态机迁移
        conn.execute(
            """INSERT INTO usage_records
                 (usage_id, request_id, attempt_no, account_id, node_id, model, access,
                  tokens_in, tokens_out, usage_amount, usage_unit, amount_minor, usage_source,
                  state, receipt_id, recorded_at)
               VALUES (%s,%s,%s,%s,'n1',%s,%s,%s,%s,%s,'token',%s,'dual','recorded',%s,%s)""",
            (usage_id, request_id, attempt_no, account_id, model, access, tokens_in, tokens_out,
             str(tokens_in + tokens_out), amount_minor, receipt_id, recorded_at))
        if state == "settled":
            conn.execute("UPDATE usage_records SET state='settled', settled_at=%s "
                         "WHERE usage_id=%s", (NOW, usage_id))
    return usage_id


# ─────────────────────────────────────────────────────── 汇总
def test_summary_groups_by_model(migrated, account):
    _seed_usage(migrated, account_id=account, model="m-alpha", amount_minor=100,
                tokens_in=10, tokens_out=5)
    _seed_usage(migrated, account_id=account, model="m-alpha", amount_minor=50,
                tokens_in=20, tokens_out=5)
    _seed_usage(migrated, account_id=account, model="m-beta", amount_minor=25,
                tokens_in=7, tokens_out=3)
    with connect(migrated) as conn:
        payload = usage.summary(conn, account_id=str(account), date_from=NOW - timedelta(days=1),
                                date_to=NOW + timedelta(days=1), group_by="model")

    assert payload["group_by"] == "model"
    assert payload["period"]["from"].endswith("Z") and payload["period"]["to"].endswith("Z")
    assert payload["totals"] == {"requests": 3, "prompt_tokens": 37, "completion_tokens": 13,
                                 "billable": {"amount": "1.75", "unit": "USD"}}
    groups = {group["key"]: group for group in payload["groups"]}
    assert set(groups) == {"m-alpha", "m-beta"}
    assert groups["m-alpha"]["requests"] == 2
    assert groups["m-alpha"]["tokens"] == 40
    assert groups["m-alpha"]["billable"]["amount"] == "1.50"
    assert groups["m-beta"]["billable"]["amount"] == "0.25"


def test_summary_groups_by_utc_day(migrated, account):
    day1 = NOW - timedelta(days=1)
    day2 = NOW
    _seed_usage(migrated, account_id=account, recorded_at=day1, amount_minor=10)
    _seed_usage(migrated, account_id=account, recorded_at=day2, amount_minor=20)
    with connect(migrated) as conn:
        payload = usage.summary(conn, account_id=str(account), date_from=day1 - timedelta(hours=1),
                                date_to=day2, group_by="day")
    keys = [group["key"] for group in payload["groups"]]
    assert keys == sorted(keys)
    assert str(day1.date()) in keys and str(day2.date()) in keys


def test_summary_respects_period_and_account(migrated, account):
    other = uuid.uuid4()
    _seed_usage(migrated, account_id=account, amount_minor=100, recorded_at=NOW)
    _seed_usage(migrated, account_id=account, amount_minor=999,
                recorded_at=NOW - timedelta(days=10))
    _seed_usage(migrated, account_id=other, amount_minor=777, recorded_at=NOW)
    with connect(migrated) as conn:
        payload = usage.summary(conn, account_id=str(account), date_from=NOW - timedelta(days=1),
                                date_to=NOW, group_by="model")
    assert payload["totals"]["requests"] == 1
    assert payload["totals"]["billable"]["amount"] == "1.00"


def test_summary_day_end_boundary_is_inclusive(migrated, account):
    """``to`` 传日期时按当日末含端点（spec From/To「含端点」）。"""
    _seed_usage(migrated, account_id=account, amount_minor=42, recorded_at=NOW)
    with connect(migrated) as conn:
        payload = usage.summary(conn, account_id=str(account), date_from=str(NOW.date()),
                                date_to=str(NOW.date()), group_by="model")
    assert payload["totals"]["billable"]["amount"] == "0.42"


def test_summary_rejects_bad_group_by(migrated, account):
    with connect(migrated) as conn:
        with pytest.raises(errors.InvalidArgument) as exc:
            usage.summary(conn, account_id=str(account), date_from=NOW, date_to=NOW,
                          group_by="tenant")
    assert exc.value.code == "40001"


def test_summary_rejects_reversed_period(migrated, account):
    with connect(migrated) as conn:
        with pytest.raises(errors.InvalidArgument):
            usage.summary(conn, account_id=str(account), date_from=NOW,
                          date_to=NOW - timedelta(days=1), group_by="model")


# ─────────────────────────────────────────────────────── 明细（游标分页）
def test_records_default_page_size_and_cursor(migrated, account):
    for index in range(facts.DEFAULT_PAGE_SIZE + 5):
        _seed_usage(migrated, account_id=account, amount_minor=index,
                    recorded_at=NOW - timedelta(minutes=index))
    with connect(migrated) as conn:
        first = usage.records_page(conn, account_id=str(account))
        assert len(first["data"]) == facts.DEFAULT_PAGE_SIZE
        assert first["page"]["has_more"] is True
        assert first["page"]["cursor"] == ""
        next_cursor = first["page"]["next_cursor"]
        assert next_cursor

        second = usage.records_page(conn, account_id=str(account), cursor=next_cursor)
        assert len(second["data"]) == 5
        assert second["page"]["has_more"] is False
        assert second["page"]["next_cursor"] is None
        first_ids = {item["usage_id"] for item in first["data"]}
        second_ids = {item["usage_id"] for item in second["data"]}
        assert not first_ids & second_ids


def test_records_sorted_by_recorded_at_desc(migrated, account):
    old = _seed_usage(migrated, account_id=account, recorded_at=NOW - timedelta(hours=2))
    new = _seed_usage(migrated, account_id=account, recorded_at=NOW)
    with connect(migrated) as conn:
        page = usage.records_page(conn, account_id=str(account), limit=10)
    ids = [item["usage_id"] for item in page["data"]]
    assert ids[:2] == [new, old]


def test_records_filters(migrated, account):
    _seed_usage(migrated, account_id=account, model="m-x", state="recorded")
    _seed_usage(migrated, account_id=account, model="m-y", state="settled")
    _seed_usage(migrated, account_id=account, model="m-x", state="settled",
                recorded_at=NOW - timedelta(days=2))
    with connect(migrated) as conn:
        by_model = usage.records_page(conn, account_id=str(account), model="m-x")
        assert all(item["model"] == "m-x" for item in by_model["data"])
        by_state = usage.records_page(conn, account_id=str(account), state="settled")
        assert all(item["state"] == "settled" for item in by_state["data"])
        windowed = usage.records_page(conn, account_id=str(account),
                                      date_from=NOW - timedelta(hours=1), date_to=NOW)
        assert all(item["recorded_at"].endswith("Z") for item in windowed["data"])
        assert len(windowed["data"]) < 3


def test_records_amount_shape_and_no_text_fields(migrated, account):
    _seed_usage(migrated, account_id=account, amount_minor=125)
    with connect(migrated) as conn:
        page = usage.records_page(conn, account_id=str(account))
    item = page["data"][0]
    assert item["amount"] == {"amount": "1.25", "unit": "USD"}
    assert item["state"] == "recorded" and item["correction_id"] is None
    for forbidden in ("prompt", "response", "content"):
        assert forbidden not in item


@pytest.mark.parametrize("limit", [0, -1, facts.MAX_PAGE_SIZE + 1])
def test_records_rejects_out_of_range_limit(migrated, account, limit):
    with connect(migrated) as conn:
        with pytest.raises(errors.InvalidArgument) as exc:
            usage.records_page(conn, account_id=str(account), limit=limit)
    assert exc.value.code == "40001"


def test_records_rejects_bad_state_and_cursor(migrated, account):
    with connect(migrated) as conn:
        with pytest.raises(errors.InvalidArgument):
            usage.records_page(conn, account_id=str(account), state="exploded")
        with pytest.raises(errors.InvalidArgument):
            usage.records_page(conn, account_id=str(account), cursor="not-a-cursor")


def test_records_isolated_by_account(migrated, account):
    other = uuid.uuid4()
    _seed_usage(migrated, account_id=account, amount_minor=1)
    _seed_usage(migrated, account_id=other, amount_minor=2)
    with connect(migrated) as conn:
        page = usage.records_page(conn, account_id=str(account), limit=200)
    assert {item["amount"]["amount"] for item in page["data"]} == {"0.01"}


def test_records_show_corrected_state_with_correction_id(migrated, account):
    """``state=corrected`` 的行带 correction_id，原值不可改（spec UsageRecord 描述）。"""
    usage_id = _seed_usage(migrated, account_id=account, state="recorded")
    with connect(migrated) as conn:
        conn.execute("UPDATE usage_records SET state='corrected', corrected_at=%s, "
                     "correction_id='corr-1' WHERE usage_id=%s", (NOW, usage_id))
        page = usage.records_page(conn, account_id=str(account))
    item = page["data"][0]
    assert item["state"] == "corrected" and item["correction_id"] == "corr-1"
    rows = fetch_all(migrated, "SELECT amount_minor FROM usage_records WHERE usage_id = %s",
                     (usage_id,))
    assert rows[0][0] == 125                       # 原值未改
