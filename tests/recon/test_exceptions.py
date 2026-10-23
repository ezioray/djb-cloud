# SPDX-License-Identifier: Apache-2.0
"""差异台账：列表 / 游标 / 处置码 / 关闭后不可重开 / diff 归零 / 幂等重放。"""
from __future__ import annotations

from datetime import timedelta

from app.recon import engine, facts, models
from reconkit import (FIXED_NOW, fetch_exceptions, fetch_run, post_journal, receipt_spec,
                      seed_receipt, seed_usage, simple_journal_lines)

LIST = "/api/v1/admin/treasury/recon/exceptions"
RESOLVE = "/api/v1/admin/treasury/recon/exceptions/{exception_id}/resolve"
SIGN_OFF = "/api/v1/admin/treasury/recon/runs/{run_id}/sign-off"


def _run_with_exception(conn, *, diff: int = 300, task: str = "task-x",
                        cutoff=FIXED_NOW) -> tuple[dict, dict]:
    seed_usage(conn, task_id=task, amount_minor=diff, recorded_at=cutoff - timedelta(hours=2))
    seed_receipt(conn, task_id=task, price_minor=0, receipt_id=f"rcpt-{task}",
                 reported_at=cutoff - timedelta(hours=1))
    run = engine.run(conn, receipt_spec(cutoff=cutoff), now=cutoff)[0]["run"]
    exception = fetch_exceptions(conn, str(run["run_id"]))[0]
    return run, exception


def test_list_and_filter_exceptions(client, savepoint_conn) -> None:
    run, exception = _run_with_exception(savepoint_conn)
    response = client.get(LIST, params={"run_id": str(run["run_id"])})
    assert response.status_code == 200
    body = response.json()
    assert [item["exception_id"] for item in body["data"]] == [str(exception["exception_id"])]
    assert body["data"][0]["severity"] == "P2"
    assert body["page"]["has_more"] is False

    assert client.get(LIST, params={"severity": "P0"}).json()["data"] == []
    assert len(client.get(LIST, params={"severity": "P2"}).json()["data"]) == 1
    assert len(client.get(LIST, params={"status": "open"}).json()["data"]) == 1
    assert client.get(LIST, params={"severity": "P9"}).status_code == 400
    assert client.get(LIST, params={"status": "nope"}).status_code == 400


def test_exception_pagination_uses_cursor(client, savepoint_conn) -> None:
    # 每个 run 的期间互相不重叠（相隔 2 天），否则早期批次也会把后面造的数据算进去
    for index in range(3):
        _run_with_exception(savepoint_conn, diff=100 + index, task=f"task-page-{index}",
                            cutoff=FIXED_NOW - timedelta(days=2 * index))
    first = client.get(LIST, params={"limit": 2}).json()
    assert len(first["data"]) == 2
    assert first["page"]["has_more"] is True
    second = client.get(LIST, params={"limit": 2,
                                      "cursor": first["page"]["next_cursor"]}).json()
    assert len(second["data"]) == 1
    assert second["page"]["has_more"] is False
    assert {item["exception_id"] for item in first["data"]} & \
           {item["exception_id"] for item in second["data"]} == set()
    assert client.get(LIST, params={"cursor": "!!!"}).status_code == 400


def test_resolve_with_external_fix_closes_and_zeroes_diff(client, savepoint_conn) -> None:
    run, exception = _run_with_exception(savepoint_conn, diff=300)
    response = client.post(
        RESOLVE.format(exception_id=exception["exception_id"]),
        json={"resolution_code": "external_fix", "root_cause": "节点账单口径修正"},
        headers={"X-Admin-Step-Up": "ok"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "closed"
    assert payload["resolution_code"] == "external_fix"
    assert payload["closed_at"] is not None
    assert payload["resolved_by"] == ADMIN_ID
    # INV-01：关完 diff 归零
    assert fetch_run(savepoint_conn, str(run["run_id"]))["diff_minor"] == 0


ADMIN_ID = "admin-maker"


def test_adjust_journal_requires_existing_posted_journal(client, savepoint_conn) -> None:
    run, exception = _run_with_exception(savepoint_conn, diff=300, task="task-j")
    missing = client.post(
        RESOLVE.format(exception_id=exception["exception_id"]),
        json={"resolution_code": "adjust_journal", "root_cause": "补记"},
        headers={"X-Admin-Step-Up": "ok"})
    assert missing.status_code == 409
    assert missing.json()["error"]["code"] == 49204
    assert missing.json()["error"]["reason"] == "journal_id_required"

    bogus = client.post(
        RESOLVE.format(exception_id=exception["exception_id"]),
        json={"resolution_code": "adjust_journal", "root_cause": "补记",
              "resolution_journal_id": "00000000-0000-7000-8000-000000000009"},
        headers={"X-Admin-Step-Up": "ok"})
    assert bogus.status_code == 409
    assert bogus.json()["error"]["reason"] == "journal_not_found"

    # 先用 M06 落一张真实的调整凭证（只写存量表，属测试造数）
    journal_id = post_journal(savepoint_conn, simple_journal_lines(300),
                              ts=FIXED_NOW - timedelta(minutes=10))
    ok = client.post(
        RESOLVE.format(exception_id=exception["exception_id"]),
        json={"resolution_code": "adjust_journal", "root_cause": "补记",
              "resolution_journal_id": journal_id},
        headers={"X-Admin-Step-Up": "ok"})
    assert ok.status_code == 200
    assert ok.json()["resolution_journal_id"] == journal_id


def test_write_off_requires_root_cause(client, savepoint_conn) -> None:
    _, exception = _run_with_exception(savepoint_conn, diff=100, task="task-w")
    response = client.post(RESOLVE.format(exception_id=exception["exception_id"]),
                           json={"resolution_code": "write_off"},
                           headers={"X-Admin-Step-Up": "ok"})
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "root_cause_required"


def test_closed_exception_cannot_be_reopened(client, savepoint_conn) -> None:
    _, exception = _run_with_exception(savepoint_conn, diff=100, task="task-r")
    url = RESOLVE.format(exception_id=exception["exception_id"])
    first = client.post(url, json={"resolution_code": "false_positive", "root_cause": "重复上报"},
                        headers={"X-Admin-Step-Up": "ok"})
    assert first.status_code == 200
    again = client.post(url, json={"resolution_code": "false_positive", "root_cause": "再试"},
                        headers={"X-Admin-Step-Up": "ok"})
    assert again.status_code == 409
    assert again.json()["error"]["code"] == 49204
    assert again.json()["error"]["reason"] == "exception_already_closed"


def test_resolve_is_idempotent_with_same_key(client, savepoint_conn) -> None:
    _, exception = _run_with_exception(savepoint_conn, diff=100, task="task-i")
    url = RESOLVE.format(exception_id=exception["exception_id"])
    body = {"resolution_code": "external_fix", "root_cause": "ok"}
    headers = {"X-Admin-Step-Up": "ok", "X-DJB-Idempotency-Key": "idem-resolve-0001"}
    first = client.post(url, json=body, headers=headers)
    second = client.post(url, json=body, headers=headers)
    assert (first.status_code, second.status_code) == (200, 200)
    assert second.json()["closed_at"] == first.json()["closed_at"]


def test_unknown_exception_returns_404(client) -> None:
    response = client.post(RESOLVE.format(exception_id="00000000-0000-7000-8000-000000000000"),
                           json={"resolution_code": "false_positive", "root_cause": "x"},
                           headers={"X-Admin-Step-Up": "ok"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 40401
    assert client.post(RESOLVE.format(exception_id="nope"),
                       json={"resolution_code": "false_positive", "root_cause": "x"},
                       headers={"X-Admin-Step-Up": "ok"}).status_code == 404


def test_resolve_then_sign_off_succeeds(client, savepoint_conn) -> None:
    """未结 P1 处理完 → 签核放行（I-17 的闭环）。"""
    seed_usage(savepoint_conn, task_id="task-close", amount_minor=50_000,
               recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(savepoint_conn, task_id="task-close", price_minor=0,
                 receipt_id="rcpt-close", reported_at=FIXED_NOW - timedelta(hours=1))
    run = engine.run(savepoint_conn, receipt_spec(), now=FIXED_NOW)[0]["run"]
    exception = fetch_exceptions(savepoint_conn, str(run["run_id"]))[0]
    assert exception["severity"] == "P1"

    blocked = client.post(SIGN_OFF.format(run_id=run["run_id"]), json={},
                          headers={"X-Admin-Step-Up": "ok"})
    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == 49202

    resolved = client.post(
        RESOLVE.format(exception_id=exception["exception_id"]),
        json={"resolution_code": "adjust_journal", "root_cause": "补记",
              "resolution_journal_id": post_journal(savepoint_conn, simple_journal_lines(50_000),
                                                    ts=FIXED_NOW - timedelta(minutes=5))},
        headers={"X-Admin-Step-Up": "ok"})
    assert resolved.status_code == 200

    signed = client.post(SIGN_OFF.format(run_id=run["run_id"]), json={},
                         headers={"X-Admin-Step-Up": "ok"})
    assert signed.status_code == 200
    assert signed.json()["status"] == facts.RUN_STATUS_SIGNED_OFF


def test_exception_payload_matches_contract_shape(client, savepoint_conn) -> None:
    _, exception = _run_with_exception(savepoint_conn, diff=100, task="task-shape")
    item = client.get(LIST, params={"run_id": str(exception["run_id"])}).json()["data"][0]
    required = {"exception_id", "run_id", "scope", "kind", "severity", "diff_minor", "status",
                "sla_due"}
    assert required <= set(item)
    assert item["scope"] in facts.SCOPES
    assert item["severity"] in facts.SEVERITIES
    assert item["status"] in facts.EXCEPTION_STATUSES
    assert isinstance(item["diff_minor"], int)


def test_models_exception_draft_defaults() -> None:
    draft = models.ExceptionDraft(kind="amount_mismatch", severity="P2", ref_type="task",
                                  ref_id="t", diff_minor=1, sla_due=FIXED_NOW, scope="receipt")
    assert draft.owner is None and draft.extra == {}
