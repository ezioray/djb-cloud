# SPDX-License-Identifier: AGPL-3.0-or-later
"""双人签核（INV-03 / INV-05）：阻断、幂等、step-up、凭证前置。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.recon import engine, facts, models
from reconkit import ADMIN_PRINCIPAL, build_client
from reconkit import (FIXED_NOW, fetch_run, receipt_spec, seed_receipt, seed_usage)

SIGN_OFF = "/api/v1/admin/treasury/recon/runs/{run_id}/sign-off"


def _make_run(conn, *, amount: int = 100, price: int = 97, task: str = "task-s1",
              created_by: str = "maker-1", tenant_id: str | None = None) -> dict:
    seed_usage(conn, task_id=task, amount_minor=amount,
               recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(conn, task_id=task, price_minor=price, receipt_id=f"rcpt-{task}",
                 reported_at=FIXED_NOW - timedelta(hours=1))
    spec = models.RunSpec(scope="receipt", subject_ref="m05",
                          period_start=FIXED_NOW - timedelta(days=1), period_end=FIXED_NOW,
                          cutoff_at=FIXED_NOW, created_by=created_by, tenant_id=tenant_id,
                          grace_seconds=facts.DEFAULT_GRACE_SECONDS)
    return engine.run(conn, spec, now=FIXED_NOW)[0]["run"]


def _sign_off(client, run_id: str, *, body: dict | None = None, headers: dict | None = None):
    merged = {"X-Admin-Step-Up": "stepup-token"}
    merged.update(headers or {})
    return client.post(SIGN_OFF.format(run_id=run_id), json=body or {}, headers=merged)


def test_sign_off_blocked_by_open_p1(client, savepoint_conn) -> None:
    """存在未结 P1 → 409 + 49202（INV-03 / I-17），并给出按档位计数。"""
    run = _make_run(savepoint_conn, amount=50_000, price=0)     # 500.00 USD 差 → P1
    response = _sign_off(client, str(run["run_id"]))
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == 49202
    assert error["reason"] == "pending_p0_p1"
    assert error["type"] == "conflict_error"
    assert error["pending"] == 1
    assert error["by_severity"]["P1"] == 1
    assert fetch_run(savepoint_conn, str(run["run_id"]))["status"] == facts.RUN_STATUS_EXCEPTIONS_OPEN


def test_sign_off_succeeds_and_is_two_person(client, savepoint_conn) -> None:
    run = _make_run(savepoint_conn, amount=100, price=100, created_by="maker-1")   # 无差异
    response = _sign_off(client, str(run["run_id"]), body={"reviewer_note": "已复核"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == facts.RUN_STATUS_SIGNED_OFF
    assert payload["signed_off_by"] == ADMIN_PRINCIPAL["admin_id"]
    assert payload["signed_off_at"] is not None
    assert payload["reviewer_note"] == "已复核"
    assert payload["duplicate"] is False


def test_reviewer_must_differ_from_maker(client, savepoint_conn) -> None:
    """INV-05 双人原则：复核人 = 制单人 → 409（不是 49202/49203）。"""
    run = _make_run(savepoint_conn, amount=100, price=100,
                    created_by=ADMIN_PRINCIPAL["admin_id"])
    response = _sign_off(client, str(run["run_id"]))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40919
    assert response.json()["error"]["reason"] == "reviewer_equals_maker"


def test_second_sign_off_is_rejected(client, savepoint_conn) -> None:
    run = _make_run(savepoint_conn, amount=100, price=100, created_by="maker-1")
    assert _sign_off(client, str(run["run_id"])).status_code == 200
    again = _sign_off(client, str(run["run_id"]))
    assert again.status_code == 409
    assert again.json()["error"]["code"] == 49203


def test_sign_off_replay_with_same_idempotency_key(client, savepoint_conn) -> None:
    """同幂等键重放 → 200 + 同一签核时间（不触发 49203）。"""
    run = _make_run(savepoint_conn, amount=100, price=100, created_by="maker-1")
    key = "idem-signoff-0001"
    first = _sign_off(client, str(run["run_id"]), headers={"X-DJB-Idempotency-Key": key})
    assert first.status_code == 200
    second = _sign_off(client, str(run["run_id"]), headers={"X-DJB-Idempotency-Key": key})
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["signed_off_at"] == first.json()["signed_off_at"]


def test_step_up_missing_returns_424(savepoint_conn) -> None:
    run = _make_run(savepoint_conn, amount=100, price=100)
    with build_client(savepoint_conn, step_up=False) as client:
        response = client.post(SIGN_OFF.format(run_id=run["run_id"]), json={},
                               headers={"X-Admin-Step-Up": "expired"})
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401

    with build_client(savepoint_conn, step_up=None) as client:      # 未接线：仍要 step-up 头
        missing = client.post(SIGN_OFF.format(run_id=run["run_id"]), json={})
    assert missing.status_code == 424
    assert missing.json()["error"]["code"] == 42401


def test_sign_off_requires_write_scope(savepoint_conn) -> None:
    run = _make_run(savepoint_conn, amount=100, price=100)
    read_only = {"admin_id": "reader", "tenant_id": None, "scopes": ["recon.read"]}
    with build_client(savepoint_conn, admin=read_only) as client:
        response = _sign_off(client, str(run["run_id"]))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 47010


def test_unknown_run_returns_49201(client) -> None:
    response = _sign_off(client, "00000000-0000-7000-8000-000000000000")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 49201
    assert _sign_off(client, "not-a-uuid").json()["error"]["code"] == 49201


def test_sign_off_with_missing_attestation_is_404(client, savepoint_conn) -> None:
    run = _make_run(savepoint_conn, amount=100, price=100)
    response = _sign_off(client, str(run["run_id"]),
                         body={"attestation_id": "00000000-0000-7000-8000-000000000001"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 49212


def test_sign_off_with_revoked_attestation_is_conflict(client, savepoint_conn) -> None:
    from reconkit import utc

    run = _make_run(savepoint_conn, amount=100, price=100)
    with savepoint_conn.cursor() as cur:
        import uuid

        attestation_id = str(uuid.uuid4())
        cur.execute(
            """INSERT INTO reconciliation_attestations
                 (attestation_id, period_start, period_end, ledger_root, payable_total_minor,
                  batch_hash, signature_ref, status)
               VALUES (%s,%s,%s,%s,1,%s,'sig','revoked')""",
            (attestation_id, utc(2026, 10, 1), utc(2026, 10, 31), "a" * 64, "b" * 32))
    response = _sign_off(client, str(run["run_id"]), body={"attestation_id": attestation_id})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 49205
    assert response.json()["error"]["reason"] == "attestation_not_valid"


def test_cross_tenant_run_is_invisible(savepoint_conn) -> None:
    run = _make_run(savepoint_conn, amount=100, price=100, tenant_id="tenant-b")
    with build_client(savepoint_conn) as client:                     # tenant-a 的管理员
        response = _sign_off(client, str(run["run_id"]))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 49201


@pytest.mark.parametrize("path,method", [
    (SIGN_OFF, "post"),
    ("/api/v1/admin/treasury/recon/attestations", "post"),
    ("/api/v1/admin/treasury/recon/exceptions/{id}/resolve", "post"),
])
def test_write_endpoints_require_step_up(client, savepoint_conn, path: str, method: str) -> None:
    url = path.format(run_id="00000000-0000-7000-8000-000000000000",
                      id="00000000-0000-7000-8000-000000000000")
    response = getattr(client, method)(url, json={})
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401
