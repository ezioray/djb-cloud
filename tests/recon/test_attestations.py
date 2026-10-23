# SPDX-License-Identifier: Apache-2.0
"""复核凭证：提交 / 唯一 valid / 双人 / 幂等 / validate 只回结论（INV-05 / §6.2）。"""
from __future__ import annotations

import uuid
from datetime import timedelta

from app.recon import engine, facts, models
from conftest import ADMIN_PRINCIPAL, build_client
from reconkit import FIXED_NOW, receipt_spec, seed_receipt, seed_usage

SUBMIT = "/api/v1/admin/treasury/recon/attestations"
GET = SUBMIT + "/{attestation_id}"
VALIDATE = SUBMIT + "/{attestation_id}/validate"

BODY = {
    "period_start": "2026-10-01T00:00:00Z",
    "period_end": "2026-10-31T00:00:00Z",
    "ledger_root": "a" * 64,
    "batch_hash": "b" * 32,
    "payable_total_minor": 123_456,
    "signature_ref": "hsm:reviewer-key-1:0001",
}
STEP_UP = {"X-Admin-Step-Up": "ok"}


def _submit(client, body=None, headers=None):
    merged = dict(STEP_UP)
    merged.update(headers or {})
    return client.post(SUBMIT, json=body or dict(BODY), headers=merged)


def test_submit_get_and_validate(client) -> None:
    created = _submit(client)
    assert created.status_code == 201
    payload = created.json()
    assert payload["status"] == "valid"
    assert payload["batch_hash"] == BODY["batch_hash"]
    assert payload["reviewer_id"] == ADMIN_PRINCIPAL["admin_id"]
    assert payload["duplicate"] is False

    fetched = client.get(GET.format(attestation_id=payload["attestation_id"]))
    assert fetched.status_code == 200
    assert fetched.json()["attestation_id"] == payload["attestation_id"]

    validated = client.get(VALIDATE.format(attestation_id=payload["attestation_id"]))
    assert validated.status_code == 200
    conclusion = validated.json()
    assert set(conclusion) <= {"valid", "status", "checked_at", "reasons"}
    assert conclusion["valid"] is True
    assert conclusion["status"] == "valid"
    assert conclusion["reasons"] == []
    # 只回结论：凭证正文一个字段都不许漏
    for leaked in ("ledger_root", "batch_hash", "payable_total_minor", "signature_ref",
                   "reviewer_id", "attestation_id"):
        assert leaked not in conclusion


def test_second_valid_for_same_period_and_batch_is_409(client) -> None:
    assert _submit(client).status_code == 201
    again = _submit(client, headers={"X-DJB-Idempotency-Key": "idem-attest-0002"})
    assert again.status_code == 409
    assert again.json()["error"]["code"] == 49205
    assert again.json()["error"]["reason"] == "valid_attestation_exists"


def test_different_batch_hash_is_allowed(client) -> None:
    assert _submit(client).status_code == 201
    other = dict(BODY, batch_hash="c" * 32)
    assert _submit(client, other).status_code == 201


def test_reviewer_equals_maker_is_rejected(client, savepoint_conn) -> None:
    """INV-05：复核人 ≠ 制单人（制单人取该期间最近 run 的 created_by）。"""
    seed_usage(savepoint_conn, task_id="task-maker", amount_minor=100,
               recorded_at=FIXED_NOW - timedelta(hours=2))
    seed_receipt(savepoint_conn, task_id="task-maker", price_minor=100,
                 receipt_id="rcpt-maker", reported_at=FIXED_NOW - timedelta(hours=1))
    spec = models.RunSpec(scope="receipt", subject_ref="m05",
                          period_start=FIXED_NOW - timedelta(days=1), period_end=FIXED_NOW,
                          cutoff_at=FIXED_NOW, created_by=ADMIN_PRINCIPAL["admin_id"])
    engine.run(savepoint_conn, spec, now=FIXED_NOW)

    response = _submit(client)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == 40919
    assert response.json()["error"]["reason"] == "reviewer_equals_maker"


def test_submit_is_idempotent_with_same_key(client) -> None:
    key = "idem-attest-0001"
    first = _submit(client, headers={"X-DJB-Idempotency-Key": key})
    second = _submit(client, headers={"X-DJB-Idempotency-Key": key})
    assert (first.status_code, second.status_code) == (201, 201)
    assert second.json()["duplicate"] is True
    assert second.json()["attestation_id"] == first.json()["attestation_id"]


def test_same_key_different_payload_is_rejected(client) -> None:
    key = "idem-attest-0003"
    assert _submit(client, headers={"X-DJB-Idempotency-Key": key}).status_code == 201
    response = _submit(client, dict(BODY, payable_total_minor=9), 
                       headers={"X-DJB-Idempotency-Key": key})
    assert response.status_code == 409
    assert response.json()["error"]["reason"] == "idempotency_key_reused"


def test_shape_validation(client) -> None:
    assert _submit(client, dict(BODY, ledger_root="x" * 64)).status_code == 400
    assert _submit(client, dict(BODY, batch_hash="short")).status_code == 400
    assert _submit(client, dict(BODY, payable_total_minor=-1)).status_code == 400
    assert _submit(client, dict(BODY, signature_ref="")).status_code == 400
    missing = {key: value for key, value in BODY.items() if key != "ledger_root"}
    assert _submit(client, missing).status_code == 400


def test_unknown_attestation_is_404(client) -> None:
    unknown = "00000000-0000-7000-8000-000000000001"
    assert client.get(GET.format(attestation_id=unknown)).json()["error"]["code"] == 49212
    assert client.get(VALIDATE.format(attestation_id=unknown)).json()["error"]["code"] == 49212
    assert client.get(GET.format(attestation_id="nope")).json()["error"]["code"] == 49212


def test_validate_reports_revoked(client, savepoint_conn) -> None:
    created = _submit(client).json()
    savepoint_conn.execute(
        "UPDATE reconciliation_attestations SET status='revoked' WHERE attestation_id = %s",
        (created["attestation_id"],))
    conclusion = client.get(VALIDATE.format(attestation_id=created["attestation_id"])).json()
    assert conclusion["valid"] is False
    assert conclusion["status"] == "revoked"
    assert conclusion["reasons"] == ["attestation_revoked"]


def test_validate_requires_service_principal(savepoint_conn) -> None:
    admin_only = {"admin_id": "admin-1", "tenant_id": None,
                  "scopes": ["recon.read", "recon.write"]}
    with build_client(savepoint_conn, service=None) as client:
        created = _submit(client).json()
        response = client.get(VALIDATE.format(attestation_id=created["attestation_id"]))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == 40101


def test_validate_requires_validate_scope(savepoint_conn) -> None:
    weak_service = {"service_id": "M14-console", "scopes": ["recon.attestation.read"]}
    with build_client(savepoint_conn, service=weak_service) as client:
        created = _submit(client).json()
        response = client.get(VALIDATE.format(attestation_id=created["attestation_id"]))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == 49206
    assert response.json()["error"]["reason"] == "attestation_validation_unavailable"


def test_cross_tenant_attestation_is_invisible(savepoint_conn) -> None:
    with build_client(savepoint_conn) as tenant_a:
        created = _submit(tenant_a).json()
        assert tenant_a.get(GET.format(attestation_id=created["attestation_id"])).status_code == 200

    tenant_b = {"admin_id": "admin-b", "tenant_id": "tenant-b",
                "scopes": ["recon.read", "recon.write"]}
    with build_client(savepoint_conn, admin=tenant_b) as client_b:
        response = client_b.get(GET.format(attestation_id=created["attestation_id"]))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == 49212


def test_attestation_requires_step_up(client) -> None:
    response = client.post(SUBMIT, json=dict(BODY))
    assert response.status_code == 424
    assert response.json()["error"]["code"] == 42401


def test_validate_module_helper_only_returns_conclusion() -> None:
    """纯函数层再钉一次：validate 的字段集合是封闭的（多一个就是泄露）。"""
    from app.recon.attestation import VALIDATE_FIELDS, validate

    row = {"status": "valid", "signature_ref": "sig", "ledger_root": "a" * 64}
    conclusion = validate(row, now=FIXED_NOW)
    assert set(conclusion) <= set(VALIDATE_FIELDS)
    assert conclusion["valid"] is True

    expired = validate({**row, "status": "superseded"}, now=FIXED_NOW)
    assert expired["valid"] is False
    assert expired["reasons"] == ["attestation_superseded"]

    unknown = validate(None, now=FIXED_NOW)
    assert unknown == {"valid": False, "status": "unknown",
                       "checked_at": "2026-10-23T09:00:00.000000Z",
                       "reasons": ["attestation_not_found"]}
    assert facts.ATTESTATION_STATUSES == ("valid", "superseded", "revoked")
