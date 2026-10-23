# SPDX-License-Identifier: Apache-2.0
"""M08 持久化层（psycopg3，无 ORM）。

隔离与安全：

* 用户侧读一律带 account_id（跨账户 = 不存在 → 404，不泄露存在性）；
* 管理面按角色 / scope 控制（router），SQL 层不做隐式越权；
* 所有 SQL 参数化；JSONB 只放白名单键（事件层再兜底）；
* 写接口不 commit：事务边界在 router / service（业务写入 + outbox 同事务）；
* 读别人只走 M09 的只读视图 / 注入的校验器（本文件不 join 非 M08 基表）。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import clock, facts, models
from .errors import BadRequest, NotFound

__all__ = [
    # 订单 / 尝试
    "insert_order", "get_order", "find_order_by_idempotency", "list_orders",
    "update_order", "insert_attempt", "get_attempt", "get_attempt_by_txn",
    "list_attempts", "update_attempt",
    # 池 / 钱包 / 批次 / 转账
    "get_pool", "list_pools", "list_wallet_pool_rows", "get_wallet", "get_wallet_by_address",
    "list_wallets", "insert_wallet", "update_wallet", "set_wallet_status",
    "insert_provision_batch", "get_provision_batch", "find_provision_by_idempotency",
    "update_provision_batch", "list_provision_batches", "insert_activation",
    "list_activations", "append_pool_event", "list_pool_events",
    "insert_transfer", "get_transfer", "list_transfers", "wallet_in_flight",
    # 出款
    "insert_payout_batch", "get_payout_batch", "find_payout_by_idempotency",
    "find_payout_by_intent", "find_provision_by_signing_request",
    "update_payout_batch", "list_payout_batches", "insert_payout_item",
    "list_payout_items", "update_payout_item",
    "insert_payout_address", "get_payout_address", "get_payout_address_by_id",
    "find_payout_address_by_key", "find_payout_address_by_idempotency",
    "update_payout_address", "list_payout_addresses",
    # 退款
    "insert_refund", "get_refund", "find_open_refund", "find_refund_by_idempotency",
    "update_refund", "list_refunds", "refunded_total",
    # 意图 / 签名
    "insert_intent", "get_intent", "update_intent", "insert_signing_request",
    "get_signing_request", "update_signing_request", "insert_signing_event",
    "list_signing_events", "last_signing_event", "signed_counts",
]

ORDER_COLUMNS = (
    "order_id, order_no, account_id, tenant_id, amount_minor, currency, method, provider,"
    " status, credited_minor, description, policy_version, idempotency_key, request_hash,"
    " trace_id, created_by, expires_at, paid_at, credited_at, closed_at, created_at, updated_at"
)
ATTEMPT_COLUMNS = (
    "attempt_id, order_id, provider, provider_txn_id, provider_status, status, amount_minor,"
    " fee_minor, net_minor, currency, signature_verified, payload_hash, failure_code,"
    " query_confirmed, query_result, settled_minor, settlement_fee_minor, created_at, updated_at"
)
WALLET_COLUMNS = (
    "wallet_id, chain_id, address, pool_id, pool_role, fund_class, custody_kind, status,"
    " switch_state, signer_set_ref, descriptor_hash, balance_minor, gas_ok, cap_minor,"
    " policy_version, provisioned_at, activated_at, last_switched_at, retired_at, retired_reason,"
    " updated_at"
)
BATCH_COLUMNS = (
    "batch_id, batch_no, pool_id, kind, wallet_count, descriptor_merkle_root, cap_params,"
    " dedupe_key, status, nonce, expires_at, created_at, owner_signed_at, reviewer_attested_at,"
    " hsm_verified_at, activated_at, auth_object_type, auth_hash, contains_transfer, reason,"
    " created_by, idempotency_key, signing_request_id, policy_version, updated_at"
)
PAYOUT_COLUMNS = (
    "batch_id, batch_no, status, total_gross_minor, total_fee_minor, total_net_minor, item_count,"
    " items_hash, attestation_ref, attestation_valid, gas_mode, policy_version, maker_id,"
    " checker_id, checked_at, signed_at, broadcast_at, settled_at, chain_tx_id, signing_request_id,"
    " intent_id, failure_reason, idempotency_key, created_at, updated_at"
)
PAYOUT_ITEM_COLUMNS = (
    "item_id, batch_id, payee_account_id, payee_address, gross_minor, fee_minor, net_minor,"
    " status, gas_mode, policy_version, address_id, carry_of_item_id, carried_to_batch_id,"
    " chain_tx_id, journal_id, failure_reason, created_at, updated_at"
)
ADDRESS_COLUMNS = (
    "address_id, account_id, chain_id, address, status, ownership_challenge_ref,"
    " ownership_verified_at, risk_level, cooldown_until, first_transfer_at, first_transfer_minor,"
    " changed_at, previous_address, approved_by, approved_at, rejected_reason, label,"
    " idempotency_key, created_at, updated_at"
)
REFUND_COLUMNS = (
    "refund_request_id, refund_no, account_id, order_no, payment_ref, amount_minor, currency,"
    " reason_code, evidence_ref, original_route, original_route_hash, status, deadline_at,"
    " requested_by, approved_by, approved_at, cooldown_until, executing_at, succeeded_at,"
    " failed_at, failure_code, journal_id, idempotency_key, created_at, updated_at"
)
INTENT_COLUMNS = (
    "intent_id, kind, chain_id, asset, total_amount_minor, item_count, recipients_hash, nonce,"
    " status, auth_object_type, auth_hash, policy_version, memo_hash, created_by, correlation_id,"
    " idempotency_key, created_at, expires_at, updated_at"
)
SIGNING_COLUMNS = (
    "signing_request_id, intent_id, kind, status, signer_set_ref, threshold_n, signer_count_n,"
    " signed_count, policy_version, requested_at, presented_at, signed_at, verified_at,"
    " co_signed_at, broadcast_at, expires_at, auth_hash, txid, created_by, idempotency_key,"
    " created_at, updated_at"
)
SIGNING_EVENT_COLUMNS = (
    "signing_event_id, signing_request_id, event, signer_type, signer_ref, signature_hash,"
    " device_id, auth_hash, txid, error_code, occurred_at, recorded_at"
)


def _uuid_text(value: Any) -> str | None:
    return None if value is None else str(value)


# ═══════════════════════════════════════════════════════════ 订单
def insert_order(conn: Any, *, order_id: str, draft: models.OrderDraft, policy_version: str,
                 trace_id: str, created_by: str, idempotency_key: str | None,
                 now: datetime, expires_at: datetime | None = None) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO payment_orders (order_id, account_id, amount_minor, currency, method,
                                        provider, status, description, policy_version,
                                        idempotency_key, request_hash, trace_id, created_by,
                                        expires_at, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, 'created', %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {ORDER_COLUMNS}
            """,
            (order_id, draft.account_id, draft.amount_minor, draft.currency, draft.method,
             draft.provider, draft.description, policy_version, idempotency_key,
             draft.request_hash, trace_id, created_by, expires_at, now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_order(conn: Any, identifier: str, *, account_id: str | None = None,
              lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    params: list[Any] = [str(identifier), str(identifier)]
    clause = ""
    if account_id is not None:
        clause = " AND account_id = %s"
        params.append(str(account_id))
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {ORDER_COLUMNS} FROM payment_orders"
            f" WHERE (order_no = %s OR order_id::text = %s){clause}{suffix}", tuple(params))
        return cur.fetchone()


def find_order_by_idempotency(conn: Any, key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {ORDER_COLUMNS} FROM payment_orders WHERE idempotency_key = %s",
                    (key,))
        return cur.fetchone()


def list_orders(conn: Any, *, account_id: str, status: str | None = None,
                cursor: str | None = None, limit: int = facts.DEFAULT_PAGE_SIZE
                ) -> tuple[list[dict[str, Any]], bool, str | None]:
    conditions = ["account_id = %s"]
    params: list[Any] = [str(account_id)]
    if status is not None:
        conditions.append("status = %s")
        params.append(status)
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment, identity = parsed
        conditions.append("(created_at, order_id) < (%s, %s)")
        params.extend([moment, identity])
    params.append(limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {ORDER_COLUMNS} FROM payment_orders WHERE " + " AND ".join(conditions) +
            " ORDER BY created_at DESC, order_id DESC LIMIT %s", tuple(params))
        rows = list(cur.fetchall())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = models.encode_cursor(last["created_at"], str(last["order_id"]))
    return rows, has_more, next_cursor


def update_order(conn: Any, order_id: str, *, status: str,
                 paid_at: datetime | None = None, credited_at: datetime | None = None,
                 closed_at: datetime | None = None, credited_minor: int | None = None
                 ) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            UPDATE payment_orders
               SET status = %s,
                   paid_at = COALESCE(%s, paid_at),
                   credited_at = COALESCE(%s, credited_at),
                   closed_at = COALESCE(%s, closed_at),
                   credited_minor = COALESCE(%s, credited_minor)
             WHERE order_id = %s
             RETURNING {ORDER_COLUMNS}
            """,
            (status, paid_at, credited_at, closed_at, credited_minor, str(order_id)))
        row = cur.fetchone()
    if row is None:
        raise NotFound("支付订单不存在")
    return dict(row)


# ═══════════════════════════════════════════════════════════ 支付尝试
def insert_attempt(conn: Any, *, attempt_id: str, order_id: str, provider: str,
                   provider_txn_id: str | None, provider_status: str, status: str,
                   amount_minor: int, fee_minor: int, net_minor: int, currency: str,
                   signature_verified: bool, payload_hash: str | None,
                   failure_code: str | None, query_confirmed: bool = False,
                   query_result: str | None = None, now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO payment_attempts (attempt_id, order_id, provider, provider_txn_id,
                                          provider_status, status, amount_minor, fee_minor,
                                          net_minor, currency, signature_verified, payload_hash,
                                          failure_code, query_confirmed, query_result,
                                          created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {ATTEMPT_COLUMNS}
            """,
            (attempt_id, str(order_id), provider, provider_txn_id, provider_status, status,
             int(amount_minor), int(fee_minor), int(net_minor), currency,
             bool(signature_verified), payload_hash, failure_code, bool(query_confirmed),
             query_result, now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_attempt(conn: Any, attempt_id: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {ATTEMPT_COLUMNS} FROM payment_attempts WHERE attempt_id = %s{suffix}",
                    (str(attempt_id),))
        return cur.fetchone()


def get_attempt_by_txn(conn: Any, provider: str, provider_txn_id: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {ATTEMPT_COLUMNS} FROM payment_attempts"
            " WHERE provider = %s AND provider_txn_id = %s", (provider, str(provider_txn_id)))
        return cur.fetchone()


def list_attempts(conn: Any, order_id: str) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {ATTEMPT_COLUMNS} FROM payment_attempts WHERE order_id = %s"
                    " ORDER BY created_at ASC", (str(order_id),))
        return list(cur.fetchall())


def update_attempt(conn: Any, attempt_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "provider_status", "provider_txn_id", "signature_verified",
               "failure_code", "query_confirmed", "query_result", "settled_minor",
               "settlement_fee_minor", "fee_minor", "net_minor"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"payment_attempts 不可更新字段：{sorted(unknown)}")
    if not fields:
        return get_attempt(conn, attempt_id) or {}
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(attempt_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE payment_attempts SET {assignments}, updated_at = now()"
            f" WHERE attempt_id = %s RETURNING {ATTEMPT_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("支付尝试不存在")
    return dict(row)


# ═══════════════════════════════════════════════════════════ 池 / 钱包
def get_pool(conn: Any, pool_id: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT pool_id, chain_id, role, fund_class, min_spare_count, max_active_count,"
            " switch_threshold_pct, activate_batch_size, provision_lead_time_h, pool_cap_minor,"
            f" switch_policy, status, policy_version, created_at, updated_at FROM wallet_pool"
            f" WHERE pool_id = %s{suffix}", (str(pool_id),))
        return cur.fetchone()


def list_wallet_pool_rows(conn: Any, *, status: str | None = None,
                          role: str | None = None) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []
    if status is not None:
        conditions.append("p.status = %s")
        params.append(status)
    if role is not None:
        conditions.append("p.role = %s")
        params.append(role)
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT p.pool_id, p.chain_id, p.role, p.fund_class, p.min_spare_count,"
            " p.max_active_count, p.switch_threshold_pct, p.activate_batch_size,"
            " p.provision_lead_time_h, p.pool_cap_minor, p.status, p.policy_version,"
            " v.depth_ready, v.depth_available, v.in_service_count, v.active_balance_minor"
            " FROM wallet_pool p LEFT JOIN v_m08_pool_depth v ON v.pool_id = p.pool_id"
            f"{where} ORDER BY p.pool_id", tuple(params))
        return list(cur.fetchall())


def list_pools(conn: Any, *, status: str | None = None, role: str | None = None
               ) -> list[dict[str, Any]]:
    return list_wallet_pool_rows(conn, status=status, role=role)


def find_pool_by_key(conn: Any, chain_id: str, role: str, fund_class: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT pool_id FROM wallet_pool WHERE chain_id = %s AND role = %s"
                    " AND fund_class = %s", (str(chain_id), str(role), str(fund_class)))
        row = cur.fetchone()
    return None if row is None else get_pool(conn, str(row["pool_id"]))


def insert_pool(conn: Any, *, pool_id: str, chain_id: str, role: str, fund_class: str,
                min_spare: int, max_active: int, switch_threshold_pct: int,
                activate_batch_size: int, provision_lead_time_h: int, pool_cap_minor: int,
                switch_policy: str, policy_version: str, now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO wallet_pool (pool_id, chain_id, role, fund_class, min_spare_count,
                                     max_active_count, switch_threshold_pct, activate_batch_size,
                                     provision_lead_time_h, pool_cap_minor, switch_policy,
                                     policy_version, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING pool_id
            """,
            (str(pool_id), str(chain_id), str(role), str(fund_class), int(min_spare),
             int(max_active), int(switch_threshold_pct), int(activate_batch_size),
             int(provision_lead_time_h), int(pool_cap_minor), switch_policy, policy_version,
             now, now))
        row = cur.fetchone()
    assert row is not None
    return get_pool(conn, str(row["pool_id"])) or {}


def get_wallet(conn: Any, wallet_id: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {WALLET_COLUMNS} FROM wallet WHERE wallet_id = %s{suffix}",
                    (str(wallet_id),))
        return cur.fetchone()


def get_wallet_by_address(conn: Any, chain_id: str, address: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {WALLET_COLUMNS} FROM wallet WHERE chain_id = %s AND address = %s",
                    (str(chain_id), str(address).lower()))
        return cur.fetchone()


def list_wallets(conn: Any, pool_id: str, *, lock: bool = False) -> list[dict[str, Any]]:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {WALLET_COLUMNS} FROM wallet WHERE pool_id = %s"
                    f" ORDER BY provisioned_at ASC{suffix}", (str(pool_id),))
        return list(cur.fetchall())


def insert_wallet(conn: Any, *, wallet_id: str, chain_id: str, address: str, pool_id: str,
                  role: str, fund_class: str, custody_kind: str, signer_set_ref: str,
                  descriptor_hash: str, cap_minor: int | None, policy_version: str,
                  now: datetime, status: str = facts.WALLET_PROVISIONING,
                  balance_minor: int = 0, gas_ok: bool = False) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO wallet (wallet_id, chain_id, address, pool_id, pool_role, fund_class,
                                custody_kind, status, switch_state, signer_set_ref,
                                descriptor_hash, balance_minor, gas_ok, cap_minor,
                                policy_version, provisioned_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NULL, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {WALLET_COLUMNS}
            """,
            (str(wallet_id), str(chain_id), str(address).lower(), str(pool_id), role, fund_class,
             custody_kind, status, signer_set_ref, descriptor_hash, int(balance_minor),
             bool(gas_ok), cap_minor, policy_version, now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def update_wallet(conn: Any, wallet_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "switch_state", "balance_minor", "gas_ok", "cap_minor",
               "activated_at", "last_switched_at", "retired_at", "retired_reason",
               "descriptor_hash", "signer_set_ref"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"wallet 不可更新字段：{sorted(unknown)}")
    if not fields:
        return get_wallet(conn, wallet_id) or {}
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(wallet_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE wallet SET {assignments}, updated_at = now() WHERE wallet_id = %s"
            f" RETURNING {WALLET_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("钱包不存在")
    return dict(row)


def set_wallet_status(conn: Any, wallet_id: str, *, status: str,
                      switch_state: str | None = None, retired_reason: str | None = None,
                      retired_at: datetime | None = None) -> dict[str, Any]:
    fields: dict[str, Any] = {"status": status}
    if switch_state is not None:
        fields["switch_state"] = switch_state
    if retired_reason is not None:
        fields["retired_reason"] = retired_reason
    if retired_at is not None:
        fields["retired_at"] = retired_at
    return update_wallet(conn, wallet_id, **fields)


# ─────────────────────────────────────────── 预生成批次
def insert_provision_batch(conn: Any, *, batch_id: str, pool_id: str, batch_no: str,
                           wallet_count: int, descriptor_merkle_root: str,
                           cap_params: Mapping[str, Any], dedupe_key: str, status: str,
                           expires_at: datetime, created_by: str,
                           idempotency_key: str | None, policy_version: str,
                           now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO wallet_provision_batch (batch_id, pool_id, batch_no, kind, wallet_count,
                                                descriptor_merkle_root, cap_params, dedupe_key,
                                                status, expires_at, created_at, created_by,
                                                idempotency_key, policy_version, updated_at)
            VALUES (%s, %s, %s, 'WALLET_PROVISION', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {BATCH_COLUMNS}
            """,
            (str(batch_id), str(pool_id), batch_no, int(wallet_count), descriptor_merkle_root,
             Jsonb(dict(cap_params)), dedupe_key, status, expires_at, now, created_by,
             idempotency_key, policy_version, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_provision_batch(conn: Any, batch_id: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {BATCH_COLUMNS} FROM wallet_provision_batch"
            f" WHERE batch_id = %s OR batch_no = %s{suffix}", (str(batch_id), str(batch_id)))
        return cur.fetchone()


def find_provision_by_idempotency(conn: Any, key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {BATCH_COLUMNS} FROM wallet_provision_batch"
                    " WHERE idempotency_key = %s", (key,))
        return cur.fetchone()


def update_provision_batch(conn: Any, batch_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "batch_no", "activated_at", "owner_signed_at", "reviewer_attested_at",
               "hsm_verified_at", "signing_request_id", "auth_hash", "reason"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"wallet_provision_batch 不可更新字段：{sorted(unknown)}")
    if not fields:
        return get_provision_batch(conn, batch_id) or {}
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(batch_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE wallet_provision_batch SET {assignments}, updated_at = now()"
            f" WHERE batch_id = %s RETURNING {BATCH_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("预生成批次不存在")
    return dict(row)


def list_provision_batches(conn: Any, *, pool_id: str | None = None,
                           limit: int = facts.DEFAULT_PAGE_SIZE) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        if pool_id is None:
            cur.execute(f"SELECT {BATCH_COLUMNS} FROM wallet_provision_batch"
                        " ORDER BY created_at DESC LIMIT %s", (limit,))
        else:
            cur.execute(f"SELECT {BATCH_COLUMNS} FROM wallet_provision_batch WHERE pool_id = %s"
                        " ORDER BY created_at DESC LIMIT %s", (str(pool_id), limit))
        return list(cur.fetchall())


def insert_activation(conn: Any, *, activation_id: str, batch_id: str, wallet_id: str,
                      switch_state: str, cap_applied_minor: int, status: str,
                      activated_at: datetime | None, audit_hash: str | None) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO wallet_activation (activation_id, batch_id, wallet_id, switch_state,
                                           cap_applied_minor, status, activated_at, audit_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (batch_id, wallet_id) DO UPDATE
               SET status = EXCLUDED.status, activated_at = EXCLUDED.activated_at,
                   switch_state = EXCLUDED.switch_state, audit_hash = EXCLUDED.audit_hash
            RETURNING *
            """,
            (str(activation_id), str(batch_id), str(wallet_id), switch_state,
             int(cap_applied_minor), status, activated_at, audit_hash))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def list_activations(conn: Any, batch_id: str) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM wallet_activation WHERE batch_id = %s"
                    " ORDER BY created_at ASC", (str(batch_id),))
        return list(cur.fetchall())


def append_pool_event(conn: Any, *, pool_id: str, event: str, batch_id: str | None,
                      actor: str, payload: Mapping[str, Any], now: datetime) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO wallet_pool_event (pool_id, event, batch_id, actor, payload, ts)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (str(pool_id), event, _uuid_text(batch_id), actor, Jsonb(dict(payload)), now))


def list_pool_events(conn: Any, pool_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM wallet_pool_event WHERE pool_id = %s"
                    " ORDER BY seq DESC LIMIT %s", (str(pool_id), limit))
        return list(cur.fetchall())


# ─────────────────────────────────────────── 钱包转账（归集 / 调拨 / 出款执行）
def insert_transfer(conn: Any, *, transfer_id: str, batch_no: str | None, kind: str,
                    chain_id: str, from_wallet_id: str | None, to_wallet_id: str | None,
                    from_address: str | None, to_address: str | None, qty_minor: int,
                    amount_minor: int, gas_fee_minor: int, gas_reserve_pol: int,
                    status: str, intent_id: str | None, nonce: int | None,
                    policy_version: str, now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO wallet_transfers (transfer_id, batch_no, kind, chain_id, from_wallet_id,
                                          to_wallet_id, from_address, to_address, qty_minor,
                                          amount_minor, gas_fee_minor, gas_reserve_pol, status,
                                          intent_id, nonce, policy_version, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (str(transfer_id), batch_no, kind, str(chain_id), _uuid_text(from_wallet_id),
             _uuid_text(to_wallet_id), from_address, to_address, int(qty_minor),
             int(amount_minor), int(gas_fee_minor), int(gas_reserve_pol), status,
             _uuid_text(intent_id), nonce, policy_version, now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_transfer(conn: Any, transfer_id: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT * FROM wallet_transfers WHERE transfer_id = %s{suffix}",
                    (str(transfer_id),))
        return cur.fetchone()


def list_transfers(conn: Any, *, batch_no: str | None = None, wallet_id: str | None = None,
                   limit: int = facts.DEFAULT_PAGE_SIZE) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []
    if batch_no is not None:
        conditions.append("batch_no = %s")
        params.append(batch_no)
    if wallet_id is not None:
        conditions.append("(from_wallet_id = %s OR to_wallet_id = %s)")
        params.extend([wallet_id, wallet_id])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT * FROM wallet_transfers{where} ORDER BY created_at DESC LIMIT %s",
                    tuple(params))
        return list(cur.fetchall())


def wallet_in_flight(conn: Any, wallet_id: str) -> int:
    """在途交易数（status in planned/signed/broadcast）。"""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM wallet_transfers WHERE status IN ('planned','signed','broadcast')"
            " AND (from_wallet_id = %s OR to_wallet_id = %s)", (str(wallet_id), str(wallet_id)))
        return int(cur.fetchone()[0])


# ═══════════════════════════════════════════════════════════ 出款批次 / 明细 / 地址
def insert_payout_batch(conn: Any, *, batch_id: str, status: str, item_count: int,
                        totals: Mapping[str, int], items_hash: str,
                        gas_mode: str, policy_version: str, maker_id: str,
                        idempotency_key: str | None, now: datetime,
                        attestation_ref: str | None = None) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO payout_batches (batch_id, status, total_gross_minor, total_fee_minor,
                                        total_net_minor, item_count, items_hash, gas_mode,
                                        policy_version, maker_id, attestation_ref,
                                        idempotency_key, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {PAYOUT_COLUMNS}
            """,
            (str(batch_id), status, int(totals["total_gross_minor"]),
             int(totals["total_fee_minor"]), int(totals["total_net_minor"]), int(item_count),
             items_hash, gas_mode, policy_version, maker_id, attestation_ref, idempotency_key,
             now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_payout_batch(conn: Any, identifier: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {PAYOUT_COLUMNS} FROM payout_batches"
            f" WHERE batch_id::text = %s OR batch_no = %s{suffix}", (str(identifier), str(identifier)))
        return cur.fetchone()


def find_payout_by_idempotency(conn: Any, key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {PAYOUT_COLUMNS} FROM payout_batches WHERE idempotency_key = %s",
                    (key,))
        return cur.fetchone()


def update_payout_batch(conn: Any, batch_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "attestation_ref", "attestation_valid", "checker_id", "checked_at",
               "signed_at", "broadcast_at", "settled_at", "chain_tx_id", "signing_request_id",
               "intent_id", "failure_reason", "gas_mode"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"payout_batches 不可更新字段：{sorted(unknown)}")
    if not fields:
        return get_payout_batch(conn, batch_id) or {}
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(batch_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"UPDATE payout_batches SET {assignments}, updated_at = now() WHERE batch_id = %s"
            f" RETURNING {PAYOUT_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("出款批次不存在")
    return dict(row)


def list_payout_batches(conn: Any, *, status: str | None = None, cursor: str | None = None,
                        limit: int = facts.DEFAULT_PAGE_SIZE
                        ) -> tuple[list[dict[str, Any]], bool, str | None]:
    conditions: list[str] = []
    params: list[Any] = []
    if status is not None:
        conditions.append("status = %s")
        params.append(status)
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment, identity = parsed
        conditions.append("(created_at, batch_id) < (%s, %s)")
        params.extend([moment, identity])
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {PAYOUT_COLUMNS} FROM payout_batches{where}"
                    " ORDER BY created_at DESC, batch_id DESC LIMIT %s", tuple(params))
        rows = list(cur.fetchall())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = models.encode_cursor(last["created_at"], str(last["batch_id"]))
    return rows, has_more, next_cursor


def insert_payout_item(conn: Any, *, item_id: str, batch_id: str, payee_account_id: str,
                       payee_address: str, gross_minor: int, fee_minor: int, net_minor: int,
                       status: str, gas_mode: str, policy_version: str,
                       address_id: str | None, carry_of_item_id: str | None,
                       now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO payout_items (item_id, batch_id, payee_account_id, payee_address,
                                      gross_minor, fee_minor, net_minor, status, gas_mode,
                                      policy_version, address_id, carry_of_item_id, created_at,
                                      updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {PAYOUT_ITEM_COLUMNS}
            """,
            (str(item_id), str(batch_id), payee_account_id, payee_address.lower(),
             int(gross_minor), int(fee_minor), int(net_minor), status, gas_mode,
             policy_version, _uuid_text(address_id), _uuid_text(carry_of_item_id), now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def list_payout_items(conn: Any, batch_id: str) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {PAYOUT_ITEM_COLUMNS} FROM payout_items WHERE batch_id = %s"
                    " ORDER BY created_at ASC, item_id ASC", (str(batch_id),))
        return list(cur.fetchall())


def update_payout_item(conn: Any, item_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "chain_tx_id", "journal_id", "failure_reason",
               "carried_to_batch_id", "fee_minor", "net_minor"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"payout_items 不可更新字段：{sorted(unknown)}")
    if not fields:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT {PAYOUT_ITEM_COLUMNS} FROM payout_items WHERE item_id = %s",
                        (str(item_id),))
            row = cur.fetchone()
        if row is None:
            raise NotFound("出款明细不存在")
        return dict(row)
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(item_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"UPDATE payout_items SET {assignments}, updated_at = now()"
                    f" WHERE item_id = %s RETURNING {PAYOUT_ITEM_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("出款明细不存在")
    return dict(row)


def insert_payout_address(conn: Any, *, address_id: str, account_id: str, chain_id: str,
                          address: str, status: str, ownership_challenge_ref: str,
                          ownership_verified_at: datetime | None, risk_level: str,
                          cooldown_until: datetime, changed_at: datetime,
                          approved_by: str | None, approved_at: datetime | None,
                          idempotency_key: str | None, now: datetime,
                          label: str | None = None) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO payout_addresses (address_id, account_id, chain_id, address, status,
                                          ownership_challenge_ref, ownership_verified_at,
                                          risk_level, cooldown_until, changed_at, approved_by,
                                          approved_at, label, idempotency_key, created_at,
                                          updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {ADDRESS_COLUMNS}
            """,
            (str(address_id), account_id, chain_id, address.lower(), status,
             ownership_challenge_ref, ownership_verified_at, risk_level, cooldown_until,
             changed_at, approved_by, approved_at, label, idempotency_key, now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_payout_address(conn: Any, address: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {ADDRESS_COLUMNS} FROM payout_addresses"
                    f" WHERE address = %s{suffix}", (str(address).lower(),))
        return cur.fetchone()


def get_payout_address_by_id(conn: Any, address_id: str, *, lock: bool = False
                             ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {ADDRESS_COLUMNS} FROM payout_addresses"
                    f" WHERE address_id::text = %s{suffix}", (str(address_id),))
        return cur.fetchone()


def find_payout_address_by_key(conn: Any, account_id: str, chain_id: str, address: str
                               ) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {ADDRESS_COLUMNS} FROM payout_addresses"
                    " WHERE account_id = %s AND chain_id = %s AND address = %s",
                    (account_id, chain_id, str(address).lower()))
        return cur.fetchone()


def find_payout_address_by_idempotency(conn: Any, key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {ADDRESS_COLUMNS} FROM payout_addresses WHERE idempotency_key = %s",
                    (key,))
        return cur.fetchone()


def update_payout_address(conn: Any, address_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "cooldown_until", "approved_by", "approved_at", "rejected_reason",
               "risk_level", "first_transfer_at", "first_transfer_minor", "changed_at",
               "previous_address", "ownership_verified_at", "label"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"payout_addresses 不可更新字段：{sorted(unknown)}")
    if not fields:
        return get_payout_address_by_id(conn, address_id) or {}
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(address_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"UPDATE payout_addresses SET {assignments}, updated_at = now()"
                    f" WHERE address_id = %s RETURNING {ADDRESS_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("收款地址不存在")
    return dict(row)


def list_payout_addresses(conn: Any, *, account_id: str | None = None,
                          limit: int = facts.DEFAULT_PAGE_SIZE) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        if account_id is None:
            cur.execute(f"SELECT {ADDRESS_COLUMNS} FROM payout_addresses"
                        " ORDER BY created_at DESC LIMIT %s", (limit,))
        else:
            cur.execute(f"SELECT {ADDRESS_COLUMNS} FROM payout_addresses WHERE account_id = %s"
                        " ORDER BY created_at DESC LIMIT %s", (account_id, limit))
        return list(cur.fetchall())


# ═══════════════════════════════════════════════════════════ 退款
def insert_refund(conn: Any, *, refund_request_id: str, account_id: str, order_no: str,
                  payment_ref: str, amount_minor: int, currency: str, reason_code: str,
                  evidence_ref: str | None, original_route: str, original_route_hash: str,
                  status: str, deadline_at: datetime, requested_by: str,
                  cooldown_until: datetime, idempotency_key: str | None,
                  now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO refund_requests (refund_request_id, account_id, order_no, payment_ref,
                                         amount_minor, currency, reason_code, evidence_ref,
                                         original_route, original_route_hash, status, deadline_at,
                                         requested_by, cooldown_until, idempotency_key,
                                         created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {REFUND_COLUMNS}
            """,
            (str(refund_request_id), account_id, order_no, payment_ref, int(amount_minor),
             currency, reason_code, evidence_ref, original_route, original_route_hash, status,
             deadline_at, requested_by, cooldown_until, idempotency_key, now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_refund(conn: Any, identifier: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {REFUND_COLUMNS} FROM refund_requests"
            f" WHERE refund_request_id::text = %s OR refund_no = %s{suffix}",
            (str(identifier), str(identifier)))
        return cur.fetchone()


def find_open_refund(conn: Any, order_no: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"SELECT {REFUND_COLUMNS} FROM refund_requests"
            " WHERE order_no = %s AND status IN ('requested','approved','executing')"
            f" ORDER BY created_at DESC LIMIT 1{suffix}", (str(order_no),))
        return cur.fetchone()




def find_payout_by_intent(conn: Any, intent_id: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {PAYOUT_COLUMNS} FROM payout_batches"
                    f" WHERE intent_id = %s{suffix}", (str(intent_id),))
        return cur.fetchone()


def find_provision_by_signing_request(conn: Any, signing_request_id: str,
                                      *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {BATCH_COLUMNS} FROM wallet_provision_batch"
                    f" WHERE signing_request_id = %s{suffix}", (str(signing_request_id),))
        return cur.fetchone()


def find_refund_by_idempotency(conn: Any, key: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {REFUND_COLUMNS} FROM refund_requests WHERE idempotency_key = %s",
                    (key,))
        return cur.fetchone()


def update_refund(conn: Any, refund_request_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "approved_by", "approved_at", "executing_at", "succeeded_at",
               "failed_at", "failure_code", "journal_id"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"refund_requests 不可更新字段：{sorted(unknown)}")
    if not fields:
        return get_refund(conn, refund_request_id) or {}
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(refund_request_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"UPDATE refund_requests SET {assignments}, updated_at = now()"
                    f" WHERE refund_request_id = %s RETURNING {REFUND_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("退款申请不存在")
    return dict(row)


def list_refunds(conn: Any, *, account_id: str, cursor: str | None = None,
                 limit: int = facts.DEFAULT_PAGE_SIZE
                 ) -> tuple[list[dict[str, Any]], bool, str | None]:
    conditions = ["account_id = %s"]
    params: list[Any] = [account_id]
    parsed = models.decode_cursor(cursor)
    if parsed is not None:
        moment, identity = parsed
        conditions.append("(created_at, refund_request_id) < (%s, %s)")
        params.extend([moment, identity])
    params.append(limit + 1)
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {REFUND_COLUMNS} FROM refund_requests WHERE "
                    + " AND ".join(conditions) +
                    " ORDER BY created_at DESC, refund_request_id DESC LIMIT %s", tuple(params))
        rows = list(cur.fetchall())
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = models.encode_cursor(last["created_at"], str(last["refund_request_id"]))
    return rows, has_more, next_cursor


def refunded_total(conn: Any, order_no: str) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COALESCE(sum(amount_minor), 0) FROM refund_requests"
                    " WHERE order_no = %s AND status IN ('approved','executing','succeeded')",
                    (str(order_no),))
        return int(cur.fetchone()[0])


# ═══════════════════════════════════════════════════════════ 资金意图 / 签名
def insert_intent(conn: Any, *, intent_id: str, kind: str, chain_id: str, asset: str,
                  total_amount_minor: int, item_count: int, recipients_hash: str | None,
                  status: str, policy_version: str, memo_hash: str | None, created_by: str,
                  correlation_id: str | None, idempotency_key: str | None,
                  expires_at: datetime, now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO treasury_intents (intent_id, kind, chain_id, asset, total_amount_minor,
                                          item_count, recipients_hash, status, policy_version,
                                          memo_hash, created_by, correlation_id, idempotency_key,
                                          created_at, expires_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {INTENT_COLUMNS}
            """,
            (str(intent_id), kind, chain_id, asset, int(total_amount_minor), int(item_count),
             recipients_hash, status, policy_version, memo_hash, created_by, correlation_id,
             idempotency_key, now, expires_at, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_intent(conn: Any, intent_id: str, *, lock: bool = False) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {INTENT_COLUMNS} FROM treasury_intents"
                    f" WHERE intent_id::text = %s{suffix}", (str(intent_id),))
        return cur.fetchone()


def update_intent(conn: Any, intent_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "auth_object_type", "auth_hash"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"treasury_intents 不可更新字段：{sorted(unknown)}")
    if not fields:
        return get_intent(conn, intent_id) or {}
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(intent_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"UPDATE treasury_intents SET {assignments}, updated_at = now()"
                    f" WHERE intent_id = %s RETURNING {INTENT_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("资金意图不存在")
    return dict(row)


def insert_signing_request(conn: Any, *, signing_request_id: str, intent_id: str, kind: str,
                           status: str, signer_set_ref: str | None, threshold_n: int,
                           signer_count_n: int, policy_version: str, requested_at: datetime,
                           expires_at: datetime, created_by: str,
                           idempotency_key: str | None, now: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO signing_intents (signing_request_id, intent_id, kind, status,
                                         signer_set_ref, threshold_n, signer_count_n,
                                         signed_count, policy_version, requested_at, expires_at,
                                         created_by, idempotency_key, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 0, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {SIGNING_COLUMNS}
            """,
            (str(signing_request_id), str(intent_id), kind, status, signer_set_ref,
             int(threshold_n), int(signer_count_n), policy_version, requested_at, expires_at,
             created_by, idempotency_key, now, now))
        row = cur.fetchone()
    assert row is not None
    return dict(row)


def get_signing_request(conn: Any, signing_request_id: str, *, lock: bool = False
                        ) -> dict[str, Any] | None:
    suffix = " FOR UPDATE" if lock else ""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {SIGNING_COLUMNS} FROM signing_intents"
                    f" WHERE signing_request_id::text = %s{suffix}", (str(signing_request_id),))
        return cur.fetchone()


def update_signing_request(conn: Any, signing_request_id: str, **fields: Any) -> dict[str, Any]:
    allowed = {"status", "signed_count", "presented_at", "signed_at", "verified_at",
               "co_signed_at", "broadcast_at", "auth_hash", "txid"}
    unknown = set(fields) - allowed
    if unknown:
        raise BadRequest(f"signing_intents 不可更新字段：{sorted(unknown)}")
    if not fields:
        return get_signing_request(conn, signing_request_id) or {}
    assignments = ", ".join(f"{name} = %s" for name in fields)
    params = list(fields.values()) + [str(signing_request_id)]
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"UPDATE signing_intents SET {assignments}, updated_at = now()"
                    f" WHERE signing_request_id = %s RETURNING {SIGNING_COLUMNS}", tuple(params))
        row = cur.fetchone()
    if row is None:
        raise NotFound("签名请求不存在")
    return dict(row)


def insert_signing_event(conn: Any, *, signing_event_id: str, signing_request_id: str,
                         event: str, signer_type: str, signer_ref: str | None,
                         signature_hash: str | None, device_id: str | None,
                         auth_hash: str | None, txid: str | None, error_code: str | None,
                         occurred_at: datetime) -> dict[str, Any]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            f"""
            INSERT INTO signing_events (signing_event_id, signing_request_id, event, signer_type,
                                        signer_ref, signature_hash, device_id, auth_hash, txid,
                                        error_code, occurred_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (signing_request_id, event, signer_type) DO NOTHING
            RETURNING {SIGNING_EVENT_COLUMNS}
            """,
            (str(signing_event_id), str(signing_request_id), event, signer_type, signer_ref,
             signature_hash, device_id, auth_hash, txid, error_code, occurred_at))
        row = cur.fetchone()
        if row is not None:
            return dict(row)
        cur.execute(f"SELECT {SIGNING_EVENT_COLUMNS} FROM signing_events"
                    " WHERE signing_request_id = %s AND event = %s AND signer_type = %s",
                    (str(signing_request_id), event, signer_type))
        existing = cur.fetchone()
    if existing is None:                                # pragma: no cover - 竞态兜底
        raise NotFound("签名事件不存在")
    return dict(existing)


def list_signing_events(conn: Any, signing_request_id: str) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {SIGNING_EVENT_COLUMNS} FROM signing_events"
                    " WHERE signing_request_id = %s ORDER BY seq ASC", (str(signing_request_id),))
        return list(cur.fetchall())


def last_signing_event(conn: Any, signing_request_id: str) -> dict[str, Any] | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(f"SELECT {SIGNING_EVENT_COLUMNS} FROM signing_events"
                    " WHERE signing_request_id = %s ORDER BY seq DESC LIMIT 1",
                    (str(signing_request_id),))
        return cur.fetchone()


def signed_counts(conn: Any, signing_request_id: str) -> dict[str, int]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FILTER (WHERE event = 'signed'),"
            "       count(*) FILTER (WHERE event = 'co_signed'),"
            "       count(*) FILTER (WHERE event = 'verified')"
            " FROM signing_events WHERE signing_request_id = %s", (str(signing_request_id),))
        signed, co_signed, verified = cur.fetchone()
    return {"signed": int(signed), "co_signed": int(co_signed), "verified": int(verified)}

