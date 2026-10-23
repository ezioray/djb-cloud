# SPDX-License-Identifier: Apache-2.0
"""M08b 钱包池 / 预生成 / 激活 / 切换 / 退休 / 归集 / 平台收款地址（M08 §3 / §6 流程 4 / §7）。

关键口径（逐条对应不变量）：

INV-01 池键 chain:role:fund_class 创建后不可改；一只钱包只属一个池与一个 fund_class
INV-02 激活批次内不得携带转账指令（描述符只含地址 / wallet_id / 角色 / 阈值；库层 CHECK 兜底）
INV-03 standby 余额 = 0；ready = active ∧ gas_ok（激活 ≠ 可用）
INV-04 cap × 在用只数 ≤ 池合计上限；cap 下限 1,000 USD
INV-05 max_active 只自动上调（+4，硬顶 20）
INV-06 池空不得停收款：新地址先摊到现有钱包，扩容量另行走批次
INV-13 地址白名单（出款侧在 payout.py；这里只做平台收款地址的冷却）

fund_class 口径（Lead 2026-10-24 裁决）：API / 事件 / 响应一律用规范枚举 {CLIENT, PLATFORM}；
004 存量表的历史命名 customer / platform 只做**存储层映射**（policy.storage_pool_key），
不改旧表、不改旧命名。wallet.role ∈ {hot, warm} 与 fund_class 是两维。

密钥边界：地址由 HSM / xpub 派生服务产出；本模块**不派生私钥**。S1/S2 使用注入的
address_allocator；默认 SyntheticAddressAllocator 只生成**测试网占位地址**（无密钥能力），
批次 cap_params 会记录 synthetic=true，真实环境必须注入 HSM 分配器（证据「遗留」CR-P9）。
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Mapping, Sequence

from . import clock, config_source, errors, events, facts, ids, models, policy, signing, store
from .errors import (
    AddressConflict,
    BadRequest,
    ChainUnsupported,
    Conflict,
    NotFound,
    ProvisionBatchExpired,
)

__all__ = [
    "AddressAllocator", "SyntheticAddressAllocator", "create_pool", "list_pools", "pool_detail",
    "provision", "request_provision_signature", "activate_batch", "switch_address",
    "retire_wallet", "sweep_plan", "complete_sweep", "get_platform_deposit_address",
    "publish_platform_deposit_address", "PLATFORM_DEPOSIT_ACCOUNT", "DEPOSIT_COOLDOWN_H",
]

#: 平台收款地址的「账户」标识（deposit_address.account_id）
PLATFORM_DEPOSIT_ACCOUNT = "platform:deposit"
DEPOSIT_COOLDOWN_H = 24


class AddressAllocator:
    """地址分配器协议（HSM / xpub 派生服务在合并期注入）。"""

    synthetic = False

    def allocate(self, *, pool_id: str, count: int, start_index: int) -> list[str]:
        raise NotImplementedError


class SyntheticAddressAllocator(AddressAllocator):
    """测试网占位地址（无密钥能力；确定性，便于断言）。

    地址形态 = 0x + sha256(pool_id|index)，**不可用于主网**；批次会记录 synthetic=true。
    """

    synthetic = True

    def allocate(self, *, pool_id: str, count: int, start_index: int) -> list[str]:
        addresses: list[str] = []
        for offset in range(int(count)):
            index = int(start_index) + offset
            digest = hashlib.sha256(f"{pool_id}|{index}".encode("utf-8")).hexdigest()
            addresses.append("0x" + digest[:40])
        return addresses


def _config(config_provider: config_source.ConfigProvider | None,
            chain: str, role: str, fund_class: str) -> config_source.TreasuryConfig:
    return config_source.load(config_provider, chain=chain, role=role, fund_class=fund_class)


def _pool_row(conn: Any, canonical_pool_id: str, *, lock: bool = False) -> dict[str, Any]:
    storage = policy.storage_pool_key(canonical_pool_id)
    row = store.get_pool(conn, storage, lock=lock)
    if row is None:
        raise NotFound("钱包池不存在")
    return row


# ═══════════════════════════════════════════════════════════ 池
def create_pool(conn: Any, draft: models.PoolDraft, *, actor: str, now: datetime,
                idempotency_key: str | None = None,
                config_provider: config_source.ConfigProvider | None = None
                ) -> dict[str, Any]:
    """新建钱包池（池键不可变；cap / max_active 受 facts §2 约束）。"""
    chain, role, fund_class = draft.chain, draft.role, draft.fund_class
    if chain != facts.CHAIN_ID:
        raise ChainUnsupported("一期仅 Polygon（K6）", reason="chain_unsupported")
    if role == "hot" and fund_class == "PLATFORM":
        raise BadRequest("平台热池不建（决策 K5）", field="fund_class")
    if draft.pool_cap_minor <= 0:
        raise BadRequest("pool_cap_minor 必须 > 0", field="pool_cap_minor")
    if draft.max_active * facts.WALLET_CAP_FLOOR_MINOR > draft.pool_cap_minor:
        raise BadRequest(
            "池合计上限不足以覆盖 cap 下限 × max_active（INV-04）", field="pool_cap_minor")
    storage_fund_class = policy.legacy_fund_class(fund_class)
    existing = store.find_pool_by_key(conn, chain, role, storage_fund_class)
    if existing is not None:
        return {"pool": existing, "created": False}
    moment = clock.as_utc(now)
    config = _config(config_provider, chain, role, fund_class)
    row = store.insert_pool(
        conn, pool_id=f"{chain}:{role}:{storage_fund_class}", chain_id=chain, role=role,
        fund_class=storage_fund_class, min_spare=draft.min_spare, max_active=draft.max_active,
        switch_threshold_pct=draft.switch_threshold_pct,
        activate_batch_size=draft.activate_batch_size,
        provision_lead_time_h=draft.provision_lead_time_h,
        pool_cap_minor=draft.pool_cap_minor, switch_policy="least_utilized",
        policy_version=config.policy_version, now=moment)
    store.append_pool_event(conn, pool_id=str(row["pool_id"]), event="wallet_pool_created",
                            batch_id=None, actor=actor,
                            payload={"pool_id": policy.canonical_pool_id(str(row["pool_id"])),
                                     "reason": draft.reason,
                                     "idempotency_key": None if not idempotency_key
                                     else hashlib.sha256(
                                         idempotency_key.encode()).hexdigest()[:16]},
                            now=moment)
    return {"pool": row, "created": True}


def list_pools(conn: Any, *, config_provider: config_source.ConfigProvider | None = None,
               status: str | None = None, role: str | None = None) -> list[dict[str, Any]]:
    if status is not None and status not in ("active", "paused", "retired"):
        raise BadRequest("status 必须是 active / paused / retired 之一", field="status")
    if role is not None and role not in ("hot", "warm"):
        raise BadRequest("role 必须是 hot / warm 之一", field="role")
    rows = store.list_wallet_pool_rows(conn, status=status, role=role)
    payloads: list[dict[str, Any]] = []
    for row in rows:
        fund_class = policy.canonical_fund_class(row["fund_class"])
        config = _config(config_provider, row["chain_id"], row["role"], fund_class)
        payload = models.pool_payload(row)
        payload["effective_config"] = config.as_dict()
        payloads.append(payload)
    return payloads


def pool_detail(conn: Any, canonical_pool_id: str, *,
                config_provider: config_source.ConfigProvider | None = None) -> dict[str, Any]:
    pool = _pool_row(conn, canonical_pool_id)
    chain, role, fund_class = policy.split_pool_key(
        policy.canonical_pool_id(str(pool["pool_id"])))
    wallets = store.list_wallets(conn, str(pool["pool_id"]))
    config = _config(config_provider, chain, role, fund_class)
    depth = policy.depth(wallets)
    active = [wallet for wallet in wallets if wallet["status"] == facts.WALLET_ACTIVE]
    in_service = [wallet for wallet in active if wallet["switch_state"] == facts.SWITCH_IN_SERVICE]
    availability = policy.pool_empty_plan(wallets=wallets) if depth["depth_ready"] == 0 else None
    row = {**pool, **depth, "in_service_count": len(in_service),
           "active_balance_minor": sum(int(item["balance_minor"]) for item in active)}
    payload = models.pool_payload(row, wallets=wallets)
    payload["effective_config"] = config.as_dict()
    payload["provision_required"] = policy.should_provision(
        depth_available=depth["depth_available"], min_spare=config.min_spare,
        projected_utilization_pct=0, auto_expand=config.auto_expand)
    payload["pool_empty_plan"] = availability
    return payload


# ═══════════════════════════════════════════════════════════ 预生成 / 激活
def provision(conn: Any, draft: models.ProvisionDraft, *, actor: str,
              idempotency_key: str | None,
              config_provider: config_source.ConfigProvider | None,
              allocator: AddressAllocator | None, now: datetime,
              trace_id: str | None = None) -> dict[str, Any]:
    """预生成：只造描述符与占位地址，**不碰钱、不含转账指令**（INV-02）。"""
    chain, role, fund_class = policy.split_pool_key(draft.pool_id)
    pool = _pool_row(conn, draft.pool_id, lock=True)
    storage_pool_id = str(pool["pool_id"])
    if pool["status"] != "active":
        raise Conflict(f"池 {draft.pool_id} 当前状态 {pool['status']}，不得预生成",
                       reason="pool_not_active")
    if idempotency_key:
        replay = store.find_provision_by_idempotency(conn, idempotency_key)
        if replay is not None:
            return {"batch": replay, "replayed": True, "wallets": []}
    config = _config(config_provider, chain, role, fund_class)
    wallets = store.list_wallets(conn, storage_pool_id)
    count = min(int(draft.wallet_count), int(pool["activate_batch_size"]))
    count = max(facts.ACTIVATE_BATCH_MIN, min(count, facts.MAX_BATCH_SIZE))
    occupied = len([wallet for wallet in wallets
                    if wallet["status"] in (facts.WALLET_ACTIVE, facts.WALLET_PROVISIONING)])
    if occupied + count > int(pool["max_active_count"]):
        raise Conflict(
            f"超出 max_active（{pool['max_active_count']}）：扩容只开容量，不得越过在用上限"
            "（INV-05：上调须走已发布策略，不自动缩容）",
            reason="max_active_exceeded")
    cap = policy.cap_plan(pool_cap_minor=int(pool["pool_cap_minor"]),
                          in_service_count=max(int(pool["max_active_count"]), 1))
    allocator = allocator or SyntheticAddressAllocator()
    start_index = len(wallets)
    addresses = allocator.allocate(pool_id=storage_pool_id, count=count,
                                   start_index=start_index)
    signer_set_ref = signing.WALLET_SIGNER_SET
    wallet_ids = [str(ids.uuid7()) for _ in range(count)]
    descriptors = policy.descriptors_for_batch(
        pool_id=draft.pool_id, wallet_ids=wallet_ids, addresses=addresses,
        signer_set_ref=signer_set_ref)
    policy.assert_no_transfer_instructions({"descriptors": descriptors})
    merkle = policy.descriptor_merkle_root(descriptors)
    moment = clock.as_utc(now)
    batch_no = f"WB-{moment:%Y%m%d}-{ids.random_hex(3)}"
    batch = store.insert_provision_batch(
        conn, batch_id=str(ids.uuid7()), pool_id=storage_pool_id, batch_no=batch_no,
        wallet_count=count, descriptor_merkle_root=merkle,
        cap_params={"wallet_cap_minor": cap, "pool_cap_minor": int(pool["pool_cap_minor"]),
                    "max_active": int(pool["max_active_count"]),
                    "synthetic": bool(getattr(allocator, "synthetic", False)),
                    "descriptors": descriptors},
        dedupe_key=f"{storage_pool_id}:{batch_no}", status="draft",
        expires_at=clock.add_seconds(moment, facts.PROVISION_BATCH_TTL_H * 3600),
        created_by=actor, idempotency_key=idempotency_key,
        policy_version=config.policy_version, now=moment)
    created: list[dict[str, Any]] = []
    for descriptor, wallet_id in zip(descriptors, wallet_ids):
        existing = store.get_wallet_by_address(conn, chain, descriptor["address"])
        if existing is not None:
            raise AddressConflict(f"地址冲突：{descriptor['address']} 已存在（40915，整批不激活）",
                                  reason="address_conflict")
        row = store.insert_wallet(
            conn, wallet_id=wallet_id, chain_id=chain, address=descriptor["address"],
            pool_id=storage_pool_id, role=role, fund_class=policy.legacy_fund_class(fund_class),
            custody_kind="self_custody_hot" if role == "hot" else "self_custody_warm",
            signer_set_ref=signer_set_ref,
            descriptor_hash=hashlib.sha256(
                f"{wallet_id}|{descriptor['address']}".encode("utf-8")).hexdigest(),
            cap_minor=cap, policy_version=config.policy_version, now=moment)
        created.append(row)
    store.append_pool_event(conn, pool_id=storage_pool_id, event="wallet_provision",
                            batch_id=str(batch["batch_id"]), actor=actor,
                            payload={"batch_no": batch_no, "wallet_count": count,
                                     "descriptor_merkle_root": merkle,
                                     "synthetic": bool(getattr(allocator, "synthetic", False))},
                            now=moment)
    return {"batch": batch, "replayed": False, "wallets": created,
            "descriptors_merkle_root": merkle,
            "note": "扩容只开容量：本批次不含任何转账指令（INV-02）"}


def request_provision_signature(conn: Any, batch_id: str, *, actor: str,
                                now: datetime, trace_id: str | None = None,
                                idempotency_key: str | None = None) -> dict[str, Any]:
    """预生成批次 → WALLET_PROVISION 意图 + 签名请求（≤24h，不动钱）。

    说明：spec 1.2.5 没有为预生成单独开签名请求端点（activate 只引用 signing_request_id），
    因此这是**域内函数**（签名域 / 内部任务调用），不进 HTTP 路由。
    """
    batch = store.get_provision_batch(conn, batch_id, lock=True)
    if batch is None:
        raise NotFound("预生成批次不存在")
    if batch["status"] in ("activated", "expired", "failed", "cancelled"):
        raise Conflict(f"批次已是终态：{batch['status']}", reason="batch_terminal")
    moment = clock.as_utc(now)
    if moment >= clock.as_utc(batch["expires_at"]):
        store.update_provision_batch(conn, str(batch["batch_id"]), status="expired")
        raise ProvisionBatchExpired("扩容批次已过期（40914）：请重新生成描述符再签",
                                    reason="provision_batch_expired")
    if batch["status"] in ("pending_sign", "signed") and batch.get("signing_request_id"):
        existing = store.get_signing_request(conn, str(batch["signing_request_id"]))
        if existing is not None:
            return {"batch": batch, "intent": None, "signing_request": existing,
                    "replayed": True}
    canonical = policy.canonical_pool_id(str(batch["pool_id"]))
    chain, role, fund_class = policy.split_pool_key(canonical)
    pool = store.get_pool(conn, str(batch["pool_id"]))
    result = signing.request_signature(
        conn, kind="WALLET_PROVISION", chain_id=chain,
        asset=facts.PAYOUT_ASSET, total_amount_minor=0, item_count=int(batch["wallet_count"]),
        recipients_hash=str(batch["descriptor_merkle_root"]),
        policy_version=str(batch["policy_version"] or "m08-pool-default"),
        created_by=actor, correlation_id=str(batch["batch_no"]), now=moment,
        trace_id=trace_id, idempotency_key=idempotency_key,
        memo="WALLET_PROVISION：只开容量，不含转账")
    batch = store.update_provision_batch(
        conn, str(batch["batch_id"]), status="pending_sign",
        signing_request_id=str(result["signing_request"]["signing_request_id"]))
    store.append_pool_event(conn, pool_id=str(batch["pool_id"]),
                            event="wallet_sign_requested",
                            batch_id=str(batch["batch_id"]), actor=actor,
                            payload={"signing_request_id": str(
                                result["signing_request"]["signing_request_id"]),
                                "pool_status": (pool or {}).get("status")}, now=moment)
    return {"batch": batch, "intent": result["intent"],
            "signing_request": result["signing_request"], "replayed": False}


def _bind_signing_request(conn: Any, batch: Mapping[str, Any],
                          signing_request_id: str | None) -> None:
    """activate 只引用签名请求：可绑定一次，绑定后不可改（不接受签名字节）。"""
    existing = batch.get("signing_request_id")
    if signing_request_id is None:
        if not existing:
            raise Conflict("批次尚未绑定签名请求：缺 2/3 签不得激活（INV-10）",
                           reason="signature_missing")
        return
    request = store.get_signing_request(conn, str(signing_request_id))
    if request is None:
        raise NotFound("签名请求不存在")
    if existing is not None and str(existing) != str(signing_request_id):
        raise Conflict("批次已绑定其他签名请求：不得替换（改单 = 新批次）",
                       reason="signing_request_conflict")
    if existing is None:
        store.update_provision_batch(conn, str(batch["batch_id"]),
                                     signing_request_id=str(signing_request_id))


def activate_batch(conn: Any, batch_id: str, *, actor: str, now: datetime,
                   signing_request_id: str | None = None,
                   trace_id: str | None = None) -> dict[str, Any]:
    """2/3 签名 + HSM 验签后批量激活；余额必须为 0（INV-03），地址不得冲突（40915）。"""
    batch = store.get_provision_batch(conn, batch_id, lock=True)
    if batch is None:
        raise NotFound("预生成批次不存在")
    if batch["status"] == "activated":
        raise Conflict("批次已激活，不可回退（§3）", reason="batch_already_activated")
    if batch["status"] in ("expired", "failed", "cancelled"):
        raise Conflict(f"批次已是终态：{batch['status']}", reason="batch_terminal")
    moment = clock.as_utc(now)
    if moment >= clock.as_utc(batch["expires_at"]):
        store.update_provision_batch(conn, str(batch["batch_id"]), status="expired")
        raise ProvisionBatchExpired("扩容批次已过期（40914）", reason="provision_batch_expired")
    _bind_signing_request(conn, batch, signing_request_id)
    batch = store.get_provision_batch(conn, batch_id, lock=True) or batch
    signing.require_signed(conn, str(batch["signing_request_id"]))
    if batch["status"] == "pending_sign":
        batch = store.update_provision_batch(conn, str(batch["batch_id"]), status="signed")
    cap_params = dict(batch.get("cap_params") or {})
    descriptors = list(cap_params.get("descriptors") or [])
    if not descriptors:
        raise Conflict("批次缺少描述符（不可激活）", reason="descriptor_missing")
    activated: list[dict[str, Any]] = []
    in_service_assigned = any(
        wallet["status"] == facts.WALLET_ACTIVE
        and wallet["switch_state"] == facts.SWITCH_IN_SERVICE
        for wallet in store.list_wallets(conn, str(batch["pool_id"])))
    for descriptor in descriptors:
        wallet = store.get_wallet(conn, str(descriptor["wallet_id"]), lock=True)
        if wallet is None:
            raise NotFound("批次钱包不存在")
        if wallet["status"] == facts.WALLET_RETIRED:
            raise Conflict("已退休钱包不得重新激活（只能新建一只）", reason="wallet_retired")
        if int(wallet["balance_minor"]) != 0:
            raise Conflict("standby 钱包余额必须为 0（INV-03）", reason="standby_balance_not_zero")
        switch_state = facts.SWITCH_STANDBY if in_service_assigned else facts.SWITCH_IN_SERVICE
        in_service_assigned = True
        wallet = store.update_wallet(conn, str(wallet["wallet_id"]),
                                     status=facts.WALLET_ACTIVE,
                                     switch_state=switch_state,
                                     activated_at=moment)
        store.insert_activation(
            conn, activation_id=str(ids.uuid7()), batch_id=str(batch["batch_id"]),
            wallet_id=str(wallet["wallet_id"]), switch_state=switch_state,
            cap_applied_minor=int(wallet.get("cap_minor") or 0), status="activated",
            activated_at=moment, audit_hash=str(batch["descriptor_merkle_root"]))
        activated.append(wallet)
    batch = store.update_provision_batch(
        conn, str(batch["batch_id"]), status="activated", activated_at=moment,
        hsm_verified_at=moment)
    store.append_pool_event(conn, pool_id=str(batch["pool_id"]), event="wallet_activation",
                            batch_id=str(batch["batch_id"]), actor=actor,
                            payload={"wallet_ids": [str(item["wallet_id"])
                                                    for item in activated],
                                     "descriptor_merkle_root": str(
                                         batch["descriptor_merkle_root"])},
                            now=moment)
    return {"batch": batch, "wallets": activated}


# ═══════════════════════════════════════════════════════════ 切换 / 退休
def switch_address(conn: Any, draft: models.SwitchDraft, *, actor: str,
                   config_provider: config_source.ConfigProvider | None,
                   now: datetime, trace_id: str | None = None) -> dict[str, Any]:
    """一级触发：把新收款地址切到池内下一只（least_utilized → newest_activated）。

    池空（无 ready 钱包）时**不停收款**：返回 spread_to（摊到现有钱包）+ 扩容建议（INV-06）。
    """
    chain, role, fund_class = policy.split_pool_key(draft.pool_id)
    pool = _pool_row(conn, draft.pool_id, lock=True)
    storage_pool_id = str(pool["pool_id"])
    if not draft.reason:
        raise BadRequest("reason 必填（切换必须留理由）", field="reason")
    wallets = store.list_wallets(conn, storage_pool_id, lock=True)
    depth = policy.depth(wallets)
    current = next((wallet for wallet in wallets
                    if wallet["status"] == facts.WALLET_ACTIVE
                    and wallet["switch_state"] == facts.SWITCH_IN_SERVICE), None)
    target = policy.select_switch_wallet(
        wallet for wallet in wallets if wallet is not current)
    moment = clock.as_utc(now)
    if target is None:
        plan = policy.pool_empty_plan(wallets=wallets)
        store.append_pool_event(conn, pool_id=storage_pool_id, event="wallet_switch_skipped",
                                batch_id=None, actor=actor,
                                payload={"reason": "pool_empty", "depth": depth,
                                         "plan": plan}, now=moment)
        return {"switched": False, "pool_id": draft.pool_id, "plan": plan,
                "stop_collection": False,
                "ack": models.switch_ack_payload(
                    pool_id=draft.pool_id, status="triggered",
                    from_wallet_id=(None if current is None else str(current["wallet_id"])),
                    to_wallet_id=None, switched_at=None, plan=plan)}
    from_wallet = str(current["wallet_id"]) if current else ""
    if current is not None:
        store.update_wallet(conn, str(current["wallet_id"]),
                            switch_state=facts.SWITCH_SWITCHING_OUT,
                            last_switched_at=moment)
    target = store.update_wallet(conn, str(target["wallet_id"]),
                                 switch_state=facts.SWITCH_IN_SERVICE)
    switch_id = str(ids.uuid7())
    events.wallet_switched(conn, pool_id=draft.pool_id, from_wallet=from_wallet,
                           to_wallet=str(target["wallet_id"]), reason=draft.reason,
                           occurred_at=moment, switch_id=switch_id, trace_id=trace_id)
    store.append_pool_event(conn, pool_id=storage_pool_id, event="wallet_switch",
                            batch_id=None, actor=actor,
                            payload={"from_wallet": from_wallet,
                                     "to_wallet": str(target["wallet_id"]),
                                     "switch_id": switch_id, "reason": draft.reason},
                            now=moment)
    return {"switched": True, "pool_id": draft.pool_id, "from_wallet": from_wallet,
            "to_wallet": target, "switch_id": switch_id, "stop_collection": False,
            "ack": models.switch_ack_payload(
                pool_id=draft.pool_id, status="done",
                from_wallet_id=from_wallet or None,
                to_wallet_id=str(target["wallet_id"]), switched_at=moment)}


def retire_wallet(conn: Any, draft: models.RetireDraft, *, actor: str,
                  attestation_valid: bool, now: datetime,
                  trace_id: str | None = None) -> dict[str, Any]:
    """退休四步：drain → zero → frozen → retire（退休必须有 attestation，40916）。"""
    wallet = store.get_wallet(conn, draft.wallet_id, lock=True)
    if wallet is None:
        raise NotFound("钱包不存在")
    moment = clock.as_utc(now)
    in_flight = store.wallet_in_flight(conn, draft.wallet_id)
    target_status = policy.retire_step(
        status=str(wallet["status"]), step=draft.step,
        balance_minor=int(wallet["balance_minor"]), in_flight=in_flight,
        last_switched_at=wallet.get("last_switched_at"), now=moment)
    if policy.retire_required_attestation(draft.step):
        policy.ensure_attestation(attestation_ref=draft.attestation_ref,
                                  valid=bool(attestation_valid))
    fields: dict[str, Any] = {"status": target_status}
    if draft.step == "drain":
        fields["switch_state"] = facts.SWITCH_SWITCHING_OUT
        fields["last_switched_at"] = wallet.get("last_switched_at") or moment
    elif draft.step == "zero":
        fields["switch_state"] = facts.SWITCH_DRAINING
    elif draft.step == "retire":
        fields["retired_at"] = moment
        fields["retired_reason"] = f"retire_by:{actor}"
    updated = store.update_wallet(conn, draft.wallet_id, **fields)
    store.append_pool_event(conn, pool_id=str(wallet["pool_id"] or ""),
                            event=f"wallet_retire_{draft.step}", batch_id=None, actor=actor,
                            payload={"wallet_id": draft.wallet_id, "status": target_status,
                                     "in_flight": in_flight,
                                     "reason": draft.reason}, now=moment)
    return models.wallet_payload(updated)


# ═══════════════════════════════════════════════════════════ 归集（热 → 温）
def sweep_plan(conn: Any, *, pool_id: str, config_provider: config_source.ConfigProvider | None,
               actor: str, now: datetime, trace_id: str | None = None) -> dict[str, Any]:
    """归集制单：余额 > cap 60% 且 gas 充足 → SWEEP 意图 + 转账计划（逐批签，无免签）。"""
    chain, role, fund_class = policy.split_pool_key(pool_id)
    if role != "hot":
        raise BadRequest("归集只从热钱包发起（§19.7）", field="pool_id")
    pool = _pool_row(conn, pool_id, lock=True)
    config = _config(config_provider, chain, role, fund_class)
    wallets = store.list_wallets(conn, str(pool["pool_id"]))
    sources = [wallet for wallet in wallets
               if wallet["status"] == facts.WALLET_ACTIVE
               and policy.sweep_amount(balance_minor=int(wallet["balance_minor"]),
                                       cap_minor=int(wallet["cap_minor"]
                                                     or facts.WALLET_CAP_MINOR),
                                       gas_ok=bool(wallet["gas_ok"])) > 0]
    if not sources:
        return {"batch_no": None, "transfers": [], "intent": None,
                "reason": "no_sweep_needed"}
    target_pool = store.get_pool(conn, policy.storage_pool_key(
        policy.pool_key(chain, "warm", fund_class)))
    if target_pool is None:
        raise Conflict("同 fund_class 的温池不存在：归集不得跨 fund_class（§19.7）",
                       reason="no_warm_pool")
    destinations = [wallet for wallet in store.list_wallets(conn, str(target_pool["pool_id"]))
                    if wallet["status"] == facts.WALLET_ACTIVE
                    and wallet["switch_state"] == facts.SWITCH_IN_SERVICE]
    if not destinations:
        raise Conflict("温池没有 in_service 钱包：归集失败转人工（不跨 fund_class）",
                       reason="no_sweep_destination")
    destination = sorted(destinations, key=lambda item: int(item["balance_minor"]))[0]
    moment = clock.as_utc(now)
    batch_no = f"SW-{moment:%Y%m%d}-{ids.random_hex(3)}"
    transfers: list[dict[str, Any]] = []
    total_amount = 0
    for wallet in sources[:facts.SWEEP_MAX_SOURCE_WALLETS]:
        amount = policy.sweep_amount(balance_minor=int(wallet["balance_minor"]),
                                     cap_minor=int(wallet["cap_minor"]
                                                   or facts.WALLET_CAP_MINOR),
                                     gas_ok=bool(wallet["gas_ok"]))
        if amount <= 0:
            continue
        total_amount += int(amount)
        transfer = store.insert_transfer(
            conn, transfer_id=str(ids.uuid7()), batch_no=batch_no, kind="sweep",
            chain_id=chain, from_wallet_id=str(wallet["wallet_id"]),
            to_wallet_id=str(destination["wallet_id"]),
            from_address=str(wallet["address"]), to_address=str(destination["address"]),
            qty_minor=facts.MICRO_PER_MINOR * int(amount),
            amount_minor=int(amount) * facts.MICRO_PER_MINOR,
            gas_fee_minor=0, gas_reserve_pol=facts.GAS_RESERVE_POL, status="planned",
            intent_id=None, nonce=None, policy_version=config.policy_version, now=moment)
        transfers.append(transfer)
    recipients_hash = policy.descriptor_merkle_root([
        {"wallet_id": str(destination["wallet_id"]), "address": str(destination["address"]),
         "role": "warm", "fund_class": fund_class, "signer_set_ref": signing.WALLET_SIGNER_SET,
         "threshold": facts.SIGNER_THRESHOLD}])
    result = signing.request_signature(
        conn, kind="SWEEP", chain_id=chain, asset=facts.PAYOUT_ASSET,
        total_amount_minor=total_amount, item_count=len(transfers),
        recipients_hash=recipients_hash, policy_version=config.policy_version,
        created_by=actor, correlation_id=batch_no, now=moment, trace_id=trace_id,
        memo="SWEEP：热 → 温，逐批签")
    for transfer in transfers:
        with conn.cursor() as cur:
            cur.execute("UPDATE wallet_transfers SET intent_id = %s WHERE transfer_id = %s",
                        (str(result["intent"]["intent_id"]), str(transfer["transfer_id"])))
    store.append_pool_event(conn, pool_id=str(pool["pool_id"]), event="sweep_planned",
                            batch_id=None, actor=actor,
                            payload={"batch_no": batch_no,
                                     "transfer_count": len(transfers),
                                     "total_amount_minor": total_amount}, now=moment)
    return {"batch_no": batch_no, "transfers": transfers, "intent": result["intent"],
            "signing_request": result["signing_request"],
            "total_amount_minor": total_amount}


def complete_sweep(conn: Any, transfer_id: str, *, txid: str, actor: str, now: datetime,
                   trace_id: str | None = None) -> dict[str, Any]:
    """归集达确认：更新余额 / 转账状态 → sweep.completed（E9 由 M06 消费事件入账）。"""
    transfer = store.get_transfer(conn, transfer_id, lock=True)
    if transfer is None:
        raise NotFound("归集转账不存在")
    if transfer["kind"] != "sweep":
        raise BadRequest("该转账不是归集", field="transfer_id")
    if transfer["status"] == "confirmed":
        raise Conflict("归集转账已确认（幂等拒绝重复确认）", reason="transfer_confirmed")
    moment = clock.as_utc(now)
    with conn.cursor() as cur:
        cur.execute("UPDATE wallet_transfers SET status = 'confirmed', chain_tx_id = %s,"
                    " confirmed_at = %s, updated_at = now() WHERE transfer_id = %s",
                    (txid, moment, str(transfer_id)))
    amount_micro = int(transfer["amount_minor"])
    amount_units = amount_micro // facts.MICRO_PER_MINOR
    source = store.get_wallet(conn, str(transfer["from_wallet_id"]), lock=True)
    target = store.get_wallet(conn, str(transfer["to_wallet_id"]), lock=True)
    if source is not None:
        store.update_wallet(conn, str(source["wallet_id"]),
                            balance_minor=max(int(source["balance_minor"]) - amount_units, 0))
    if target is not None:
        store.update_wallet(conn, str(target["wallet_id"]),
                            balance_minor=int(target["balance_minor"]) + amount_units)
    events.sweep_completed(conn, batch_no=str(transfer["batch_no"]),
                           from_wallet=str(transfer["from_wallet_id"]),
                           to_wallet=str(transfer["to_wallet_id"]),
                           amount_minor=amount_micro, txid=txid, occurred_at=moment,
                           transfer_id=str(transfer_id), trace_id=trace_id)
    updated = store.get_transfer(conn, transfer_id)
    return {"transfer": updated, "txid": txid}


# ═══════════════════════════════════════════════════════════ 平台收款地址（后台）
def get_platform_deposit_address(conn: Any, *, chain_id: str = facts.CHAIN_ID
                                 ) -> dict[str, Any] | None:
    if chain_id != facts.CHAIN_ID:
        raise ChainUnsupported("一期仅 Polygon（K6）", reason="chain_unsupported")
    with conn.cursor() as cur:
        cur.execute(
            "SELECT address_id, chain_id, address, status, purpose, derivation_index,"
            " xpub_fingerprint, reason, ticket_id, monitoring_until, created_at, updated_at"
            " FROM deposit_address WHERE chain_id = %s AND purpose = 'platform'"
            " AND status = 'active' ORDER BY created_at DESC LIMIT 1", (chain_id,))
        row = cur.fetchone()
    if row is None:
        return None
    return {"address_id": str(row[0]), "chain_id": row[1], "address": row[2],
            "status": row[3], "purpose": row[4], "derivation_index": int(row[5]),
            "xpub_fingerprint": row[6], "reason": row[7], "ticket_id": row[8],
            "monitoring_until": row[9], "created_at": row[10], "updated_at": row[11]}


def get_deposit_address_view(conn: Any, *, chain_id: str = facts.CHAIN_ID) -> dict[str, Any]:
    row = get_platform_deposit_address(conn, chain_id=chain_id)
    return models.deposit_address_payload(row, chain=chain_id)


def publish_platform_deposit_address(conn: Any, draft: models.DepositAddressDraft, *,
                                     actor: str, now: datetime) -> dict[str, Any]:
    """发布平台收款地址：reason + ticket 必填；旧地址监听 ≥90 天；24h 冷却。"""
    if draft.chain != facts.CHAIN_ID:
        raise ChainUnsupported("一期仅 Polygon（K6）", reason="chain_unsupported")
    if not draft.reason or not draft.ticket:
        raise BadRequest("发布平台收款地址必须带 reason + ticket（高危四件套留痕）",
                         field="ticket")
    normalized = str(draft.address).strip().lower()
    if not normalized.startswith("0x") or len(normalized) != 42:
        raise BadRequest("address 必须是 0x 开头的 40 位十六进制地址", field="address")
    try:
        int(normalized[2:], 16)
    except ValueError as exc:
        raise BadRequest("address 不是合法十六进制地址", field="address") from exc
    moment = clock.as_utc(now)
    current = get_platform_deposit_address(conn, chain_id=draft.chain)
    monitoring_until = None
    if current is not None:
        created = clock.as_utc(current["created_at"])
        if moment < clock.add_seconds(created, DEPOSIT_COOLDOWN_H * 3600):
            raise Conflict("平台收款地址 24h 冷却未结束（§19.6.1）",
                           reason="address_cooldown")
        monitoring_until = clock.add_seconds(
            moment, facts.OLD_ADDRESS_MONITOR_D * 24 * 3600)
        with conn.cursor() as cur:
            cur.execute("UPDATE deposit_address SET status = 'retired',"
                        " monitoring_until = %s, updated_at = %s WHERE address_id = %s",
                        (monitoring_until, moment, current["address_id"]))
    with conn.cursor() as cur:
        cur.execute("SELECT COALESCE(max(derivation_index), 0) + 1 FROM deposit_address"
                    " WHERE chain_id = %s", (draft.chain,))
        index = int(cur.fetchone()[0])
        fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
        cur.execute(
            """
            INSERT INTO deposit_address (chain_id, address, account_id, purpose,
                                         derivation_path, derivation_index, xpub_fingerprint,
                                         status, reason, ticket_id, created_at, updated_at)
            VALUES (%s, %s, %s, 'platform', %s, %s, %s, 'active', %s, %s, %s, %s)
            RETURNING address_id
            """,
            (draft.chain, normalized, PLATFORM_DEPOSIT_ACCOUNT,
             f"m/44'/60'/0'/2/{index}", index, fingerprint, draft.reason, draft.ticket,
             moment, moment))
        address_id = str(cur.fetchone()[0])
    row = {"address_id": address_id, "chain_id": draft.chain, "address": normalized,
           "status": "active", "created_at": moment, "retired_at": None,
           "monitoring_until": monitoring_until, "updated_at": moment}
    payload = models.deposit_address_payload(row, chain=draft.chain)
    payload["previous_address"] = (current or {}).get("address")
    payload["old_address_monitor_days"] = facts.OLD_ADDRESS_MONITOR_D
    return payload
