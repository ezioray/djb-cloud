# SPDX-License-Identifier: Apache-2.0
"""复核凭证（M09 §3.1 / §3.2 / §6.2 第 3 步）：提交、查询、出款前 validate。

三条不变量落点：
* **INV-05**：同一 ``(period_start, period_end, batch_hash)`` 只能一个 valid；复核人 ≠ 制单人；
  签名覆盖 ``ledger_root + batch_hash + balances + payable_total``（本模块只存**引用**，
  不持有私钥、不存签名原文 —— M09 §1「不做链上签名与广播」）。
* **只追加**：valid 只能 revoke / supersede 后新件替代（库层 903 触发器兜底）。
* **validate 只回结论**：``valid / status / checked_at / reasons``，绝不返回凭证正文
  （M08 出款前校验用，spec 1.2.3 明确「只返回结论，不返回凭证正文」）。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

import psycopg

from . import clock, models, store
from .errors import AttestationConflict, Conflict

__all__ = ["maker_for_period", "submit", "validate", "VALIDATE_FIELDS"]

#: validate 允许出现在响应里的字段（测试据此断言「不外泄」）
VALIDATE_FIELDS: tuple[str, ...] = ("valid", "status", "checked_at", "reasons")


def maker_for_period(conn: psycopg.Connection, period_start: datetime,
                     period_end: datetime) -> str | None:
    """找出该期间的「制单人」：最近一条已签核批次的 ``created_by``。

    用途：INV-05「复核人 ≠ 制单人」。找不到制单人（同期没有 run）时返回 None，
    由调用方决定（本模块的策略是**放行**并在证据里登记：无制单人可比）。
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT created_by FROM reconciliation_runs
                WHERE cutoff_at >= %s AND cutoff_at < %s AND created_by IS NOT NULL
                ORDER BY (status IN ('signed_off', 'closed')) DESC, cutoff_at DESC
                LIMIT 1""", (period_start, period_end))
        row = cur.fetchone()
    return None if row is None else row[0]


def submit(conn: psycopg.Connection, draft: models.AttestationDraft, *,
           reviewer_id: str | None, now: datetime | None = None,
           balances_ref: str | None = None) -> dict[str, Any]:
    """提交凭证（同事务）：幂等重放 → 制单人比对 → INV-05 唯一 valid → 落库。"""
    moment = clock.as_utc(now or clock.utcnow())

    replay = store.find_attestation_by_idempotency(conn, draft.idempotency_key)
    if replay is not None:
        same = (replay["period_start"] == draft.period_start
                and replay["period_end"] == draft.period_end
                and replay["ledger_root"] == draft.ledger_root
                and replay["batch_hash"] == draft.batch_hash
                and int(replay["payable_total_minor"]) == int(draft.payable_total_minor))
        if not same:
            raise Conflict("同一幂等键用于不同的凭证载荷：拒绝重放（24h 窗口）",
                           reason="idempotency_key_reused", field="Idempotency-Key")
        return {"attestation": replay, "duplicate": True}

    maker = draft.maker_id or maker_for_period(conn, draft.period_start, draft.period_end)
    if reviewer_id is not None and maker is not None and reviewer_id == maker:
        # 产品 §9 A6 写的是 49212，但 spec 1.2.3 把 49212 登记为「凭证不存在（404）」；
        # 契约优先 → 状态冲突 409/40919（已在 errors.py 头注释与证据「遗留」登记）。
        raise Conflict("复核人不得等于制单人（INV-05 双人原则）",
                       reason="reviewer_equals_maker", maker_id=maker)

    existing = store.find_valid_attestation(conn, draft)
    if existing is not None:
        raise AttestationConflict(
            "同一期间 + batch_hash 已有 valid 凭证：先 revoke 再提交新件（INV-05）",
            reason="valid_attestation_exists")

    try:
        with conn.transaction():
            row = store.insert_attestation(conn, draft, reviewer_id=reviewer_id, now=moment,
                                           balances_ref=balances_ref)
    except psycopg.errors.UniqueViolation as exc:
        if "reconciliation_attestations_valid_uq" in str(exc) or "valid" in str(exc):
            raise AttestationConflict(
                "同一期间 + batch_hash 已有 valid 凭证：先 revoke 再提交新件（INV-05）",
                reason="valid_attestation_exists") from exc
        raise Conflict("凭证写入冲突：幂等键或唯一约束不满足", reason="attestation_conflict") from exc
    return {"attestation": row, "duplicate": False}


def validate(row: Mapping[str, Any] | None, *, now: datetime | None = None) -> dict[str, Any]:
    """出款前校验结论（**只回结论**，调用方为 M08）。

    ``valid`` 的口径：``status == 'valid'`` 且未过期。过期口径属私有配置（M10 ``por.*`` /
    ``recon.*``），本轮**没有**登记 TTL 常量 → 不做时间过期判断，状态枚举保留 ``expired``
    给 T4 接配置；不发明业务窗口，也不把「未配置」伪装成「已过期」。
    """
    moment = clock.as_utc(now or clock.utcnow())
    if row is None:
        return {"valid": False, "status": "unknown", "checked_at": clock.iso_micros(moment),
                "reasons": ["attestation_not_found"]}

    status = row["status"]
    reasons: list[str] = []
    if status != "valid":
        reasons.append(f"attestation_{status}")
    if not row.get("signature_ref"):
        reasons.append("signature_ref_missing")           # 库层拦得住，读路径再断言一次

    payload = {
        "valid": not reasons,
        "status": status,
        "checked_at": clock.iso_micros(moment),
        "reasons": reasons,
    }
    # 硬约束：只允许这四项进响应（多一个字段就是泄露凭证正文）
    assert set(payload) <= set(VALIDATE_FIELDS), "validate 响应字段越界（会泄露凭证正文）"
    return payload
