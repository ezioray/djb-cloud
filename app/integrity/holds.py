# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 §6.1 待分润冻结服务（C14 核心；**只冻结、不罚没、不碰账本**）。

对外只有五个动作（路由 / 调度 / 结算接线都走这里，不直接写 SQL）：

======================================  ============================================
``create_or_escalate``                  创建 / 升级冻结（I0 不建 hold，只留事件）
``release``                             人工复核解除（I0/I1 一人；I2+ 双人）
``expire_due``                          把到期 I1 翻成 expired（仍只改本表）
``frozen_total`` / ``is_frozen``        给后续调度 / 结算放行用的只读判定
``active_holds`` / ``list_holds``       管理面查询
======================================  ============================================

不变量：

1. ``frozen_amount_micro = base_amount_micro * ratio_bp // 10000``（整数向下取整；
   下界由 DB CHECK 与触发器双重兜底）；
2. 同 ``(node_id, model)`` 只有 1 条 active；升级 = 改同一行（只升不降，降级 40919）；
3. I1 ``expires_at = now + 7d``；I2+ 无自动到期（NULL），只能人工 release；
4. 冻结 / 解除**只改本表 + 追加事件**：不写 ledger_*、不出分录、不改余额（S2 不罚没）；
5. 开关 ``supply.freeze.enabled`` 关闭时：**写路径 fail-closed**（503/50001），
   读路径只读可用（rollback_rule=释放全部 active hold 只改状态，不改账本）。

``base_amount_micro`` 只由调用方传入（M05 待分润快照）；本模块**不查账本**，
所以这里没有、也不应该有 ``SELECT ... FROM ledger_*`` / ``account_balances``。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Iterable, Sequence

from . import clock, facts, features, models, store
from .errors import Conflict, FeatureUnavailable, Forbidden, NotFound
from .ids import uuid7

__all__ = [
    "feature_enabled", "require_feature", "ratio_bp_for", "frozen_amount", "create_or_escalate",
    "release", "expire_due", "active_holds", "frozen_total", "is_frozen", "get_hold",
    "list_holds", "list_events",
]


# ───────────────────────────────────────────────────────── 开关（fail-closed）
def feature_enabled() -> bool:
    """只读开关：``supply.freeze.enabled``（默认 False；打开必须改代码 + 评审）。"""
    return features.enabled(facts.FEATURE_NAME)


def require_feature() -> None:
    if not feature_enabled():
        raise FeatureUnavailable(
            "待分润冻结功能未启用（supply.freeze.enabled=false，默认关闭）："
            "写操作 fail-closed；已有冻结记录保持只读可查",
            reason="feature_disabled")


# ───────────────────────────────────────────────────────── 纯函数
def ratio_bp_for(level: Any) -> int:
    return facts.LEVEL_RATIO_BP[models.normalize_level(level)]


def frozen_amount(base_amount_micro: int, ratio_bp: int) -> int:
    """``base * ratio // 10000``（整数向下取整；与 DB CHECK 同一算式）。"""
    if base_amount_micro < 0 or ratio_bp < 0:
        raise ValueError("金额与比例必须非负")
    return (int(base_amount_micro) * int(ratio_bp)) // 10000


def _detail(**values: Any) -> dict[str, Any]:
    """事件 detail 只放元数据（比例 / 金额 / 计数 / 粗粒度原因），DB CHECK 再兜底。"""
    return {key: value for key, value in values.items() if value is not None}


def _event(conn: Any, *, hold_id: uuid.UUID | None, node_id: str, model: str, event: str,
           from_level: str | None, to_level: str | None, detail: dict[str, Any],
           actor: str, now: datetime) -> dict[str, Any]:
    return store.insert_event(
        conn, event_id=uuid7(), hold_id=hold_id, node_id=node_id, model=model,
        event=event, from_level=from_level, to_level=to_level, detail=detail,
        actor=actor, created_at=now)


def _new_hold_id() -> uuid.UUID:
    return uuid7()


# ───────────────────────────────────────────────────────── 创建 / 升级
def create_or_escalate(conn: Any, *, node_id: Any, model: Any, level: Any,
                       base_amount_micro: Any, reason: Any, evidence_ref: Any,
                       actor: Any, now: datetime | None = None,
                       upstream_id: Any = None) -> dict[str, Any]:
    """创建或升级冻结（I0 → 不建 hold，只留事件；已有 active → 只升不降）。

    返回 ``{"action": "created|escalated|noted", "hold": payload|None, "event": payload}``。
    """
    require_feature()
    moment = now or clock.utcnow()
    node = models.validate_node_id(node_id)
    model_id = models.validate_model(model)
    target_level = models.normalize_level(level)
    base = models.validate_amount(base_amount_micro)
    reason_text = models.validate_reason(reason)
    evidence = models.validate_evidence_ref(evidence_ref)
    actor_text = models.normalize_actor(actor)
    upstream = models.normalize_text(upstream_id, field="upstream_id", max_len=128,
                                     required=False)

    ratio = ratio_bp_for(target_level)
    frozen = frozen_amount(base, ratio)

    # I0：观察级不建 hold（§6.1 I0 = 0%），但要留可追溯事件
    if target_level == "I0":
        event = _event(conn, hold_id=None, node_id=node, model=model_id,
                       event=facts.EVENT_CREATED, from_level=None, to_level="I0",
                       detail=_detail(hold=False, ratio_bp=0, base_amount_micro=base,
                                      reason=reason_text, evidence_ref=evidence),
                       actor=actor_text, now=moment)
        return {"action": "noted", "hold": None, "event": models.event_payload(event)}

    store.lock_node_model(conn, node, model_id)
    _expire_due(conn, moment, actor="system:ttl")

    existing = store.find_active_hold(conn, node, model_id, now=moment, for_update=True)
    if existing is None:
        hold = store.insert_hold(
            conn, hold_id=_new_hold_id(), node_id=node, upstream_id=upstream,
            model=model_id, level=target_level, ratio_bp=ratio, base_amount_micro=base,
            frozen_amount_micro=frozen, reason=reason_text, evidence_ref=evidence,
            created_at=moment,
            expires_at=(moment + facts.I1_TTL) if target_level == "I1" else None)
        event = _event(conn, hold_id=uuid.UUID(str(hold["id"])), node_id=node,
                       model=model_id, event=facts.EVENT_CREATED, from_level=None,
                       to_level=target_level,
                       detail=_detail(ratio_bp=ratio, base_amount_micro=base,
                                      frozen_amount_micro=frozen, reason=reason_text,
                                      evidence_ref=evidence, upstream_id=upstream),
                       actor=actor_text, now=moment)
        return {"action": "created", "hold": models.hold_payload(hold),
                "event": models.event_payload(event)}

    old_level = str(existing["level"])
    old_rank = facts.LEVEL_RANK[old_level]
    new_rank = facts.LEVEL_RANK[target_level]
    if new_rank == old_rank:
        raise Conflict(
            f"该节点模型已有同级冻结（{old_level}），升级只接受更高等级；"
            "如需变更金额请先解除后重建",
            reason="not_escalation", level=old_level)
    if new_rank < old_rank:
        raise Conflict(
            f"冻结等级只升不降（{old_level} → {target_level}）：降级需先 release 再重建",
            reason="downgrade_rejected", level=old_level)

    hold = store.escalate_hold(
        conn, uuid.UUID(str(existing["id"])), level=target_level, ratio_bp=ratio,
        base_amount_micro=base, frozen_amount_micro=frozen, reason=reason_text,
        evidence_ref=evidence,
        expires_at=(moment + facts.I1_TTL) if target_level == "I1" else None,
        updated_at=moment)
    event = _event(conn, hold_id=uuid.UUID(str(hold["id"])), node_id=node, model=model_id,
                   event=facts.EVENT_ESCALATED, from_level=old_level, to_level=target_level,
                   detail=_detail(ratio_bp=ratio, base_amount_micro=base,
                                  frozen_amount_micro=frozen,
                                  prev_base_amount_micro=int(existing["base_amount_micro"]),
                                  reason=reason_text, evidence_ref=evidence),
                   actor=actor_text, now=moment)
    return {"action": "escalated", "hold": models.hold_payload(hold),
            "event": models.event_payload(event)}


# ───────────────────────────────────────────────────────── 解除（人工复核）
def release(conn: Any, hold_id: Any, *, reviewers: Sequence[str], reason: Any, actor: Any,
            now: datetime | None = None, scopes: Iterable[str] = ()) -> dict[str, Any]:
    """解除冻结（只改本表状态 + 追加事件，**不动账本**）。

    * I0 / I1：1 名复核人；
    * I2：2 名**不同**复核人；
    * I3 / I4：2 名不同复核人 **且** 主体 scope 含 ``integrity:release:high``；
    * 已 released：幂等返回（action=unchanged）；已 expired：40919（无可解除）。

    返回 ``{"action": "released|unchanged", "hold": payload, "event": payload|None}``。
    """
    require_feature()
    moment = now or clock.utcnow()
    identifier = models.parse_hold_id(hold_id)
    names = models.normalize_reviewers(list(reviewers))
    reason_text = models.validate_reason(reason)
    actor_text = models.normalize_actor(actor)
    scope_set = {str(item) for item in scopes}

    hold = store.get_hold(conn, identifier, for_update=True)
    if hold is None:
        raise NotFound("冻结记录不存在", reason="not_found")
    level = str(hold["level"])
    if hold["state"] == "released":
        return {"action": "unchanged", "hold": models.hold_payload(hold), "event": None}
    if hold["state"] == "expired":
        raise Conflict("冻结已到期（expired），无可解除；如需重新冻结请新建",
                       reason="hold_expired", level=level)

    required = facts.REVIEWERS_REQUIRED[level]
    if len(names) < required:
        raise Conflict(
            f"{level} 解除需要 {required} 名不同复核人（收到 {len(names)} 名）",
            reason="reviewers_insufficient", level=level)
    if level in facts.HIGH_LEVELS:
        if facts.WILDCARD_SCOPE not in scope_set and facts.HIGH_RELEASE_SCOPE not in scope_set:
            raise Forbidden(
                f"{level} 解除需要 scope {facts.HIGH_RELEASE_SCOPE}",
                reason="scope_required")

    released = store.mark_released(conn, identifier, reviewers=names, reason=reason_text,
                                   released_at=moment)
    event = _event(conn, hold_id=identifier, node_id=str(hold["node_id"]),
                   model=str(hold["model"]), event=facts.EVENT_RELEASED, from_level=level,
                   to_level=None,
                   detail=_detail(reviewers=len(names), reason=reason_text,
                                  released_by=actor_text,
                                  frozen_amount_micro=int(hold["frozen_amount_micro"])),
                   actor=actor_text, now=moment)
    return {"action": "released", "hold": models.hold_payload(released),
            "event": models.event_payload(event)}


# ───────────────────────────────────────────────────────── 到期 / 查询
def _expire_due(conn: Any, now: datetime, *, actor: str) -> list[dict[str, Any]]:
    rows = store.expire_due(conn, now)
    for row in rows:
        _event(conn, hold_id=uuid.UUID(str(row["id"])), node_id=str(row["node_id"]),
               model=str(row["model"]), event=facts.EVENT_EXPIRED,
               from_level=str(row["level"]), to_level=None,
               detail=_detail(reason="i1_ttl_elapsed",
                              frozen_amount_micro=int(row["frozen_amount_micro"])),
               actor=actor, now=now)
    return rows


def expire_due(conn: Any, now: datetime | None = None) -> list[dict[str, Any]]:
    """把到期 I1 hold 翻成 expired 并留事件（供定时任务 / 列表前扫；不碰账本）。"""
    require_feature()
    return [models.hold_payload(row) for row in _expire_due(conn, now or clock.utcnow(),
                                                            actor="system:ttl")]


def active_holds(conn: Any, *, node_id: str | None = None, model: str | None = None,
                 now: datetime | None = None) -> list[dict[str, Any]]:
    moment = now or clock.utcnow()
    rows, _, _ = store.list_holds(conn, state="active",
                                  node_id=models.normalize_text(node_id, field="node_id",
                                                                max_len=facts.NODE_MAX_LEN,
                                                                required=False),
                                  model=models.normalize_text(model, field="model",
                                                              max_len=facts.MODEL_MAX_LEN,
                                                              required=False),
                                  level=None, limit=facts.MAX_PAGE_SIZE, cursor=None,
                                  now=moment)
    return [models.hold_payload(row) for row in rows]


def frozen_total(conn: Any, node_id: Any, *, now: datetime | None = None) -> int:
    """该节点当前被冻结的待分润合计（micro；只读，不查账本）。"""
    node = models.validate_node_id(node_id)
    return store.frozen_total(conn, node, now=now or clock.utcnow())


def is_frozen(conn: Any, node_id: Any, model: Any, *, now: datetime | None = None) -> bool:
    """调度 / 结算接线用：该 (node, model) 是否有生效中的冻结。"""
    node = models.validate_node_id(node_id)
    model_id = models.validate_model(model)
    row = store.find_active_hold(conn, node, model_id, now=now or clock.utcnow())
    return row is not None


def get_hold(conn: Any, hold_id: Any) -> dict[str, Any] | None:
    row = store.get_hold(conn, models.parse_hold_id(hold_id))
    return models.hold_payload(row) if row else None


def list_holds(conn: Any, *, state: str = "active", node_id: str | None = None,
               model: str | None = None, level: str | None = None, limit: int | None = None,
               cursor: str | None = None, now: datetime | None = None
               ) -> dict[str, Any]:
    """管理面列表（``active`` 默认 / ``all`` / 单态；节点 / 模型 / 等级过滤 + 游标分页）。"""
    state_value = str(state or "active").strip().lower()
    if state_value not in facts.HOLD_STATE_FILTERS:
        from .errors import BadRequest

        raise BadRequest("state 必须是 active / all / released / expired", field="state")
    level_value = models.normalize_level(level) if level else None
    page_limit = models.page_limit(limit)
    moment = now or clock.utcnow()
    if state_value == "active" and feature_enabled():
        # 读前把到期行翻掉，口径一致；开关关闭时保持**纯只读**（§9 rollback_rule）
        _expire_due(conn, moment, actor="system:ttl")
    rows, has_more, next_cursor = store.list_holds(
        conn, state=state_value,
        node_id=models.normalize_text(node_id, field="node_id",
                                      max_len=facts.NODE_MAX_LEN, required=False),
        model=models.normalize_text(model, field="model",
                                    max_len=facts.MODEL_MAX_LEN, required=False),
        level=level_value, limit=page_limit, cursor=cursor, now=moment)
    return {
        "items": [models.hold_payload(row) for row in rows],
        "has_more": has_more,
        "next_cursor": next_cursor,
        "state": state_value,
    }


def list_events(conn: Any, hold_id: Any, *, limit: int = 50) -> list[dict[str, Any]]:
    identifier = models.parse_hold_id(hold_id)
    return [models.event_payload(row)
            for row in store.list_events(conn, identifier, limit=max(1, min(200, int(limit))))]
