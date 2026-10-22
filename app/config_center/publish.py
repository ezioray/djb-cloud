# SPDX-License-Identifier: Apache-2.0
"""发布单流程（T3，S1 子集）：创建 → 复核 ≠ 发起 → 调度 → 生效 → 收口；过期/取消。

M10 §6 流程 1 的九步在 S1 落成六个可调用动作（灰度/预发的 S2 部分用特性开关挡住）：

    1  草稿      store.create_draft（T2）
    2  影响面    :func:`impact_analysis`（consumers 全部可解析、为空即拒）→ 建发布单 pending_approval
    3  复核      :func:`approve_request`（复核人 ≠ 发起人；P0 需 FIN/AUDIT；step-up 发布/审批各一次）
    4  调度      effective_at 未来 → scheduled；否则 approved
    5  全量      :func:`activate_request`（单行 CAS → active → 同事务写 config.published）
    6  收口      :func:`close_request`（观测结论入单）
    7  逾期      :func:`expire_requests`（4h 未复核 → expired，**不自动放行**）
    8  撤销      :func:`cancel_request`
    9  归档      T4（快照保留 ≥3 年，本层只写 closed）

不变量落点：
  · INV-03 复核人 ≠ 发起人：应用层 + 1001 版本触发器 + 1002 SoD CHECK（三处）；
  · INV-04 P0/P1 冷却：:func:`assert_cooldown` 读 facts（24h / 60min），窗内只允许回滚（T4）；
  · INV-07 同 key 单未完结发布单：应用层检查 + 1006 部分唯一索引；
  · step-up：发布与审批各一次且 **不得复用**（1006 的 stepup_ck + 本层校验）；
  · 事务边界：版本切 active、发布单、outbox 同一事务；outbox 写失败即整体回滚（有测试）。

本层不做 HTTP、不做角色认证（Principal 由路由层构造后传入），也不直接写审计（T5 接 M16 API）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, time as dtime, timedelta, timezone
from typing import Any, Iterable, Mapping

import psycopg
from psycopg.types.json import Jsonb

from . import audit as audit_mod
from . import canonical, facts, features, outbox, snapshot, store, validators
from decimal import Decimal

from .errors import (
    ApproverNotAllowed,
    DangerousKeyForbidden,
    CooldownActive,
    GrayPlanInvalid,
    IdempotencyConflict,
    KeyLocked,
    OutsidePublishWindow,
    SelfApprovalForbidden,
    StateConflict,
    StepUpRequired,
    ValidationFailed,
    VersionNotFound,
)
from .registry import AUX_NAMESPACES, DOMAINS, ConfigKey, Registry, load as load_registry

__all__ = [
    "DEFAULT_SCOPE",
    "IN_FLIGHT",
    "TERMINAL",
    "APPROVALS_REQUIRED",
    "P0_APPROVER_ROLES",
    "Principal",
    "impact_analysis",
    "effective_values",
    "assert_publish_window",
    "assert_step_up",
    "assert_cooldown",
    "create_request",
    "rollback",
    "kill_switch",
    "restore_kill_switch",
    "expire_kill_switches",
    "approve_request",
    "promote_request",
    "activate_request",
    "schedule_request",
    "close_request",
    "cancel_request",
    "expire_requests",
    "get_request",
    "list_requests",
    "current_policy_version",
]

DEFAULT_SCOPE = store.DEFAULT_SCOPE
#: 「未完结」= 在飞四态（active 不阻塞下一次发布，收口靠 close；与 1006 索引一致）
IN_FLIGHT: tuple[str, ...] = ("pending_approval", "approved", "scheduled", "rolling_out")
TERMINAL: tuple[str, ...] = ("closed", "rejected", "expired", "cancelled", "rolled_back", "failed")
#: INV-03：P0/P1 需 1 名复核人（≠ 发起人）；P2 单人可发
APPROVALS_REQUIRED: dict[str, int] = {"P0": 1, "P1": 1, "P2": 0}
#: §21.4.3：P0 复核人必须来自 FIN 或 AUDIT（按域表）
P0_APPROVER_ROLES: frozenset[str] = frozenset({"FIN", "AUDIT"})

_CONSUMER_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")

#: 回滚 / kill switch 的事件 reason_code（机器码，不是业务数字）
ROLLBACK_REASON_CODE = "manual_rollback"
KILL_SWITCH_REASON_CODE = "kill_switch"
KILL_SWITCH_EXPIRED_CODE = "kill_switch_expired"
KILL_SWITCH_RESTORED_CODE = "kill_switch_restored"
SYSTEM_ACTOR = "system:kill_switch_expiry"
KILL_SWITCH_MAX_TTL_S = 86400


# ───────────────────────────────────────────────────────────── 主体
@dataclass(frozen=True)
class Principal:
    """管理面调用主体（由 T4/路由层构造；本层只判定，不做认证）。"""

    actor: str
    roles: frozenset[str] = frozenset()
    step_up_at: datetime | None = None
    step_up_ref: str | None = None

    def has_role(self, *roles: str) -> bool:
        return bool(self.roles & set(roles))

    def as_dict(self) -> dict[str, Any]:
        return {"actor": self.actor, "roles": sorted(self.roles)}


# ───────────────────────────────────────────────────────────── 小工具
def _rows(conn: psycopg.Connection, sql: str, params: Any = ()) -> list[dict[str, Any]]:
    cur = conn.execute(sql, params)
    columns = [desc.name for desc in cur.description or ()]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def _one(conn: psycopg.Connection, sql: str, params: Any = ()) -> dict[str, Any] | None:
    rows = _rows(conn, sql, params)
    return rows[0] if rows else None


def _now(now: datetime | None) -> datetime:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValidationFailed("now 必须带时区（UTC）")
    return moment.astimezone(timezone.utc)


def _text(value: Any, *, field: str, minimum: int = 1, maximum: int = 512) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ValidationFailed(f"{field} 必须是 {minimum}–{maximum} 字符的字符串：{value!r}")
    return value


def _domain_roles(item: ConfigKey) -> tuple[frozenset[str], frozenset[str]]:
    """返回 (发起角色组, 审批角色组)；辅助命名空间（config./points.）的 owner 兼两职。"""
    for domain in DOMAINS:
        if domain.code == item.domain:
            return frozenset(domain.proposer_roles), frozenset(domain.approver_roles)
    for aux in AUX_NAMESPACES:
        if aux.namespace == item.domain:
            return frozenset(aux.owner_roles), frozenset(aux.owner_roles)
    raise ValidationFailed(f"键 {item.key} 的配置域未登记：{item.domain}")


def _assert_proposer(principal: Principal, item: ConfigKey) -> None:
    proposer_roles, _ = _domain_roles(item)
    if not principal.roles & proposer_roles:
        raise ApproverNotAllowed(
            f"{principal.actor} 缺少发起角色（{item.key} 属 {item.domain}，"
            f"需要 {sorted(proposer_roles)}）", key=item.key)


def _assert_approver(principal: Principal, item: ConfigKey) -> None:
    _, approver_roles = _domain_roles(item)
    if not principal.roles & approver_roles:
        raise ApproverNotAllowed(
            f"{principal.actor} 缺少审批角色（{item.key} 需要 {sorted(approver_roles)}）",
            key=item.key)
    if item.risk == "P0" and not principal.roles & P0_APPROVER_ROLES:
        raise ApproverNotAllowed(
            f"P0 复核人必须来自 {sorted(P0_APPROVER_ROLES)}（§21.4.3），"
            f"{principal.actor} 只有 {sorted(principal.roles)}", key=item.key)


def assert_step_up(principal: Principal, *, now: datetime, purpose: str = "publish") -> None:
    """step-up ≤5 分钟（facts §8），且 ref 必填（用于「发布与审批各一次、不得复用」）。"""
    moment = _now(now)
    ttl = facts.step_up_ttl()
    if not principal.step_up_ref or principal.step_up_at is None:
        raise StepUpRequired(f"{purpose} 需要 step-up 二次认证（≤{int(ttl.total_seconds())}s）")
    at = principal.step_up_at
    if at.tzinfo is None:
        raise StepUpRequired("step_up_at 必须带时区（UTC）")
    age = moment - at.astimezone(timezone.utc)
    if age > ttl or age < -ttl:
        raise StepUpRequired(
            f"{purpose} 的 step-up 已失效（{int(age.total_seconds())}s，上限 {int(ttl.total_seconds())}s）")


def assert_publish_window(now: datetime, *, window: Any = None) -> None:
    """发布窗口：工作日 10:00–17:00（UTC+8），窗口外只允许 kill switch / 回滚（§21.1.2）。"""
    spec = window or facts.publish_window()
    moment = _now(now)
    offset = timezone(_parse_offset(spec.timezone))
    local = moment.astimezone(offset)
    if local.isoweekday() not in spec.weekdays:
        raise OutsidePublishWindow(
            f"发布窗口外：{local.isoformat()} 是周{local.isoweekday()}，"
            f"只允许工作日 {spec.weekdays}（M10 §8.1）")
    start = dtime.fromisoformat(spec.start)
    end = dtime.fromisoformat(spec.end)
    if not start <= local.time() <= end:
        raise OutsidePublishWindow(
            f"发布窗口外：{local.strftime('%H:%M')}，只允许 {spec.start}–{spec.end}（UTC+8）")


def _parse_offset(value: str) -> timedelta:
    match = re.fullmatch(r"([+-])(\d{2}):(\d{2})", value)
    if not match:
        raise ValidationFailed(f"时区偏移非法：{value!r}")
    sign = 1 if match.group(1) == "+" else -1
    return sign * timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))


# ───────────────────────────────────────────────────────────── 影响面 / 冷却
def impact_analysis(conn: psycopg.Connection, item: ConfigKey, *,
                    scope: str = DEFAULT_SCOPE, scope_id: str = "") -> dict[str, Any]:
    """第 2 步：影响面（consumers 全部可解析，为空即拒）。"""
    consumers = list(item.consumers)
    if not consumers:
        raise ValidationFailed(
            f"{item.key} 的 consumers 为空：影响面无法生成，拒绝建发布单（M10 §6 流程 1 步 2）",
            key=item.key)
    unresolvable = [name for name in consumers if not _CONSUMER_RE.match(name)]
    if unresolvable:
        raise ValidationFailed(
            f"{item.key} 的 consumers 无法解析：{unresolvable}", key=item.key,
            details=[{"field": "consumers", "value": name} for name in unresolvable])
    active = store.active_version(conn, key=item.key, scope=scope, scope_id=scope_id)
    return {
        "key": item.key,
        "namespace": item.namespace,
        "risk_level": item.risk,
        "consumers": consumers,
        "active_version": active["version"] if active else None,
        "scope": scope,
        "scope_id": scope_id,
    }


def _payload_of(row: Mapping[str, Any] | None) -> Any:
    if row is None:
        return None
    return row["value"] if row.get("value") is not None else row.get("secret_ref")


def _active_values(conn: psycopg.Connection) -> dict[str, Any]:
    rows = _rows(conn, "SELECT key, value, secret_ref FROM config_versions WHERE status = 'active'")
    return {row["key"]: _payload_of(row) for row in rows}


def effective_values(conn: psycopg.Connection, *, registry: Registry | None = None,
                     ) -> dict[str, Any]:
    """当前有效值 = 声明默认（①）被 active 版本（②）覆盖（§21.2.3）。

    跨字段断言必须看「有效值」而不是「只看 active」：fee_cap_pct 没有 active 版本时，
    承诺上限仍然来自声明默认 20，不能被绕过。
    """
    reg = registry or load_registry()
    values: dict[str, Any] = {
        item.key: item.default for item in reg.keys
        if item.publishable and item.default is not None
    }
    values.update(_active_values(conn))
    return values


def _validate_candidate(conn: psycopg.Connection, item: ConfigKey,
                        version_row: Mapping[str, Any], registry: Registry) -> Any:
    """第②道校验：单值（含幅度/收紧）+ 与当前有效值的跨字段断言。"""
    effective = effective_values(conn, registry=registry)
    result = validators.validate_value(
        item.key, _payload_of(version_row), current=effective.get(item.key))
    merged = {**effective, item.key: result.value}
    validators.validate_cross_field(merged, touched=[item.key])
    return result.value


def _find_idempotent_request(conn: psycopg.Connection, *, scope: str, scope_id: str,
                             key: str, version: int, principal: Principal,
                             idempotency_key: str) -> dict[str, Any] | None:
    """发布单幂等：同键同载荷 → 首次结果；同键不同载荷 → 409/40919。

    必须在 INV-07 在飞检查**之前**：同一次请求的重放不能被自己的在飞发布单挡住。
    """
    existing = _one(conn,
                    "SELECT * FROM config_publish_requests WHERE scope = %s AND idempotency_key = %s",
                    (scope, idempotency_key))
    if existing is None:
        return None
    same = (existing["key"] == key
            and existing["versions"] == {key: version}
            and existing["scope_id"] == scope_id
            and existing["proposed_by"] == principal.actor)
    if not same:
        raise IdempotencyConflict(
            f"幂等键 {idempotency_key!r} 已用于不同发布单"
            f"（{existing['key']} v{existing['versions']}）", key=key)
    row = dict(existing)
    row["replayed"] = True
    return row


def assert_cooldown(conn: psycopg.Connection, item: ConfigKey, *, now: datetime,
                    scope: str = DEFAULT_SCOPE, scope_id: str = "") -> None:
    """INV-04：P0/P1 冷却窗内不得二次发布（只允许回滚；回滚在 T4）。"""
    moment = _now(now)
    seconds = facts.cooldowns()[item.risk]
    if seconds <= 0:
        return
    row = _one(conn,
               """SELECT max(COALESCE(effective_at, updated_at)) AS last_at
                    FROM config_versions
                   WHERE key = %s AND scope = %s AND scope_id = %s
                     AND status IN ('active', 'superseded') AND published_by IS NOT NULL""",
               (item.key, scope, scope_id))
    last_at = row["last_at"] if row else None
    if last_at is None:
        return
    if last_at.tzinfo is None:
        last_at = last_at.replace(tzinfo=timezone.utc)
    deadline = last_at + timedelta(seconds=seconds)
    if moment < deadline:
        raise CooldownActive(
            f"{item.key}（{item.risk}）冷却期未到：上次生效 {last_at.isoformat()}，"
            f"最早 {deadline.isoformat()} 才能再次发布（INV-04）", key=item.key)


def _assert_no_in_flight(conn: psycopg.Connection, key: str, *, scope: str, scope_id: str) -> None:
    row = _one(conn,
               """SELECT publish_request_id, status FROM config_publish_requests
                   WHERE key = %s AND scope = %s AND scope_id = %s AND status = ANY(%s)
                   LIMIT 1""",
               (key, scope, scope_id, list(IN_FLIGHT)))
    if row is not None:
        raise KeyLocked(
            f"{key} 已有未完结发布单 {row['publish_request_id']}（{row['status']}），"
            f"同 key 同时只允许一个（INV-07）", key=key)


# ───────────────────────────────────────────────────────────── 读
def _load_request(conn: psycopg.Connection, request_id: str, *, for_update: bool = False,
                  ) -> dict[str, Any]:
    sql = "SELECT * FROM config_publish_requests WHERE publish_request_id = %s"
    if for_update:
        sql += " FOR UPDATE"
    row = _one(conn, sql, (request_id,))
    if row is None:
        raise VersionNotFound(f"发布单不存在：{request_id}", key=None)
    return row


def get_request(conn: psycopg.Connection, request_id: str) -> dict[str, Any]:
    return _load_request(conn, request_id)


def list_requests(conn: psycopg.Connection, *, key: str | None = None,
                  status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    if not 1 <= limit <= 200:
        raise ValidationFailed(f"limit 越界 1..200：{limit}")
    clauses, params = [], []
    if key is not None:
        clauses.append("key = %s")
        params.append(key)
    if status is not None:
        clauses.append("status = %s")
        params.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    return _rows(conn, f"""SELECT * FROM config_publish_requests {where}
                            ORDER BY requested_at DESC LIMIT %s""", params)


def current_policy_version(conn: psycopg.Connection) -> dict[str, Any] | None:
    """当前全部 active 配置的快照摘要（INV-08；无 active 时返回 None）。"""
    entries = store.active_entries(conn)
    if not entries:
        return None
    digest = canonical.snapshot_digest(entries)
    return {"snapshot_digest": digest, "policy_version": canonical.policy_version(digest),
            "entries": len(entries)}


# ───────────────────────────────────────────────────────────── 第 2 步：建发布单
def create_request(
    conn: psycopg.Connection,
    *,
    key: str,
    version: int,
    principal: Principal,
    reason: str,
    scope: str = DEFAULT_SCOPE,
    scope_id: str = "",
    effective_at: Any = None,
    gray_plan: Mapping[str, Any] | None = None,
    ticket: str | None = None,
    idempotency_key: str | None = None,
    trace_id: str | None = None,
    now: datetime | None = None,
    registry: Registry | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """把已存在的 draft 版本提交为发布单（P0/P1 → pending_approval；P2 单人可发 → approved）。"""
    return _create_request_impl(
        conn, key=key, version=version, principal=principal, reason=reason, scope=scope,
        scope_id=scope_id, effective_at=effective_at, gray_plan=gray_plan, ticket=ticket,
        idempotency_key=idempotency_key, trace_id=trace_id, now=now, registry=registry,
        audit=audit)


def _create_request_impl(
    conn: psycopg.Connection,
    *,
    key: str,
    version: int,
    principal: Principal,
    reason: str,
    scope: str = DEFAULT_SCOPE,
    scope_id: str = "",
    effective_at: Any = None,
    gray_plan: Mapping[str, Any] | None = None,
    ticket: str | None = None,
    idempotency_key: str | None = None,
    trace_id: str | None = None,
    now: datetime | None = None,
    registry: Registry | None = None,
    skip_cooldown: bool = False,
    rollback_target_version: int | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """内部：发布单创建（回滚复用它，``skip_cooldown=True`` 因为止损免冷却）。"""
    reg = registry or load_registry()
    item = reg.require(key)
    validators.check_publishable(item.key, registry=reg)
    moment = _now(now)
    scope, scope_id = store.normalize_scope(scope, scope_id)
    reason = _text(reason, field="reason", minimum=4, maximum=512)
    _assert_proposer(principal, item)
    if idempotency_key is not None:
        _text(idempotency_key, field="idempotency_key", minimum=8, maximum=128)
        replay = _find_idempotent_request(
            conn, scope=scope, scope_id=scope_id, key=key, version=version,
            principal=principal, idempotency_key=idempotency_key)
        if replay is not None:
            return replay

    version_row = store.get_version(conn, key=key, version=version, scope=scope, scope_id=scope_id)
    if version_row is None:
        raise VersionNotFound(f"{key} v{version} 不存在（scope={scope}/{scope_id}）", key=key)
    if version_row["status"] != "draft":
        raise StateConflict(f"{key} v{version} 不是 draft（{version_row['status']}），不能重复发布",
                            key=key)

    # 第②道校验：值 + 幅度/收紧 + 跨字段（发布前重跑）
    _validate_candidate(conn, item, version_row, reg)
    impact = impact_analysis(conn, item, scope=scope, scope_id=scope_id)

    if gray_plan is not None:
        _validate_gray_plan(gray_plan)

    effective = validators.as_utc(effective_at, field="effective_at") if effective_at else None
    risk = item.risk
    needs_approval = APPROVALS_REQUIRED[risk] > 0
    if needs_approval:
        assert_step_up(principal, now=moment, purpose="publish")
        if not skip_cooldown:
            assert_cooldown(conn, item, now=moment, scope=scope, scope_id=scope_id)

    _assert_no_in_flight(conn, key, scope=scope, scope_id=scope_id)

    status = "pending_approval" if needs_approval else "approved"
    expires_at = moment + facts.approval_timeout() if needs_approval else None
    row = _one(
        conn,
        """INSERT INTO config_publish_requests
             (key, namespace, key_set, versions, risk_level, scope, scope_id, status,
              proposed_by, approved_by, decision, gray_plan, requested_at, expires_at,
              effective_at, reason, ticket, idempotency_key, publish_step_up_ref,
              rollback_target_version)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           RETURNING *""",
        (key, item.namespace, [key], Jsonb({key: version}), risk, scope, scope_id, status,
         principal.actor, [], None, Jsonb(dict(gray_plan)) if gray_plan else None,
         moment, expires_at, effective, reason, ticket, idempotency_key,
         principal.step_up_ref if needs_approval else None, rollback_target_version),
    )
    assert row is not None
    row["replayed"] = False
    row["impact"] = impact
    action = ("config.rollback.requested" if rollback_target_version
              else "config.publish.requested")
    audit_mod.emit(audit, audit_mod.build_event(
        action, actor=principal.actor, key=key, scope=scope, scope_id=scope_id,
        version=version, request_id=str(row["publish_request_id"]), reason=reason,
        trace_id=trace_id, occurred_at=moment,
        metadata={"risk_level": risk, "status": status,
                  "rollback_target_version": rollback_target_version}))
    return row


def _validate_gray_plan(gray_plan: Mapping[str, Any]) -> None:
    """灰度计划（S2 起启用；开关关闭时一律 47007）。"""
    if not features.enabled("config_center.gray_rollout"):
        raise GrayPlanInvalid("灰度发布 S2 起启用（config_center.gray_rollout=false），S1 拒绝灰度计划")
    if not isinstance(gray_plan, Mapping):
        raise GrayPlanInvalid("gray_plan 必须是对象")
    buckets = gray_plan.get("buckets")
    if not isinstance(buckets, list) or not buckets:
        raise GrayPlanInvalid("gray_plan.buckets 必须是非空数组")
    if any(isinstance(step, bool) or not isinstance(step, int) or not 0 <= step <= 100
           for step in buckets):
        raise GrayPlanInvalid(f"gray_plan.buckets 每步必须是 0–100 整数：{buckets!r}")
    if any(b <= a for a, b in zip(buckets, buckets[1:])) or buckets[-1] != 100:
        raise GrayPlanInvalid(f"gray_plan.buckets 必须递增且末位 100：{buckets!r}")
    observation = gray_plan.get("observation_seconds")
    if observation is not None and (isinstance(observation, bool) or not isinstance(observation, int)
                                    or observation < 60):
        raise GrayPlanInvalid(f"gray_plan.observation_seconds 必须 ≥60：{observation!r}")


# ───────────────────────────────────────────────────────────── 第 3 步：复核
def approve_request(
    conn: psycopg.Connection,
    request_id: str,
    *,
    principal: Principal,
    decision: str,
    reason: str,
    now: datetime | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """复核通过 / 驳回：复核人 ≠ 发起人（INV-03）；P0 需 FIN/AUDIT；step-up 不得复用。"""
    moment = _now(now)
    request = _load_request(conn, request_id, for_update=True)
    if request["status"] != "pending_approval":
        raise StateConflict(
            f"发布单 {request_id} 状态为 {request['status']}，只有 pending_approval 可复核")
    if decision not in ("approve", "reject"):
        raise ValidationFailed(f"decision 必须是 approve / reject：{decision!r}")
    reason = _text(reason, field="reason", minimum=2, maximum=512)

    item = (load_registry()).require(request["key"])
    if principal.actor == request["proposed_by"]:
        raise SelfApprovalForbidden(
            f"复核人 = 发起人（{principal.actor}）：自批自核硬拒绝（INV-03 / 47002）", key=item.key)
    _assert_approver(principal, item)
    assert_step_up(principal, now=moment, purpose="approve")
    if principal.step_up_ref == request["publish_step_up_ref"]:
        raise StepUpRequired("发布与复核必须各做一次 step-up，不得复用同一个 ref（§21.4.3）")

    if decision == "reject":
        new_status = "rejected"
        approved_by = list(request["approved_by"])
    else:
        approved_by = [principal.actor]
        new_status = "approved"          # 调度是下一步（approved → scheduled，§3 状态机）

    row = _one(
        conn,
        """UPDATE config_publish_requests
              SET status = %s,
                  decision = %s,
                  decision_reason = %s,
                  approved_by = %s,
                  approval_step_up_ref = %s,
                  updated_at = now()
            WHERE publish_request_id = %s
        RETURNING *""",
        (new_status, decision, reason, approved_by, principal.step_up_ref, request_id),
    )
    assert row is not None
    audit_mod.emit(audit, audit_mod.build_event(
        "config.publish.approved" if decision == "approve" else "config.publish.rejected",
        actor=principal.actor, key=item.key, scope=request["scope"],
        scope_id=request["scope_id"], version=request["versions"].get(item.key)
        if isinstance(request["versions"], dict) else None,
        request_id=request_id, reason=reason, occurred_at=moment,
        metadata={"decision": decision, "status": new_status}))
    return row


# ───────────────────────────────────────────────────────────── 第 4 步：调度
def schedule_request(
    conn: psycopg.Connection,
    request_id: str,
    *,
    principal: Principal,
    now: datetime | None = None,
) -> dict[str, Any]:
    """已复核 → 已排期（approved → scheduled）：必须有未来的 effective_at。"""
    moment = _now(now)
    request = _load_request(conn, request_id, for_update=True)
    if request["status"] != "approved":
        raise StateConflict(
            f"发布单 {request_id} 状态为 {request['status']}，只有 approved 可排期")
    item = (load_registry()).require(request["key"])
    proposer_roles, _ = _domain_roles(item)
    if principal.actor != request["proposed_by"] and not principal.roles & proposer_roles:
        raise ApproverNotAllowed(f"{principal.actor} 无权排期 {item.key}", key=item.key)
    effective = request["effective_at"]
    if effective is None:
        raise ValidationFailed(f"发布单 {request_id} 没有 effective_at，无需排期（可直接生效）")
    if effective <= moment:
        raise ValidationFailed(
            f"发布单 {request_id} 的 effective_at 不晚于当前时间 {moment.isoformat()}，无需排期")
    row = _one(
        conn,
        """UPDATE config_publish_requests
              SET status = 'scheduled', updated_at = now()
            WHERE publish_request_id = %s
        RETURNING *""",
        (request_id,),
    )
    assert row is not None
    return row


# ───────────────────────────────────────────────────────────── 第 5 步：生效
def _activate_and_emit(
    conn: psycopg.Connection,
    *,
    item: ConfigKey,
    version_row: Mapping[str, Any],
    published_by: str,
    approved_by: str | None,
    effective_at: datetime,
    period: str,
    request_id: str | None,
    now: datetime,
    trace_id: str | None,
    reason_code: str | None = None,
) -> dict[str, Any]:
    """切 active + 同事务落快照 + 断言 digest 一致（R-14）+ 写 outbox 事件。"""
    activated = store.activate(
        conn,
        key=item.key,
        version=version_row["version"],
        published_by=published_by,
        approved_by=approved_by,
        effective_at=effective_at,
        scope=version_row["scope"],
        scope_id=version_row["scope_id"],
    )
    snapshot_row = snapshot.write_snapshot(
        conn, period=period, publish_request_id=request_id, now=now)
    policy = current_policy_version(conn)
    if policy is None:  # pragma: no cover - 刚激活至少一条
        raise ValidationFailed("生效后仍没有 active 配置（数据异常）")
    # R-14：落库快照的 digest 必须等于事件将携带的 digest，不一致即拒绝（外层回滚）
    snapshot.assert_snapshot_consistent(snapshot_row, expected_digest=policy["snapshot_digest"])
    digest = snapshot_row["snapshot_digest"]
    policy_version = canonical.policy_version(digest)

    if activated["rollback_to"]:
        event = outbox.rolled_back_event(
            namespace=item.namespace, key=item.key, version=activated["version"],
            rollback_to=activated["rollback_to"],
            reason_code=reason_code or ROLLBACK_REASON_CODE,
            scope=activated["scope"], scope_id=activated["scope_id"],
            request_id=request_id, trace_id=trace_id, occurred_at=now,
            snapshot_digest=digest)
    else:
        event = outbox.published_event(
            namespace=item.namespace, key=item.key, version=activated["version"],
            risk_level=item.risk, policy_version=policy_version,
            effective_at=activated["effective_at"] or now,
            scope=activated["scope"], scope_id=activated["scope_id"],
            request_id=request_id, trace_id=trace_id, occurred_at=now,
            snapshot_digest=digest, emergency=bool(activated["emergency"]))
    outbox.append_event(conn, event)
    return {"version": activated, "snapshot": snapshot_row, "snapshot_digest": digest,
            "policy_version": policy_version, "event": event}


def activate_request(
    conn: psycopg.Connection,
    request_id: str,
    *,
    now: datetime | None = None,
    trace_id: str | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """全量生效：单行 CAS 切版本 → 同事务写快照 + config.published / config.rolled_back。"""
    moment = _now(now)
    request = _load_request(conn, request_id, for_update=True)
    if request["status"] not in ("approved", "scheduled", "rolling_out"):
        raise StateConflict(
            f"发布单 {request_id} 状态为 {request['status']}，不能直接生效"
            "（pending_approval 必须先复核，M10 §3 禁止跳过复核）")
    effective = request["effective_at"]
    if effective is not None and moment < effective:
        raise StateConflict(
            f"发布单 {request_id} 未到生效时间 {effective.isoformat()}"
            f"（状态 {request['status']}；已复核的请先 schedule_request）")

    item = (load_registry()).require(request["key"])
    versions = request["versions"]
    if not isinstance(versions, dict) or request["key"] not in versions:
        raise ValidationFailed(
            f"发布单 {request_id} 的 versions 不包含 {request['key']}：{versions!r}")
    version_row = store.get_version(conn, key=request["key"], version=int(versions[request["key"]]),
                                    scope=request["scope"], scope_id=request["scope_id"])
    if version_row is None:
        raise VersionNotFound(f"{request['key']} 的目标版本不存在", key=request["key"])
    _validate_candidate(conn, item, version_row, load_registry())

    # 回滚 / kill switch 属止损，不受发布窗口限制（§21.1.2：窗口外只允许 kill switch、回滚）
    if not version_row["rollback_to"]:
        assert_publish_window(moment)

    approved = list(request["approved_by"])
    result = _activate_and_emit(
        conn, item=item, version_row=version_row,
        published_by=request["proposed_by"],
        approved_by=approved[0] if approved else None,
        effective_at=effective or moment,
        period=f"publish:{request_id}",
        request_id=request_id, now=moment, trace_id=trace_id,
        reason_code=ROLLBACK_REASON_CODE if version_row["rollback_to"] else None,
    )
    row = _one(
        conn,
        """UPDATE config_publish_requests
              SET status = 'active', snapshot_after = %s, updated_at = now()
            WHERE publish_request_id = %s
        RETURNING *""",
        (result["snapshot_digest"], request_id),
    )
    assert row is not None
    audit_mod.emit(audit, audit_mod.build_event(
        "config.rolled_back" if result["version"]["rollback_to"] else "config.published",
        actor=request["proposed_by"], key=request["key"], scope=request["scope"],
        scope_id=request["scope_id"], version=result["version"]["version"],
        request_id=request_id, trace_id=trace_id, occurred_at=moment,
        metadata={"policy_version": result["policy_version"],
                  "snapshot_digest": result["snapshot_digest"]}))
    return {"request": row, **result}


# ───────────────────────────────────────────────────────────── 第 6 步：收口
def close_request(
    conn: psycopg.Connection,
    request_id: str,
    *,
    principal: Principal,
    observation: str,
    now: datetime | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """收口：观测结论入单（active → closed）。"""
    moment = _now(now)
    request = _load_request(conn, request_id, for_update=True)
    if request["status"] != "active":
        raise StateConflict(f"发布单 {request_id} 状态为 {request['status']}，只有 active 可收口")
    item = (load_registry()).require(request["key"])
    proposer_roles, _ = _domain_roles(item)
    if principal.actor != request["proposed_by"] and not principal.roles & proposer_roles:
        raise ApproverNotAllowed(f"{principal.actor} 无权收口 {item.key}", key=item.key)
    observation = _text(observation, field="observation", minimum=2, maximum=2048)
    row = _one(
        conn,
        """UPDATE config_publish_requests
              SET status = 'closed', closed_at = %s, observation = %s, updated_at = now()
            WHERE publish_request_id = %s
        RETURNING *""",
        (moment, observation, request_id),
    )
    assert row is not None
    audit_mod.emit(audit, audit_mod.build_event(
        "config.closed", actor=principal.actor, key=item.key, scope=request["scope"],
        scope_id=request["scope_id"], version=(request["versions"] or {}).get(item.key)
        if isinstance(request["versions"], dict) else None,
        request_id=request_id, reason=observation, occurred_at=moment))
    return row


def cancel_request(
    conn: psycopg.Connection,
    request_id: str,
    *,
    principal: Principal,
    reason: str,
    now: datetime | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """撤销未生效的发布单（发起人或 SUPER）。"""
    request = _load_request(conn, request_id, for_update=True)
    if request["status"] not in ("draft", "pending_approval", "approved", "scheduled"):
        raise StateConflict(f"发布单 {request_id} 状态为 {request['status']}，不能撤销")
    if principal.actor != request["proposed_by"] and "SUPER" not in principal.roles:
        raise ApproverNotAllowed(f"{principal.actor} 无权撤销他人发布单：{request_id}")
    reason = _text(reason, field="reason", minimum=2, maximum=512)
    row = _one(
        conn,
        """UPDATE config_publish_requests
              SET status = 'cancelled', decision_reason = %s, updated_at = now()
            WHERE publish_request_id = %s
        RETURNING *""",
        (reason, request_id),
    )
    assert row is not None
    item = load_registry().require(request["key"])
    audit_mod.emit(audit, audit_mod.build_event(
        "config.cancelled", actor=principal.actor, key=item.key, scope=request["scope"],
        scope_id=request["scope_id"], request_id=request_id, reason=reason))
    return row


# ───────────────────────────────────────────────────────────── 过期（不自动放行）
def expire_requests(conn: psycopg.Connection, *, now: datetime | None = None) -> list[str]:
    """pending_approval 超过 4h → expired；**不自动放行**（§21.4.2）。"""
    moment = _now(now)
    cur = conn.execute(
        """UPDATE config_publish_requests
              SET status = 'expired', updated_at = now()
            WHERE status = 'pending_approval'
              AND expires_at IS NOT NULL AND expires_at <= %s
        RETURNING publish_request_id""",
        (moment,))
    return [row[0] for row in cur.fetchall()]


def promote_request(
    conn: psycopg.Connection,
    request_id: str,
    *,
    principal: Principal,
    target_stage: str,
    now: datetime | None = None,
    trace_id: str | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """灰度推进（S2）：next_bucket 逐桶推进、full 直接全量；观测窗未满 47007。

    S1 灰度为特性开关（默认关闭）：开关关闭时一律 47007（spec 1.2.1 已登记该端点）。
    """
    if not features.enabled("config_center.gray_rollout"):
        raise GrayPlanInvalid("灰度推进 S2 起启用（config_center.gray_rollout=false）")
    if target_stage not in ("next_bucket", "full"):
        raise ValidationFailed(f"target_stage 必须是 next_bucket / full：{target_stage!r}")
    moment = _now(now)
    request = _load_request(conn, request_id, for_update=True)
    if request["status"] not in ("approved", "scheduled", "rolling_out"):
        raise StateConflict(
            f"发布单 {request_id} 状态为 {request['status']}，不能推进灰度")
    item = load_registry().require(request["key"])
    plan = dict(request["gray_plan"] or {})
    buckets = list(plan.get("buckets") or [])
    if not buckets:
        raise GrayPlanInvalid(f"发布单 {request_id} 没有灰度计划（gray_plan.buckets）")
    observation = int(plan.get("observation_seconds") or 0)
    entered = int(plan.get("current_bucket") or 0)
    last_promoted = plan.get("last_promoted_at")
    if request["status"] == "rolling_out" and observation and last_promoted:
        last_at = datetime.fromisoformat(str(last_promoted))
        if moment < last_at + timedelta(seconds=observation):
            raise GrayPlanInvalid(
                f"观测窗未满（{observation}s），不得推进到下一桶（409 + 47007）")

    # 最后一个桶 = 全量：进入 100% 桶即激活（不再多一次 promote）
    if target_stage == "next_bucket" and entered + 1 < len(buckets) - 1:
        if request["status"] == "approved":      # §3 状态机：approved → scheduled → rolling_out
            conn.execute("""UPDATE config_publish_requests SET status = 'scheduled',
                                   updated_at = now()
                             WHERE publish_request_id = %s""", (request_id,))
        new_plan = {**plan, "current_bucket": entered + 1,
                    "last_promoted_at": moment.isoformat()}
        row = _one(conn,
                   """UPDATE config_publish_requests
                         SET status = 'rolling_out', gray_plan = %s, updated_at = now()
                       WHERE publish_request_id = %s RETURNING *""",
                   (Jsonb(new_plan), request_id))
        assert row is not None
        audit_mod.emit(audit, audit_mod.build_event(
            "config.promoted", actor=principal.actor, key=item.key, scope=request["scope"],
            scope_id=request["scope_id"], request_id=request_id, occurred_at=moment,
            metadata={"bucket": buckets[entered + 1], "stage": "rolling_out"}))
        return {"request": row, "bucket": buckets[entered + 1], "activated": False}

    versions = request["versions"]
    version = int(versions[request["key"]]) if isinstance(versions, dict) else None
    approved = list(request["approved_by"])
    result = _activate_and_emit(
        conn, item=item,
        version_row=store.get_version(conn, key=request["key"], version=version,
                                      scope=request["scope"], scope_id=request["scope_id"]),
        published_by=request["proposed_by"], approved_by=approved[0] if approved else None,
        effective_at=moment, period=f"publish:{request_id}", request_id=request_id,
        now=moment, trace_id=trace_id)
    row = _one(conn,
               """UPDATE config_publish_requests
                     SET status = 'active', snapshot_after = %s, updated_at = now()
                   WHERE publish_request_id = %s RETURNING *""",
               (result["snapshot_digest"], request_id))
    assert row is not None
    audit_mod.emit(audit, audit_mod.build_event(
        "config.promoted", actor=principal.actor, key=item.key, scope=request["scope"],
        scope_id=request["scope_id"], version=version, request_id=request_id,
        occurred_at=moment,
        metadata={"bucket": buckets[-1], "stage": "active",
                  "policy_version": result["policy_version"]}))
    return {"request": row, "bucket": buckets[-1], "activated": True, **result}


# ═════════════════════════════════════════════════════════════════════════════
# T4：回滚（INV-09）· kill switch（§21.4.2 流程 3）· 到期自动恢复
# ═════════════════════════════════════════════════════════════════════════════
def _cmp_value(value: Any) -> Any:
    """kill switch 收紧比较用的可比数值（布尔按 0/1，金额字符串按 Decimal）。"""
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return Decimal(str(value))
    if isinstance(value, str) and re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return Decimal(value)
    return value


def _tighter(item: ConfigKey, new: Any, current: Any) -> bool:
    """新值是否比当前值更保守（kill switch 只收紧；方向来自注册表）。"""
    if current is None:
        return True
    new_cmp, old_cmp = _cmp_value(new), _cmp_value(current)
    if item.direction == "reduce":
        return new_cmp < old_cmp
    if item.direction == "raise":
        return new_cmp > old_cmp
    return False


def _active_payload(conn: psycopg.Connection, *, key: str, scope: str,
                    scope_id: str) -> tuple[dict[str, Any] | None, Any]:
    row = store.active_version(conn, key=key, scope=scope, scope_id=scope_id)
    return row, _payload_of(row)


def rollback(
    conn: psycopg.Connection,
    *,
    key: str,
    target_version: int,
    principal: Principal,
    reason: str,
    scope: str = DEFAULT_SCOPE,
    scope_id: str = "",
    ticket: str | None = None,
    idempotency_key: str | None = None,
    now: datetime | None = None,
    trace_id: str | None = None,
    registry: Registry | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """回滚：以历史版本为内容生成**新版本**（rollback_to=target），再走复核 → 生效。

    · INV-09：历史版本一个字节都不改；
    · 目标必须是历史不可变版本（active / superseded / rolled_back），draft / rejected 不可回滚；
    · 回滚是止损：**不受发布窗口与冷却期限制**（§21.1.2），但仍需 P0/P1 复核 + step-up；
    · 生效时发 ``config.rolled_back``（payload 含 rollback_to / reason_code）。
    """
    reg = registry or load_registry()
    item = reg.require(key)
    validators.check_publishable(item.key, registry=reg)
    moment = _now(now)
    scope, scope_id = store.normalize_scope(scope, scope_id)
    reason = _text(reason, field="reason", minimum=4, maximum=512)
    _assert_proposer(principal, item)
    if target_version < 1:
        raise ValidationFailed(f"target_version 必须是正整数：{target_version!r}")

    if idempotency_key is not None:
        _text(idempotency_key, field="idempotency_key", minimum=8, maximum=128)
        existing = _one(conn,
                        "SELECT * FROM config_publish_requests WHERE scope = %s AND idempotency_key = %s",
                        (scope, idempotency_key))
        if existing is not None:
            same = (existing["key"] == key
                    and existing["scope_id"] == scope_id
                    and existing["proposed_by"] == principal.actor
                    and existing["rollback_target_version"] == target_version)
            if not same:
                raise IdempotencyConflict(
                    f"幂等键 {idempotency_key!r} 已用于不同发布单（{existing['key']}）", key=key)
            row = dict(existing)
            row["replayed"] = True
            return row

    target = store.get_version(conn, key=key, version=target_version,
                               scope=scope, scope_id=scope_id)
    if target is None:
        raise VersionNotFound(f"{key} v{target_version} 不存在（回滚目标）", key=key)
    if target["status"] not in ("active", "superseded", "rolled_back"):
        raise StateConflict(
            f"{key} v{target_version} 状态为 {target['status']}，只有历史生效版本可回滚（INV-09）")
    current = store.active_version(conn, key=key, scope=scope, scope_id=scope_id)
    if current is not None and current["version"] == target_version:
        raise StateConflict(f"{key} v{target_version} 已是当前生效版本，无需回滚")

    new_version = store.create_draft(
        conn,
        key=key,
        value=_payload_of(target),
        scope=scope,
        scope_id=scope_id,
        reason=reason,
        actor=principal.actor,
        ticket=ticket,
        now=moment,
        rollback_to=target_version,
        registry=reg,
    )
    request = _create_request_impl(
        conn, key=key, version=new_version["version"], principal=principal, reason=reason,
        scope=scope, scope_id=scope_id, ticket=ticket, idempotency_key=idempotency_key,
        trace_id=trace_id, now=moment, registry=reg, audit=audit,
        skip_cooldown=True, rollback_target_version=target_version)
    request["rollback_to"] = target_version
    request["new_version"] = new_version["version"]
    return request


def kill_switch(
    conn: psycopg.Connection,
    *,
    key: str,
    value: Any,
    ttl_seconds: int,
    principal: Principal,
    reason: str,
    scope: str = DEFAULT_SCOPE,
    scope_id: str = "",
    now: datetime | None = None,
    trace_id: str | None = None,
    registry: Registry | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """紧急收紧：立即生成并生效一个紧急版本（单人可发、只收紧、ttl ≤86400）。

    到期由 :func:`expire_kill_switches` 自动回到上一生效版本；也支持 :func:`restore_kill_switch`
    提前人工恢复。放宽一律 47004（危险键禁改口径）。
    """
    reg = registry or load_registry()
    item = reg.require(key)
    if not item.kill_switch or item.direction == "none":
        raise DangerousKeyForbidden(
            f"{key} 未声明可 kill switch（x-djb-kill-switch=true 且 direction≠none），拒绝（47004）",
            key=key)
    moment = _now(now)
    scope, scope_id = store.normalize_scope(scope, scope_id)
    reason = _text(reason, field="reason", minimum=4, maximum=512)
    _assert_proposer(principal, item)
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ValidationFailed(f"ttl_seconds 必须是整数：{ttl_seconds!r}")
    if not 1 <= ttl_seconds <= KILL_SWITCH_MAX_TTL_S:
        raise ValidationFailed(
            f"ttl_seconds 越界 1..{KILL_SWITCH_MAX_TTL_S}：{ttl_seconds}（M10 §6 流程 3）")

    current_row, current = _active_payload(conn, key=key, scope=scope, scope_id=scope_id)
    result = validators.validate_value(item.key, value, current=current)
    merged = {**effective_values(conn, registry=reg), item.key: result.value}
    validators.validate_cross_field(merged, touched=[item.key])
    if not _tighter(item, result.value, current):
        raise DangerousKeyForbidden(
            f"{key} 的 kill switch 只允许收紧（direction={item.direction}）："
            f"{current!r} → {result.value!r}（放宽一律 47004）", key=key)

    version_row = store.create_draft(
        conn, key=key, value=result.value, scope=scope, scope_id=scope_id,
        reason=reason, actor=principal.actor, now=moment,
        emergency=True, kill_switch_ttl_s=ttl_seconds,
        kill_switch_prev_version=current_row["version"] if current_row else None,
        registry=reg,
    )
    out = _activate_and_emit(
        conn, item=item, version_row=version_row,
        published_by=principal.actor, approved_by=None,
        effective_at=moment,
        period=f"kill:{key}:{version_row['version']}",
        request_id=None, now=moment, trace_id=trace_id,
    )
    audit_mod.emit(audit, audit_mod.build_event(
        "config.kill_switch", actor=principal.actor, key=key, scope=scope,
        scope_id=scope_id, version=version_row["version"], reason=reason,
        trace_id=trace_id, occurred_at=moment,
        before=current, after=result.value,
        metadata={"ttl_seconds": ttl_seconds,
                  "previous_version": current_row["version"] if current_row else None}))
    out["request"] = None
    out["expires_at"] = version_row["kill_switch_expires_at"]
    return out


def _restore_previous(
    conn: psycopg.Connection,
    *,
    key: str,
    scope: str,
    scope_id: str,
    actor_label: str,
    reason_code: str,
    reason: str,
    now: datetime,
    trace_id: str | None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """把生效中的紧急版本恢复到它的上一生效版本（生成新版本 + 发 config.rolled_back）。"""
    reg = load_registry()
    item = reg.require(key)
    active = store.active_version(conn, key=key, scope=scope, scope_id=scope_id)
    if active is None or not active["emergency"]:
        raise StateConflict(f"{key} 没有生效中的 kill switch 版本")
    previous = active["kill_switch_prev_version"]
    if not previous:
        raise ValidationFailed(f"{key} 的紧急版本没有记录上一生效版本，无法自动恢复")
    target = store.get_version(conn, key=key, version=int(previous),
                               scope=scope, scope_id=scope_id)
    if target is None:
        raise VersionNotFound(f"{key} v{previous}（恢复目标）不存在", key=key)
    new_version = store.create_draft(
        conn, key=key, value=_payload_of(target), scope=scope, scope_id=scope_id,
        reason=reason, actor=actor_label, now=now, rollback_to=int(previous), registry=reg,
    )
    out = _activate_and_emit(
        conn, item=item, version_row=new_version,
        published_by=actor_label, approved_by=None,
        effective_at=now,
        period=f"restore:{key}:{new_version['version']}",
        request_id=None, now=now, trace_id=trace_id,
        reason_code=reason_code,
    )
    audit_mod.emit(audit, audit_mod.build_event(
        "config.rolled_back", actor=actor_label, key=key, scope=scope, scope_id=scope_id,
        version=new_version["version"], reason=reason_code, trace_id=trace_id,
        occurred_at=now, metadata={"restored_from": int(previous),
                                   "kill_switch": True}))
    out["request"] = None
    out["restored_from"] = int(previous)
    return out


def restore_kill_switch(
    conn: psycopg.Connection,
    *,
    key: str,
    principal: Principal,
    reason: str,
    scope: str = DEFAULT_SCOPE,
    scope_id: str = "",
    now: datetime | None = None,
    trace_id: str | None = None,
    registry: Registry | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> dict[str, Any]:
    """提前人工恢复（到期自动恢复由 :func:`expire_kill_switches` 做）。"""
    moment = _now(now)
    reg = registry or load_registry()
    item = reg.require(key)
    _assert_proposer(principal, item)
    scope, scope_id = store.normalize_scope(scope, scope_id)
    reason = _text(reason, field="reason", minimum=4, maximum=512)
    return _restore_previous(
        conn, key=key, scope=scope, scope_id=scope_id,
        actor_label="system:kill_switch_restore",
        reason_code=KILL_SWITCH_RESTORED_CODE,
        reason=f"{principal.actor}: {reason}",
        now=moment, trace_id=trace_id, audit=audit)


def expire_kill_switches(
    conn: psycopg.Connection,
    *,
    now: datetime | None = None,
    trace_id: str | None = None,
    audit: "audit_mod.AuditSink | None" = None,
) -> list[dict[str, Any]]:
    """到期自动恢复：把所有过期的紧急版本恢复到上一生效版本（P95 ≤60s 由即时执行保证）。"""
    moment = _now(now)
    rows = _rows(conn,
                 """SELECT key, scope, scope_id, version FROM config_versions
                     WHERE emergency AND status = 'active'
                       AND kill_switch_expires_at IS NOT NULL
                       AND kill_switch_expires_at <= %s
                     ORDER BY key""", (moment,))
    restored: list[dict[str, Any]] = []
    for row in rows:
        out = _restore_previous(
            conn, key=row["key"], scope=row["scope"], scope_id=row["scope_id"],
            actor_label=SYSTEM_ACTOR, reason_code=KILL_SWITCH_EXPIRED_CODE,
            reason=f"kill switch ttl 到期自动恢复（v{row['version']}）",
            now=moment, trace_id=trace_id, audit=audit)
        restored.append({"key": row["key"], "scope": row["scope"],
                         "scope_id": row["scope_id"], "expired_version": row["version"],
                         "restored_from": out["restored_from"],
                         "new_version": out["version"]["version"]})
    return restored
