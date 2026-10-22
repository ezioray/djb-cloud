# SPDX-License-Identifier: Apache-2.0
"""M01 T4 · 管理面领域层（冻结 / 解冻 / 角色绑定 / 租户配额）。

权限与复核（M01 §4.1、§6.3、INV-05 / INV-06 / INV-07；spec 1.2.1 admin 段）：
- **调用方身份**：adminBearer 会话 + step-up（``X-Admin-Step-Up`` 或会话内 5 分钟窗口），
  由 :mod:`app.identity.router` 统一解析；本模块只接收已解析的 ``operator_id``。
- **冻结**：``frozen_until`` 必填、≤180 天；写 ``frozen_reason`` + 审批链（``evidence_ref``）；
  解冻人 ≠ 冻结人（40902）。
- **角色**：八角色白名单；授予需 ``second_approver`` ≠ 操作人（SoD）；SVC 不得绑自然人；
  变更后 ``session_epoch++``（旧会话 40102）；读侧给出 ``roles`` + ``session_epoch``。
- **配额**：``kind / value / policy_version``；生效值 = min(租户, Key, 节点能力)；
  **升配额需 FIN 复核**（03-facts 未定义阈值，S1 取更严口径：任何上调都要复核），
  降配额立即生效；每次变更写一条 ``tenant_quota_history``（只追加，不覆盖历史）。

审计：状态类动作发已登记的 ``account.state.changed``；角色变更触发 ``session.revoked``；
配额变更落历史表 + 结构化日志。所有 payload / 日志只用内部 id 与原因码，**不含 PII**。
"""
from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

import psycopg

from . import clock, errors, models, state

REASON_MAX = 500
EVIDENCE_MAX = 128
# spec TenantQuotaEntry.kind 是自由字符串，示例用 daily_spend；本项目口径是 daily_usd_minor
QUOTA_KIND_ALIASES = {"daily_spend": "daily_usd_minor", "daily_spend_minor": "daily_usd_minor"}


@dataclass(frozen=True)
class QuotaEntry:
    kind: str
    value: int
    key_id: int | None = None
    unit: str | None = None


# --------------------------------------------------------------------------- 入参校验
def _reason(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise models.InvalidArgument("reason 必填", field="reason")
    if len(value) > REASON_MAX:
        raise models.InvalidArgument(f"reason 最长 {REASON_MAX}", field="reason")
    return value.strip()


def _evidence_ref(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise models.InvalidArgument("evidence_ref 必须是非空字符串", field="evidence_ref")
    text = value.strip()
    if len(text) > EVIDENCE_MAX:
        raise models.InvalidArgument(f"evidence_ref 最长 {EVIDENCE_MAX}", field="evidence_ref")
    return text


def _operator(value: Any) -> uuid.UUID:
    """复核人 / 操作人：spec 里是字符串，内部统一成账户 UUID（非法即 400）。"""
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str) or not value.strip():
        raise models.InvalidArgument("second_approver 必填", field="second_approver")
    try:
        return uuid.UUID(value.strip())
    except ValueError as exc:
        raise models.InvalidArgument("second_approver 必须是账户 UUID", field="second_approver") \
            from exc


def _roles(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise models.InvalidArgument(f"{field} 必须是字符串数组", field=field)
    out: list[str] = []
    for role in value:
        if role not in models.ADMIN_ROLES:
            raise models.InvalidArgument(
                f"{field} 含未登记角色：{role!r}", field=field, allowed=list(models.ADMIN_ROLES))
        if role not in out:
            out.append(role)
    return out


def _quota_entries(value: Any) -> list[QuotaEntry]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or not value:
        raise models.InvalidArgument("quotas 必须是至少 1 条的对象数组", field="quotas")
    entries: list[QuotaEntry] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise models.InvalidArgument("quotas 每项必须是对象", field="quotas")
        raw_kind = item.get("kind")
        if not isinstance(raw_kind, str) or not raw_kind.strip():
            raise models.InvalidArgument("quotas[].kind 必填", field="quotas")
        kind = QUOTA_KIND_ALIASES.get(raw_kind.strip(), raw_kind.strip())
        if kind not in models.QUOTA_KINDS:
            raise models.InvalidArgument(
                f"未登记的配额种类：{raw_kind!r}", field="quotas",
                allowed=list(models.QUOTA_KINDS))
        raw_value = item.get("value")
        if not isinstance(raw_value, int) or isinstance(raw_value, bool) or raw_value < 0:
            raise models.InvalidArgument("quotas[].value 必须是非负整数", field="quotas")
        key_id = item.get("key_id")
        if key_id is not None:
            try:
                key_id = int(str(key_id))
            except (TypeError, ValueError) as exc:
                raise models.InvalidArgument("quotas[].key_id 必须是整数", field="quotas") from exc
        entries.append(QuotaEntry(kind=kind, value=raw_value, key_id=key_id,
                                  unit=item.get("unit")))
    return entries


# --------------------------------------------------------------------------- 冻结 / 解冻
def freeze(c, *, account_id: str | uuid.UUID, operator_id: uuid.UUID, payload: Mapping[str, Any],
           now: datetime | None = None, trace_id: str | None = None) -> models.Account:
    """冻结：理由 + 期限必填（≤180 天）；审批链留痕（evidence_ref 进 frozen_approval）。"""
    moment = now or clock.utcnow()
    target = _account_uuid(account_id)
    reason = _reason(payload.get("reason"))
    evidence = _evidence_ref(payload.get("evidence_ref"))
    until = payload.get("frozen_until")
    if until is not None and not isinstance(until, str):
        raise models.InvalidArgument("frozen_until 必须是 RFC 3339 字符串", field="frozen_until")
    deadline = _parse_datetime(until, "frozen_until") if until else None
    approval = [{"action": "freeze", "operator": str(operator_id),
                 "evidence_ref": evidence}]
    account = state.freeze(c, target, until=deadline, reason=reason, approval_chain=approval,
                           actor_id=operator_id, now=moment, trace_id=trace_id)
    models.log.info("identity.admin.freeze account_id=%s operator=%s until=%s evidence=%s",
                    account.id, operator_id, account.frozen_until, evidence or "-")
    return account


def unfreeze(c, *, account_id: str | uuid.UUID, operator_id: uuid.UUID,
             payload: Mapping[str, Any], now: datetime | None = None,
             trace_id: str | None = None) -> models.Account:
    """解冻：与原冻结人必须不同（40902）；重复解冻按状态冲突返回。"""
    moment = now or clock.utcnow()
    target = _account_uuid(account_id)
    reason = _reason(payload.get("reason"))
    evidence = _evidence_ref(payload.get("evidence_ref"))
    account = state.unfreeze(c, target, approver_id=operator_id, reason=reason, now=moment,
                             trace_id=trace_id)
    models.log.info("identity.admin.unfreeze account_id=%s operator=%s evidence=%s",
                    account.id, operator_id, evidence or "-")
    return account


def _account_uuid(value: str | uuid.UUID) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except ValueError as exc:
        raise models.InvalidArgument("账户 id 非法", field="id") from exc


def _parse_datetime(value: str, field: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise models.InvalidArgument(f"{field} 不是合法时间", field=field) from exc
    if parsed.tzinfo is None:
        raise models.InvalidArgument(f"{field} 必须带时区（UTC）", field=field)
    return parsed


# --------------------------------------------------------------------------- 角色
def roles_view(c, account_id: str | uuid.UUID, *, now: datetime | None = None) -> dict[str, Any]:
    """读侧（GET 语义；spec 1.2.1 未声明 GET 路由，供 M14 / 后续契约扩展复用）。"""
    moment = now or clock.utcnow()
    target = models.get_account(c, _account_uuid(account_id))
    return {"account_id": str(target.id),
            "roles": list(models.effective_roles(c, target.id, now=moment)),
            "session_epoch": target.session_epoch}


def set_roles(c, *, account_id: str | uuid.UUID, operator_id: uuid.UUID,
              payload: Mapping[str, Any], now: datetime | None = None,
              trace_id: str | None = None) -> dict[str, Any]:
    """授予 / 回收角色：SoD（second_approver ≠ 操作人）+ 八角色白名单 + epoch++。"""
    moment = now or clock.utcnow()
    target = models.get_account(c, _account_uuid(account_id))
    grant = _roles(payload.get("grant"), "grant")
    revoke = _roles(payload.get("revoke"), "revoke")
    if not grant and not revoke:
        raise models.InvalidArgument("grant / revoke 至少给一项", field="grant")
    reason = _reason(payload.get("reason"))
    approver = _operator(payload.get("second_approver"))
    if approver == operator_id:
        raise models.StateConflict("复核人不得是操作人（SoD）", reason="dual_control_required")
    scope = payload.get("scope", "platform")
    if not isinstance(scope, str) or not scope.strip():
        raise models.InvalidArgument("scope 必须是非空字符串", field="scope")
    scope = scope.strip()
    before = list(models.effective_roles(c, target.id, now=moment))

    for role in grant:
        # 授予写只读账户（frozen / closing）→ 403/40304；回收是安全动作，始终允许
        models.assert_writable(target, action="授予后台角色")
        models.bind_role(c, account_id=target.id, admin_role=role, granted_by=operator_id,
                         approved_by=approver, scope=scope, now=moment, trace_id=trace_id)
    for role in revoke:
        for binding in _live_bindings(c, target.id, role):
            models.revoke_role(c, binding, reason=reason, actor_id=operator_id, now=moment,
                               trace_id=trace_id)
    after = list(models.effective_roles(c, target.id, now=moment))
    models.log.info("identity.admin.roles account_id=%s operator=%s approver=%s "
                    "grant=%s revoke=%s before=%s after=%s reason=%s",
                    target.id, operator_id, approver, grant, revoke, before, after, reason)
    account = models.get_account(c, target.id)
    return {"account_id": str(account.id), "roles": after,
            "session_epoch": account.session_epoch}


def _live_bindings(c, account_id: uuid.UUID, role: str) -> list[uuid.UUID]:
    with c.cursor() as cur:
        cur.execute("""SELECT id FROM role_bindings
                        WHERE account_id = %s AND admin_role = %s AND revoked_at IS NULL""",
                    (account_id, role))
        return [row[0] for row in cur.fetchall()]


# --------------------------------------------------------------------------- 配额
def quotas_view(c, tenant_id: str | uuid.UUID, *, key_id: int | None = None) -> dict[str, Any]:
    """读侧（GET 语义；spec 1.2.1 未声明 GET 路由，供 M14 / 后续契约扩展复用）。"""
    target = _account_uuid(tenant_id)
    rows = models.get_quotas(c, target, key_id=key_id)
    latest = _latest_policy_version(c, target, key_id=key_id)
    return {
        "tenant_id": str(target),
        "quotas": [{"kind": row.kind, "value": int(row.value),
                    "policy_version": row.policy_version,
                    **({"key_id": str(row.key_id)} if row.key_id is not None else {})}
                   for row in rows],
        "policy_version": latest,
    }


def _latest_policy_version(c, tenant_id: uuid.UUID, *, key_id: int | None = None) -> str | None:
    """最近一次配额变更的版本。

    取 ``tenant_quota_history`` 的最后一条（主键 uuid7 时间有序，确定性好）；
    历史表为空时退回现值行，避免「同一事务内 now() 相同」造成的排序并列。
    """
    with c.cursor() as cur:
        cur.execute(
            """SELECT policy_version FROM tenant_quota_history
                WHERE tenant_id = %s AND (%s::bigint IS NULL OR key_id = %s::bigint)
                ORDER BY id DESC LIMIT 1""",
            (tenant_id, key_id, key_id))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute(
            """SELECT policy_version FROM tenant_quotas
                WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 1""",
            (tenant_id,))
        row = cur.fetchone()
    return row[0] if row else None


def _require_tenant(c, tenant_id: uuid.UUID) -> None:
    """租户必须存在：personal 账户即租户，team/enterprise 的租户是 org。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT 1 FROM user_accounts WHERE tenant_id = %s
               UNION ALL SELECT 1 FROM orgs WHERE id = %s LIMIT 1""",
            (tenant_id, tenant_id))
        if cur.fetchone() is None:
            raise models.NotFound("租户不存在", tenant_id=str(tenant_id))


def next_policy_version(moment: datetime) -> str:
    """配额版本号：时间序 + 随机尾（同秒多次变更也不冲突；只增不改）。"""
    return f"q-{moment.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"


def set_quotas(c, *, tenant_id: str | uuid.UUID, operator_id: uuid.UUID,
               payload: Mapping[str, Any], now: datetime | None = None,
               trace_id: str | None = None) -> dict[str, Any]:
    """改配额：升需复核（FIN SoD），降立即生效；每次变更写一条只追加历史。"""
    moment = now or clock.utcnow()
    target = _account_uuid(tenant_id)
    entries = _quota_entries(payload.get("quotas"))
    reason = _reason(payload.get("reason"))
    approver_raw = payload.get("second_approver")
    approver = _operator(approver_raw) if approver_raw is not None else None

    _require_tenant(c, target)
    current = {(row.key_id, row.kind): int(row.value) for row in models.get_quotas(c, target)}
    increases = [e for e in entries if e.value > current.get((e.key_id, e.kind), -1)]
    if increases and approver is None:
        # 双人复核属于 SoD（不是 step-up），按 spec 的 409 + 40902 表达
        raise models.StateConflict("升配额需要 FIN 复核（second_approver 必填）",
                                  reason="quota_increase_requires_approval")
    if approver is not None and approver == operator_id:
        raise models.StateConflict("复核人不得是操作人（SoD）", reason="dual_control_required")

    version = next_policy_version(moment)
    for entry in entries:
        previous = current.get((entry.key_id, entry.kind))
        models.set_quota(c, tenant_id=target, kind=entry.kind, value=entry.value,
                         policy_version=version, key_id=entry.key_id, now=moment)
        try:
            _record_history(c, tenant_id=target, entry=entry, previous=previous,
                            policy_version=version, actor_id=operator_id, reason=reason,
                            now=moment)
        except psycopg.errors.IntegrityError as exc:
            # 历史落不下就不该改现值：整体回滚并给规范错误码（不吞成 500）
            raise models.StateConflict("配额历史写入失败，已整体回滚",
                                       reason="quota_history_conflict") from exc
    # 版本是「租户策略快照」而非单行属性：整租户的行同步到同一版本，
    # 否则零星改一个 kind 会让快照出现两个版本，触发 INV-07 的 40907。
    with c.cursor() as cur:
        cur.execute("UPDATE tenant_quotas SET policy_version = %s WHERE tenant_id = %s",
                    (version, target))
    models.log.info("identity.admin.quotas tenant_id=%s operator=%s approver=%s kinds=%s "
                    "policy_version=%s reason=%s",
                    target, operator_id, approver, [e.kind for e in entries], version, reason)
    payload_out = quotas_view(c, target)
    payload_out["policy_version"] = version
    payload_out["effective_at"] = moment.isoformat()
    return payload_out


def _record_history(c, *, tenant_id: uuid.UUID, entry: QuotaEntry, previous: int | None,
                    policy_version: str, actor_id: uuid.UUID, reason: str,
                    now: datetime) -> None:
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO tenant_quota_history
                   (id, tenant_id, key_id, kind, value, previous_value, policy_version,
                    actor_id, reason, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (models.uuid7(), tenant_id, entry.key_id, entry.kind, entry.value, previous,
             policy_version, actor_id, reason, now))


__all__ = ["REASON_MAX", "EVIDENCE_MAX", "QUOTA_KIND_ALIASES", "QuotaEntry",
           "freeze", "unfreeze", "roles_view", "set_roles", "quotas_view", "set_quotas",
           "next_policy_version"]
