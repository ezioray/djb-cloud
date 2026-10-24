# SPDX-License-Identifier: AGPL-3.0-or-later
"""M01 identity-tenant · 账户五态机 / 冻结期限 / 注销三步（DEV-M01-T1）。

唯一口径（M01 §3；03-facts §8）::

    pending_verify ─验证─▶ normal ⇄ frozen(frozen_until) ─▶ closing(30d) ─▶ closed
    可逆分支：frozen ──解除/到期──▶ normal；closing ──撤回──▶ normal；closed 不可逆

设计要点：
- **未登记的边一律拒绝**（``IllegalTransition`` 40903）：即使调用方传了合法状态名，
  只要不在 ``TRANSITIONS`` 里就报错，不存在「顺手放行」的默认分支。
- 每次迁移在**同一事务**里写一条 ``account.state.changed``（outbox），并带
  ``idempotency_key``，因此 job 重放不会重复产生事件（A2）。
- 冻结必须带 ``frozen_until`` + ``frozen_reason`` + ``approval_chain``，期限 ≤180 天（INV-01）；
  解冻人不得是冻结人（40902），到期解冻由 job 执行且可重放。
- 注销三步：结清检查（四项）→ ``closing``（只读、可撤回）→ 30 天后删除个人信息、
  撤销全部 Key 与会话、请求账本去关联 → ``closed``（不可逆，INV-03）。
  四项未结清一律 40906 + 未结项清单；账本去关联只**标记**不碰 M06 表。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

from psycopg.types.json import Jsonb

from . import models
from .models import (
    ACCOUNT_STATES,
    CLOSING_COOLOFF_DAYS,
    FREEZE_MAX_DAYS,
    PENDING_VERIFY_TTL_DAYS,
    Account,
    AccountClosed,
    AccountReadOnly,
    ClosureBlocked,
    IdentityError,
    IllegalTransition,
    InvalidArgument,
    NotFound,
    StateConflict,
    _ACCOUNT_COLS,
    _make,
    _now,
    _one,
    _text,
    emit_event,
    log,
)

# --------------------------------------------------------------------------- 迁移表
TRANSITIONS: dict[str, frozenset[str]] = {
    "pending_verify": frozenset({"normal", "closed"}),   # 验证通过 / 7 天未验清理
    "normal": frozenset({"frozen", "closing"}),
    "frozen": frozenset({"normal", "closing"}),          # 解除或到期 / 升级注销
    "closing": frozenset({"normal", "closed"}),          # 撤回 / 冷静期结束
    "closed": frozenset(),                               # 不可逆（INV-03）
}

# 注销前置四项（INV-08）；缺项 / False 即 40906，并回未结项清单
CLOSURE_CHECKS = (
    ("locked_earnings", "存在锁定收益"),
    ("open_disputes", "存在未结争议"),
    ("negative_balance", "存在负余额"),
    ("open_tickets", "存在未结工单"),
)


def can_transition(from_state: str, to_state: str) -> bool:
    """五态机查询（供 T2/T4 与前端展示「可读动作清单」）。"""
    return to_state in TRANSITIONS.get(from_state, frozenset())


def legal_targets(from_state: str) -> tuple[str, ...]:
    return tuple(sorted(TRANSITIONS.get(from_state, frozenset())))


# --------------------------------------------------------------------------- 基础迁移
def transition(c, account_id: uuid.UUID, to_state: str, *, reason_code: str,
               tenant_id: uuid.UUID | None = None, fields: Mapping[str, Any] | None = None,
               now: datetime | None = None, trace_id: str | None = None,
               idempotency_key: str | None = None) -> tuple[Account, Account]:
    """执行一次有向迁移：返回 ``(迁移前, 迁移后)``，并落 ``account.state.changed``。

    ``fields`` 只能带本模块列（冻结 / 冷静期等附加字段），且不与 state 冲突。
    """
    models._check(to_state, ACCOUNT_STATES, "to_state")
    _text(reason_code, "reason_code", max_len=64)
    before = models.get_account(c, account_id, tenant_id=tenant_id, for_update=True)
    if to_state == before.state:
        raise IllegalTransition(f"状态未变化（{before.state}），不产生事件",
                                reason="noop_transition", from_state=before.state,
                                to_state=to_state)
    if not can_transition(before.state, to_state):
        raise IllegalTransition(
            f"非法迁移 {before.state} → {to_state}",
            from_state=before.state, to_state=to_state,
            allowed=list(legal_targets(before.state)))
    sets = ["state = %s"]
    params: list[Any] = [to_state]
    effective_fields: dict[str, Any] = dict(fields or {})
    if before.state == "frozen" and to_state != "frozen":
        # 离开 frozen 必须一并清空冻结留痕（库层 CHECK 也这么要求；历史留在 outbox）
        for column in ("frozen_until", "frozen_reason", "frozen_by", "frozen_approval"):
            effective_fields.setdefault(column, None)
    for column, value in effective_fields.items():
        if column == "state":
            raise InvalidArgument("fields 不得覆盖 state", field=column)
        sets.append(f"{column} = %s")
        params.append(Jsonb(value) if isinstance(value, (dict, list)) else value)
    params.append(account_id)
    with c.cursor() as cur:
        cur.execute(
            f"UPDATE user_accounts SET {', '.join(sets)} WHERE id = %s RETURNING {_ACCOUNT_COLS}",
            params)
        after = _make(Account, _one(cur))
    emit_event(c, "account.state.changed", aggregate_type="account", aggregate_id=after.id,
               payload={"account_id": str(after.id), "type": after.type,
                        "tenant_id": str(after.tenant_id), "from": before.state,
                        "to": after.state, "reason_code": reason_code,
                        "frozen_until": after.frozen_until.isoformat()
                        if after.frozen_until else None},
               trace_id=trace_id, now=now,
               idempotency_key=idempotency_key
               or f"account.state.changed:{after.id}:{before.state}:{to_state}:{reason_code}")
    log.info("identity.account.state_changed account_id=%s from=%s to=%s reason=%s",
             after.id, before.state, after.state, reason_code)
    return before, after


# --------------------------------------------------------------------------- 注册验证
def verify(c, account_id: uuid.UUID, *, now: datetime | None = None,
           trace_id: str | None = None) -> Account:
    """pending_verify → normal（验证成功）。"""
    _, after = transition(c, account_id, "normal", reason_code="email_verified",
                          now=now, trace_id=trace_id)
    return after


def expire_pending(c, *, now: datetime | None = None, trace_id: str | None = None) -> list[uuid.UUID]:
    """7 天未验证清理 job（可重放）：pending_verify → closed，并删除个人信息。

    只清 PII，不删行：账本去关联化要求主体仍可被引用（INV-03）。
    """
    moment = _now(now)
    cutoff = moment - timedelta(days=PENDING_VERIFY_TTL_DAYS)
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {_ACCOUNT_COLS} FROM user_accounts
                 WHERE state = 'pending_verify' AND created_at <= %s
                 ORDER BY created_at FOR UPDATE""",
            (cutoff,))
        rows = [_make(Account, r) for r in models._rows(cur)]
    closed: list[uuid.UUID] = []
    for account in rows:
        transition(c, account.id, "closed", reason_code="pending_verify_expired",
                   fields={"closed_at": moment}, now=moment, trace_id=trace_id)
        models.purge_user_pii(c, account.user_id)
        with c.cursor() as cur:
            cur.execute("UPDATE user_accounts SET pii_purged_at = %s WHERE id = %s",
                        (moment, account.id))
        closed.append(account.id)
    return closed


# --------------------------------------------------------------------------- 冻结 / 解冻
def _freeze_deadline(until: datetime, moment: datetime) -> datetime:
    """INV-01：``frozen_until`` 必填、必须在未来、单次 ≤180 天。"""
    if until.tzinfo is None:
        raise InvalidArgument("frozen_until 必须带时区（UTC）", field="frozen_until")
    deadline = until.astimezone(moment.tzinfo)
    if deadline <= moment:
        raise InvalidArgument("frozen_until 必须在将来", field="frozen_until")
    if deadline > moment + timedelta(days=FREEZE_MAX_DAYS):
        raise InvalidArgument(f"冻结单次不得超过 {FREEZE_MAX_DAYS} 天（INV-01）",
                              field="frozen_until", max_days=FREEZE_MAX_DAYS)
    return deadline


def freeze(c, account_id: uuid.UUID, *, until: datetime | None, reason: str,
           approval_chain: Sequence[Mapping[str, Any]] | None, actor_id: uuid.UUID | None = None,
           now: datetime | None = None, trace_id: str | None = None) -> Account:
    """normal → frozen：理由 + 期限 + 审批链必填（A1：缺 ``frozen_until`` → 40001，不落库）。"""
    moment = _now(now)
    if until is None:
        raise InvalidArgument("冻结必须填写 frozen_until（INV-01 / A1）", field="frozen_until")
    deadline = _freeze_deadline(until, moment)
    reason = _text(reason, "frozen_reason", max_len=200)
    if not approval_chain:
        raise InvalidArgument("冻结必须带 approval_chain（留痕）", field="approval_chain")
    if actor_id is None:
        raise InvalidArgument("冻结必须记录操作者", field="actor_id")
    before = models.get_account(c, account_id, for_update=True)
    if before.state == "frozen":
        raise StateConflict("账户已冻结：续期请走 renew_freeze（须新裁决）",
                            reason="already_frozen", account_id=str(account_id))
    _, after = transition(
        c, account_id, "frozen", reason_code="risk_freeze", now=moment, trace_id=trace_id,
        fields={"frozen_until": deadline, "frozen_reason": reason, "frozen_by": actor_id,
                "frozen_approval": Jsonb(list(approval_chain))})
    # M01 §6.3：冻结即让会话失效（epoch++ 且撤销活跃会话）
    models.invalidate_sessions(c, account_id, reason="frozen", now=moment, trace_id=trace_id)
    return models.get_account(c, account_id)


def renew_freeze(c, account_id: uuid.UUID, *, until: datetime, reason: str,
                 approval_chain: Sequence[Mapping[str, Any]] | None,
                 actor_id: uuid.UUID | None = None, now: datetime | None = None,
                 trace_id: str | None = None) -> Account:
    """续期：须新裁决（approval_chain 必填）+ 留痕；只能延长，不能缩短。"""
    moment = _now(now)
    deadline = _freeze_deadline(until, moment)
    if not approval_chain:
        raise InvalidArgument("续期冻结必须带新的 approval_chain（INV-01）", field="approval_chain")
    account = models.get_account(c, account_id, for_update=True)
    if account.state != "frozen" or account.frozen_until is None:
        raise StateConflict("只有 frozen 账户可续期", reason="not_frozen",
                            state=account.state)
    if deadline <= account.frozen_until:
        raise InvalidArgument("续期必须晚于当前冻结到期时间", field="frozen_until")
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE user_accounts
                   SET frozen_until = %s, frozen_reason = %s, frozen_approval = %s,
                       frozen_by = %s
                 WHERE id = %s RETURNING {_ACCOUNT_COLS}""",
            (deadline, _text(reason, "frozen_reason", max_len=200),
             Jsonb(list(approval_chain)), actor_id or account.frozen_by, account_id))
        renewed = _make(Account, _one(cur))
    # 续期不是状态迁移（frozen → frozen），但仍是事实：落一条 event 留痕
    emit_event(c, "account.state.changed", aggregate_type="account", aggregate_id=renewed.id,
               payload={"account_id": str(renewed.id), "type": renewed.type,
                        "tenant_id": str(renewed.tenant_id), "from": "frozen", "to": "frozen",
                        "reason_code": "freeze_renewed",
                        "frozen_until": renewed.frozen_until.isoformat()
                        if renewed.frozen_until else None},
               trace_id=trace_id, now=moment,
               idempotency_key=f"account.freeze.renewed:{renewed.id}:"
                               f"{renewed.frozen_until.isoformat()}")
    return renewed


def unfreeze(c, account_id: uuid.UUID, *, approver_id: uuid.UUID | None, reason: str,
             now: datetime | None = None, trace_id: str | None = None) -> Account:
    """frozen → normal（人工解冻）：审批人不得是冻结人（M01 §6.3、INV-05 同口径）。"""
    account = models.get_account(c, account_id, for_update=True)
    if account.state != "frozen":
        raise StateConflict("只有 frozen 账户可解冻", reason="not_frozen", state=account.state)
    if approver_id is None:
        raise InvalidArgument("解冻必须记录审批人", field="approver_id")
    if account.frozen_by is not None and approver_id == account.frozen_by:
        raise StateConflict("解冻人不得是冻结人（双人复核）", reason="dual_control_required",
                            account_id=str(account_id))
    _text(reason, "reason", max_len=200)
    _, after = transition(
        c, account_id, "normal", reason_code="manual_unfreeze", now=now, trace_id=trace_id,
        fields={"frozen_until": None, "frozen_reason": None, "frozen_by": None,
                "frozen_approval": None})
    return after


def expire_freeze(c, *, now: datetime | None = None, trace_id: str | None = None) -> list[uuid.UUID]:
    """到期自动解除 job（可重放）：只处理 ``frozen`` 且 ``frozen_until <= now`` 的账户。

    重放不产生第二条事件：第一次迁移后状态已是 normal，扫描条件不再命中（A2）。
    """
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {_ACCOUNT_COLS} FROM user_accounts
                 WHERE state = 'frozen' AND frozen_until <= %s
                 ORDER BY frozen_until FOR UPDATE""",
            (moment,))
        rows = [_make(Account, r) for r in models._rows(cur)]
    thawed: list[uuid.UUID] = []
    for account in rows:
        transition(c, account.id, "normal", reason_code="freeze_expired", now=moment,
                   trace_id=trace_id,
                   fields={"frozen_until": None, "frozen_reason": None, "frozen_by": None,
                           "frozen_approval": None})
        thawed.append(account.id)
    return thawed


# --------------------------------------------------------------------------- 注销三步
def check_closure(c, account_id: uuid.UUID, *,
                  checks: Mapping[str, bool]) -> list[str]:
    """注销前置检查（INV-08）。四项由调用方经 M05 / M06 / M08 内部只读 API 查得后传入，
    本模块**不 join** 对方基表。返回未结项 key 列表；全部结清返回空列表。
    """
    missing = [name for name, _ in CLOSURE_CHECKS if name not in checks]
    if missing:
        raise InvalidArgument(f"注销前置缺少检查项：{missing}", reason="closure_checks_incomplete",
                             missing=missing)
    unmet = [name for name, _ in CLOSURE_CHECKS if not checks[name]]
    return unmet


def precheck_closure(c, account_id: uuid.UUID, *, checks: Mapping[str, bool]) -> list[dict]:
    """给管理面 / T2 用的清单：未结项 → 直接 40906（带可读清单）。"""
    account = models.get_account(c, account_id)
    if account.state == "closed":
        raise AccountClosed("账户已注销", account_id=str(account_id))
    unmet = check_closure(c, account_id, checks=checks)
    if unmet:
        labels = dict(CLOSURE_CHECKS)
        raise ClosureBlocked("注销前置未结清", account_id=str(account_id),
                             unmet=[{"item": name, "label": labels[name]} for name in unmet])
    return []


def start_closing(c, account_id: uuid.UUID, *, checks: Mapping[str, bool],
                  reason: str = "user_request", now: datetime | None = None,
                  trace_id: str | None = None) -> Account:
    """第一步：结清检查通过后进入 ``closing``（只读、可撤回），冷静期 30 天。"""
    moment = _now(now)
    precheck_closure(c, account_id, checks=checks)
    account = models.get_account(c, account_id, for_update=True)
    if account.state not in ("normal", "frozen"):
        raise IllegalTransition(f"{account.state} 不能进入 closing",
                                from_state=account.state, to_state="closing")
    _, after = transition(
        c, account_id, "closing", reason_code=_text(reason, "reason", max_len=64).lower(),
        now=moment, trace_id=trace_id,
        fields={"closing_deadline": moment + timedelta(days=CLOSING_COOLOFF_DAYS),
                "frozen_until": None, "frozen_reason": None, "frozen_by": None,
                "frozen_approval": None})
    # closing 只读：立刻撤销全部会话与 Key 的**写**能力（Key 保留到正式 closed 再撤销）
    models.invalidate_sessions(c, account_id, reason="closing", now=moment, trace_id=trace_id)
    return after


def withdraw_closing(c, account_id: uuid.UUID, *, reason: str = "withdraw",
                     now: datetime | None = None, trace_id: str | None = None) -> Account:
    """冷静期内撤回：``closing`` → ``normal``。"""
    _, after = transition(c, account_id, "normal",
                          reason_code=_text(reason, "reason", max_len=64).lower(),
                          now=now, trace_id=trace_id,
                          fields={"closing_deadline": None})
    return after


def finalize_closing(c, account_id: uuid.UUID, *, now: datetime | None = None,
                     trace_id: str | None = None) -> dict:
    """第三步：冷静期满 → 删除个人信息、撤销全部 Key 与会话、请求账本去关联 → ``closed``。

    返回删除报告（M01 §6.4：``closed`` 后只允许导出删除报告）。
    """
    moment = _now(now)
    account = models.get_account(c, account_id, for_update=True)
    if account.is_closed:
        raise AccountClosed("账户已注销（INV-03 不可逆）", account_id=str(account_id))
    if account.state != "closing":
        raise StateConflict("只有 closing 账户可执行注销", reason="not_closing",
                            state=account.state)
    if account.closing_deadline is None or account.closing_deadline > moment:
        raise ClosureBlocked("冷静期未满，不可注销", account_id=str(account_id),
                             deadline=account.closing_deadline.isoformat()
                             if account.closing_deadline else None)
    with c.cursor() as cur:
        cur.execute("SELECT id FROM api_keys WHERE account_id = %s AND revoked_at IS NULL",
                    (account_id,))
        key_ids = [r[0] for r in cur.fetchall()]
    for key_id in key_ids:
        models.revoke_api_key(c, key_id, reason="account_closed", now=moment, trace_id=trace_id)
    sessions = models.revoke_live_sessions(c, account_id, reason="account_closed", now=moment,
                                           trace_id=trace_id)
    with c.cursor() as cur:
        cur.execute(
            """SELECT id FROM role_bindings WHERE account_id = %s AND revoked_at IS NULL""",
            (account_id,))
        roles = [r[0] for r in cur.fetchall()]
    for binding_id in roles:
        models.revoke_role(c, binding_id, reason="account_closed", now=moment, trace_id=trace_id)
    purged = models.purge_user_pii(c, account.user_id)
    _, after = transition(
        c, account_id, "closed", reason_code="cooloff_elapsed", now=moment, trace_id=trace_id,
        fields={"closed_at": moment, "pii_purged_at": moment,
                "ledger_unlink_requested_at": moment})
    report = {
        "account_id": str(account.id),
        "tenant_id": str(account.tenant_id),
        "closed_at": moment.isoformat(),
        "api_keys_revoked": len(key_ids),
        "sessions_revoked": sessions,
        "roles_revoked": len(roles),
        "pii_fields_purged": purged,
        # 账本分录不删：只请求去关联（INV-03），由 M06 侧异步执行
        "ledger_unlink_requested": True,
    }
    log.info("identity.account.closed account_id=%s keys=%s sessions=%s",
             account.id, len(key_ids), sessions)
    return report


def run_closing_jobs(c, *, now: datetime | None = None,
                     trace_id: str | None = None) -> list[dict]:
    """冷静期到期 job（可重放）：逐个执行第三步并回收删除报告。"""
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            """SELECT id FROM user_accounts
                WHERE state = 'closing' AND closing_deadline <= %s
                ORDER BY closing_deadline""",
            (moment,))
        ids = [r[0] for r in cur.fetchall()]
    return [finalize_closing(c, account_id, now=moment, trace_id=trace_id) for account_id in ids]


# --------------------------------------------------------------------------- 只读校验
def require_writable(c, account_id: uuid.UUID, *, tenant_id: uuid.UUID | None = None,
                     action: str = "write") -> Account:
    """读账户并断言可写（T2/T3 的写入口统一走这里）。"""
    return models.assert_writable(models.get_account(c, account_id, tenant_id=tenant_id),
                                  action=action)


def require_login_allowed(c, account_id: uuid.UUID, *,
                          tenant_id: uuid.UUID | None = None) -> Account:
    """closed 禁止登录；frozen / closing 允许登录但只读（M01 §3）。"""
    account = models.get_account(c, account_id, tenant_id=tenant_id)
    if account.is_closed:
        raise AccountClosed("账户已注销：禁止登录", account_id=str(account_id))
    if account.state == "pending_verify":
        raise InvalidArgument("账户未验证：禁止登录", reason="account_not_verified")
    return account


__all__ = [
    "TRANSITIONS", "CLOSURE_CHECKS", "can_transition", "legal_targets", "transition",
    "verify", "expire_pending", "freeze", "renew_freeze", "unfreeze", "expire_freeze",
    "check_closure", "precheck_closure", "start_closing", "withdraw_closing",
    "finalize_closing", "run_closing_jobs", "require_writable", "require_login_allowed",
    "IdentityError", "IllegalTransition", "AccountClosed", "AccountReadOnly",
    "ClosureBlocked", "NotFound", "StateConflict",
]
