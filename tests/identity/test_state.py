# SPDX-License-Identifier: Apache-2.0
"""账户五态机 / 冻结期限 / 注销三步（DEV-M01-T1 验收 2）。

覆盖：
- **全部 25 个 (from, to) 组合**：登记的边必须能走通，未登记的边必须 40903；
- 冻结：缺 ``frozen_until``（A1）、超 180 天、过去时间、缺审批链、缺操作者、续期规则、
  解冻人 = 冻结人（40902）、到期 job 重放只产生一条事件（A2）；
- 注销三步：四项前置（40906 + 清单）、closing 只读、撤回、冷静期未满、正式注销、closed 不可逆；
- 状态迁移一定落 ``account.state.changed``，且每次迁移的 ``from/to`` 与实际一致。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import psycopg
import pytest

from app.identity import models, state

from conftest import (
    account_state,
    all_events,
    backdate_account,
    rows,
    scalar,
    state_events,
)

CLEAN = {"locked_earnings": True, "open_disputes": True, "negative_balance": True,
         "open_tickets": True}


# --------------------------------------------------------------------------- 构造到指定状态
def _to_state(f, target: str) -> models.Account:
    """把新账户推到目标状态（只用于准备夹具，走的仍是合法边）。"""
    account = f.normal()
    if target == "normal":
        return account
    if target == "pending_verify":
        return f.account()
    if target == "frozen":
        return f.freeze(account)
    if target == "closing":
        return state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)
    if target == "closed":
        state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)
        state.finalize_closing(f.conn, account.id, now=f.moment + timedelta(days=30))
        return models.get_account(f.conn, account.id)
    raise AssertionError(target)


LEGAL_EDGES = sorted((src, dst) for src, targets in state.TRANSITIONS.items() for dst in targets)
ALL_PAIRS = sorted((src, dst) for src in models.ACCOUNT_STATES for dst in models.ACCOUNT_STATES)


def test_transition_table_is_a_closed_set():
    assert set(state.TRANSITIONS) == set(models.ACCOUNT_STATES)
    for src, targets in state.TRANSITIONS.items():
        assert targets <= set(models.ACCOUNT_STATES), f"{src} 指向了未登记状态"
    assert state.TRANSITIONS["closed"] == frozenset()
    assert state.legal_targets("closed") == ()
    assert state.can_transition("normal", "frozen") and not state.can_transition("closed", "normal")


@pytest.mark.parametrize("src,dst", ALL_PAIRS)
def test_every_pair_is_either_legal_or_rejected(f, src, dst):
    """25 个组合全覆盖：登记的边走通并落事件，未登记的一律 40903 且状态不变。"""
    account = _to_state(f, src)
    assert account_state(f.conn, account.id) == src
    legal = state.can_transition(src, dst)

    if dst == "frozen":
        fields = {"frozen_until": f.moment + timedelta(days=1), "frozen_reason": "r",
                  "frozen_by": uuid.uuid4(), "frozen_approval": [{"a": 1}]}
    elif dst == "closing":
        fields = {"closing_deadline": f.moment + timedelta(days=30)}
    elif src == "frozen":
        fields = {"frozen_until": None, "frozen_reason": None, "frozen_by": None,
                  "frozen_approval": None}
    elif src == "closing" and dst == "normal":
        fields = {"closing_deadline": None}
    elif dst == "closed":
        fields = {"closed_at": f.moment}
    else:
        fields = {}

    if legal:
        before, after = state.transition(f.conn, account.id, dst, reason_code="test_edge",
                                        fields=fields, now=f.moment)
        assert (before.state, after.state) == (src, dst)
        assert account_state(f.conn, account.id) == dst
        events = state_events(f.conn, account.id)
        assert events[-1]["payload"]["from"] == src
        assert events[-1]["payload"]["to"] == dst
    else:
        with pytest.raises(state.IllegalTransition) as exc:
            state.transition(f.conn, account.id, dst, reason_code="test_edge",
                             fields=fields, now=f.moment)
        assert exc.value.status_code == 409
        assert exc.value.code == "40903"
        assert account_state(f.conn, account.id) == src, "非法迁移不得落库"


def test_legal_edges_count_is_the_spec_graph():
    assert LEGAL_EDGES == [
        ("closing", "closed"), ("closing", "normal"),
        ("frozen", "closing"), ("frozen", "normal"),
        ("normal", "closing"), ("normal", "frozen"),
        ("pending_verify", "closed"), ("pending_verify", "normal"),
    ]


def test_noop_transition_is_rejected(f):
    account = f.normal()
    with pytest.raises(state.IllegalTransition) as exc:
        state.transition(f.conn, account.id, "normal", reason_code="again", now=f.moment)
    assert exc.value.reason == "noop_transition"
    assert len(state_events(f.conn, account.id)) == 1, "noop 不得新增事件"


# --------------------------------------------------------------------------- 注册 / 验证
def test_registration_then_verify(f):
    account = f.account()
    assert account.state == "pending_verify"
    assert account.tenant_id == account.id, "personal 租户 1:1（INV-01）"
    assert [e["type"] for e in all_events(f.conn)] == ["account.created"]
    # 注册事务内落租户配额主体（M01 §6.1）
    assert models.quota_snapshot(f.conn, account.tenant_id)["effective"] == {"qps": 3}

    verified = state.verify(f.conn, account.id, now=f.moment)
    assert verified.state == "normal"
    assert state_events(f.conn, account.id)[0]["payload"]["reason_code"] == "email_verified"


def test_verify_twice_is_rejected(f):
    account = f.normal()
    with pytest.raises(state.IllegalTransition):
        state.verify(f.conn, account.id, now=f.moment)


def test_pending_verify_cannot_write(f):
    account = f.account()
    with pytest.raises(models.InvalidArgument) as exc:
        models.create_api_key(f.conn, account_id=account.id, now=f.moment)
    assert exc.value.code == "40001"


def test_expire_pending_closes_and_purges(f):
    account = f.account()
    backdate_account(f.conn, account.id, days=8)
    closed = state.expire_pending(f.conn, now=f.moment)
    assert closed == [account.id]
    after = models.get_account(f.conn, account.id)
    assert after.state == "closed" and after.pii_purged_at is not None
    assert models.get_user(f.conn, account.user_id).email_hash is None
    assert state.expire_pending(f.conn, now=f.moment) == []          # 重放无副作用


def test_expire_pending_skips_fresh_accounts(f):
    account = f.account()
    assert state.expire_pending(f.conn, now=f.moment) == []
    assert account_state(f.conn, account.id) == "pending_verify"


# --------------------------------------------------------------------------- 冻结
def test_freeze_requires_frozen_until(f):
    """A1：冻结不填 frozen_until → 40001，且不落 frozen 记录。"""
    account = f.normal()
    with pytest.raises(models.InvalidArgument) as exc:
        state.freeze(f.conn, account.id, until=None, reason="risk",
                     approval_chain=[{"approver": "a"}], actor_id=uuid.uuid4(), now=f.moment)
    assert exc.value.code == "40001"
    assert account_state(f.conn, account.id) == "normal"
    assert scalar(f.conn, "SELECT count(*) FROM user_accounts WHERE frozen_until IS NOT NULL") == 0
    assert len(state_events(f.conn, account.id)) == 1, "冻结被拒时不得新增事件（只有 verify 那条）"


@pytest.mark.parametrize("days", [0, -1, 181, 400])
def test_freeze_window_bounds(f, days):
    account = f.normal()
    with pytest.raises(models.InvalidArgument) as exc:
        state.freeze(f.conn, account.id, until=f.moment + timedelta(days=days), reason="risk",
                     approval_chain=[{"approver": "a"}], actor_id=uuid.uuid4(), now=f.moment)
    assert exc.value.code == "40001"
    assert account_state(f.conn, account.id) == "normal"


def test_freeze_boundary_180_days_is_allowed(f):
    account = f.normal()
    frozen = f.freeze(account, days=180)
    assert frozen.state == "frozen"
    assert frozen.frozen_until == f.moment + timedelta(days=180)
    assert frozen.frozen_reason and frozen.frozen_by is not None and frozen.frozen_approval


def test_freeze_requires_reason_approval_and_actor(f):
    account = f.normal()
    cases = [
        dict(until=f.moment + timedelta(days=1), reason="  ", approval_chain=[{"a": 1}],
             actor_id=uuid.uuid4()),
        dict(until=f.moment + timedelta(days=1), reason="risk", approval_chain=[],
             actor_id=uuid.uuid4()),
        dict(until=f.moment + timedelta(days=1), reason="risk", approval_chain=[{"a": 1}],
             actor_id=None),
    ]
    for kwargs in cases:
        with pytest.raises(models.InvalidArgument) as exc:
            state.freeze(f.conn, account.id, now=f.moment, **kwargs)
        assert exc.value.code == "40001"
    assert account_state(f.conn, account.id) == "normal"


def test_freeze_requires_aware_datetime(f):
    account = f.normal()
    naive = (f.moment + timedelta(days=1)).replace(tzinfo=None)
    with pytest.raises(models.InvalidArgument):
        state.freeze(f.conn, account.id, until=naive, reason="risk",
                     approval_chain=[{"a": 1}], actor_id=uuid.uuid4(), now=f.moment)


def test_freeze_from_pending_verify_is_illegal(f):
    account = f.account()
    with pytest.raises(state.IllegalTransition):
        f.freeze(account)
    assert account_state(f.conn, account.id) == "pending_verify"


def test_freeze_twice_needs_renewal_path(f):
    account = f.freeze(f.normal())
    with pytest.raises(models.StateConflict) as exc:
        f.freeze(account, days=3)
    assert exc.value.reason == "already_frozen"


def test_renew_freeze_extends_and_logs(f):
    account = f.freeze(f.normal(), days=7)
    renewed = state.renew_freeze(f.conn, account.id, until=f.moment + timedelta(days=30),
                                 reason="case_escalated",
                                 approval_chain=[{"approver": "risk-2", "at": "t1"}],
                                 actor_id=uuid.uuid4(), now=f.moment)
    assert renewed.frozen_until == f.moment + timedelta(days=30)
    assert state_events(f.conn, account.id)[-1]["payload"]["reason_code"] == "freeze_renewed"


def test_renew_freeze_rejects_shorter_or_missing_approval(f):
    account = f.freeze(f.normal(), days=30)
    with pytest.raises(models.InvalidArgument):
        state.renew_freeze(f.conn, account.id, until=f.moment + timedelta(days=10),
                           reason="shorter", approval_chain=[{"a": 1}], now=f.moment)
    with pytest.raises(models.InvalidArgument):
        state.renew_freeze(f.conn, account.id, until=f.moment + timedelta(days=40),
                           reason="no chain", approval_chain=None, now=f.moment)
    with pytest.raises(models.StateConflict):
        state.renew_freeze(f.conn, f.normal().id, until=f.moment + timedelta(days=40),
                           reason="not frozen", approval_chain=[{"a": 1}], now=f.moment)


def test_unfreeze_by_freezer_is_rejected(f):
    freezer = uuid.uuid4()
    account = f.freeze(f.normal(), actor_id=freezer)
    with pytest.raises(models.StateConflict) as exc:
        state.unfreeze(f.conn, account.id, approver_id=freezer, reason="appeal_ok",
                       now=f.moment)
    assert exc.value.code == "40902"
    assert account_state(f.conn, account.id) == "frozen"


def test_unfreeze_clears_frozen_fields_and_logs(f):
    account = f.freeze(f.normal())
    thawed = state.unfreeze(f.conn, account.id, approver_id=uuid.uuid4(),
                            reason="appeal_approved", now=f.moment)
    assert thawed.state == "normal"
    assert (thawed.frozen_until, thawed.frozen_reason, thawed.frozen_by,
            thawed.frozen_approval) == (None, None, None, None)
    assert state_events(f.conn, account.id)[-1]["payload"]["reason_code"] == "manual_unfreeze"
    with pytest.raises(models.StateConflict):
        state.unfreeze(f.conn, account.id, approver_id=uuid.uuid4(), reason="again",
                       now=f.moment)


def test_unfreeze_requires_approver(f):
    account = f.freeze(f.normal())
    with pytest.raises(models.InvalidArgument):
        state.unfreeze(f.conn, account.id, approver_id=None, reason="x", now=f.moment)


def test_expire_freeze_job_is_replayable(f):
    """A2：到期解冻 job 重放两次 → 只产生一次 account.state.changed。"""
    first = f.freeze(f.normal(), days=1)
    second = f.freeze(f.normal(), days=2)
    later = f.moment + timedelta(days=3)

    assert sorted(state.expire_freeze(f.conn, now=later)) == sorted([first.id, second.id])
    assert state.expire_freeze(f.conn, now=later) == []
    assert state.expire_freeze(f.conn, now=later + timedelta(days=1)) == []

    assert account_state(f.conn, first.id) == "normal"
    assert len(state_events(f.conn, first.id)) == 3           # verify + frozen + expired
    expired = [e for e in state_events(f.conn, first.id)
               if e["payload"]["reason_code"] == "freeze_expired"]
    assert len(expired) == 1
    assert int(scalar(f.conn, "SELECT count(*) FROM identity_outbox"
                              " WHERE idempotency_key LIKE %s",
                      (f"%{first.id}%freeze_expired%",))) == 1


def test_expire_freeze_ignores_unexpired(f):
    account = f.freeze(f.normal(), days=30)
    assert state.expire_freeze(f.conn, now=f.moment + timedelta(days=29)) == []
    assert account_state(f.conn, account.id) == "frozen"


def test_freeze_invalidates_sessions(f):
    """M01 §6.3：冻结即 session_epoch++ 且撤销活跃会话。"""
    account = f.normal()
    session = f.session(account)
    frozen = f.freeze(account)
    assert frozen.session_epoch == account.session_epoch + 1
    with pytest.raises(models.SessionInvalid) as exc:
        models.validate_session(f.conn, session.id, now=f.moment)
    assert exc.value.code == "40102"
    assert models.get_session(f.conn, session.id).revoked_at is not None


# --------------------------------------------------------------------------- 注销三步
def test_closure_precheck_lists_all_unmet_items(f):
    account = f.normal()
    # 检查项本身缺失属调用方 bug → 40001（不是 40906）
    with pytest.raises(models.InvalidArgument) as exc:
        state.start_closing(f.conn, account.id, checks={}, now=f.moment)
    assert exc.value.code == "40001"
    assert exc.value.reason == "closure_checks_incomplete"

    with pytest.raises(models.ClosureBlocked) as exc:
        state.start_closing(f.conn, account.id,
                            checks={"locked_earnings": False, "open_disputes": False,
                                    "negative_balance": True, "open_tickets": False},
                            now=f.moment)
    assert exc.value.code == "40906"
    assert [item["item"] for item in exc.value.details["unmet"]] == [
        "locked_earnings", "open_disputes", "open_tickets"]
    assert account_state(f.conn, account.id) == "normal", "前置未清不得进入 closing"


def test_closing_flow_is_read_only_and_reversible(f):
    account = f.normal()
    closing = state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)
    assert closing.state == "closing"
    assert closing.closing_deadline == f.moment + timedelta(days=30)

    # closing 只读：建 Key 40304，登录仍可（只读 + 可撤回）
    with pytest.raises(models.AccountReadOnly) as exc:
        models.create_api_key(f.conn, account_id=account.id, now=f.moment)
    assert exc.value.code == "40304"
    assert models.create_session(f.conn, account_id=account.id, now=f.moment).epoch == 1

    # 冷静期内不可注销
    with pytest.raises(models.ClosureBlocked):
        state.finalize_closing(f.conn, account.id, now=f.moment + timedelta(days=29))

    # 撤回 → normal（可写）
    back = state.withdraw_closing(f.conn, account.id, now=f.moment + timedelta(days=1))
    assert back.state == "normal" and back.closing_deadline is None
    models.create_api_key(f.conn, account_id=account.id, now=f.moment)


def test_closing_from_frozen_is_allowed_and_clears_freeze(f):
    account = f.freeze(f.normal())
    closing = state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)
    assert closing.state == "closing"
    assert closing.frozen_until is None and closing.frozen_reason is None


def test_finalize_closing_two_steps_and_report(f):
    """注销三步：结清 → closing → 30 天后删 PII / 撤销 Key 与会话 / 请求账本去关联 → closed。"""
    account = f.normal()
    key, _plaintext = f.key(account)
    models.bind_role(f.conn, account_id=account.id, admin_role="OPS",
                     granted_by=uuid.uuid4(), approved_by=uuid.uuid4(), now=f.moment)
    state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)
    session = f.session(account)          # closing 只读但仍可登录（可撤回）

    report = state.finalize_closing(f.conn, account.id, now=f.moment + timedelta(days=30))
    after = models.get_account(f.conn, account.id)

    assert after.state == "closed" and after.closed_at is not None
    assert after.pii_purged_at is not None and after.ledger_unlink_requested_at is not None
    assert models.get_user(f.conn, account.user_id).email_hash is None
    assert models.get_api_key(f.conn, key.id).revoked_at is not None
    assert models.get_session(f.conn, session.id).revoked_at is not None
    assert models.effective_roles(f.conn, account.id, now=f.moment) == []
    assert report["account_id"] == str(account.id)
    assert report["api_keys_revoked"] == 1
    assert report["sessions_revoked"] == 1
    assert report["roles_revoked"] == 1
    assert report["ledger_unlink_requested"] is True
    assert state_events(f.conn, account.id)[-1]["payload"]["to"] == "closed"


def test_closed_is_irreversible(f):
    account = f.normal()
    state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)
    state.finalize_closing(f.conn, account.id, now=f.moment + timedelta(days=30))

    for target in ("normal", "frozen", "closing", "pending_verify"):
        with pytest.raises(state.AccountClosed) as exc:
            state.transition(f.conn, account.id, target, reason_code="try", now=f.moment)
        assert exc.value.code == "40903"
    assert account_state(f.conn, account.id) == "closed"
    with pytest.raises(models.AccountClosed):
        state.finalize_closing(f.conn, account.id, now=f.moment + timedelta(days=60))
    with pytest.raises(models.AccountClosed):
        state.precheck_closure(f.conn, account.id, checks=CLEAN)
    with pytest.raises(models.AccountClosed) as exc:
        state.require_login_allowed(f.conn, account.id)
    assert exc.value.code == "40903"


def test_run_closing_jobs_collects_reports(f):
    due = f.normal()
    not_due = f.normal()
    state.start_closing(f.conn, due.id, checks=CLEAN, now=f.moment)
    state.start_closing(f.conn, not_due.id, checks=CLEAN, now=f.moment + timedelta(days=10))

    reports = state.run_closing_jobs(f.conn, now=f.moment + timedelta(days=31))
    assert [r["account_id"] for r in reports] == [str(due.id)]
    assert account_state(f.conn, due.id) == "closed"
    assert account_state(f.conn, not_due.id) == "closing"
    assert state.run_closing_jobs(f.conn, now=f.moment + timedelta(days=31)) == []


def test_start_closing_from_pending_or_closing_is_illegal(f):
    pending = f.account()
    with pytest.raises(state.IllegalTransition):
        state.start_closing(f.conn, pending.id, checks=CLEAN, now=f.moment)

    account = f.normal()
    state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)
    with pytest.raises(state.IllegalTransition):
        state.start_closing(f.conn, account.id, checks=CLEAN, now=f.moment)


def test_withdraw_closing_from_normal_is_illegal(f):
    account = f.normal()
    with pytest.raises(state.IllegalTransition):
        state.withdraw_closing(f.conn, account.id, now=f.moment)


def test_require_writable_and_login_gates(f):
    frozen = f.freeze(f.normal())
    with pytest.raises(models.AccountReadOnly):
        state.require_writable(f.conn, frozen.id)
    assert state.require_login_allowed(f.conn, frozen.id).state == "frozen"

    pending = f.account()
    with pytest.raises(models.InvalidArgument):
        state.require_login_allowed(f.conn, pending.id)
    with pytest.raises(models.InvalidArgument):
        state.require_writable(f.conn, pending.id)

    normal = f.normal()
    assert state.require_writable(f.conn, normal.id).state == "normal"


def test_transition_respects_tenant_isolation(f):
    account = f.normal()
    other_tenant = uuid.uuid4()
    with pytest.raises(models.NotFound) as exc:
        state.transition(f.conn, account.id, "frozen", reason_code="x",
                         tenant_id=other_tenant, now=f.moment)
    assert exc.value.code == "40401"


def test_fields_cannot_override_state(f):
    account = f.normal()
    with pytest.raises(models.InvalidArgument):
        state.transition(f.conn, account.id, "frozen", reason_code="x",
                         fields={"state": "closed"}, now=f.moment)


def test_transition_unknown_state_name(f):
    account = f.normal()
    with pytest.raises(models.InvalidArgument):
        state.transition(f.conn, account.id, "suspended", reason_code="x", now=f.moment)


def test_transition_reason_code_required(f):
    account = f.normal()
    with pytest.raises(models.InvalidArgument):
        state.transition(f.conn, account.id, "frozen", reason_code="   ", now=f.moment)


def test_events_carry_frozen_until(f):
    account = f.freeze(f.normal(), days=5)
    event = state_events(f.conn, account.id)[-1]
    assert datetime.fromisoformat(event["payload"]["frozen_until"]) == \
        f.moment + timedelta(days=5)
    assert event["type"] == "account.state.changed"


def test_state_event_payload_has_no_pii(f):
    account = f.freeze(f.normal())
    payloads = [e["payload"] for e in rows(f.conn, "SELECT payload FROM identity_outbox")]
    blob = str(payloads)
    assert "example.com" not in blob and "@" not in blob
