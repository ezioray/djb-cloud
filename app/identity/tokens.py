# SPDX-License-Identifier: Apache-2.0
"""会话与令牌生命周期（DEV-M01-T2）：登录 / 刷新轮换 / 登出 / 访问鉴权 / step-up。

口径（M01 §1、§6；03-facts §8；spec 1.2.0 `AuthTokens`）：

| 会话 kind | access TTL | 滑动 | 空闲 | 绝对上限 | refresh |
| --- | --- | --- | --- | --- | --- |
| `user` | ≤2 h | 否（固定 2 h） | 否 | 30 天（刷新窗口） | 有，刷新即轮换 |
| `admin` | 30 min | 有（每次访问续 30 min） | 15 min | 12 h | 无 |
| `mfa_pending` | 5 min | 否 | 否 | 5 min | 无（只能换正式令牌） |
| `step_up` | 5 min | 否 | 否 | 5 min | 无（高危动作专用） |

不变量：
- **库里只有哈希**：``access_hash`` / ``refresh_hash`` = sha256(明文)；明文只在响应出现一次。
- **刷新即轮换**：旧 refresh 令牌立即失效；重放旧令牌 → 40103（spec）。
- **刷新不延长绝对过期时间**：轮换出的新会话继承原 ``absolute_expires_at``。
- **登出写 epoch**：``all_devices=true`` 时 ``session_epoch++`` 并撤销全部会话，旧令牌立刻 40102。
- **MFA 未完成只发短期令牌**：kind=mfa_pending 的令牌不能访问业务端点。
- 冻结 / 角色变更 / 注销沿用 T1 的 ``models.invalidate_sessions``（epoch++ + 撤销）。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from . import clock, credentials, errors, models

# M01 §8.2：登录失败锁定 5 次 / 15 分钟；step-up 5 分钟
from .models import (
    ACCESS_TTL_HOURS,
    LOGIN_LOCK_MINUTES,
    MFA_MAX_FAILURES,
    MFA_PENDING_TTL_MINUTES,
    REFRESH_TTL_DAYS,
    SESSION_ABSOLUTE_HOURS,
    SESSION_IDLE_MINUTES,
    SESSION_SLIDE_MINUTES,
    STEP_UP_MINUTES,
    Session,
    SessionInvalid,
    _SESSION_COLS,
    _make,
    _one,
)

LOGIN_METHODS = ("password", "oauth", "sms_code")
SCAN_PROVIDER = "qr"
# 防枚举：账号不存在时也跑一次同代价的口令派生（常数时间无关，等代价即可）
_DUMMY_HASH = "scrypt$n=16384,r=8,p=1$" + "00" * 16 + "$" + "00" * 32


@dataclass(frozen=True)
class LoginResult:
    account: models.Account
    user: models.User
    session: Session | None
    access_token: str | None
    refresh_token: str | None
    mfa_required: bool
    expires_in: int
    refresh_expires_at: datetime | None
    roles: tuple[str, ...]
    scan: dict[str, Any] | None = None


@dataclass(frozen=True)
class AuthContext:
    """调用方身份上下文。

    两条来源：**会话**（T2，``session`` 非空）与 **API Key**（T3 网关鉴权，``session`` 为空、
    ``api_key_id`` 非空）。下游按 ``via`` 判断，不要假设 session 一定存在。
    """

    session: Session | None
    account: models.Account
    user: models.User
    roles: tuple[str, ...]
    step_up_active: bool = False
    api_key_id: int | None = None
    api_key_prefix: str | None = None
    key_overlap: bool = False
    quotas: dict | None = None

    @property
    def via(self) -> str:
        return "api_key" if self.api_key_id is not None else "session"

    @property
    def account_id(self) -> uuid.UUID:
        return self.account.id

    @property
    def tenant_id(self) -> uuid.UUID:
        return self.account.tenant_id


@dataclass(frozen=True)
class StepUpGrant:
    session: Session
    access_token: str
    expires_at: datetime


def _now(now: datetime | None) -> datetime:
    return now.astimezone(clock.utcnow().tzinfo) if now else clock.utcnow()


def _seconds(delta: timedelta) -> int:
    return max(int(delta.total_seconds()), 1)


# --------------------------------------------------------------------------- 会话签发
def _issue_session(c, *, account: models.Account, kind: str, moment: datetime,
                   mfa: bool, access_ttl: timedelta, absolute: datetime,
                   refresh_ttl: timedelta | None = None, client_ip: str | None = None,
                   step_up_until: datetime | None = None) -> tuple[Session, str, str | None]:
    """签发会话 + 两枚令牌（明文返回给调用方，库中只有 sha256）。"""
    access, access_hash = credentials.new_token()
    refresh = refresh_hash = None
    if refresh_ttl is not None:
        refresh, refresh_hash = credentials.new_token()
    if kind == "admin":                       # 后台会话另有 12 h 绝对上限（03-facts §8）
        absolute = min(absolute, moment + timedelta(hours=SESSION_ABSOLUTE_HOURS))
    expires_at = min(moment + access_ttl, absolute)
    idle_until = (moment + timedelta(minutes=SESSION_IDLE_MINUTES)
                  if kind in ("admin", "step_up") else None)
    refresh_expires = min(moment + refresh_ttl, absolute) if refresh_ttl else None
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO sessions
                    (id, account_id, tenant_id, epoch, kind, mfa, created_at, last_seen_at,
                     expires_at, refresh_expires_at, absolute_expires_at, idle_expires_at,
                     access_hash, refresh_hash, step_up_until, client_ip_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING {_SESSION_COLS}""",
            (models.uuid7(), account.id, account.tenant_id, account.session_epoch, kind, mfa,
             moment, moment, expires_at, refresh_expires, absolute, idle_until,
             access_hash, refresh_hash, step_up_until,
             credentials.token_hash(client_ip) if client_ip else None),
        )
        return _make(Session, _one(cur)), access, refresh


def _find_by_access(c, access_token: str) -> Session | None:
    with c.cursor() as cur:
        cur.execute(f"SELECT {_SESSION_COLS} FROM sessions WHERE access_hash = %s",
                    (credentials.token_hash(access_token),))
        row = _one(cur)
    return _make(Session, row) if row else None


def _find_by_refresh(c, refresh_token: str, *, for_update: bool = False) -> Session | None:
    sql = f"SELECT {_SESSION_COLS} FROM sessions WHERE refresh_hash = %s"
    with c.cursor() as cur:
        cur.execute(sql + (" FOR UPDATE" if for_update else ""),
                    (credentials.token_hash(refresh_token),))
        row = _one(cur)
    return _make(Session, row) if row else None


# --------------------------------------------------------------------------- 登录锁定
def _assert_not_locked(auth: models.UserAuth, moment: datetime) -> None:
    locked_until = auth.login_locked_until
    if locked_until is not None and locked_until > moment:
        raise errors.LoginThrottled(
            "登录失败次数过多，请稍后再试", reason="login_locked",
            retry_after_s=_seconds(locked_until - moment))


def register_failure(c, user_id: uuid.UUID, moment: datetime) -> None:
    """失败计数 +1；达到阈值即锁定 15 分钟（M01 §8.2）。

    **必须由调用方在业务事务回滚之后调用**（通常用独立 autocommit 连接）：
    否则回滚会把「失败留痕」一起抹掉，等于给暴力破解开后门。
    :func:`login` 不自己写，而是在异常上带 ``bump_user_id`` 交给路由执行。
    """
    with c.cursor() as cur:
        cur.execute(
            """UPDATE users
                  SET failed_login_count = failed_login_count + 1,
                      login_locked_until = CASE
                        WHEN failed_login_count + 1 >= %s THEN %s
                        ELSE login_locked_until END
                WHERE id = %s""",
            (MFA_MAX_FAILURES, moment + timedelta(minutes=LOGIN_LOCK_MINUTES), user_id))


def _clear_failures(c, user_id: uuid.UUID, moment: datetime) -> None:
    with c.cursor() as cur:
        cur.execute(
            """UPDATE users
                  SET failed_login_count = 0, login_locked_until = NULL, last_login_at = %s
                WHERE id = %s""",
            (moment, user_id))


# --------------------------------------------------------------------------- 登录
def login(c, *, method: str, identifier: str, secret: str | None = None,
          provider: str | None = None, mfa_code: str | None = None,
          client_ip: str | None = None, now: datetime | None = None,
          trace_id: str | None = None) -> LoginResult:
    """登录（password / oauth+qr 扫码轮询 / sms_code 未接入）。"""
    models._check(method, LOGIN_METHODS, "method")
    if not identifier or not identifier.strip():
        raise models.InvalidArgument("identifier 必填", field="identifier")
    moment = _now(now)
    if method == "sms_code":
        raise errors.AuthMethodUnavailable(
            "短信验证码登录未接入（通知通道归 M12）", reason="sms_not_available", method=method)
    if method == "oauth":
        if provider == SCAN_PROVIDER:
            from . import scan                                   # 局部导入避免无谓依赖
            return _scan_login(c, identifier.strip(), now=moment, client_ip=client_ip,
                               trace_id=trace_id)
        raise errors.AuthMethodUnavailable(
            "外部 OAuth 提供方未接入（S1 仅支持扫码）", reason="oauth_not_available",
            provider=provider)

    user = models.find_user_by_identifier(c, identifier)
    if user is None:
        credentials.verify_password(_DUMMY_HASH, secret or "")   # 等代价，防时间侧信道
        raise errors.LoginCredentialError("账号或凭据错误")
    auth = models.get_user_auth(c, user.id, for_update=True)
    _assert_not_locked(auth, moment)
    if not credentials.verify_password(auth.password_hash, secret):
        raise _credential_error("账号或凭据错误", auth.user_id)

    account = models.primary_account(c, user.id)
    if account.is_closed:
        raise models.AccountClosed("账户已注销：禁止登录", account_id=str(account.id))

    mfa_required = auth.mfa_state == "enabled"
    if mfa_required and mfa_code is None:
        # MFA 未完成：只发 5 分钟短期令牌（kind=mfa_pending），不能访问业务端点
        session, access, _ = _issue_session(
            c, account=account, kind="mfa_pending", moment=moment, mfa=False,
            access_ttl=timedelta(minutes=MFA_PENDING_TTL_MINUTES),
            absolute=moment + timedelta(minutes=MFA_PENDING_TTL_MINUTES),
            client_ip=client_ip)
        _clear_failures(c, user.id, moment)
        return LoginResult(account=account, user=user, session=session, access_token=access,
                           refresh_token=None, mfa_required=True,
                           expires_in=_seconds(timedelta(minutes=MFA_PENDING_TTL_MINUTES)),
                           refresh_expires_at=None,
                           roles=_roles(c, account.id, moment))
    if mfa_required and not credentials.verify_factor(auth.mfa_secret_hash, mfa_code):
        raise _credential_error("账号或凭据错误", user.id)

    session, access, refresh = _issue_session(
        c, account=account, kind="user", moment=moment, mfa=mfa_required,
        access_ttl=timedelta(hours=ACCESS_TTL_HOURS),
        absolute=moment + timedelta(days=REFRESH_TTL_DAYS),
        refresh_ttl=timedelta(days=REFRESH_TTL_DAYS), client_ip=client_ip)
    _clear_failures(c, user.id, moment)
    return LoginResult(account=account, user=user, session=session, access_token=access,
                       refresh_token=refresh, mfa_required=False,
                       expires_in=_seconds(timedelta(hours=ACCESS_TTL_HOURS)),
                       refresh_expires_at=session.refresh_expires_at,
                       roles=_roles(c, account.id, moment))


def _credential_error(message: str, user_id: uuid.UUID | None = None,
                      reason: str | None = None) -> errors.LoginCredentialError:
    """构造凭据错误；``bump_user_id`` 提示调用方回滚后补记失败次数（不进响应体）。"""
    exc = errors.LoginCredentialError(message, reason=reason) if reason \
        else errors.LoginCredentialError(message)
    exc.bump_user_id = user_id
    return exc


def _scan_login(c, ticket: str, *, now: datetime, client_ip: str | None,
                trace_id: str | None) -> LoginResult:
    """扫码轮询（spec：复用 /auth/login）：pending/scanned → 202 中间态；confirmed → 换令牌。"""
    from . import scan

    state = scan.poll(c, ticket, now=now)
    if state.status in ("created", "scanned"):
        return LoginResult(account=None, user=None, session=None, access_token=None,
                           refresh_token=None, mfa_required=False, expires_in=0,
                           refresh_expires_at=None, roles=(),
                           scan={"status": state.status,
                                 "expires_at": state.expires_at.isoformat(),
                                 "retry_after_s": state.retry_after_s(now)})
    if state.status in ("expired", "consumed"):
        # 到期 / 已换取：一律 40905（ScanStatus.expired 是终态；不能落到 404）
        raise errors.ScanTicketInvalid(
            f"扫码票据已不可用：{state.status}", status=state.status)
    account = models.get_account(c, state.account_id)
    if account.is_closed:
        raise models.AccountClosed("账户已注销：禁止登录", account_id=str(account.id))
    user = models.get_user(c, account.user_id)
    auth = models.get_user_auth(c, user.id)
    if auth.mfa_state == "enabled":
        raise errors.LoginCredentialError("该账户已启用 MFA：请用密码 + MFA 登录",
                                          reason="mfa_required_for_scan")
    scan.consume(c, ticket, now=now)
    session, access, refresh = _issue_session(
        c, account=account, kind="user", moment=now, mfa=False,
        access_ttl=timedelta(hours=ACCESS_TTL_HOURS),
        absolute=now + timedelta(days=REFRESH_TTL_DAYS),
        refresh_ttl=timedelta(days=REFRESH_TTL_DAYS), client_ip=client_ip)
    _clear_failures(c, user.id, now)
    return LoginResult(account=account, user=user, session=session, access_token=access,
                       refresh_token=refresh, mfa_required=False,
                       expires_in=_seconds(timedelta(hours=ACCESS_TTL_HOURS)),
                       refresh_expires_at=session.refresh_expires_at,
                       roles=_roles(c, account.id, now))


def _roles(c, account_id: uuid.UUID, moment: datetime) -> tuple[str, ...]:
    return tuple(models.effective_roles(c, account_id, now=moment))


# --------------------------------------------------------------------------- 刷新（轮换）
def refresh(c, refresh_token: str, *, client_ip: str | None = None,
            now: datetime | None = None, trace_id: str | None = None) -> LoginResult:
    """刷新即轮换：旧令牌立即失效，新会话继承绝对过期时间（不延长）。"""
    if not refresh_token:
        raise errors.RefreshTokenRejected("缺少 refresh_token")
    moment = _now(now)
    old = _find_by_refresh(c, refresh_token, for_update=True)
    if old is None:
        raise errors.RefreshTokenRejected("刷新令牌无效")
    if old.revoked_at is not None:
        # 重放已轮换的令牌：按 spec 40103 处理，并要求重新登录
        raise errors.RefreshTokenRejected("刷新令牌已轮换或撤销，请重新登录",
                                          revoked_reason=old.revoked_reason)
    if old.refresh_expires_at is None or old.refresh_expires_at <= moment:
        raise SessionInvalid("刷新令牌已过期", session_id=str(old.id), reason="expired")
    if old.absolute_expires_at is not None and old.absolute_expires_at <= moment:
        # pragma: no cover - refresh_expires_at 恒 ≤ absolute_expires_at，先被上面拦下
        raise SessionInvalid("会话已到绝对过期时间", session_id=str(old.id),
                             reason="absolute_expiry")
    account = models.get_account(c, old.account_id, tenant_id=old.tenant_id)
    if account.is_closed:
        raise SessionInvalid("账户已注销", session_id=str(old.id), reason="account_closed")
    if old.epoch != account.session_epoch:
        models.revoke_session(c, old.id, reason="epoch_mismatch", now=moment,
                              trace_id=trace_id)
        raise SessionInvalid("会话 epoch 已失效（角色 / 状态变更）", session_id=str(old.id),
                             reason="epoch_mismatch")

    # 只作废「刷新」这一半：清空 refresh_hash + 记 rotated_at，access 令牌保留到自然过期
    with c.cursor() as cur:
        cur.execute("UPDATE sessions SET rotated_at = %s, refresh_hash = NULL WHERE id = %s",
                    (moment, old.id))
    absolute = old.absolute_expires_at or old.refresh_expires_at
    session, access, new_refresh = _issue_session(
        c, account=account, kind="user", moment=moment, mfa=old.mfa,
        access_ttl=timedelta(hours=ACCESS_TTL_HOURS), absolute=absolute,
        refresh_ttl=timedelta(days=REFRESH_TTL_DAYS), client_ip=client_ip)
    user = models.get_user(c, account.user_id)
    return LoginResult(account=account, user=user, session=session, access_token=access,
                       refresh_token=new_refresh, mfa_required=False,
                       expires_in=_seconds(timedelta(hours=ACCESS_TTL_HOURS)),
                       refresh_expires_at=session.refresh_expires_at,
                       roles=_roles(c, account.id, moment))


# --------------------------------------------------------------------------- 登出
def resolve_session(c, access_token: str) -> Session:
    """按令牌取会话（**不看**撤销 / 过期状态）：仅供幂等登出这类「重放也合法」的场景。"""
    if not access_token:
        raise SessionInvalid("缺少访问令牌", reason="missing_token")
    session = _find_by_access(c, access_token)
    if session is None:
        raise SessionInvalid("令牌无效", reason="unknown_token")
    return session


def logout(c, *, session: Session | None = None, access_token: str | None = None,
           all_devices: bool = False, now: datetime | None = None,
           trace_id: str | None = None) -> tuple[int, datetime]:
    """退出：撤销当前会话；``all_devices`` 时 epoch++ 并撤销全部（幂等）。"""
    moment = _now(now)
    ctx_session = session or resolve_session(c, access_token or "")
    if all_devices:
        revoked = models.invalidate_sessions(c, ctx_session.account_id, reason="logout_all",
                                             now=moment, trace_id=trace_id)
        return revoked, moment
    current = models.get_session(c, ctx_session.id)
    if current.revoked_at is not None:        # 幂等：返回首次撤销时间，不报错
        return 0, current.revoked_at
    models.revoke_session(c, current.id, reason="logout", now=moment, trace_id=trace_id)
    return 1, moment


# --------------------------------------------------------------------------- 鉴权
def authenticate(c, access_token: str, *, now: datetime | None = None,
                 allow_pending: bool = False, touch: bool = True,
                 trace_id: str | None = None) -> AuthContext:
    """校验访问令牌 → 会话 + 账户 + 角色（40102 覆盖：不存在/撤销/过期/空闲/epoch/注销）。"""
    if not access_token:
        raise SessionInvalid("缺少访问令牌", reason="missing_token")
    moment = _now(now)
    session = _find_by_access(c, access_token)
    if session is None:
        raise SessionInvalid("令牌无效", reason="unknown_token")
    if session.revoked_at is not None:
        raise SessionInvalid("会话已撤销", session_id=str(session.id), reason="revoked")
    if session.kind == "mfa_pending" and not allow_pending:
        raise SessionInvalid("MFA 未完成：该令牌只能用于换取正式令牌",
                             session_id=str(session.id), reason="mfa_pending")
    if session.expires_at <= moment:
        raise SessionInvalid("会话已过期", session_id=str(session.id), reason="expired")
    if session.absolute_expires_at is not None and session.absolute_expires_at <= moment:
        # pragma: no cover - expires_at 恒 ≤ absolute_expires_at，此分支是防御性二次校验
        models.revoke_session(c, session.id, reason="absolute_expiry", now=moment,
                              trace_id=trace_id)
        raise SessionInvalid("会话已到绝对过期时间", session_id=str(session.id),
                             reason="absolute_expiry")
    if session.idle_expires_at is not None and session.idle_expires_at <= moment:
        models.revoke_session(c, session.id, reason="idle_timeout", now=moment,
                              trace_id=trace_id)
        raise SessionInvalid("会话空闲超时", session_id=str(session.id), reason="idle_timeout")

    account = models.get_account(c, session.account_id, tenant_id=session.tenant_id)
    if account.is_closed:
        models.revoke_session(c, session.id, reason="account_closed", now=moment,
                              trace_id=trace_id)
        raise SessionInvalid("账户已注销", session_id=str(session.id), reason="account_closed")
    if session.epoch != account.session_epoch:
        models.revoke_session(c, session.id, reason="epoch_mismatch", now=moment,
                              trace_id=trace_id)
        raise SessionInvalid("会话 epoch 已失效（角色 / 状态变更）",
                             session_id=str(session.id), reason="epoch_mismatch")
    user = models.get_user(c, account.user_id)
    if touch:
        session = _touch(c, session, moment)
    step_up_active = session.kind == "step_up" or (
        session.step_up_until is not None and session.step_up_until > moment)
    return AuthContext(session=session, account=account, user=user,
                       roles=_roles(c, account.id, moment), step_up_active=step_up_active)


def _touch(c, session: Session, moment: datetime) -> Session:
    """滑动续期：仅 admin（30 min 滑动）；用户令牌是固定 2 h，不滑动。"""
    idle_until = (moment + timedelta(minutes=SESSION_IDLE_MINUTES)
                  if session.kind in ("admin", "step_up") else None)
    expires = session.expires_at
    if session.kind == "admin":
        absolute = session.absolute_expires_at or (
            session.created_at + timedelta(hours=SESSION_ABSOLUTE_HOURS))
        expires = min(moment + timedelta(minutes=SESSION_SLIDE_MINUTES), absolute)
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE sessions SET last_seen_at = %s, idle_expires_at = %s, expires_at = %s
                 WHERE id = %s RETURNING {_SESSION_COLS}""",
            (moment, idle_until, expires, session.id))
        return _make(Session, _one(cur))


def require_step_up(ctx: AuthContext, *, now: datetime | None = None) -> AuthContext:
    """高危动作闸门（供 T4 复用）：不在 step-up 窗口内一律 424 / 42401。"""
    moment = _now(now)
    if ctx.session is None:                       # Key 鉴权没有会话，不能承载 step-up
        raise errors.StepUpRequired("API Key 方式不支持 step-up，请用会话 + MFA")
    if not ctx.step_up_active:
        raise errors.StepUpRequired("需要二次认证（step-up ≤5 分钟）")
    if ctx.session.step_up_until is not None and ctx.session.step_up_until <= moment:
        raise errors.StepUpRequired("二次认证已过期，请重新验证")
    return ctx


# --------------------------------------------------------------------------- step-up
def step_up(c, *, access_token: str, code: str, now: datetime | None = None,
            client_ip: str | None = None, trace_id: str | None = None) -> StepUpGrant:
    """二次认证：校验 MFA 因子，签发 5 分钟 step_up 会话，并在源会话上打 step_up 窗口。"""
    moment = _now(now)
    ctx = authenticate(c, access_token, now=moment, allow_pending=True, trace_id=trace_id)
    auth = models.get_user_auth(c, ctx.user.id)
    if auth.mfa_state != "enabled":
        raise errors.MfaNotEnabled("账户未启用 MFA，无法 step-up")
    _assert_not_locked(auth, moment)
    if not credentials.verify_factor(auth.mfa_secret_hash, code):
        raise _credential_error("二次认证码错误", auth.user_id, reason="invalid_mfa_code")
    until = moment + timedelta(minutes=STEP_UP_MINUTES)
    with c.cursor() as cur:
        cur.execute("UPDATE sessions SET step_up_until = %s WHERE id = %s",
                    (until, ctx.session.id))
    session, access, _ = _issue_session(
        c, account=ctx.account, kind="step_up", moment=moment, mfa=True,
        access_ttl=timedelta(minutes=STEP_UP_MINUTES), absolute=until,
        client_ip=client_ip, step_up_until=until)
    _clear_failures(c, ctx.user.id, moment)
    return StepUpGrant(session=session, access_token=access, expires_at=until)


def expire_idle(c, *, now: datetime | None = None, trace_id: str | None = None) -> int:
    """空闲 / 绝对到期回收 job（可重放）：撤销到点的会话，返回条数。"""
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            """SELECT id FROM sessions
                WHERE revoked_at IS NULL
                  AND ((idle_expires_at IS NOT NULL AND idle_expires_at <= %s)
                    OR (absolute_expires_at IS NOT NULL AND absolute_expires_at <= %s)
                    OR (expires_at <= %s AND kind <> 'user'))
                ORDER BY created_at""",
            (moment, moment, moment))
        ids = [r[0] for r in cur.fetchall()]
    for session_id in ids:
        models.revoke_session(c, session_id, reason="expired", now=moment, trace_id=trace_id)
    return len(ids)


__all__ = [
    "LOGIN_METHODS", "SCAN_PROVIDER", "LoginResult", "AuthContext",
    "StepUpGrant", "login", "refresh", "logout", "authenticate", "resolve_session",
    "require_step_up", "step_up", "expire_idle", "register_failure",
]
