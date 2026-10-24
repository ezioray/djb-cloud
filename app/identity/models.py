# SPDX-License-Identifier: AGPL-3.0-or-later
"""M01 identity-tenant · 领域模型与唯一写入口（DEV-M01-T1）。

范围（M01 §10.1 T1）：**只做模型 + 迁移 + 状态机**；登录 / 会话端点 / API 在 T2 起，
因此本包不 import ``app.api``，也不提供任何 HTTP 处理函数。

铁律（本模块自检）：
- **不跨模块**：只 import 标准库与 ``psycopg``，不 import 任何其它 ``app.*`` 模块，
  不读 M06 / M10 基表（余额、配置一律由调用方通过内部只读 API 传入）。
- **不存明文**：Key 只存 ``sha256`` 与 8 位前缀（INV-04）；邮箱 / 手机只存不可逆哈希。
- **一份事实一个来源**：所有业务数字集中在下面的常量块，逐条标注 03-facts / M01 §8 出处；
  ``contracts/facts.yaml`` 生成器（DEV-W0-QA-01）落地后整块替换为生成产物。

八张表（01-ownership §2）：users · user_accounts · orgs · org_members ·
api_keys（在 002 存量表上只加列）· sessions · role_bindings · tenant_quotas；
另有本模块自有 outbox ``identity_outbox``（01-ownership §2「每个模块自己的 outbox」）。

连接由调用方传入（``c`` = psycopg 连接，事务边界在调用方），本模块不自己开事务。
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from . import credentials

# --------------------------------------------------------------------------- 常量
# 两类常量，出处不同，不能混：
#   (1) **facts 派生**（03-facts §8）：五态、冻结上限、冷静期、八角色、会话 TTL、step-up。
#       CR-4 起统一从 contracts/facts.yaml 读取（app/identity/facts.py），代码里不再写字面量。
#   (2) **本模块常量**（M01 §8.1 / §8.2）：03-facts §13.4 明确不覆盖单模块内部算法常量，
#       故仍留在本文件，逐条标注出处。
from .facts import (                       # noqa: E402  (常量块紧随其后，便于对照阅读)
    ACCOUNT_STATES,
    ADMIN_ROLES,
    CLOSING_COOLOFF_DAYS,
    FREEZE_MAX_DAYS,
    SESSION_ABSOLUTE_HOURS,
    SESSION_IDLE_MINUTES,
    SESSION_SLIDE_MINUTES,
    STEP_UP_MINUTES,
)

ACCOUNT_TYPES = ("personal", "team", "enterprise")
ORG_TYPES = ("team", "enterprise")
ORG_STATES = ("active", "closing", "closed")
ORG_ROLES = ("owner", "admin", "operator", "billing")
MEMBER_STATES = ("invited", "active", "removed")
ROLE_SCOPES = ("platform", "tenant")
QUOTA_KINDS = ("qps", "daily_usd_minor", "concurrency")
MFA_STATES = ("none", "pending", "enabled")
# T2 新增两种会话：mfa_pending（MFA 未完成的短期令牌）/ step_up（二次认证 5 分钟）
SESSION_KINDS = ("user", "admin", "mfa_pending", "step_up")

PENDING_VERIFY_TTL_DAYS = 7                # M01 §3：7 天未验证 → 清理
INVITE_TTL_HOURS = 72                      # M01 §8.2：邀请令牌一次性 ≤72 h
ROLE_RECLAIM_DAYS = 90                     # M01 §8.2：角色 90 天自动回收
KEY_PREFIX_LEN = 8                         # M01 §8.2：Key 前缀 8 位（仅展示 / 排障）
KEY_MAX_PER_ACCOUNT = 10                   # M01 §8.1：identity.max_keys_per_account 默认 10
KEY_ENTROPY_BYTES = 32                     # M01 §6.2：256 bit
ROTATE_MAX_OVERLAP_SECONDS = 86_400         # spec 1.2.1：轮换重叠期 ≤24 h
DEFAULT_QPS = 3                            # M01 §8.1：quota.default_qps 默认 3
ACCESS_TTL_HOURS = 2                       # M01 §1：访问令牌 ≤2 h
REFRESH_TTL_DAYS = 30                      # M01 §1：刷新令牌 ≤30 天
SEATS = {"personal": 1, "team": 20, "enterprise": 200}   # M01 §1：席位上限
OWNER_TRANSFER_COOLDOWN_HOURS = 24         # INV-05：owner 转让 24 h 冷却
PII_PEPPER_ENV = "DJB_IDENTITY_PII_PEPPER"  # 密钥引用（09 安全）：不写死、不入库
MFA_PIN_MIN_DIGITS = 6                     # M01 §8.2：二次认证码位数（S1 用固定 6 位 PIN）
MFA_MAX_FAILURES = 5                       # M01 §8.2：登录失败锁定 5 次 / 15 分钟
LOGIN_LOCK_MINUTES = 15                    # M01 §8.2：锁定时长
SCAN_TICKET_TTL_SECONDS = 120              # M01 §8.2：扫码中间态 120 s
MFA_PENDING_TTL_MINUTES = 5                 # M01 §8.2：step-up ≤5 分钟（MFA 未完成短期令牌同口径）
TOKEN_ENTROPY_BYTES = 32                   # 不透明令牌 256 bit（M01 §6.2 同口径）

# 可写操作（建 Key / 充值 / 接新单）只允许 normal（M01 §3）
WRITABLE_STATES = frozenset({"normal"})
# 只读 + 可申诉 / 可撤回：这些状态仍然允许读自己与申诉
READ_ONLY_STATES = frozenset({"frozen", "closing"})

log = logging.getLogger("djb.identity")


# --------------------------------------------------------------------------- 错误
class IdentityError(Exception):
    """领域错误。``status_code`` / ``code`` 直接对应 M01 §4.1 与 00-conventions §5 的码段。"""

    status_code = 400
    code = "40001"
    reason = "identity_error"

    def __init__(self, message: str, *, reason: str | None = None, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        if reason is not None:
            self.reason = reason
        self.details = details

    def as_dict(self) -> dict:
        """错误信封的 error 段（00-conventions §5：{error:{type, code, message, request_id}}）。"""
        return {"type": type(self).__name__, "code": self.code, "message": self.message,
                "reason": self.reason, **self.details}


class NotFound(IdentityError):
    """对象不存在 / 跨租户不可见：一律 40401，不泄露存在性（A6、M07 CR-2 口径）。"""

    status_code = 404
    code = "40401"
    reason = "not_found"


class InvalidArgument(IdentityError):
    """字段取值不合法（枚举越界、空白理由、负值等）。"""

    status_code = 400
    code = "40001"


class AccountReadOnly(IdentityError):
    """账户只读：frozen / closing（M01 §7：40304 + 可读动作清单）。"""

    status_code = 403
    code = "40304"
    reason = "account_read_only"


class StateConflict(IdentityError):
    """状态冲突（重复绑定、席位已满、Key 数上限、双人复核不足等）。"""

    status_code = 409
    code = "40902"
    reason = "state_conflict"


class AccountClosed(IdentityError):
    """closed 不可逆（INV-03）。"""

    status_code = 409
    code = "40903"
    reason = "account_closed"


class IllegalTransition(AccountClosed):
    """五态机非法迁移（INV-03；未登记的有向边一律拒绝）。"""

    reason = "illegal_transition"


class KeyLimitReached(StateConflict):
    reason = "key_limit_reached"


class ApiKeyInvalid(IdentityError):
    """Key 哈希未命中或已撤销（M01 §7：40101）。"""

    status_code = 401
    code = "40101"
    reason = "api_key_invalid"


class SessionInvalid(IdentityError):
    """令牌过期 / 已撤销 / epoch 不符（M01 §7、A4：40102）。"""

    status_code = 401
    code = "40102"
    reason = "session_invalid"


class ClosureBlocked(IdentityError):
    """注销前置未结清（INV-08：40906 + 未结项清单）；冷静期未满同码。"""

    status_code = 409
    code = "40906"
    reason = "closure_blocked"


class InviteInvalid(IdentityError):
    """邀请令牌无效 / 过期 / 已用（INV-08、40905）。"""

    status_code = 409
    code = "40905"
    reason = "invite_invalid"


class QuotaSnapshotMissing(IdentityError):
    """配额快照缺失或 policy_version 不一致：不得计费（INV-07、40907）。"""

    status_code = 409
    code = "40907"
    reason = "quota_snapshot_missing"


# --------------------------------------------------------------------------- ID 与哈希
def uuid7(now_ns: int | None = None) -> uuid.UUID:
    """UUIDv7（00-conventions §2：内部主键时间有序）。

    PG15 没有 ``uuidv7()``（PG18 才有），故在 Python 侧生成：
    48 bit 毫秒时间戳 | 4 bit 版本 7 | 12 bit rand_a | 2 bit 变体 10 | 62 bit rand_b。
    """
    millis = (time.time_ns() if now_ns is None else now_ns) // 1_000_000
    rand = secrets.randbits(74)
    value = ((millis & ((1 << 48) - 1)) << 80) | (0x7 << 76) \
        | (((rand >> 62) & 0x0FFF) << 64) | (0b10 << 62) | (rand & ((1 << 62) - 1))
    return uuid.UUID(int=value)


def hash_secret(plaintext: str) -> str:
    """``sha256`` 十六进制：Key 与邀请令牌的唯一入库形态（INV-04）。"""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def hash_pii(value: str, *, pepper: str | None = None) -> str:
    """邮箱 / 手机的不可逆哈希（M01 §3 email_hash）。

    归一化后哈希；若部署侧注入了 ``DJB_IDENTITY_PII_PEPPER``（密钥引用，不进库）则用
    HMAC-SHA256，防止离线彩虹表反查。未注入时退化为 sha256（单测 / CI 确定性）。
    """
    normalized = value.strip().lower()
    key = pepper if pepper is not None else os.environ.get(PII_PEPPER_ENV)
    if key:
        return hmac.new(key.encode("utf-8"), normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return hash_secret(normalized)


def generate_api_key() -> tuple[str, str, str]:
    """生成 Key：返回 ``(明文, 前缀, sha256)``。明文只允许出现在创建 / 轮换响应里一次。"""
    plaintext = secrets.token_urlsafe(KEY_ENTROPY_BYTES)
    return plaintext, plaintext[:KEY_PREFIX_LEN], hash_secret(plaintext)


# --------------------------------------------------------------------------- 行 → 对象
def _make(cls: type, row: Mapping[str, Any]):
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in row.items() if k in names})


def _now(now: datetime | None = None) -> datetime:
    return now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)


def _row_dict(cur, row) -> dict:
    """把一行统一成 dict：兼容默认 tuple 行与调用方自带的 dict 行工厂。"""
    if isinstance(row, Mapping):
        return dict(row)
    return dict(zip([d.name for d in cur.description], row))


def _rows(cur) -> list[dict]:
    return [_row_dict(cur, r) for r in cur.fetchall()]


def _one(cur) -> dict | None:
    row = cur.fetchone()
    return None if row is None else _row_dict(cur, row)


@dataclasses.dataclass(frozen=True)
class User:
    id: uuid.UUID
    email_hash: str | None
    phone_hash: str | None
    mfa_state: str
    display_name: str | None
    locale: str
    created_at: datetime
    updated_at: datetime


@dataclasses.dataclass(frozen=True)
class UserAuth:
    """登录因子与锁定状态（与 ``User`` 分开，避免把口令派生物随手传进序列化路径）。"""

    user_id: uuid.UUID
    password_hash: str | None
    password_updated_at: datetime | None
    mfa_state: str
    mfa_secret_hash: str | None
    mfa_salt: str | None
    mfa_enabled_at: datetime | None
    failed_login_count: int
    login_locked_until: datetime | None
    last_login_at: datetime | None


@dataclasses.dataclass(frozen=True)
class Org:
    id: uuid.UUID
    tenant_id: uuid.UUID
    type: str
    name: str
    seats: int
    seats_limit: int
    owner_account_id: uuid.UUID | None
    state: str
    owner_transfer_cooldown_until: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclasses.dataclass(frozen=True)
class Account:
    id: uuid.UUID
    user_id: uuid.UUID
    type: str
    state: str
    tenant_id: uuid.UUID
    org_id: uuid.UUID | None
    session_epoch: int
    frozen_until: datetime | None
    frozen_reason: str | None
    frozen_by: uuid.UUID | None
    frozen_approval: Any
    closing_deadline: datetime | None
    closed_at: datetime | None
    pii_purged_at: datetime | None
    ledger_unlink_requested_at: datetime | None
    created_at: datetime
    updated_at: datetime

    @property
    def writable(self) -> bool:
        return self.state in WRITABLE_STATES

    @property
    def is_closed(self) -> bool:
        return self.state == "closed"


@dataclasses.dataclass(frozen=True)
class OrgMember:
    id: uuid.UUID
    org_id: uuid.UUID
    tenant_id: uuid.UUID
    account_id: uuid.UUID
    org_role: str
    state: str
    invited_by: uuid.UUID | None
    invite_hash: str | None
    invite_expires_at: datetime | None
    joined_at: datetime | None
    removed_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclasses.dataclass(frozen=True)
class ApiKey:
    """Key 视图。**注意**：没有明文字段，也没有可选回明文的路径。"""

    id: int
    user_id: str
    key_prefix: str
    key_hash: str
    account_id: uuid.UUID | None
    tenant_id: uuid.UUID | None
    qps: int | None
    daily_usd_minor: int | None
    label: str | None
    rotated_from: int | None
    last_used_at: datetime | None
    created_by: uuid.UUID | None
    created_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None
    scopes: list[str] | None = None
    expires_at: datetime | None = None

    @property
    def live(self) -> bool:
        """**未安排**失效（没有任何 revoked_at）。用于「是否计入单账户 Key 上限」。"""
        return self.revoked_at is None

    def active_at(self, moment: datetime) -> bool:
        """在 ``moment`` 是否可用于鉴权：未过期，且未撤销或仍在重叠期（revoked_at 在未来）。"""
        if self.revoked_at is not None and self.revoked_at <= moment:
            return False
        if self.expires_at is not None and self.expires_at <= moment:
            return False
        return True

    def overlapping_at(self, moment: datetime) -> bool:
        """是否处于轮换重叠期：已安排失效、但失效时刻还没到。"""
        return self.revoked_at is not None and self.revoked_at > moment


@dataclasses.dataclass(frozen=True)
class Session:
    id: uuid.UUID
    account_id: uuid.UUID
    tenant_id: uuid.UUID
    epoch: int
    kind: str
    mfa: bool
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    refresh_expires_at: datetime | None
    absolute_expires_at: datetime | None
    idle_expires_at: datetime | None
    step_up_until: datetime | None
    rotated_at: datetime | None
    revoked_at: datetime | None
    revoked_reason: str | None


@dataclasses.dataclass(frozen=True)
class RoleBinding:
    id: uuid.UUID
    account_id: uuid.UUID
    tenant_id: uuid.UUID
    admin_role: str
    scope: str
    granted_by: uuid.UUID
    approved_by: uuid.UUID
    granted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None

    def active_at(self, moment: datetime) -> bool:
        return self.revoked_at is None and self.expires_at > moment


@dataclasses.dataclass(frozen=True)
class TenantQuota:
    id: uuid.UUID
    tenant_id: uuid.UUID
    key_id: int | None
    kind: str
    value: int
    policy_version: str
    created_at: datetime
    updated_at: datetime


# --------------------------------------------------------------------------- 列清单
_USER_COLS = "id, email_hash, phone_hash, mfa_state, display_name, locale, created_at, updated_at"
_USER_AUTH_COLS = ("u.id AS user_id, u.password_hash, u.password_updated_at, u.mfa_state, "
                   "u.mfa_secret_hash, u.mfa_salt, u.mfa_enabled_at, u.failed_login_count, "
                   "u.login_locked_until, u.last_login_at")
_ORG_COLS = ("id, tenant_id, type, name, seats, seats_limit, owner_account_id, state, "
             "owner_transfer_cooldown_until, created_at, updated_at")
_ACCOUNT_COLS = ("id, user_id, type, state, tenant_id, org_id, session_epoch, frozen_until, "
                 "frozen_reason, frozen_by, frozen_approval, closing_deadline, closed_at, "
                 "pii_purged_at, ledger_unlink_requested_at, created_at, updated_at")
_MEMBER_COLS = ("id, org_id, tenant_id, account_id, org_role, state, invited_by, invite_hash, "
                "invite_expires_at, joined_at, removed_at, created_at, updated_at")
_KEY_COLS = ("id, user_id, key_prefix, key_hash, account_id, tenant_id, qps, daily_usd_minor, "
             "label, rotated_from, last_used_at, created_by, created_at, revoked_at, "
             "revoked_reason, scopes, expires_at")
# 注意：刻意**不含** access_hash / refresh_hash——会话视图不回令牌材料（INV-04）
_SESSION_COLS = ("id, account_id, tenant_id, epoch, kind, mfa, created_at, last_seen_at, "
                 "expires_at, refresh_expires_at, absolute_expires_at, idle_expires_at, "
                 "step_up_until, rotated_at, revoked_at, revoked_reason")
_ROLE_COLS = ("id, account_id, tenant_id, admin_role, scope, granted_by, approved_by, granted_at, "
              "expires_at, revoked_at, revoked_reason")
_QUOTA_COLS = "id, tenant_id, key_id, kind, value, policy_version, created_at, updated_at"


def _check(value: str, allowed: Sequence[str], field: str) -> str:
    if value not in allowed:
        raise InvalidArgument(f"{field} 必须是 {tuple(allowed)} 之一，收到 {value!r}", field=field)
    return value


_LOCALE_RE = re.compile(r"^[a-z]{2}(-[A-Z]{2})?$")


def _text(value: str | None, field: str, *, max_len: int = 200) -> str:
    if value is None or not value.strip():
        raise InvalidArgument(f"{field} 必填", field=field)
    if len(value) > max_len:
        raise InvalidArgument(f"{field} 超长（>{max_len}）", field=field)
    return value.strip()


# --------------------------------------------------------------------------- outbox
def emit_event(c, event_type: str, *, aggregate_type: str, aggregate_id: Any,
               payload: Mapping[str, Any], trace_id: str | None = None,
               idempotency_key: str | None = None, correlation_id: str | None = None,
               causation_id: uuid.UUID | None = None, now: datetime | None = None) -> bool:
    """在同一本地事务里落一条 outbox 事件（02-events §1 信封；M01 §6 事务边界）。

    幂等：``idempotency_key`` 已存在时不重复落、返回 False —— 到期解冻 job 重放两次只产生
    一条 ``account.state.changed``（A2）。payload 不含 PII / 明文。
    """
    event_id = uuid7()
    moment = _now(now)
    key = idempotency_key or f"{event_type}:{aggregate_id}:{int(moment.timestamp() * 1e6)}"
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO identity_outbox
                   (event_id, type, occurred_at, aggregate_type, aggregate_id,
                    correlation_id, causation_id, trace_id, idempotency_key, payload)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (idempotency_key) DO NOTHING
               RETURNING seq""",
            (event_id, event_type, moment, aggregate_type, str(aggregate_id),
             correlation_id, causation_id, trace_id or uuid7().hex, key,
             Jsonb(dict(payload))),
        )
        return cur.fetchone() is not None


def pending_events(c, *, limit: int = 100) -> list[dict]:
    """投递侧取未发布事件（T1 只提供读口，投递在 M16 / T2）。"""
    with c.cursor() as cur:
        cur.execute(
            """SELECT seq, event_id, type, version, occurred_at, aggregate_type, aggregate_id,
                      correlation_id, causation_id, trace_id, idempotency_key, payload
                 FROM identity_outbox
                WHERE published_at IS NULL
                ORDER BY seq
                LIMIT %s""",
            (limit,),
        )
        return _rows(cur)


# --------------------------------------------------------------------------- users
def create_user(c, *, email: str | None = None, phone: str | None = None,
                mfa_state: str = "none", display_name: str | None = None,
                locale: str = "zh-CN", user_id: uuid.UUID | None = None,
                password: str | None = None, now: datetime | None = None) -> User:
    """建登录身份。邮箱 / 手机只以哈希入库；口令只存 scrypt 派生串（T2 起）。"""
    _check(mfa_state, MFA_STATES, "mfa_state")
    if mfa_state != "none":
        raise InvalidArgument("注册只能以 mfa_state=none 开始，绑 MFA 走 mfa.enroll（T2）",
                              field="mfa_state")
    password_hash = credentials.hash_password(password) if password else None
    if email is None and phone is None:
        # 服务账户（SVC）没有自然人联系方式；有联系方式的账户仍需在 T2 走验证流程
        log.debug("identity.user.create service-account user_id=%s", user_id)
    moment = _now(now)
    with c.cursor() as cur:
        try:
            cur.execute(
                f"""INSERT INTO users
                        (id, email_hash, phone_hash, mfa_state, display_name, locale, created_at,
                         password_hash, password_updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {_USER_COLS}""",
                (user_id or uuid7(), hash_pii(email) if email else None,
                 hash_pii(phone) if phone else None, mfa_state,
                 _text(display_name, "display_name", max_len=64) if display_name else None,
                 locale, moment, password_hash, moment if password_hash else None),
            )
        except UniqueViolation as exc:      # 同一邮箱 / 手机只能有一个登录身份
            raise StateConflict("该邮箱或手机号已注册", reason="user_exists") from exc
        return _make(User, _one(cur))


def get_user(c, user_id: uuid.UUID, *, for_update: bool = False) -> User:
    with c.cursor() as cur:
        cur.execute(f"SELECT {_USER_COLS} FROM users WHERE id = %s"
                    + (" FOR UPDATE" if for_update else ""), (user_id,))
        row = _one(cur)
    if row is None:
        raise NotFound("登录身份不存在", user_id=str(user_id))
    return _make(User, row)


def find_user_by_identifier(c, identifier: str) -> User | None:
    """按「邮箱或手机」反查登录身份（T2 登录入口）。查询键是哈希，不落明文。"""
    value = credentials.normalize_identifier(identifier)
    sql = f"SELECT {_USER_COLS} FROM users WHERE email_hash = %s OR phone_hash = %s"
    with c.cursor() as cur:
        cur.execute(sql, (hash_pii(value), hash_pii(value)))
        row = _one(cur)
    return _make(User, row) if row else None


def find_user_by_email(c, email: str) -> User | None:
    """按邮箱反查（登录入口 T2 用）；查询键是哈希，不落明文。"""
    with c.cursor() as cur:
        cur.execute(f"SELECT {_USER_COLS} FROM users WHERE email_hash = %s", (hash_pii(email),))
        row = _one(cur)
    return _make(User, row) if row else None


def get_user_auth(c, user_id: uuid.UUID, *, for_update: bool = False) -> UserAuth:
    """取登录因子与锁定状态（唯一读口；调用方不要自己拼 SQL 读 password_hash）。"""
    with c.cursor() as cur:
        cur.execute(f"SELECT {_USER_AUTH_COLS} FROM users u WHERE u.id = %s"
                    + (" FOR UPDATE" if for_update else ""), (user_id,))
        row = _one(cur)
    if row is None:
        raise NotFound("登录身份不存在", user_id=str(user_id))
    return _make(UserAuth, row)


def set_password(c, user_id: uuid.UUID, password: str, *, now: datetime | None = None) -> None:
    """改口令：只写派生串 + 时间戳；同时清零失败计数（改密即解封）。"""
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            """UPDATE users
                  SET password_hash = %s, password_updated_at = %s,
                      failed_login_count = 0, login_locked_until = NULL
                WHERE id = %s""",
            (credentials.hash_password(password), moment, user_id))
        if cur.rowcount != 1:
            raise NotFound("登录身份不存在", user_id=str(user_id))


PROFILE_FIELDS = ("display_name", "locale")


def update_user_profile(c, user_id: uuid.UUID, fields: Mapping[str, Any], *,
                        now: datetime | None = None) -> User:
    """局部更新展示类字段（spec：只允许 display_name / locale；身份字段一律拒绝）。"""
    unknown = [key for key in fields if key not in PROFILE_FIELDS]
    if unknown:
        raise InvalidArgument(f"不允许经 profile 修改：{unknown}", reason="immutable_field",
                              fields=unknown)
    if not fields:
        raise InvalidArgument("至少提供一个可改字段", reason="empty_update")
    sets, params = [], []
    for key in PROFILE_FIELDS:
        if key not in fields:
            continue
        value = fields[key]
        if key == "display_name":
            params.append(None if value is None else _text(value, "display_name", max_len=64))
        else:
            if value is None or not _LOCALE_RE.match(str(value)):
                raise InvalidArgument("locale 必须是 BCP 47 形态（如 zh-CN）", field="locale")
            params.append(str(value))
        sets.append(f"{key} = %s")
    params.append(user_id)
    with c.cursor() as cur:
        cur.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = %s RETURNING {_USER_COLS}",
                    params)
        row = _one(cur)
    if row is None:
        raise NotFound("登录身份不存在", user_id=str(user_id))
    return _make(User, row)


def purge_user_pii(c, user_id: uuid.UUID, *, now: datetime | None = None) -> int:
    """注销第三步：删除个人信息（只清哈希与昵称，行保留以便账本去关联）。"""
    with c.cursor() as cur:
        cur.execute(
            """UPDATE users
                  SET email_hash = NULL, phone_hash = NULL, display_name = NULL
                WHERE id = %s
                  AND (email_hash IS NOT NULL OR phone_hash IS NOT NULL
                       OR display_name IS NOT NULL)""",
            (user_id,),
        )
        return cur.rowcount


# --------------------------------------------------------------------------- orgs / members
def create_org(c, *, type: str, name: str, seats_limit: int | None = None,
               org_id: uuid.UUID | None = None, now: datetime | None = None) -> Org:
    """建组织（team / enterprise）。tenant_id 恒等于 org id（1:1，INV-01）。"""
    _check(type, ORG_TYPES, "type")
    oid = org_id or uuid7()
    limit = seats_limit if seats_limit is not None else SEATS[type]
    if not 1 <= limit <= SEATS[type]:
        raise InvalidArgument(f"seats_limit 必须在 1..{SEATS[type]}（{type}）", field="seats_limit")
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO orgs (id, tenant_id, type, name, seats, seats_limit, created_at)
                VALUES (%s, %s, %s, %s, 0, %s, %s)
                RETURNING {_ORG_COLS}""",
            (oid, oid, type, _text(name, "name", max_len=120), limit, _now(now)),
        )
        return _make(Org, _one(cur))


def get_org(c, org_id: uuid.UUID, *, for_update: bool = False) -> Org:
    with c.cursor() as cur:
        cur.execute(f"SELECT {_ORG_COLS} FROM orgs WHERE id = %s"
                    + (" FOR UPDATE" if for_update else ""), (org_id,))
        row = _one(cur)
    if row is None:
        raise NotFound("组织不存在", org_id=str(org_id))
    return _make(Org, row)


def _require_org_writable(c, org_id: uuid.UUID) -> Org:
    org = get_org(c, org_id, for_update=True)
    if org.state != "active":
        raise AccountReadOnly(f"组织处于 {org.state}，只读", org_id=str(org_id), state=org.state)
    return org


def _seat_take(c, org_id: uuid.UUID) -> None:
    """席位 +1（成员**接受邀请**时占用）：超出上限即拒绝（M01 §1 席位上限）。"""
    with c.cursor() as cur:
        cur.execute(
            """UPDATE orgs SET seats = seats + 1
                WHERE id = %s AND seats < seats_limit
                RETURNING seats""",
            (org_id,),
        )
        if cur.fetchone() is None:
            raise StateConflict("席位已满", reason="seats_exceeded", org_id=str(org_id))


def _seat_available(c, org_id: uuid.UUID) -> None:
    """只读预览：空位用尽时提前拒绝邀请（不占用席位，避免过期邀请泄漏席位）。"""
    with c.cursor() as cur:
        cur.execute("SELECT seats, seats_limit FROM orgs WHERE id = %s FOR UPDATE", (org_id,))
        row = cur.fetchone()
    if row is None:                                     # pragma: no cover - 调用方已取过 org
        raise NotFound("组织不存在", org_id=str(org_id))
    if row[0] >= row[1]:
        raise StateConflict("席位已满", reason="seats_exceeded", org_id=str(org_id))


def _seat_release(c, org_id: uuid.UUID) -> None:
    with c.cursor() as cur:
        cur.execute("UPDATE orgs SET seats = GREATEST(seats - 1, 0) WHERE id = %s", (org_id,))


def invite_member(c, org_id: uuid.UUID, account_id: uuid.UUID, org_role: str, *,
                  actor_id: uuid.UUID | None = None, now: datetime | None = None) -> tuple[OrgMember, str]:
    """邀请成员：``invited`` + 一次性令牌（只存哈希，≤72 h）。返回 (成员, 明文令牌)。"""
    _check(org_role, ORG_ROLES, "org_role")
    org = _require_org_writable(c, org_id)
    _seat_available(c, org_id)
    moment = _now(now)
    token = secrets.token_urlsafe(24)
    with c.cursor() as cur:
        try:
            cur.execute(
                f"""INSERT INTO org_members
                        (id, org_id, tenant_id, account_id, org_role, state, invited_by,
                         invite_hash, invite_expires_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, 'invited', %s, %s, %s, %s)
                    RETURNING {_MEMBER_COLS}""",
                (uuid7(), org.id, org.tenant_id, account_id, org_role, actor_id,
                 hash_secret(token), moment + timedelta(hours=INVITE_TTL_HOURS), moment),
            )
        except UniqueViolation as exc:                  # 同账户同组织只有一条成员关系
            raise StateConflict("该账户已是组织成员或已被邀请",
                                reason="member_exists", account_id=str(account_id)) from exc
        return _make(OrgMember, _one(cur)), token


def accept_invite(c, token: str, *, now: datetime | None = None) -> OrgMember:
    """接受邀请：令牌一次性，过期 / 不存在 / 已用统一 40905（INV-08）；此刻占席位。"""
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {_MEMBER_COLS} FROM org_members
                 WHERE invite_hash = %s AND state = 'invited' FOR UPDATE""",
            (hash_secret(token),),
        )
        row = _one(cur)
        if row is None:
            raise InviteInvalid("邀请令牌无效或已使用")
        member = _make(OrgMember, row)
        if member.invite_expires_at is None or member.invite_expires_at <= moment:
            raise InviteInvalid("邀请令牌已过期", org_id=str(member.org_id))
        _seat_take(c, member.org_id)
        cur.execute(
            f"""UPDATE org_members
                   SET state = 'active', joined_at = %s, invite_hash = NULL, invite_expires_at = NULL
                 WHERE id = %s
                 RETURNING {_MEMBER_COLS}""",
            (moment, member.id),
        )
        return _make(OrgMember, _one(cur))


def remove_member(c, member_id: uuid.UUID, *, now: datetime | None = None,
                  actor_id: uuid.UUID | None = None) -> OrgMember:
    """移除成员：``removed``（保留 90 天，M01 §5）；owner 必须先转让（INV-05）。"""
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(f"SELECT {_MEMBER_COLS} FROM org_members WHERE id = %s FOR UPDATE", (member_id,))
        row = _one(cur)
        if row is None:
            raise NotFound("成员不存在", member_id=str(member_id))
        member = _make(OrgMember, row)
        if member.state == "removed":                 # 幂等
            return member
        if member.org_role == "owner":
            raise StateConflict("owner 不可直接移除：先转让（INV-05）", reason="owner_protected")
        cur.execute(
            f"""UPDATE org_members
                   SET state = 'removed', removed_at = %s,
                       invite_hash = NULL, invite_expires_at = NULL
                 WHERE id = %s RETURNING {_MEMBER_COLS}""",
            (moment, member_id),
        )
        if member.state == "active":
            _seat_release(c, member.org_id)
        return _make(OrgMember, _one(cur))


def list_members(c, org_id: uuid.UUID) -> list[OrgMember]:
    with c.cursor() as cur:
        cur.execute(f"SELECT {_MEMBER_COLS} FROM org_members WHERE org_id = %s ORDER BY created_at",
                    (org_id,))
        return [_make(OrgMember, r) for r in _rows(cur)]


def transfer_org_owner(c, org_id: uuid.UUID, to_account_id: uuid.UUID, *,
                       requester_id: uuid.UUID, approver_id: uuid.UUID,
                       second_factor: bool, target_confirmed: bool,
                       now: datetime | None = None) -> Org:
    """owner 转让（INV-05）：双方确认 + 二次认证 + 非同一人复核 + 24 h 冷却。"""
    moment = _now(now)
    org = _require_org_writable(c, org_id)
    if not target_confirmed:
        raise StateConflict("需被转让方确认", reason="target_not_confirmed")
    if not second_factor:
        raise StateConflict("需二次认证", reason="step_up_required")
    if approver_id == requester_id:
        raise StateConflict("复核人不得与发起人同一人", reason="dual_control_required")
    if org.owner_transfer_cooldown_until and org.owner_transfer_cooldown_until > moment:
        raise StateConflict("24 h 冷却未结束", reason="owner_transfer_cooling",
                            until=org.owner_transfer_cooldown_until.isoformat())
    with c.cursor() as cur:
        cur.execute(
            """SELECT id FROM org_members
                WHERE org_id = %s AND account_id = %s AND state = 'active' AND org_role <> 'owner'""",
            (org_id, to_account_id),
        )
        if cur.fetchone() is None:
            raise StateConflict("目标账户不是该组织的在册成员", reason="not_a_member")
        # 旧 owner 降级 → 新 owner 升级：先降后升，避免触发「每 org 恰一 owner」部分唯一
        cur.execute(
            """UPDATE org_members SET org_role = 'admin'
                WHERE org_id = %s AND org_role = 'owner' AND state <> 'removed'""", (org_id,))
        cur.execute(
            """UPDATE org_members SET org_role = 'owner'
                WHERE org_id = %s AND account_id = %s""", (org_id, to_account_id))
        cur.execute(
            f"""UPDATE orgs
                   SET owner_account_id = %s,
                       owner_transfer_cooldown_until = %s
                 WHERE id = %s RETURNING {_ORG_COLS}""",
            (to_account_id, moment + timedelta(hours=OWNER_TRANSFER_COOLDOWN_HOURS), org_id),
        )
        return _make(Org, _one(cur))


# --------------------------------------------------------------------------- 账户
def create_account(c, *, user_id: uuid.UUID, type: str = "personal",
                   org_id: uuid.UUID | None = None, tenant_id: uuid.UUID | None = None,
                   account_id: uuid.UUID | None = None, policy_version: str | None = None,
                   now: datetime | None = None,
                   trace_id: str | None = None) -> Account:
    """建账户（初始 ``pending_verify``）：users + user_accounts + 事件同事务（M01 §6.1）。

    - personal：tenant 即账户本身（``tenant_id = id``，1:1，INV-01）。
    - team / enterprise：``tenant_id = org_id``，org 必须在 ``active`` 且未超席位。
    """
    _check(type, ACCOUNT_TYPES, "type")
    get_user(c, user_id)                                   # 不存在 → 40401
    aid = account_id or uuid7()
    if type == "personal":
        if org_id is not None:
            raise InvalidArgument("personal 账户不得挂在 org 下", field="org_id")
        tenant = aid
    else:
        if org_id is None:
            raise InvalidArgument(f"{type} 账户必须指定 org_id", field="org_id")
        org = _require_org_writable(c, org_id)
        if org.tenant_id != org_id:                         # pragma: no cover - 库层 CHECK 已保证
            raise StateConflict("组织租户不一致", reason="tenant_mismatch")
        tenant = org_id
    if tenant_id is not None and tenant_id != tenant:
        raise InvalidArgument("tenant_id 与账户类型推导结果不一致", field="tenant_id")
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO user_accounts
                    (id, user_id, type, state, tenant_id, org_id, created_at)
                VALUES (%s, %s, %s, 'pending_verify', %s, %s, %s)
                RETURNING {_ACCOUNT_COLS}""",
            (aid, user_id, type, tenant, org_id, _now(now)),
        )
        account = _make(Account, _one(cur))
    if policy_version is not None:
        # M01 §6.1：注册事务内一并落租户配额主体（默认 qps 来自 quota.default_qps）
        set_quota(c, tenant_id=tenant, kind="qps", value=DEFAULT_QPS,
                  policy_version=policy_version, now=now)
    emit_event(c, "account.created", aggregate_type="account", aggregate_id=account.id,
               payload={"account_id": str(account.id), "type": account.type,
                        "tenant_id": str(account.tenant_id)},
               trace_id=trace_id, idempotency_key=f"account.created:{account.id}", now=now)
    log.info("identity.account.created account_id=%s type=%s tenant_id=%s",
             account.id, account.type, account.tenant_id)
    return account


def get_account(c, account_id: uuid.UUID, *, tenant_id: uuid.UUID | None = None,
                for_update: bool = False) -> Account:
    """按 id 取账户；带 ``tenant_id`` 时跨租户一律 40401（不泄露存在性，A6）。"""
    sql = f"SELECT {_ACCOUNT_COLS} FROM user_accounts WHERE id = %s"
    params: list[Any] = [account_id]
    if tenant_id is not None:
        sql += " AND tenant_id = %s"
        params.append(tenant_id)
    if for_update:
        sql += " FOR UPDATE"
    with c.cursor() as cur:
        cur.execute(sql, params)
        row = _one(cur)
    if row is None:
        raise NotFound("账户不存在", account_id=str(account_id))
    return _make(Account, row)


def primary_account(c, user_id: uuid.UUID, *, for_update: bool = False) -> Account:
    """登录身份的主账户：优先 personal（1:1），否则取最早创建的账户。"""
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {_ACCOUNT_COLS} FROM user_accounts
                 WHERE user_id = %s
                 ORDER BY (type = 'personal') DESC, created_at, id
                 LIMIT 1""" + (" FOR UPDATE" if for_update else ""),
            (user_id,))
        row = _one(cur)
    if row is None:
        raise NotFound("该登录身份没有账户", user_id=str(user_id))
    return _make(Account, row)


def list_accounts(c, *, state: str | None = None, tenant_id: uuid.UUID | None = None,
                  limit: int = 200) -> list[Account]:
    sql = f"SELECT {_ACCOUNT_COLS} FROM user_accounts WHERE TRUE"
    params: list[Any] = []
    if state is not None:
        _check(state, ACCOUNT_STATES, "state")
        sql += " AND state = %s"
        params.append(state)
    if tenant_id is not None:
        sql += " AND tenant_id = %s"
        params.append(tenant_id)
    sql += " ORDER BY created_at LIMIT %s"
    params.append(limit)
    with c.cursor() as cur:
        cur.execute(sql, params)
        return [_make(Account, r) for r in _rows(cur)]


def assert_writable(account: Account, *, action: str = "write") -> Account:
    """写操作闸门（M01 §3 五态「禁止」列）：只有 ``normal`` 可写。

    pending_verify → 40001（未验证）；frozen / closing → 40304（只读 + 可申诉 / 可撤回）；
    closed → 40903（不可逆）。
    """
    if account.state in WRITABLE_STATES:
        return account
    if account.state == "closed":
        raise AccountClosed(f"账户已注销：禁止{action}", account_id=str(account.id))
    if account.state in READ_ONLY_STATES:
        raise AccountReadOnly(f"账户处于 {account.state}（只读）：禁止{action}",
                              account_id=str(account.id), state=account.state)
    raise InvalidArgument(f"账户处于 {account.state}：禁止{action}",
                          reason="account_not_verified", account_id=str(account.id),
                          state=account.state)


# --------------------------------------------------------------------------- api_keys
def _count_live_keys(c, account_id: uuid.UUID, now: datetime | None = None) -> int:
    """单账户 Key 上限的计数口径：未安排失效且未过期（重叠期的旧钥不占额度）。"""
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            """SELECT count(*) FROM api_keys
                WHERE account_id = %s AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > %s)""",
            (account_id, moment))
        return int(cur.fetchone()[0])


MAX_SCOPES = 16
SCOPE_MAX_LEN = 64


def _normalize_scopes(scopes: Sequence[str] | None) -> list[str] | None:
    """scopes：字符串数组，去重保序，单条 1..64 字符，至多 16 条（spec 未限上限，这里给工程上限）。"""
    if scopes is None:
        return None
    if isinstance(scopes, (str, bytes)) or not isinstance(scopes, Sequence):
        raise InvalidArgument("scopes 必须是字符串数组", field="scopes")
    out: list[str] = []
    for scope in scopes:
        if not isinstance(scope, str) or not 1 <= len(scope.strip()) <= SCOPE_MAX_LEN:
            raise InvalidArgument(f"scopes 单项必须是 1..{SCOPE_MAX_LEN} 字符的字符串",
                                  field="scopes")
        item = scope.strip()
        if item not in out:
            out.append(item)
    if len(out) > MAX_SCOPES:
        raise InvalidArgument(f"scopes 最多 {MAX_SCOPES} 条", field="scopes")
    return out


def _check_key_expiry(expires_at: datetime | None, moment: datetime) -> datetime | None:
    """Key 级过期时间：必须在将来（否则建出来就是废钥）。"""
    if expires_at is None:
        return None
    if expires_at.tzinfo is None:
        raise InvalidArgument("expires_at 必须带时区（UTC）", field="expires_at")
    expiry = expires_at.astimezone(moment.tzinfo)
    if expiry <= moment:
        raise InvalidArgument("expires_at 必须在将来", field="expires_at")
    return expiry


def create_api_key(c, *, account_id: uuid.UUID, tenant_id: uuid.UUID | None = None,
                   label: str | None = None, qps: int | None = None,
                   daily_usd_minor: int | None = None, created_by: uuid.UUID | None = None,
                   scopes: Sequence[str] | None = None, expires_at: datetime | None = None,
                   now: datetime | None = None, trace_id: str | None = None) -> tuple[ApiKey, str]:
    """建 Key：返回 ``(行, 明文)``。**明文只在此处出现一次**，库与日志里只有哈希与前缀。"""
    moment = _now(now)
    account = assert_writable(get_account(c, account_id, tenant_id=tenant_id),
                              action="建 Key")
    if qps is not None and qps <= 0:
        raise InvalidArgument("qps 必须 > 0", field="qps")
    if daily_usd_minor is not None and daily_usd_minor <= 0:
        raise InvalidArgument("daily_usd_minor 必须 > 0", field="daily_usd_minor")
    scope_list = _normalize_scopes(scopes)
    expires = _check_key_expiry(expires_at, moment)
    if _count_live_keys(c, account.id, moment) >= KEY_MAX_PER_ACCOUNT:
        raise KeyLimitReached(f"单个账户最多 {KEY_MAX_PER_ACCOUNT} 个有效 Key",
                              account_id=str(account.id))
    plaintext, prefix, digest = generate_api_key()
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO api_keys
                    (user_id, key_prefix, key_hash, account_id, tenant_id, qps,
                     daily_usd_minor, label, created_by, created_at, scopes, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING {_KEY_COLS}""",
            (str(account.user_id), prefix, digest, account.id, account.tenant_id,
             qps, daily_usd_minor,
             label if label is None else _text(label, "label", max_len=64), created_by,
             moment, Jsonb(list(scope_list)) if scope_list is not None else None, expires),
        )
        key = _make(ApiKey, _one(cur))
    emit_event(c, "apikey.created", aggregate_type="api_key", aggregate_id=key.id,
               payload={"api_key_id": key.id, "account_id": str(account.id),
                        "prefix": key.key_prefix},
               trace_id=trace_id, idempotency_key=f"apikey.created:{key.id}", now=now)
    # 日志只写短码与 id：明文 / 完整哈希都不进日志（00-conventions §8）
    log.info("identity.apikey.created api_key_id=%s account_id=%s prefix=%s",
             key.id, account.id, key.key_prefix)
    return key, plaintext


def get_api_key(c, key_id: int, *, account_id: uuid.UUID | None = None,
                tenant_id: uuid.UUID | None = None, for_update: bool = False) -> ApiKey:
    sql = f"SELECT {_KEY_COLS} FROM api_keys WHERE id = %s"
    params: list[Any] = [key_id]
    if account_id is not None:
        sql += " AND account_id = %s"
        params.append(account_id)
    if tenant_id is not None:
        sql += " AND tenant_id = %s"
        params.append(tenant_id)
    if for_update:
        sql += " FOR UPDATE"
    with c.cursor() as cur:
        cur.execute(sql, params)
        row = _one(cur)
    if row is None:
        raise NotFound("Key 不存在", api_key_id=key_id)
    return _make(ApiKey, row)


def list_api_keys(c, account_id: uuid.UUID, *, tenant_id: uuid.UUID | None = None,
                  include_revoked: bool = False,
                  now: datetime | None = None) -> list[ApiKey]:
    """列表只回前缀与限额（M01 §4.1），永不回哈希以外的明文材料。

    ``include_revoked=False`` 返回「此刻仍可用于鉴权」的 Key（未过期，且未撤销或仍在轮换重叠期）。
    """
    moment = _now(now)
    sql = f"SELECT {_KEY_COLS} FROM api_keys WHERE account_id = %s"
    params: list[Any] = [account_id]
    if tenant_id is not None:
        sql += " AND tenant_id = %s"
        params.append(tenant_id)
    if not include_revoked:
        sql += (" AND (revoked_at IS NULL OR revoked_at > %s)"
                " AND (expires_at IS NULL OR expires_at > %s)")
        params.extend([moment, moment])
    sql += " ORDER BY id DESC"
    with c.cursor() as cur:
        cur.execute(sql, params)
        return [_make(ApiKey, r) for r in _rows(cur)]


def revoke_api_key(c, key_id: int, *, account_id: uuid.UUID | None = None,
                   tenant_id: uuid.UUID | None = None, reason: str = "revoked",
                   now: datetime | None = None, trace_id: str | None = None) -> ApiKey:
    """撤销 Key（**幂等**，A3）：已有失效时刻则原样返回，不报 500、不重复发事件。"""
    key = get_api_key(c, key_id, account_id=account_id, tenant_id=tenant_id, for_update=True)
    if key.revoked_at is not None:
        return key
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE api_keys SET revoked_at = %s, revoked_reason = %s
                 WHERE id = %s RETURNING {_KEY_COLS}""",
            (moment, _text(reason, "reason", max_len=64), key_id),
        )
        revoked = _make(ApiKey, _one(cur))
    emit_event(c, "apikey.revoked", aggregate_type="api_key", aggregate_id=revoked.id,
               payload={"api_key_id": revoked.id, "account_id": str(revoked.account_id),
                        "prefix": revoked.key_prefix, "reason": revoked.revoked_reason},
               trace_id=trace_id, idempotency_key=f"apikey.revoked:{revoked.id}", now=now)
    return revoked


def rotate_api_key(c, key_id: int, *, account_id: uuid.UUID | None = None,
                   tenant_id: uuid.UUID | None = None, overlap_seconds: int = 0,
                   name: str | None = None, scopes: Sequence[str] | None = None,
                   expires_at: datetime | None = None, now: datetime | None = None,
                   trace_id: str | None = None) -> tuple[ApiKey, str]:
    """轮换：新钥生效 + 旧钥按 ``overlap_seconds`` 失效（0 = 立即；≤86400，spec 1.2.1）。

    重叠期内旧钥只允许验签（``ApiKey.overlapping_at``），不接受新注册（INV-10）。
    返回 ``(新钥, 明文)``（旧钥的失效时刻可回查 ``api_keys.revoked_at``）。
    同事务：外部看不到「新旧同时无主」的中间态。
    """
    moment = _now(now)
    if not isinstance(overlap_seconds, int) or isinstance(overlap_seconds, bool) \
            or not 0 <= overlap_seconds <= ROTATE_MAX_OVERLAP_SECONDS:
        raise InvalidArgument(f"overlap_seconds 必须在 0..{ROTATE_MAX_OVERLAP_SECONDS}",
                              field="overlap_seconds")
    old = get_api_key(c, key_id, account_id=account_id, tenant_id=tenant_id, for_update=True)
    if old.account_id is None or old.tenant_id is None:
        raise StateConflict("存量原型 Key 无账户归属，不能轮换", reason="legacy_key",
                            api_key_id=key_id)
    if old.revoked_at is not None:
        raise StateConflict("旧 Key 已撤销，不能轮换", reason="key_revoked", api_key_id=key_id)
    if not old.active_at(moment):
        raise ApiKeyInvalid("旧 Key 已过期，不能轮换", api_key_id=key_id)
    with c.cursor() as cur:                      # 旧钥：失效时刻 = now + overlap（0 = 立即）
        cur.execute(
            """UPDATE api_keys SET revoked_at = %s, revoked_reason = 'rotated'
                WHERE id = %s RETURNING {_KEY_COLS}""".format(_KEY_COLS=_KEY_COLS),
            (moment + timedelta(seconds=overlap_seconds), old.id))
        rotated = _make(ApiKey, _one(cur))
    emit_event(c, "apikey.revoked", aggregate_type="api_key", aggregate_id=rotated.id,
               payload={"api_key_id": rotated.id, "account_id": str(rotated.account_id),
                        "prefix": rotated.key_prefix, "reason": "rotated",
                        "effective_at": rotated.revoked_at.isoformat()},
               trace_id=trace_id, idempotency_key=f"apikey.revoked:{rotated.id}", now=moment)
    new, plaintext = create_api_key(c, account_id=rotated.account_id,
                                    tenant_id=rotated.tenant_id,
                                    label=name if name is not None else rotated.label,
                                    qps=rotated.qps,
                                    daily_usd_minor=rotated.daily_usd_minor,
                                    created_by=rotated.created_by,
                                    scopes=scopes if scopes is not None else rotated.scopes,
                                    expires_at=expires_at, now=moment, trace_id=trace_id)
    with c.cursor() as cur:
        cur.execute("UPDATE api_keys SET rotated_from = %s WHERE id = %s", (rotated.id, new.id))
    return get_api_key(c, new.id), plaintext


def lookup_api_key(c, plaintext: str, *, tenant_id: uuid.UUID | None = None,
                   now: datetime | None = None) -> ApiKey:
    """鉴权热路径：只按哈希查；未命中 / 已过失效时刻 / 已过期 / 跨租户统一 40101（M01 §7）。

    注意：轮换重叠期的旧钥（``revoked_at`` 在未来）**仍会返回**——是否允许使用由调用方裁决
    （网关用 :func:`app.identity.api_keys.verify_api_key` 的 ``allow_overlap``）。
    """
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(f"SELECT {_KEY_COLS} FROM api_keys WHERE key_hash = %s",
                    (hash_secret(plaintext),))
        row = _one(cur)
    if row is None:
        raise ApiKeyInvalid("Key 无效或已撤销")
    key = _make(ApiKey, row)
    if not key.active_at(moment) or (tenant_id is not None and key.tenant_id != tenant_id):
        raise ApiKeyInvalid("Key 无效或已撤销")
    return key


def authenticate_api_key(c, plaintext: str, *, tenant_id: uuid.UUID | None = None,
                         now: datetime | None = None) -> Account:
    """Key → 账户（T2 兼容入口）；账户不存在或已注销一律 40101。"""
    moment = _now(now)
    key = lookup_api_key(c, plaintext, tenant_id=tenant_id, now=moment)
    if key.account_id is None:
        raise ApiKeyInvalid("Key 未绑定账户")
    account = get_account(c, key.account_id, for_update=False)
    if account.is_closed:
        raise ApiKeyInvalid("账户已注销")
    return account


# --------------------------------------------------------------------------- sessions
def create_session(c, *, account_id: uuid.UUID, tenant_id: uuid.UUID | None = None,
                   kind: str = "user", mfa: bool = False, now: datetime | None = None) -> Session:
    """建会话：``epoch`` 取自账户当前值；角色变更 / 冻结会 ``epoch++`` 让旧会话失效（A4）。"""
    _check(kind, SESSION_KINDS, "kind")
    account = get_account(c, account_id, tenant_id=tenant_id)
    if account.is_closed:
        raise AccountClosed("账户已注销：禁止登录", account_id=str(account.id))
    if account.state == "pending_verify":
        raise InvalidArgument("账户未验证：禁止登录", reason="account_not_verified",
                              account_id=str(account.id))
    moment = _now(now)
    absolute = moment + timedelta(hours=SESSION_ABSOLUTE_HOURS)
    if kind == "admin":
        expires = moment + timedelta(minutes=SESSION_SLIDE_MINUTES)
    else:
        expires = moment + timedelta(hours=ACCESS_TTL_HOURS)
    expires = min(expires, absolute)
    refresh = moment + timedelta(days=REFRESH_TTL_DAYS) if kind == "user" else None
    with c.cursor() as cur:
        cur.execute(
            f"""INSERT INTO sessions
                    (id, account_id, tenant_id, epoch, kind, mfa, created_at, last_seen_at,
                     expires_at, refresh_expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING {_SESSION_COLS}""",
            (uuid7(), account.id, account.tenant_id, account.session_epoch, kind, mfa,
             moment, moment, expires, refresh),
        )
        return _make(Session, _one(cur))


def get_session(c, session_id: uuid.UUID, *, tenant_id: uuid.UUID | None = None,
                for_update: bool = False) -> Session:
    sql = f"SELECT {_SESSION_COLS} FROM sessions WHERE id = %s"
    params: list[Any] = [session_id]
    if tenant_id is not None:
        sql += " AND tenant_id = %s"
        params.append(tenant_id)
    if for_update:
        sql += " FOR UPDATE"
    with c.cursor() as cur:
        cur.execute(sql, params)
        row = _one(cur)
    if row is None:
        raise SessionInvalid("会话不存在或不可见", session_id=str(session_id))
    return _make(Session, row)


def validate_session(c, session_id: uuid.UUID, *, tenant_id: uuid.UUID | None = None,
                     now: datetime | None = None) -> Session:
    """校验会话：撤销 / 过期 / epoch 不符一律 40102（A4：角色变更后用旧会话）。"""
    session = get_session(c, session_id, tenant_id=tenant_id)
    moment = _now(now)
    if session.revoked_at is not None:
        raise SessionInvalid("会话已撤销", session_id=str(session_id))
    if session.expires_at <= moment:
        raise SessionInvalid("会话已过期", session_id=str(session_id))
    account = get_account(c, session.account_id, tenant_id=session.tenant_id)
    if session.epoch != account.session_epoch:
        raise SessionInvalid("会话 epoch 已失效（角色 / 状态变更）",
                             session_id=str(session_id), epoch=session.epoch)
    if account.is_closed:
        raise SessionInvalid("账户已注销", session_id=str(session_id))
    return session


def touch_session(c, session_id: uuid.UUID, *, now: datetime | None = None) -> Session:
    """滑动续期：不越过 12 h 绝对上限（03-facts §8）。"""
    session = get_session(c, session_id, for_update=True)
    moment = _now(now)
    if session.revoked_at is not None or session.expires_at <= moment:
        raise SessionInvalid("会话已失效", session_id=str(session_id))
    cap = session.created_at + timedelta(hours=SESSION_ABSOLUTE_HOURS)
    expires = min(moment + timedelta(minutes=SESSION_SLIDE_MINUTES), cap)
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE sessions SET last_seen_at = %s, expires_at = %s
                 WHERE id = %s RETURNING {_SESSION_COLS}""",
            (moment, expires, session_id),
        )
        return _make(Session, _one(cur))


def revoke_session(c, session_id: uuid.UUID, *, reason: str = "revoked",
                   now: datetime | None = None, trace_id: str | None = None) -> Session:
    session = get_session(c, session_id, for_update=True)
    if session.revoked_at is not None:                    # 幂等
        return session
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            f"""UPDATE sessions SET revoked_at = %s, revoked_reason = %s
                 WHERE id = %s RETURNING {_SESSION_COLS}""",
            (moment, _text(reason, "reason", max_len=64), session_id),
        )
        revoked = _make(Session, _one(cur))
    emit_event(c, "session.revoked", aggregate_type="session", aggregate_id=revoked.id,
               payload={"session_id": str(revoked.id), "account_id": str(revoked.account_id),
                        "epoch": revoked.epoch, "reason": revoked.revoked_reason},
               trace_id=trace_id, idempotency_key=f"session.revoked:{revoked.id}", now=now)
    return revoked


def revoke_live_sessions(c, account_id: uuid.UUID, *, reason: str = "revoked",
                         now: datetime | None = None, trace_id: str | None = None) -> int:
    """撤销该账户全部活跃会话（角色变更 / 离职 / 冻结 / 注销均用）。返回撤销条数。"""
    with c.cursor() as cur:
        cur.execute("SELECT id FROM sessions WHERE account_id = %s AND revoked_at IS NULL",
                    (account_id,))
        ids = [r[0] for r in cur.fetchall()]
    for sid in ids:
        revoke_session(c, sid, reason=reason, now=now, trace_id=trace_id)
    return len(ids)


def bump_session_epoch(c, account_id: uuid.UUID) -> int:
    """``session_epoch++``（INV-06：角色变更；M01 §6.3：冻结）—— 旧会话随即失效。"""
    with c.cursor() as cur:
        cur.execute(
            """UPDATE user_accounts SET session_epoch = session_epoch + 1
                WHERE id = %s RETURNING session_epoch""",
            (account_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise NotFound("账户不存在", account_id=str(account_id))
    return int(row[0])


def invalidate_sessions(c, account_id: uuid.UUID, *, reason: str,
                        now: datetime | None = None, trace_id: str | None = None) -> int:
    """epoch+1 并撤销全部活跃会话：一次调用同时满足「旧令牌 40102」与「留痕」。"""
    bump_session_epoch(c, account_id)
    return revoke_live_sessions(c, account_id, reason=reason, now=now, trace_id=trace_id)


# --------------------------------------------------------------------------- role_bindings
def bind_role(c, *, account_id: uuid.UUID, admin_role: str, granted_by: uuid.UUID,
              approved_by: uuid.UUID, scope: str = "platform",
              tenant_id: uuid.UUID | None = None, now: datetime | None = None,
              trace_id: str | None = None) -> RoleBinding:
    """授予后台角色：八角色白名单 + 双人复核 + SVC 不得绑自然人 + 90 天到期（INV-06）。"""
    _check(admin_role, ADMIN_ROLES, "admin_role")
    _check(scope, ROLE_SCOPES, "scope")
    if approved_by == granted_by:
        raise StateConflict("角色授予需第二人确认（复核人不得为授予人）",
                            reason="dual_control_required")
    account = get_account(c, account_id, tenant_id=tenant_id)
    if account.is_closed:
        raise AccountClosed("账户已注销：禁止授予角色", account_id=str(account.id))
    if admin_role == "SVC":
        user = get_user(c, account.user_id)
        if user.email_hash is not None or user.phone_hash is not None:
            raise StateConflict("SVC 不得绑自然人账户（有邮箱 / 手机）",
                                reason="svc_must_be_natural_free")
    moment = _now(now)
    with c.cursor() as cur:
        try:
            cur.execute(
                f"""INSERT INTO role_bindings
                        (id, account_id, tenant_id, admin_role, scope, granted_by, approved_by,
                         expires_at, granted_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING {_ROLE_COLS}""",
                (uuid7(), account.id, account.tenant_id, admin_role, scope, granted_by,
                 approved_by, moment + timedelta(days=ROLE_RECLAIM_DAYS), moment),
            )
        except UniqueViolation as exc:
            raise StateConflict("该角色已存在未撤销的绑定", reason="role_already_bound",
                                admin_role=admin_role) from exc
        binding = _make(RoleBinding, _one(cur))
    # INV-06：角色变更 ⇒ session_epoch++，旧会话立即失效
    invalidate_sessions(c, account.id, reason=f"role_granted:{admin_role}",
                        now=now, trace_id=trace_id)
    return binding


def revoke_role(c, binding_id: uuid.UUID, *, reason: str = "revoked",
                actor_id: uuid.UUID | None = None, now: datetime | None = None,
                trace_id: str | None = None) -> RoleBinding:
    with c.cursor() as cur:
        cur.execute(f"SELECT {_ROLE_COLS} FROM role_bindings WHERE id = %s FOR UPDATE",
                    (binding_id,))
        row = _one(cur)
        if row is None:
            raise NotFound("角色绑定不存在", binding_id=str(binding_id))
        binding = _make(RoleBinding, row)
        if binding.revoked_at is not None:                 # 幂等
            return binding
        cur.execute(
            f"""UPDATE role_bindings SET revoked_at = %s, revoked_reason = %s
                 WHERE id = %s RETURNING {_ROLE_COLS}""",
            (_now(now), _text(reason, "reason", max_len=64), binding_id),
        )
        revoked = _make(RoleBinding, _one(cur))
    invalidate_sessions(c, revoked.account_id, reason="role_revoked", now=now, trace_id=trace_id)
    return revoked


def effective_roles(c, account_id: uuid.UUID, *, now: datetime | None = None) -> list[str]:
    """当前生效角色（未撤销且未到期）；默认拒绝——没有任何绑定即无权限。"""
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            """SELECT admin_role FROM role_bindings
                WHERE account_id = %s AND revoked_at IS NULL AND expires_at > %s
                ORDER BY admin_role""",
            (account_id, moment),
        )
        return [r[0] for r in cur.fetchall()]


def reclaim_expired_roles(c, *, now: datetime | None = None,
                          trace_id: str | None = None) -> list[uuid.UUID]:
    """90 天到期回收 job（可重放）：撤销到期绑定并让该账户会话失效。"""
    moment = _now(now)
    with c.cursor() as cur:
        cur.execute(
            """SELECT id, account_id FROM role_bindings
                WHERE revoked_at IS NULL AND expires_at <= %s FOR UPDATE""",
            (moment,),
        )
        rows = cur.fetchall()
    accounts: list[uuid.UUID] = []
    for binding_id, account_id in rows:
        revoke_role(c, binding_id, reason="expired", now=moment, trace_id=trace_id)
        if account_id not in accounts:
            accounts.append(account_id)
    return accounts


# --------------------------------------------------------------------------- tenant_quotas
def _upsert_quota(c, *, tenant_id: uuid.UUID, kind: str, value: int, policy_version: str,
                  key_id: int | None, now: datetime | None) -> dict:
    params_tail = [value, policy_version]
    with c.cursor() as cur:
        if key_id is None:
            cur.execute(
                "SELECT id FROM tenant_quotas WHERE tenant_id = %s AND kind = %s AND key_id IS NULL"
                " FOR UPDATE", (tenant_id, kind))
        else:
            cur.execute(
                "SELECT id FROM tenant_quotas WHERE tenant_id = %s AND kind = %s AND key_id = %s"
                " FOR UPDATE", (tenant_id, kind, key_id))
        row = cur.fetchone()
        if row is None:
            cur.execute(
                f"""INSERT INTO tenant_quotas (id, tenant_id, key_id, kind, value, policy_version)
                    VALUES (%s, %s, %s, %s, %s, %s) RETURNING {_QUOTA_COLS}""",
                (uuid7(), tenant_id, key_id, kind, value, policy_version))
        else:
            cur.execute(
                f"""UPDATE tenant_quotas SET value = %s, policy_version = %s
                     WHERE id = %s RETURNING {_QUOTA_COLS}""",
                (value, policy_version, row[0]))
        return _one(cur)


def set_quota(c, *, tenant_id: uuid.UUID, kind: str, value: int, policy_version: str,
              key_id: int | None = None, now: datetime | None = None) -> TenantQuota:
    """写配额（幂等 upsert）。``policy_version`` 必填：无快照不得计费（INV-07）。"""
    _check(kind, QUOTA_KINDS, "kind")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise InvalidArgument("配额值必须是非负整数", field="value")
    _text(policy_version, "policy_version", max_len=64)
    if key_id is not None:
        # 租户隔离：Key 级配额必须指向本租户的 Key（库层复合外键 + 这里给 40401）
        key = get_api_key(c, key_id)
        if key.account_id is None or key.tenant_id is None:
            raise StateConflict("存量原型 Key 无账户归属，不能挂配额", reason="legacy_key",
                                api_key_id=key_id)
        if key.tenant_id != tenant_id:
            raise NotFound("Key 不存在", api_key_id=key_id)
    return _make(TenantQuota, _upsert_quota(c, tenant_id=tenant_id, kind=kind, value=value,
                                            policy_version=policy_version, key_id=key_id,
                                            now=now))


def get_quotas(c, tenant_id: uuid.UUID, *, key_id: int | None = None) -> list[TenantQuota]:
    """取租户级 + （可选）Key 级配额行；返回顺序稳定（kind 升序）。"""
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT {_QUOTA_COLS} FROM tenant_quotas
                 WHERE tenant_id = %s AND (key_id IS NULL OR key_id = %s)
                 ORDER BY kind, key_id NULLS FIRST""",
            (tenant_id, key_id),
        )
        return [_make(TenantQuota, r) for r in _rows(cur)]


def effective_quotas(*, tenant: Sequence[TenantQuota] | Mapping[str, int],
                     key: Sequence[TenantQuota] | Mapping[str, int] | None = None,
                     node: Mapping[str, int] | None = None) -> dict[str, int]:
    """``生效配额 = min(租户, Key, 节点能力)``（INV-07）；缺的档位视为无该档上限。"""
    def as_map(source) -> dict[str, int]:
        if isinstance(source, Mapping):
            return {str(k): int(v) for k, v in source.items()}
        return {row.kind: int(row.value) for row in source}

    layers = [as_map(tenant)]
    if key:
        layers.append(as_map(key))
    if node:
        layers.append(as_map(node))
    kinds: set[str] = set()
    for layer in layers:
        kinds.update(layer)
    return {kind: min(layer[kind] for layer in layers if kind in layer) for kind in sorted(kinds)}


def quota_snapshot(c, tenant_id: uuid.UUID, *, key_id: int | None = None,
                   node_caps: Mapping[str, int] | None = None) -> dict:
    """M01 §6.5 返回体：``{quotas[], policy_version, effective}``（60 s 缓存由调用方负责）。"""
    rows = get_quotas(c, tenant_id, key_id=key_id)
    tenant_rows = [r for r in rows if r.key_id is None]
    key_rows = [r for r in rows if r.key_id is not None]
    if not tenant_rows:
        raise QuotaSnapshotMissing("配额快照缺失", tenant_id=str(tenant_id))
    versions = {r.policy_version for r in tenant_rows + key_rows}
    if len(versions) != 1:
        raise QuotaSnapshotMissing("policy_version 不一致，禁止计费",
                                   tenant_id=str(tenant_id), versions=sorted(versions))
    effective = effective_quotas(tenant=tenant_rows, key=key_rows, node=node_caps)
    return {
        "tenant_id": str(tenant_id),
        "key_id": key_id,
        "policy_version": versions.pop(),
        "quotas": [{"key_id": r.key_id, "kind": r.kind, "value": int(r.value)}
                   for r in tenant_rows + key_rows],
        "effective": effective,
    }
