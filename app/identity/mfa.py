# SPDX-License-Identifier: Apache-2.0
"""MFA 因子生命周期（M01 §3 mfa_state、§8.2；spec `LoginRequest.mfa_code`）。

``users.mfa_state``：``none`` → ``pending``（已登记因子，待确认）→ ``enabled``；
``enabled`` 也可回 ``none``（关闭）。因子本身**只存 scrypt 派生串 + salt**，
明文不出现在库、日志、事件里（``credentials.hash_factor``）。

S1 的因子是 6 位 PIN（低熵，靠 scrypt + 5 次锁定 + 15 分钟冷处理）；
TOTP / 硬件密钥需要共享密钥托管在 KMS（M16），接入后只换 ``credentials`` 里两个函数，
状态机与接口不变——这是刻意的分层。
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime

from . import clock, credentials, errors, models

PIN_RE = re.compile(r"^\d{%d}$" % models.MFA_PIN_MIN_DIGITS)


def _now(now: datetime | None) -> datetime:
    return now.astimezone(clock.utcnow().tzinfo) if now else clock.utcnow()


def _check_pin(pin: str | None) -> str:
    if pin is None or not PIN_RE.match(pin):
        raise models.InvalidArgument(
            f"MFA 因子必须是 {models.MFA_PIN_MIN_DIGITS} 位数字", field="mfa_code")
    return pin


def enroll(c, account_id: uuid.UUID, pin: str, *, now: datetime | None = None) -> None:
    """登记因子：none → pending（此时登录仍不要求 MFA，需 ``confirm`` 才算启用）。"""
    _check_pin(pin)
    account = models.get_account(c, account_id)
    models.assert_writable(account, action="登记 MFA")
    auth = models.get_user_auth(c, account.user_id, for_update=True)
    if auth.mfa_state == "enabled":
        raise models.StateConflict("MFA 已启用：先关闭再重新登记", reason="mfa_already_enabled")
    stored, salt = credentials.hash_factor(pin)
    with c.cursor() as cur:
        cur.execute(
            """UPDATE users SET mfa_state = 'pending', mfa_secret_hash = %s,
                                mfa_salt = %s, mfa_enabled_at = NULL
                WHERE id = %s""",
            (stored, salt, account.user_id))


def confirm(c, account_id: uuid.UUID, pin: str, *,
            now: datetime | None = None) -> datetime:
    """确认因子：pending → enabled。返回启用时间。"""
    _check_pin(pin)
    moment = _now(now)
    account = models.get_account(c, account_id)
    auth = models.get_user_auth(c, account.user_id, for_update=True)
    if auth.mfa_state == "none":
        raise errors.MfaNotEnabled("尚未登记 MFA 因子", reason="mfa_not_enrolled")
    if not credentials.verify_factor(auth.mfa_secret_hash, pin):
        raise errors.LoginCredentialError("MFA 因子不匹配", reason="invalid_mfa_code")
    with c.cursor() as cur:
        cur.execute(
            """UPDATE users SET mfa_state = 'enabled', mfa_enabled_at = %s
                WHERE id = %s""",
            (moment, account.user_id))
    return moment


def disable(c, account_id: uuid.UUID, pin: str, *, now: datetime | None = None) -> None:
    """关闭 MFA：enabled/pending → none，并清空因子（不留残余）。"""
    _check_pin(pin)
    account = models.get_account(c, account_id)
    auth = models.get_user_auth(c, account.user_id, for_update=True)
    if auth.mfa_state == "none":
        raise errors.MfaNotEnabled("MFA 未启用", reason="mfa_not_enabled")
    if not credentials.verify_factor(auth.mfa_secret_hash, pin):
        raise errors.LoginCredentialError("MFA 因子不匹配", reason="invalid_mfa_code")
    with c.cursor() as cur:
        cur.execute(
            """UPDATE users SET mfa_state = 'none', mfa_secret_hash = NULL, mfa_salt = NULL,
                                mfa_enabled_at = NULL
                WHERE id = %s""",
            (account.user_id,))


def verify(c, account_id: uuid.UUID, pin: str) -> bool:
    """只校验不迁移状态（供 tokens.step_up 等复用）。"""
    account = models.get_account(c, account_id)
    auth = models.get_user_auth(c, account.user_id)
    return auth.mfa_state == "enabled" and credentials.verify_factor(auth.mfa_secret_hash, pin)


def status(c, account_id: uuid.UUID) -> dict:
    """脱敏状态视图：只回状态与启用时间，永不回因子。"""
    account = models.get_account(c, account_id)
    auth = models.get_user_auth(c, account.user_id)
    return {"mfa_state": auth.mfa_state,
            "mfa_enabled_at": auth.mfa_enabled_at.isoformat() if auth.mfa_enabled_at else None}


__all__ = ["PIN_RE", "enroll", "confirm", "disable", "verify", "status"]
