# SPDX-License-Identifier: Apache-2.0
"""M14 领域策略：状态机 / 双人复核 / 签名链接 / 沙箱窗口。

**不变量落地位置**（INV 编号见 M14 §3）::

    INV-04  导出：>1000 行或含个人信息 → 双人复核；链接 TTL ≤15 分钟 + 一次性；水印
    INV-05  删除 30 天办结；保留任务 report 必含「已删 / 部分保留 / 最迟清除日 / 方式」
    INV-07  保留任务 (object, cutoff) 唯一 + 失败可重放
    INV-09  只读沙箱 ≤4h、不得回写生产
    INV-11  升级完成判据不由 M14 判定（只展示）

签名链接（下载）：``token = base64url(payload) + "." + base64url(HMAC-SHA256)``。
密钥只从注入参数 / 环境取得，绝不落库、绝不进日志；token 解码后仍要校验
(state=done / 未过期 / 一次性)；一次性消费由 ``store`` 的 ``link_consumed_at`` 保证。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta
from typing import Any, Mapping

from . import clock, errors, facts, ids

__all__ = [
    "assert_transition", "dual_review_required", "resolve_export_max_rows",
    "link_ttl_seconds", "mint_download_token", "verify_download_token", "make_watermark",
    "retention_cutoff", "retention_policy_days", "batch_dual_review_required",
    "sandbox_expires_at", "assert_sandbox_read_only", "link_secret_from_env",
]


# ───────────────────────────────────────────────────────────── 状态机
def assert_transition(table: str, current: str, target: str) -> None:
    """非法迁移 → 40901（域层先判；库层触发器是最后一道防线）。"""
    mapping = (facts.EXPORT_TRANSITIONS if table == "export"
               else facts.RETENTION_TRANSITIONS)
    allowed = mapping.get(current)
    if allowed is None:
        raise errors.Conflict(f"未知状态：{current}", reason="unknown_state")
    if target not in allowed:
        raise errors.Conflict(
            f"非法状态迁移：{current} → {target}（{table}）", reason="illegal_transition")


# ───────────────────────────────────────────────────────────── 导出策略（INV-04）
def dual_review_required(estimated_rows: int, contains_personal_data: bool) -> bool:
    return bool(contains_personal_data or estimated_rows > facts.EXPORT_LARGE_ROWS)


def resolve_export_max_rows(configured: Any) -> int:
    """M10 ``data.export_max_rows``（默认 200000，范围 1000–1000000）；配置坏了回到默认。"""
    if isinstance(configured, bool) or not isinstance(configured, int):
        return facts.EXPORT_MAX_ROWS_DEFAULT
    if not (facts.EXPORT_MAX_ROWS_MIN <= configured <= facts.EXPORT_MAX_ROWS_MAX):
        return facts.EXPORT_MAX_ROWS_DEFAULT
    return configured


def link_ttl_seconds(configured: Any) -> int:
    """``data.export_link_ttl_min``：配置 5–60 分钟，但实现硬上限 15 分钟（INV-04）。"""
    default = facts.EXPORT_LINK_TTL_DEFAULT_S
    if isinstance(configured, bool) or not isinstance(configured, int):
        return default
    seconds = configured * 60
    if seconds <= 0:
        return default
    return min(seconds, facts.EXPORT_LINK_TTL_MAX_S)


def make_watermark(export_no: str, requester: str, moment: datetime) -> str:
    """文件水印：单号 + 请求人短码 + 时间。**不含** PII / 全量标识。"""
    digest = hashlib.sha256(requester.encode("utf-8")).hexdigest()[:8]
    stamp = clock.as_utc(moment).strftime("%Y%m%dT%H%M%SZ")
    return f"{facts.WATERMARK_PREFIX} {export_no} {digest} {stamp}"[:facts.MAX_WATERMARK_LEN]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(payload: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, payload, hashlib.sha256).digest()


def mint_download_token(export_id: str, *, now: datetime, ttl_s: int,
                        secret: bytes) -> tuple[str, datetime, str]:
    """签名一次性链接 token；返回 (token, expires_at, jti)。"""
    ttl = max(1, min(int(ttl_s), facts.EXPORT_LINK_TTL_MAX_S))
    expires_at = clock.as_utc(now) + timedelta(seconds=ttl)
    jti = secrets.token_hex(16)
    payload = {
        "eid": export_id,
        "exp": int(expires_at.timestamp()),
        "jti": jti,
        "use": 1,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    token = f"{_b64(raw)}.{_b64(_sign(raw, secret))}"
    return token, expires_at, jti


def verify_download_token(token: str, *, secret: bytes, now: datetime) -> dict[str, Any]:
    """验签 + 过期校验；失败一律 40901（不泄露签名细节）。"""
    if not isinstance(token, str) or token.count(".") != 1:
        raise errors.Conflict("下载链接无效或已被使用", reason="link_invalid")
    encoded, signature = token.split(".", 1)
    try:
        raw = _unb64(encoded)
        provided = _unb64(signature)
    except (ValueError, TypeError):
        raise errors.Conflict("下载链接无效或已被使用", reason="link_invalid") from None
    if not hmac.compare_digest(provided, _sign(raw, secret)):
        raise errors.Conflict("下载链接无效或已被使用", reason="link_invalid")
    try:
        payload = json.loads(raw.decode("utf-8"))
        export_id = str(payload["eid"])
        expires_ts = int(payload["exp"])
        jti = str(payload["jti"])
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise errors.Conflict("下载链接无效或已被使用", reason="link_invalid") from None
    if expires_ts <= int(clock.as_utc(now).timestamp()):
        raise errors.Conflict("下载链接已过期：请重新获取（≤15 分钟）",
                              reason="link_expired")
    return {"export_id": export_id, "expires_at": expires_ts, "jti": jti}


def link_secret_from_env(value: str | None = None) -> bytes:
    """链接签名密钥：环境 / 注入；缺省用进程内随机（S1 本机），绝不写日志。"""
    import os

    resolved = value or os.environ.get("DJB_EXPORT_LINK_SECRET") or ""
    if resolved:
        return resolved.encode("utf-8")
    return secrets.token_bytes(32)


# ───────────────────────────────────────────────────────────── 保留（INV-05 / INV-07）
def retention_policy_days(object_name: str, provided: int | None = None) -> int:
    if provided is not None:
        return provided
    return facts.RETENTION_POLICY_DAYS[object_name]


def retention_cutoff(now: datetime, policy_days: int) -> datetime:
    """cutoff 取 (now - policy_days) 的 **UTC 日界**：同一天重复触发天然同键（幂等）。"""
    return clock.start_of_utc_day(clock.as_utc(now) - timedelta(days=policy_days))


# ───────────────────────────────────────────────────────────── 批量 / 沙箱（INV-03 / INV-09）
def batch_dual_review_required(count: int, action_type: str) -> bool:
    return count > facts.BATCH_DUAL_REVIEW_ITEMS or action_type in facts.DUAL_REVIEW_ACTIONS


def sandbox_expires_at(now: datetime, ttl_s: int | None = None) -> datetime:
    ttl = facts.SANDBOX_MAX_S if not ttl_s else min(int(ttl_s), facts.SANDBOX_MAX_S)
    return clock.as_utc(now) + timedelta(seconds=max(1, ttl))


def assert_sandbox_read_only(session: Mapping[str, Any], *, now: datetime,
                             write: bool = False) -> None:
    """只读沙箱：过期 / 非只读 / 尝试回写 → 40301（INV-09，不得回写生产）。"""
    if not isinstance(session, Mapping) or not session.get("read_only", False):
        raise errors.Forbidden("只读沙箱会话不可回写生产", reason="sandbox_read_only")
    expires_at = session.get("expires_at")
    if isinstance(expires_at, str):
        expires_at = clock.parse_datetime(expires_at, field="expires_at")
    if not isinstance(expires_at, datetime) or clock.as_utc(now) >= clock.as_utc(expires_at):
        raise errors.Forbidden("只读沙箱会话已过期（≤4h）", reason="sandbox_expired")
    if write:
        raise errors.Forbidden("只读沙箱会话只读：写操作被拒绝", reason="sandbox_read_only")
