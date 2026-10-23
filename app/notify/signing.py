# SPDX-License-Identifier: Apache-2.0
"""M12 Webhook 签名与密钥（INV-05）。

签名串（规格 §3 INV-05 / §6.3，与产品 §12.5.2 的 API 签名窗口同口径）::

    X-DJB-Signature: sha256=HMAC_SHA256(secret, timestamp + "." + body)
    X-DJB-Timestamp: <unix 秒>
    X-DJB-Event:     <事件名>

要点：

* **原始 body 参与验签**（不重排 JSON、不补空格）；调用方必须传发送时的字节；
* 时间戳偏差 ≤ ``SIGNATURE_WINDOW_S``（300 s），超出即拒（防重放）；
* 比较用 :func:`hmac.compare_digest`（常量时间），失败不区分「格式错」与「密钥错」的措辞；
* ``secret`` 只在创建订阅时生成一次返回，服务端只保留 :func:`hash_secret`（SHA-256 十六进制）。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets as _secrets
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from . import clock, facts

__all__ = [
    "SIGNATURE_HEADER", "TIMESTAMP_HEADER", "EVENT_HEADER", "VerifyResult",
    "new_secret", "hash_secret", "build_signature", "sign_headers", "verify_signature",
    "body_bytes", "headers_of",
]

SIGNATURE_HEADER = "X-DJB-Signature"
TIMESTAMP_HEADER = "X-DJB-Timestamp"
EVENT_HEADER = "X-DJB-Event"

#: 32 字节随机 → 43 字符 base64url（无填充）；足够 256-bit 熵
SECRET_BYTES = 32


@dataclass(frozen=True)
class VerifyResult:
    """验签结果：``reason`` 是短码（``ok`` 表示通过）。"""

    ok: bool
    reason: str

    def __bool__(self) -> bool:                                   # pragma: no cover - 便利
        return self.ok


def new_secret() -> str:
    """生成一次性订阅密钥（只在创建响应里出现一次；不落库、不打日志）。"""
    return _secrets.token_urlsafe(SECRET_BYTES)


def hash_secret(secret: str) -> str:
    """服务端只存这个：``sha256(secret)`` 十六进制（与 1203 的 CHECK 形状一致）。"""
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret 必须是非空字符串")
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def body_bytes(body: Any) -> bytes:
    """统一 body 口径：``str`` 按 UTF-8 编码，``bytes`` 原样（原始 body 参与验签）。"""
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    raise TypeError(f"body 必须是 str 或 bytes：{type(body).__name__}")


def _timestamp_text(timestamp: Any, *, now: datetime | None = None) -> str:
    if isinstance(timestamp, datetime):
        moment = clock.to_utc(timestamp)
        return str(int(moment.timestamp()))
    if now is not None and timestamp in (None, ""):
        return str(int(clock.to_utc(now).timestamp()))
    return str(timestamp)


def build_signature(secret: str, timestamp: Any, body: Any) -> str:
    """``sha256=HMAC_SHA256(secret, timestamp + "." + body)``（返回含 ``sha256=`` 前缀）。"""
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret 不能为空")
    message = f"{_timestamp_text(timestamp)}.".encode("utf-8") + body_bytes(body)
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"{facts.SIGNATURE_ALG}={digest}"


def sign_headers(secret: str, event: str, body: Any, *,
                 timestamp: int | None = None, now: datetime | None = None) -> dict[str, str]:
    """生成三个签名头（§6.3）。``timestamp`` 缺省取 ``now``（测试可注入固定时刻）。"""
    moment = clock.to_utc(now) if now is not None else clock.now()
    stamp = int(moment.timestamp()) if timestamp is None else int(timestamp)
    return {
        SIGNATURE_HEADER: build_signature(secret, stamp, body),
        TIMESTAMP_HEADER: str(stamp),
        EVENT_HEADER: event,
    }


def headers_of(headers: Mapping[str, str]) -> tuple[str | None, str | None, str | None]:
    """从请求头里取签名三元组（大小写不敏感）。"""
    lowered = {str(key).lower(): value for key, value in headers.items()}
    return (lowered.get(SIGNATURE_HEADER.lower()),
            lowered.get(TIMESTAMP_HEADER.lower()),
            lowered.get(EVENT_HEADER.lower()))


def verify_signature(secret: str, timestamp: Any, body: Any, signature: str, *,
                     now: datetime | None = None,
                     tolerance: int = facts.SIGNATURE_WINDOW_S) -> VerifyResult:
    """校验对端/来件签名：算法、时间窗（±300 s）、常量时间比较。

    ``reason`` 短码：``ok`` / ``malformed_signature`` / ``unsupported_alg`` /
    ``timestamp_invalid`` / ``timestamp_out_of_window`` / ``signature_mismatch``。
    """
    if not isinstance(signature, str) or "=" not in signature:
        return VerifyResult(False, "malformed_signature")
    alg, _, digest = signature.partition("=")
    if alg.strip().lower() != facts.SIGNATURE_ALG:
        return VerifyResult(False, "unsupported_alg")
    try:
        stamp = int(str(timestamp).strip())
    except (TypeError, ValueError):
        return VerifyResult(False, "timestamp_invalid")
    current = int(clock.to_utc(now).timestamp()) if now is not None else int(time.time())
    if abs(current - stamp) > int(tolerance):
        return VerifyResult(False, "timestamp_out_of_window")
    expected = build_signature(secret, stamp, body)
    if not hmac.compare_digest(expected, f"{facts.SIGNATURE_ALG}={digest.strip()}"):
        return VerifyResult(False, "signature_mismatch")
    return VerifyResult(True, "ok")
