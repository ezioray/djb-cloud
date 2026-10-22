# SPDX-License-Identifier: Apache-2.0
"""凭据派生：口令 / MFA 因子 / 会话令牌。**任何明文都不入库、不入日志。**

算法选择（09 安全：密钥只以引用出现；无 KMS 时不引入外部依赖）：
- 口令与 6 位 MFA 因子：``scrypt``（Python 标准库 ``hashlib.scrypt``），入库串固定形如
  ``scrypt$n=16384,r=8,p=1$<salt_hex>$<hash_hex>``，可直接被库层 CHECK 校验形状。
  scrypt 自带内存硬度，对 6 位 PIN 这种低熵因子同样适用（单次约 80 ms，配合 5 次锁定）。
- 会话令牌：``secrets.token_urlsafe(32)``（256 bit），库中只存 ``sha256`` 十六进制。
- 一切比较用 ``hmac.compare_digest``（常数时间），避免计时侧信道。

TOTP / 硬件因子留待 M16 KMS 接入后替换（共享密钥必须在 KMS 内，不进 DB）；
S1 用 PIN 因子 + 失败锁定，语义与 ``mfa_state`` 五态不变。
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16
TOKEN_ENTROPY_BYTES = 32
_PREFIX_RE = re.compile(r"^scrypt\$n=(\d+),r=(\d+),p=(\d+)\$([0-9a-f]+)\$([0-9a-f]+)$")


def _scrypt(secret: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=SCRYPT_DKLEN, maxmem=64 * 1024 * 1024)


def hash_password(password: str) -> str:
    """口令 → 自描述派生串（含 salt 与参数，便于将来换参数）。"""
    if not password:
        raise ValueError("password 不得为空")
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _scrypt(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return f"scrypt$n={SCRYPT_N},r={SCRYPT_R},p={SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(stored: str | None, password: str | None) -> bool:
    """常数时间校验；存储串损坏或为空一律 False（不抛异常，避免区分失败原因）。"""
    if not stored or password is None:
        return False
    match = _PREFIX_RE.match(stored)
    if match is None:
        return False
    n, r, p, salt_hex, digest_hex = match.groups()
    try:
        expected = bytes.fromhex(digest_hex)
        actual = _scrypt(password, bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p))
    except (ValueError, MemoryError):                    # pragma: no cover - 参数被改坏
        return False
    return hmac.compare_digest(actual, expected)


def hash_factor(pin: str) -> tuple[str, str]:
    """MFA 因子 → ``(scrypt 串, salt_hex)``；salt 单独存一列便于库层 CHECK 形状。"""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _scrypt(pin, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return (f"scrypt$n={SCRYPT_N},r={SCRYPT_R},p={SCRYPT_P}${salt.hex()}${digest.hex()}",
            salt.hex())


def verify_factor(stored: str | None, pin: str | None) -> bool:
    """与 :func:`verify_password` 同款校验（MFA 因子复用同一派生参数）。"""
    return verify_password(stored, pin)


def new_token() -> tuple[str, str]:
    """不透明令牌 → ``(明文, sha256)``。明文只出现在响应里一次。"""
    plaintext = secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)
    return plaintext, token_hash(plaintext)


def token_hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def normalize_identifier(identifier: str) -> str:
    """登录标识归一（邮箱大小写 / 手机号空格），与 ``models.hash_pii`` 口径一致。"""
    return identifier.strip().lower()


__all__ = [
    "hash_password", "verify_password", "hash_factor", "verify_factor",
    "new_token", "token_hash", "normalize_identifier",
    "SCRYPT_N", "SCRYPT_R", "SCRYPT_P", "SCRYPT_DKLEN", "SALT_BYTES", "TOKEN_ENTROPY_BYTES",
]
