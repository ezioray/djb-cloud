# SPDX-License-Identifier: AGPL-3.0-or-later
"""bundle 签名（S2 过渡期 HMAC-SHA256；S3 换 Ed25519）。

铁律（M18 §10 / INV-04 同口径）：

* 密钥**只从环境变量** :data:`facts.SIGNING_KEY_ENV` 读，不落库、不写日志、不进响应、
  不进 argv；未配置 / 过短（< 32 字符）一律按「未配置」处理 → 发布 fail-closed（503/50001）；
* 签名对象是 **payload 的 sha256 十六进制**（canonical JSON 的函数），不是 payload 本身：
  客户端可先校验 payload_hash 再验签，两步都可复算；
* 验签用 ``hmac.compare_digest``（常数时间），失败只回 ``signature_invalid``，
  **不回显期望签名**（防签名预言机）。
"""
from __future__ import annotations

import hashlib
import hmac
import os

from . import facts
from .errors import FeatureUnavailable

__all__ = ["load_key", "key_configured", "sign", "verify", "signature_of"]


def load_key() -> bytes:
    """读签名密钥；未配置 / 过短 → 503 + 50001（fail-closed，不回落明文签名）。"""
    raw = (os.environ.get(facts.SIGNING_KEY_ENV) or "").strip()
    if len(raw) < facts.SIGNING_KEY_MIN_LEN:
        raise FeatureUnavailable(
            f"签名密钥未配置（{facts.SIGNING_KEY_ENV} 缺失或短于 "
            f"{facts.SIGNING_KEY_MIN_LEN} 字符）：发布 fail-closed",
            reason="signing_key_missing")
    return raw.encode("utf-8")


def key_configured() -> bool:
    """只读探测（不返回密钥本身；给 health / 证据用）。"""
    return len((os.environ.get(facts.SIGNING_KEY_ENV) or "").strip()) >= facts.SIGNING_KEY_MIN_LEN


def signature_of(payload_hash: str, *, key: bytes | None = None) -> str:
    """``hmac-sha256:<64 hex>``（签名对象 = payload_hash 字符串本身）。"""
    if not isinstance(payload_hash, str) or not payload_hash.strip():
        raise ValueError("payload_hash 必填")
    material = key if key is not None else load_key()
    digest = hmac.new(material, payload_hash.strip().encode("utf-8"),
                      hashlib.sha256).hexdigest()
    return facts.SIGNING_PREFIX + digest


def sign(payload_hash: str) -> str:
    """发布用：算签名（密钥未配置 → 503/50001）。"""
    return signature_of(payload_hash)


def verify(payload_hash: str, signature: str, *, key: bytes | None = None) -> bool:
    """验签（常数时间）。任何形态错误 → ``False``，不抛异常、不回显期望值。"""
    if not isinstance(payload_hash, str) or not isinstance(signature, str):
        return False
    text = signature.strip()
    if not text.startswith(facts.SIGNING_PREFIX):
        return False
    try:
        material = key if key is not None else load_key()
    except FeatureUnavailable:
        return False
    expected = hmac.new(material, payload_hash.strip().encode("utf-8"),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(text[len(facts.SIGNING_PREFIX):], expected)
