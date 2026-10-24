# SPDX-License-Identifier: AGPL-3.0-or-later
"""凭据与隐私原语：指纹再哈希、客户端密钥、疑似凭据字段扫描（INV-03 / INV-04 / INV-10）。

铁律：

* **明文只出现一次**：客户端密钥 / 绑定码的明文只在响应里出现一次；库里只有 ``sha256``
  与 8 位前缀；日志里**永远**不出现明文（连前缀都只在排障字段里出现）。
* **指纹只存哈希**（INV-03）：客户端上报的已经是哈希，服务端**再哈希**一次，明文不入库、
  不回传、不进日志与事件。
* **服务端不接收凭据本体**（INV-04）：疑似凭据字段（``key``/``secret``/``token``/
  ``password``/``credential`` 等且值 ≥16 字符）→ 400 + 告警，**丢弃字段且不落值**；
  ``credential_handle`` 是白名单字段（只登记句柄，不解析）。
* 一切比较用 ``hmac.compare_digest``（常数时间）。
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import Any, Mapping

from . import facts
from .errors import CredentialFieldRejected, InvalidArgument

_FINGERPRINT_RE = re.compile(r"^[0-9A-Za-z_:+./@=-]+$")


# --------------------------------------------------------------------------- 指纹（INV-03）
def hash_fingerprint(raw: str) -> str:
    """硬件指纹哈希（客户端本地算好的哈希）→ 服务端**再哈希**后的入库形态。"""
    return hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()


def normalize_fingerprint(raw: Any) -> str:
    """校验并归一化上报的指纹哈希；非法即 40001（INV-03）。"""
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidArgument("hardware_fingerprint 必填", field="hardware_fingerprint")
    value = raw.strip()
    if not facts.FINGERPRINT_MIN_LEN <= len(value) <= facts.FINGERPRINT_MAX_LEN:
        raise InvalidArgument("hardware_fingerprint 长度不合法", field="hardware_fingerprint")
    if not _FINGERPRINT_RE.match(value):
        raise InvalidArgument("hardware_fingerprint 含非法字符", field="hardware_fingerprint")
    return value


# --------------------------------------------------------------------------- 客户端密钥（INV-10）
def hash_secret(plaintext: str) -> str:
    """``sha256`` 十六进制：密钥 / 绑定码的唯一入库形态。"""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def new_client_key() -> tuple[str, str, str]:
    """生成客户端密钥：返回 ``(明文, 8 位前缀, sha256)``。明文只允许出现在响应里一次。"""
    plaintext = secrets.token_urlsafe(facts.KEY_ENTROPY_BYTES)
    return plaintext, plaintext[:facts.KEY_PREFIX_LEN], hash_secret(plaintext)


def new_binding_code() -> tuple[str, str]:
    """生成一次性绑定码：返回 ``(明文, sha256)``；明文只在签发响应里出现一次。"""
    plaintext = secrets.token_urlsafe(facts.BINDING_CODE_ENTROPY_BYTES)
    return plaintext, hash_secret(plaintext)


def key_matches(plaintext: str, stored_hash: str | None) -> bool:
    """常数时间比较（避免计时侧信道）。"""
    if not plaintext or not stored_hash:
        return False
    return hmac.compare_digest(hash_secret(plaintext), stored_hash)


# --------------------------------------------------------------------------- 疑似凭据字段扫描（INV-04）
def _segment_is_suspect(segment: str) -> bool:
    lowered = segment.strip().lower()
    if not lowered:
        return False
    if lowered in facts.CREDENTIAL_FIELD_ALLOWLIST:
        return False
    if lowered in facts.SUSPECT_CREDENTIAL_FIELDS:
        return True
    for suspect in facts.SUSPECT_CREDENTIAL_FIELDS:
        if lowered.endswith("_" + suspect) or lowered.startswith(suspect + "_"):
            return True
    return False


def _iter_fields(value: Any, path: str = ""):
    if isinstance(value, Mapping):
        for name, item in value.items():
            child = f"{path}.{name}" if path else str(name)
            yield str(name), item, child
            yield from _iter_fields(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_fields(item, f"{path}[{index}]")


def suspect_fields(body: Mapping[str, Any] | None) -> tuple[str, ...]:
    """返回疑似凭据字段的**路径**（如 ``upstream.api_key``）；**绝不返回值**。

    判定（M02 INV-04）：字段名任一 underscore / dash / dot / 方括号分段命中凭据词，
    且值是字符串且长度 ≥ ``SECRET_VALUE_MIN_LEN``。
    """
    if not isinstance(body, Mapping):
        return ()
    found: list[str] = []
    for name, value, path in _iter_fields(body):
        if not isinstance(value, str) or len(value) < facts.SECRET_VALUE_MIN_LEN:
            continue
        if _segment_is_suspect(name) or _segment_is_suspect(path.rsplit(".", 1)[-1]):
            found.append(path)
    return tuple(dict.fromkeys(found))


def scan_credentials(body: Mapping[str, Any] | None) -> None:
    """疑似凭据 → 40001 + 只报字段名（值被调用方丢弃，不落库、不进日志）。"""
    fields = suspect_fields(body)
    if fields:
        raise CredentialFieldRejected(
            "请求疑似包含凭据本体：请只提交 credential_handle（H1 / INV-04）",
            fields=list(fields))


__all__ = [
    "hash_fingerprint", "normalize_fingerprint", "hash_secret", "new_client_key",
    "new_binding_code", "key_matches", "suspect_fields", "scan_credentials",
]
