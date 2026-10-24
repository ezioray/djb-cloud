# SPDX-License-Identifier: AGPL-3.0-or-later
"""双签收据的规范串与 HMAC-SHA256 验签（M05 §8.2 / 04-api-contracts CR-2 / INV-01）。

钉死的三件事（CR-2 已裁决，写进 04/02，不许各端各自实现）：

1. **算法**：``hmac-sha256:`` 前缀 + 64 位小写十六进制摘要；
2. **字段顺序**：``receipt_id, task_id, access, usage_amount, usage_unit, price_amount``；
3. **原样字符串**：直接用上报文本拼接（``usage_amount="1000"`` 与 ``"1000.0"`` 是**不同**的
   规范串），绝不使用 DB ``NUMERIC`` 回读值重新格式化。

两侧密钥**必须不同**（INV-01：供方与需方各持一把，单方无法伪造双侧签名）；密钥只以
「引用」形式注入——默认读两个环境变量（与 legacy ``app/receipt.py`` 同款密钥引用方式），
合并时由 Lead 换成 KMS / Secret 提供者。**任何日志、异常、事件都不带密钥或签名原文。**
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping, NamedTuple

from . import errors, facts

log = logging.getLogger("djb.metering.signing")

#: 密钥环境变量名（**引用**，不是值；凭据不入库、不入日志、不进仓库）
ENV_PROVIDER_KEY = "DJB_M05_RECEIPT_PROVIDER_KEY"
ENV_CONSUMER_KEY = "DJB_M05_RECEIPT_CONSUMER_KEY"


class SignatureKeys(NamedTuple):
    """两侧独立密钥。"""

    provider: bytes
    consumer: bytes


#: ``provider() -> SignatureKeys | Mapping[str, bytes|str] | None``
KeysProvider = Callable[[], "SignatureKeys | Mapping[str, Any] | None"]


def _env_keys() -> SignatureKeys | None:
    raw_provider = os.environ.get(ENV_PROVIDER_KEY)
    raw_consumer = os.environ.get(ENV_CONSUMER_KEY)
    if not raw_provider or not raw_consumer:
        return None
    return SignatureKeys(raw_provider.encode(), raw_consumer.encode())


_keys_provider: KeysProvider | None = None


def set_keys_provider(provider: KeysProvider | None) -> None:
    """注入密钥提供者（测试 / KMS 接线）；传 None 恢复默认（环境变量引用）。"""
    global _keys_provider
    _keys_provider = provider


def current_keys_provider() -> KeysProvider | None:
    return _keys_provider


def _as_keys(raw: Any) -> SignatureKeys | None:
    if raw is None:
        return None
    if isinstance(raw, SignatureKeys):
        return raw
    if isinstance(raw, Mapping):
        provider = raw.get("provider")
        consumer = raw.get("consumer")
        if provider is None or consumer is None:
            return None
        return SignatureKeys(
            provider.encode() if isinstance(provider, str) else bytes(provider),
            consumer.encode() if isinstance(consumer, str) else bytes(consumer))
    return None


def resolve_keys(provider: KeysProvider | None = None) -> SignatureKeys:
    """取两侧密钥；未接线 / 为空 / 两侧相同 / 过短 → :class:`KeysUnavailable`（fail-closed）。"""
    active = provider if provider is not None else _keys_provider
    keys = _as_keys(active()) if active is not None else _env_keys()
    if keys is None:
        raise errors.KeysUnavailable(
            "双签密钥未接线：需要供方与需方各一把独立密钥（M05 INV-01）")
    if not keys.provider or not keys.consumer:
        raise errors.KeysUnavailable("双签密钥有空值（M05 INV-01）")
    if hmac.compare_digest(keys.provider, keys.consumer):
        raise errors.KeysUnavailable("供方与需方密钥相同：单方即可伪造双侧签名（M05 INV-01）")
    if min(len(keys.provider), len(keys.consumer)) < facts.SIGNATURE_MIN_KEY_BYTES:
        raise errors.KeysUnavailable(
            f"签名密钥长度不足 {facts.SIGNATURE_MIN_KEY_BYTES} 字节（不满足 HMAC-SHA256 基线）")
    return keys


def canonical_string(fields: Mapping[str, Any]) -> str:
    """按固定顺序拼 6 个规范字段的**原样字符串**（M05 §8.2）。"""
    parts: list[str] = []
    for name in facts.CANONICAL_FIELDS:
        if name not in fields:
            raise errors.InvalidArgument(f"缺规范字段 {name}（M05 §8.2）", field=name)
        raw = fields[name]
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            # 数值也按「上报原样」的语义转成文本（调用方应已保留原字符串）
            raw = str(raw)
        if not isinstance(raw, str):
            raise errors.InvalidArgument(f"规范字段 {name} 必须是字符串", field=name)
        if "\n" in raw or "\r" in raw:
            raise errors.InvalidArgument(f"规范字段 {name} 不得包含换行", field=name)
        parts.append(raw)
    return facts.CANONICAL_SEPARATOR.join(parts)


def digest(key: bytes, payload: str) -> str:
    """``hmac-sha256:<hex>``（小写）。"""
    return facts.SIGNATURE_PREFIX + hmac.new(key, payload.encode("utf-8"),
                                             hashlib.sha256).hexdigest()


def sign(fields: Mapping[str, Any], keys: SignatureKeys) -> dict[str, str]:
    """产出两侧签名（测试 / M15 客户端参考实现；服务端只验不算）。"""
    payload = canonical_string(fields)
    return {"sig_provider": digest(keys.provider, payload),
            "sig_consumer": digest(keys.consumer, payload)}


def _well_formed(signature: Any) -> bool:
    if not isinstance(signature, str):
        return False
    if not signature.startswith(facts.SIGNATURE_PREFIX):
        return False
    body = signature[len(facts.SIGNATURE_PREFIX):]
    return len(body) == facts.SIG_HEX_LEN and all(c in "0123456789abcdef" for c in body)


@dataclass(frozen=True)
class SignatureCheck:
    """验签结果（**不含**签名原文与密钥；只给原因码，便于安全日志）。"""

    ok: bool
    reason: str | None = None
    side: str | None = None

    def as_detail(self) -> dict[str, Any]:
        return {"signature_side": self.side, "signature_reason": self.reason}


def verify_pair(fields: Mapping[str, Any], *, sig_provider: Any, sig_consumer: Any,
                keys: SignatureKeys) -> SignatureCheck:
    """双侧验签：缺一 / 算法不符 / 摘要不符 → ``ok=False``（M05 INV-01）。"""
    if sig_provider in (None, ""):
        return SignatureCheck(False, "missing_provider_signature", "provider")
    if sig_consumer in (None, ""):
        return SignatureCheck(False, "missing_consumer_signature", "consumer")
    if not _well_formed(sig_provider):
        return SignatureCheck(False, "malformed_provider_signature", "provider")
    if not _well_formed(sig_consumer):
        return SignatureCheck(False, "malformed_consumer_signature", "consumer")
    payload = canonical_string(fields)
    expected_provider = digest(keys.provider, payload)
    expected_consumer = digest(keys.consumer, payload)
    if not hmac.compare_digest(expected_provider, str(sig_provider)):
        return SignatureCheck(False, "provider_signature_mismatch", "provider")
    if not hmac.compare_digest(expected_consumer, str(sig_consumer)):
        return SignatureCheck(False, "consumer_signature_mismatch", "consumer")
    return SignatureCheck(True)


def signature_ref(sig_provider: str, sig_consumer: str) -> str:
    """事件里的 ``signature_ref``：两侧摘要的**短指纹**（前 12 位，不泄露完整签名）。"""
    body = f"{sig_provider}{sig_consumer}".encode()
    return f"{facts.SIGNATURE_ALG}:{hashlib.sha256(body).hexdigest()[:facts.SIGNATURE_REF_LEN]}"


__all__ = ["SignatureKeys", "KeysProvider", "ENV_PROVIDER_KEY", "ENV_CONSUMER_KEY",
           "set_keys_provider", "current_keys_provider", "resolve_keys", "canonical_string",
           "digest", "sign", "verify_pair", "signature_ref", "SignatureCheck"]
