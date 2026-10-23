# SPDX-License-Identifier: Apache-2.0
"""PaymentProvider 适配器（M08 §1 / 产品 §19.10.1 / §19.6.5）。

一期两个实现：

* UpgProvider  —— UPG / GIFPay 形态（SHA256 规范化、回调验签、查询、退款、收银台）；
* MockProvider —— 测试 / 测试网用（同一套规范化，确定性应答，不出网）。

硬约束（§19.6.5.2 / §19.6.5.9）：

1. **签名算法通道规定 = SHA256**，禁止自创；规范化全链路只有一份 canonicalize()：
   排除 sign 与空值 → key 按 ASCII 升序 → k=v&... 拼接 → 末尾直接拼 Key → SHA256(hex)。
2. **三处都验**：请求签名、响应验签、回调验签；验签用**原始字节**，不先反序列化再重排。
3. **时钟**：timestamp 偏差 > ±300s 拒绝（payment.webhook_skew_s）。
4. **密钥只在 KMS**：适配器只持 key 引用 + 由注入的 key_provider 取密钥材料；
   未注入即 fail-closed（ProviderUnavailable），密钥不进日志 / 不进异常信息。
5. 适配器**不出网**：HTTP 传输由注入的 transport 完成（合并期由 Lead 接 httpx）；
   未注入就抛 ProviderUnavailable，绝不静默返回「成功」。
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, Sequence

from . import clock, facts
from .errors import BadRequest

__all__ = [
    "canonicalize", "sign", "verify_signature", "amount_to_major", "check_timestamp",
    "PaymentProvider", "ProviderUnavailable", "NullKeyProvider", "MemoryKeyProvider",
    "UpgProvider", "GifPayProvider", "MockProvider", "ProviderRegistry", "build_registry",
    "WebhookEvent",
]

KeyProvider = Callable[[str], bytes | None]
Transport = Callable[[str, Mapping[str, Any], Mapping[str, str]], Mapping[str, Any]]


class ProviderUnavailable(Exception):
    """通道不可用 / 未接线（未知状态：只查询、不换单重下，00-conventions §6.5）。"""

    reason = "provider_unavailable"


class NullKeyProvider:
    """未接线 KMS：取不到密钥 → 验签 fail-closed。"""

    def __call__(self, key_ref: str) -> bytes | None:
        return None


class MemoryKeyProvider:
    """测试用（**只放假密钥**；真实密钥只在 KMS）。"""

    def __init__(self, keys: Mapping[str, bytes | str] | None = None) -> None:
        self._keys = {ref: (value.encode("utf-8") if isinstance(value, str) else value)
                      for ref, value in dict(keys or {}).items()}

    def __call__(self, key_ref: str) -> bytes | None:
        return self._keys.get(key_ref)


# ═══════════════════════════════════════════════════════════ 规范化与签名（唯一实现）
def _scalar_text(value: Any, *, field_name: str) -> str:
    if isinstance(value, (dict, list, tuple)):
        raise BadRequest(f"{field_name} 不得是嵌套结构（验签规范化必须无歧义）",
                         field=field_name)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def canonicalize(fields: Mapping[str, Any]) -> str:
    """排除 sign 与空值 → key ASCII 升序 → k=v 用 & 拼接（不含 Key）。"""
    parts: list[str] = []
    for key in sorted(str(k) for k in fields):
        if key == "sign":
            continue
        value = fields.get(key)
        if value is None or (isinstance(value, str) and value.strip() == ""):
            continue
        parts.append(f"{key}={_scalar_text(value, field_name=key)}")
    return "&".join(parts)


def sign(fields: Mapping[str, Any], key: bytes) -> str:
    """SHA256(规范化串 + Key) 的小写十六进制（通道规定，禁止自创）。"""
    payload = canonicalize(fields).encode("utf-8") + key
    return hashlib.sha256(payload).hexdigest()


def verify_signature(fields: Mapping[str, Any], signature: str | None, key: bytes | None) -> bool:
    """常量时间比较；key / signature 缺失一律 False（不外泄细节）。"""
    if not signature or key is None:
        return False
    expected = sign(fields, key)
    return hmac.compare_digest(expected, str(signature).strip().lower())


def check_timestamp(timestamp: Any, *, now: datetime | None = None,
                    skew_s: int = facts.WEBHOOK_SKEW_S) -> int:
    """±skew 秒时钟窗（§19.6.5.2）；缺失 / 非法 / 超窗 → 40001。"""
    try:
        moment = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise BadRequest("timestamp 缺失或非法", field="timestamp") from exc
    current = int(clock.as_utc(now or clock.utcnow()).timestamp())
    if abs(current - moment) > int(skew_s):
        raise BadRequest("timestamp 超出 ±5 分钟窗口（重放保护）", field="timestamp")
    return moment


def amount_to_major(amount_minor: int, currency: str) -> str:
    """整数最小单位 → 主单位字符串（USD 2 / JPY 0 / KWD 3），超精度直接拒绝。"""
    scale = facts.PSP_CURRENCIES.get(currency)
    if scale is None:
        raise BadRequest(f"currency 不在支持列表 {sorted(facts.PSP_CURRENCIES)}",
                         field="currency")
    value = int(amount_minor)
    if value <= 0:
        raise BadRequest("amount_minor 必须 > 0", field="amount_minor")
    divisor = 10 ** scale
    if scale == 0:
        if value % divisor != 0:
            raise BadRequest(f"{currency} 精度为 0 位，金额超出精度", field="amount_minor")
        return str(value // divisor)
    if scale < 2 and value % divisor != 0:
        raise BadRequest(f"{currency} 精度为 {scale} 位，金额超出精度", field="amount_minor")
    whole, frac = divmod(value, divisor)
    return f"{whole}.{frac:0{scale}d}"


# ═══════════════════════════════════════════════════════════ 适配器协议
@dataclass(frozen=True)
class WebhookEvent:
    """验签通过后的回调事件（Adapter 只负责验签与解析，不判断业务）。"""

    provider: str
    fields: Mapping[str, Any]
    signature_verified: bool
    timestamp: int | None
    raw_body: bytes
    payload_hash: str


class PaymentProvider(Protocol):                     # pragma: no cover - 结构协议
    id: str

    def capabilities(self) -> dict[str, Any]: ...
    def create_checkout(self, request: Mapping[str, Any]) -> dict[str, Any]: ...
    def verify_webhook(self, raw_body: bytes, headers: Mapping[str, str],
                       *, now: datetime | None = None) -> WebhookEvent: ...
    def query_payment(self, provider_ref: str) -> dict[str, Any]: ...
    def refund(self, request: Mapping[str, Any]) -> dict[str, Any]: ...


class _BaseProvider:
    """公共部分：密钥引用 + 验签 + 时钟窗 + 传输注入。"""

    key_ref = "provider.upg.key_ref"

    def __init__(self, *, key_provider: KeyProvider | None = None,
                 transport: Transport | None = None,
                 skew_s: int = facts.WEBHOOK_SKEW_S,
                 merchant_id: str = "m08-merchant",
                 pay_methods: Sequence[str] = facts.PSP_METHODS) -> None:
        self._keys = key_provider or NullKeyProvider()
        self._transport = transport
        self._skew_s = int(skew_s)
        self._merchant_id = merchant_id
        self._pay_methods = tuple(pay_methods)

    # ── 密钥（只取引用，不进日志）
    def _key(self) -> bytes | None:
        return self._keys(self.key_ref)

    def capabilities(self) -> dict[str, Any]:
        return {
            "methods": list(self._pay_methods),
            "currencies": sorted(facts.PSP_CURRENCIES),
            "settlement_currency": "USD",
            "supports_usdt_settlement": False,
            "supports_refund": True,
            "supports_partial_refund": True,
            "supports_payout": False,
            "custodial": True,
        }

    # ── 下单（只构造请求与签名，不发送）
    def create_checkout(self, request: Mapping[str, Any]) -> dict[str, Any]:
        key = self._key()
        if key is None:
            raise ProviderUnavailable("PSP 密钥未接线（KMS 未注入）：拒绝下单")
        method = str(request.get("method") or "")
        if method not in self._pay_methods:
            raise BadRequest(f"payNo 不在白名单 {list(self._pay_methods)}", field="method")
        currency = str(request.get("currency") or facts.DEFAULT_CURRENCY)
        fields: dict[str, Any] = {
            "merId": self._merchant_id,
            "merOrderId": str(request.get("order_no") or ""),
            "amount": amount_to_major(int(request.get("amount_minor") or 0), currency),
            "currency": currency,
            "payNo": method,
            "timestamp": int(clock.as_utc(request.get("now") or clock.utcnow()).timestamp()),
            "backendUrl": str(request.get("backend_url") or ""),
            "responseUrl": str(request.get("response_url") or ""),
        }
        if not fields["merOrderId"]:
            raise BadRequest("下单必须带 order_no（= merOrderId）", field="order_no")
        signature = sign(fields, key)
        return {"provider": self.id, "request": fields, "sign": signature,
                "pay_url": f"{self.id}://checkout/{fields['merOrderId']}",
                "qr": f"{self.id}://qr/{fields['merOrderId']}"}

    # ── 回调验签（原始字节参与）
    def verify_webhook(self, raw_body: bytes, headers: Mapping[str, str],
                       *, now: datetime | None = None) -> WebhookEvent:
        key = self._key()
        if key is None:
            raise ProviderUnavailable("PSP 密钥未接线：无法验签（fail-closed）")
        payload_hash = hashlib.sha256(raw_body).hexdigest()
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BadRequest("回调必须是 JSON（原始字节参与验签）") from exc
        if not isinstance(body, Mapping):
            raise BadRequest("回调必须是 JSON 对象")
        signature = body.get("sign") or _header(headers, "X-PSP-Sign")
        check_timestamp(body.get("timestamp"), now=now, skew_s=self._skew_s)
        verified = verify_signature(body, signature, key)
        return WebhookEvent(provider=self.id, fields=dict(body),
                            signature_verified=bool(verified),
                            timestamp=int(body.get("timestamp") or 0),
                            raw_body=raw_body, payload_hash=payload_hash)

    # ── 查询（未知只查、不重下）
    def query_payment(self, provider_ref: str) -> dict[str, Any]:
        if self._transport is None:
            raise ProviderUnavailable("PSP 查询未接线（transport 未注入）：只查询、不换单重下")
        response = self._transport("query", {"platformOrderId": str(provider_ref)},
                                   {"key_ref": self.key_ref})
        return dict(response)

    # ── 退款
    def refund(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if self._transport is None:
            raise ProviderUnavailable("PSP 退款未接线（transport 未注入）：失败转工单，不换路")
        response = self._transport("refund", dict(request), {"key_ref": self.key_ref})
        return dict(response)


class UpgProvider(_BaseProvider):
    """UPG / GIFPay（SHA256 规范化；端点由配置注入，不写死）。"""

    id = "upg"
    key_ref = "provider.upg.key_ref"


class GifPayProvider(_BaseProvider):
    id = "gifpay"
    key_ref = "provider.gifpay.key_ref"


class MockProvider(_BaseProvider):
    """测试 / 测试网：确定性应答；查询结果由 scripted_status 或注入的 resolver 决定。"""

    id = "mock"
    key_ref = "provider.mock.key_ref"

    def __init__(self, *, key: bytes | str = b"test-only-mock-key",
                 scripted_status: Mapping[str, Any] | None = None,
                 status_resolver: Callable[[str], str | None] | None = None,
                 **kwargs: Any) -> None:
        kwargs.setdefault("key_provider", MemoryKeyProvider({self.key_ref: key}))
        super().__init__(**kwargs)
        self._scripted = {str(k): str(v) for k, v in dict(scripted_status or {}).items()}
        self._resolver = status_resolver

    def query_payment(self, provider_ref: str) -> dict[str, Any]:
        if self._resolver is not None:
            status = self._resolver(str(provider_ref))
        else:
            status = self._scripted.get(str(provider_ref))
        if status is None:
            raise ProviderUnavailable("mock 通道无该单号的查询结果（未知状态只查询）")
        return {"platformOrderId": str(provider_ref), "status": str(status)}


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


# ═══════════════════════════════════════════════════════════ 注册表
class ProviderRegistry:
    """通道注册表（默认：mock；未知 provider 的对外语义由 router 决定）。"""

    def __init__(self, providers: Sequence[PaymentProvider] | None = None) -> None:
        self._providers: dict[str, PaymentProvider] = {}
        for provider in providers or (MockProvider(),):
            self.register(provider)

    def register(self, provider: PaymentProvider) -> None:
        self._providers[str(provider.id)] = provider

    def get(self, provider: str) -> PaymentProvider | None:
        return self._providers.get(str(provider).strip().lower())

    def ids(self) -> list[str]:
        return sorted(self._providers)


def build_registry(providers: Sequence[PaymentProvider] | None = None) -> ProviderRegistry:
    return ProviderRegistry(providers)
