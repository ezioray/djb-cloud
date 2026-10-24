# SPDX-License-Identifier: AGPL-3.0-or-later
"""跨模块注入点（M01 鉴权 / M04 路由 / M05 计量 / 上游节点 / M10 配置）。

**为什么是注入而不是 import**（00-conventions §1.2 / 04-api-contracts §2）：

* M03 不 import 任何其它业务模块，也不直连别人的基表；合并时由 Lead 把真实实现
  （M01 ``api_keys.verify_api_key``、M04 ``/api/v1/schedule/route`` 客户端、
  M05 用量写入口、M02 节点通道）投影成下面这些**鸭子类型契约**接进来；
* **默认 fail-closed**：未接线时鉴权 / 路由 / 上游一律 503（``45001``），
  绝不放行（M03 §7「M01 鉴权超时 / 不可用 → fail closed，不绕过鉴权」）；
* provider 可以返回 dataclass / Mapping / 带属性的对象，:mod:`app.gateway.models`
  的 ``coerce_*`` 负责规整；**网关内部只认 dataclass**。

接线清单与示例见 ``app/gateway/WIRING.md``。
"""
from __future__ import annotations

import inspect
import logging
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from . import clock, errors, models

log = logging.getLogger("djb.gateway.providers")

__all__ = [
    "AuthProvider", "RouteProvider", "NodeClient", "UsageProvider", "ModelCatalogProvider",
    "UpstreamTimeout", "UpstreamFailure", "NoRoute", "AuthUnavailable", "UsageUnavailable",
    "StreamClient", "WebhookSender", "WebhookSecretProvider", "ResultSigner",
    "set_auth_provider", "set_route_provider", "set_node_client", "set_stream_client",
    "set_usage_provider", "set_model_catalog_provider", "set_webhook_sender",
    "set_webhook_secret_provider", "set_result_signer", "reset_providers", "current",
    "authenticate", "route", "send", "stream", "record_usage", "list_models",
    "send_webhook", "webhook_secret", "sign_result", "translate_error",
]


# --------------------------------------------------------------------------- 契约
@runtime_checkable
class AuthProvider(Protocol):
    """M01：``raw_key`` → 主体（``AuthContext`` / Mapping）；失败抛 M01 的 ``IdentityError``。"""

    def __call__(self, raw_key: str, *, now: Any, client_ip: str | None,
                 trace_id: str) -> Any: ...


@runtime_checkable
class RouteProvider(Protocol):
    """M04：``RouteRequest`` → 决策（``Decision`` / Mapping）；无路由抛 :class:`NoRoute`。"""

    def route(self, request: models.RouteRequest) -> Any: ...


@runtime_checkable
class NodeClient(Protocol):
    """上游节点通道：``NodeCall`` → ``NodeResult``；超时 / 失败抛本模块的两类异常。"""

    def complete(self, call: models.NodeCall) -> Any: ...


@runtime_checkable
class UsageProvider(Protocol):
    """M05：``UsageDraft`` → ``UsageReceipt``（按 ``request_id`` 幂等）。"""

    def record(self, draft: models.UsageDraft) -> Any: ...


@runtime_checkable
class StreamClient(Protocol):
    """上游流式通道：``NodeCall`` → 分块迭代器（``StreamChunk`` / Mapping / 字符串增量）。"""

    def stream(self, call: models.NodeCall) -> Any: ...


@runtime_checkable
class WebhookSender(Protocol):
    """对外 webhook 投递（HTTP）：``(url, body, headers) -> status_code``。"""

    def __call__(self, url: str, body: bytes, headers: Mapping[str, str]) -> int: ...


@runtime_checkable
class WebhookSecretProvider(Protocol):
    """按账户取 webhook 签名密钥**引用**（真实密钥由 KMS/Secret 管理，不进代码与日志）。"""

    def __call__(self, account_id: str) -> Any: ...


@runtime_checkable
class ResultSigner(Protocol):
    """批次结果签名 URL 签发（≤15 分钟；``(batch_id, expires_at) -> url``）。"""

    def __call__(self, batch_id: str, expires_at: Any) -> Any: ...


@runtime_checkable
class ModelCatalogProvider(Protocol):
    """M04 ``model_catalog`` 只读投影：``list_models()`` → ``[Model, ...]``。"""

    def list_models(self) -> Sequence[Mapping[str, Any]]: ...


# --------------------------------------------------------------------------- 异常（provider 侧）
class AuthUnavailable(Exception):
    """M01 鉴权不可用 / 超时 / 返回非法主体 → fail-closed 503（M03 §7）。"""


class NoRoute(Exception):
    """M04 无可用节点（``45001``/``50901`` 语义）；网关不自行猜节点。"""


class UpstreamTimeout(Exception):
    """上游超时（首字节前可重路由，最多 2 次）。"""


class UpstreamFailure(Exception):
    """上游异常 / 5xx（首字节前可重路由，最多 2 次）。"""


class UsageUnavailable(Exception):
    """M05 用量写入不可用（不阻塞 2xx：``request.completed`` 事件由 outbox 补偿）。"""


# --------------------------------------------------------------------------- 注册表
_auth: AuthProvider | None = None
_route: RouteProvider | None = None
_node: NodeClient | None = None
_stream: StreamClient | None = None
_usage: UsageProvider | None = None
_catalog: ModelCatalogProvider | None = None
_webhook_sender: WebhookSender | None = None
_webhook_secret: WebhookSecretProvider | None = None
_result_signer: ResultSigner | None = None


def set_auth_provider(provider: AuthProvider | None) -> None:
    global _auth
    _auth = provider


def set_route_provider(provider: RouteProvider | None) -> None:
    global _route
    _route = provider


def set_node_client(client: NodeClient | None) -> None:
    global _node
    _node = client


def set_stream_client(client: StreamClient | None) -> None:
    """注入上游**流式**通道（T3）；未接线时 stream=true 一律 503 fail-closed。"""
    global _stream
    _stream = client


def set_usage_provider(provider: UsageProvider | None) -> None:
    global _usage
    _usage = provider


def set_model_catalog_provider(provider: ModelCatalogProvider | None) -> None:
    global _catalog
    _catalog = provider


def set_webhook_sender(sender: WebhookSender | None) -> None:
    """注入对外 webhook 投递（T4）；未接线时只落库不投递（可重放）。"""
    global _webhook_sender
    _webhook_sender = sender


def set_webhook_secret_provider(provider: WebhookSecretProvider | None) -> None:
    """注入「账户 → 签名密钥引用」读取（T4）。**密钥本体不得进日志/事件/响应。**"""
    global _webhook_secret
    _webhook_secret = provider


def set_result_signer(signer: ResultSigner | None) -> None:
    """注入批次结果签名 URL 签发（T4；TTL 由网关控制 ≤15 分钟）。"""
    global _result_signer
    _result_signer = signer


def reset_providers() -> None:
    """测试与合并窗口复位（全部回到 fail-closed）。"""
    global _auth, _route, _node, _stream, _usage, _catalog
    global _webhook_sender, _webhook_secret, _result_signer
    _auth = _route = _node = _stream = _usage = _catalog = None
    _webhook_sender = _webhook_secret = _result_signer = None


def current() -> dict[str, Any]:
    """当前接线状态（**不返回** provider 本体，只返回是否接线；供 /healthz 与证据用）。"""
    return {"auth": _auth is not None, "route": _route is not None,
            "node": _node is not None, "stream": _stream is not None,
            "usage": _usage is not None, "model_catalog": _catalog is not None,
            "webhook_sender": _webhook_sender is not None,
            "webhook_secret": _webhook_secret is not None,
            "result_signer": _result_signer is not None}


def _maybe_await(value: Any) -> Any:
    """provider 允许同步或协程（合并后可能是 HTTP 客户端）。"""
    if inspect.isawaitable(value):
        close = getattr(value, "close", None)               # 丢弃协程并关闭，避免告警
        if callable(close):
            close()
        raise AuthUnavailable("同步链路上收到协程：provider 必须提供同步实现或由 router 预解析")
    return value


def _invoke(target: Any, method: str, *args: Any) -> Any:
    """调用 provider 的方法；也接受「直接可调用」（``lambda request: ...``）的简写。"""
    handler = getattr(target, method, None)
    if handler is None:
        if callable(target):
            handler = target
        else:
            raise TypeError(f"provider 缺少方法 {method}() 且不可调用：{type(target).__name__}")
    return _maybe_await(handler(*args))


# --------------------------------------------------------------------------- 调用包装
def authenticate(raw_key: str, *, now: Any = None, client_ip: str | None = None,
                 trace_id: str = "") -> models.Principal:
    """验 Key → :class:`Principal`；未接线 / 非法主体 → 503 fail-closed。"""
    if _auth is None:
        raise errors.GatewayError("service_unavailable",
                                  "鉴权未接线：网关 fail-closed（合并时由 Lead 注入 M01）",
                                  reason="unavailable", retry_after_s=5)
    moment = now or clock.utcnow()
    try:
        raw = _maybe_await(_auth(raw_key, now=moment, client_ip=client_ip,
                                 trace_id=trace_id or ""))
    except errors.GatewayError:
        raise
    except Exception as exc:                       # provider 侧的 M01 错误 / 超时
        raise translate_error(exc) from exc
    try:
        principal = models.coerce_principal(raw)
    except ValueError as exc:
        raise errors.GatewayError("service_unavailable",
                                  "鉴权返回非法主体：fail-closed", reason="unavailable",
                                  retry_after_s=5) from exc
    return principal


def route(request: models.RouteRequest) -> models.RouteDecision:
    """向 M04 取路由决策；空决策 → 503 / 50901（不自行猜节点）。"""
    if _route is None:
        raise errors.GatewayError("service_unavailable",
                                  "路由未接线：网关 fail-closed（合并时由 Lead 注入 M04）",
                                  reason="unavailable", retry_after_s=5)
    try:
        raw = _invoke(_route, "route", request)
    except errors.GatewayError:
        raise
    except NoRoute as exc:
        raise errors.GatewayError("no_node", str(exc) or "无可用节点", retry_after_s=3) from exc
    except Exception as exc:
        raise translate_error(exc) from exc
    try:
        return models.coerce_route_decision(raw)
    except ValueError as exc:
        raise errors.GatewayError("no_node", "路由决策非法：按无可用节点处理",
                                  retry_after_s=3) from exc


def send(call: models.NodeCall) -> models.NodeResult:
    """向上游节点发起一次调用（超时 / 失败分别抛 :class:`UpstreamTimeout` / :class:`UpstreamFailure`）。"""
    if _node is None:
        raise errors.GatewayError("service_unavailable",
                                  "上游通道未接线：网关 fail-closed（合并时由 Lead 注入节点通道）",
                                  reason="unavailable", retry_after_s=5)
    try:
        raw = _invoke(_node, "complete", call)
    except errors.GatewayError:
        raise
    except (UpstreamTimeout, UpstreamFailure):
        raise
    except Exception as exc:
        # 未分类的上游异常（连接重置 / 协议错乱 / 5xx 包装层）一律按「上游异常」处理：
        # 首字节前可重路由，两次都失败 → 502 / 50903（M03 §7）
        log.warning("gateway.provider.upstream_unexpected",
                    extra={"event": "provider.upstream_unexpected",
                           "error": type(exc).__name__, "node_id": call.node_id})
        raise UpstreamFailure(f"{type(exc).__name__}: {exc}") from exc
    if raw is None:
        raise UpstreamFailure("上游返回空结果")
    if isinstance(raw, models.NodeResult):
        return raw
    # 允许 Mapping / 对象：规整成 NodeResult
    pick = models.pick_value
    content = pick(raw, "content", default=None)
    finish = pick(raw, "finish_reason")
    choice = pick(raw, "choices", default=None)
    if isinstance(choice, Sequence) and choice and not isinstance(choice, (str, bytes)):
        head = choice[0]
        message = pick(head, "message", default={}) or {}
        if content is None:
            content = pick(message, "content", default="")
        if finish is None:
            finish = pick(head, "finish_reason")
    usage_block = pick(raw, "usage", default=None)
    tokens_in = models.int_or_none(pick(raw, "tokens_in", "prompt_tokens"))
    tokens_out = models.int_or_none(pick(raw, "tokens_out", "completion_tokens"))
    if isinstance(usage_block, Mapping):
        tokens_in = tokens_in if tokens_in is not None else models.int_or_none(
            usage_block.get("prompt_tokens"))
        tokens_out = tokens_out if tokens_out is not None else models.int_or_none(
            usage_block.get("completion_tokens"))
    return models.NodeResult(
        content="" if content is None else str(content),
        finish_reason=str(finish or "stop"),
        model=models.str_or_none(pick(raw, "model")),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        usage_source=str(pick(raw, "usage_source", default="actual") or "actual"),
        latency_ms=models.int_or_none(pick(raw, "latency_ms")),
        first_byte_ms=models.int_or_none(pick(raw, "first_byte_ms")),
        upstream_request_id=models.str_or_none(pick(raw, "upstream_request_id", "id")),
    )


def stream(call: models.NodeCall) -> Any:
    """向上游发起**流式**调用，返回分块迭代器（元素经 :func:`coerce_stream` 规整）。

    未接线 → 503 fail-closed；首字节前的超时 / 失败抛 :class:`UpstreamTimeout` /
    :class:`UpstreamFailure`（与 ``send`` 同口径，便于 dispatch 复用重路由逻辑）。
    """
    if _stream is None:
        raise errors.GatewayError("service_unavailable",
                                  "流式通道未接线：网关 fail-closed（合并时由 Lead 注入节点流式通道）",
                                  reason="unavailable", retry_after_s=5)
    try:
        raw = _invoke(_stream, "stream", call)
    except errors.GatewayError:
        raise
    except (UpstreamTimeout, UpstreamFailure):
        raise
    except Exception as exc:
        log.warning("gateway.provider.stream_unexpected",
                    extra={"event": "provider.stream_unexpected",
                           "error": type(exc).__name__, "node_id": call.node_id})
        raise UpstreamFailure(f"{type(exc).__name__}: {exc}") from exc
    if raw is None or isinstance(raw, (str, bytes)):
        raise UpstreamFailure("流式通道返回非法迭代器")
    return raw


def send_webhook(url: str, body: bytes, headers: Mapping[str, str]) -> int | None:
    """投递一次 webhook；未接线 → None（只落库、可重放，不算失败）。"""
    if _webhook_sender is None:
        log.info("gateway.webhook.not_wired", extra={"event": "webhook.not_wired"})
        return None
    from . import webhook as webhook_module                # 同包；避免顶层循环 import

    status = _invoke(_webhook_sender, "__call__", url, body, headers)
    return webhook_module.coerce_status(status)


def webhook_secret(account_id: str) -> str | None:
    """取账户的 webhook 签名密钥（**引用**解析后的值；未接线 → None = 不签名，拒绝投递）。"""
    if _webhook_secret is None:
        return None
    raw = _invoke(_webhook_secret, "__call__", account_id)
    return models.str_or_none(raw)


def sign_result(batch_id: str, expires_at: Any) -> str | None:
    """签发批次结果 URL；未接线 → None（响应里就不给 results_ref）。"""
    if _result_signer is None:
        return None
    return models.str_or_none(_invoke(_result_signer, "__call__", batch_id, expires_at))


def record_usage(draft: models.UsageDraft) -> models.UsageReceipt:
    """把用量事实交给 M05（按 ``request_id`` 幂等）；未接线不抛 5xx，只记日志。"""
    if _usage is None:
        log.info("gateway.usage.not_wired",
                 extra={"event": "usage.not_wired", "request_id": draft.request_id})
        return models.UsageReceipt()
    raw = _invoke(_usage, "record", draft)
    if raw is None:
        return models.UsageReceipt()
    if isinstance(raw, models.UsageReceipt):
        return raw
    return models.UsageReceipt(
        usage_id=models.str_or_none(models.pick_value(raw, "usage_id")),
        amount_minor=models.int_or_none(models.pick_value(raw, "amount_minor")),
    )


def list_models() -> list[dict[str, Any]]:
    """``/v1/models`` 的数据源（M04 ``model_catalog`` 只读投影）。"""
    if _catalog is None:
        raise errors.GatewayError("service_unavailable",
                                  "模型目录未接线：fail-closed（合并时由 Lead 注入 M04）",
                                  reason="unavailable", retry_after_s=5)
    try:
        raw = _invoke(_catalog, "list_models")
    except errors.GatewayError:
        raise
    except Exception as exc:
        raise translate_error(exc) from exc
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise errors.GatewayError("service_unavailable", "模型目录返回非法结构",
                                  reason="unavailable", retry_after_s=5)
    return [_model_dict(item) for item in raw]


_MODEL_FIELDS: tuple[str, ...] = ("id", "object", "created", "owned_by", "context_window",
                                  "unit", "price", "price_version", "available", "probe",
                                  "tokenizer_version", "model_sync_version")


def _model_dict(item: Any) -> dict[str, Any]:
    """把 M04 ``model_catalog`` 的行（Mapping 或对象）规整成 spec ``Model`` 的字段集。"""
    if isinstance(item, Mapping):
        return dict(item)
    out: dict[str, Any] = {}
    for name in _MODEL_FIELDS:
        value = getattr(item, name, None)
        if value is not None:
            out[name] = value
    return out


# --------------------------------------------------------------------------- 错误翻译
#: M01 ``IdentityError`` 的码 → 网关 key（其余按 HTTP 落兜底）
_IDENTITY_CODES: dict[str, str] = {
    "40101": "key_invalid",
    "40304": "account_readonly",
    "40903": "key_invalid",
    "40907": "service_unavailable",
}


def translate_error(exc: Exception) -> errors.GatewayError:
    """把 provider 抛出的外部异常翻成 M03 的 :class:`GatewayError`（不泄露内部细节）。"""
    if isinstance(exc, errors.GatewayError):
        return exc
    status = getattr(exc, "status_code", None)
    code = getattr(exc, "code", None)
    reason = getattr(exc, "reason", None)
    message = str(exc) or "上游依赖失败"
    if code is not None:
        mapped = _IDENTITY_CODES.get(str(code))
        if mapped:
            return errors.GatewayError(mapped, message, reason=reason)
        try:
            numeric = int(str(code))
        except (TypeError, ValueError):
            numeric = None
        if numeric is not None and status:
            http = int(status)
            if http in (400, 401, 402, 403, 404, 409, 426, 429):
                # 跨模块 4xx 语义按 HTTP 落回本模块口径：对外只给 M03 已登记码，
                # 对方的具体码只进日志（不写进 Error 信封，00-conventions §8）
                log.info("gateway.provider.error",
                         extra={"event": "provider.error", "status": http,
                                "upstream_code": numeric})
                return errors.GatewayError(_fallback_key(http), message, reason=reason)
    if status and 500 <= int(status) < 600:
        return errors.GatewayError("service_unavailable", "上游依赖暂时不可用",
                                   reason="unavailable", retry_after_s=5)
    if isinstance(exc, (TimeoutError,)):
        return errors.GatewayError("upstream_timeout", "上游依赖超时", retry_after_s=2)
    return errors.GatewayError("service_unavailable", "上游依赖暂时不可用",
                               reason="unavailable", retry_after_s=5)


def _fallback_key(http: int) -> str:
    return {400: "bad_request", 401: "key_invalid", 402: "insufficient_balance",
            403: "key_policy_denied", 409: "conflict", 429: "rate_limited",
            426: "service_unavailable"}.get(http, "service_unavailable")
