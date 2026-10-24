# SPDX-License-Identifier: AGPL-3.0-or-later
"""M02 节点通道（长轮询）· 契约层与接线位（C10a；**不含队列实现**）。

分工（01-ownership §1 · CR-C10-01）：

* **端点归 M02**：``POST /api/v1/node/channel/poll`` / ``POST /api/v1/node/channel/result``
  由本模块（``router.py``）实现——鉴权、状态、协议、请求体校验、错误信封、按 ``job_id`` 幂等；
* **数据面队列归 M03**：任务排队、租约、重派、单节点在途 1 个、断线丢在途，全部由 C10b 的
  后端提供，经 :func:`set_channel_backend` 注入。本模块**不 import** ``app.gateway``、
  不建表、不落正文、不写事件、不发队列消息。

三条铁律（写进代码也写进证据）：

1. **fail-closed**：未注入后端时 :func:`require_channel_backend` 直接抛
   :class:`~app.supply.errors.ChannelUnavailable`（HTTP 503 / ``50903``），绝不静默放行、
   绝不回落到 Echo（回落策略由部署层显式选择，见 C10 决策单 §1「降级」）；
2. **正文不落库**：``poll`` 返回的任务体、``result`` 里的 ``content`` 只在内存与响应/请求体
   过一手；本模块不写 DB、不进日志、不进事件；
3. **契约只加不改**：字段名与 spec 1.2.9 ``NodeChannelJob`` / ``NodeChannelResultRequest``
   逐字一致；未知字段由调用方容忍（tolerant reader），本模块只校验已知字段。
"""
from __future__ import annotations

import math
import uuid
from typing import Any, Mapping, Protocol, runtime_checkable

from . import facts
from .errors import ChannelUnavailable, InvalidArgument

#: 进程级接线位（部署期由 Lead / C10b 注入；测试用 fake 覆盖）
_backend: "ChannelBackend | None" = None


@runtime_checkable
class ChannelBackend(Protocol):
    """通道后端（队列）契约：**唯一**由 C10b 实现，M02 只按此协议调用。

    ``poll``
        阻塞至多 ``wait_s`` 秒取一个任务；无任务返回 ``None``（路由据此回 204）。
        返回的 dict 必须是 spec ``NodeChannelJob`` 形态::

            {"job_id": uuid, "kind": "chat.completions", "request_id": str,
             "request": {"model": str, "messages": [{"role","content"}],
                         "max_tokens": int?, "temperature": number?, "stop": [str]?},
             "timeout_s": number?, "lease_expires_at": date-time}

        **``model`` / ``messages`` 不在 job 顶层**（与客户端 ``parse_job`` 对齐）；
        任务体**不得含任何凭据或上游端点**（H1），正文不落库、不进日志。
    ``submit``
        接收一个已归一化的结果（见 :func:`validate_result`），返回
        ``{"accepted": bool, "duplicate": bool}``；``job_id`` 不存在 / 不属于该节点 → 抛
        :class:`~app.supply.errors.ChannelJobNotFound`（40401）；同 ``job_id`` 不同载荷 →
        抛 :class:`~app.supply.errors.IdempotencyConflict`（40919）。
        实现方须保证**快**（毫秒级）：路由在数据库事务内调用它，长等待只允许发生在 ``poll``。
    """

    def poll(self, node_id: str, *, wait_s: float,
             capabilities: tuple[str, ...]) -> "dict[str, Any] | None":
        ...                                                       # pragma: no cover - 协议

    def submit(self, node_id: str, job_id: str, result: dict[str, Any]) -> dict[str, Any]:
        ...                                                       # pragma: no cover - 协议


# --------------------------------------------------------------------------- 接线位
def set_channel_backend(backend: "ChannelBackend | None") -> None:
    """注入 / 摘除通道后端（``None`` = 未接线，fail-closed）。

    传非 ``None`` 时做**鸭子类型**检查（``poll`` / ``submit`` 必须可调用）——接线错误应在
    启动期暴露，而不是在第一个节点请求时变成 500。
    """
    global _backend
    if backend is not None:
        if not callable(getattr(backend, "poll", None)) \
                or not callable(getattr(backend, "submit", None)):
            raise TypeError("ChannelBackend 必须实现 poll() 与 submit()")
    _backend = backend


def channel_backend() -> "ChannelBackend | None":
    """当前后端（未接线返回 ``None``；只读快照，供健康检查 / 测试断言）。"""
    return _backend


def require_channel_backend() -> ChannelBackend:
    """取后端；未接线 → ``503`` / ``50903``（fail-closed，不回落 Echo）。"""
    backend = _backend
    if backend is None:
        raise ChannelUnavailable("节点通道未接线（C10b 队列未注入）",
                                 reason="channel_unavailable")
    return backend


def is_wired() -> bool:
    """通道是否已接线（健康检查 / 特性开关观测用；不暴露后端细节）。"""
    return _backend is not None


# --------------------------------------------------------------------------- 请求校验
def _require_number(value: Any, *, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidArgument(f"{field} 必须是数字", field=field)
    number = float(value)
    if not math.isfinite(number) or number < minimum or number > maximum:
        raise InvalidArgument(f"{field} 必须在 {minimum:g}–{maximum:g} 之间", field=field)
    return number


def _optional_int(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidArgument(f"{field} 必须是非负整数", field=field)
    return value


def _optional_text(value: Any, *, field: str, max_len: int = 200) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidArgument(f"{field} 必须是字符串", field=field)
    text = value.strip()
    if len(text) > max_len:
        raise InvalidArgument(f"{field} 超长（≤{max_len}）", field=field)
    return text or None


def validate_capabilities(value: Any) -> tuple[str, ...]:
    """``capabilities``：可选字符串数组；未知值不报错（宽容读取，INV-05 口径）。"""
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise InvalidArgument("capabilities 必须是数组", field="capabilities")
    if len(value) > facts.CHANNEL_MAX_CAPABILITIES:
        raise InvalidArgument(f"capabilities 最多 {facts.CHANNEL_MAX_CAPABILITIES} 项",
                              field="capabilities")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise InvalidArgument(f"capabilities[{index}] 必须是非空字符串",
                                  field=f"capabilities[{index}]")
        text = item.strip()
        if len(text) > facts.CHANNEL_CAPABILITY_MAX_LEN:
            raise InvalidArgument(f"capabilities[{index}] 超长", field=f"capabilities[{index}]")
        result.append(text)
    return tuple(dict.fromkeys(result))


def validate_poll(body: Mapping[str, Any]) -> tuple[float, tuple[str, ...]]:
    """``poll`` 请求体 → ``(wait_s, capabilities)``；越界一律 40001。"""
    raw_wait = body.get("wait_s")
    if raw_wait is None:
        wait_s = float(facts.CHANNEL_WAIT_S_DEFAULT)
    else:
        wait_s = _require_number(raw_wait, field="wait_s",
                                 minimum=facts.CHANNEL_WAIT_S_MIN,
                                 maximum=facts.CHANNEL_WAIT_S_MAX)
    return wait_s, validate_capabilities(body.get("capabilities"))


def _require_job_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidArgument("job_id 必填", field="job_id")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, TypeError) as exc:
        raise InvalidArgument("job_id 必须是 UUID", field="job_id") from exc


def validate_result(body: Mapping[str, Any]) -> dict[str, Any]:
    """``result`` 请求体 → 归一化结果（只保留已知字段；未知字段丢弃，不落库）。

    交叉校验：``status=failed`` 必须给 ``error_code`` 或 ``error_class``——
    失败结果没有原因码，排障与计费都无法对账（M02 §7 失败矩阵口径）。
    """
    job_id = _require_job_id(body.get("job_id"))
    status = body.get("status")
    if status not in facts.CHANNEL_RESULT_STATUSES:
        raise InvalidArgument(
            f"status 必须是 {'/'.join(facts.CHANNEL_RESULT_STATUSES)} 之一", field="status")
    usage_source = body.get("usage_source")
    if usage_source is not None and usage_source not in facts.CHANNEL_USAGE_SOURCES:
        raise InvalidArgument(
            f"usage_source 必须是 {'/'.join(facts.CHANNEL_USAGE_SOURCES)} 之一",
            field="usage_source")
    result: dict[str, Any] = {
        "job_id": job_id,
        "status": status,
        "content": _optional_text(body.get("content"), field="content", max_len=1_000_000),
        "finish_reason": _optional_text(body.get("finish_reason"), field="finish_reason",
                                        max_len=64),
        "tokens_in": _optional_int(body.get("tokens_in"), field="tokens_in"),
        "tokens_out": _optional_int(body.get("tokens_out"), field="tokens_out"),
        "usage_source": usage_source,
        "latency_ms": _optional_int(body.get("latency_ms"), field="latency_ms"),
        "first_byte_ms": _optional_int(body.get("first_byte_ms"), field="first_byte_ms"),
        "error_code": _optional_text(body.get("error_code"), field="error_code", max_len=64),
        "error_class": _optional_text(body.get("error_class"), field="error_class", max_len=64),
        "upstream_request_id": _optional_text(body.get("upstream_request_id"),
                                              field="upstream_request_id", max_len=128),
    }
    if status == "failed" and not (result["error_code"] or result["error_class"]):
        raise InvalidArgument("status=failed 时必须给 error_code 或 error_class",
                              field="error_code")
    return result


__all__ = ["ChannelBackend", "set_channel_backend", "channel_backend", "require_channel_backend",
           "is_wired", "validate_poll", "validate_result", "validate_capabilities"]
