# SPDX-License-Identifier: AGPL-3.0-or-later
"""向**上游节点**发起调用并做首字节前的重试（M03 §6.1 / §7 / INV-M03-01）。

不变量：

* **只在首字节前重试**：非流式请求的「首字节」= 上游开始返回；本模块在拿到上游完整
  结果前失败才重试。流式由 T3 在 SSE 层复用同一策略（首字节后不再重路由）。
* **最多 2 次尝试**（``facts.RETRY_MAX_ATTEMPTS``）：第 2 次会**重新向 M04 要路由**
  （换节点），而不是打同一个节点。
* **两次都失败不计费**：只返回错误；成功那次才写用量（INV-M03-01）。
* **超时 / 5xx 分类**：超时 → 504 / ``50902``；其它上游异常 → 502 / ``50903``；
  无可用节点（路由空） → 503 / ``50901``。
* **不记录正文**：``NodeCall`` 里的 messages 只在本进程内存里过一手。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from . import clock, errors, facts, models, providers

__all__ = ["DispatchOutcome", "Attempt", "dispatch"]

RouteFn = Callable[[int], models.RouteDecision]
SendFn = Callable[[models.NodeCall], models.NodeResult]


@dataclass(frozen=True)
class Attempt:
    attempt_no: int
    node_id: str
    error_class: str | None = None
    error_code: int | None = None


@dataclass
class DispatchOutcome:
    """派发结果：成功带 ``result`` + 决策；失败带 ``error`` + 尝试轨迹。"""

    attempts: list[Attempt] = field(default_factory=list)
    decision: models.RouteDecision | None = None
    result: models.NodeResult | None = None
    error: errors.GatewayError | None = None

    @property
    def attempt_count(self) -> int:
        return len(self.attempts)

    @property
    def upstream_error_class(self) -> str | None:
        for item in reversed(self.attempts):
            if item.error_class:
                return item.error_class
        return None

    @property
    def succeeded(self) -> bool:
        return self.result is not None


def dispatch(*, route: RouteFn, send: SendFn, call_factory: Callable[[models.RouteDecision],
                                                                    models.NodeCall],
             request_id: str, trace_id: str, attempts_max: int = facts.RETRY_MAX_ATTEMPTS,
             now: datetime | None = None) -> DispatchOutcome:
    """执行「路由 → 派发」，失败时按 §7 重路由（≤``attempts_max`` 次）。

    ``route(attempt_no)`` 返回决策；``call_factory(decision)`` 生成 :class:`models.NodeCall`；
    ``send(call)`` 执行一次上游调用（超时抛 ``providers.UpstreamTimeout``）。
    """
    outcome = DispatchOutcome()
    moment = clock.as_utc(now or clock.utcnow())
    attempt_no = 1
    while attempt_no <= attempts_max:
        decision = route(attempt_no)
        outcome.decision = decision
        call = call_factory(decision)
        try:
            result = send(call)
        except providers.UpstreamTimeout as exc:
            outcome.attempts.append(Attempt(attempt_no, decision.node_id, "timeout", 50902))
            _log_attempt(request_id, trace_id, attempt_no, decision.node_id, "timeout", moment)
            if attempt_no >= attempts_max:
                outcome.error = errors.GatewayError(
                    "upstream_timeout", "上游超时，请稍后重试", retry_after_s=2,
                    upstream_error_class="timeout",
                    details={"attempts": attempt_no})
                return outcome
            attempt_no += 1
            continue
        except providers.UpstreamFailure as exc:
            outcome.attempts.append(Attempt(attempt_no, decision.node_id, "upstream_error", 50903))
            _log_attempt(request_id, trace_id, attempt_no, decision.node_id, "upstream_error",
                         moment)
            if attempt_no >= attempts_max:
                outcome.error = errors.GatewayError(
                    "upstream_error", "上游返回异常，请稍后重试", upstream_error_class="upstream",
                    details={"attempts": attempt_no})
                return outcome
            attempt_no += 1
            continue
        outcome.attempts.append(Attempt(attempt_no, decision.node_id))
        outcome.result = result
        return outcome
    # 理论不可达（attempts_max ≥ 1）
    outcome.error = errors.GatewayError("upstream_error", "上游返回异常",              # pragma: no cover
                                        upstream_error_class="unknown")
    return outcome


def _log_attempt(request_id: str, trace_id: str, attempt_no: int, node_id: str,
                 error_class: str, moment: datetime) -> None:
    import logging

    logging.getLogger("djb.gateway.dispatch").warning(
        "gateway.dispatch.attempt_failed",
        extra={"event": "dispatch.attempt_failed", "request_id": request_id,
               "trace_id": trace_id, "attempt_no": attempt_no, "node_id": node_id,
               "error_class": error_class, "ts": clock.iso(moment)})
