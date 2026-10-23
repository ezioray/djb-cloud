# SPDX-License-Identifier: Apache-2.0
"""节点级熔断（M04 §7 失败矩阵 / §8.2「熔断：κ ≥2.50 持续 60 s 或失败率 >30%；10 min」）。

规则（全部来自 §8.2，模块内不写第二份数字）：

* **触发**：``κ ≥ 2.50`` **持续 60 s**，或 5 分钟失败率 **> 30%**；
* **处置顺序**：降权 → 停接新 → 只服务在途 → **熔断 10 min**；
* **恢复**：连续 5 min 正常 / 半开探测放 1 个轻单元试水（§4.7.2 节点异常行）。

M04 的职责边界：**只判定与停接新**（P1 淘汰 / P4 让路），不碰节点的状态机（M02 拥有）。
κ 与失败率由 M16 指标 / M02 心跳经注入 provider 提供（默认未接线 → 不熔断，避免用猜的数）。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping

from . import clock, facts

log = logging.getLogger("djb.scheduling.circuit")

CircuitProvider = Callable[[Any, str], Mapping[str, Any] | None]
_provider: CircuitProvider | None = None


def set_provider(provider: CircuitProvider | None) -> None:
    """注入节点健康快照（M16 指标 / M02 心跳）。

    provider 返回::

        {"kappa_milli": int,              # 当前负载惩罚
         "kappa_sustained_s": int,        # κ 已持续多久
         "fail_rate_bps": int,            # 5 min 失败率
         "opened_until": datetime|None}   # 已熔断到期时刻
    """
    global _provider
    _provider = provider


def current_provider() -> CircuitProvider | None:
    return _provider


@dataclass(frozen=True)
class Trip:
    """一次熔断判定结果。"""

    open: bool
    reason: str | None = None
    until: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"open": self.open, "reason": self.reason,
                "until": self.until.isoformat() if self.until else None}


def should_trip(*, kappa_milli: int | None = None, kappa_sustained_s: int | None = None,
                fail_rate_bps: int | None = None) -> Trip:
    """纯函数：按 §8.2 判定是否应熔断（不含「已熔断」状态）。"""
    if kappa_milli is not None and kappa_milli >= facts.KAPPA_CIRCUIT_MILLI \
            and (kappa_sustained_s or 0) >= facts.CIRCUIT_SUSTAIN_S:
        return Trip(open=True, reason="kappa")
    if fail_rate_bps is not None and fail_rate_bps > facts.CIRCUIT_FAIL_RATE_BPS:
        return Trip(open=True, reason="fail_rate")
    return Trip(open=False)


def evaluate(node_state: Mapping[str, Any] | None, *, now: datetime | None = None) -> Trip:
    """把 provider 快照判成「现在能不能接新」（含 10 min 熔断窗口）。"""
    moment = now or clock.utcnow()
    if not node_state:
        return Trip(open=False)
    opened_until = node_state.get("opened_until")
    if opened_until is not None and opened_until > moment:
        return Trip(open=True, reason="cooldown", until=opened_until)
    trip = should_trip(kappa_milli=node_state.get("kappa_milli"),
                       kappa_sustained_s=node_state.get("kappa_sustained_s"),
                       fail_rate_bps=node_state.get("fail_rate_bps"))
    if trip.open:
        return Trip(open=True, reason=trip.reason,
                    until=moment + _seconds(facts.CIRCUIT_OPEN_S))
    return Trip(open=False)


def _seconds(value: int):
    from datetime import timedelta

    return timedelta(seconds=int(value))


def is_open(c, node_id: str, *, now: datetime | None = None) -> Trip:
    """查一个节点当前是否熔断（provider 未接线 → 一律不熔断）。"""
    if _provider is None:
        return Trip(open=False)
    try:
        state = _provider(c, node_id)
    except Exception:                                        # pragma: no cover - 防御
        log.warning("scheduling.circuit.provider_failed",
                    extra={"event": "circuit.provider_failed", "node_id": node_id})
        return Trip(open=False)
    verdict = evaluate(state, now=now)
    if verdict.open:
        log.warning("scheduling.circuit.open", extra={"event": "circuit.open",
                                                     "node_id": node_id,
                                                     "reason": verdict.reason})
    return verdict


__all__ = ["CircuitProvider", "set_provider", "current_provider", "Trip", "should_trip",
           "evaluate", "is_open"]
