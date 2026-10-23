# SPDX-License-Identifier: Apache-2.0
"""单 Key QPS 限流（M03 §4.1 / §4.4 的 ``42901``）。

口径：

* **滑动窗口**（不是固定窗口）：窗口 1 s 内最多 ``limit`` 次；命中上限 → 429 /
  ``42901`` + ``Retry-After``（整数秒，取「最早一次请求滑出窗口」的剩余时间，≥1）+ 三件套
  ``X-DJB-RateLimit-Limit`` / ``-Remaining`` / ``-Reset``。
* **时间来自注入的 now**（用例钉死时钟），本模块不读墙上时间 → 可确定性重放。
* **按作用域隔离**：``key:<api_key_id>`` / ``tenant:<tenant_id>`` / ``node:<node_id>``
  各自一个窗口；一次性请求最多占三个作用域（min(租户, Key, 节点)），任一超限即 429。
* **不泄露阈值**：``Retry-After`` 与三件套只给「本次生效上限 / 剩余 / 重置秒数」，
  不给配额规则、租户档位或风控原因（INV-M03-05）。

进程内实现（单实例网关）；多实例部署时由 M16 的入口层做全局一致限流，
本模块的作用域键与窗口口径保持不变（见 ``WIRING.md``「多实例」段）。
"""
from __future__ import annotations

import math
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from . import clock, errors, facts

__all__ = ["LimitDecision", "SlidingWindowLimiter", "LIMITER", "enforce"]

WINDOW_S: int = 1
"""窗口长度（秒）：QPS 语义即「每 1 秒」；配置键 ``gateway.rate_limit_qps`` 同口径。"""


@dataclass(frozen=True)
class LimitDecision:
    """一次限流判定结果（``allowed=False`` 时 ``retry_after_s`` 必 >0）。"""

    allowed: bool
    limit: int
    remaining: int
    reset_s: int
    retry_after_s: int | None = None

    def headers(self) -> dict[str, str]:
        return {
            facts.RATE_LIMIT_LIMIT_HEADER: str(int(self.limit)),
            facts.RATE_LIMIT_REMAINING_HEADER: str(max(0, int(self.remaining))),
            facts.RATE_LIMIT_RESET_HEADER: str(max(0, int(self.reset_s))),
        }


class SlidingWindowLimiter:
    """滑动窗口计数器（进程内、线程安全、时钟注入）。"""

    def __init__(self, *, window_s: int = WINDOW_S) -> None:
        self.window_s = int(window_s)
        self._hits: dict[str, deque[datetime]] = {}
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def take(self, scope: str, limit: int | None, *, now: datetime | None = None,
             cost: int = 1) -> LimitDecision:
        """尝试占用 ``cost`` 次配额；``limit`` 为 None 表示该作用域不限流。"""
        moment = clock.as_utc(now or clock.utcnow())
        if limit is None:
            return LimitDecision(allowed=True, limit=0, remaining=0, reset_s=0)
        limit = int(limit)
        if limit <= 0:
            # 0 / 负数视为「关闭该作用域」，不是「全拒」——避免配置错误把流量全打死
            return LimitDecision(allowed=True, limit=0, remaining=0, reset_s=0)
        window = timedelta(seconds=self.window_s)
        boundary = moment - window
        with self._lock:
            hits = self._hits.setdefault(scope, deque())
            while hits and hits[0] <= boundary:
                hits.popleft()
            if len(hits) + max(1, int(cost)) > limit:
                oldest = hits[0]
                wait = (oldest + window - moment).total_seconds()
                retry_after = max(1, int(math.ceil(wait)))
                return LimitDecision(allowed=False, limit=limit,
                                     remaining=max(0, limit - len(hits)),
                                     reset_s=retry_after, retry_after_s=retry_after)
            hits.append(moment)
            remaining = max(0, limit - len(hits))
            reset_s = self.window_s
            return LimitDecision(allowed=True, limit=limit, remaining=remaining, reset_s=reset_s)


#: 进程级限流器（多实例部署时见模块文档「由 M16 入口层全局一致」）
LIMITER = SlidingWindowLimiter()


def enforce(decisions: list[LimitDecision], *, now: datetime | None = None) -> LimitDecision:
    """把一组判定合成一次结果：任一拒绝即 429（``Retry-After`` 取最大值）。"""
    denied = [item for item in decisions if not item.allowed]
    if denied:
        worst = max(denied, key=lambda item: item.retry_after_s or 0)
        raise errors.GatewayError(
            "rate_limited", "请求过于频繁，请按 Retry-After 退避",
            reason="rate_limited", retry_after_s=worst.retry_after_s or 1,
            details={"limit": worst.limit, "remaining": worst.remaining},
            headers={**worst.headers(),
                     facts.RETRY_AFTER_HEADER: str(worst.retry_after_s or 1)},
        )
    allowed = [item for item in decisions if item.limit > 0]
    if not allowed:
        return LimitDecision(allowed=True, limit=0, remaining=0, reset_s=0)
    # 成功时回「最紧的那个作用域」，让客户端看到当前生效上限
    return min(allowed, key=lambda item: item.remaining)
