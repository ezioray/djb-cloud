# SPDX-License-Identifier: Apache-2.0
"""公平观测与计数（M04 §8.2「基尼 ≤0.35 / 小节点中位等待 ≤5 min」/ §4.7.5 / INV-08）。

边界写清楚：

* **T3 做的是计数与观测**：把 ``quota_usage`` 里 M04 自有的并发 / 花费计数聚合成
  公平指标（基尼、单租户占比、等待时长），超阈值只**告警留痕**，不改变决策；
* **S2 的加权公平**（按 tenant 维护虚拟时间、权重函数）不在本模块范围；
* 纯整数实现：基尼用「排序后前缀和」算，输出 milli（0.35 = 350），无浮点。

指标口径（都在 docstring 里写死，便于审计）：

* 基尼 —— 对各租户在**同一模型**上的**并发占用**求基尼系数；
* 小节点中位等待 —— 节点侧等待时长中位数（来源是 M02/M16 指标，M04 只做判定）；
* 反饥饿 —— 等待 >30 min 进优先队列（§8.2），由 ``starvation`` 判定。
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import clock, facts, quota

log = logging.getLogger("djb.scheduling.fairness")

MedianWaitProvider = Callable[[Any], "int | None"]
_median_wait: MedianWaitProvider | None = None


def set_median_wait_provider(provider: MedianWaitProvider | None) -> None:
    """注入「小节点中位等待（秒）」来源（M02 心跳 / M16 指标）。默认未接线 → 不观测。"""
    global _median_wait
    _median_wait = provider


# --------------------------------------------------------------------------- 基尼（纯函数）
def gini_milli(values: Sequence[int]) -> int:
    """基尼系数（milli）：0 = 完全均等，1000 = 完全不均等。

    算法：排序后 ``Σ(2i − n + 1)·xᵢ ÷ (n · Σx)``（整数运算，无浮点）。
    负数输入按 0 处理（计数不该为负；防御性夹取）。
    """
    numbers = sorted(max(0, int(value)) for value in values)
    count = len(numbers)
    if count == 0:
        return 0
    total = sum(numbers)
    if total <= 0:
        return 0
    weighted = sum((2 * index - count + 1) * value
                   for index, value in enumerate(numbers))
    return max(0, min(1_000, weighted * 1_000 // (count * total)))


def median(values: Iterable[int]) -> int | None:
    """整数中位数（偶数个取中间两个的**下界**，避免引入除法误差）。"""
    numbers = sorted(int(value) for value in values)
    if not numbers:
        return None
    return numbers[(len(numbers) - 1) // 2]


# --------------------------------------------------------------------------- 阈值判定
def gini_breach(gini: int | None) -> bool:
    """基尼是否超过 §8.2 的 0.35（350 milli）。"""
    return gini is not None and int(gini) > facts.GINI_MAX_MILLI


def wait_breach(median_wait_s: int | None) -> bool:
    """小节点中位等待是否超过 §8.2 的 5 min（300 s）。"""
    return median_wait_s is not None and int(median_wait_s) > facts.SMALL_NODE_MEDIAN_WAIT_S


def starvation(waited_s: int | None) -> bool:
    """等待 >30 min → 应进优先队列（§8.2 反饥饿）。"""
    return waited_s is not None and int(waited_s) > facts.ANTI_STARVATION_S


# --------------------------------------------------------------------------- 观测
def observe(c, *, now: datetime | None = None, model: str | None = None,
            kind: str = "day") -> dict[str, Any]:
    """汇总一次公平快照（只读）：基尼 / 单租户最大占比 / 等待中位数 / 越限项。

    数据来源全部是 M04 自有表（``quota_usage``）；等待指标需要 provider，未接线则不观测
    （``wait_observed=False``，不当 0 处理——0 会被误读成「没人等」）。
    """
    moment = now or clock.utcnow()
    models = [model] if model else _models(c)
    per_model: dict[str, int] = {}
    shares: list[int] = []
    for name in models:
        counts = quota.model_concurrency(c, model=name, now=moment, kind=kind)
        total = sum(counts.values())
        per_model[name] = total
        if total > 0:
            shares.extend(quota.share_bps(value, total) for value in counts.values())
    gini = gini_milli(list(per_model.values())) if per_model else 0
    max_share = max(shares) if shares else 0

    median_wait = None
    if _median_wait is not None:
        try:
            median_wait = _median_wait(c)
        except Exception:                                    # pragma: no cover - 防御
            log.warning("scheduling.fairness.median_wait_failed",
                        extra={"event": "fairness.median_wait_failed"})
            median_wait = None

    breaches: list[str] = []
    if gini_breach(gini):
        breaches.append("gini")
    if wait_breach(median_wait):
        breaches.append("small_node_wait")
    if facts.MAX_TENANT_SHARE_PCT * 100 < max_share:
        breaches.append("tenant_share")

    snapshot = {"window": kind, "models": per_model, "gini_milli": gini,
                "gini_threshold_milli": facts.GINI_MAX_MILLI,
                "max_tenant_share_bps": max_share,
                "share_threshold_bps": facts.MAX_TENANT_SHARE_PCT * 100,
                "median_wait_s": median_wait,
                "wait_observed": median_wait is not None,
                "breaches": breaches}
    if breaches:
        log.warning("scheduling.fairness.breach",
                    extra={"event": "fairness.breach", "breaches": breaches,
                           "gini_milli": gini, "max_tenant_share_bps": max_share})
    return snapshot


def _models(c) -> list[str]:
    with c.cursor() as cur:
        cur.execute("SELECT DISTINCT model FROM quota_usage WHERE concurrent > 0 ORDER BY model")
        return [row[0] for row in cur.fetchall()]


def waiting(waited_s: int | None) -> Mapping[str, Any]:
    """等待时长 → 归档建议（反饥饿 / 公平告警）。"""
    return {"waited_s": waited_s, "starvation": starvation(waited_s),
            "wait_breach": wait_breach(waited_s)}


__all__ = ["MedianWaitProvider", "set_median_wait_provider", "gini_milli", "median",
           "gini_breach", "wait_breach", "starvation", "observe", "waiting"]
