# SPDX-License-Identifier: Apache-2.0
"""P4 抢占判定（M04 §6 流程 2 第 4 步 / INV-09 / INV-10 / §8.2 抢占参数）。

四条硬规则：

* **只允许 realtime 抢 batch**，batch 之间互不抢占（INV-09）；
* **无可用检查点禁止入组网队列**（INV-09）：检查点缺失或超过优雅中断窗口（≤30 s）；
* **每节点每小时被抢占 ≤6 次**（INV-10）；超限则该节点本小时退出 batch 候选池；
* **无合法对象 → 排队（必给 ETA）或明确拒绝**，不制造隐形等待（§4.7.3 P4 失败动作）。

T2 的边界：抢占的**执行**（真正让 batch 让路）归 T4，且受 ``features.scheduling.p4_preemption``
开关控制（默认关闭）。关着时本模块只产出 ``preempt_plan=[]`` 并按排队处理，
决策与 ETA 语义不变——这样「先能把话说清楚，再能真的动手」。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from . import facts, features

log = logging.getLogger("djb.scheduling.preempt")


@dataclass(frozen=True)
class PreemptOutcome:
    """P4 的结论：抢占 / 排队 / 拒绝（三者互斥，排队必带 ETA）。"""

    outcome: str
    plan: tuple[dict[str, Any], ...] = ()
    eta_seconds: int | None = None
    reason_codes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"outcome": self.outcome, "preempt_plan": list(self.plan),
                "eta_seconds": self.eta_seconds, "reason_codes": list(self.reason_codes)}


def checkpoint_usable(checkpoint_age_s: int | None) -> bool:
    """检查点是否可用（INV-09：优雅中断 ≤30 s，超过就没法安全让路）。"""
    return checkpoint_age_s is not None and 0 <= int(checkpoint_age_s) <= facts.PREEMPT_GRACEFUL_S


def pick_victims(victims: Iterable[Mapping[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    """挑让路对象：等待最久优先（``started_at`` 升序，同刻按 ``request_id`` 字典序）。

    只挑 **batch** 且检查点可用的对象；排序固定 → 同一输入同一计划（INV-03）。
    """
    eligible = [dict(item) for item in victims
                if item.get("tier") == "batch" and checkpoint_usable(item.get("checkpoint_age_s"))]
    eligible.sort(key=lambda item: (str(item.get("started_at") or ""),
                                    str(item.get("request_id") or "")))
    return eligible[:max(0, limit)]


def evaluate(*, tier: str, required_units: int = 1,
             victims: Sequence[Mapping[str, Any]] = (),
             budget_used: int = 0, budget_limit: int = facts.PREEMPT_BUDGET_PER_H,
             checkpoint_age_s: int | None = None,
             queue_level_pct: int | None = None,
             eta_seconds: int | None = None,
             preempt_enabled: bool | None = None) -> PreemptOutcome:
    """P4：在「没有可行解」或「池级水位越限」时决定抢占 / 排队 / 拒绝。

    ``queue_level_pct`` ≥ 95 ⇒ 只保实时（§8.2 队列水位）；batch 直接拒绝。
    """
    enabled = features.enabled("scheduling.p4_preemption") if preempt_enabled is None \
        else bool(preempt_enabled)
    eta = int(eta_seconds) if eta_seconds is not None else facts.BOOKING_TTL_S

    # 队列水位 95%：只保实时（§8.2）
    if queue_level_pct is not None and queue_level_pct >= facts.QUEUE_WATERMARK_PCT[2] \
            and tier != "realtime":
        return PreemptOutcome(outcome="rejected", reason_codes=("queue_full",))

    # batch 互不抢占（INV-09）：只能排队或拒绝
    if tier != "realtime":
        if not checkpoint_usable(checkpoint_age_s):
            return PreemptOutcome(outcome="rejected", reason_codes=("no_checkpoint",))
        tight = queue_level_pct is not None and queue_level_pct >= facts.QUEUE_WATERMARK_PCT[1]
        return PreemptOutcome(outcome="queued", eta_seconds=eta,
                              reason_codes=("queue_tight",) if tight else ())

    # realtime：不能排队等（token 档 P99 预算 20 ms），抢不到就**明确拒绝**（§4.7.7 降级链）
    if not enabled:
        return PreemptOutcome(outcome="rejected", reason_codes=("preempt_disabled",))

    remaining_budget = max(0, int(budget_limit) - int(budget_used))
    if remaining_budget <= 0:
        return PreemptOutcome(outcome="rejected",
                              reason_codes=("preempt_budget_exhausted",))

    plan = pick_victims(victims, limit=min(remaining_budget, max(1, int(required_units))))
    if not plan:
        return PreemptOutcome(outcome="rejected")

    entries = tuple({"node_id": item.get("node_id"), "request_id": item.get("request_id"),
                     "graceful_s": facts.PREEMPT_GRACEFUL_S,
                     "checkpoint_age_s": item.get("checkpoint_age_s")} for item in plan)
    log.info("scheduling.p4.preempt_plan", extra={"event": "p4.preempt_plan",
                                                  "victims": len(entries)})
    return PreemptOutcome(outcome="preempt", plan=entries,
                          eta_seconds=facts.PREEMPT_GRACEFUL_S)


def budget_exhausted(budget_used: int, budget_limit: int = facts.PREEMPT_BUDGET_PER_H) -> bool:
    """节点本小时是否已用完抢占预算（INV-10：≤6 次·h⁻¹）。"""
    return int(budget_used) >= int(budget_limit)


__all__ = ["PreemptOutcome", "checkpoint_usable", "pick_victims", "evaluate",
           "budget_exhausted"]
