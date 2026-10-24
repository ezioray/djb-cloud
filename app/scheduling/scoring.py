# SPDX-License-Identifier: AGPL-3.0-or-later
"""P2 打分与 tie-break（M04 §6 流程 2 第 2 步 / INV-04 / product §4.7.3）。

公式（product §4.7.3，与 §13.4.3 同一公式）::

    effective_cost = 报价 ÷ 可靠性系数ρ ÷ 负载惩罚κ + 延迟代价λ
    选定节点 = argmin(effective_cost)

**全整数实现**：`cost` 以 1e-6 分（"微分"）为单位，用整除算出来，
比较与排序都不出现浮点——这是 INV-03「复算一致率 100%」的前提。
::

    cost_micro = ask_minor × 1e12 ÷ (rho_milli × kappa_milli) + lambda_micro

**tie-break（INV-04）**：与最优成本的差 ≤ ``tie_break_epsilon_bps``（默认 300 bps = 3%）
视为同分，再按固定顺序决出：① 内网亲和命中 → ② ρ 更高 → ③ ``node_id`` 字典序。
**不含任何平台收入因子**（INV-04 明文禁止）。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from . import config_source, facts, models

log = logging.getLogger("djb.scheduling.scoring")

_MICRO = 1_000_000
_BPS = 10_000


def lambda_micro(tier: str, lambda_milli_cfg: int = 1_000) -> int:
    """延迟代价 λ（微分）：通道常量（§8.2）× 全局倍率（``routing.latency_lambda``）。

    S1 没有候选级实测延迟（跨区域放置 S3 才开），所以 λ 是同通道的常量；
    它仍然进 score_breakdown，保证成本可解释、可复算。
    """
    base = facts.LATENCY_LAMBDA_MICRO.get(tier)
    if base is None:
        raise ValueError(f"未知通道：{tier!r}（M04 §8.2 只定义 {tuple(facts.LATENCY_LAMBDA_MICRO)}）")
    return base * max(500, min(10_000, int(lambda_milli_cfg))) // 1_000


def effective_cost_micro(ask_minor: int, rho_milli: int, kappa_milli: int,
                         lambda_micro_value: int) -> int:
    """``effective_cost``（微分）：整数除法，结果对同一输入恒定（INV-03）。"""
    if ask_minor < 0:
        raise ValueError("ask_minor 不能为负")
    rho = max(facts.RHO_MIN_MILLI, min(facts.RHO_MAX_MILLI, int(rho_milli)))
    kappa = max(facts.KAPPA_MIN_MILLI, min(facts.KAPPA_MAX_MILLI, int(kappa_milli)))
    return (ask_minor * 10**12) // (rho * kappa) + int(lambda_micro_value)


def score(candidate: models.Candidate, *, lambda_value: int) -> models.Score:
    """单个候选打分（ρ / κ 越界夹取；缺失标记原样带出，供可见性使用）。"""
    rho = max(facts.RHO_MIN_MILLI, min(facts.RHO_MAX_MILLI, int(candidate.rho_milli)))
    kappa = max(facts.KAPPA_MIN_MILLI, min(facts.KAPPA_MAX_MILLI, int(candidate.kappa_milli)))
    cost = effective_cost_micro(candidate.ask_price_minor, rho, kappa, lambda_value)
    return models.Score(node_id=candidate.node_id, ask_price_minor=candidate.ask_price_minor,
                        rho_milli=rho, kappa_milli=kappa, lambda_micro=lambda_value,
                        cost_micro=cost, affinity_hit=candidate.affinity_hit,
                        rep_missing=candidate.rep_missing, load_missing=candidate.load_missing)


def score_all(candidates: Iterable[models.Candidate], *, tier: str,
              config: Mapping[str, Any] | None = None) -> list[models.Score]:
    """P2：对所有候选打分（返回顺序 = 输入顺序 = ``node_id`` 字典序）。"""
    values = config or {}
    value = lambda_micro(tier, config_source.latency_lambda_milli(values)
                         if values else 1_000)
    return [score(candidate, lambda_value=value) for candidate in candidates]


@dataclass(frozen=True)
class Selection:
    """tie-break 结果：赢家 + 用了哪条规则 + 同分集合（排名区间可解释）。"""

    winner: models.Score
    tie_break: str
    tied: tuple[str, ...]
    band_micro: int

    def as_dict(self) -> dict[str, Any]:
        return {"node_id": self.winner.node_id, "tie_break": self.tie_break,
                "tied": list(self.tied), "band_micro": self.band_micro}


def select(scores: Sequence[models.Score], *, epsilon_bps: int = facts.TIE_EPSILON_DEFAULT_BPS) \
        -> Selection:
    """在已打分的候选里选一个（INV-04：固定 tie-break，不含平台收入因子）。"""
    if not scores:
        raise ValueError("select() 需要至少一个候选（空候选集应先走降级 / 拒绝）")

    ordered = sorted(scores, key=lambda item: (item.cost_micro, item.node_id))
    best = ordered[0]
    epsilon = max(0, min(facts.TIE_EPSILON_MAX_BPS, int(epsilon_bps)))
    band = best.cost_micro * epsilon // _BPS
    tied = [item for item in ordered if item.cost_micro - best.cost_micro <= band]

    if len(tied) == 1:
        return Selection(winner=best, tie_break="cost", tied=(best.node_id,),
                         band_micro=band)

    # ① 内网亲和命中
    affinity = [item for item in tied if item.affinity_hit]
    if len(affinity) == 1:
        return Selection(winner=affinity[0], tie_break="affinity",
                         tied=tuple(item.node_id for item in tied), band_micro=band)

    pool = affinity or tied
    # ② ρ 更高（ρ 已夹取到 [0.50, 1.20]，同为 milli 整数可比）
    highest_rho = max(item.rho_milli for item in pool)
    by_rho = [item for item in pool if item.rho_milli == highest_rho]
    if len(by_rho) == 1 and len(pool) > 1:
        return Selection(winner=by_rho[0], tie_break="rho",
                         tied=tuple(item.node_id for item in tied), band_micro=band)

    # ③ node_id 字典序
    winner = sorted(by_rho, key=lambda item: item.node_id)[0]
    return Selection(winner=winner, tie_break="node_id",
                     tied=tuple(item.node_id for item in tied), band_micro=band)


def ranked(scores: Sequence[models.Score], *, epsilon_bps: int = facts.TIE_EPSILON_DEFAULT_BPS) \
        -> list[models.Score]:
    """兜底链用的排序：同分集合内按 tie-break 规则排好，供换节点 / 换区域依次尝试。"""
    remaining = list(scores)
    result: list[models.Score] = []
    while remaining:
        selection = select(remaining, epsilon_bps=epsilon_bps)
        result.append(selection.winner)
        remaining = [item for item in remaining if item.node_id != selection.winner.node_id]
    return result


__all__ = ["lambda_micro", "effective_cost_micro", "score", "score_all", "Selection",
           "select", "ranked"]
