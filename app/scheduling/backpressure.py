# SPDX-License-Identifier: Apache-2.0
"""背压：队列水位的三档动作（M04 §8.2「队列水位 70% / 85% / 95%」）。

| 水位 | 档位 | 动作 |
| --- | --- | --- |
| < 70% | ``ok`` | 正常接单 |
| ≥ 70% | ``notice`` | 向供方广播「该档位需求高」（**价格信号而非命令**，§13.4.3） |
| ≥ 85% | ``tight`` | 开始收紧：batch 排队并给 ETA，限额下调一档 |
| ≥ 95% | ``realtime_only`` | 只保实时：batch 直接拒绝（``queue_full``） |

阈值只来自 :data:`facts.QUEUE_WATERMARK_PCT`，模块内不出现第二个水位数字。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import facts

LEVELS: tuple[str, ...] = ("ok", "notice", "tight", "realtime_only")

#: 档位 → 允许接单的档位集合
SERVED_TIERS: dict[str, tuple[str, ...]] = {
    "ok": facts.TIERS,
    "notice": facts.TIERS,
    "tight": facts.TIERS,                     # 收紧：batch 排队但仍可进
    "realtime_only": ("realtime",),
}


@dataclass(frozen=True)
class Backpressure:
    """一次背压判定：档位 + 可执行动作（可见、可审计）。"""

    level: str
    watermark_pct: int | None
    actions: tuple[str, ...] = ()
    served_tiers: tuple[str, ...] = facts.TIERS

    def allows(self, tier: str) -> bool:
        return tier in self.served_tiers

    def as_dict(self) -> dict[str, Any]:
        return {"level": self.level, "watermark_pct": self.watermark_pct,
                "actions": list(self.actions), "served_tiers": list(self.served_tiers)}


def classify(watermark_pct: int | None) -> Backpressure:
    """按水位分类；``None``（无数据）视为正常，不制造保守限流。"""
    if watermark_pct is None:
        return Backpressure(level="ok", watermark_pct=None)
    pct = max(0, min(100, int(watermark_pct)))
    notice, tight, full = facts.QUEUE_WATERMARK_PCT
    if pct >= full:
        return Backpressure(level="realtime_only", watermark_pct=pct,
                            actions=("reject_batch", "broadcast_demand_signal"),
                            served_tiers=("realtime",))
    if pct >= tight:
        return Backpressure(level="tight", watermark_pct=pct,
                            actions=("queue_batch_with_eta", "broadcast_demand_signal"))
    if pct >= notice:
        return Backpressure(level="notice", watermark_pct=pct,
                            actions=("broadcast_demand_signal",))
    return Backpressure(level="ok", watermark_pct=pct)


def level_name(watermark_pct: int | None) -> str:
    return classify(watermark_pct).level


__all__ = ["LEVELS", "SERVED_TIERS", "Backpressure", "classify", "level_name"]
