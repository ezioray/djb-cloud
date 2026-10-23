# SPDX-License-Identifier: Apache-2.0
"""差异分级与 SLA（INV-02 / 03-facts §7）。纯函数，不碰 DB。

分级口径（03-facts §7，整数最小单位）：

    P0  > 1,000 USD（> 100000 分）**或结构性**（与金额无关）
    P1  100 – 1,000 USD（10000 ≤ |diff| ≤ 100000）
    P2  < 100 USD（< 10000）

边界取端点归属：1000.00 整 → P1（P0 是**严格**大于）；100.00 整 → P1。
结构性差异（``facts.STRUCTURAL_KINDS``）一律 P0 —— 这是 INV-02，不看金额：
借贷不平 / 重复入账 / 平台无对应 / 签名不可验 / 派生余额漂移。

SLA（首响）：P0 15 分钟 / P1 1 小时 / P2 1 个工作日（24h 近似，见 facts 注释）。
"""
from __future__ import annotations

from datetime import datetime, timedelta

from . import facts

__all__ = ["is_structural", "classify", "sla_due", "classify_and_schedule", "age_days",
           "age_bucket"]


def is_structural(kind: str) -> bool:
    """INV-02：结构性差异与金额无关，一律 P0。"""
    return kind in facts.STRUCTURAL_KINDS


def _magnitude(diff_minor: int) -> int:
    if isinstance(diff_minor, bool) or not isinstance(diff_minor, int):
        raise TypeError("diff_minor 必须是整数最小单位")
    return abs(diff_minor)


def classify(diff_minor: int, *, kind: str | None = None) -> str:
    """按金额 + kind 定档（结构性优先，不看金额）。"""
    if kind is not None and is_structural(kind):
        return "P0"
    magnitude = _magnitude(diff_minor)
    if magnitude > facts.P0_AMOUNT_MINOR_EXCLUSIVE:
        return "P0"
    if magnitude >= facts.P1_AMOUNT_MINOR_MIN:
        return "P1"
    return "P2"


def sla_due(raised_at: datetime, severity: str) -> datetime:
    """首响截止 = 开启时刻 + 档位窗口。"""
    if severity not in facts.SEVERITY_SLA_SECONDS:
        raise ValueError(f"未知 severity：{severity!r}")
    return raised_at + timedelta(seconds=facts.SEVERITY_SLA_SECONDS[severity])


def classify_and_schedule(diff_minor: int, *, kind: str, raised_at: datetime) -> tuple[str, datetime]:
    """一次算完 (severity, sla_due)，保证两处口径一致。"""
    severity = classify(diff_minor, kind=kind)
    return severity, sla_due(raised_at, severity)


def age_days(created_at: datetime, now: datetime) -> float:
    """账龄（天，支持小数；负值按 0 处理，防时钟回拨把桶算成负数）。"""
    delta = (now - created_at).total_seconds() / 86400.0
    return max(0.0, delta)


def age_bucket(created_at: datetime, now: datetime) -> str:
    """账龄桶（M09 §8.2：0–1 / 1–3 / 3–7 / 7–30 / 30 天以上）。"""
    days = age_days(created_at, now)
    for (low, high), label in zip(facts.AGE_BUCKETS, facts.AGE_BUCKET_LABELS):
        if high is None or low <= days < high:
            return label
    return facts.AGE_BUCKET_LABELS[-1]                     # pragma: no cover - 兜底
