# SPDX-License-Identifier: Apache-2.0
"""P3 约束：配额 / 并发 / 亲和（M04 §6 流程 2 第 3 步 / INV-07 / INV-08）。

三个硬约束与两个可见标记：

* **并发 = min(平台下发, 终端上报, 节点 max_qps)**（INV-07）。终端只能收紧；
  终端上报值 **大于** 平台值时：按平台值夹取、记 ``tenant_widened`` 并告警（不放宽）。
* **配额**（日 / 周 / 月，平台策略 + 终端单向收紧）：来源是 M01 的 ``tenant_quotas``，
  S1 通过**注入 provider** 读（不 import ``app.identity``、不 join 它的基表）。
* **每日花费上限**：超限 → ``42902``（M04 §4.1 / product §6.3）。
* **反亲和**（§4.7.4 第 4 条）：同租户并发单元不落同一物理机 —— 需要 ``physical_host_id``
  来源；未接线时开关保持关闭（``features.scheduling.affinity_hard_constraint``），
  即「不拿猜测的拓扑淘汰候选」。
* **单租户同模型并发占比 ≤25%**（INV-08）：超限**降权**而不是淘汰，且必须在响应可见。
  T2 只做阈值判定与可见标记（``share_exceeded``），降权系数由 T3 的公平计数落地。

计数落库：``quota_usage`` 按 ``(tenant_id, model, window_kind, window_start)`` 唯一，
由 P5 在决策事务内 ``+1``，消费方释放时 ``-1``（永不删除行）。
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping

from . import clock, facts, models
from .errors import SpendCapExceeded

log = logging.getLogger("djb.scheduling.quota")

QuotaProvider = Callable[[Any, uuid.UUID, str], Mapping[str, Any] | None]
_quota_provider: QuotaProvider | None = None

BPS = 10_000


def set_quota_provider(provider: QuotaProvider | None) -> None:
    """注入配额快照（M01 ``tenant_quotas`` 的只读视图 / API）。

    provider 返回::

        {"remaining": int | None,          # 剩余配额（None = 不限）
         "daily_spend_minor": int,          # 已花费（USD 分）
         "daily_cap_minor": int | None,     # 每日上限（None = 不限）
         "share_pct_bps": int | None}       # 该租户同模型当前并发占比（bps）
    """
    global _quota_provider
    _quota_provider = provider


def current_provider() -> QuotaProvider | None:
    return _quota_provider


# --------------------------------------------------------------------------- INV-07
def resolve_concurrency(platform_down: int | None, terminal_reported: int | None,
                        node_max_qps: int | None) -> tuple[int, bool]:
    """``并发 = min(平台下发, 终端上报, 节点 max_qps)``；返回 ``(生效值, 是否夹取过放宽)``。

    缺省项不参与 min（None = 未提供）。终端上报 > 平台下发 ⇒ **放宽尝试**：
    按平台值夹取并返回 ``widened=True``（调用方记 ``tenant_widened`` + 告警）。
    """
    values = [value for value in (platform_down, terminal_reported, node_max_qps)
              if value is not None]
    if not values:
        return 0, False
    for value in values:
        if value < 0:
            raise ValueError("并发上限不能为负（INV-07）")
    widened = (platform_down is not None and terminal_reported is not None
               and terminal_reported > platform_down)
    effective = min(values)
    if widened:
        effective = min(platform_down, node_max_qps) if node_max_qps is not None \
            else int(platform_down)
        log.warning("scheduling.quota.terminal_widened",
                    extra={"event": "quota.terminal_widened", "platform": platform_down,
                           "terminal": terminal_reported})
    return int(effective), widened


# --------------------------------------------------------------------------- INV-08
def share_exceeded(share_pct_bps: int | None, limit_pct: int) -> bool:
    """单租户同模型并发占比是否超限（INV-08：默认 25% = 2500 bps）。"""
    if share_pct_bps is None:
        return False
    return int(share_pct_bps) > int(limit_pct) * 100


# --------------------------------------------------------------------------- 窗口
def window_start(moment: datetime, kind: str = "day") -> datetime:
    """配额窗口起点（UTC；day = 当日 00:00，week = 周一 00:00，month = 1 日 00:00）。

    00-conventions §4.2 的业务日切（UTC+4）只用于对账 cutoff；配额窗口按 UTC 日，
    与账本期间同口径（§4.2「报表周期与账本期间按 UTC 日 / 月」）。
    """
    if kind not in facts.QUOTA_WINDOWS:
        raise ValueError(f"未知窗口：{kind!r}（M04 §3 只定义 {facts.QUOTA_WINDOWS}）")
    day = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    if kind == "day":
        return day
    if kind == "week":
        return day - timedelta(days=day.weekday())
    return day.replace(day=1)


# --------------------------------------------------------------------------- P3 判定
@dataclass(frozen=True)
class QuotaDecision:
    """P3 的结论：是否放行 + 可见标记（每个标记都能进 reason_codes）。"""

    allowed: bool
    effective_concurrency: int
    reason_codes: tuple[str, ...] = ()
    widening_rejected: bool = False
    share_exceeded: bool = False
    remaining: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "effective_concurrency": self.effective_concurrency,
                "reason_codes": list(self.reason_codes),
                "widening_rejected": self.widening_rejected,
                "share_exceeded": self.share_exceeded, "remaining": self.remaining}


def snapshot(c, tenant_id: uuid.UUID, model: str) -> dict[str, Any]:
    """取一次配额快照（provider 注入；缺省 = 不限）。**每次请求只取一次**，供 P3 复用。"""
    if _quota_provider is None:
        return {}
    try:
        return dict(_quota_provider(c, tenant_id, model) or {})
    except Exception:                                        # pragma: no cover - 防御
        log.warning("scheduling.quota.provider_failed", extra={"event": "quota.provider_failed"})
        return {}


def decide(*, snapshot: Mapping[str, Any] | None, node_max_qps: int | None,
           platform_concurrency: int | None, terminal_concurrency: int | None,
           limit_pct: int, required_units: int = 1) -> QuotaDecision:
    """P3 的**纯函数**部分：配额 / 并发 / 花费上限 / 占比（同一输入同一结论）。

    ``remaining`` 为 None 表示不限；``required_units`` 是本次要占用的并发单元数。
    """
    values: Mapping[str, Any] = snapshot or {}
    effective, widened = resolve_concurrency(platform_concurrency, terminal_concurrency,
                                             node_max_qps)
    reasons: list[str] = []
    if widened:
        reasons.append("tenant_widened")

    remaining = values.get("remaining")
    spend = int(values.get("daily_spend_minor") or 0)
    cap = values.get("daily_cap_minor")
    share = values.get("share_pct_bps")

    if cap is not None and spend > int(cap):
        raise SpendCapExceeded("已超每日花费上限（42902）", reason="spend_cap_exceeded",
                               daily_spend_minor=spend, daily_cap_minor=int(cap))

    over_share = share_exceeded(share, limit_pct)
    if over_share:
        reasons.append("share_exceeded")

    insufficient = remaining is not None and int(remaining) < required_units
    exceeds_concurrency = effective < required_units
    allowed = not insufficient and not exceeds_concurrency
    if insufficient or exceeds_concurrency:
        reasons.append("quota_exhausted")

    return QuotaDecision(allowed=allowed, effective_concurrency=effective,
                         reason_codes=tuple(reasons), widening_rejected=widened,
                         share_exceeded=over_share,
                         remaining=None if remaining is None else int(remaining))


def evaluate(c, *, tenant_id: uuid.UUID, model: str, node_max_qps: int | None,
             platform_concurrency: int | None, terminal_concurrency: int | None,
             limit_pct: int, required_units: int = 1) -> QuotaDecision:
    """``snapshot`` + ``decide`` 的便捷组合（单候选 / 测试 / 别的模块复用）。"""
    return decide(snapshot=snapshot(c, tenant_id, model), node_max_qps=node_max_qps,
                  platform_concurrency=platform_concurrency,
                  terminal_concurrency=terminal_concurrency, limit_pct=limit_pct,
                  required_units=required_units)


# --------------------------------------------------------------------------- 计数落库
def reserve(c, *, tenant_id: uuid.UUID, model: str, now: datetime | None = None,
            units: int = 1, spend_minor: int = 0, share_pct_bps: int | None = None,
            kind: str = "day") -> int:
    """P5：同一事务内 +1 并发（并累加花费 / 占比）。返回新的并发数。"""
    moment = now or clock.utcnow()
    start = window_start(moment, kind)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO quota_usage (tenant_id, model, window_kind, window_start,
                                        concurrent, daily_spend_minor, share_pct_bps, updated_at)
               VALUES (%s, %s, %s, %s, %s, %s, COALESCE(%s, 0), %s)
               ON CONFLICT (tenant_id, model, window_kind, window_start) DO UPDATE
                  SET concurrent = quota_usage.concurrent + EXCLUDED.concurrent,
                      daily_spend_minor = quota_usage.daily_spend_minor
                                          + EXCLUDED.daily_spend_minor,
                      share_pct_bps = COALESCE(%s, quota_usage.share_pct_bps),
                      updated_at = EXCLUDED.updated_at
               RETURNING concurrent""",
            (tenant_id, model, kind, start, units, spend_minor, share_pct_bps, moment,
             share_pct_bps))
        row = cur.fetchone()
    return int(row[0]) if row else 0


def release(c, *, tenant_id: uuid.UUID, model: str, now: datetime | None = None,
            units: int = 1, kind: str = "day") -> int:
    """消费方释放并发（``-1``，夹到 ≥0；行永不删除）。"""
    moment = now or clock.utcnow()
    start = window_start(moment, kind)
    with c.cursor() as cur:
        cur.execute(
            """UPDATE quota_usage
                  SET concurrent = GREATEST(concurrent - %s, 0), updated_at = %s
                WHERE tenant_id = %s AND model = %s AND window_kind = %s
                  AND window_start = %s
                RETURNING concurrent""",
            (units, moment, tenant_id, model, kind, start))
        row = cur.fetchone()
    return int(row[0]) if row else 0


def usage(c, *, tenant_id: uuid.UUID, model: str, now: datetime | None = None,
          kind: str = "day") -> dict[str, Any] | None:
    moment = now or clock.utcnow()
    start = window_start(moment, kind)
    with c.cursor() as cur:
        cur.execute(
            """SELECT concurrent, daily_spend_minor, share_pct_bps FROM quota_usage
                WHERE tenant_id = %s AND model = %s AND window_kind = %s AND window_start = %s""",
            (tenant_id, model, kind, start))
        row = cur.fetchone()
    if row is None:
        return None
    return {"concurrent": int(row[0]), "daily_spend_minor": int(row[1]),
            "share_pct_bps": int(row[2])}


__all__ = ["QuotaProvider", "set_quota_provider", "current_provider", "resolve_concurrency",
           "share_exceeded", "window_start", "QuotaDecision", "snapshot", "decide", "evaluate",
           "reserve", "release", "usage"]
