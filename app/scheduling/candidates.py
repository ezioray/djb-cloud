# SPDX-License-Identifier: AGPL-3.0-or-later
"""P1 过滤：候选集与逐条淘汰码（M04 §6 流程 2 第 1 步 / product §4.7.3 F1–F5）。

数据来源（01-ownership §2 的**只读依赖**，不 import 他人的包、不 join 基表）：

* ``v_supply_capacity_latest``（M02）——每个 ``(node_id, kind, model)`` 的最新公告，
  已过滤过期与 0 容量；
* ``v_supply_upstream_verified``（M02，209）——``state='verified'`` 的上游 × 模型；
  候选必须命中其中一条**且** ``verified_at`` 在 ``CANDIDATE_PROBE_FRESH_S`` 内（C9b）；
* ``v_supply_node_snapshot``（M02）——节点身份 / 版本 / ``last_seen_at``（在线判定输入）；
* ``quotes``（本模块）——**报价以报价簿为准**，公告里的 ``ask_price`` 只做展示口径。

准入 / 隔离 / 亲和这三类输入在 S1 还没有上游模块（M11 风控、M07 信誉、物理拓扑），
因此都以**注入 provider** 的形式留口，默认给「缺失」口径并在决策里标 ``rep_missing`` /
``load_missing``（product §4.7.3 P2 规定的兜底），绝不自己编造系数。
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import circuit, clock, facts, models

log = logging.getLogger("djb.scheduling.candidates")

# --------------------------------------------------------------------------- provider 钩子
ReputationProvider = Callable[[Any, str], "int | None"]
LoadProvider = Callable[[Any, Mapping[str, Any]], "int | None"]
AffinityProvider = Callable[[Any, Any, Mapping[str, Any]], "bool"]
MarketProvider = Callable[..., Iterable[Mapping[str, Any]]]

_reputation: ReputationProvider | None = None
_load: LoadProvider | None = None
_affinity: AffinityProvider | None = None
_market: MarketProvider | None = None


def set_reputation_provider(provider: ReputationProvider | None) -> None:
    """注入 ρ 来源（M07 信誉）。返回 milli（500–1200）；None = 缺失（兜底 0.80）。"""
    global _reputation
    _reputation = provider


def set_load_provider(provider: LoadProvider | None) -> None:
    """注入 κ 来源（M02 水位 / M16 指标）。返回 milli（1000–3000）；None = 缺失（1.00）。"""
    global _load
    _load = provider


def set_affinity_provider(provider: AffinityProvider | None) -> None:
    """注入亲和判定（机架内网 / 反亲和的 ``physical_host_id`` 来源）。"""
    global _affinity
    _affinity = provider


def set_market_provider(provider: MarketProvider | None) -> None:
    """注入市场快照来源（默认读 M02 两个只读视图；测试可用它喂固定候选集）。"""
    global _market
    _market = provider


# --------------------------------------------------------------------------- 快照
@dataclass(frozen=True)
class SnapshotResult:
    """P1 的结果：候选集 + 淘汰明细 + 锚点输入。"""

    candidates: tuple[models.Candidate, ...]
    eliminated: tuple[dict[str, Any], ...]
    quote_version: int
    stale: bool = False
    source: str = "views"

    def as_inputs(self) -> list[dict[str, Any]]:
        return [candidate.as_input() for candidate in self.candidates]


@dataclass(frozen=True)
class RouteInput:
    """路由输入（spec ``RouteRequest`` 的领域形态）。"""

    model: str
    kind: str
    tenant_id: Any
    trace_id: str
    requested_tokens: int | None = None
    deadline_seconds: int | None = None
    required_access: tuple[str, ...] = ()
    max_price_minor: int | None = None
    attempt_no: int = 1

    def as_dict(self) -> dict[str, Any]:
        """稳定性输入（参与 ``request_digest``；不含 trace_id —— 它只是链路标识）。"""
        return {"model": self.model, "kind": self.kind, "tenant_id": str(self.tenant_id),
                "requested_tokens": self.requested_tokens,
                "deadline_seconds": self.deadline_seconds,
                "required_access": list(self.required_access),
                "max_price_minor": self.max_price_minor}


def _probe_join(now: datetime, probe_freshness_s: int | None) -> tuple[str, dict[str, Any]]:
    """上游验证门控的 JOIN 片段（C9b）。

    ``probe_freshness_s is None`` = 不过滤（**仅供兼容测试**：证明其余 P1 逻辑与门控解耦）。
    子查询先 ``DISTINCT`` 掉同 ``(node, access, model)`` 的多条 verified 上游，
    避免一条公告被放大成多行候选（JOIN 语义保持，行数不放大）。
    """
    if probe_freshness_s is None:
        return "", {}
    join = (
        f"JOIN (SELECT DISTINCT node_id, access_type, model"
        f"        FROM {facts.UPSTREAM_VERIFIED_VIEW}"
        f"       WHERE verified_at >= %(cutoff)s) v"
        f"  ON v.node_id = c.node_id AND v.access_type = c.access AND v.model = c.model")
    return join, {"cutoff": now - timedelta(seconds=int(probe_freshness_s))}


def _attestation_join() -> str:
    """C12 证明门控：``DJB_ATTEST=1`` 时只放行 L3+ 且未过期的 (node, model)。"""
    if os.environ.get("DJB_ATTEST") != "1":
        return ""
    return (f" JOIN {facts.ATTESTED_VIEW} a"
            f"   ON a.node_id = c.node_id AND a.model = c.model")


def _view_rows(c, *, model: str, now: datetime,
               probe_freshness_s: int | None = facts.CANDIDATE_PROBE_FRESH_S
               ) -> list[Mapping[str, Any]]:
    """默认市场来源：M02 三个只读视图（报价另从 ``quotes`` 取，见 :func:`collect`）。"""
    probe_join, probe_params = _probe_join(now, probe_freshness_s)
    attestation_join = _attestation_join()
    with c.cursor() as cur:
        cur.execute(
            f"""SELECT s.node_id, s.account_id, s.tenant_id, s.region, s.lifecycle_state,
                       s.last_seen_at, c.access, c.model, c.unit, c.max_qps,
                       c.resource_level, c.announced_at
                  FROM {facts.CAPACITY_LATEST_VIEW} c
                  JOIN {facts.NODE_SNAPSHOT_VIEW} s ON s.node_id = c.node_id
                  {probe_join}
                  {attestation_join}
                  LEFT JOIN {facts.INTEGRITY_FROZEN_VIEW} f
                         ON f.node_id = c.node_id AND f.model = c.model
                 WHERE c.model = %(model)s
                   AND f.node_id IS NULL
                 ORDER BY s.node_id, c.access""",
            {"model": model, **probe_params})
        names = [column.name for column in cur.description]
        return [dict(zip(names, row)) for row in cur.fetchall()]


def _book(c, *, model: str, now: datetime) -> list[models.Quote]:
    from . import quotes as quote_book

    return quote_book.active_book(c, now=now, model=model)


def _book_stale(book: Sequence[models.Quote], now: datetime, refresh_s: int) -> bool:
    """报价簿是否「上一版」：最新一条 active 报价的建立时刻超过刷新窗口（M04 §7）。"""
    if not book:
        return False
    newest = max(quote.created_at for quote in book)
    return (now - newest).total_seconds() > refresh_s


def _quote_version(c, *, now: datetime) -> int:
    from . import quotes as quote_book

    return quote_book.current_version(c)


def _presence(last_seen_at: datetime | None, now: datetime, freshness_s: int) -> str:
    if last_seen_at is None:
        return "never"
    if (now - last_seen_at).total_seconds() <= freshness_s:
        return "online"
    return "stale"


def _rho(c, node_id: str) -> tuple[int, bool]:
    """ρ（milli）：缺失 → 0.80 + ``rep_missing``；越界夹取到 [0.50, 1.20]。"""
    if _reputation is None:
        return facts.RHO_MISSING_MILLI, True
    try:
        value = _reputation(c, node_id)
    except Exception:                                        # pragma: no cover - 防御
        log.warning("scheduling.reputation.failed",
                    extra={"event": "reputation.failed", "node_id": node_id})
        return facts.RHO_MISSING_MILLI, True
    if value is None:
        return facts.RHO_MISSING_MILLI, True
    return max(facts.RHO_MIN_MILLI, min(facts.RHO_MAX_MILLI, int(value))), False


def _kappa(c, row: Mapping[str, Any]) -> tuple[int, bool]:
    """κ（milli）：缺失 → 1.00 + ``load_missing``；越界夹取到 [1.00, 3.00]。"""
    if _load is None:
        return facts.KAPPA_MISSING_MILLI, True
    try:
        value = _load(c, row)
    except Exception:                                        # pragma: no cover - 防御
        log.warning("scheduling.load.failed", extra={"event": "load.failed"})
        return facts.KAPPA_MISSING_MILLI, True
    if value is None:
        return facts.KAPPA_MISSING_MILLI, True
    return max(facts.KAPPA_MIN_MILLI, min(facts.KAPPA_MAX_MILLI, int(value))), False


def collect(c, route: RouteInput, *, now: datetime | None = None,
            freshness_s: int = facts.CANDIDATE_FRESHNESS_S,
            quotebook_refresh_s: int = facts.QUOTEBOOK_REFRESH_S,
            bid: models.Bid | None = None,
            check_isolation: bool = True,
            probe_freshness_s: int | None = facts.CANDIDATE_PROBE_FRESH_S) -> SnapshotResult:
    """P1：把市场快照过滤成候选集，淘汰项带 F1–F5 码（顺序即判定顺序）。

    ``stale`` 的口径（M04 §7）：报价簿最近一次刷新距今超过 ``quotebook_refresh_s``
    → 用最后有效快照放行并打 ``stale``；心跳过期不产生 stale，而是 F2 直接淘汰。

    ``probe_freshness_s``（C9b）：候选必须命中「已验证且新鲜」的上游。
    ``None`` 只用于兼容测试（**默认关闭门控仅限测试**）；生产路径必须用默认 900 s。
    门控在 SQL 层完成（未命中 = 不进候选集），因此不产生额外的淘汰码。
    """
    moment = now or clock.utcnow()
    rows = list(_market(c, model=route.model) if _market is not None
                else _view_rows(c, model=route.model, now=moment,
                                probe_freshness_s=probe_freshness_s))
    book = _book(c, model=route.model, now=moment)
    quote_map = {(quote.node_id, quote.access, quote.unit): quote for quote in book}
    quote_version = _quote_version(c, now=moment)
    stale = _book_stale(book, moment, quotebook_refresh_s)

    candidates: list[models.Candidate] = []
    eliminated: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for row in rows:
        node_id = str(row["node_id"])
        access = row.get("access")
        unit = row.get("unit") or "token"

        # F1 能力匹配：model（归一后）/ access / 容量形态
        if str(row.get("model") or "").strip().lower() != route.model:
            eliminated.append(_drop(node_id, "F1"))
            continue
        if access not in facts.ACCESS_TYPES:
            eliminated.append(_drop(node_id, "F1", detail="access_unknown"))
            continue
        if route.required_access and access not in route.required_access:
            eliminated.append(_drop(node_id, "F1", detail="access_mismatch"))
            continue

        # F2 新鲜度：心跳超新鲜度 或 state ≠ online
        lifecycle = row.get("lifecycle_state")
        presence = _presence(row.get("last_seen_at"), moment, freshness_s)
        if presence != "online":
            eliminated.append(_drop(node_id, "F2", detail=f"presence_{presence}"))
            continue

        # F3 准入 · 地域 · 档位 · 熔断（§7：熔断期只服务在途，不接新）
        if lifecycle != "active":
            eliminated.append(_drop(node_id, "F3", detail=f"lifecycle_{lifecycle}"))
            continue
        if route.kind not in facts.TIERS:
            eliminated.append(_drop(node_id, "F3", detail="tier_unknown"))
            continue
        if circuit.is_open(c, node_id, now=moment).open:
            eliminated.append(_drop(node_id, "F3", detail="circuit_open"))
            continue

        # F4 租户隔离（白黑名单 / 同账户自成交）：S1 只经注入 provider
        if check_isolation and not _isolation_ok(c, route, row):
            eliminated.append(_drop(node_id, "F4"))
            continue

        # F5 报价有效性：必须有一条 active 且未过期的报价，且与出价区间有交集
        quote = quote_map.get((node_id, access, unit))
        if quote is None:
            eliminated.append(_drop(node_id, "F5", detail="no_quote"))
            continue
        from . import matching

        bid_low = bid.min_price_minor if bid else 0
        bid_high = bid.max_price_minor if bid else None
        if bid is not None and route.max_price_minor is not None:
            bid_high = route.max_price_minor if bid_high is None \
                else min(bid_high, route.max_price_minor)
        elif bid is None and route.max_price_minor is not None:
            bid_high = route.max_price_minor
        if not matching.matched(quote.a_lo, quote.a_hi, bid_low, bid_high):
            eliminated.append(_drop(node_id, "F5", detail="no_intersection"))
            continue

        key = (node_id, access)
        if key in seen:                                       # 同节点同口径只留一条
            continue
        seen.add(key)
        rho, rep_missing = _rho(c, node_id)
        kappa, load_missing = _kappa(c, row)
        candidates.append(models.Candidate(
            node_id=node_id, access=access, model=route.model, unit=unit,
            ask_price_minor=quote.a_lo, price_max_minor=quote.a_hi,
            max_qps=int(row["max_qps"]) if row.get("max_qps") is not None else None,
            resource_level=row.get("resource_level"), region=row.get("region"),
            last_seen_at=row.get("last_seen_at"), announced_at=row.get("announced_at"),
            rho_milli=rho, kappa_milli=kappa,
            affinity_hit=_affinity_hit(c, route, row),
            physical_host_id=row.get("physical_host_id"),
            quote_id=quote.quote_id, quote_version=quote.quote_version,
            quote_created_at=quote.created_at,
            account_id=str(row["account_id"]) if row.get("account_id") else None,
            tenant_id=str(row["tenant_id"]) if row.get("tenant_id") else None,
            rep_missing=rep_missing, load_missing=load_missing,
        ))

    log.info("scheduling.p1.collected",
             extra={"event": "p1.collected", "model": route.model,
                    "candidates": len(candidates), "eliminated": len(eliminated)})
    return SnapshotResult(candidates=tuple(sorted(candidates, key=lambda item: item.node_id)),
                          eliminated=tuple(eliminated), quote_version=quote_version,
                          stale=stale)


def _drop(node_id: str, code: str, *, detail: str | None = None) -> dict[str, Any]:
    """淘汰项（对外只暴露粗粒度码 + 粗粒度 detail，不含阈值）。"""
    item: dict[str, Any] = {"node_id": node_id, "reason_code": code,
                            "reason": facts.ELIMINATION_CODES[code]}
    if detail:
        item["detail"] = detail
    return item


def _isolation_ok(c, route: RouteInput, row: Mapping[str, Any]) -> bool:
    """F4 租户隔离：默认只看「同账户自成交」（M04 §11 / product §4.7.3 F4）。

    节点所属账户 = 用方账户时不允许自成交；白黑名单需要 M11，未接线前不参与判定。
    """
    try:
        owner = row.get("account_id")
        if owner is None:
            return True
        return str(owner) != str(route.tenant_id)
    except Exception:                                        # pragma: no cover - 防御
        log.warning("scheduling.isolation.failed", extra={"event": "isolation.failed"})
        return True


def _affinity_hit(c, route: RouteInput, row: Mapping[str, Any]) -> bool:
    if _affinity is None:
        return False
    try:
        return bool(_affinity(c, route, row))
    except Exception:                                        # pragma: no cover - 防御
        log.warning("scheduling.affinity.failed", extra={"event": "affinity.failed"})
        return False


def rebuild(records: Sequence[Mapping[str, Any]]) -> list[models.Candidate]:
    """复算回放：把决策日志里的候选快照还原成 :class:`models.Candidate`（纯函数）。"""
    return [models.Candidate.from_input(record) for record in records]


__all__ = ["SnapshotResult", "RouteInput", "set_reputation_provider", "set_load_provider",
           "set_affinity_provider", "set_market_provider", "collect", "rebuild"]
