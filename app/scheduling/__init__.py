# SPDX-License-Identifier: Apache-2.0
"""M04 scheduler-pricing（DEV-M04 T1+T2：报价簿 / 撮合 / 取价 + P1–P5 决策管线 / 决策日志）。

本包是 M04 的**唯一写入口**，也是以下 6 张表的唯一写者（01-ownership §2 / M04 §5）::

    quotes · bids · bookings · routing_decisions · quota_usage · model_catalog

分层（每层职责单一，便于复算与审计）::

    facts.py        常量（M04 §8.1/§8.2 + spec 枚举 + F1–F5 淘汰码），一份事实一个来源
    errors.py       错误码（40001 / 40303 / 40401 / 40901 / 40902 / 42901 / 42902 / 45001）
    clock.py        可注入时钟 + 快照时刻截断（INV-03 的锚点稳定性）
    config_source.py  M10 配置的注入 provider（缺省 = §8.1 默认值，越界夹取）
    features.py     特性开关登记（三字段 + 默认关闭）
    models.py       金额换算（整数分）/ UUIDv7 / 聚合数据类 / 候选输入快照
    quotes.py       报价簿（只追加 + 版本化 + 内容不变不升版本）
    bids.py         出价簿（同上，版本按 (tenant, model)）
    matching.py     INV-01 区间相交 / INV-02 取价 / 成交锁 bookings
    events.py       5 个事件信封（02-events §1）+ 注入的 publisher
    candidates.py   P1 过滤（F1–F5）+ 注入的 ρ / κ / 亲和 provider
    scoring.py      P2 effective_cost（整数微分）+ INV-04 tie-break
    quota.py        P3 配额 / 并发（三者取最小）/ 占比
    preempt.py      P4 抢占（只 realtime 抢 batch，检查点 + 预算）
    pipeline.py     P1–P5 编排：``solve``（纯函数）+ ``execute``（同事务落库）
    decisions.py    决策日志（四元锚点唯一，只追加，12 个月归档口径）
    replay.py       复算回放（并发 1，只读）
    snapshot.py     公开快照（只含输入 + quote_version）
    migrate.py      401–406 迁移与回滚（证据用 CLI）
    router.py       6 个端点（**不接 app/api.py**，由 Lead 合并时 include）

边界：不 import 任何其它 ``app.*`` 业务模块（只用 ``app.db``）；
节点 / 容量只读 M02 的 ``v_supply_node_snapshot`` / ``v_supply_capacity_latest`` 视图；
租户配额只经注入 provider；不改 ``app/pricing.py``（legacy adapter，只读引用）、
``app/api.py``、其它模块、spec、contracts。
"""
from __future__ import annotations

from . import (bids, candidates, clock, config_source, decisions, errors, events, facts,
               features, matching, migrate, models, pipeline, preempt, quota, quotes, replay,
               router, scoring, snapshot)

__version__ = "0.2.0-dev-m04t2"

__all__ = [
    "facts", "errors", "clock", "config_source", "features", "models", "quotes", "bids",
    "matching", "events", "candidates", "scoring", "quota", "preempt", "pipeline", "decisions",
    "replay", "snapshot", "migrate", "router",
]
