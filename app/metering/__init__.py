# SPDX-License-Identifier: Apache-2.0
"""M05 metering-receipt（DEV-M05 T1+T2：双签收据受理 + 用量落库 / 汇总 / 明细）。

本包是 M05 的**唯一写入口**，也是以下 5 张表的唯一写者（01-ownership §2 / M05 §5）::

    usage_records · metering_receipts · usage_corrections · upstream_bills · loss_pool_entries

> ``metering_receipts`` 对应 M05 §5 的 ``receipts``：001_init 的历史 ``receipts`` 表被
> legacy adapter（``app/api.py`` / ``app/reconcile.py``）占用且形状不同，00-conventions §7.1
> 禁止重建存量表，因此本模块新建自有表；该命名偏差已在证据文件登记为待 Lead 裁决项。

分层（每层职责单一，便于复算与审计）::

    facts.py          常量 / 枚举（M05 §8.1、§8.2 + spec 1.2.x + 02-events §3），唯一来源
    errors.py         错误码（40001 / 40013 / 40101 / 40303 / 40401 / 46001 / 50001）
    clock.py          可注入时钟（测试确定性）
    config_source.py  ``metering.*`` 配置的注入式只读快照（§8.1 默认值 + 范围夹取）
    features.py       特性开关登记（三字段 + 默认关闭 + 无可写面）
    amounts.py        金额 / 用量 / 单价的整数精确换算（INV-05，不四舍五入）
    signing.py        6 字段规范串 + 双侧 HMAC-SHA256 验签（CR-2，密钥只做引用）
    models.py         UUIDv7 / 收据解析 / 受理结论 / 用量行（纯函数）
    events.py         ``receipt.signed`` / ``usage.recorded`` / ``usage.settled`` 信封（T3 投递）
    events.py         ``receipt.signed`` / ``usage.recorded`` / ``usage.settled`` 信封
    outbox.py         本地事务 + outbox：同事务入队 / 至少一次派发 / 退避 / 死信 / 保留期
    settlement.py     M06 E6 的注入式对接（同步仅管理面重放，默认被开关挡住）
    consumers.py      消费 request.completed / request.failed / booking.created / config.published
    receipts.py       批量受理：幂等 + 24h 窗口 + 双签 + 金额复核 + 同事务落库
    usage.py          用量汇总（model / day）与明细（游标分页）
    corrections.py    校正：只追加 + 累计不超原额 + 双人复核 + 幂等键
    bills.py          上游账单导入（幂等 / 1% 容差 / >1% 追加校正）
    loss_pool.py      亏损池：只记「上游已消耗、用户未计费」，注入 sink 接 M06
    migrate.py        501–508 迁移与回滚（证据用 CLI）
    router.py         4 个端点（**不接 app/api.py**，由 Lead 合并时 include）

边界：不 import 任何其它 ``app.*`` 业务模块（只用 ``app.db``）；节点存在性只读 M02 的
``v_supply_node_snapshot`` 视图；账户 / 成交价 / 账本只经**注入 provider**（T3 接线）；
不改 ``app/receipt.py``（legacy adapter，只读引用）、``app/api.py``、其它模块、spec、contracts。
"""
from __future__ import annotations

from . import (amounts, bills, clock, config_source, consumers, corrections, errors, events,
               facts, features, loss_pool, models, outbox, receipts, settlement, signing, usage)

__version__ = "0.5.0-dev-m05t5"

__all__ = [
    "facts", "errors", "clock", "config_source", "features", "amounts", "signing", "models",
    "events", "outbox", "settlement", "consumers", "receipts", "usage", "corrections", "bills",
    "loss_pool",
]
