# SPDX-License-Identifier: Apache-2.0
"""M08 payments-treasury：支付订单 / PSP / 钱包池 / 归集 / 分润 / 退款 / gas / 签名意图。

阶段（M08 §0 / README §1.1）：S1 接口与数据模型（不接 PSP / 主网）；S2 测试网闭环；
S3 真钱（本模块**不做**真钱，也不接主网；所有通道默认关闭，需显式接线）。

责任边界（M08 §1）：

* **做**：支付订单与 PSP 适配（下单 / 回调验签 / 幂等 / 金额与币种校验）；钱包池预生成 /
  2/3 激活 / 70% 切地址 / 退休四步；归集制单与确认；分润批次 maker–checker–signer；
  退款申请与执行状态机；gas 三模式按批次快照；资金意图与签名六事件（只 propose，不持钥）；
* **不做**：不记账（E3/E4/E5 只交出 PostingRequest，由 M06 posting API 落账）；不生成对账 /
  差异 / attestation（M09）；不发布配置（M10）；不执行风控规则（M11）；不投递通知（M12）；
  不写 accounts（M01）/ recon_*（M09）/ audit_log（M16）；不存私钥 / 助记词 / 完整签名 / 卡号。

模块结构::

    facts.py          枚举 / 常量（03-facts §1–§5 + M08 §8.2）/ 事件 payload 白名单
    errors.py         40001 / 40101 / 40301 / 40401 / 40910–40919 / 42210 / 42211 / 42401 / 45001
    clock.py          UTC 时钟（业务日切 UTC+4）
    ids.py            UUIDv7 / 对外单号前缀
    config_source.py  M10 treasury.* / payment.* / billing.* 只读绑定（默认值 + 来源标记）
    policy.py         状态机 + 不变量纯函数（INV-01…INV-14）
    models.py         请求解析 / 行映射 / 对客白名单 / 游标
    provider.py       PaymentProvider 适配器（UPG / GIFPay SHA256 规范化 + mock）
    ledger.py         M06 posting 适配层（E3 / E4 两步 / E5 两步；只 propose）
    events.py         02-events 信封 + m08_outbox（同事务、幂等、退避、dead）
    store.py          SQL（psycopg3；用户侧按 account_id 隔离）
    order.py          下单 / 查询 / 取消 / 回调（验签 + 查询二次确认 + E3）
    signing.py        资金意图 + 签名请求 + 六事件（2-of-3）
    wallet.py         池深度 / 预生成 / 激活 / 切换 / 退休 / 归集 / 平台收款地址
    payout.py         分润批次 / 白名单（72h 冷却 + 首笔 ≤100）/ gas 三模式
    refund.py         退款（14 天 / 原路 / 双人 24h 冷却）
    audit.py          M16 审计钩子（不拥有审计表）
    router.py         create_router(...) 路由工厂（默认 fail-closed）
    migrate.py        800–805 迁移执行器（up / up-only / down / status / seed）
"""
from __future__ import annotations

from . import (audit, clock, config_source, errors, events, facts, ids, ledger, models,
               order, payout, policy, provider, refund, signing, store, wallet)

__version__ = "0.1.0-dev-m08"

__all__ = [
    "audit", "clock", "config_source", "errors", "events", "facts", "ids", "ledger",
    "models", "order", "payout", "policy", "provider", "refund", "signing", "store", "wallet",
    "__version__",
]
