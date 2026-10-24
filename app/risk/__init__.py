# SPDX-License-Identifier: AGPL-3.0-or-later
"""M11 risk-abuse：风控规则元数据 / 限额 / 案件 / 申诉 / 处置提案（S1+S2 管理面）。

责任边界（M11 §1）：

* **做**：规则元数据（``config_ref`` + ``rule_version``，阈值只在 M10）、限额与只读视图
  ``v_risk_limits``、案件全生命周期与证据链、申诉与 SLA、设备 / 行为信号流水（只存哈希 / 簇 ID）、
  四类 ``risk.*`` 事件；
* **不做**：不定义阈值 / 权重 / 名单（INV-01），不改账户状态（INV-04：只发
  ``risk.action.requested`` 提案给 M01），不做资金动作，不写 audit_log（走 M16）。

对外只有管理面 API（9 条，spec 1.2.4）+ 只读视图 + 事件；**不进入转发路径**（CR-2 方案 A）。

模块结构::

    facts.py          枚举 / 时长常量 / 事件 payload 白名单（零阈值数值）
    errors.py         40001 / 40101 / 40301 / 40401 / 40919 / 42401 + 48001–48006
    models.py         请求解析 / 行映射 / 对客白名单序列化 / 游标
    policy.py         案件·申诉状态机 / 冻结期限 / 申诉窗口 / SLA / SoD / 粗粒度 reason
    config_source.py  M10 risk.* 只读绑定（只解析版本，不读值）+ LKG
    events.py         02-events 信封校验 + outbox（同事务、幂等、退避）
    store.py          SQL（租户隔离在 SQL；JSONB 只放白名单键）
    cases.py          开案 / 去重 / 处置分级（只提案）
    appeals.py        申诉受理 / 裁决 / SLA 升级
    router.py         create_router(...) 路由工厂（默认 fail-closed）
    migrate.py        1100–1104 迁移执行器（up / down / status）
    ids.py            UUIDv7
    clock.py          UTC 时间
"""
from __future__ import annotations

from . import (appeals, audit, cases, clock, config_source, errors, events, facts, ids,
               models, policy, store)

__all__ = [
    "appeals", "audit", "cases", "clock", "config_source", "errors", "events", "facts",
    "ids", "models", "policy", "store",
]
