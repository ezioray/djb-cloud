# SPDX-License-Identifier: Apache-2.0
"""M14 admin-data · 数据治理（导出 / 删除 / 保留）+ Ops 只读面（S1 只读 / S2 完整）。

责任边界（M14 §1）::

    **做**：导出申请—审批—执行—报告闭环；保留任务（dry-run / 删除报告 / 幂等重放）；
    Ops 健康总览（七块红黄绿 + 最近变更）、变更日历、批量五步（预览→执行→撤销）、
    操作回放（审计时间线）、只读沙箱会话策略。

    **不做**：不写任何业务表（1301–1303 三张自有表 + outbox）；不直连他域基表
    （只读 v_<module>_* 视图 / audit_log）；不执行发布、不迁移、不备份（M16）；
    不做对账计算（M09）；不在模型调用路径上；不持有签名私钥。

模块结构::

    facts.py     枚举 / 状态机 / 保留矩阵 / 事件 payload 白名单
    errors.py    40001 / 40101 / 40301 / 40401 / 40901 / 42401 / 49001 / 45001
    clock.py ids.py
    models.py    请求解析 / 行 → 契约 payload / 游标
    policy.py    状态机 / 双人复核 / 链接 TTL 与一次性 / 沙箱
    store.py     M14 三表 + outbox 的 SQL；只读视图 / audit_log 适配
    export.py    导出闭环（申请 / 审批 / 执行 / 完成 / 取消 / 签名链接）
    retention.py 保留任务（dry-run / 删除报告 / 幂等重放）
    batch.py     批量五步 + 只读沙箱
    ops.py       健康总览 / 变更日历 / 操作回放（只读聚合）
    audit.py     审计钩子（写 M16 审计链，未接线时返回 False）
    events.py    02-events 信封 + outbox（同事务、幂等、退避）
    router.py    create_router(...) 十条端点（**未接 app/api.py**，由 Lead include）
    migrate.py   1301–1304 迁移执行器（--up / --up-only / --down / --status）
"""
from __future__ import annotations

from . import (audit, batch, clock, errors, events, export, facts, ids, models, ops,
               policy, retention, store)

__all__ = [
    "audit", "batch", "clock", "errors", "events", "export", "facts", "ids", "models",
    "ops", "policy", "retention", "store",
]

#: 模块版本（代码版本；不是契约版本）
__version__ = "0.1.0"
