# SPDX-License-Identifier: Apache-2.0
"""M09 recon-reports · 三方对账 / 差异台账 / 复核凭证 / 报表（S1：receipt + daily_close）。

模块分层（对外只暴露这几层，测试与接线都从这里进）::

    facts      常量（出处逐条标注：03-facts §6/§7/§10、M09 §8.1/§8.2、spec 参数）
    errors     错误码（49201–49206 / 49210–49212 + 已登记通用码），信封在 router 组装
    clock      UTC 时钟（测试可注入固定时刻）
    models     RunSpec / ExceptionDraft / 请求解析 / 行 → 契约 payload / 游标 / UUIDv7
    grading    差异分级与 SLA（INV-02 结构性一律 P0）
    store      M09 五张表的读写（事务边界由调用方给）
    m06        M06 只读适配（试算平衡 / 科目余额漂移，整数口径）
    engine     对账引擎：scope=receipt / daily_close；chain/psp/bank 留扩展点（依赖 M08）
    attestation 复核凭证提交 / 查询 / validate（只回结论）
    reports    REP-01 recon-daily / REP-02 exceptions（T4 的 por/monthly 不注册路由）
    router     create_router(...) 路由工厂（**未接 api.py**，由 Lead include）
    migrate    迁移执行器 CLI（--up / --up-only / --down / --status）

红线：不写 M05/M06 表、不持有私钥、不伪造外部账户数据、不发布。
"""
from __future__ import annotations

from . import (attestation, clock, engine, errors, facts, grading, m06, migrate, models,
               reports, store)

__all__ = [
    "attestation", "clock", "engine", "errors", "facts", "grading", "m06", "migrate", "models",
    "reports", "store", "__version__",
]

#: 模块版本（与 rule_version 区分：这是代码版本，rule_version 是对账口径版本）
__version__ = "0.1.0"
