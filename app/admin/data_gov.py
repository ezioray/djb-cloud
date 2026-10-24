# SPDX-License-Identifier: AGPL-3.0-or-later
"""M14 数据治理 / Ops 只读面 · 管理面路由入口（薄门面，不含业务逻辑）。

为什么单独留这个文件：历史管理面服务层（``ops_center`` / ``ops_growth`` /
``upgrade_center``）都在 ``app/admin/`` 下且**不注册 HTTP 路由**；M14 新增的
数据治理与 Ops 面沿用同一入口位置，但实现全部在 ``app/data_gov/``，本文件只导出
``create_router``，不复制任何 SQL / 状态机。

接线（由 Lead 在 ``app/api.py`` 完成，本席不改 api.py）::

    from app.admin.data_gov import create_router as create_data_gov_router
    app.include_router(create_data_gov_router(
        connection_factory=db.conn,
        admin_resolver=_admin_dev_principal,
        step_up_verifier=...,
        retention_executor=...,          # Owner 删除执行器（M16 / 各 Owner API）
        health_probes=...,               # 未接线时未接块的健康状态为 yellow
        batch_probe=..., batch_executor=..., batch_undoer=...,
    ))
"""
from __future__ import annotations

from app.data_gov.router import create_router

__all__ = ["create_router"]
