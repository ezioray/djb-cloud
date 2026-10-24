# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 · supply-integrity 服务端（C14 待分润冻结核心）。

范围（task-15 / Lead 裁决）：

* **只冻结不罚没**（S2）：冻结的是供应方的「待分润」（M05 待分润快照），不是用户资金；
* **绝不改账本**：本包没有任何 ``ledger_*`` 写入、不新增账本科目、不生成分录/冲正；
  解除冻结只改 ``supplier_integrity_holds.state``，账本行一一不动（迁移/用例双证 diff=0）；
* 等级与比例（决策覆盖 M17 §6.1 草案的 10/50/100）：
  ``I0=0 / I1=50% / I2=80% / I3=I4=100%``；
* I1 自动到期 ``now + 7d``；I2+ 无自动到期，只能人工复核释放；
* 同一 ``(node_id, model)`` 只能有 1 条 ``active``（升级 = 改同一行，只升不降）。

分层（与 M02/M03/M05/M11 同款，单包无跨模块 import）::

    facts.py     常量（等级 / 比例 / 事件 / 分页 / scope）
    features.py  特性开关登记（supply.freeze.enabled，默认关闭，无写面）
    errors.py    错误码与错误信封（40001 / 40101 / 40301 / 40401 / 40919 / 503+50001）
    clock.py     UTC 时间与 ISO 序列化
    ids.py       UUIDv7
    models.py    行 → API 载荷、分页游标
    store.py     纯 SQL（psycopg3，无 ORM）
    holds.py     业务服务：create_or_escalate / release / expire_due / 查询
    migrate.py   1710 迁移执行器（up / down / status，供三跑演练与 CI）
    router.py    管理面路由（**不接 app/api.py**，Lead 合并时 include）

硬约束：不写正文 / 不写凭据 / 不写阈值；错误文案只给粗粒度 reason（INV-01 / INV-02 口径）。
"""

__all__ = ["MODULE_ID"]

MODULE_ID = "M17"
