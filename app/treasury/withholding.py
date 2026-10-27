# SPDX-License-Identifier: AGPL-3.0-or-later
"""M08 × M17 扣留桥（只读预览，**不动账本 / 不出分录 / 不改余额**）。

用途：分润出款（M08c）在制单前，按 M17 的 active 冻结总额算出「本笔应扣留多少」。
本模块只做三件事：

1. :func:`enabled` —— 开关 ``treasury.withhold.enabled``（默认关闭，S2 测试网
   ``DJB_WITHHOLD=1`` 打开；三字段：owner=treasury-seat / expire_at=2026-12-31 /
   rollback_rule=关开关即回到「不扣留」旧行为，不改任何历史数据）；
2. :func:`preview` —— ``withheld = min(active 冻结总额, 本笔应付)``，返回
   ``{withheld_micro, payable_micro, hold_ids}``；冻结总额由
   :func:`app.integrity.holds.frozen_total` 只读计算；
3. :func:`apply_to_items` —— 批量预览（出款批次用），纯函数式返回，不写任何表。

边界（硬约束）：

* **不 import 账本写接口**：本模块没有 ``INSERT/UPDATE ledger_*``，也不改余额；
* 开关关闭时 ``withheld=0`` 且不查询冻结表（fail-open 到旧行为，便于回滚）；
* 扣留只是「不出款」，不改变应付金额的记账口径（记账仍在 M08/M06，另行接线）。
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Iterable, Mapping

FLAG = "treasury.withhold.enabled"
ENV_SWITCH = "DJB_WITHHOLD"
OWNER = "treasury-seat"
EXPIRE_AT = "2026-12-31"
ROLLBACK_RULE = "关开关即回到不扣留旧行为；已扣留金额不追溯，无需数据回滚"

__all__ = ["FLAG", "ENV_SWITCH", "OWNER", "EXPIRE_AT", "ROLLBACK_RULE", "flag_spec",
           "enabled", "preview", "apply_to_items"]


def flag_spec() -> dict[str, Any]:
    return {"name": FLAG, "owner": OWNER, "expire_at": EXPIRE_AT,
            "rollback_rule": ROLLBACK_RULE, "default": False}


def enabled() -> bool:
    """默认关闭；``DJB_WITHHOLD=1`` 打开（与其它 S2 模块同款环境开关）。"""
    return os.environ.get(ENV_SWITCH, "").strip() in {"1", "true", "yes", "on"}


def preview(conn: Any, *, node_id: str, gross_micro: int,
            now: datetime | None = None) -> dict[str, Any]:
    """单笔扣留预览：``withheld = min(active 冻结总额, gross)``。

    返回 ``{"enabled", "withheld_micro", "payable_micro", "hold_ids"}``；
    ``hold_ids`` 只列 id（便于对账/审计），不含金额明细。
    """
    gross = max(0, int(gross_micro))
    if not enabled():
        return {"enabled": False, "withheld_micro": 0, "payable_micro": gross,
                "hold_ids": []}
    # 延迟 import：treasury 不因 M17 未部署而无法加载（S2 模块可独立启用）
    from app.integrity import holds as integrity_holds

    frozen = int(integrity_holds.frozen_total(conn, node_id, now=now))
    withheld = min(gross, max(0, frozen))
    hold_ids = [str(item["id"]) for item in
                integrity_holds.active_holds(conn, node_id=node_id, now=now)]
    return {"enabled": True, "withheld_micro": withheld,
            "payable_micro": gross - withheld, "hold_ids": hold_ids}


def apply_to_items(conn: Any, items: Iterable[Mapping[str, Any]], *,
                   now: datetime | None = None) -> list[dict[str, Any]]:
    """批量预览（出款批次制单前调用）。

    入参每项需含 ``payee_account_id``（或 ``node_id``）与 ``gross_micro``；
    返回同长度列表，每项附加 ``withholding`` 字段。**不写库**。
    """
    out: list[dict[str, Any]] = []
    for item in items:
        node_id = str(item.get("node_id") or item.get("payee_account_id") or "")
        row = dict(item)
        row["withholding"] = preview(conn, node_id=node_id,
                                     gross_micro=int(item.get("gross_micro") or 0),
                                     now=now)
        out.append(row)
    return out
