# SPDX-License-Identifier: Apache-2.0
"""链上收款域（一期仅 Polygon PoS，决策 K6）。

本包只做链上**收款**：地址派生 → 扫描事件 → E1/E2 入账 → 错链/假充值冲正。
不做签名、不转账、不持有任何私钥（见 ``polygon.py`` 顶部红线）。

特性开关（硬约束：三字段 owner / expire_at / rollback_rule 齐全，默认关闭）：

===============  =======  =========  ==========  ======================================================
flag             默认     owner      expire_at   rollback_rule
===============  =======  =========  ==========  ======================================================
``polygon_ingest``  **off**  chain-dev  2026-12-31  关闭后停止扫描与入账（新 tx 不再写链上表/账本）；
                                                   **已入账不回滚**，错单按 §20.4.6 走冲正
                                                  （``void`` + ``reverse_of``，只追加不删改）
===============  =======  =========  ==========  ======================================================

用法：进程环境变量 ``DJB_FF_POLYGON_INGEST=1`` 打开；缺省、``0``、``off`` 均为关闭。
``expire_at`` 到期后开关**强制为关**（fail-closed），需重新评审后改日期，不允许静默续期。
"""
from __future__ import annotations

import os
from datetime import date

__all__ = ["FEATURE_FLAGS", "flag_spec", "flag_enabled", "flag_expired", "REQUIRED_FLAG_FIELDS"]

REQUIRED_FLAG_FIELDS = ("owner", "expire_at", "rollback_rule")

FEATURE_FLAGS: dict[str, dict] = {
    "polygon_ingest": {
        "default": False,
        "owner": "chain-dev",
        "expire_at": "2026-12-31",
        "rollback_rule": ("关闭后停止扫描与入账（新 tx 不再写 chain_tx/ledger）；"
                          "已入账不回滚，错单走冲正 void+reverse_of；"
                          "存量 chain_tx/chain_tx_event 只追加，不删不改"),
        "summary": "Polygon PoS 收款扫描 + E1/E2 入账 + 错链/假充值冲正",
    },
}

_ENV_PREFIX = "DJB_FF_"
_TRUTHY = {"1", "true", "yes", "on"}


def flag_spec(name: str) -> dict:
    """返回开关定义（含三字段）。缺字段直接报错，不允许「裸开关」上线。"""
    try:
        spec = dict(FEATURE_FLAGS[name])
    except KeyError:
        raise KeyError(f"未登记的特性开关: {name}") from None
    missing = [f for f in REQUIRED_FLAG_FIELDS if not spec.get(f)]
    if missing:
        raise ValueError(f"特性开关 {name} 缺三字段中的 {missing}（owner / expire_at / rollback_rule 必填）")
    return spec


def flag_expired(name: str, *, today: date | None = None) -> bool:
    """开关是否已过 expire_at（到期即强制为关）。"""
    spec = flag_spec(name)
    today = today or date.today()
    return today > date.fromisoformat(spec["expire_at"])


def flag_enabled(name: str, *, override: bool | None = None, today: date | None = None) -> bool:
    """读开关。优先级：显式 override（测试用）> 环境变量 > 默认值；到期一律 False。"""
    spec = flag_spec(name)
    if flag_expired(name, today=today):
        return False
    if override is not None:
        return bool(override)
    raw = os.environ.get(_ENV_PREFIX + name.upper())
    if raw is None or raw.strip() == "":
        return bool(spec["default"])
    return raw.strip().lower() in _TRUTHY
