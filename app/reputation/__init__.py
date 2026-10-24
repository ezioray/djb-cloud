# SPDX-License-Identifier: AGPL-3.0-or-later
"""M07 reputation-cop：信誉分 / 等级 / COP / 邀请 / 人工授予（S1 基础面）。

**COP 台账不重建**（Lead 裁决 / DEV-0003）：唯一账本是既有 ``points_*``（migration 006 +
``app/points.py``）；本包只提供只读映射视图 ``v_m07_cop_ledger``（migration 707）与
薄封装，不新建 ``cop_ledger``（703）。

模块边界（M07 规格 §1）：

* 做：信誉分与等级重算（纯函数 + 可注入配置）、COP 台账读写（经 points）、单层邀请、
  用户间转让（默认关）、人工授予 / 扣回、生产 ``reputation.changed`` / ``cop.earned`` /
  ``cop.spent`` / ``invite.bound``；
* 不做：USD 账本 / 科目分录（M06）、计费与收据（M05）、出款与清算（M08）、
  风控规则与申诉裁决（M11）、任何「COP 换现金」的能力。

对外入口：:func:`app.reputation.router.create_router`（工厂注入连接与鉴权，**不接 api.py**）。
"""
from __future__ import annotations

__all__ = ["errors", "facts", "score", "cop", "invites", "grants", "events", "store",
           "models", "outbox", "router", "migrate", "clock"]

__version__ = "0.1.0"
