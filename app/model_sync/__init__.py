# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 model-sync 服务端（C17）：厂商模型 / tokenizer 版本注册表 + 签名 bundle 分发。

边界（M18-model-sync.md §2 / task-17）：

* 只维护**元数据 / 指纹**（family / version / hash / context_window），不分发厂商受限
  tokenizer 权重，不采集用户正文；
* 不接 ``app/api.py``（由 Lead 合并时统一 include），不改根 spec（Lead 写 1.2.12）；
* 不碰账本：本包没有任何 ``ledger`` 写路径；
* 写路径默认关闭（``model.sync.enabled`` / ``model.sync.auto_publish`` 默认 False；
  S2 测试网用 ``DJB_MODEL_SYNC=1`` 显式激活），未接线鉴权一律 401（fail-closed）。
"""
from __future__ import annotations

__all__ = ["facts", "errors", "features", "clock", "ids", "signing", "registry", "store",
           "router", "migrate"]
