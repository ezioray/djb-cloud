# SPDX-License-Identifier: Apache-2.0
"""M03 gateway-protocol · OpenAI 兼容入口与协议门面（T1+T2）。

分层（00-conventions §2「代码包 app/<module>/，模块内分层」）：

``errors``      错误信封 / M03 §4.4 错误码表（唯一出口）
``auth``        Bearer Key 鉴权编排（M01 ``verify_api_key`` 经**注入 provider**，fail-closed）
``ratelimit``   单 Key QPS 滑动窗口（429 + ``Retry-After`` + ``X-DJB-RateLimit-*``）
``quota``       配额口径 ``min(租户, Key, 节点)`` + 每日花费上限（42902）
``idempotency`` ``X-DJB-Idempotency-Key`` 24h + 请求体指纹 300s / 流式 60s
``validation``  请求体校验（``messages`` ≤256、单条 content ≤1 MiB、413 / 40001）
``providers``   跨模块只读/写**注入点**（M01 鉴权、M04 路由、M05 用量、节点上游、M10 配置）
``dispatch``    向上游节点发起调用（首字节前最多 2 次尝试 / 两次失败不计费）
``store``       本模块表读写（``api_request_log`` / ``m03_outbox`` / ``m03_idempotency``）
``events``      ``request.completed`` / ``request.failed`` 信封（02-events §1）
``chat``        实时非流式主链路（鉴权 → 限流/配额 → 校验 → 幂等 → 路由 → 派发 → 计量 → 留痕）
``router``      ``/v1/*`` HTTP 层（**不接 app/api.py**，由 Lead 合并时统一 include）
``migrate``     301–305 迁移执行器（空库 / 升级 / 回滚三跑）

硬边界：**不 import 任何其它业务模块**（M01/M04/M05 只经 :mod:`app.gateway.providers`
注入），不写别人的表，不持久化 prompt / response 正文。

接线说明见 ``app/gateway/WIRING.md``（合并时由 Lead 注入 5 个 provider）。
"""
from __future__ import annotations

__all__ = ["__version__"]

#: 本包版本（跟随交付批次，不是协议版本；协议版本见 facts.PROTOCOL_VERSION_CURRENT）
__version__ = "0.2.0"
