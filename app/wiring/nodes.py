# SPDX-License-Identifier: Apache-2.0
"""S1 demo 的上游节点通道与模型目录（非生产实现，只在 demo / 测试里用）。"""
from __future__ import annotations

from typing import Any

from app.gateway import models as gateway_models


class EchoNodeClient:
    """M03 ``NodeClient``：不访问网络，固定返回 1000 in / 500 out。"""

    def complete(self, call: gateway_models.NodeCall) -> Any:
        return gateway_models.NodeResult(
            content="S1 demo answer",
            finish_reason="stop",
            model=call.model,
            tokens_in=1000,
            tokens_out=500,
            usage_source="dual",
            latency_ms=12,
            first_byte_ms=4,
            upstream_request_id=f"up-{call.request_id}",
        )


class DemoCatalog:
    """M03 ``ModelCatalogProvider``：返回 demo 模型。"""

    def list_models(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "demo-model",
                "object": "model",
                "owned_by": "djb",
                "created": 0,
            }
        ]
