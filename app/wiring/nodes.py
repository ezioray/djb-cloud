# SPDX-License-Identifier: AGPL-3.0-or-later
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
    """M03 ``ModelCatalogProvider``：返回 demo 模型 + 真实可用性投影（C9 / spec 1.2.8）。

    ``availability`` 是可选注入（``app.wiring.availability.SupplyAvailability``）：
    有则给每行补 ``available`` / ``probe``；没有则**不补字段**（缺省即未知，绝不默认可用）。
    """

    def __init__(self, availability: Any | None = None) -> None:
        self._availability = availability

    def list_models(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = [
            {
                "id": "demo-model",
                "object": "model",
                "owned_by": "djb",
                "created": 0,
            }
        ]
        if self._availability is not None:
            for row in rows:
                row.update(self._availability.status(str(row["id"])))
        return rows
