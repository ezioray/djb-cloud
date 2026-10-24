# SPDX-License-Identifier: AGPL-3.0-or-later
"""C10 接线：M03 队列 ↔ M02 ChannelBackend ↔ ChannelNodeClient 的端到端形状。

不启 HTTP（端点由 tests/supply/test_channel_api.py 覆盖）；这里证明：
网关 complete() 入队 → M02 poll 拿到 spec 形状 → submit 结果 → 网关拿到 NodeResult。
"""
from __future__ import annotations

import threading

from app.gateway import models, providers
from app.supply import channel as supply_channel
from app.wiring import install
from app.wiring.db import Database
from gatewaykit import dsn


def _call(node_id: str = "node-c10") -> models.NodeCall:
    return models.NodeCall(
        node_id=node_id,
        upstream_id=None,
        access=None,
        model="m1",
        messages=({"role": "user", "content": "hello-c10"},),
        request_id="req-c10",
        trace_id="trace-c10",
        attempt_no=1,
        max_tokens=8,
        timeout_s=5,
    )


def test_install_channel_wires_m02_backend_and_client(migrated: str):
    db = Database(schema=migrated, dsn=dsn())
    wiring = install(db, channel=True)
    try:
        assert wiring.node is wiring.channel_client
        backend = supply_channel.require_channel_backend()
        assert backend is not None

        result: dict[str, object] = {}

        def run() -> None:
            result["value"] = wiring.node.complete(_call())

        thread = threading.Thread(target=run)
        thread.start()
        job = backend.poll("node-c10", wait_s=2.0, capabilities=())
        assert job is not None
        assert job["kind"] == "chat.completions"
        assert job["request_id"] == "req-c10"
        assert job["request"]["model"] == "m1"
        assert job["request"]["messages"][0]["content"] == "hello-c10"
        assert "model" not in job and "messages" not in job
        assert job["timeout_s"] == 5

        ack = backend.submit("node-c10", str(job["job_id"]), {
            "job_id": job["job_id"], "status": "completed", "content": "world-c10",
            "finish_reason": "stop", "tokens_in": 3, "tokens_out": 2,
            "usage_source": "actual",
        })
        assert ack["accepted"] is True
        thread.join(5)
        assert not thread.is_alive()
        node_result = result["value"]
        assert node_result.content == "world-c10"
        assert node_result.tokens_in == 3 and node_result.tokens_out == 2
    finally:
        supply_channel.set_channel_backend(None)
        providers.reset_providers()


def test_install_without_channel_keeps_echo_and_fail_closed(migrated: str):
    db = Database(schema=migrated, dsn=dsn())
    wiring = install(db)
    try:
        assert wiring.node.__class__.__name__ == "EchoNodeClient"
        assert supply_channel.channel_backend() is None
    finally:
        supply_channel.set_channel_backend(None)
        providers.reset_providers()
