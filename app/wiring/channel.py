# SPDX-License-Identifier: AGPL-3.0-or-later
"""C10 接线：把 M03 内存队列适配成 M02 ``ChannelBackend``，并装配 ``ChannelNodeClient``。

分工（CR-C10-01）：

* M02 只认 :class:`app.supply.channel.ChannelBackend`（``poll`` / ``submit``）；
* M03 的 :class:`app.gateway.channel.ChannelQueue` 持有任务、租约、重派与结果；
* 本文件只做**形状适配**：``ChannelJob`` → spec 1.2.9 ``NodeChannelJob``（``request`` 嵌套），
  submit 原样转给队列。**不落正文、不写库**。

生产接线必须显式判断 ``gateway.channel.enabled``（默认关）；``install(channel=True)`` 只给
S1/S2 demo 与测试用，避免在开关未批准时把生产流量切到内存队列。
"""
from __future__ import annotations

from typing import Any

from app.gateway import channel as gateway_channel
from app.gateway import clock as gateway_clock
from app.gateway import errors as gateway_errors
from app.supply import channel as supply_channel
from app.supply import errors as supply_errors


def _job_payload(job: gateway_channel.ChannelJob) -> dict[str, Any]:
    """M03 ``ChannelJob`` → spec ``NodeChannelJob``（只放执行必需字段）。"""
    request: dict[str, Any] = {
        "model": job.model,
        "messages": [dict(item) for item in job.messages],
    }
    if job.max_tokens is not None:
        request["max_tokens"] = int(job.max_tokens)
    if job.temperature is not None:
        request["temperature"] = float(job.temperature)
    if job.stop:
        request["stop"] = list(job.stop)
    payload: dict[str, Any] = {
        "job_id": job.job_id,
        "kind": "chat.completions",
        "request_id": job.request_id,
        "request": request,
        "lease_expires_at": gateway_clock.iso(job.lease_until) if job.lease_until else None,
    }
    if job.timeout_s is not None:
        payload["timeout_s"] = float(job.timeout_s)
    return payload


class ChannelBackendAdapter:
    """``ChannelQueue`` 的 M02 适配器（只做形状转换，不复制队列语义）。"""

    def __init__(self, queue: gateway_channel.ChannelQueue) -> None:
        self._queue = queue

    def poll(self, node_id: str, *, wait_s: float,
             capabilities: tuple[str, ...]) -> dict[str, Any] | None:
        job = self._queue.poll(node_id, wait_s=wait_s, capabilities=capabilities)
        return None if job is None else _job_payload(job)

    def submit(self, node_id: str, job_id: str, result: dict[str, Any]) -> dict[str, Any]:
        try:
            reply = self._queue.submit(node_id, job_id, result)
        except gateway_errors.GatewayError as exc:
            message = str(exc)
            if "未知任务" in message or "不属于该节点" in message:
                raise supply_errors.ChannelJobNotFound(message) from exc
            if "不一致" in message or "租约" in message or "已取消" in message:
                raise supply_errors.IdempotencyConflict(message) from exc
            raise supply_errors.ChannelUnavailable(message) from exc
        status = str(reply.get("status") or "").strip()
        return {"accepted": status in ("accepted", "duplicate"),
                "duplicate": status == "duplicate"}


def install_channel(*, queue: gateway_channel.ChannelQueue | None = None
                    ) -> tuple[gateway_channel.ChannelQueue,
                               gateway_channel.ChannelNodeClient]:
    """创建队列 + 客户端，并把 M02 后端接上；返回 ``(queue, node_client)``。"""
    channel_queue = queue if queue is not None else gateway_channel.ChannelQueue()
    client = gateway_channel.ChannelNodeClient(channel_queue)
    supply_channel.set_channel_backend(ChannelBackendAdapter(channel_queue))
    return channel_queue, client


__all__ = ["ChannelBackendAdapter", "install_channel"]
