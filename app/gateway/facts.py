# SPDX-License-Identifier: Apache-2.0
"""M03 gateway-protocol · 常量（一份事实一个来源）。

本文件每条常量都能追到出处，代码里**不再出现同义字面量**：

* **本模块常量**（M03 §8.2）：重试次数、幂等 / 指纹窗口、批次保留与签名 URL、
  ``messages`` 上限、单条 content 上限、请求 ID 头、大任务确认阈值、弃用公示期。
* **契约枚举**（M03 §5 / spec）：``service_tier`` / ``status`` / ``usage_source`` /
  批状态机 / ``finish_reason`` / ``role``。新增值只加不改（INV-M03-07）。
* **配置键**（M03 §8.1，Owner = M10）：这里只登记**键名与合法区间**；运行时值由
  config-center 经 :mod:`app.gateway.config_source` 的注入 provider 下发。
  模块不读环境变量里的业务常量、不内置业务默认值（00-conventions §1.5）。
* **事件**（02-events §3 / M03 §4.2）：``request.completed`` / ``request.failed``
  的类型、生产者、必含 payload 键。
* **SLO**（03-facts §10，Owner = M03 / M16）：只用于指标与断言，**不参与准入判定**；
  ``tests/gateway/test_facts.py`` 会把它与 ``contracts/facts.yaml`` 对账，防止漂移。
"""
from __future__ import annotations

# --------------------------------------------------------------------------- M03 §8.2 本模块常量
RETRY_MAX_ATTEMPTS: int = 2
"""同一次用户请求最多 2 次尝试（M03 §6.2 / §7；只在**首字节前**重路由）。"""

IDEMPOTENCY_TTL_S: int = 86_400
"""``X-DJB-Idempotency-Key`` 幂等窗口 24h（M03 §3.1 / §8.2 / 00-conventions §5）。"""

FINGERPRINT_WINDOW_S: int = 300
"""非流式请求体指纹去重窗口 300s（M03 §8.2）。"""

STREAM_DEDUP_WINDOW_S: int = 60
"""流式仅请求建立去重窗口 60s（M03 §8.2；T3 使用）。"""

BATCH_RESULT_TTL_DAYS: int = 7
"""慢任务结果保留 7 天（M03 §8.2 / INV-M03-09）。"""

BATCH_RESULT_URL_TTL_S: int = 900
"""结果签名 URL ≤15 分钟（M03 §8.2 / INV-M03-09）。"""

MESSAGES_MAX_ITEMS: int = 256
"""spec ``ChatCompletionRequest.messages.maxItems``。"""

MESSAGE_CONTENT_MAX_BYTES: int = 1_048_576
"""spec ``ChatMessage.content.maxLength``（1 MiB）。"""

REQUEST_ID_HEADER: str = "X-Request-Id"
"""回显头（CR-2 已统一为 spec 的 ``X-Request-Id``）。"""

BATCH_COST_CONFIRM_USD: int = 10
"""大任务预估成本 >10 USD 先确认（M03 §6.3 / §8.2）。"""

DEPRECATION_NOTICE_DAYS: int = 90
"""协议 / 模型弃用提前公示 90 天（M03 §4.3 / §8.2）。"""

# --------------------------------------------------------------------------- HTTP 头（spec / M03 §4.1）
AUTH_HEADER: str = "Authorization"
BEARER_SCHEME: str = "Bearer"
IDEMPOTENCY_HEADER: str = "X-DJB-Idempotency-Key"
PROTOCOL_VERSION_HEADER: str = "DJB-Protocol-Version"
CAPABILITIES_HEADER: str = "DJB-Capabilities"
RETRY_AFTER_HEADER: str = "Retry-After"
LOCATION_HEADER: str = "Location"
IDEMPOTENT_REPLAY_HEADER: str = "X-DJB-Idempotent-Replay"
RATE_LIMIT_LIMIT_HEADER: str = "X-DJB-RateLimit-Limit"
RATE_LIMIT_REMAINING_HEADER: str = "X-DJB-RateLimit-Remaining"
RATE_LIMIT_RESET_HEADER: str = "X-DJB-RateLimit-Reset"
RATE_LIMIT_HEADERS: tuple[str, ...] = (RATE_LIMIT_LIMIT_HEADER, RATE_LIMIT_REMAINING_HEADER,
                                       RATE_LIMIT_RESET_HEADER)
"""限流头（M03 §4.1「限流响应带 X-DJB-RateLimit-*」；三件套口径见 docs）。"""

# --------------------------------------------------------------------------- 协议版本（M03 §4.3）
PROTOCOL_VERSION_CURRENT: str = "1.0.0"
"""服务端当前协议版本（``MAJOR.MINOR.PATCH``）。"""

PROTOCOL_MAJOR_SUPPORTED: tuple[int, ...] = (1,)
"""支持的协议 MAJOR（URL 的 ``v1`` 冻结；不兼容返回 426 / 42601 —— T4 接线）。"""

# --------------------------------------------------------------------------- 枚举（M03 §5 / spec）
SERVICE_TIERS: tuple[str, ...] = ("realtime", "batch")
REQUEST_STATUSES: tuple[str, ...] = ("completed", "failed", "interrupted")
USAGE_SOURCES: tuple[str, ...] = ("estimated", "actual")
BATCH_STATUSES: tuple[str, ...] = ("queued", "running", "succeeded", "failed", "canceled")
BATCH_TERMINAL_STATUSES: tuple[str, ...] = ("succeeded", "failed", "canceled")
BATCH_KINDS: tuple[str, ...] = ("chat", "completion")
MESSAGE_ROLES: tuple[str, ...] = ("system", "user", "assistant", "tool")
FINISH_REASONS: tuple[str, ...] = ("stop", "length", "tool_calls", "content_filter",
                                   "upstream_error")

# --------------------------------------------------------------------------- 流式（T3，M03 §4.3 / §6.2）
SSE_MEDIA_TYPE: str = "text/event-stream"
SSE_DONE: str = "[DONE]"
"""SSE 结束标记：``data: [DONE]``（INV-M03-04）。"""

SSE_CHUNK_OBJECT: str = "chat.completion.chunk"
"""流式分块对象名（OpenAI 兼容）。"""

SSE_HEARTBEAT_S: int = 15
"""心跳注释帧间隔（``: keepalive``；防止中间层空闲超时，不产生业务帧）。"""

STREAM_MAX_ATTEMPTS: int = 2
"""流式只在**首字节前**重路由（M03 §6.2/§7），与 ``RETRY_MAX_ATTEMPTS`` 同值但语义独立。"""

# --------------------------------------------------------------------------- 慢任务（T4，M03 §6.3）
BATCH_BODY_MAX_BYTES: int = 8 * 1_048_576
"""批量提交体上限（实现参数；spec ``PayloadTooLarge`` 注明「放宽不算破坏性变更」）。"""

BATCH_MAX_ITEMS: int = 10_000
"""单批次最大条目数（实现参数；超过 → 413 / 40013）。"""

BATCH_COST_CONFIRM_MINOR: int = BATCH_COST_CONFIRM_USD * 100
"""预估成本超过该值（USD 分）需先确认（M03 §6.3 / §8.2 的 10 USD）。"""

WEBHOOK_EVENTS: tuple[str, ...] = ("batch.queued", "batch.started", "batch.checkpoint_restored",
                                   "batch.completed", "batch.failed", "batch.eta_updated")
"""对外 webhook 事件（M03 §4.3；属**外部投递**，不走内部事件总线）。"""

WEBHOOK_SIGNATURE_HEADER: str = "X-DJB-Signature"
WEBHOOK_TIMESTAMP_HEADER: str = "X-DJB-Timestamp"
WEBHOOK_EVENT_HEADER: str = "X-DJB-Event"
WEBHOOK_SIGNATURE_ALGORITHM: str = "hmac-sha256"
WEBHOOK_MAX_ATTEMPTS: int = 3
WEBHOOK_BACKOFF_S: tuple[int, ...] = (1, 5, 30)
WEBHOOK_TOLERANCE_S: int = 300
"""验签时间窗（±5 分钟）——投递契约的一部分，客户端必须校验。"""

# --------------------------------------------------------------------------- 请求体上限（spec）
CHAT_BODY_MAX_BYTES: int = 1_048_576
"""请求体上限（spec ``PayloadTooLarge``：chat 建议 ≤1 MiB；超出 → 413 / 40013）。"""

IDEMPOTENCY_KEY_MIN_LENGTH: int = 16
IDEMPOTENCY_KEY_MAX_LENGTH: int = 128
MODEL_SLUG_MAX_LENGTH: int = 128
USER_FIELD_MAX_LENGTH: int = 128

# --------------------------------------------------------------------------- 配置键（M03 §8.1，Owner = M10）
CONFIG_KEYS: dict[str, str] = {
    "rate_limit_qps": "gateway.rate_limit_qps",
    "stream_timeout_s": "gateway.stream_timeout_s",
}
"""M03 §8.1 两个配置键；**只登记键名**，运行值由 M10 下发。"""

#: 键的合法区间（M10 schema 未下发时的防御性夹取范围；不是业务默认值）
CONFIG_KEY_RANGES: dict[str, tuple[int, int]] = {
    "gateway.rate_limit_qps": (1, 100_000),
    "gateway.stream_timeout_s": (1, 600),
}

# --------------------------------------------------------------------------- 事件（02-events §3 / M03 §4.2）
EVENT_TYPES: tuple[str, ...] = ("request.completed", "request.failed")
EVENT_VERSION: int = 1
EVENT_PRODUCER: str = "M03"
EVENT_AGGREGATE_TYPE: dict[str, str] = {
    "request.completed": "request",
    "request.failed": "request",
}
EVENT_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    "request.completed": ("request_id", "model", "tokens_in", "tokens_out", "latency_ms",
                          "node_id", "usage_source"),
    "request.failed": ("request_id", "error_code", "upstream_error_class", "attempts"),
}
EVENT_PUBLISHED_RETENTION_DAYS: int = 30
"""outbox 已发布行保留 30 天（与 M04/M05 outbox 同口径）。"""

EVENT_RETRY_BACKOFF_S: tuple[int, ...] = (1, 5, 30, 300, 1_800)
"""投递退避 1s/5s/30s/5min/30min，最多 8 次 → 死信（02-events §2.3）。"""

# --------------------------------------------------------------------------- SLO（03-facts §10）
SLO_FIRST_BYTE_P95_MS: int = 1_200
"""分区域首字节 P95 ≤1.2 s（03-facts §10；只用于指标与断言）。"""

SLO_GATEWAY_OVERHEAD_MS: int = 20
"""网关额外开销 ≤20 ms（03-facts §10；只用于指标与断言）。"""

# --------------------------------------------------------------------------- 保留期（M03 §5）
REQUEST_LOG_RETENTION_DAYS: int = 7
"""``api_request_log`` 只存元数据、保留 7 天（INV-M03-02）。"""


__all__ = [name for name in dir() if name.isupper() or name in {"CONFIG_KEYS",
                                                               "CONFIG_KEY_RANGES",
                                                               "EVENT_AGGREGATE_TYPE",
                                                               "EVENT_PAYLOAD_KEYS"}]
